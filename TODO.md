# TODO — Future improvements

## 1. TCP stream reassembly

### The problem

`snidump` processes each captured packet independently. There is no memory
between callback invocations. When `tls_process_record` or
`http_process_request` is called, the payload must contain a complete,
self-consistent message or the call returns 0 and the packet is discarded.

TCP is a byte-stream protocol. The kernel makes no promise about how bytes are
grouped into segments. A single TLS ClientHello or HTTP request can legally
arrive split across two or more segments when:

- The message is larger than the path MTU (common on VPN/tunnel links where
  the effective MTU may be ~1400 bytes or less).
- Nagle's algorithm or TCP segmentation offload (TSO) reshapes segments.
- The sending TLS stack performs multiple `write()` calls for the one message.
- A retransmit changes the segment boundaries.

When a ClientHello is fragmented, `snidump` misses the SNI silently — no
warning is printed, the connection just goes unlogged.

### Why the PSH-flag BPF heuristic is kept

The default BPF filter includes `tcp[tcpflags] & tcp-push == tcp-push`, which
restricts capture to segments where the sender set the PSH (Push) flag. PSH is
set by TCP when the sender explicitly flushes buffered data, which in practice
nearly always coincides with the final (or only) segment of an application-
layer write. For a TLS ClientHello sent in a single `write()` call, PSH is
almost always set on exactly that segment.

Without stream reassembly, dropping segments that don't carry PSH is a net
win: a fragmented ClientHello (where PSH may only be on the last fragment) is
unprocessable anyway — snidump cannot assemble it — so receiving the fragments
only wastes CPU. The PSH filter is a deliberate, coherent compromise given the
current architecture. It should be revisited or removed only if reassembly is
implemented (see below).

The trade-off: TLS stacks on embedded or unusual systems that omit PSH on the
ClientHello will be silently missed. In practice this is rare on standard
implementations.

### What a fix would require

Full TCP stream reassembly needs:

1. **Per-flow state keyed on the 4-tuple** `(src-IP, src-port, dst-IP, dst-port)`.
   A hash table (e.g., uthash, khash) is the typical data structure.

2. **Sequence-number-aware per-flow buffer.** Each arriving segment is placed
   at its correct offset within the flow's byte stream. The buffer must handle:
   - Out-of-order segments (a later sequence number arrives before an earlier one).
   - Retransmits (duplicate sequence numbers; the second copy is discarded).
   - Gaps (missing segments; the buffer stalls until the gap is filled or a
     timeout fires).

3. **Completion detection.** For TLS: once 5 bytes are available, read
   `TLSPlaintext__length`; wait until that many additional bytes are buffered,
   then call `tls_process_record`. For HTTP: wait for `\r\n\r\n`.

4. **Flow eviction.** Flows must be removed after the handshake completes
   (SNI found), after a RST/FIN, or after an idle timeout. Without eviction,
   the flow table grows without bound and memory is exhausted.

5. **Memory limits.** Cap either the number of tracked flows or the per-flow
   buffer size. When the cap is hit, oldest or smallest flows are evicted.
   The cap must be tunable for the expected traffic volume.

6. **BPF adjustment.** With reassembly, the PSH restriction can be removed
   (see above). The BPF would change to:
   ```
   ip and tcp and (dst port 80 or dst port 443)
   ```

### Existing libraries to consider

- **libnids** — portable TCP reassembly and IP defragmentation library,
  designed as a layer on top of libpcap. API is a natural fit for this project.
  No longer actively maintained.
- **libntoh** — modern alternative to libnids, still maintained.
- **Zeek (formerly Bro)** — full IDS/NSM framework with excellent reassembly;
  overkill for this use case but the source is a useful reference.

### Effort estimate

Without an external library: approximately 500–800 lines of new C including
the hash table, buffer management, and eviction logic. Using libnids or libntoh
it would be closer to 100–150 lines of integration code plus a new build
dependency.

---

## 2. QUIC / HTTP/3 SNI extraction

### The problem

QUIC (RFC 9000) is a UDP-based transport protocol. HTTP/3 runs over QUIC. On
port 443, a significant and growing fraction of traffic is QUIC — all modern
Chrome/Firefox browsers prefer QUIC when the server supports it, and all major
CDN operators (Cloudflare, Fastly, Akamai, Google) advertise QUIC support.

`snidump` currently passes the UDP payload of any UDP packet to
`tls_process_record`. QUIC Initial packets begin with a **long header** whose
first byte has the form `0b11xxxxxx` (values 0xC0–0xFF), which is not a valid
TLS `ContentType` byte (20–23). The function returns 0 immediately. QUIC
traffic on port 443 produces no output whatsoever — it is silently discarded.

### What QUIC Initial packets look like

```
Byte 0:  Header Form (1) | Fixed Bit (1) | Long Packet Type (2) | Reserved (2) | Packet Number Length (2)
         For Initial: 0b11000000 = 0xC0 (before header protection)
Bytes 1-4:   QUIC version (0x00000001 for QUIC v1)
Byte 5:      Destination Connection ID Length
Bytes 6..:   Destination Connection ID (0–20 bytes)
             Source Connection ID Length
             Source Connection ID (0–20 bytes)
             Token Length (variable-length integer)
             Token (0 or more bytes)
             Packet Length (variable-length integer)
             Packet Number (1–4 bytes, protected)
             Payload (protected)
```

The payload is encrypted, but QUIC Initial packets use a **publicly known
key** derived from the Destination Connection ID via HKDF-SHA256 (RFC 9001
§5.2). This is intentional — Initial packets carry the TLS handshake, and the
spec requires that passive observers (e.g., network monitors) can always read
them. The derivation uses a fixed salt and the label `"client in"`.

Inside the decrypted payload is a sequence of QUIC frames. One of them will be
a **CRYPTO frame** (type byte `0x06`) carrying the TLS ClientHello bytes. The
TLS ClientHello inside QUIC is structurally identical to a TLS 1.3 ClientHello
— including the SNI extension — so the existing `tls_process_Handshake_ClientHello`
parser can be reused once the QUIC framing is stripped.

### What a fix would require

1. **QUIC Initial packet detection.** Check that:
   - The transport is UDP.
   - Byte 0 `& 0xF0 == 0xC0` (long header, Initial type).
   - Bytes 1–4 are the QUIC v1 version (`0x00000001`). Other version values
     indicate a different QUIC version or a Version Negotiation packet.

2. **Variable-length header parsing.** Read the Destination Connection ID
   length, skip the DCID, read the Source Connection ID length, skip the SCID,
   skip the token, and read the packet length. All lengths use QUIC's
   variable-length integer encoding (RFC 9000 §16), where the two high bits of
   the first byte encode how many bytes the integer occupies (1, 2, 4, or 8).

3. **Initial key derivation** (RFC 9001 §5.2):
   ```
   initial_salt    = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a  (fixed, QUIC v1)
   initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
   client_secret  = HKDF-Expand-Label(initial_secret, "client in", "", 32)
   key            = HKDF-Expand-Label(client_secret, "quic key",  "", 16)
   iv             = HKDF-Expand-Label(client_secret, "quic iv",   "", 12)
   hp_key         = HKDF-Expand-Label(client_secret, "quic hp",   "", 16)
   ```
   This requires SHA-256 and AES-128, which are available in most system
   crypto libraries (OpenSSL, libgcrypt, or the BSD/Linux kernel via AF_ALG).
   Alternatively, a self-contained HKDF-SHA256 + AES-128-GCM implementation
   is ~300 lines of C.

4. **Header protection removal** (RFC 9001 §5.4). The packet number field and
   the low bits of byte 0 are masked. The mask is computed as
   `AES-128-ECB(hp_key, sample)` where `sample` is 16 bytes taken from the
   encrypted payload at offset 4 from the packet number field. XOR the mask
   to recover the real packet number length and packet number.

5. **Payload decryption** with AES-128-GCM using the derived `key` and a
   nonce constructed from `iv XOR packet_number` (left-padded to 12 bytes).

6. **CRYPTO frame assembly.** A single QUIC Initial may contain multiple
   CRYPTO frames (offsets within the TLS stream). They must be assembled in
   order before the TLS parser is called — effectively a simplified version of
   the TCP reassembly problem, but bounded because all CRYPTO data for the
   ClientHello fits within the Initial flight and QUIC guarantees ordering
   within a connection.

7. **Feed into existing TLS parser.** Pass the assembled TLS ClientHello bytes
   to `tls_process_record` — the existing code handles the rest.

### Effort estimate

The crypto primitives (HKDF + AES-128-GCM) are the largest piece. Using
OpenSSL (adding `-lssl -lcrypto` to the Makefile): ~200 lines. The QUIC
header parser and frame extractor: ~250 lines. Total: approximately 450 lines
of new C, plus the OpenSSL dependency, plus updating the BPF default to
include UDP port 443.

### Impact

Chrome, Firefox, and all major CDN-fronted services (Google, Cloudflare,
Meta, Akamai) prefer QUIC when available. On a modern client network, 30–60%
of HTTPS connections may use QUIC. Without this feature, snidump silently
misses a substantial and growing fraction of hostnames on port 443.
