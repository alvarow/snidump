# snidump — Usage Guide

`snidump` captures network traffic and extracts:
- The **SNI hostname** from TLS ClientHello messages (RFC 4366)
- The **Host header** from plaintext HTTP/1.1 requests (RFC 2616)

It reads from a live network interface or a pre-recorded PCAP file and can
write matching packets to a new PCAP file.  Both IPv4 and IPv6 are supported.

## Building

```sh
make          # release builds: bin/snidump  bin/snidump_noether
make debug    # debug  builds: bin/snidump_dbg  bin/snidump_noether_dbg
```

Two variants are produced:

| Binary | Description |
|--------|-------------|
| `snidump` | Standard build; expects Ethernet frames (DLT\_EN10MB). Handles both IPv4 and IPv6. |
| `snidump_noether` | Compiled with `-D__NO_ETHERNET__`; skips the Ethernet header. Use on tunnel / raw-IP interfaces (e.g., `tun0`, `gif0`). Detects IPv4 vs IPv6 from the version nibble. |

**Dependencies:** `libpcap`, `libpcre2`

```sh
# Debian / Ubuntu
sudo apt install libpcap-dev libpcre2-dev

# FreeBSD / pfSense (libpcap is in base)
sudo pkg install pcre2
make CC=clang CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"
```

## Synopsis

```
snidump [-h] [-f bpf] [-p] [-q] [-t] [-j] [-c N] -i interface [-w dump.pcap]
snidump [-h] [-f bpf] [-p] [-q] [-t] [-j] [-c N] -r trace.pcap  [-w dump.pcap]
```

| Flag | Argument | Description |
|------|----------|-------------|
| `-i` | interface | Live capture on the named interface |
| `-r` | file.pcap | Read from a PCAP trace file instead of a live interface |
| `-p` | — | Enable promiscuous mode (live capture only) |
| `-f` | bpf-filter | Override the default BPF filter |
| `-w` | out.pcap | Write matched packets to a PCAP file |
| `-q` | — | Quiet: suppress all informational output; only hostnames go to stdout |
| `-t` | — | Prefix each hostname line with a UTC timestamp |
| `-j` | — | JSON output — one object per line, includes timestamp (implies `-t` format) |
| `-c` | N | Stop after N hostname matches |
| `-h` | — | Print usage and exit |

Exactly one of `-i` or `-r` is required. `-i` and `-r` cannot be combined.

## Output formats

### Default (plain text)

```
<src-ip>:<src-port> -> <dst-ip>:[<dst-port>] <len>:<hostname>
```

IPv4 example:
```
192.168.1.10:52001 -> 140.82.121.4:[443] 14:www.github.com
```

IPv6 example (addresses are bracketed to delimit them from the port):
```
[2001:db8::1]:52001 -> [2001:db8::2]:[443] 14:www.github.com
```

The destination port appears in square brackets. For TLS the length prefix is
the byte-length of the SNI value; for HTTP it is the byte-length of the Host
header value (after stripping any explicit port).

Informational messages and statistics go to stderr. Hostnames always go to
stdout, making it straightforward to redirect or pipe them independently.

### With `-t` (timestamp prefix)

```
2026-08-27T14:23:01Z 192.168.1.10:52001 -> 140.82.121.4:[443] 14:www.github.com
```

### With `-j` (JSON, one object per line)

```json
{"time":"2026-08-27T14:23:01Z","proto":"TLS","src":"192.168.1.10:52001","dst":"140.82.121.4:443","host":"www.github.com"}
{"time":"2026-08-27T14:23:02Z","proto":"HTTP","src":"192.168.1.10:52100","dst":"93.184.216.34:80","host":"example.com"}
{"time":"2026-08-27T14:23:03Z","proto":"HTTP","src":"192.168.1.10:52200","dst":"93.184.216.34:8080","host":"example.com","port":8080}
{"time":"2026-08-27T14:23:04Z","proto":"TLS","src":"[2001:db8::1]:52300","dst":"[2001:4860:4860::8888]:443","host":"www.google.com"}
```

Fields: `time` (UTC ISO 8601), `proto` (`TLS` or `HTTP`), `src`, `dst`
(`address:port`; IPv6 addresses are bracketed), `host`, `port` (optional —
present only when an HTTP `Host` header carries an explicit port number, e.g.
`Host: example.com:8080`).

## Default BPF filter

```
(ip or ip6) and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and (dst port 80 or dst port 443)
```

This targets TCP segments with the PSH flag set going to port 80 (HTTP) or
443 (HTTPS/TLS), on both IPv4 and IPv6.  Override with `-f` when you need
different ports or protocols.

The PSH flag heuristic is intentional: without TCP stream reassembly a
fragmented ClientHello is unprocessable regardless of the BPF, so filtering
to PSH segments (which almost always carry complete application writes) reduces
noise without missing anything the tool could actually parse.

---

## Examples

### 1 — Live capture on an interface (requires root / CAP\_NET\_RAW)

```sh
sudo ./bin/snidump -i eth0
```

Sample output:

```
[*] PID: 4721
[*] Device: 'eth0'
[*] Promiscuous: 0
[*] Datalink: EN10MB (1)
[*] BPF: '(ip or ip6) and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and (dst port 80 or dst port 443)'
Capturing ...
192.168.1.10:52001 -> 140.82.121.4:[443] 14:www.github.com
192.168.1.10:52002 -> 142.250.185.78:[443] 14:www.google.com
[2001:db8::1]:52003 -> [2001:4860:4860::8888]:[443] 14:www.google.com
192.168.1.10:52004 -> 151.101.1.140:[80] 10:example.com
^C
312 packets received
0 packets dropped
Goodbye
```

### 2 — Live capture in promiscuous mode (see all traffic on the segment)

```sh
sudo ./bin/snidump -p -i eth0
```

### 3 — Read from a saved PCAP file

```sh
./bin/snidump -r capture.pcap
```

No root privileges are needed when reading from a file.

### 4 — Quiet mode: hostnames only, no informational output

```sh
sudo ./bin/snidump -q -i eth0
```

Only hostname lines go to stdout. Useful when the output is piped directly
into another tool.

### 5 — Timestamped output

```sh
sudo ./bin/snidump -t -i eth0
```

```
2026-08-27T14:23:01Z 192.168.1.10:52001 -> 140.82.121.4:[443] 14:www.github.com
```

### 6 — JSON output

```sh
sudo ./bin/snidump -j -i eth0
```

Each hostname event is emitted as a self-contained JSON object, one per line
(NDJSON / JSON Lines format). Suitable for ingestion by `jq`, Splunk,
Elasticsearch, etc.

```sh
# Extract only TLS hostnames with jq
sudo ./bin/snidump -jq -i eth0 | jq -r 'select(.proto=="TLS") | .host'
```

### 7 — Save matching packets to a PCAP file

```sh
sudo ./bin/snidump -i eth0 -w tls_hosts.pcap
```

The dump file contains all packets that matched the BPF filter, in standard
`pcap` format readable by Wireshark, `tcpdump`, etc.

### 8 — Monitor a non-standard TLS port

Override the BPF filter to capture TLS on port 8443 in addition to 443:

```sh
sudo ./bin/snidump -i eth0 \
  -f '(ip or ip6) and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and (dst port 443 or dst port 8443)'
```

### 9 — Monitor plaintext HTTP on a custom port

```sh
sudo ./bin/snidump -i eth0 \
  -f '(ip or ip6) and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and dst port 8080'
```

### 10 — Capture both TCP and UDP traffic

Include UDP to catch any non-standard setups:

```sh
sudo ./bin/snidump -i eth0 \
  -f '(ip or ip6) and ((tcp and (tcp[tcpflags] & tcp-push == tcp-push)) or udp) and (dst port 80 or dst port 443)'
```

### 11 — Tunnel / raw-IP interface (no Ethernet header)

Use the `snidump_noether` binary for interfaces that deliver raw IP frames,
such as VPN tunnels (`tun0`) or GIF tunnels (`gif0` on FreeBSD):

```sh
sudo ./bin/snidump_noether -i tun0
```

Both IPv4 and IPv6 are handled automatically; the version is determined from
the first byte of each raw IP frame.

### 12 — Log hostnames to a file while printing to the terminal

```sh
sudo ./bin/snidump -i eth0 | tee hosts.log
```

Because informational messages go to stderr and hostnames go to stdout, this
captures only hostnames in `hosts.log`.

### 13 — Offline analysis pipeline: extract unique hostnames, sorted

```sh
./bin/snidump -r big_capture.pcap | awk '{print $NF}' | sort -u
```

The last field on each output line is `<len>:<hostname>`; cut the length
prefix with `cut`:

```sh
./bin/snidump -r big_capture.pcap \
  | awk '{print $NF}' \
  | cut -d: -f2- \
  | sort -u > unique_hosts.txt
```

With JSON output, use `jq`:

```sh
./bin/snidump -jq -r big_capture.pcap \
  | jq -r '.host' | sort -u > unique_hosts.txt
```

---

## Notes

### IPv6
Both IPv4 and IPv6 are supported. IPv6 extension headers (Hop-by-Hop,
Routing, Destination Options, Fragment, AH) are walked transparently to
locate the TCP/UDP transport layer. Non-first fragments and ESP-encapsulated
packets are skipped. IPv6 addresses in the output are bracketed
(`[addr]:port`) to distinguish them from the port number.

### Fragmented packets
A TLS ClientHello spread across multiple TCP segments will not be reassembled;
the SNI will be missed for those sessions. The tool operates on individual
packet payloads, not TCP streams. In practice this is rare on standard MTU
links (the ClientHello almost always fits in a single segment). See `TODO.md`
for a discussion of what full reassembly would require.

### HTTP/2 (h2)
HTTP/2 runs over TLS; the SNI is extracted at the TLS handshake layer before
any HTTP/2 framing is seen, so HTTP/2 hostnames are captured correctly.

### HTTP methods supported
The HTTP engine matches: `GET`, `POST`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`,
`TRACE`, `CONNECT`, `PATCH`, and the WebDAV methods `PROPFIND`, `PROPPATCH`,
`MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`. Both `HTTP/1.0` and `HTTP/1.1`
request lines are recognised.

### QUIC / HTTP/3
QUIC (UDP port 443) uses a different framing for the TLS ClientHello and
cannot be parsed by the current code. See `TODO.md` for details.

### Datalink type check
At startup snidump checks the datalink type reported by libpcap and exits
with a fatal error if it does not match the compiled-in expectation (`EN10MB`
for the standard binary, `RAW` for `snidump_noether`). This prevents silent
misparsing on interfaces with unexpected link-layer framing (e.g., running
`snidump` on a loopback interface that delivers `DLT_NULL` frames).

### Privileges
Live capture requires the process to have read access to the network interface,
typically root or a user in the `wireshark` / `pcap` group. Offline reading
(`-r`) requires only read access to the file.

On Linux you can grant the capability instead of running as root:

```sh
sudo setcap cap_net_raw+eip ./bin/snidump
./bin/snidump -i eth0
```
