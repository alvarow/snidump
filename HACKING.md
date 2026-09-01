# snidump — Code Notes

## Architecture

The program has three compilation units:

| File | Role |
|------|------|
| `snidump.c` | Entry point, `pcap` loop, packet dissector (Ethernet/raw → IP/IPv6 → TCP/UDP) |
| `tls.c` | TLS record / ClientHello parser; calls back into `snidump.c` with the SNI value |
| `http.c` | HTTP/1.1 request parser using PCRE; calls back into `snidump.c` with the Host value |

Public surfaces are declared in `tls_api.h` and `http_api.h`. Both engines
communicate results upward via function pointers registered at startup.

### Per-packet context

All mutable state for a single packet is consolidated in `struct packet_ctx`,
defined in `snidump.c`. A single instance lives in `main()` and is passed to
`pcap_loop` as the user pointer, which threads it through to `my_pcap_handler`
on every callback invocation.

`sni_handler` has a fixed signature imposed by the callback API and cannot
receive the context directly. A static pointer `g_ctx` is set to the current
context at the top of `my_pcap_handler` so `sni_handler` can reach it. This
is safe because `pcap_loop` is single-threaded and the callback is synchronous.

`pcap_handle` and the `g_stop` signal flag remain file-scope statics because
the signal handler also needs them.

### `tls.c` internals

All TLS wire-format structs, string tables, and helper functions are
**private to `tls.c`** (`static` storage class). Nothing in `tls.h` has
associated storage — the header contains only constants and macros.

`read_bytes()` is also private to `tls.c`. It returns `int`: `-1` on error,
`0` for a zero-byte read, or the byte count on success. All call sites check
`< 0` for failure.

`aux.h` is retained as a placeholder; its former content (`struct
read_bytes_ctx` and `read_bytes`) was moved into `tls.c`.

### Signal handling

`SIGINT` and `SIGTERM` both invoke a minimal handler that sets
`volatile sig_atomic_t g_stop = 1` and calls `pcap_breakloop()`.
`pcap_breakloop` is technically not async-signal-safe per POSIX, but in
all practical libpcap implementations it only sets a flag inside the handle
struct — the same approach used by `tcpdump`. `SIGSEGV` is intentionally
not handled; a real segfault should produce a core dump.

---

## snidump vs snidump_noether

### What pcap delivers

When pcap hands a packet to the callback it includes the **link-layer header**
— the bytes that precede the IP header. The header format depends on the
interface type, reported as a DLT (Data Link Type) constant:

| Interface | DLT | Link-layer header | Use |
|-----------|-----|-------------------|-----|
| Ethernet, Wi-Fi, most physical NICs | `DLT_EN10MB` (1) | 14 bytes: 6 dst MAC + 6 src MAC + 2 EtherType | `snidump` |
| TUN interfaces (`tun0`, OpenVPN TUN, WireGuard) | `DLT_RAW` (12) | None — packet starts at IP byte 0 | `snidump_noether` |
| FreeBSD GIF/GRE tunnels (`gif0`, `gre0`) | `DLT_RAW` (12) | None | `snidump_noether` |
| TAP interfaces | `DLT_EN10MB` (1) | Full Ethernet frame | `snidump` |
| BSD loopback (`lo0` on macOS/FreeBSD) | `DLT_NULL` (0) | 4-byte protocol family word | **Neither** (unsupported) |
| Linux `any` pseudo-interface | `DLT_LINUX_SLL` (113) | 16-byte cooked header | **Neither** (unsupported) |

### The compile-time flag

`snidump_noether` is built with `-D__NO_ETHERNET__`, which sets:

```c
#if !__NO_ETHERNET__
#define SIZE_ETHERNET  sizeof(struct ether_header)  /* 14 */
#else
#define SIZE_ETHERNET  0
#endif
```

`SIZE_ETHERNET` is used in every pointer calculation that locates the IP
header and the transport header. Making it a compile-time constant lets the
compiler fold all those additions and eliminate the link-type conditional
entirely from the hot path, keeping the per-packet callback branchless with
respect to link-layer format.

The Ethernet type-checking block (which dispatches on `ETHERTYPE_IP` vs
`ETHERTYPE_IPV6`) is also `#if !__NO_ETHERNET__` and compiled out completely
in `snidump_noether`. Instead, the version nibble of byte 0
(`packet[0] >> 4`) distinguishes IPv4 from IPv6 at runtime, since both TUN
and other `DLT_RAW` sources deliver raw IP frames of either version.

### The startup datalink guard

At startup, `pcap_datalink()` is called and compared against the expected
value for the compiled variant:

```c
#if !__NO_ETHERNET__
    const int expected_dlt = DLT_EN10MB;
#else
    const int expected_dlt = DLT_RAW;
#endif
```

A mismatch produces a fatal error and exits immediately. For example, running
`snidump` on a TUN interface prints:

```
[FATAL] Unexpected datalink type RAW (12); expected EN10MB (Ethernet).
        Use snidump_noether for raw-IP interfaces.
```

Without this guard, `snidump` on a `DLT_RAW` interface would silently
interpret the first 14 bytes of every IP header as a fake Ethernet header,
then attempt to parse the remaining bytes as IP, producing garbage output
with no indication anything was wrong.

### Decision guide

```
Ethernet or Wi-Fi NIC (eth0, em0, en0, wlan0)  →  snidump
TAP virtual interface                            →  snidump   (TAP is Ethernet-level)
TUN virtual interface (tun0, VPN tunnel)         →  snidump_noether
FreeBSD gif/gre tunnel (gif0, gre0)              →  snidump_noether
Not sure?  Run snidump; if you see the [FATAL]   →  switch to snidump_noether
           message above, switch binaries.
```

---

## Known limitations

### No TCP stream reassembly

Each packet payload is parsed independently. A TLS ClientHello fragmented
across two or more TCP segments will not be matched. In practice the
ClientHello almost always fits in a single segment (typically 300–500 bytes,
well under a 1460-byte Ethernet MTU). Fragmentation becomes a problem on
links with small MTUs (PPPoE, some VPN configurations). See `TODO.md` for
what a full reassembly implementation would require.

### QUIC / HTTP3

QUIC (UDP port 443) encapsulates the TLS ClientHello inside its own packet
framing and requires decryption of the QUIC Initial packet before the SNI is
accessible. The current code passes UDP payloads to `tls_process_record`,
which rejects them immediately because the QUIC long-header byte is not a
valid TLS ContentType. See `TODO.md` for the full implementation plan.

### Signal handler strictness

`pcap_breakloop()` is called from the signal handler. It is not listed as
async-signal-safe by POSIX, though all known libpcap implementations make it
safe in practice (it only sets a flag). A strictly conforming implementation
would use a self-pipe or `pcap_setnonblock` with a manual select loop.

---

## Building the pfSense package

`make pkg-build` requires BSD make and FreeBSD's `bsd.port.mk` (ports tree).
It cannot run on Linux — FreeBSD containers do not work inside a Linux Docker
host because they require the FreeBSD kernel ABI.

### Option 1 — KVM VM on Linux (recommended)

See `docs/freebsd-build-vm.md` for full instructions. Short version:

```sh
# On the FreeBSD 15 VM, in the repo:
pkg install -y pcre2
make CC=clang CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"
cp bin/snidump bin/snidump_noether builds/amd64/freebsd-15/
make pkg-build
```

Copy the result back:

```sh
scp root@<vm-ip>:snidump/pkg/work/pkg/pfSense-pkg-snidump-*.pkg .
```

### Option 2 — GitHub Actions (CI)

The `vmactions/freebsd-vm` action provides a real FreeBSD VM in GitHub's
runners. Add `.github/workflows/pkg.yml`:

```yaml
name: Build pfSense package
on: [push, workflow_dispatch]
jobs:
  pkg:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vmactions/freebsd-vm@v1
        with:
          release: "15.0"
          usesh: true
          prepare: pkg install -y pcre2
          run: |
            make CC=clang CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"
            cp bin/snidump bin/snidump_noether builds/amd64/freebsd-15/
            make pkg-build
      - uses: actions/upload-artifact@v4
        with:
          name: pfSense-pkg-snidump
          path: pkg/work/pkg/*.pkg
```

---

## Bugs fixed

| Area | Bug |
|------|-----|
| `tls.c:674` | `#if __debug__` (lowercase) → `#if __DEBUG__`; ChangeCipherSpec debug print never fired in any build |
| `tls.h` | `n24toh32` big-endian branch used `>>` instead of `<<`; produced 0 on big-endian hosts |
| `tls.h` / `snidump.c` | `__BIG_ENDIAN__` → `__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__`; the old macro is undefined on some big-endian targets |
| `snidump.c` | `assert()` for packet-length bounds checks → proper `if`/`return`; asserts are no-ops in release builds (`NDEBUG`) |
| `snidump.c` | Reject `-i` and `-r` used together; previously the second `pcap_open_*` call silently leaked the first handle |
| `snidump.c` | `sni_handler` printed hostname one byte per `fprintf` call → single `%.*s` |
| `snidump.c` | `pcap_datalink()` check added at startup to catch wrong-binary / wrong-interface mismatches |
| `colors.h` | `istty_stdout`/`istty_stderr` defined in header → `extern` declarations; definitions moved to `snidump.c` |
| `colors.h` | `CPRINT_STDERR`/`CPRINT_STDOUT` used `__VA_ARGS__` without `##`; no-arg calls failed to compile in debug builds |
| `snidump.c` | `IPPROTO_TCP`/`IPPROTO_UDP` `#define` wrapped in `#ifndef` guards to avoid redefinition warnings |
| `http.c` | Migrated from PCRE1 (`libpcre`) to PCRE2 (`libpcre2-8`); PCRE1 is end-of-life and absent from modern FreeBSD/pfSense. `pcre2_match_data` objects are allocated once at init and reused per-packet to avoid heap allocation in the hot path |
| `http.c` | Added length underflow guard before `headers_length` subtraction |
| `tls.c` / `aux.h` | `read_bytes()` returned `size_t`; callers checked `<= 0` (unsigned comparison); return type changed to `int`, callers updated to `< 0` |
| `tls.h` / `aux.h` | Function and variable definitions in headers → moved to `tls.c` as `static`; headers now contain only constants and macros |
