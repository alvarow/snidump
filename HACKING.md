# snidump — Code Notes

## Architecture

The program has three compilation units:

| File | Role |
|------|------|
| `snidump.c` | Entry point, `pcap` loop, packet dissector (Ethernet → IP → TCP/UDP) |
| `tls.c` | TLS record / ClientHello parser; calls back into `snidump.c` with the SNI value |
| `http.c` | HTTP/1.1 request parser using PCRE; calls back into `snidump.c` with the Host value |

Public surfaces are declared in `tls_api.h` and `http_api.h`. Both engines
communicate results upward via function pointers registered at startup.

### Headers used as implementation files

`tls.h` and `aux.h` contain definitions (struct instances, function bodies)
not just declarations. This is intentional — they are included by exactly one
`.c` file each — but it means they must not be included from more than one
translation unit or the linker will report duplicate symbols. `colors.h` had
this problem and was fixed; `tls.h` has the same latent risk.

### Global state

The parser relies on several globals set by `my_pcap_handler` and read by
`sni_handler`:

- `ip` — pointer into the current packet buffer (IP header)
- `src_port`, `dst_port` — ports from the current TCP/UDP header
- `flag_sni_available` — set to 1 when a hostname is found

This is safe because `pcap_loop` is single-threaded and the callback is
synchronous. It would need to become per-packet context if multi-threading
were ever added.

## Known limitations

### No TCP stream reassembly

Each packet payload is parsed independently. A TLS ClientHello that is
fragmented across two or more TCP segments will not be matched. In practice
the ClientHello almost always fits in one segment, but this is not guaranteed.

### IPv4 only

The Ethernet-type check (`ETHERTYPE_IP = 0x0800`) and the IP version check
(`IP_V == 4`) mean IPv6 traffic is silently discarded.

### HTTP/1.0 not matched

The request-line regex in `http.c` requires `HTTP/1.1`. HTTP/1.0 requests do
not match. TLS SNI is unaffected.

### Signal handler safety

`signal_handler` calls `pcap_breakloop()` which is not listed as
async-signal-safe by POSIX. In practice it works because `pcap_breakloop`
just sets a flag, but it is technically undefined behavior. A strictly
conforming fix would set a `volatile sig_atomic_t` flag in the handler and
check it in the loop.

Additionally, `SIGSEGV` is handled with the same handler. Calling any
non-trivial function from a `SIGSEGV` handler is undefined behavior; the
process is in an indeterminate state when the handler fires. The handler
should either do nothing or call `_exit()`.

### `read_bytes` return type

`read_bytes()` (in `aux.h`) returns `size_t`, which is unsigned. All call
sites check the return value with `<= 0`. The comparison works correctly
because `size_t` can only be 0 (failure) or positive (success), but it
triggers signed/unsigned comparison warnings and is semantically misleading.

## Bugs fixed

| Commit area | Bug |
|-------------|-----|
| `tls.c:674` | `#if __debug__` (lowercase) → `#if __DEBUG__`; ChangeCipherSpec debug print never fired |
| `tls.h` | `n24toh32` big-endian branch used `>>` instead of `<<`; produced 0 on big-endian hosts |
| `tls.h` | Removed dead `#if/#else` on `n24toh32` — both branches were identical; byte-by-byte extraction is endian-neutral |
| `tls.h` / `snidump.c` | `__BIG_ENDIAN__` → `__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__`; the old macro is not reliable on all targets |
| `snidump.c` | `assert()` for packet-length bounds checks → proper `if`/`return`; asserts are no-ops in release builds (`NDEBUG`) |
| `snidump.c` | Reject `-i` and `-r` used together; previously the second `pcap_open_*` call silently leaked the first handle |
| `snidump.c` | `sni_handler` printed hostname one byte per `fprintf` call → single `%.*s` call |
| `colors.h` | `istty_stdout`/`istty_stderr` defined in header → `extern` declarations; definitions moved to `snidump.c` |
| `snidump.c` | `IPPROTO_TCP`/`IPPROTO_UDP` `#define` wrapped in `#ifndef` guards to avoid redefinition warnings |
| `http.c` | Added underflow guard before `headers_length` subtraction |
