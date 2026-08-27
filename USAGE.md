# snidump — Usage Guide

`snidump` captures network traffic and extracts:
- The **SNI hostname** from TLS ClientHello messages (RFC 4366)
- The **Host header** from plaintext HTTP/1.1 requests (RFC 2616)

It reads from a live network interface or a pre-recorded PCAP file and can
write matching packets to a new PCAP file.

## Building

```sh
make          # release builds: bin/snidump  bin/snidump_noether
make debug    # debug  builds: bin/snidump_dbg  bin/snidump_noether_dbg
```

Two variants are produced:

| Binary | Description |
|--------|-------------|
| `snidump` | Standard build; expects Ethernet frames (DLT\_EN10MB) |
| `snidump_noether` | Compiled with `-D__NO_ETHERNET__`; skips the 14-byte Ethernet header. Use on tunnel / raw-IP interfaces (e.g., `tun0`, `gif0`). |

**Dependencies:** `libpcap`, `libpcre`

```sh
# Debian / Ubuntu
sudo apt install libpcap-dev libpcre3-dev

# FreeBSD
sudo pkg install pcre
# libpcap is in base on FreeBSD
```

## Synopsis

```
snidump [-h] [-f bpf] [-p] -i interface [-w dump.pcap]
snidump [-h] [-f bpf] [-p] -r trace.pcap  [-w dump.pcap]
```

| Flag | Argument | Description |
|------|----------|-------------|
| `-i` | interface | Live capture on the named interface |
| `-r` | file.pcap | Read from a PCAP trace file instead of a live interface |
| `-p` | — | Enable promiscuous mode (live capture only) |
| `-f` | bpf-filter | Override the default BPF filter |
| `-w` | out.pcap | Write matched packets to a PCAP file |
| `-h` | — | Print usage and exit |

Exactly one of `-i` or `-r` is required.

## Output format

Each line written to stdout represents one observed hostname:

```
<src-ip>:<src-port> -> <dst-ip>:[<dst-port>] <len>:<hostname>
```

The destination port is shown in square brackets. For TLS the length is the
byte-length of the SNI value; for HTTP it is the byte-length of the Host
header value.

Informational messages and statistics go to stderr.

## Default BPF filter

```
ip and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and (dst port 80 or dst port 443)
```

This targets TCP segments with the PSH flag set (data-carrying) going to port
80 (HTTP) or 443 (HTTPS/TLS). Override with `-f` when you need different ports
or protocols.

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
[*] BPF: 'ip and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and (dst port 80 or dst port 443)'
Capturing ...
192.168.1.10:52001 -> 140.82.121.4:[443] 14:www.github.com
192.168.1.10:52002 -> 142.250.185.78:[443] 14:www.google.com
192.168.1.10:52003 -> 151.101.1.140:[80] 10:example.com
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

### 4 — Save matching packets to a PCAP file

```sh
sudo ./bin/snidump -i eth0 -w tls_hosts.pcap
```

The dump file contains only the packets that matched the BPF filter, in
standard `pcap` format readable by Wireshark, `tcpdump`, etc.

### 5 — Monitor a non-standard TLS port

Override the BPF filter to capture TLS on port 8443 in addition to 443:

```sh
sudo ./bin/snidump -i eth0 \
  -f 'ip and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and (dst port 443 or dst port 8443)'
```

### 6 — Monitor plaintext HTTP on a custom port

```sh
sudo ./bin/snidump -i eth0 \
  -f 'ip and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and dst port 8080'
```

### 7 — Capture both TCP and UDP traffic

Some DNS-over-HTTPS or QUIC setups use UDP. The default filter is TCP-only;
include UDP as well:

```sh
sudo ./bin/snidump -i eth0 \
  -f 'ip and (tcp[tcpflags] & tcp-push == tcp-push or udp) and (dst port 80 or dst port 443)'
```

### 8 — Tunnel / raw-IP interface (no Ethernet header)

Use the `snidump_noether` binary for interfaces that deliver raw IP frames,
such as VPN tunnels (`tun0`) or GIF tunnels (`gif0` on FreeBSD):

```sh
sudo ./bin/snidump_noether -i tun0
```

### 9 — Log hostnames to a file while printing to the terminal

```sh
sudo ./bin/snidump -i eth0 | tee hosts.log
```

Because informational messages go to stderr and hostnames go to stdout, this
captures only hostnames in `hosts.log`.

### 10 — Offline analysis pipeline: extract unique hostnames, sorted

```sh
./bin/snidump -r big_capture.pcap | awk '{print $NF}' | sort -u
```

The last field on each output line is `<len>:<hostname>`; cut the length
prefix with a second `awk` or `cut`:

```sh
./bin/snidump -r big_capture.pcap \
  | awk '{print $NF}' \
  | cut -d: -f2- \
  | sort -u > unique_hosts.txt
```

---

## Notes

### IPv6
`snidump` processes IPv4 packets only. IPv6 is silently skipped.

### Fragmented packets
A TLS ClientHello that is spread across multiple TCP segments will not be
fully reassembled; the SNI will be missed for those sessions. The tool works
on individual packet payloads, not TCP streams.

### HTTP/2 (h2)
HTTP/2 traffic travels over TLS; the SNI is extracted at the TLS handshake
layer before any HTTP/2 framing is seen, so HTTP/2 hostnames are captured
correctly.

### HTTP/1.0
The HTTP engine matches `HTTP/1.1` request lines only; `HTTP/1.0` requests
are not matched.

### Privileges
Live capture requires the process to have read access to the network interface,
typically root or a user in the `wireshark` / `pcap` group. Offline reading
(`-r`) requires only read access to the file.

On Linux you can grant the capability instead of running as root:

```sh
sudo setcap cap_net_raw+eip ./bin/snidump
./bin/snidump -i eth0
```
