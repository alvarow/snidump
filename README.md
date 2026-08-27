# snidump

Extracts the Server Name Indication (SNI) field from TLS ClientHello messages
(RFC 4366) and the Host header from HTTP/1.1 requests (RFC 2616).  Supports
both IPv4 and IPv6.

Input is either a live network interface (optionally in promiscuous mode) or a
PCAP trace file.  Output can be plain text, timestamped, or JSON.  Matching
packets can be saved to a new PCAP file.

```
Use: snidump [-h] [-f bpf] [-p] [-q] [-t] [-j] -i interface [-w dump.pcap]
Use: snidump [-h] [-f bpf] [-p] [-q] [-t] [-j] -r trce.pcap  [-w dump.pcap]

  -q  quiet: suppress informational output
  -t  prefix each hostname line with a UTC timestamp
  -j  JSON output (one object per line, includes timestamp)
```

**Dependencies:** `libpcap`, `libpcre`

## Quick start

```sh
# Debian / Ubuntu
sudo apt install libpcap-dev libpcre3-dev
make

# FreeBSD (libpcap is in base)
sudo pkg install pcre
make
```

## Sample output

```
# ./bin/snidump -p -i eth0
[*] PID: 1234
[*] Device: 'eth0'
[*] Promiscuous: 1
[*] Datalink: EN10MB (1)
[*] BPF: '(ip or ip6) and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and (dst port 80 or dst port 443)'
Capturing ...
192.168.0.4:53072 -> 192.30.252.130:[443] 14:www.github.com
192.168.0.4:53073 -> 192.30.252.130:[443] 10:github.com
[2001:db8::1]:52001 -> [2001:4860:4860::8888]:[443] 14:www.google.com
192.168.0.6:47232 -> 74.125.226.48:[80] 14:www.google.com

91 packets received
0 packets dropped
Goodbye
```

### JSON output (`-j`)

```sh
./bin/snidump -q -j -i eth0
```

```json
{"time":"2026-08-27T14:23:01Z","proto":"TLS","src":"192.168.0.4:53072","dst":"192.30.252.130:443","host":"www.github.com"}
{"time":"2026-08-27T14:23:02Z","proto":"HTTP","src":"192.168.0.6:47232","dst":"74.125.226.48:80","host":"www.google.com"}
{"time":"2026-08-27T14:23:03Z","proto":"TLS","src":"[2001:db8::1]:52001","dst":"[2001:4860:4860::8888]:443","host":"www.google.com"}
```

## Documentation

| File | Contents |
|------|----------|
| `USAGE.md` | Full flag reference, output formats, and annotated examples |
| `HACKING.md` | Architecture notes, design decisions, and fixed-bug table |
| `TODO.md` | TCP stream reassembly and QUIC/HTTP3 deep-dives |

## Running as a service

The `contrib/` directory contains ready-to-use service files.

### Linux — systemd

```sh
# 1. Install binary
sudo cp bin/snidump /usr/local/bin/

# 2. Create log directory and dedicated user
sudo useradd -r -s /sbin/nologin snidump
sudo mkdir -p /var/log/snidump
sudo chown snidump:snidump /var/log/snidump

# 3. Install and enable the unit
sudo cp contrib/snidump.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now snidump

# 4. Install log rotation
sudo cp contrib/snidump.logrotate /etc/logrotate.d/snidump
```

Edit `/etc/systemd/system/snidump.service` to change the interface (`-i eth0`)
or other flags before enabling.  The unit runs as an unprivileged user with
only `CAP_NET_RAW` granted via `AmbientCapabilities`; no root required.

```sh
journalctl -u snidump -f              # errors / service events
tail -f /var/log/snidump/hosts.jsonl  # hostname events
```

### FreeBSD — rc.d

```sh
# 1. Install binary
sudo cp bin/snidump /usr/local/bin/

# 2. Install rc script
sudo cp contrib/snidump.rc /usr/local/etc/rc.d/snidump
sudo chmod +x /usr/local/etc/rc.d/snidump

# 3. Enable in /etc/rc.conf
echo 'snidump_enable="YES"'    | sudo tee -a /etc/rc.conf
echo 'snidump_interface="em0"' | sudo tee -a /etc/rc.conf

# 4. Start
sudo service snidump start
sudo service snidump status
```

Add to `/etc/newsyslog.conf` for log rotation:

```
/var/log/snidump/hosts.jsonl  snidump:snidump  640  30  *  @T00  CZ
```
