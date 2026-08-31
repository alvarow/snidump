/* kontaxis 2015-10-31 */

#include <arpa/inet.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <pcap/pcap.h>

#if !__DEBUG__
#define NDEBUG
#endif
#include <assert.h>

#include "tls_api.h"
#include "http_api.h"

#include "colors.h"

uint8_t istty_stdout;
uint8_t istty_stderr;

/* References:
 *   netinet/ether.h
 *   netinet/ip.h
 *   netinet/ip6.h
 *   netinet/tcp.h
 *   netinet/udp.h
 */

/* Ethernet */

#define ETH_ALEN 6

struct ether_header
{
  uint8_t  ether_dhost[ETH_ALEN];
  uint8_t  ether_shost[ETH_ALEN];
  uint16_t ether_type;
} __attribute__ ((__packed__));

#define ETHERTYPE_IP   0x0800
#define ETHERTYPE_IPV6 0x86DD

#if !__NO_ETHERNET__
#define SIZE_ETHERNET sizeof(struct ether_header)
#else
#define SIZE_ETHERNET 0
#endif

/* IPv4 */

struct my_iphdr
{
  uint8_t  vhl;
#define IP_HL(ip) (((ip)->vhl) & 0x0F)
#define IP_V(ip)  (((ip)->vhl) >> 4)
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
} __attribute__ ((__packed__));

#define MIN_SIZE_IP (sizeof(struct my_iphdr))

#define IPVERSION 4

/* IPv6 */

struct my_ip6hdr
{
  uint8_t  vcf[4];       /* version(4) + traffic class(8) + flow label(20) */
  uint16_t payload_len;
  uint8_t  next_hdr;
  uint8_t  hop_limit;
  uint8_t  saddr[16];
  uint8_t  daddr[16];
} __attribute__ ((__packed__));

#define MIN_SIZE_IP6 (sizeof(struct my_ip6hdr))

/* Protocol / next-header numbers */

#ifndef IPPROTO_TCP
#define IPPROTO_TCP       6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP      17
#endif
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS   0   /* IPv6 Hop-by-Hop Options */
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING  43   /* IPv6 Routing Header */
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44   /* IPv6 Fragment Header */
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH       51   /* Authentication Header */
#endif
#ifndef IPPROTO_ESP
#define IPPROTO_ESP      50   /* Encapsulating Security Payload */
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS  60   /* IPv6 Destination Options */
#endif
#ifndef IPPROTO_MH
#define IPPROTO_MH      135   /* IPv6 Mobility Header */
#endif

/* TCP */

struct my_tcphdr
{
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  uint8_t  res1doff;
#define TCP_OFF(th) (((th)->res1doff & 0xF0) >> 4)
  uint8_t  flags;
#define TCP_FIN  (0x1 << 0)
#define TCP_SYN  (0x1 << 1)
#define TCP_RST  (0x1 << 2)
#define TCP_PUSH (0x1 << 3)
#define TCP_ACK  (0x1 << 4)
#define TCP_URG  (0x1 << 5)
#define TCP_ECE  (0x1 << 6)
#define TCP_CWR  (0x1 << 7)
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
} __attribute__ ((__packed__));

#define MIN_SIZE_TCP (sizeof(struct my_tcphdr))

/* UDP */

struct udphdr
{
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
} __attribute__ ((__packed__));

#define MIN_SIZE_UDP (sizeof(struct udphdr))


/* converts 16 bits in host byte order to 16 bits in network byte order */
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define h16ton16(n) (n)
#else
#define h16ton16(n) \
((uint16_t) (((uint16_t) n) << 8) | (uint16_t) (((uint16_t) n) >> 8))
#endif

#define n16toh16(n) h16ton16(n)

#define likely(x)   __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)


/* -------------------------------------------------------------------------
 * IPv6 extension header walker
 *
 * Walks the extension header chain starting at 'offset' bytes into 'packet',
 * with 'next_hdr' being the first next-header value to examine.
 *
 * On success: sets *transport_offset and returns IPPROTO_TCP or IPPROTO_UDP.
 * On failure: returns -1 (unrecognised, encrypted, or non-first fragment).
 * -------------------------------------------------------------------------
 */
static int ip6_skip_exthdr(const uint8_t *packet, uint32_t caplen,
	uint32_t offset, uint8_t next_hdr, uint32_t *transport_offset)
{
	while (1) {
		switch (next_hdr) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				*transport_offset = offset;
				return next_hdr;

			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_DSTOPTS:
			case IPPROTO_MH:
				/* Generic extension header.
				 * Byte 0: next header.  Byte 1: length in 8-octet units,
				 * not counting the first 8 bytes.
				 * Total size = (len + 1) * 8.
				 */
				if (offset + 2 > caplen) return -1;
				next_hdr = packet[offset];
				offset  += (uint32_t)(packet[offset + 1] + 1) * 8;
				if (offset > caplen) return -1;
				break;

			case IPPROTO_FRAGMENT: {
				/* Fragment header is always 8 bytes.
				 * Bytes 2-3 hold the fragment offset (high 13 bits) + flags.
				 * If offset != 0 this is not the first fragment; the
				 * transport header is absent.
				 */
				if (offset + 8 > caplen) return -1;
				uint16_t frag_off =
					(uint16_t)((packet[offset + 2] << 8) | packet[offset + 3])
					& 0xFFF8;
				if (frag_off != 0) return -1;
				next_hdr = packet[offset];
				offset  += 8;
				break;
			}

			case IPPROTO_AH:
				/* Authentication Header.
				 * Byte 1: payload length in 4-octet units minus 2.
				 * Total size = (len + 2) * 4.
				 */
				if (offset + 2 > caplen) return -1;
				next_hdr = packet[offset];
				offset  += (uint32_t)(packet[offset + 1] + 2) * 4;
				if (offset > caplen) return -1;
				break;

			case IPPROTO_ESP:
			default:
				/* Cannot parse through ESP (encrypted).
				 * Unknown next-header: bail out.
				 */
				return -1;
		}
	}
}


/* -------------------------------------------------------------------------
 * Per-packet context
 * -------------------------------------------------------------------------
 */

struct packet_ctx {
	struct my_iphdr   *ip;    /* non-NULL for IPv4 packets */
	struct my_ip6hdr  *ip6;   /* non-NULL for IPv6 packets */
	uint8_t            is_ipv6;
	uint16_t           src_port;
	uint16_t           dst_port;
	uint8_t            flag_sni_available;
	pcap_dumper_t     *pcap_dumper_handle;
	uint8_t            opt_quiet;
	uint8_t            opt_timestamp;
	uint8_t            opt_json;
	uint32_t           opt_count;   /* 0 = unlimited */
	uint32_t           match_count;
	const char        *current_proto;
};

static struct packet_ctx *g_ctx;
static pcap_t *pcap_handle; /* forward declaration; defined in signal section */

static void timestamp_now(char *buf, size_t bufsz)
{
	time_t t;
	struct tm tmbuf;
	time(&t);
	strftime(buf, bufsz, "%Y-%m-%dT%H:%M:%SZ", gmtime_r(&t, &tmbuf));
}

/*
 * Write a JSON-escaped string to fp.
 * Escapes '"' and '\' per RFC 8259; control characters become \uXXXX.
 * Written directly to fp to avoid a potentially large stack buffer.
 */
static void json_write_escaped(FILE *fp, const uint8_t *s, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if      (s[i] == '"')  fputs("\\\"", fp);
		else if (s[i] == '\\') fputs("\\\\", fp);
		else if (s[i] < 0x20)  fprintf(fp, "\\u%04x", (unsigned)s[i]);
		else                   fputc(s[i], fp);
	}
}

/*
 * Format the source or destination IP address into buf.
 * IPv4: "w.x.y.z"
 * IPv6: "[addr]"  (brackets so "addr:port" is unambiguous)
 */
static void fmt_addr(char *buf, size_t bufsz,
	const struct packet_ctx *ctx, int src)
{
	if (ctx->ip6) {
		char addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6,
			src ? (const void *)ctx->ip6->saddr
			    : (const void *)ctx->ip6->daddr,
			addr, sizeof(addr));
		snprintf(buf, bufsz, "[%s]", addr);
	} else {
		const uint8_t *a = src
			? (const uint8_t *)&ctx->ip->saddr
			: (const uint8_t *)&ctx->ip->daddr;
		snprintf(buf, bufsz, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
	}
}

int sni_handler(uint8_t *host_name, uint16_t host_name_length)
{
	struct packet_ctx *ctx = g_ctx;
	char src_addr[INET6_ADDRSTRLEN + 2]; /* +2 for [ ] */
	char dst_addr[INET6_ADDRSTRLEN + 2];
	char ts[32];

	fmt_addr(src_addr, sizeof(src_addr), ctx, 1);
	fmt_addr(dst_addr, sizeof(dst_addr), ctx, 0);

	/*
	 * Strip an optional :port suffix from HTTP Host header values.
	 * e.g. "example.com:8080" -> host="example.com", host_port=8080
	 * TLS SNI never carries a port, so this only runs for HTTP.
	 *
	 * Scan from the right for the last ':' followed entirely by ASCII
	 * digits.  IPv6 bracket notation (e.g. "[::1]:8080") is handled
	 * correctly: the ']' before the ':' is not a digit, so the colon
	 * inside the brackets is never mis-identified as a port separator.
	 */
	uint16_t hostname_len = host_name_length;
	uint16_t host_port    = 0;
	if (ctx->current_proto[0] == 'H') { /* "HTTP" */
		int k;
		for (k = (int)host_name_length - 1; k > 0; k--) {
			if (host_name[k] == ':') {
				int m;
				unsigned long p = 0;
				for (m = k + 1; m < (int)host_name_length; m++) {
					if (host_name[m] < '0' || host_name[m] > '9') {
						p = 0;
						break;
					}
					p = p * 10 + (host_name[m] - '0');
				}
				if (p > 0 && p <= 65535 && m > k + 1) {
					host_port    = (uint16_t)p;
					hostname_len = (uint16_t)k;
				}
				break;
			}
		}
	}

	if (ctx->opt_json) {
		timestamp_now(ts, sizeof(ts));
		fprintf(stdout,
			"{\"time\":\"%s\",\"proto\":\"%s\","
			"\"src\":\"%s:%u\","
			"\"dst\":\"%s:%u\","
			"\"host\":\"",
			ts, ctx->current_proto,
			src_addr, n16toh16(ctx->src_port),
			dst_addr, n16toh16(ctx->dst_port));
		json_write_escaped(stdout, host_name, (int)hostname_len);
		if (host_port) {
			fprintf(stdout, "\",\"port\":%u}\n", host_port);
		} else {
			fputs("\"}\n", stdout);
		}
	} else {
		if (ctx->opt_timestamp) {
			timestamp_now(ts, sizeof(ts));
			fprintf(stdout, "%s ", ts);
		}
		fprintf(stdout, "%s:%u -> %s:[%u] ",
			src_addr, n16toh16(ctx->src_port),
			dst_addr, n16toh16(ctx->dst_port));
		CPRINT_STDOUT(C_RED_LIGHT, "%u:%.*s\n", hostname_len,
			(int)hostname_len, (char *)host_name);
	}

	ctx->flag_sni_available = 1;

	if (ctx->opt_count > 0 && ++ctx->match_count >= ctx->opt_count) {
		pcap_breakloop(pcap_handle);
	}

	return 0;
}


void my_pcap_handler(uint8_t *user, const struct pcap_pkthdr *header,
	const uint8_t *packet)
{
	struct packet_ctx *ctx = (struct packet_ctx *)user;
	g_ctx = ctx;

#if !__NO_ETHERNET__
	struct ether_header *ether;
#endif
	struct my_tcphdr *tcp;
	struct udphdr    *udp;

	uint8_t  *payload       = NULL;
	uint16_t  payload_length = 0;

	uint16_t r;

	if (header->caplen < header->len) {
#if __DEBUG__
		fprintf(stderr, "WARNING: caplen %u < len %u. Ignoring.\n",
			header->caplen, header->len);
#endif
		return;
	}

	/* -----------------------------------------------------------------
	 * Determine network-layer protocol (IPv4 or IPv6).
	 * ----------------------------------------------------------------- */

#if !__NO_ETHERNET__
	if (header->caplen < SIZE_ETHERNET) {
		return;
	}

	ether = (struct ether_header *)packet;

	if (ether->ether_type == h16ton16(ETHERTYPE_IP)) {
		ctx->is_ipv6 = 0;
	} else if (ether->ether_type == h16ton16(ETHERTYPE_IPV6)) {
		ctx->is_ipv6 = 1;
	} else {
#if __DEBUG__
		fprintf(stderr,
			"WARNING: ether_type 0x%04x is not IP or IPv6. Ignoring.\n",
			n16toh16(ether->ether_type));
#endif
		return;
	}

#else /* __NO_ETHERNET__: raw IP, check version nibble */

	if (header->caplen < 1) {
		return;
	}
	{
		uint8_t ver = packet[0] >> 4;
		if (ver == 4)      ctx->is_ipv6 = 0;
		else if (ver == 6) ctx->is_ipv6 = 1;
		else               return;
	}

#endif /* __NO_ETHERNET__ */

	/* -----------------------------------------------------------------
	 * Parse the IP or IPv6 header, then the transport header.
	 * ----------------------------------------------------------------- */

	if (!ctx->is_ipv6) {
		/* IPv4 */

		if (header->caplen < SIZE_ETHERNET + MIN_SIZE_IP) {
			return;
		}

		ctx->ip  = (struct my_iphdr *)(packet + SIZE_ETHERNET);
		ctx->ip6 = NULL;

		if (unlikely(IP_V(ctx->ip) != 4)) {
#if __DEBUG__
			fprintf(stderr, "WARNING: IP version != 4. Ignoring.\n");
#endif
			return;
		}

		switch (ctx->ip->protocol) {
			case IPPROTO_TCP: {
					if (header->caplen <
						SIZE_ETHERNET +
						(IP_HL(ctx->ip) * sizeof(uint32_t)) + MIN_SIZE_TCP) {
						return;
					}
					tcp = (struct my_tcphdr *)
						(packet + SIZE_ETHERNET +
						(IP_HL(ctx->ip) * sizeof(uint32_t)));
					ctx->src_port = tcp->source;
					ctx->dst_port = tcp->dest;

					if (header->caplen < SIZE_ETHERNET +
						(IP_HL(ctx->ip) * sizeof(uint32_t)) +
						(TCP_OFF(tcp) * sizeof(uint32_t))) {
						return;
					}
					payload = (uint8_t *)
						(packet + SIZE_ETHERNET +
						(IP_HL(ctx->ip) * sizeof(uint32_t)) +
						(TCP_OFF(tcp) * sizeof(uint32_t)));
					payload_length = header->caplen - SIZE_ETHERNET -
						(IP_HL(ctx->ip) * sizeof(uint32_t)) -
						(TCP_OFF(tcp) * sizeof(uint32_t));
				}
				break;
			case IPPROTO_UDP: {
					if (header->caplen <
						SIZE_ETHERNET +
						(IP_HL(ctx->ip) * sizeof(uint32_t)) + MIN_SIZE_UDP) {
						return;
					}
					udp = (struct udphdr *)
						(packet + SIZE_ETHERNET +
						(IP_HL(ctx->ip) * sizeof(uint32_t)));
					ctx->src_port = udp->source;
					ctx->dst_port = udp->dest;

					if (header->caplen < SIZE_ETHERNET +
						(IP_HL(ctx->ip) * sizeof(uint32_t)) +
						sizeof(struct udphdr)) {
						return;
					}
					payload = (uint8_t *)
						(packet + SIZE_ETHERNET +
						(IP_HL(ctx->ip) * sizeof(uint32_t)) +
						sizeof(struct udphdr));
					payload_length = header->caplen - SIZE_ETHERNET -
						(IP_HL(ctx->ip) * sizeof(uint32_t)) -
						sizeof(struct udphdr);
				}
				break;
			default:
#if __DEBUG__
				fprintf(stderr, "WARNING: ip->protocol == %u. Ignoring.\n",
					ctx->ip->protocol);
#endif
				return;
		}

	} else {
		/* IPv6 */

		uint32_t transport_offset;
		int proto;

		if (header->caplen < SIZE_ETHERNET + MIN_SIZE_IP6) {
			return;
		}

		ctx->ip6 = (struct my_ip6hdr *)(packet + SIZE_ETHERNET);
		ctx->ip  = NULL;

		proto = ip6_skip_exthdr(packet, header->caplen,
			(uint32_t)(SIZE_ETHERNET + MIN_SIZE_IP6),
			ctx->ip6->next_hdr,
			&transport_offset);

		if (proto < 0) {
#if __DEBUG__
			fprintf(stderr,
				"WARNING: IPv6 extension header walk failed. Ignoring.\n");
#endif
			return;
		}

		switch (proto) {
			case IPPROTO_TCP: {
					if (header->caplen < transport_offset + MIN_SIZE_TCP) {
						return;
					}
					tcp = (struct my_tcphdr *)(packet + transport_offset);
					ctx->src_port = tcp->source;
					ctx->dst_port = tcp->dest;

					if (header->caplen < transport_offset +
						(TCP_OFF(tcp) * sizeof(uint32_t))) {
						return;
					}
					payload = (uint8_t *)
						(packet + transport_offset +
						(TCP_OFF(tcp) * sizeof(uint32_t)));
					payload_length = header->caplen - transport_offset -
						(TCP_OFF(tcp) * sizeof(uint32_t));
				}
				break;
			case IPPROTO_UDP: {
					if (header->caplen < transport_offset + MIN_SIZE_UDP) {
						return;
					}
					udp = (struct udphdr *)(packet + transport_offset);
					ctx->src_port = udp->source;
					ctx->dst_port = udp->dest;

					if (header->caplen <
						transport_offset + sizeof(struct udphdr)) {
						return;
					}
					payload = (uint8_t *)
						(packet + transport_offset + sizeof(struct udphdr));
					payload_length = header->caplen - transport_offset -
						sizeof(struct udphdr);
				}
				break;
			default:
				return;
		}
	}

	/* Save to dump file (all BPF-matched packets). */
	if (ctx->pcap_dumper_handle) {
		pcap_dump((u_char *)ctx->pcap_dumper_handle, header, packet);
	}

#if __DEBUG__
	{
		char src_addr[INET6_ADDRSTRLEN + 2];
		char dst_addr[INET6_ADDRSTRLEN + 2];
		fmt_addr(src_addr, sizeof(src_addr), ctx, 1);
		fmt_addr(dst_addr, sizeof(dst_addr), ctx, 0);
		fprintf(stderr, "%s:%u -> %s:[%u] (payload:%u)\n",
			src_addr, n16toh16(ctx->src_port),
			dst_addr, n16toh16(ctx->dst_port),
			payload_length);
	}
#endif

	if (payload_length == 0 || payload == NULL) {
		return;
	}

	ctx->flag_sni_available = 0;

	ctx->current_proto = "TLS";
	r = tls_process_record(payload, payload_length);
#if __DEBUG__
	if (r < payload_length) {
		fprintf(stderr, "tls_process_record() processed %u / %u bytes.\n",
			r, payload_length);
	}
#endif
	if (ctx->flag_sni_available || r != 0) {
		return;
	}

	ctx->current_proto = "HTTP";
	r = http_process_request(payload, payload_length);
#if __DEBUG__
	if (r < payload_length) {
		fprintf(stderr, "http_process_request() processed %u / %u bytes.\n",
			r, payload_length);
	}
#endif
	(void)r;
}


/* -------------------------------------------------------------------------
 * Signal handling
 * -------------------------------------------------------------------------
 */

static volatile sig_atomic_t g_stop = 0;

static void signal_handler(int signum)
{
	(void)signum;
	g_stop = 1;
	pcap_breakloop(pcap_handle);
}


#define SNAPLEN 65535
#define PROMISCUOUS ((opt_flags & OPT_PROMISCUOUS) == OPT_PROMISCUOUS)
#define PCAP_TIMEOUT 1000

#define BPF_DEFAULT \
	"(ip or ip6) and tcp and " \
	"(tcp[tcpflags] & tcp-push == tcp-push) and " \
	"(dst port 80 or dst port 443)"
#define BPF bpf_s
#define BPF_OPTIMIZE 1

int main(int argc, char *argv[])
{
	char *device_name;
	char *trace_fname;

	char errbuf[PCAP_ERRBUF_SIZE];

	char *bpf_s;
	char *bpf_default = BPF_DEFAULT;
	struct bpf_program bpf;

	char *dump_fname;
#if __DEBUG__
	unsigned int dump_fname_sz;
#endif

	struct pcap_stat ps;
	struct sigaction act;

	int i;
#define OPT_DEVICE      (0x1 << 0)
#define OPT_PROMISCUOUS (0x1 << 1)
#define OPT_BPF         (0x1 << 2)
#define OPT_TRACE       (0x1 << 3)
#define OPT_DUMP        (0x1 << 4)
#define OPT_QUIET       (0x1 << 5)
#define OPT_TIMESTAMP   (0x1 << 6)
#define OPT_JSON        (0x1 << 7)
	uint8_t opt_flags;

	struct packet_ctx pkt_ctx;

	opt_flags = 0;
	memset(&pkt_ctx, 0, sizeof(pkt_ctx));
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

	CPRINT_INIT

	while ((i = getopt(argc, argv, "hf:pi:r:w:qtjc:")) != -1) {
		switch (i) {
			case 'h':
				fprintf(stderr,
					"Use: %s [-h] [-f bpf] [-p] [-q] [-t] [-j] [-c N] "
					"-i interface [-w dump.pcap]\n", argv[0]);
				fprintf(stderr,
					"Use: %s [-h] [-f bpf] [-p] [-q] [-t] [-j] [-c N] "
					"-r trce.pcap  [-w dump.pcap]\n", argv[0]);
				fprintf(stderr,
					"  -p    promiscuous mode (live capture only)\n");
				fprintf(stderr,
					"  -f bpf  override the default BPF capture filter\n");
				fprintf(stderr,
					"  -w file  write matched packets to a pcap file\n");
				fprintf(stderr,
					"  -q    quiet: suppress informational output\n");
				fprintf(stderr,
					"  -t    prefix each hostname line with a UTC timestamp\n");
				fprintf(stderr,
					"  -j    JSON output (one object per line, includes timestamp)\n");
				fprintf(stderr,
					"  -c N  stop after N hostname matches\n");
				return -1;
			case 'f':
				bpf_s = optarg;
				opt_flags |= OPT_BPF;
				break;
			case 'p':
				opt_flags |= OPT_PROMISCUOUS;
				break;
			case 'i':
				device_name = optarg;
				opt_flags |= OPT_DEVICE;
				break;
			case 'r':
				trace_fname = optarg;
				opt_flags |= OPT_TRACE;
				break;
			case 'w':
				dump_fname = optarg;
				opt_flags |= OPT_DUMP;
				break;
			case 'q':
				opt_flags |= OPT_QUIET;
				break;
			case 't':
				opt_flags |= OPT_TIMESTAMP;
				break;
			case 'j':
				opt_flags |= OPT_JSON;
				break;
			case 'c': {
				char *end;
				unsigned long n = strtoul(optarg, &end, 10);
				if (*end != '\0' || n == 0) {
					fprintf(stderr,
						"[FATAL] -c requires a positive integer.\n");
					return -1;
				}
				pkt_ctx.opt_count = (uint32_t)(n > UINT32_MAX
					? UINT32_MAX : n);
				break;
			}
			default:
				break;
		}
	}

	pkt_ctx.opt_quiet     = (opt_flags & OPT_QUIET)     ? 1 : 0;
	pkt_ctx.opt_timestamp = (opt_flags & OPT_TIMESTAMP) ? 1 : 0;
	pkt_ctx.opt_json      = (opt_flags & OPT_JSON)      ? 1 : 0;

	if (!(opt_flags & (OPT_DEVICE | OPT_TRACE))) {
		fprintf(stderr,
			"[FATAL] Missing target interface or trace file. Try -h.\n");
		return -1;
	}

	if ((opt_flags & OPT_DEVICE) && (opt_flags & OPT_TRACE)) {
		fprintf(stderr,
			"[FATAL] Cannot specify both -i and -r. Try -h.\n");
		return -1;
	}

#if __DEBUG__
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
	fprintf(stderr, "BIG_ENDIAN\n");
#else
	fprintf(stderr, "LITTLE_ENDIAN\n");
#endif
#endif

	if (!pkt_ctx.opt_quiet) {
		fprintf(stdout, "[*] PID: %u\n", getpid());
	}

	if (opt_flags & OPT_DEVICE) {
		if (!pkt_ctx.opt_quiet) {
			fprintf(stdout, "[*] Device: '%s'\n", device_name);
			fprintf(stdout, "[*] Promiscuous: %d\n", PROMISCUOUS);
		}

		if (!(pcap_handle =
			pcap_open_live(device_name, SNAPLEN, PROMISCUOUS, PCAP_TIMEOUT,
			errbuf))) {
			fprintf(stderr, "[FATAL] %s\n", errbuf);
			return -1;
		}
	}

	if (opt_flags & OPT_TRACE) {
		if (!pkt_ctx.opt_quiet) {
			fprintf(stdout, "[*] Trace: '%s'\n", trace_fname);
		}

		if (!(pcap_handle =
			pcap_open_offline(trace_fname, errbuf))) {
			fprintf(stderr, "[FATAL] %s\n", errbuf);
			return -1;
		}
	}

	{
#if !__NO_ETHERNET__
		const int   expected_dlt      = DLT_EN10MB;
		const char *expected_dlt_name = "EN10MB (Ethernet)";
#else
		const int   expected_dlt      = DLT_RAW;
		const char *expected_dlt_name = "RAW (raw IP)";
#endif
		int dlt = pcap_datalink(pcap_handle);
		if (!pkt_ctx.opt_quiet) {
			fprintf(stdout, "[*] Datalink: %s (%d)\n",
				pcap_datalink_val_to_name(dlt), dlt);
		}
		if (dlt != expected_dlt) {
			fprintf(stderr,
				"[FATAL] Unexpected datalink type %s (%d); expected %s. "
				"Use snidump_noether for raw-IP interfaces.\n",
				pcap_datalink_val_to_name(dlt), dlt, expected_dlt_name);
			pcap_close(pcap_handle);
			return -1;
		}
	}

	if (!(opt_flags & OPT_BPF)) {
		bpf_s = bpf_default;
		opt_flags |= OPT_BPF;
	}

	if (!pkt_ctx.opt_quiet) {
		fprintf(stdout, "[*] BPF: '%s'\n", bpf_s);
	}

	if (pcap_compile(pcap_handle, &bpf, BPF, BPF_OPTIMIZE,
		PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "[FATAL] Couldn't parse filter. %s\n",
			pcap_geterr(pcap_handle));
		pcap_close(pcap_handle);
		return -1;
	}

	if (pcap_setfilter(pcap_handle, &bpf) == -1) {
		fprintf(stderr, "[FATAL] Couldn't install filter. %s\n",
			pcap_geterr(pcap_handle));
		pcap_close(pcap_handle);
		return -1;
	}

	pcap_freecode(&bpf);

	pkt_ctx.pcap_dumper_handle = NULL;

	if (opt_flags & OPT_DUMP) {
		if (!pkt_ctx.opt_quiet) {
			fprintf(stdout, "[*] Dump: '%s'\n", dump_fname);
		}

		if (!(pkt_ctx.pcap_dumper_handle =
			pcap_dump_open(pcap_handle, dump_fname))) {
			fprintf(stderr, "[WARNING] Couldn't create dump file. %s\n",
				pcap_geterr(pcap_handle));
		}
	}

#if __DEBUG__
	if ((!(opt_flags & OPT_DUMP)) && (opt_flags & OPT_DEVICE)) {
		dump_fname_sz = strlen(device_name) + strlen(".pcap") + 1;
		if ((dump_fname = malloc(sizeof(char) * dump_fname_sz)) == NULL) {
			perror("malloc");
			return -1;
		}
		snprintf(dump_fname, dump_fname_sz, "%s%s", device_name, ".pcap");
		if (!(pkt_ctx.pcap_dumper_handle =
			pcap_dump_open(pcap_handle, dump_fname))) {
			pcap_geterr(pcap_handle);
		}
	}
#endif

	tls_set_callback_handshake_clienthello_servername(&sni_handler);
	http_set_callback_request_host(&sni_handler);

	http_init();

	act.sa_handler = signal_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	if (sigaction(SIGINT, &act, NULL)) {
		perror("sigaction");
		if (!pkt_ctx.opt_quiet) {
			fprintf(stderr,
				"[WARNING] Failed to set signal handler for SIGINT.\n");
		}
	}

	if (sigaction(SIGTERM, &act, NULL)) {
		perror("sigaction");
		if (!pkt_ctx.opt_quiet) {
			fprintf(stderr,
				"[WARNING] Failed to set signal handler for SIGTERM.\n");
		}
	}

	if (!pkt_ctx.opt_quiet) {
		fprintf(stderr, "Capturing ...\n");
	}

	if (pcap_loop(pcap_handle, -1, &my_pcap_handler, (u_char *)&pkt_ctx)
		== -1) {
		fprintf(stderr, "[FATAL] pcap_loop failed. %s\n",
			pcap_geterr(pcap_handle));
	}

	if (!(opt_flags & OPT_TRACE) && !pkt_ctx.opt_quiet) {
		if (pcap_stats(pcap_handle, &ps) == -1) {
			fprintf(stderr, "pcap_stats failed. %s\n",
				pcap_geterr(pcap_handle));
		} else {
			fprintf(stderr, "%u packets received\n", ps.ps_recv);
			fprintf(stderr, "%u packets dropped\n",
				ps.ps_drop + ps.ps_ifdrop);
		}
	}

	pcap_close(pcap_handle);

	http_cleanup();

	if (pkt_ctx.pcap_dumper_handle) {
		pcap_dump_close(pkt_ctx.pcap_dumper_handle);

		if (!pkt_ctx.opt_quiet) {
			fprintf(stderr, "Written %s\n", dump_fname);
		}
		if (!(opt_flags & OPT_DUMP)) {
			free(dump_fname);
		}
	}

	if (!pkt_ctx.opt_quiet) {
		fprintf(stderr, "Goodbye\n");
	}

	return 0;
}
