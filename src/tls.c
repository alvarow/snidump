/* kontaxis 2015-10-31 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>

#include <assert.h>

#include "tls.h"
#include "ciphersuites.h"

#include "tls_api.h"

#include "colors.h"

/* -------------------------------------------------------------------------
 * read_bytes — bounded cursor over a flat buffer
 * ------------------------------------------------------------------------- */

struct read_bytes_ctx {
	void  *in;
	size_t read_bytes_available;
};

/*
 * Copies exactly must_read_bytes from ctx->in into out, or fails.
 * Passing NULL for out skips the copy but still advances the cursor.
 *
 * Returns must_read_bytes on success, -1 on failure (not enough data or
 * null ctx).  A must_read_bytes of 0 always succeeds and returns 0.
 */
static int read_bytes(struct read_bytes_ctx *ctx, void *out,
	size_t must_read_bytes)
{
	if (!ctx) {
		return -1;
	}

	if (must_read_bytes == 0) {
		return 0;
	}

	if (ctx->read_bytes_available < must_read_bytes) {
		return -1;
	}

	if (~((size_t)0x0) - (size_t)ctx->in < must_read_bytes) {
		return -1;
	}

	if (out != NULL) {
		memcpy(out, ctx->in, must_read_bytes);
	}
	ctx->in = ((uint8_t *)ctx->in) + must_read_bytes;
	ctx->read_bytes_available -= must_read_bytes;

	return (int)must_read_bytes;
}

/* -------------------------------------------------------------------------
 * TLS wire-format structs (private to this TU)
 * -------------------------------------------------------------------------
 * These are file-scope variables used as scratch space while parsing a
 * single packet.  The tool is single-threaded so this is safe.
 * -------------------------------------------------------------------------
 */

static struct __attribute__((__packed__))
{
	uint8_t  TLSPlaintext__type;
	uint8_t  TLSPlaintext__versionMajor;
	uint8_t  TLSPlaintext__versionMinor;
	uint16_t TLSPlaintext__length;
} tls_TLSPlaintext_header =
{
	.TLSPlaintext__versionMajor = PROTOCOLMAJOR,
	.TLSPlaintext__versionMinor = PROTOCOLMINOR
};

static struct __attribute__((__packed__))
{
	uint8_t type;
} tls_ChangeCipherSpec;

static struct __attribute__((__packed__))
{
	uint8_t Alert__level;
	uint8_t Alert__description;
} tls_Alert;

static struct __attribute__((__packed__))
{
	uint8_t  Handshake__type;
	uint8_t  Handshake__length[3];
} tls_Handshake_header;

static struct __attribute__((__packed__))
{
	uint8_t  client_version_major;
	uint8_t  client_version_minor;
	uint32_t random_gmt_unix_time;
	uint8_t  random_random_bytes[28];
} tls_ClientHello_intro =
{
	.client_version_major = PROTOCOLMAJOR,
	.client_version_minor = PROTOCOLMINOR
};

static struct __attribute__((__packed__))
{
	uint8_t session_id_length;
	uint8_t session_id[32];
} tls_ClientHello_session =
{
	.session_id_length = 0
};

static struct __attribute__((__packed__))
{
	uint16_t cipher_suites_length;
	uint16_t cipher_suites[(0xFFFF - 1)/sizeof(uint16_t)];
} tls_ClientHello_ciphersuites =
{
	.cipher_suites_length = 0x0200,
	.cipher_suites[0] = h16ton16(CIPHERSUITEMANDATORY)
};

static struct __attribute__((__packed__))
{
	uint8_t compression_methods_length;
	uint8_t compression_methods[0xFF];
} tls_ClientHello_compression =
{
	.compression_methods_length = 0x1,
	.compression_methods[0] = 0x0
};

static struct __attribute__((__packed__))
{
	uint16_t extensions_length;
	uint8_t  extensions[0xFFFF];
} tls_extensions;

static struct __attribute__((__packed__))
{
	uint16_t extension_type;
	uint16_t extension_data_length;
	uint8_t  extension_data[0xFFFF];
} tls_Extension;

static struct __attribute__((__packed__))
{
	uint8_t  name_type;
	uint16_t host_name_length;
	uint8_t  host_name[0xFFFF];
} tls_ServerName;

static struct __attribute__((__packed__))
{
	uint16_t server_name_list_length;
	uint8_t  server_name_list[0xFFFF];
} tls_ServerNameList;

/* -------------------------------------------------------------------------
 * Debug-only helpers (string tables and type-to-string functions)
 * -------------------------------------------------------------------------
 */

#if __DEBUG__

static const char *tls_ExtensionNames[TLS_EXTENSIONS_MAX + 1] = {
	"server_name", /* 0 */
};

#define TLS_EXTENSION_TXT(n) \
  (((n) >= 0 && (n) <= TLS_EXTENSIONS_MAX) ? tls_ExtensionNames[(n)] \
    : "UNKNOWN")


static const char *tls_ContentType(uint8_t n)
{
	switch (n) {
		case SSL3_RT_CHANGE_CIPHER_SPEC: return "change_cipher_spec";
		case SSL3_RT_ALERT:              return "alert";
		case SSL3_RT_HANDSHAKE:          return "handshake";
		case SSL3_RT_APPLICATION_DATA:   return "application_data";
		default:                         return "UNKNOWN";
	}
}

static const char *tls_AlertLevel(uint8_t n)
{
	switch (n) {
		case SSL3_AL_WARNING: return "warning";
		case SSL3_AL_FATAL:   return "fatal";
		default:              return "UNKNOWN";
	}
}

static const char *tls_AlertDescription(uint8_t n)
{
	switch (n) {
		case SSL3_AD_CLOSE_NOTIFY:        return "close_notify";
		case SSL3_AD_UNEXPECTED_MESSAGE:  return "unexpected_message";
		case SSL3_AD_BAD_RECORD_MAC:      return "bad_record_mac";
		case 21: return "decryption_failed_RESERVED";
		case 22: return "record_overflow";
		case 30: return "decompression_failure";
		case 40: return "handshake_failure";
		case 41: return "no_certificate_RESERVED";
		case 42: return "bad_certificate";
		case 43: return "unsupported_certificate";
		case 44: return "certificate_revoked";
		case 45: return "certificate_expired";
		case 46: return "certificate_unknown";
		case 47: return "illegal_parameter";
		case 48: return "unknown_ca";
		case 49: return "access_denied";
		case 50: return "decode_error";
		case 51: return "decrypt_error";
		default: return "UNKNOWN";
	}
}

static const char *tls_HandshakeType(uint8_t n)
{
	switch (n) {
		case SSL3_MT_HELLO_REQUEST:       return "hello_request";
		case SSL3_MT_CLIENT_HELLO:        return "client_hello";
		case SSL3_MT_SERVER_HELLO:        return "server_hello";
		case SSL3_MT_CERTIFICATE:         return "certificate";
		case SSL3_MT_SERVER_KEY_EXCHANGE: return "server_key_exchange";
		case SSL3_MT_CERTIFICATE_REQUEST: return "certificate_request";
		case SSL3_MT_SERVER_DONE:         return "server_hello_done";
		case SSL3_MT_CERTIFICATE_VERIFY:  return "certificate_verify";
		case SSL3_MT_CLIENT_KEY_EXCHANGE: return "client_key_exchange";
		case SSL3_MT_FINISHED:            return "finished";
		default:                          return "UNKNOWN";
	}
}

#endif /* __DEBUG__ */

/* -------------------------------------------------------------------------
 * TLS processing
 * -------------------------------------------------------------------------
 */

static void *tls_in;

static int (*callback_handshake_clienthello_servername)(uint8_t *, uint16_t);

int tls_set_callback_handshake_clienthello_servername(
	int (*handler)(uint8_t *, uint16_t))
{
	callback_handshake_clienthello_servername = handler;
	return 0;
}

static int tls_process_Handshake_ClientHello_Extensions_ServerName()
{
	size_t must_read_bytes;
	size_t must_read_name_list_bytes;

#if __DEBUG__
	unsigned int i;
#endif

	must_read_bytes = n16toh16(tls_Extension.extension_data_length);

	if (must_read_bytes <
		sizeof(tls_ServerNameList.server_name_list_length)) {
#if __DEBUG__
		fprintf(stderr,
			"Size of tls_ServerNameList.server_name_list_length is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in, &tls_ServerNameList.server_name_list_length,
		sizeof(tls_ServerNameList.server_name_list_length)) < 0) {
#if __DEBUG__
		fprintf(stderr,
			"Not enough bytes for tls_ServerNameList.server_name_list_length.\n");
#endif
		return 0;
	}
	must_read_bytes -= sizeof(tls_ServerNameList.server_name_list_length);

#if __DEBUG__
	fprintf(stderr,
		"TLS ClientHello Extension SNI list length: %u\n",
		n16toh16(tls_ServerNameList.server_name_list_length));
#endif

	if (must_read_bytes < n16toh16(tls_ServerNameList.server_name_list_length)) {
#if __DEBUG__
		fprintf(stderr,
			"tls_ServerNameList.server_name_list_length is not expected.\n");
#endif
		return 0;
	}

	must_read_name_list_bytes =
		n16toh16(tls_ServerNameList.server_name_list_length);

	while (must_read_name_list_bytes > 0) {
		if (must_read_name_list_bytes < sizeof(tls_ServerName.name_type)) {
#if __DEBUG__
			fprintf(stderr, "Size of tls_ServerName.name_type is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, &tls_ServerName.name_type,
			sizeof(tls_ServerName.name_type)) < 0) {
#if __DEBUG__
			fprintf(stderr, "Not enough bytes for tls_ServerName.name_type.\n");
#endif
			return 0;
		}
		must_read_name_list_bytes -= sizeof(tls_ServerName.name_type);

#if __DEBUG__
		fprintf(stderr,
			"TLS ClientHello Extension SNI Type: (%u)\n",
			tls_ServerName.name_type);
#endif

		if (must_read_name_list_bytes < sizeof(tls_ServerName.host_name_length)) {
#if __DEBUG__
			fprintf(stderr,
				"Size of tls_ServerName.host_name_length is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, &tls_ServerName.host_name_length,
			sizeof(tls_ServerName.host_name_length)) < 0) {
#if __DEBUG__
			fprintf(stderr,
				"Not enough bytes for tls_ServerName.host_name_length.\n");
#endif
			return 0;
		}
		must_read_name_list_bytes -= sizeof(tls_ServerName.host_name_length);

#if __DEBUG__
		fprintf(stderr,
			"TLS ClientHello Extension SNI length: %u\n",
			n16toh16(tls_ServerName.host_name_length));
#endif

		if (must_read_name_list_bytes <
			n16toh16(tls_ServerName.host_name_length)) {
#if __DEBUG__
			fprintf(stderr,
				"tls_ServerName.host_name_length is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, &tls_ServerName.host_name,
			n16toh16(tls_ServerName.host_name_length)) < 0) {
#if __DEBUG__
			fprintf(stderr, "Not enough bytes for tls_ServerName.host_name.\n");
#endif
			return 0;
		}
		must_read_name_list_bytes -= n16toh16(tls_ServerName.host_name_length);

#if __DEBUG__
		fprintf(stderr, "TLS ClientHello Extension SNI: ");
		for (i = 0; i < n16toh16(tls_ServerName.host_name_length); i++) {
			fprintf(stderr, "%c", tls_ServerName.host_name[i]);
		}
		fprintf(stderr, " (0x");
		for (i = 0; i < n16toh16(tls_ServerName.host_name_length); i++) {
			fprintf(stderr, "%02x", (uint8_t)tls_ServerName.host_name[i]);
		}
		fprintf(stderr, ")\n");
#endif

		if (callback_handshake_clienthello_servername != NULL) {
			callback_handshake_clienthello_servername(
				tls_ServerName.host_name,
				n16toh16(tls_ServerName.host_name_length));
		}
	}
	must_read_bytes -= n16toh16(tls_ServerNameList.server_name_list_length);

	return n16toh16(tls_Extension.extension_data_length) - must_read_bytes;
}

static int tls_process_Handshake_ClientHello_Extensions()
{
	size_t must_read_bytes;
	unsigned int r;

	must_read_bytes = n16toh16(tls_extensions.extensions_length);

	while (must_read_bytes > 0) {
		if (must_read_bytes < sizeof(tls_Extension.extension_type)) {
#if __DEBUG__
			fprintf(stderr,
				"Size of tls_Extension.extension_type is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, &tls_Extension.extension_type,
			sizeof(tls_Extension.extension_type)) < 0) {
#if __DEBUG__
			fprintf(stderr,
				"Not enough bytes for tls_Extension.extension_type.\n");
#endif
			return 0;
		}
		must_read_bytes -= sizeof(tls_Extension.extension_type);

#if __DEBUG__
		fprintf(stderr, "TLS ClientHello Extension Type: %s (0x%04x)\n",
			TLS_EXTENSION_TXT(n16toh16(tls_Extension.extension_type)),
			n16toh16(tls_Extension.extension_type));
#endif

		if (must_read_bytes < sizeof(tls_Extension.extension_data_length)) {
#if __DEBUG__
			fprintf(stderr,
				"Size of tls_Extension.extension_data_length is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, &tls_Extension.extension_data_length,
			sizeof(tls_Extension.extension_data_length)) < 0) {
#if __DEBUG__
			fprintf(stderr,
				"Not enough bytes for tls_Extension.extension_data_length.\n");
#endif
			return 0;
		}
		must_read_bytes -= sizeof(tls_Extension.extension_data_length);

#if __DEBUG__
		fprintf(stderr, "TLS ClientHello Extension Length: %u\n",
			n16toh16(tls_Extension.extension_data_length));
#endif

		if (must_read_bytes < n16toh16(tls_Extension.extension_data_length)) {
#if __DEBUG__
			fprintf(stderr,
				"tls_Extension.extension_data_length is not expected.\n");
#endif
			return 0;
		}

		switch (n16toh16(tls_Extension.extension_type)) {
			case TLS_EXTENSION_TYPE_SERVER_NAME:
				if ((r = tls_process_Handshake_ClientHello_Extensions_ServerName())
					== 0) {
					return r;
				}
				must_read_bytes -= r;
				break;

			default:
				if (read_bytes(tls_in, NULL,
					n16toh16(tls_Extension.extension_data_length)) < 0) {
#if __DEBUG__
					fprintf(stderr, "Not enough bytes to match "
						"tls_Extension.extension_data_length.\n");
#endif
					return 0;
				}
				must_read_bytes -= n16toh16(tls_Extension.extension_data_length);
				break;
		}
	}

	return n16toh16(tls_extensions.extensions_length);
}

/*
 * Processes a TLS Handshake ClientHello message.
 * Returns number of bytes consumed, or 0 on parse error.
 */
static int tls_process_Handshake_ClientHello()
{
#if __DEBUG__
	unsigned int i;
	time_t t;
	struct tm *ts;
	char time_buf[80];
#endif

	unsigned int r;
	size_t must_read_bytes;

	must_read_bytes = n24toh32(tls_Handshake_header.Handshake__length);

	if (must_read_bytes < sizeof(tls_ClientHello_intro)) {
#if __DEBUG__
		fprintf(stderr, "Size of tls_ClientHello_intro is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in, &tls_ClientHello_intro,
		sizeof(tls_ClientHello_intro)) < 0) {
#if __DEBUG__
		fprintf(stderr, "Not enough bytes for ClientHello_intro.\n");
#endif
		return 0;
	}
	must_read_bytes -= sizeof(tls_ClientHello_intro);

#if __DEBUG__
	fprintf(stderr, "TLS ClientHello Version: %s (0x%02x%02x)\n",
		PROTOCOL_TXT(tls_ClientHello_intro.client_version_minor),
		tls_ClientHello_intro.client_version_major,
		tls_ClientHello_intro.client_version_minor);

	t = ntohl(tls_ClientHello_intro.random_gmt_unix_time);
	ts = localtime(&t);
	if (strftime(time_buf, sizeof(time_buf), "%b %d, %Y %H:%M:%S %Z", ts)) {
		fprintf(stderr, "TLS ClientHello Random gmt_unix_time: %s (%u)\n",
			time_buf, ntohl(tls_ClientHello_intro.random_gmt_unix_time));
	}

	fprintf(stderr, "TLS ClientHello Random random_bytes: ");
	for (i = 0; i < 28; i++)
		fprintf(stderr, "%02x", tls_ClientHello_intro.random_random_bytes[i]);
	fprintf(stderr, "\n");
#endif

	if (must_read_bytes < sizeof(tls_ClientHello_session.session_id_length)) {
#if __DEBUG__
		fprintf(stderr,
			"Size of tls_ClientHello_session.session_id_length is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in, &tls_ClientHello_session.session_id_length,
		sizeof(tls_ClientHello_session.session_id_length)) < 0) {
#if __DEBUG__
		fprintf(stderr,
			"Not enough bytes for tls_ClientHello_session.session_id_length.\n");
#endif
		return 0;
	}
	must_read_bytes -= sizeof(tls_ClientHello_session.session_id_length);

#if __DEBUG__
	fprintf(stderr, "TLS ClientHello Session ID Length: %u\n",
		tls_ClientHello_session.session_id_length);
#endif

	if (must_read_bytes < tls_ClientHello_session.session_id_length) {
#if __DEBUG__
		fprintf(stderr,
			"tls_ClientHello_session.session_id_length is not expected.\n");
#endif
		return 0;
	}

	if (tls_ClientHello_session.session_id_length) {
		if (tls_ClientHello_session.session_id_length >
			sizeof(tls_ClientHello_session.session_id)) {
#if __DEBUG__
			fprintf(stderr,
				"Size of tls_ClientHello_session.session_id is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, tls_ClientHello_session.session_id,
			tls_ClientHello_session.session_id_length) < 0) {
#if __DEBUG__
			fprintf(stderr,
				"Not enough bytes to match tls_ClientHello_session.session_id.\n");
#endif
			return 0;
		}
		must_read_bytes -= tls_ClientHello_session.session_id_length;
	}

#if __DEBUG__
	for (i = 0; i < tls_ClientHello_session.session_id_length; i++) {
		if (i == 0) fprintf(stderr, "TLS ClientHello Session ID: ");
		fprintf(stderr, "%02x", tls_ClientHello_session.session_id[i]);
		if (i + 1 == tls_ClientHello_session.session_id_length)
			fprintf(stderr, "\n");
	}
#endif

	if (must_read_bytes <
		sizeof(tls_ClientHello_ciphersuites.cipher_suites_length)) {
#if __DEBUG__
		fprintf(stderr, "Size of tls_ClientHello_ciphersuites.cipher_suites_length "
			"is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in,
		&tls_ClientHello_ciphersuites.cipher_suites_length,
		sizeof(tls_ClientHello_ciphersuites.cipher_suites_length)) < 0) {
#if __DEBUG__
		fprintf(stderr, "Not enough bytes to match "
			"tls_ClientHello_ciphersuites.cipher_suites_length.\n");
#endif
		return 0;
	}
	must_read_bytes -= sizeof(tls_ClientHello_ciphersuites.cipher_suites_length);

#if __DEBUG__
	fprintf(stderr, "TLS ClientHello Cipher Suites Length: %u\n",
		n16toh16(tls_ClientHello_ciphersuites.cipher_suites_length));
#endif

	if (must_read_bytes <
		n16toh16(tls_ClientHello_ciphersuites.cipher_suites_length)) {
#if __DEBUG__
		fprintf(stderr, "tls_ClientHello_ciphersuites.cipher_suites_length "
			"is not expected.\n");
#endif
		return 0;
	}

	if (n16toh16(tls_ClientHello_ciphersuites.cipher_suites_length) >
		sizeof(tls_ClientHello_ciphersuites.cipher_suites)) {
#if __DEBUG__
		fprintf(stderr, "Size of tls_ClientHello_ciphersuites.cipher_suites "
			"is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in, tls_ClientHello_ciphersuites.cipher_suites,
		n16toh16(tls_ClientHello_ciphersuites.cipher_suites_length)) < 0) {
#if __DEBUG__
		fprintf(stderr,
			"Not enough bytes for tls_ClientHello_ciphersuites.cipher_suites.\n");
#endif
		return 0;
	}
	must_read_bytes -=
		n16toh16(tls_ClientHello_ciphersuites.cipher_suites_length);

#if __DEBUG__
	for (i = 0;
		i < n16toh16(tls_ClientHello_ciphersuites.cipher_suites_length) /
			sizeof(CipherSuite); i++) {
		fprintf(stderr, "TLS ClientHello Cipher Suite: %s (0x%04x)\n",
			CIPHER_TXT(n16toh16(tls_ClientHello_ciphersuites.cipher_suites[i])),
			n16toh16(tls_ClientHello_ciphersuites.cipher_suites[i]));
	}
#endif

	if (must_read_bytes <
		sizeof(tls_ClientHello_compression.compression_methods_length)) {
#if __DEBUG__
		fprintf(stderr, "Size of tls_ClientHello_compression.compression_methods_length "
			"is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in,
		&tls_ClientHello_compression.compression_methods_length,
		sizeof(tls_ClientHello_compression.compression_methods_length)) < 0) {
#if __DEBUG__
		fprintf(stderr, "Not enough bytes for "
			"tls_ClientHello_compression.compression_methods_length.\n");
#endif
		return 0;
	}
	must_read_bytes -=
		sizeof(tls_ClientHello_compression.compression_methods_length);

#if __DEBUG__
	fprintf(stderr, "TLS ClientHello Compression Methods Length: %u\n",
		tls_ClientHello_compression.compression_methods_length);
#endif

	if (must_read_bytes <
		tls_ClientHello_compression.compression_methods_length) {
#if __DEBUG__
		fprintf(stderr, "tls_ClientHello_compression.compression_methods_length "
			"is not expected.\n");
#endif
		return 0;
	}

	if (tls_ClientHello_compression.compression_methods_length >
		sizeof(tls_ClientHello_compression.compression_methods)) {
#if __DEBUG__
		fprintf(stderr, "Size of tls_ClientHello_compression.compression_methods "
			"is not expected.\n");
#endif
		return 0;
	}

	if (read_bytes(tls_in, tls_ClientHello_compression.compression_methods,
		tls_ClientHello_compression.compression_methods_length) < 0) {
#if __DEBUG__
		fprintf(stderr, "Not enough bytes for "
			"tls_ClientHello_compression.compression_methods.\n");
#endif
		return 0;
	}
	must_read_bytes -= tls_ClientHello_compression.compression_methods_length;

#if __DEBUG__
	for (i = 0;
		i < tls_ClientHello_compression.compression_methods_length; i++) {
		fprintf(stderr, "TLS ClientHello Compression Method: %u\n",
			tls_ClientHello_compression.compression_methods[i]);
	}
#endif

	if (must_read_bytes > 0) {
		if (must_read_bytes < sizeof(tls_extensions.extensions_length)) {
#if __DEBUG__
			fprintf(stderr,
				"Size of tls_extensions.extensions_length is not expected.\n");
#endif
			return 0;
		}

		if (read_bytes(tls_in, &tls_extensions.extensions_length,
			sizeof(tls_extensions.extensions_length)) < 0) {
#if __DEBUG__
			fprintf(stderr,
				"Not enough bytes for tls_extensions.extensions_length.\n");
#endif
			return 0;
		}
		must_read_bytes -= sizeof(tls_extensions.extensions_length);

#if __DEBUG__
		fprintf(stderr, "TLS ClientHello Extensions Length: %u\n",
			n16toh16(tls_extensions.extensions_length));
#endif

		if (must_read_bytes < n16toh16(tls_extensions.extensions_length)) {
#if __DEBUG__
			fprintf(stderr,
				"tls_extensions.tls_extensions_length is not expected.\n");
#endif
			return 0;
		}

		if ((r = tls_process_Handshake_ClientHello_Extensions()) == 0) {
			return r;
		}
		must_read_bytes -= r;
	}

	return n24toh32(tls_Handshake_header.Handshake__length) - must_read_bytes;
}

/*
 * Processes the given payload as a TLS record.
 *
 * Returns number of bytes processed.
 * - Zero indicates some parsing error (payload is not a TLS record).
 * - More than zero but less than payload_length indicates a TLS record was
 *   found with good confidence but trailing bytes could not be parsed.
 * - Exactly payload_length indicates successful parsing of the full payload.
 */
uint32_t tls_process_record(uint8_t *payload, uint32_t payload_length)
{
	unsigned int r;

	size_t must_read_bytes;
	size_t read_bytes_checkpoint;

	struct read_bytes_ctx ctx;

	read_bytes_checkpoint = 0;

	ctx.in = payload;
	ctx.read_bytes_available = payload_length;
	tls_in = &ctx;

	while (ctx.read_bytes_available > 0) {
		if (read_bytes(tls_in, &tls_TLSPlaintext_header,
			sizeof(tls_TLSPlaintext_header)) < 0) {
#if __DEBUG__
			fprintf(stderr, "Not enough bytes for tls_TLSPlaintext_header.\n");
#endif
			return read_bytes_checkpoint;
		}

#if __DEBUG__
		CPRINT_STDERR(C_BLUE_LIGHT, "[.] TLS Record "
			"type:%u(%s) version:%u.%u length:%u\n",
			tls_TLSPlaintext_header.TLSPlaintext__type,
			tls_ContentType(tls_TLSPlaintext_header.TLSPlaintext__type),
			tls_TLSPlaintext_header.TLSPlaintext__versionMajor,
			tls_TLSPlaintext_header.TLSPlaintext__versionMinor,
			n16toh16(tls_TLSPlaintext_header.TLSPlaintext__length));
#endif

		if (n16toh16(tls_TLSPlaintext_header.TLSPlaintext__length) > 0x4000) {
#if __DEBUG__
			fprintf(stderr, "TLSPlaintext__length > 0x4000.\n");
#endif
			return read_bytes_checkpoint;
		}

		must_read_bytes =
			n16toh16(tls_TLSPlaintext_header.TLSPlaintext__length);

		if (ctx.read_bytes_available < must_read_bytes) {
#if __DEBUG__
			fprintf(stderr, "Not enough bytes to match TLSPlaintext__length.\n");
#endif
			return read_bytes_checkpoint;
		}

		switch (tls_TLSPlaintext_header.TLSPlaintext__type) {

			case SSL3_RT_CHANGE_CIPHER_SPEC:
				while (must_read_bytes > 0) {
					if (must_read_bytes < sizeof(tls_ChangeCipherSpec)) {
#if __DEBUG__
						fprintf(stderr,
							"Size of tls_ChangeCipherSpec is not expected.\n");
#endif
						return read_bytes_checkpoint;
					}

					if (read_bytes(tls_in, &tls_ChangeCipherSpec,
						sizeof(tls_ChangeCipherSpec)) < 0) {
#if __DEBUG__
						fprintf(stderr,
							"Not enough bytes for tls_ChangeCipherSpec.\n");
#endif
						return read_bytes_checkpoint;
					}
					must_read_bytes -= sizeof(tls_ChangeCipherSpec);

#if __DEBUG__
					CPRINT_STDERR(C_CYAN_LIGHT, "[.] TLS tls_ChangeCipherSpec\n");
#endif
				}

				read_bytes_checkpoint =
					payload_length - ctx.read_bytes_available;
				break;

			case SSL3_RT_ALERT:
				while (must_read_bytes > 0) {
					if (must_read_bytes < sizeof(tls_Alert)) {
#if __DEBUG__
						fprintf(stderr,
							"Size of tls_Alert is not expected.\n");
#endif
						return read_bytes_checkpoint;
					}

					if (read_bytes(tls_in, &tls_Alert,
						sizeof(tls_Alert)) < 0) {
#if __DEBUG__
						fprintf(stderr, "Not enough bytes for tls_Alert.\n");
#endif
						return read_bytes_checkpoint;
					}
					must_read_bytes -= sizeof(tls_Alert);

#if __DEBUG__
					CPRINT_STDERR(C_CYAN_LIGHT, "[.] TLS tls_Alert "
						"level:%u(%s) description:%u(%s)\n",
						tls_Alert.Alert__level,
						tls_AlertLevel(tls_Alert.Alert__level),
						tls_Alert.Alert__description,
						tls_AlertDescription(tls_Alert.Alert__description));
#endif

					switch (tls_Alert.Alert__level) {
						case SSL3_AL_WARNING:
						case SSL3_AL_FATAL:
							break;
						default:
#if __DEBUG__
							CPRINT_STDERR(C_RED_LIGHT,
								"[!] Unknown TLS Alert level:%u\n",
								tls_Alert.Alert__level);
#endif
							return read_bytes_checkpoint;
					}

					switch (tls_Alert.Alert__description) {
						case SSL3_AD_CLOSE_NOTIFY:
						case SSL3_AD_UNEXPECTED_MESSAGE:
						case SSL3_AD_BAD_RECORD_MAC:
							break;
						default:
#if __DEBUG__
							CPRINT_STDERR(C_RED_LIGHT,
								"[!] Unknown TLS Alert description:%u\n",
								tls_Alert.Alert__description);
#endif
							return read_bytes_checkpoint;
					}
				}

				read_bytes_checkpoint =
					payload_length - ctx.read_bytes_available;
				break;

			case SSL3_RT_HANDSHAKE:
				while (must_read_bytes > 0) {
					if (must_read_bytes < sizeof(tls_Handshake_header)) {
#if __DEBUG__
						fprintf(stderr,
							"Size of tls_Handshake_header is not expected.\n");
#endif
						return read_bytes_checkpoint;
					}

					if (read_bytes(tls_in, &tls_Handshake_header,
						sizeof(tls_Handshake_header)) < 0) {
#if __DEBUG__
						fprintf(stderr,
							"Not enough bytes for tls_Handshake_header.\n");
#endif
						return read_bytes_checkpoint;
					}
					must_read_bytes -= sizeof(tls_Handshake_header);

#if __DEBUG__
					CPRINT_STDERR(C_CYAN_LIGHT,
						"[.] TLS Handshake type:%u(%s) length:%u\n",
						tls_Handshake_header.Handshake__type,
						tls_HandshakeType(tls_Handshake_header.Handshake__type),
						n24toh32(tls_Handshake_header.Handshake__length));
#endif

					if (must_read_bytes <
						n24toh32(tls_Handshake_header.Handshake__length)) {
#if __DEBUG__
						fprintf(stderr,
							"Not enough bytes to match Handshake__length.\n");
#endif
						return read_bytes_checkpoint;
					}

					switch (tls_Handshake_header.Handshake__type) {
						case SSL3_MT_CLIENT_HELLO:
							if ((r = tls_process_Handshake_ClientHello()) == 0) {
								return read_bytes_checkpoint;
							}
							must_read_bytes -= r;
							break;

						case SSL3_MT_HELLO_REQUEST:
						case SSL3_MT_SERVER_HELLO:
						case SSL3_MT_CERTIFICATE:
						case SSL3_MT_SERVER_KEY_EXCHANGE:
						case SSL3_MT_CERTIFICATE_REQUEST:
						case SSL3_MT_SERVER_DONE:
						case SSL3_MT_CERTIFICATE_VERIFY:
						case SSL3_MT_CLIENT_KEY_EXCHANGE:
						case SSL3_MT_FINISHED:
							if (read_bytes(tls_in, NULL,
								n24toh32(tls_Handshake_header.Handshake__length)) < 0) {
#if __DEBUG__
								fprintf(stderr,
									"Not enough bytes to match Handshake__length.\n");
#endif
								return read_bytes_checkpoint;
							}
							must_read_bytes -=
								n24toh32(tls_Handshake_header.Handshake__length);
							break;

						default:
#if __DEBUG__
							CPRINT_STDERR(C_RED_LIGHT,
								"[!] Unknown TLS handshake type:%u\n",
								(unsigned int)tls_Handshake_header.Handshake__type);
							for (r = 0; r < sizeof(tls_Handshake_header); r++) {
								fprintf(stderr, "0x%02x ",
									*(uint8_t *)(((uint8_t *)&tls_Handshake_header) + r));
							}
							fprintf(stderr, "\n");
#endif
							return read_bytes_checkpoint;
					}
				}

				read_bytes_checkpoint =
					payload_length - ctx.read_bytes_available;
				break;

			case SSL3_RT_APPLICATION_DATA:
				if (read_bytes(tls_in, NULL,
					n16toh16(tls_TLSPlaintext_header.TLSPlaintext__length)) < 0) {
#if __DEBUG__
					fprintf(stderr,
						"Not enough bytes to match TLSPlaintext__length.\n");
#endif
					return 0;
				}
				must_read_bytes = 0;

#if __DEBUG__
				CPRINT_STDERR(C_CYAN_LIGHT,
					"[.] TLS Application Data (%u)\n",
					n16toh16(tls_TLSPlaintext_header.TLSPlaintext__length));
#endif

				read_bytes_checkpoint =
					payload_length - ctx.read_bytes_available;
				break;

			default:
#if __DEBUG__
				CPRINT_STDERR(C_RED_LIGHT,
					"[!] Unknown TLS record type:%u\n",
					(unsigned int)tls_TLSPlaintext_header.TLSPlaintext__type);
				for (r = 0; r < sizeof(tls_TLSPlaintext_header); r++) {
					fprintf(stderr, "0x%02x ",
						*(uint8_t *)(((uint8_t *)&tls_TLSPlaintext_header) + r));
				}
				fprintf(stderr, "\n");
#endif
				return read_bytes_checkpoint;
		}

		assert(must_read_bytes == 0);
	}

	return read_bytes_checkpoint;
}
