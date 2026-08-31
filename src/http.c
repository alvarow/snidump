/* kontaxis 2015-10-31 */

#include <stdio.h>
#include <stdint.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "http_api.h"

/* Compiled patterns and reusable match-data objects (allocated once in
 * http_init, freed in http_cleanup).  Reusing match_data avoids a
 * per-packet heap allocation on every pcre2_match call.
 */
static pcre2_code       *pcre_HTTP_RequestLine;
static pcre2_match_data *pcre_md_HTTP_RequestLine;

static pcre2_code       *pcre_HTTP_RequestHeaderHost;
static pcre2_match_data *pcre_md_HTTP_RequestHeaderHost;


static int (*callback_request_host)(uint8_t *, uint16_t);

int http_set_callback_request_host(
  int (*handler)(uint8_t *, uint16_t))
{
  callback_request_host = handler;
  return 0;
}


/* Process the given payload as an HTTP request.
 *
 * Returns number of bytes processed.
 * - Zero indicates some parsing error. (Payload is not an HTTP request.)
 * - More than zero but less than payload_length indicates that an HTTP
 * request has been found with good confidence but there are trailing bytes
 * that we cannot make sense of.
 * - Exactly payload_length indicates with high confidence succesful parsing
 * of the entire payload as an HTTP request.
 *
 * Reference: https://tools.ietf.org/rfc/rfc2616.txt
 */
uint16_t http_process_request(uint8_t *payload, uint16_t payload_length)
{
	int r;
	PCRE2_SIZE *ovector;

	/* Points to the beginning of the headers. */
	uint8_t *headers;
	uint16_t headers_length;

	/* Auxiliary variable. Used to iterate over payload bytes. */
	uint16_t i;

	/* Line ending with a CRLF. Extracted from payload. */
	uint8_t *line;
	uint16_t line_length;

	/* Make sure payload starts with a Request-Line. (RFC2616 #5.1) */
	r = pcre2_match(pcre_HTTP_RequestLine,
		(PCRE2_SPTR)payload, payload_length,
		0, 0, pcre_md_HTTP_RequestLine, NULL);

	/* Error or no match. In any case we cannot proceed. */
	if (r <= 0) {
#if __DEBUG__
		if (r != PCRE2_ERROR_NOMATCH) {
			PCRE2_UCHAR errbuf[256];
			pcre2_get_error_message(r, errbuf, sizeof(errbuf));
			fprintf(stderr, "%s/%s: pcre2_match(RequestLine): %s\n",
				__FILE__, __func__, (char *)errbuf);
		}
#endif
		return 0;
	}

	ovector = pcre2_get_ovector_pointer(pcre_md_HTTP_RequestLine);

	/* Match starts at ovector[0] and ends right before ovector[1].
	 * We will work on payload beyond the request line. */
	if (ovector[1] - ovector[0] > payload_length) {
		return 0;
	}
	/* Check for address overflow. */
	if (SIZE_MAX - (size_t)payload < (size_t)(ovector[1] - ovector[0])) {
		return 0;
	}
	headers        = payload + (ovector[1] - ovector[0]);
	headers_length = payload_length - (uint16_t)(ovector[1] - ovector[0]);

	for (i = 0, line = headers; i < headers_length; i++) {
		/* The current line ends at the sequence \r\n. (RFC2616 #5) */
		if (headers[i] != '\n' || i == 0 || headers[i - 1] != '\r') {
			continue;
		}

		/* New line. Starts at line and has 'line_length' bytes. Including \r\n. */

		/* line_length = (line_end) - line + 1 */
		line_length = (uint16_t)((headers + i) - line + 1);

		/* Empty line indicates the end of header fields. (RFC2616 #5)
		 * We stop processing immediately. This means that requests with a message
		 * body (e.g., POST requests) line - payload != payload_length which may
		 * produce a warning. This also means that we may miss additional requests
		 * in the same payload. TODO: Skip Content-Length bytes and look for a
		 * Request-Line followed by request headers.
		 */
		if (line_length == 2) {
			line += line_length;
			i += 1;
			break;
		}

		/* Match the current line against the Host request header field.
		 * (RFC2616 #14.23)
		 */
		r = pcre2_match(pcre_HTTP_RequestHeaderHost,
			(PCRE2_SPTR)line, line_length,
			0, 0, pcre_md_HTTP_RequestHeaderHost, NULL);

		/* Error or no match. We move on to the next line. (if any) */
		if (r <= 0) {
#if __DEBUG__
			if (r != PCRE2_ERROR_NOMATCH) {
				PCRE2_UCHAR errbuf[256];
				pcre2_get_error_message(r, errbuf, sizeof(errbuf));
				fprintf(stderr, "%s/%s: pcre2_match(RequestHeaderHost): %s\n",
					__FILE__, __func__, (char *)errbuf);
			}
#endif
			line += line_length;
			continue;
		}

		/* Match found starting at ovector[2] and ending right before ovector[3].
		 * We invoke the registered callback. (if any)
		 * We keep parsing the rest of the headers since there may be additional
		 * Host header fields in this request. (unlikely)
		 */
		ovector = pcre2_get_ovector_pointer(pcre_md_HTTP_RequestHeaderHost);
		if (callback_request_host != NULL) {
			callback_request_host(
				line + ovector[2],
				(uint16_t)(ovector[3] - ovector[2]));
		}

		line += line_length;
	}

	/* Return number of bytes processed. */
	return (uint16_t)(line - payload);
}


int http_init()
{
	int        pcre_error;
	PCRE2_SIZE pcre_erroffset;
	PCRE2_UCHAR pcre_errbuf[256];

	/*
	 * 5.1 Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
	 * https://tools.ietf.org/rfc/rfc2616.txt
	 */
	const char *regex_HTTP_RequestLine =
		"^(?:OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PATCH"
		"|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK) [^ ]+ HTTP/1\\.[01]\r\n";

	pcre_HTTP_RequestLine = pcre2_compile(
		(PCRE2_SPTR)regex_HTTP_RequestLine,
		PCRE2_ZERO_TERMINATED, 0,
		&pcre_error, &pcre_erroffset, NULL);

	if (pcre_HTTP_RequestLine == NULL) {
		pcre2_get_error_message(pcre_error, pcre_errbuf, sizeof(pcre_errbuf));
		fprintf(stderr, "%s/%s: pcre2_compile(%s): %s at offset %zu\n",
			__FILE__, __func__,
			regex_HTTP_RequestLine, (char *)pcre_errbuf, pcre_erroffset);
		return -1;
	}

	pcre_md_HTTP_RequestLine =
		pcre2_match_data_create_from_pattern(pcre_HTTP_RequestLine, NULL);

	/*
	 * 14.23 Host = "Host" ":" host [ ":" port ] ; Section 3.2.2
	 * https://tools.ietf.org/rfc/rfc2616.txt
	 */
	const char *regex_HTTP_RequestHeaderHost = "^Host:[ ]*([^ ]+)[ ]*\r\n";

	pcre_HTTP_RequestHeaderHost = pcre2_compile(
		(PCRE2_SPTR)regex_HTTP_RequestHeaderHost,
		PCRE2_ZERO_TERMINATED, PCRE2_CASELESS,
		&pcre_error, &pcre_erroffset, NULL);

	if (pcre_HTTP_RequestHeaderHost == NULL) {
		pcre2_get_error_message(pcre_error, pcre_errbuf, sizeof(pcre_errbuf));
		fprintf(stderr, "%s/%s: pcre2_compile(%s): %s at offset %zu\n",
			__FILE__, __func__,
			regex_HTTP_RequestHeaderHost, (char *)pcre_errbuf, pcre_erroffset);
		return -1;
	}

	pcre_md_HTTP_RequestHeaderHost =
		pcre2_match_data_create_from_pattern(pcre_HTTP_RequestHeaderHost, NULL);

	return 0;
}


void http_cleanup()
{
	pcre2_match_data_free(pcre_md_HTTP_RequestLine);
	pcre2_code_free(pcre_HTTP_RequestLine);

	pcre2_match_data_free(pcre_md_HTTP_RequestHeaderHost);
	pcre2_code_free(pcre_HTTP_RequestHeaderHost);
}
