#ifndef __TLS_H__
#define __TLS_H__

/* kontaxis 2015-10-31 */

#include <stdint.h>
#include "ciphersuites.h"

/*
 * References:
 * - https://tools.ietf.org/html/rfc5246 TLS 1.2
 * - https://tools.ietf.org/html/rfc4346 TLS 1.1
 * - https://tools.ietf.org/html/rfc2246 TLS 1.0
 * - https://tools.ietf.org/html/rfc6101 SSL 3.0
 */

/* converts 16 bits in host byte order to 16 bits in network byte order */
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define h16ton16(n) (n)
#else
#define h16ton16(n) \
((uint16_t) (((uint16_t) n) << 8) | (uint16_t) (((uint16_t) n) >> 8))
#endif

#define n16toh16(buf) h16ton16(buf)

/* converts 24 bits in network byte order to 32 bits in host byte order */
#define n24toh32(buf) \
(((uint32_t) *(((uint8_t*)buf) + 0)) << 16 |\
 ((uint32_t) *(((uint8_t*)buf) + 1)) <<  8 |\
 ((uint32_t) *(((uint8_t*)buf) + 2)) <<  0)

/* converts 24 bits in host byte order to 24 bits in network byte order */
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define h24ton24(n,buf) \
{\
*(((uint8_t*)buf) + 0) = (uint8_t) (((uint32_t)n) >>  0);\
*(((uint8_t*)buf) + 1) = (uint8_t) (((uint32_t)n) >>  8);\
*(((uint8_t*)buf) + 2) = (uint8_t) (((uint32_t)n) >> 16);\
}
#else
#define h24ton24(n,buf) \
{\
*(((uint8_t*)buf) + 0) = (uint8_t) (((uint32_t)n) >> 16);\
*(((uint8_t*)buf) + 1) = (uint8_t) (((uint32_t)n) >>  8);\
*(((uint8_t*)buf) + 2) = (uint8_t) (((uint32_t)n) >>  0);\
}
#endif

/* ContentType */
#define SSL3_RT_CHANGE_CIPHER_SPEC 20
#define SSL3_RT_ALERT              21
#define SSL3_RT_HANDSHAKE          22
#define SSL3_RT_APPLICATION_DATA   23

/* AlertLevel */
#define SSL3_AL_WARNING 1
#define SSL3_AL_FATAL   2

/* AlertDescription */
#define SSL3_AD_CLOSE_NOTIFY        0
#define SSL3_AD_UNEXPECTED_MESSAGE 10
#define SSL3_AD_BAD_RECORD_MAC     20

/* HandshakeType */
#define SSL3_MT_HELLO_REQUEST        0
#define SSL3_MT_CLIENT_HELLO         1
#define SSL3_MT_SERVER_HELLO         2
#define SSL3_MT_CERTIFICATE         11
#define SSL3_MT_SERVER_KEY_EXCHANGE 12
#define SSL3_MT_CERTIFICATE_REQUEST 13
#define SSL3_MT_SERVER_DONE         14
#define SSL3_MT_CERTIFICATE_VERIFY  15
#define SSL3_MT_CLIENT_KEY_EXCHANGE 16
#define SSL3_MT_FINISHED            20

/* Transport Layer Security (TLS) Extensions */
#define TLS_EXTENSION_TYPE_SERVER_NAME 0
#define TLS_EXTENSIONS_MAX             0

#define TLS_HASH_ALGORITHMS_MAX      6
#define TLS_SIGNATURE_ALGORITHMS_MAX 3

#endif
