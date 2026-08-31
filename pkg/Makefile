# pkg/Makefile
PORTNAME=	pfSense-pkg-snidump
PORTVERSION=	0.1.0
CATEGORIES=	security
MAINTAINER=	alvaro@example.com
COMMENT=	Extracts TLS SNI and HTTP Host headers from live traffic

LICENSE=	MIT

RUN_DEPENDS=	${LOCALBASE}/lib/libpcre2-8.so:security/pcre2

NO_BUILD=	yes
NO_FETCH=	yes

PLIST_FILES=	\
	usr/local/bin/snidump \
	usr/local/bin/snidump_noether \
	usr/local/etc/rc.d/snidump \
	"@dir usr/local/etc/newsyslog.conf.d" \
	usr/local/etc/newsyslog.conf.d/snidump

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/../files/usr/local/bin/snidump \
		${STAGEDIR}${PREFIX}/bin/snidump
	${INSTALL_PROGRAM} ${WRKSRC}/../files/usr/local/bin/snidump_noether \
		${STAGEDIR}${PREFIX}/bin/snidump_noether
	${INSTALL_SCRIPT} ${WRKSRC}/../files/usr/local/etc/rc.d/snidump \
		${STAGEDIR}${PREFIX}/etc/rc.d/snidump
	${INSTALL_DATA} ${WRKSRC}/../files/usr/local/etc/newsyslog.conf.d/snidump \
		${STAGEDIR}${PREFIX}/etc/newsyslog.conf.d/snidump

post-install:
	@${INSTALL} -d -m 750 ${STAGEDIR}/var/log/snidump

.include <bsd.port.mk>
