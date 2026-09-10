# pkg/Makefile
PORTNAME=	pfSense-pkg-snidump
PORTVERSION!=	cat ${.CURDIR}/../VERSION | tr -d '[:space:]'
CATEGORIES=	security
MAINTAINER=	alvaro@example.com
COMMENT=	Extracts TLS SNI and HTTP Host headers from live traffic

LICENSE=	MIT

RUN_DEPENDS=	${LOCALBASE}/lib/libpcre2-8.so:security/pcre2

NO_BUILD=	yes
NO_FETCH=	yes

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/../files/usr/local/bin/snidump \
		${STAGEDIR}${PREFIX}/bin/snidump
	${INSTALL_PROGRAM} ${WRKSRC}/../files/usr/local/bin/snidump_noether \
		${STAGEDIR}${PREFIX}/bin/snidump_noether
	${INSTALL_DIR} ${STAGEDIR}${PREFIX}/etc/rc.d
	${INSTALL_SCRIPT} ${WRKSRC}/../files/usr/local/etc/rc.d/snidump \
		${STAGEDIR}${PREFIX}/etc/rc.d/snidump
	${INSTALL_DIR} ${STAGEDIR}${PREFIX}/etc/newsyslog.conf.d
	${INSTALL_DATA} ${WRKSRC}/../files/usr/local/etc/newsyslog.conf.d/snidump \
		${STAGEDIR}${PREFIX}/etc/newsyslog.conf.d/snidump
	${INSTALL_DIR} ${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${WRKSRC}/../snidump.xml \
		${STAGEDIR}${PREFIX}/pkg/snidump.xml
	${INSTALL_DATA} ${WRKSRC}/../files/usr/local/pkg/snidump.inc \
		${STAGEDIR}${PREFIX}/pkg/snidump.inc
	${INSTALL_DIR} ${STAGEDIR}${PREFIX}/www
	${INSTALL_DATA} ${WRKSRC}/../files/usr/local/www/snidump_log.php \
		${STAGEDIR}${PREFIX}/www/snidump_log.php

post-install:
	@${INSTALL} -d -m 750 ${STAGEDIR}/var/log/snidump

.include <bsd.port.mk>
