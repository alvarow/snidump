.PHONY: all debug clean install uninstall check-deps pkg-build

VERSION != cat VERSION 2>/dev/null | tr -d '\n\r '

# Compiler — defaults to gcc; override from command line if needed:
#   FreeBSD : make CC=clang CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"
CC      = gcc
CFLAGS ?=
LDFLAGS ?=

# Installation prefix — override with: make install PREFIX=/usr
PREFIX  ?= /usr/local
DESTDIR ?=

BINDIR  = $(DESTDIR)$(PREFIX)/bin
MANDIR  = $(DESTDIR)$(PREFIX)/share/man
DOCDIR  = $(DESTDIR)$(PREFIX)/share/doc/snidump
CONTRIB_SYSTEMD   = $(DESTDIR)/etc/systemd/system
CONTRIB_LOGROTATE = $(DESTDIR)/etc/logrotate.d
CONTRIB_RC        = $(DESTDIR)/usr/local/etc/rc.d

INSTALL         ?= install
INSTALL_PROGRAM ?= $(INSTALL) -m 755
INSTALL_DATA    ?= $(INSTALL) -m 644
INSTALL_DIR     ?= $(INSTALL) -d -m 755

# all is the first real target — default for both GNU make and BSD make.
all: check-deps bin/snidump bin/snidump_noether

debug: check-deps bin/snidump_dbg bin/snidump_noether_dbg

check-deps:
	@printf '#include <pcap/pcap.h>\nint main(void){return 0;}\n' | \
	  $(CC) $(CFLAGS) -x c - $(LDFLAGS) -lpcap -o /dev/null 2>/dev/null || \
	  { echo "[ERROR] libpcap not found."; \
	    echo "        Debian/Ubuntu : sudo apt install libpcap-dev"; \
	    echo "        FreeBSD/pfSense: libpcap is in the base system"; \
	    exit 1; }
	@printf '#define PCRE2_CODE_UNIT_WIDTH 8\n#include <pcre2.h>\nint main(void){return 0;}\n' | \
	  $(CC) $(CFLAGS) -x c - $(LDFLAGS) -lpcre2-8 -o /dev/null 2>/dev/null || \
	  { echo "[ERROR] libpcre2 not found."; \
	    echo "        Debian/Ubuntu : sudo apt install libpcre2-dev"; \
	    echo "        FreeBSD/pfSense: sudo pkg install pcre2"; \
	    exit 1; }

bin/snidump: src/*
	mkdir -p bin && \
	$(CC) $(CFLAGS) -D__DEBUG__=0 -Wall \
		src/snidump.c src/tls.c src/http.c \
		$(LDFLAGS) -lpcap -lpcre2-8 \
		-o bin/snidump

bin/snidump_dbg: src/*
	mkdir -p bin && \
	$(CC) $(CFLAGS) -D__DEBUG__=1 -Wall -ggdb \
		src/snidump.c src/tls.c src/http.c \
		$(LDFLAGS) -lpcap -lpcre2-8 \
		-o bin/snidump_dbg

bin/snidump_noether: src/*
	mkdir -p bin && \
	$(CC) $(CFLAGS) -D__DEBUG__=0 -Wall \
		-D__NO_ETHERNET__ \
		src/snidump.c src/tls.c src/http.c \
		$(LDFLAGS) -lpcap -lpcre2-8 \
		-o bin/snidump_noether

bin/snidump_noether_dbg: src/*
	mkdir -p bin && \
	$(CC) $(CFLAGS) -D__DEBUG__=1 -Wall -ggdb \
		-D__NO_ETHERNET__ \
		src/snidump.c src/tls.c src/http.c \
		$(LDFLAGS) -lpcap -lpcre2-8 \
		-o bin/snidump_noether_dbg

install: all
	$(INSTALL_DIR) $(BINDIR)
	$(INSTALL_PROGRAM) bin/snidump         $(BINDIR)/snidump
	$(INSTALL_PROGRAM) bin/snidump_noether $(BINDIR)/snidump_noether
	$(INSTALL_DIR) $(MANDIR)/man8
	$(INSTALL_DATA) man/man8/snidump.8 $(MANDIR)/man8/snidump.8
	$(INSTALL_DIR) $(DOCDIR)
	$(INSTALL_DATA) README.md USAGE.md HACKING.md TODO.md $(DOCDIR)/
	@echo ""
	@echo "Binaries installed to $(BINDIR)."
	@echo ""
	@echo "Service / rotation files are NOT installed automatically."
	@echo "Install them manually from contrib/ as needed:"
	@echo "  Linux   : contrib/snidump.service   -> /etc/systemd/system/"
	@echo "            contrib/snidump.logrotate -> /etc/logrotate.d/snidump"
	@echo "  FreeBSD : contrib/snidump.rc        -> /usr/local/etc/rc.d/snidump"

uninstall:
	rm -f  $(BINDIR)/snidump $(BINDIR)/snidump_noether
	rm -f  $(MANDIR)/man8/snidump.8
	rm -rf $(DOCDIR)

# Build the pfSense .pkg. Requires a FreeBSD 15 amd64 build environment.
# Binaries must already be in builds/amd64/freebsd-15/ before running this.
pkg-build:
	@test "$$(uname -s)" = "FreeBSD" || \
	  { echo "[ERROR] pkg-build must run on FreeBSD 15 (BSD make + ports tree required)."; \
	    echo "        Run this target from a FreeBSD 15 VM or jail."; \
	    echo "        See docs/freebsd-build-vm.md for build VM setup."; exit 1; }
	@test -f builds/amd64/freebsd-15/snidump || \
	  { echo "[ERROR] builds/amd64/freebsd-15/snidump not found."; \
	    echo "        Compile on a FreeBSD 15 amd64 machine first."; exit 1; }
	# Stage all installed files into pkg/stage/
	rm -rf pkg/stage
	mkdir -p pkg/stage/usr/local/bin \
	         pkg/stage/usr/local/etc/rc.d \
	         pkg/stage/usr/local/etc/newsyslog.conf.d \
	         pkg/stage/usr/local/pkg \
	         pkg/stage/usr/local/www \
	         pkg/stage/var/log/snidump
	cp builds/amd64/freebsd-15/snidump         pkg/stage/usr/local/bin/snidump
	cp builds/amd64/freebsd-15/snidump_noether pkg/stage/usr/local/bin/snidump_noether
	chmod +x pkg/stage/usr/local/bin/snidump pkg/stage/usr/local/bin/snidump_noether
	cp pkg/files/usr/local/etc/rc.d/snidump    pkg/stage/usr/local/etc/rc.d/snidump
	chmod +x pkg/stage/usr/local/etc/rc.d/snidump
	cp pkg/files/usr/local/etc/newsyslog.conf.d/snidump \
	   pkg/stage/usr/local/etc/newsyslog.conf.d/snidump
	cp pkg/snidump.xml                          pkg/stage/usr/local/pkg/snidump.xml
	cp pkg/files/usr/local/pkg/snidump.inc     pkg/stage/usr/local/pkg/snidump.inc
	cp pkg/files/usr/local/www/snidump_log.php pkg/stage/usr/local/www/snidump_log.php
	# Write UCL manifest and explicit plist; pkg create requires -p to include
	# staged files (without it only metadata is packaged).
	printf 'name: "pfSense-pkg-snidump"\nversion: "%s"\norigin: "security/pfSense-pkg-snidump"\ncomment: "Extracts TLS SNI and HTTP Host headers from live traffic"\ndesc: "snidump extracts the TLS SNI field from ClientHello messages and the Host header from HTTP/1.1 requests. Supports IPv4, IPv6, live capture, and PCAP files."\nmaintainer: "alvaro@example.com"\nwww: "https://github.com/alvarow/snidump"\nprefix: "/usr/local"\ndeps: {pcre2: {origin: "devel/pcre2", version: "%s"}}\n' \
	    "$(VERSION)" "$$(pkg query '%v' pcre2 2>/dev/null || echo 0)" > pkg/stage/+MANIFEST
	find pkg/stage -type f -not -name '+MANIFEST' | sed 's|pkg/stage||' | sort > pkg/stage/plist
	mkdir -p pkg/work/pkg
	pkg create -m pkg/stage -r pkg/stage -p pkg/stage/plist -o pkg/work/pkg/
	rm -rf pkg/stage
	@echo ""
	@echo "Package: pkg/work/pkg/pfSense-pkg-snidump-$(VERSION).pkg"

clean:
	rm -rf bin
