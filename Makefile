.PHONY: all debug clean install uninstall

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

all: bin/snidump bin/snidump_noether

debug: bin/snidump_dbg bin/snidump_noether_dbg

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

clean:
	rm -rf bin
