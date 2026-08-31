.PHONY: all debug clean install uninstall check-deps

# Default goal — must be declared before check-deps so that bare 'make'
# builds the binaries rather than stopping after the dependency check.
.DEFAULT_GOAL := all

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

all: check-deps bin/snidump bin/snidump_noether

debug: check-deps bin/snidump_dbg bin/snidump_noether_dbg

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
