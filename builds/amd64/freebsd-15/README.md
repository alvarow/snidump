# FreeBSD 15 amd64 binaries (pfSense CE 2.8.x / pfSense Plus 24.x)

Build on a FreeBSD 15 amd64 machine:

    make CC=clang CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"
    cp bin/snidump bin/snidump_noether builds/amd64/freebsd-15/

Then from the repo root:

    make pkg-build
