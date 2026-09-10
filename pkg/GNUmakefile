# pkg/GNUmakefile — GNU make stub (Linux / macOS)
#
# pkg/Makefile is a FreeBSD port Makefile that requires BSD make and the
# FreeBSD ports tree. It cannot be run directly on Linux.
#
# To build the pfSense .pkg, run from the repo root on a FreeBSD 15 machine:
#
#   make pkg-build
#
# See docs/freebsd-build-vm.md for instructions on setting up a FreeBSD 15
# build VM with KVM on Ubuntu.

.PHONY: all
all %:
	@echo "[ERROR] pkg/Makefile is a FreeBSD port Makefile (BSD make + ports tree required)."
	@echo "        On Linux, run make pkg-build from the repo root on a FreeBSD 15 machine."
	@echo "        See docs/freebsd-build-vm.md for build VM setup."
	@exit 1
