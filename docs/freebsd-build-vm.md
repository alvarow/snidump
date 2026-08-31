# Building snidump for FreeBSD with a KVM Virtual Machine

This guide walks through creating a FreeBSD 15 amd64 KVM virtual machine on Ubuntu 24 LTS, using it to build snidump natively, and then addresses arm64 builds. No cross-compilation toolchain is needed — you compile inside the VM exactly as you would on a real FreeBSD machine.

---

## 1. Install KVM/QEMU and virt-install on Ubuntu 24

```bash
sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system virtinst virt-manager cpu-checker
```

Verify KVM is usable:

```bash
kvm-ok
```

Expected output: `INFO: /dev/kvm exists` / `KVM acceleration can be used`.

Add your user to the `libvirt` and `kvm` groups so you do not need `sudo` for every operation:

```bash
sudo usermod -aG libvirt,kvm $USER
newgrp libvirt   # or log out and back in
```

Start and enable the default network (NAT, gives the VM outbound internet):

```bash
sudo virsh net-start default
sudo virsh net-autostart default
```

---

## 2. Download the FreeBSD 15 amd64 installer ISO

Go to <https://www.freebsd.org/where/> and grab the **bootonly** or **disc1** installer for 15.0-RELEASE amd64. The bootonly ISO is ~500 MB; disc1 is ~1 GB and does not need a network connection during install.

```bash
mkdir -p ~/vms/freebsd15
cd ~/vms/freebsd15

# Replace the filename with the current 15.x-RELEASE when available.
# As of this writing FreeBSD 15 is in CURRENT/STABLE; use the latest available:
curl -LO https://download.freebsd.org/releases/amd64/amd64/ISO-IMAGES/15.0/FreeBSD-15.0-RELEASE-amd64-disc1.iso
```

If 15.0-RELEASE is not yet published, substitute `14.x-RELEASE` or use a CURRENT snapshot from <https://download.freebsd.org/snapshots/amd64/amd64/ISO-IMAGES/>.

---

## 3. Create and install the VM

Create a 20 GB disk image and install from the ISO in one `virt-install` command. The VM boots in text mode — no display server required on the host.

```bash
virt-install \
  --name freebsd15 \
  --memory 2048 \
  --vcpus 2 \
  --disk path=~/vms/freebsd15/freebsd15.qcow2,size=20,format=qcow2 \
  --cdrom ~/vms/freebsd15/FreeBSD-15.0-RELEASE-amd64-disc1.iso \
  --os-variant freebsd14.0 \
  --network network=default \
  --graphics none \
  --console pty,target_type=serial \
  --extra-args "console=ttyS0,115200n8"
```

> **Note:** `--os-variant freebsd14.0` is used because `freebsd15.0` may not yet be in your libosinfo database. The variant only affects a few tuning hints and does not affect correctness.

### Installer walkthrough (text UI)

1. Choose **Install**.
2. Keymap: **US default** (hit Enter).
3. Hostname: anything, e.g. `fbsd15`.
4. Distribution components: **uncheck** everything except the base — uncheck `lib32`, `ports`, `src`. Select only `base-dbg` if you want debug symbols, otherwise just `base`.
5. Partitioning: **Auto (ZFS)** or **Auto (UFS)**. UFS is simpler. Accept defaults, select your virtual disk (`vtbd0` or `ada0`).
6. Root password: set one.
7. Network: configure the `vtnet0` (or `em0`) interface with DHCP. IPv4 DHCP is sufficient.
8. **Disable** all services except `sshd` and `ntpd`.
9. Add a regular user (e.g. `dev`) and add them to the `wheel` group.
10. **Reboot**.

After reboot the VM will boot from disk. You will get a serial console. Log in as root.

---

## 4. Post-install: install build tools inside the VM

### 4.1 Get a shell in the VM

From the Ubuntu host you have two options:

**Option A — serial console (always available):**
```bash
virsh console freebsd15
# Press Ctrl-] to detach
```

**Option B — SSH (more comfortable):**
```bash
# Find the VM's IP
virsh domifaddr freebsd15

# Then
ssh dev@<VM_IP>
```

### 4.2 Install clang, pcre2, and git

FreeBSD ships `clang` in base; you may need to install an additional `llvm` package only if the base clang is too old. Check first:

```sh
clang --version
```

On FreeBSD 15 base clang is 18 or 19. That is sufficient. If the command is missing, install it from ports:

```sh
pkg install llvm   # installs the current LLVM version from ports
```

Install pcre2 and git:

```sh
pkg install pcre2 git
```

Verify:

```sh
clang --version
# Expected: clang version 18.x.x (or 19.x.x)

pkg info pcre2
# Expected: pcre2-X.Y

git --version
```

---

## 5. Share files between the Ubuntu host and the FreeBSD VM

The simplest method is **scp / rsync over SSH**. No extra VM configuration is needed beyond the sshd already enabled during install.

### Copy the source tree to the VM

From the Ubuntu host:

```bash
rsync -av --exclude=bin/ /home/alvaro/src/snidump/ dev@<VM_IP>:~/snidump/
```

### Copy binaries back to the host

After building (see section 6), from the Ubuntu host:

```bash
scp dev@<VM_IP>:~/snidump/bin/snidump     ~/vms/freebsd15/snidump-freebsd-amd64
scp dev@<VM_IP>:~/snidump/bin/snidump_noether ~/vms/freebsd15/snidump_noether-freebsd-amd64
```

#### Alternative: virtio-9p (shared folder)

If you prefer a live shared folder, rebuild the VM with a 9p filesystem device and mount it inside FreeBSD. This is more involved and not necessary for occasional builds — skip it unless you need continuous two-way file sharing.

For reference, the virt-install flag is `--filesystem /home/alvaro/src/snidump,snidump,driver.type=virtiofs` and the FreeBSD mount command is:

```sh
mount -t virtfs -o trans=virtio snidump /mnt/snidump
```

---

## 6. Build snidump inside the FreeBSD VM

SSH into the VM, go to the source directory, and run make:

```sh
cd ~/snidump
make CC=clang CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"
```

Expected output — the two binaries are placed in `bin/`:

```
cc -D__DEBUG__=0 -Wall -I/usr/local/include src/snidump.c src/tls.c src/http.c \
    -L/usr/local/lib -lpcap -lpcre2-8 -o bin/snidump
cc -D__DEBUG__=0 -Wall -I/usr/local/include -D__NO_ETHERNET__ \
    src/snidump.c src/tls.c src/http.c \
    -L/usr/local/lib -lpcap -lpcre2-8 -o bin/snidump_noether
```

Verify:

```sh
file bin/snidump
# ELF 64-bit LSB executable, x86-64, FreeBSD, dynamically linked

ldd bin/snidump
# libpcap.so.9 => /lib/libpcap.so.9
# libpcre2-8.so.0 => /usr/local/lib/libpcre2-8.so.0
# libc.so.7 => /lib/libc.so.7
```

---

## 7. arm64 builds

### Should you use a native arm64 VM or cross-compile from amd64?

**Use a second native VM.** QEMU TCG (pure software emulation of arm64 on x86) is functional but very slow — a simple build that takes two seconds natively can take several minutes under TCG. For a project like snidump (three C source files, no generated code) TCG is tolerable but annoying. A cross-compiler toolchain for FreeBSD is not packaged for Ubuntu and requires building from source, which is a larger effort. The pragmatic choice is a second QEMU VM with KVM disabled (TCG) or, if you have arm64 hardware available, a native machine or container.

### 7a. FreeBSD arm64 VM under QEMU TCG (no KVM)

QEMU can emulate an AArch64 machine entirely in software. This requires the `qemu-system-aarch64` package (already installed with `qemu-kvm`) and the AAVMF firmware (EFI for AArch64).

#### Install AAVMF firmware

```bash
sudo apt install -y qemu-efi-aarch64
```

The firmware files land in `/usr/share/qemu-efi-aarch64/`. Copy them locally because QEMU writes to the vars file:

```bash
mkdir -p ~/vms/freebsd15-arm64
cp /usr/share/qemu-efi-aarch64/QEMU_EFI.fd ~/vms/freebsd15-arm64/OVMF_CODE.fd
dd if=/dev/zero bs=1M count=64 of=~/vms/freebsd15-arm64/OVMF_VARS.fd
```

#### Download the arm64 ISO

```bash
cd ~/vms/freebsd15-arm64
curl -LO https://download.freebsd.org/releases/arm64/aarch64/ISO-IMAGES/15.0/FreeBSD-15.0-RELEASE-arm64-aarch64-disc1.iso
```

#### Create the disk image

```bash
qemu-img create -f qcow2 ~/vms/freebsd15-arm64/freebsd15-arm64.qcow2 20G
```

#### Install FreeBSD arm64

```bash
qemu-system-aarch64 \
  -M virt \
  -cpu cortex-a57 \
  -m 2048 \
  -smp 2 \
  -drive if=pflash,format=raw,file=~/vms/freebsd15-arm64/OVMF_CODE.fd,readonly=on \
  -drive if=pflash,format=raw,file=~/vms/freebsd15-arm64/OVMF_VARS.fd \
  -drive if=virtio,format=qcow2,file=~/vms/freebsd15-arm64/freebsd15-arm64.qcow2 \
  -cdrom ~/vms/freebsd15-arm64/FreeBSD-15.0-RELEASE-arm64-aarch64-disc1.iso \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -nographic
```

Follow the same installer steps as in section 3. After installation the VM will reboot. Press Ctrl-A then X to quit QEMU, then start the VM without the `-cdrom` flag:

```bash
qemu-system-aarch64 \
  -M virt \
  -cpu cortex-a57 \
  -m 2048 \
  -smp 2 \
  -drive if=pflash,format=raw,file=~/vms/freebsd15-arm64/OVMF_CODE.fd,readonly=on \
  -drive if=pflash,format=raw,file=~/vms/freebsd15-arm64/OVMF_VARS.fd \
  -drive if=virtio,format=qcow2,file=~/vms/freebsd15-arm64/freebsd15-arm64.qcow2 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -nographic
```

SSH uses the forwarded port:

```bash
ssh -p 2222 dev@localhost
```

#### Install packages and build (arm64 VM)

The commands are identical to the amd64 case:

```sh
pkg install pcre2 git
rsync -av -e 'ssh -p 2222' --exclude=bin/ /home/alvaro/src/snidump/ dev@localhost:~/snidump/
# (run from the Ubuntu host)

# Inside the VM:
cd ~/snidump
make CC=clang CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"
```

```bash
# Copy the arm64 binary back to the host:
scp -P 2222 dev@localhost:~/snidump/bin/snidump ~/vms/freebsd15-arm64/snidump-freebsd-arm64
```

Verify the architecture:

```bash
file ~/vms/freebsd15-arm64/snidump-freebsd-arm64
# ELF 64-bit LSB executable, ARM aarch64, FreeBSD, dynamically linked
```

### 7b. Build arm64 binaries from inside the amd64 VM (cross-compilation)

FreeBSD's base system includes a complete cross-compilation toolchain. You can build arm64 binaries from the amd64 VM without a second VM. This avoids TCG emulation at the cost of slightly more complex compiler flags.

Inside the **amd64 FreeBSD VM**, install the arm64 sysroot headers (bundled in the world distribution) and the cross-linker:

```sh
# FreeBSD does not require a separate sysroot package — the cross tools are
# already in /usr/bin. You do need arm64 libraries to link against.
# The simplest approach: install the FreeBSD arm64 libraries from the archive.

pkg install wget

# Download and extract the arm64 base libs to a local sysroot:
mkdir -p ~/arm64-sysroot
cd ~/arm64-sysroot
fetch https://download.freebsd.org/releases/arm64/aarch64/15.0-RELEASE/base.txz
# (substitute with the current release URL)
tar -xf base.txz ./lib ./usr/lib ./usr/include
```

Install arm64 pcre2 headers and library. The easiest way is to extract the arm64 package:

```sh
cd ~/arm64-sysroot
pkg fetch -y --output . pcre2
# This downloads the amd64 .pkg, not arm64 — pkg does not support cross-arch fetches.
# Instead, download the arm64 package directly:
fetch "https://pkg.FreeBSD.org/FreeBSD:15:aarch64/latest/All/$(pkg rquery '%n-%v' pcre2).pkg"
tar -xf pcre2-*.pkg ./usr/local
```

Build with the FreeBSD cross-clang:

```sh
cd ~/snidump
make CC="clang --target=aarch64-unknown-freebsd15 \
           --sysroot=/root/arm64-sysroot" \
     CFLAGS="-I/root/arm64-sysroot/usr/local/include" \
     LDFLAGS="-L/root/arm64-sysroot/usr/local/lib \
              -L/root/arm64-sysroot/usr/lib \
              -L/root/arm64-sysroot/lib"
```

> **Recommendation:** Unless you are setting up a CI pipeline that needs to produce both architectures from a single machine, the two-VM approach (section 7a) is less error-prone. Use cross-compilation from the amd64 VM if you want to avoid running a second emulated VM.

---

## Quick reference

| Task | Command |
|------|---------|
| Start amd64 VM | `virsh start freebsd15` |
| Stop amd64 VM | `virsh shutdown freebsd15` |
| Console | `virsh console freebsd15` (Ctrl-] to detach) |
| SSH into amd64 VM | `ssh dev@$(virsh domifaddr freebsd15 \| awk '/ipv4/{print $4}' \| cut -d/ -f1)` |
| Start arm64 VM | `qemu-system-aarch64 -M virt -cpu cortex-a57 ... -nographic` |
| SSH into arm64 VM | `ssh -p 2222 dev@localhost` |
| Build (inside any FreeBSD VM) | `make CC=clang CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"` |
| Copy binaries to host | `scp dev@<IP>:~/snidump/bin/* .` |
