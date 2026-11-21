#!/usr/bin/env bash
# Probe the untouched Rocky Minimal package selection in an offline UEFI VM.
# Run this on a disposable x86_64 runner with QEMU and OVMF installed.
set -euo pipefail

test "$(uname -m)" = x86_64
fixture=$(cd "$(dirname "$0")" && pwd)/rocky-minimal-x86.ks
mkdir -p "${1:?private working directory}"
cd "$1"
iso=Rocky-10.3-20261113.0-x86_64-minimal.iso
# From the vendor-signed per-ISO CHECKSUM (Rocky Linux 10 release key).
checksum=878a3f92281d3eb91ca9d1a195794d47b5bce4e02a85f351c606709e98481cc4
curl --fail --location --silent --show-error --retry 2 --output "$iso" \
    "https://dl.rockylinux.org/pub/rocky/10/isos/x86_64/$iso"
printf '%s  %s\n' "$checksum" "$iso" | sha256sum -c -
label=$(blkid -s LABEL -o value "$iso")
label=${label// /\\x20}
xorriso -osirrox on -indev "$iso" -extract /images/pxeboot/vmlinuz ./vmlinuz \
    -extract /images/pxeboot/initrd.img ./initrd.img
install -m 0644 "$fixture" ks.cfg
printf 'ks.cfg\n' | cpio --quiet -o -H newc | gzip >> initrd.img
qemu-img create -f qcow2 disk.qcow2 16G
cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd

accel=tcg
qemu=(qemu-system-x86_64)
if [[ -c /dev/kvm ]] && sudo python3 -c 'import fcntl, os; fd = os.open("/dev/kvm", os.O_RDWR); assert fcntl.ioctl(fd, 0xAE00) == 12'; then
    accel=kvm
    qemu=(sudo qemu-system-x86_64)
fi
echo "Accelerator: $accel"
vm=("${qemu[@]}" -machine "q35,accel=$accel" -cpu Haswell-v4
    -m 6144 -smp 4 -nic none -display none -monitor none -no-reboot
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd
    -drive if=pflash,format=raw,file=vars.fd
    -drive if=virtio,format=qcow2,file=disk.qcow2)
timeout 45m "${vm[@]}" -serial stdio -cdrom "$iso" \
    -kernel vmlinuz -initrd initrd.img \
    -append "console=ttyS0,115200n8 inst.stage2=hd:LABEL=$label inst.ks=file:/ks.cfg inst.noninteractive" \
    | tee install.log
timeout 8m "${vm[@]}" -serial stdio | tee first-boot.log
tr -d '\r' < first-boot.log > first-boot-normalized.log
grep -Fx 'EFW_MINIMAL_UEFI=1' first-boot-normalized.log
grep -Fx 'Enforcing' first-boot-normalized.log
grep -Fx 'firewalld enabled: enabled' first-boot-normalized.log
grep -Fx 'firewalld active: active' first-boot-normalized.log
grep -E '^nftables-[0-9]' first-boot-normalized.log
grep -Fx 'EFW_MINIMAL_PROBE_DONE' first-boot-normalized.log
