#!/usr/bin/env bash
# Install in a disposable VM with no NIC, then test first access on an
# isolated QEMU network. The first-boot serial log can contain a credential.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "${1:?lab directory}"
umask 077
qemu-img create -f qcow2 disk.qcow2 16G
cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd
vm=(qemu-system-x86_64 -machine q35,accel=kvm -cpu Haswell-v4 -m 6144 -smp 4
    -display none -monitor none
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd
    -drive if=pflash,format=raw,file=vars.fd
    -drive if=virtio,format=qcow2,file=disk.qcow2)

touch install-serial.log first-boot.private.log
sudo -n timeout 25m "${vm[@]}" -nic none -serial file:install-serial.log \
    -no-reboot -boot once=d -cdrom appliance-test.iso
echo 'ISO installation ran with -nic none and rebooted' | tee validation.txt
# Add a NIC only after the install has exited. QEMU's restricted network
# provides local DHCP and loopback-forwarded management ports.
sudo -n timeout 10m "${vm[@]}" -serial file:first-boot.private.log \
    -netdev 'user,id=mgmt,restrict=on,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:8443-:443' \
    -device virtio-net-pci,netdev=mgmt &
guest=$!
trap 'sudo -n kill "$guest" 2>/dev/null || true; wait "$guest" 2>/dev/null || true' EXIT

ssh_guest=(ssh -q -i ssh -p 2222 -o BatchMode=yes -o ConnectTimeout=4
    -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes
    -o "UserKnownHostsFile=$PWD/known_hosts" root@127.0.0.1)
ready=false
for _ in {1..50}; do
    if ssh-keyscan -T 2 -t ed25519 -p 2222 127.0.0.1 > known_hosts 2>/dev/null &&
        "${ssh_guest[@]}" 'systemctl is-active --quiet efw-agent && systemctl is-active --quiet efw-web && systemctl is-active --quiet efw-firstboot'; then
        ready=true
        break
    fi
    sudo -n kill -0 "$guest"
    sleep 3
done
if ! "$ready"; then
    echo 'first boot did not bring up SSH and all appliance services' >&2
    "${ssh_guest[@]}" 'systemctl show -p Id -p ActiveState -p Result efw-agent efw-web efw-firstboot' || true
    grep -aiE 'Kernel panic|No bootable|Failed to start Edge FWSec|Starting Edge FWSec' first-boot.private.log || true
    exit 1
fi
grep -aq 'Edge FWSec console:' first-boot.private.log
grep -aq 'One-time administrator credential' first-boot.private.log
echo 'PASS: first boot displayed the console URL and the one-time credential on serial' | tee -a validation.txt

"${ssh_guest[@]}" 'bash -se' <<'GUEST' | tee -a validation.txt
test -d /sys/firmware/efi
test "$(uname -m)" = x86_64
test "$(getenforce)" = Enforcing
if rpm -q firewalld >/dev/null; then
    echo "unexpected firewalld package in appliance image" >&2
    exit 1
fi
test "$(stat -c %a /etc/issue.d/50-edge-fwsec.issue)" = 600
grep -q 'One-time administrator credential' /etc/issue.d/50-edge-fwsec.issue
test "$(stat -c %a /var/lib/efw-web/bootstrap.json)" = 600
ps -eZ | grep -Eq 'efw_agent_t.*efw-agent'
ps -eZ | grep -Eq 'efw_web_t.*efw-web'
printf 'PASS: installed x86_64 disk booted in UEFI and enforcing mode; both services are confined\n'
rpm -q edge-fwsec
GUEST
"${ssh_guest[@]}" 'head -n 4 /usr/share/doc/edge-fwsec/ISO-BUILD-INFO' > installed-build-info.txt
diff -u iso-build-info.txt installed-build-info.txt
mgmt_ip=$("${ssh_guest[@]}" "ip -o -4 addr show scope global | awk 'NR==1 {sub(/\/.*/, \"\", \$4); print \$4}'")
test -n "$mgmt_ip"
"${ssh_guest[@]}" 'cat /var/lib/efw-web/tls/self.crt' > guest.crt
https=(curl -fsS --noproxy '*' --max-time 10 --cacert guest.crt
    --connect-to "$mgmt_ip:443:127.0.0.1:8443")
"${https[@]}" "https://$mgmt_ip/" > console.html
grep -qi '<title>.*Edge FWSec' console.html
"${https[@]}" "https://$mgmt_ip/api/v1/session" | python3 -c \
    'import json, sys; s = json.load(sys.stdin); assert s["needs_bootstrap"] and s["bootstrap_pending"] and not s["authenticated"]'
echo 'PASS: HTTPS console and bootstrap API reached from the management network with verified TLS' | tee -a validation.txt

"${ssh_guest[@]}" 'install -d -m 0700 /var/tmp/efw-iso-lab && cat >/var/tmp/efw-iso-lab/e2e.sh' < "$repo/tests/install/e2e.sh"
"${ssh_guest[@]}" 'systemd-run --quiet --unit=efw-iso-e2e --remain-after-exit \
    -E EFW_TEST_VM=1 -E EFW_TEST_BOOTSTRAP_FILE=/etc/issue.d/50-edge-fwsec.issue \
    /bin/bash /var/tmp/efw-iso-lab/e2e.sh phase1'
finished=false
for _ in {1..100}; do
    state=$("${ssh_guest[@]}" 'systemctl is-active efw-iso-e2e.service || true' || true)
    if [[ $state == active || $state == failed ]]; then
        # A transient service is briefly active before ExecStart exits.
        if "${ssh_guest[@]}" 'test "$(systemctl show -p MainPID --value efw-iso-e2e.service)" = 0'; then
            finished=true
            break
        fi
    fi
    sleep 2
done
"${ssh_guest[@]}" 'journalctl -q -u efw-iso-e2e.service -o cat --no-pager' | tee -a validation.txt
"$finished"
"${ssh_guest[@]}" 'test "$(systemctl show -p Result --value efw-iso-e2e.service)" = success'
grep -Eq '^passed: 20 +failed: 0$' validation.txt
"${ssh_guest[@]}" 'bash -s' < "$repo/tests/install/fingerprint.sh" > fingerprint.txt
"${ssh_guest[@]}" 'bash -se' <<'GUEST' | tee -a validation.txt
events=$(ausearch -m AVC,USER_AVC,SELINUX_ERR -ts boot 2>/dev/null) || test "$?" -eq 1
if grep -E 'efw_(agent|web)_t|comm="nft"' <<< "$events"; then
    echo "appliance SELinux denials detected" >&2
    exit 1
fi
echo 'PASS: no SELinux denials for the appliance domains or nft since boot'
GUEST
