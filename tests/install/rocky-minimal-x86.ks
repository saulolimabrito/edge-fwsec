#version=RHEL10
cmdline
lang en_US.UTF-8
keyboard us
timezone UTC --utc
rootpw --lock
firstboot --disable
selinux --enforcing
cdrom
ignoredisk --only-use=vda
zerombr
clearpart --all --initlabel --drives=vda
autopart --type=plain
bootloader --append="console=ttyS0,115200n8"
poweroff

%packages
@^minimal-environment
%end

%post --erroronfail
cat > /usr/local/sbin/efw-minimal-probe <<'PROBE'
#!/bin/bash
set -eu
test -d /sys/firmware/efi
echo 'EFW_MINIMAL_UEFI=1'
uname -m
cat /etc/rocky-release
getenforce
rpm -q firewalld nftables || true
printf 'firewalld enabled: '
systemctl is-enabled firewalld.service || true
printf 'firewalld active: '
systemctl is-active firewalld.service || true
echo 'EFW_MINIMAL_PROBE_DONE'
systemctl poweroff --no-block
PROBE
chmod 0755 /usr/local/sbin/efw-minimal-probe
cat > /etc/systemd/system/efw-minimal-probe.service <<'UNIT'
[Unit]
Description=Report Rocky Minimal defaults on the guest serial console
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/efw-minimal-probe
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0

[Install]
WantedBy=default.target
UNIT
systemctl enable efw-minimal-probe.service
%end
