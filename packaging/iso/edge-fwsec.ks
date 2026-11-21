# Edge FWSec appliance — kickstart embedded in the ISO by packaging/iso/build-iso.sh.
#
# Installs Rocky Linux 10 Minimal plus the edge-fwsec RPM from the ISO itself
# (no network needed). Storage, the root password and the user are NOT set:
# the installer asks for them, so disk selection stays with the operator.

text
lang en_US.UTF-8
keyboard us
timezone UTC --utc
selinux --enforcing
# Edge FWSec owns the host firewall; firewalld is not installed.
firewall --disabled
# DHCP on the first interface with a link, so the console has an address at
# first boot. Edge FWSec itself never changes addresses until a configuration
# is applied and confirmed.
network --bootproto=dhcp --device=link --onboot=yes
repo --name=edge-fwsec --baseurl=file:///run/install/repo/edge-fwsec
services --enabled=NetworkManager,sshd,efw-agent,efw-web,efw-firstboot

%packages
@^minimal-environment
edge-fwsec
-firewalld
%end

%post --nochroot --erroronfail
# Keep the signing key and the build record of the media on the system.
install -D -m 0644 /run/install/repo/edge-fwsec/RPM-GPG-KEY-edge-fwsec /mnt/sysroot/etc/pki/rpm-gpg/RPM-GPG-KEY-edge-fwsec
install -D -m 0644 /run/install/repo/edge-fwsec/BUILD-INFO /mnt/sysroot/usr/share/doc/edge-fwsec/ISO-BUILD-INFO
%end

%post --erroronfail
rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-edge-fwsec
rpm -q edge-fwsec >> /usr/share/doc/edge-fwsec/ISO-BUILD-INFO
%end
