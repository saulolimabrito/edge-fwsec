#!/usr/bin/env bash
# Run in the disposable Rocky Linux package builder used by the x86 ISO lab.
set -euo pipefail
commit=${1:?source commit}
release=${2:?RPM release}
dnf -y -q install rpm-build rpm-sign gnupg2 selinux-policy-devel systemd-rpm-macros \
    bzip2 make lorax createrepo_c xorriso
cd /lab
iso=Rocky-10.3-20261113.0-x86_64-minimal.iso
export GNUPGHOME
GNUPGHOME=$(mktemp -d)
gpg --batch --import rocky-key.asc
fingerprint=$(gpg --batch --with-colons --list-keys | awk -F: '$1 == "fpr" { print $10; exit }')
test "$fingerprint" = FC226859C0860BF0DDB95B085B106C736FEDFC85
gpg --batch --verify "$iso.CHECKSUM.asc" "$iso.CHECKSUM"
awk -F '[() ]+' '/^SHA256 / {print $4 "  " $2}' "$iso.CHECKSUM" | sha256sum -c -

top=$(mktemp -d)
mkdir "$top/SOURCES"
cp /product/dist/rpm/edge-fwsec-0.4.0-x86_64.tar.gz "$top/SOURCES/"
rpmbuild -bb --target x86_64 --define "_topdir $top" \
    --define 'efw_version 0.4.0' --define "efw_release $release.g$commit" \
    --define "efw_commit $commit" /product/dist/rpm/edge-fwsec.spec
rpm=("$top"/RPMS/x86_64/edge-fwsec-*.rpm)
test -f "${rpm[0]}"
key_name='Edge FWSec disposable CI signing <ci-signing@edge-fwsec.invalid>'
gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "$key_name" rsa3072 sign 1d
gpg --batch --armor --export "$key_name" > test-signing-key.asc
rpmsign --define "_gpg_name $key_name" --addsign "${rpm[0]}"

# Use the production builder with the test overlay and serial output enabled
# for this x86 runner. The base Kickstart and offline repository stay unchanged.
mkksiso() { command mkksiso --cmdline 'console=ttyS0,115200n8' "$@"; }
export -f mkksiso
cp -r /product/packaging/iso "$top/iso"
printf '\nbootloader --append="console=ttyS0,115200n8"\n' >> "$top/iso/test-overlay.ks"
bash "$top/iso/build-iso.sh" --iso "$iso" --rpm "${rpm[0]}" \
    --key test-signing-key.asc --test-ssh-key ssh.pub --out appliance-test.iso
xorriso -indev appliance-test.iso -osirrox on -extract /edge-fwsec/BUILD-INFO iso-build-info.txt
