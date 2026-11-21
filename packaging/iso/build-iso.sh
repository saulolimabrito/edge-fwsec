#!/usr/bin/env bash
# Builds an Edge FWSec ISO from verified official Rocky Linux 10 Minimal media.
# Runs on a Rocky Linux 10 builder with lorax (mkksiso), createrepo_c, xorriso.
#
# usage: build-iso.sh --iso IN.iso --rpm edge-fwsec.rpm --key RPM-GPG-KEY --out OUT.iso
#                     [--test-ssh-key FILE.pub]   (test variant: unattended, erases disk)
set -euo pipefail
IN= RPM= KEY= OUT= SSHKEY=
while [[ $# -gt 0 ]]; do
  case $1 in
    --iso) IN=$2; shift 2 ;; --rpm) RPM=$2; shift 2 ;; --key) KEY=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;; --test-ssh-key) SSHKEY=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ -f $IN && -f $RPM && -f $KEY && -n $OUT ]] || { sed -n '2,7p' "$0"; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d /var/tmp/efw-iso.XXXXXX)
DB=$(mktemp -d /var/tmp/efw-rpmdb.XXXXXX)
trap 'rm -rf "$W" "$DB"' EXIT

# 1. The package must be signed by exactly this key (isolated keyring; rpm
#    runs confined as rpm_t and may only write directories labelled as RPM
#    databases, directly under /var/tmp).
chcon -t rpm_var_lib_t "$DB" 2>/dev/null || true
rpm --dbpath "$DB" --initdb
rpm --dbpath "$DB" --import "$KEY"
rpm --dbpath "$DB" -K "$RPM" | grep -q 'signatures OK' || { echo "RPM signature not valid for $KEY" >&2; exit 1; }

# 2. The architecture of the package must match the media.
iso_arch=$(xorriso -indev "$IN" -osirrox on -extract /.treeinfo "$W/treeinfo" >/dev/null 2>&1; sed -n 's/^arch *= *//p' "$W/treeinfo" | head -1)
rpm_arch=$(rpm -qp --qf '%{ARCH}' "$RPM" 2>/dev/null)
[[ $iso_arch == "$rpm_arch" ]] || { echo "ISO is $iso_arch, RPM is $rpm_arch" >&2; exit 1; }

# 3. Local repository added to the ISO root as /edge-fwsec.
mkdir -p "$W/edge-fwsec"
cp "$RPM" "$W/edge-fwsec/"; cp "$KEY" "$W/edge-fwsec/RPM-GPG-KEY-edge-fwsec"
createrepo_c -q "$W/edge-fwsec"
{
  echo "base_media=$(basename "$IN") sha256=$(sha256sum "$IN" | cut -d' ' -f1)"
  echo "package=$(basename "$RPM") sha256=$(sha256sum "$RPM" | cut -d' ' -f1)"
  echo "variant=$([[ -n $SSHKEY ]] && echo TEST-unattended || echo release-interactive)"
  echo "built=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$W/edge-fwsec/BUILD-INFO"

# 4. Kickstart: release, or release + test overlay.
cp "$HERE/edge-fwsec.ks" "$W/ks.cfg"
if [[ -n $SSHKEY ]]; then
  sed "s|@SSH_PUBKEY@|$(cat "$SSHKEY")|" "$HERE/test-overlay.ks" >>"$W/ks.cfg"
fi
ksvalidator "$W/ks.cfg" 2>/dev/null || true

# 5. mkksiso keeps the original boot configuration and volume label and
#    adds inst.ks pointing at the embedded kickstart.
mkksiso --ks "$W/ks.cfg" -a "$W/edge-fwsec" "$IN" "$OUT"
sha256sum "$OUT" | tee "$OUT.sha256"
cat "$W/edge-fwsec/BUILD-INFO"
