#!/usr/bin/env bash
# Edge FWSec installer for Rocky Linux 10.
#
# Installs the edge-fwsec RPM with DNF on an existing Rocky Linux 10 system
# and prepares first access. It never changes IP addresses, NetworkManager
# profiles or nftables tables it does not own. Running it again is safe:
# installed versions, configuration and accounts are preserved.
#
# usage: install.sh --rpm FILE [options]
#   --rpm FILE                 edge-fwsec RPM for this architecture (required)
#   --gpg-key FILE             public key to verify the RPM signature (imported into rpm)
#   --allow-unsigned           accept an unsigned RPM (development builds only)
#   --mgmt-interface DEV       interface that serves the console before the first
#                              configuration (default: the interface of this SSH
#                              session, else the default-route interface)
#   --replace-firewalld        stop and mask firewalld (snapshot kept for --restore-firewalld)
#   --restore-firewalld        undo --replace-firewalld from the last snapshot and exit
#   --repo DIR                 extra local repository (offline installs, e.g. from the ISO)
#   --yes                      do not ask for confirmation
#   --dry-run                  run every check, change nothing
set -euo pipefail

LOG=/var/log/edge-fwsec-install.log
SNAPDIR=/var/lib/edge-fwsec-install
RPM_FILE= GPG_KEY= ALLOW_UNSIGNED=0 MGMT= REPLACE_FW=0 RESTORE_FW=0 REPO= YES=0 DRY=0

say()  { printf '%s\n' "$*"; printf '%s %s\n' "$(date -Is)" "$*" >>"$LOG" 2>/dev/null || true; }
step() { say "==> $*"; }
fail() { say "ERROR: $*"; exit 1; }
run()  { if [[ $DRY == 1 ]]; then say "    (dry run) $*"; else say "    $*"; "$@" >>"$LOG" 2>&1; fi; }

while [[ $# -gt 0 ]]; do
  case $1 in
    --rpm) RPM_FILE=$2; shift 2 ;;
    --gpg-key) GPG_KEY=$2; shift 2 ;;
    --allow-unsigned) ALLOW_UNSIGNED=1; shift ;;
    --mgmt-interface) MGMT=$2; shift 2 ;;
    --replace-firewalld) REPLACE_FW=1; shift ;;
    --restore-firewalld) RESTORE_FW=1; shift ;;
    --repo) REPO=$2; shift 2 ;;
    --yes) YES=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) fail "unknown option $1 (see --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail "run as root"
mkdir -p "$(dirname "$LOG")"

if [[ $RESTORE_FW == 1 ]]; then
  snapshots=("$SNAPDIR"/firewalld-*)
  last=${snapshots[-1]}
  [[ -d $last ]] || fail "no firewalld snapshot in $SNAPDIR"
  step "Restoring firewalld from $last"
  run systemctl disable --now efw-agent.service
  run systemctl unmask firewalld.service
  if [[ $(cat "$last/enabled" 2>/dev/null) == enabled ]]; then run systemctl enable firewalld.service; fi
  if [[ $(cat "$last/active" 2>/dev/null) == active ]]; then run systemctl start firewalld.service; fi
  # A confirmed revision leaves its rules loaded on agent shutdown.
  # Release those tables once firewalld has recovered its prior state.
  run nft -f - <<'NFT'
destroy table inet efw_filter
destroy table ip efw_nat
NFT
  if [[ $DRY != 1 ]]; then
    say "firewalld restored and Edge FWSec tables removed. Saved revisions were preserved."
  fi
  exit 0
fi

# ---------------------------------------------------------------- checks
step "Checking the system"
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == rocky && ${VERSION_ID%%.*} == 10 ]] || fail "Rocky Linux 10 is required (found ${PRETTY_NAME:-unknown})"
say "    OS: $PRETTY_NAME"

ARCH=$(uname -m)
case $ARCH in
  x86_64)
    ld=/usr/lib64/ld-linux-x86-64.so.2
    if ! "$ld" --help 2>/dev/null | grep -q 'x86-64-v3 (supported'; then
      fail "this CPU does not support x86-64-v3, required by Rocky Linux 10 and Edge FWSec"
    fi ;;
  aarch64) ;;
  *) fail "unsupported architecture $ARCH" ;;
esac
say "    Architecture: $ARCH"

[[ -n $RPM_FILE && -f $RPM_FILE ]] || fail "--rpm FILE is required"
pkg_arch=$(rpm -qp --qf '%{ARCH}' "$RPM_FILE" 2>/dev/null) || fail "$RPM_FILE is not a readable RPM"
pkg_name=$(rpm -qp --qf '%{NAME}' "$RPM_FILE")
pkg_evr=$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$RPM_FILE")
[[ $pkg_name == edge-fwsec ]] || fail "$RPM_FILE is $pkg_name, not edge-fwsec"
[[ $pkg_arch == "$ARCH" ]] || fail "$RPM_FILE is built for $pkg_arch, this machine is $ARCH"
say "    Package: edge-fwsec $pkg_evr ($pkg_arch)"

sig="no --gpg-key given"
if [[ -n $GPG_KEY ]]; then
  [[ -f $GPG_KEY ]] || fail "key $GPG_KEY not found"
  # Verify against a throwaway database holding only this key, so the check
  # proves the package was signed by *this* key (and works in --dry-run).
  tmpdb=$(mktemp -d /var/tmp/efw-rpmdb.XXXXXX)
  trap 'rm -rf "$tmpdb"' EXIT
  # rpm runs confined (rpm_t) and may only write RPM databases.
  chcon -t rpm_var_lib_t "$tmpdb" 2>/dev/null || true
  rpm --dbpath "$tmpdb" --initdb
  rpm --dbpath "$tmpdb" --import "$GPG_KEY" || fail "cannot import $GPG_KEY"
  sig=$(rpm --dbpath "$tmpdb" -K "$RPM_FILE" 2>&1 || true)
fi
if grep -q 'signatures OK' <<<"$sig"; then
  say "    Signature: OK ($(rpm -qp --qf '%{RSAHEADER:pgpsig}' "$RPM_FILE" 2>/dev/null))"
  run rpm --import "$GPG_KEY"
elif [[ $ALLOW_UNSIGNED == 1 ]]; then
  say "    Signature: NOT VERIFIED (--allow-unsigned): $sig"
else
  fail "signature check failed: $sig (import the release key with --gpg-key)"
fi

systemctl is-active -q NetworkManager || fail "NetworkManager must be running (Edge FWSec manages interfaces through it)"
se=$(getenforce 2>/dev/null || echo Disabled)
case $se in
  Enforcing) say "    SELinux: enforcing" ;;
  Permissive) say "    WARNING: SELinux is permissive. Edge FWSec ships a policy for enforcing mode; this installer does not change the mode." ;;
  *) fail "SELinux is disabled; Edge FWSec requires SELinux (enforcing)" ;;
esac

for svc in iptables ip6tables nftables; do
  if systemctl is-enabled -q "$svc.service" 2>/dev/null; then
    fail "$svc.service is enabled and would load its own ruleset at boot; disable it first"
  fi
done

fw_active=$(systemctl is-active firewalld.service 2>/dev/null || true)
fw_enabled=$(systemctl is-enabled firewalld.service 2>/dev/null || true)
if [[ $fw_active == active || $fw_enabled == enabled ]]; then
  if [[ $REPLACE_FW != 1 ]]; then
    fail "firewalld is $fw_active/$fw_enabled. Edge FWSec owns the host firewall; rerun with --replace-firewalld (a snapshot is kept and --restore-firewalld undoes it)"
  fi
  say "    firewalld: $fw_active/$fw_enabled — will be replaced (--replace-firewalld)"
else
  say "    firewalld: not in use"
fi

tables=$(nft list tables 2>/dev/null | grep -v -E 'inet efw_filter|ip efw_nat' || true)
if [[ -n $tables ]]; then
  say "    Existing nftables tables (left untouched):"
  while read -r t; do say "      $t"; done <<<"$tables"
fi

# Management interface used before the first configuration.
if [[ -z $MGMT && -f /etc/edge-fwsec/web.env ]]; then
  MGMT=$(sed -n 's/^EFW_BOOTSTRAP_INTERFACES=//p' /etc/edge-fwsec/web.env)
fi
if [[ -z $MGMT && -n ${SSH_CONNECTION:-} ]]; then
  MGMT=$(ip -o route get "${SSH_CONNECTION%% *}" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p')
fi
if [[ -z $MGMT ]]; then
  MGMT=$(ip -o route show default 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
fi
[[ -n $MGMT ]] || fail "could not determine the management interface; pass --mgmt-interface"
ip link show "$MGMT" >/dev/null 2>&1 || fail "interface $MGMT does not exist"
mgmt_ip=$(ip -o -4 addr show dev "$MGMT" scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)
say "    Console before first configuration: $MGMT (${mgmt_ip:-no IPv4 address})"

installed=$(rpm -q --qf '%{VERSION}-%{RELEASE}' edge-fwsec 2>/dev/null || true)
[[ $installed == *"not installed"* ]] && installed=
if [[ -n $installed ]]; then say "    Installed: edge-fwsec $installed"; fi

if [[ $YES != 1 && $DRY != 1 ]]; then
  read -r -p "Proceed with the installation? [y/N] " a
  [[ $a == y || $a == Y ]] || fail "cancelled"
fi

# ---------------------------------------------------------------- changes
if [[ $REPLACE_FW == 1 && ( $fw_active == active || $fw_enabled == enabled ) ]]; then
  step "Replacing firewalld"
  snap=$SNAPDIR/firewalld-$(date +%Y%m%d-%H%M%S)
  if [[ $DRY != 1 ]]; then
    mkdir -p -m 0700 "$snap"
    echo "$fw_active" >"$snap/active"; echo "$fw_enabled" >"$snap/enabled"
    firewall-cmd --list-all-zones >"$snap/zones.txt" 2>&1 || true
    nft list ruleset >"$snap/ruleset.nft" 2>&1 || true
    cp -a /etc/firewalld "$snap/etc-firewalld" 2>/dev/null || true
  fi
  say "    snapshot: $snap"
  run systemctl disable --now firewalld.service
  run systemctl mask firewalld.service
fi

step "Installing edge-fwsec $pkg_evr"
if [[ $installed == "$pkg_evr" ]]; then
  say "    already installed; nothing to do"
else
  dnfargs=(-y)
  [[ -n $REPO ]] && dnfargs+=(--repofrompath "edge-fwsec-local,$REPO" --setopt=edge-fwsec-local.gpgcheck=0)
  run dnf "${dnfargs[@]}" install "$RPM_FILE"
fi

step "Preparing first access"
if [[ -f /etc/edge-fwsec/web.env ]]; then
  say "    /etc/edge-fwsec/web.env exists; kept unchanged"
elif [[ $DRY != 1 ]]; then
  install -d -m 0755 /etc/edge-fwsec
  printf '# Devices that serve the console before the first confirmed configuration.\nEFW_BOOTSTRAP_INTERFACES=%s\n' "$MGMT" >/etc/edge-fwsec/web.env
  chmod 0644 /etc/edge-fwsec/web.env
  restorecon -R /etc/edge-fwsec >/dev/null 2>&1 || true
  say "    wrote /etc/edge-fwsec/web.env (bootstrap interface $MGMT)"
fi
run systemctl enable --now efw-agent.service
run systemctl enable --now efw-web.service
if [[ $DRY != 1 ]]; then
  for _ in $(seq 30); do systemctl is-active -q efw-web.service && break; sleep 1; done
  systemctl is-active -q efw-agent.service || fail "efw-agent did not start (journalctl -u efw-agent)"
  systemctl is-active -q efw-web.service || fail "efw-web did not start (journalctl -u efw-web)"
fi

if [[ $DRY == 1 ]]; then
  say "Dry run complete; nothing was changed."
  exit 0
fi
if [[ -s /var/lib/efw-web/users.json ]]; then
  say "    An administrator already exists; no bootstrap credential issued (efwctl bootstrap issues one)."
else
  efwctl bootstrap 24
fi
say ""
say "Edge FWSec $pkg_evr is running. Open https://${mgmt_ip:-<address of $MGMT>}/ from the management network."
say "Nothing is filtered until you apply and confirm a configuration in the console."
