#!/usr/bin/env bash
# Prints a normalized description of an Edge FWSec installation, to compare
# install paths (ISO vs installer) on the same architecture with `diff`.
set -uo pipefail
echo "## package"
rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' edge-fwsec
echo "rpm -V: $(rpm -V edge-fwsec >/dev/null 2>&1 && echo clean || rpm -V edge-fwsec | sed 's/  */ /g' | tr '\n' ';')"
echo "## system"
echo "os $(. /etc/os-release; echo "$ID $VERSION_ID") arch $(uname -m) selinux $(getenforce)"
semodule --list-modules=full 2>/dev/null | awk '$2=="efw"{print "selinux module", $1, $2}'
echo "firewalld $(rpm -q firewalld >/dev/null 2>&1 && systemctl is-enabled firewalld 2>/dev/null || echo not-installed)"
echo "nftables.service $(systemctl is-enabled nftables 2>/dev/null)"
echo "## services"
for u in efw-agent efw-web; do echo "$u enabled=$(systemctl is-enabled $u) active=$(systemctl is-active $u)"; done
# One-shot: what matters is that it is enabled and that first access exists.
echo "efw-firstboot enabled=$(systemctl is-enabled efw-firstboot) prepared=$([[ -f /etc/edge-fwsec/web.env ]] && echo yes || echo no)"
ps -eZ | awk '/efw-(agent|web)$/{print "domain", $NF, $1}' | sort
echo "## accounts"
getent passwd efw-web | awk -F: '{print "user efw-web home=" $6 " shell=" $7}'
getent group efw | awk -F: '{print "group efw"}'
echo "## paths (mode owner:group label)"
for p in /usr/bin/efw-agent /usr/bin/efw-web /usr/bin/efwctl /var/lib/efw /var/lib/efw-web /run/efw /run/efw/agent.sock /etc/edge-fwsec /etc/edge-fwsec/web.env /var/lib/efw/state.json /var/lib/efw-web/tls /var/lib/efw-web/tls/self.key; do
  [[ -e $p ]] && stat -c "%n %a %U:%G %C" "$p" || echo "$p missing"
done
echo "## sysctl"
sysctl -n net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_redirects | paste -sd' '
echo "## sandbox (effective)"
for u in efw-agent efw-web; do systemctl show "$u" -p User -p NoNewPrivileges -p ProtectSystem -p CapabilityBoundingSet -p AmbientCapabilities | sort | paste -sd' ' | sed "s/^/$u /"; done
