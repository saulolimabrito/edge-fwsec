#!/usr/bin/env bash
# End-to-end test of an INSTALLED appliance (installer or ISO), through the
# HTTPS API exactly as the console uses it, with real nftables and
# NetworkManager in the root namespace.
#
# Layout: MGMT = an existing interface (default: the one carrying the default
# route; it keeps DHCP and gets SSH + console), WAN = eth90 and LAN = eth91
# (veth; peers in efwn-wan / efwn-lan namespaces). Disposable VM only.
#
# usage: sudo EFW_TEST_VM=1 tests/install/e2e.sh phase1|phase2|reboot-check [mgmt-dev]
#   phase1        bootstrap, first configuration, confirm, traffic, access, deadline rollback
#   phase2        start a change with a long window and leave it pending (then reboot the VM)
#   reboot-check  after the reboot: pending change gone, confirmed revision active
set -uo pipefail
PHASE=${1:?phase}
MGMT=${2:-$(ip -o route show default | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)}
[[ "${EFW_TEST_VM:-}" == 1 && $EUID -eq 0 ]] || { echo "needs root and EFW_TEST_VM=1 (disposable VM only)" >&2; exit 2; }
W=/var/tmp/efw-e2e; mkdir -p -m 0700 $W
JAR=$W/cookies; MIP=$(ip -o -4 addr show dev "$MGMT" scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)
BASE="https://$MIP"
FAILS=0; PASSES=0
ok()  { echo "PASS  $1"; PASSES=$((PASSES + 1)); }
bad() { echo "FAIL  $1${2:+ — $2}"; FAILS=$((FAILS + 1)); }
expect() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
expect_not() { local d=$1; shift; if "$@" >/dev/null 2>&1; then bad "$d"; else ok "$d"; fi; }
j() { python3 -I -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }

csrf() { cat $W/csrf 2>/dev/null; }
api() { # api METHOD PATH [JSON-FILE]
  local args=(-sk -b $JAR -c $JAR -H "Origin: $BASE" -H "X-CSRF-Token: $(csrf)" -X "$1" "$BASE$2")
  [[ -n ${3:-} ]] && args+=(-H 'Content-Type: application/json' --data-binary "@$3")
  curl "${args[@]}"
}
code() { curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "$@"; }

topology() {
  for x in wan:eth90 lan:eth91; do
    ns=efwn-${x%%:*}; dev=${x##*:}
    ip netns add "$ns" 2>/dev/null || continue
    ip -n "$ns" link set lo up
    ip link add "$dev" type veth peer name p0 netns "$ns"
    ip -n "$ns" link set p0 up
  done
  ip -n efwn-wan addr add 203.0.113.1/24 dev p0 2>/dev/null
  ip -n efwn-wan addr add 198.51.100.10/32 dev lo 2>/dev/null
  ip -n efwn-lan addr add 192.168.10.10/24 dev p0 2>/dev/null
  ip -n efwn-lan route replace default via 192.168.10.1
  ip -n efwn-wan route replace 192.168.0.0/16 via 203.0.113.2 2>/dev/null || true
  mkdir -p $W/www; echo ok >$W/www/index.html
  if ! ip netns pids efwn-wan | grep -q .; then
    ip netns exec efwn-wan python3 -I -m http.server --bind 198.51.100.10 --directory $W/www 80 >$W/wan-http.log 2>&1 &
  fi
}

config() { # config FILE LANOUT(yes|no)
  python3 -I - "$1" "$MGMT" "$2" <<'EOF'
import json, sys
out, mgmt, lanout = sys.argv[1], sys.argv[2], sys.argv[3] == "yes"
rules = [{"id": "lan-ping-fw", "direction": "input", "in": "lan", "service": "ping", "action": "accept"}]
if lanout:
    rules.append({"id": "lan-out", "direction": "forward", "in": "lan", "out": "wan", "source": ["lan_net"], "action": "accept"})
c = {"schema_version": 2,
 "interfaces": [
  {"name": "mgmt", "role": "mgmt", "device": mgmt, "ipv4": {"mode": "dhcp"}, "ipv6": {"mode": "slaac"}},
  {"name": "wan", "role": "wan", "device": "eth90", "ipv4": {"mode": "static", "addresses": ["203.0.113.2/24"]}, "ipv6": {"mode": "none"}},
  {"name": "lan", "role": "lan", "device": "eth91", "ipv4": {"mode": "static", "addresses": ["192.168.10.1/24"]}, "ipv6": {"mode": "static", "addresses": ["2001:db8:10::1/64"]}}],
 "routes": [{"destination": "198.51.100.0/24", "gateway": "203.0.113.1", "interface": "wan"}],
 "networks": [{"name": "lan_net", "prefixes": ["192.168.10.0/24", "2001:db8:10::/64"]}],
 "services": [{"name": "ping", "entries": [{"protocol": "icmp"}, {"protocol": "icmpv6"}]}],
 "admin": {"port": 443, "ssh": True, "ssh_port": 22, "interfaces": ["mgmt"], "sources": []},
 "firewall": {"default_input": "drop", "default_forward": "drop", "log_default": True, "rules": rules},
 "nat": {"source": [{"id": "lan-masq", "out": "wan", "source": ["lan_net"], "mode": "masquerade"}], "port_forwards": []}}
json.dump({"config": c}, open(out, "w"))
EOF
}

status() { api GET /api/v1/policy/status | j 'd["status"]'; }
confirmed() { api GET /api/v1/policy/status | j 'd["status"]["confirmed"]'; }
testing() { api GET /api/v1/policy/status | j 'd["status"]["testing"] is not None'; }
apply() { # apply CONFIGFILE TIMEOUT
  python3 -I - "$1" "$2" "$(confirmed)" >$W/apply.json <<'EOF'
import json, sys
d = json.load(open(sys.argv[1])); d["timeout_seconds"] = int(sys.argv[2]); d["base_revision"] = int(sys.argv[3]); d["message"] = "e2e"
print(json.dumps(d))
EOF
  api POST /api/v1/policy/apply $W/apply.json
}
login() {
  printf '{"username":"admin","password":"%s"}' "$(cat $W/pw)" >$W/login.json
  api POST /api/v1/login $W/login.json | j 'd["csrf"]' >$W/csrf
}
lan_http() { ip netns exec efwn-lan curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://198.51.100.10/ | grep -q 200; }
export -f j csrf api code status confirmed testing lan_http
export W JAR BASE

case $PHASE in
phase1)
  topology
  echo "== access before any configuration"
  expect "console answers on the management address ($MIP)" bash -c "[[ \$(code https://$MIP/api/v1/session) == 200 ]]"
  echo "== bootstrap through the API"
  tok=$(efwctl bootstrap 1 | sed -n 's/^    \([A-Z0-9-]\{29\}\)$/\1/p')
  head -c 18 /dev/urandom | base64 | tr -d '/+=' >$W/pw   # test-only password, kept in $W (0700)
  printf '{"token":"%s","username":"admin","password":"%s"}' "$tok" "$(cat $W/pw)" >$W/boot.json
  api POST /api/v1/bootstrap $W/boot.json | j 'd["csrf"]' >$W/csrf
  expect "administrator created with the one-time credential" bash -c "[[ -s $W/csrf && \$(cat $W/csrf) != None ]]"
  expect_not "the credential cannot be reused" bash -c "api POST /api/v1/bootstrap $W/boot.json | grep -q csrf"
  echo "== first configuration (network + firewall) with a deadline"
  config $W/a.json yes
  apply $W/a.json 120 >$W/r1.json
  expect "apply accepted (revision under test)" bash -c "j 'd[\"ok\"]' <$W/r1.json | grep -q True"
  sleep 4
  expect "NetworkManager configured LAN address" bash -c "ip -br addr show eth91 | grep -q 192.168.10.1/24"
  expect "NetworkManager configured WAN address" bash -c "ip -br addr show eth90 | grep -q 203.0.113.2/24"
  expect "static route installed" bash -c "ip route show 198.51.100.0/24 | grep -q 'via 203.0.113.1'"
  expect "efw tables loaded" bash -c "nft list tables | grep -q efw_filter"
  login   # the management profile was reactivated; sessions survive (in memory), re-login is harmless
  expect "console still reachable through management during the test" bash -c "[[ \$(code https://$MIP/api/v1/session) == 200 ]]"
  rev=$(api GET /api/v1/policy/status | j 'd["status"]["testing"]["revision"]')
  printf '{"revision": %s}' "$rev" >$W/confirm.json
  expect "confirm through the API" bash -c "api POST /api/v1/policy/confirm $W/confirm.json | grep -q '\"ok\":true'"
  expect "revision confirmed, nothing under test" bash -c "[[ \$(testing) == False && \$(confirmed) == $rev ]]"
  echo "== traffic and exposure"
  expect "LAN reaches the WAN side through masquerade" lan_http
  expect "WAN side saw the masqueraded address" bash -c "grep -q '^203.0.113.2 ' $W/wan-http.log"
  expect_not "console unreachable from the WAN side (nftables)" ip netns exec efwn-wan curl -sk --max-time 3 https://203.0.113.2/
  expect_not "console unreachable from the LAN side (nftables)" ip netns exec efwn-lan curl -sk --max-time 3 https://192.168.10.1/
  expect "SSH port open on management only" bash -c "nft list chain inet efw_filter input | grep efw:admin | grep -q '{ 22, 443 }'"
  echo "== deadline rollback restores connectivity"
  config $W/b.json no
  apply $W/b.json 30 >/dev/null
  sleep 3
  expect_not "LAN egress cut by the revision under test" lan_http
  sleep 33
  expect "deadline rolled back (nothing under test)" bash -c "[[ \$(testing) == False && \$(confirmed) == $rev ]]"
  expect "LAN egress restored" lan_http
  expect "history records author and rollback" bash -c "api GET '/api/v1/policy/history?limit=50' | grep -q 'confirmation deadline expired'"
  ;;
phase2)
  topology; login
  config $W/b.json no
  apply $W/b.json 600 >/dev/null
  sleep 3
  expect "change pending with a 10-minute window" bash -c "[[ \$(testing) == True ]]"
  expect_not "LAN egress cut by the pending change" lan_http
  echo "now reboot the VM, then run: $0 reboot-check"
  ;;
reboot-check)
  topology; sleep 8; login
  expect "agent and console running after reboot" bash -c "systemctl is-active -q efw-agent && systemctl is-active -q efw-web"
  expect "pending change abandoned at boot" bash -c "[[ \$(testing) == False ]]"
  expect "history shows the recovery" bash -c "api GET '/api/v1/policy/history?limit=50' | grep -q '\"action\":\"recover\"'"
  expect "confirmed ruleset active after reboot" bash -c "nft list chain inet efw_filter forward | grep -q efw:rule:lan-out"
  expect "confirmed LAN address active after reboot" bash -c "ip -br addr show eth91 | grep -q 192.168.10.1/24"
  expect "LAN egress works after reboot" lan_http
  ;;
esac
echo "passed: $PASSES  failed: $FAILS"
[[ $FAILS -eq 0 ]]
