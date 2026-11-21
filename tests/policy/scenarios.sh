#!/usr/bin/env bash
# Policy engine acceptance scenarios with real traffic between namespaces.
#
# Builds the reference topology (tests/topology/netns.sh), applies the
# ruleset rendered from internal/policy/testdata/edge.json inside efw-fw and
# checks allow/deny, stateful return traffic, NAT, port forwarding, IPv6,
# essential ICMPv6, management access, third-party table preservation,
# idempotent re-apply and atomic failure.
#
# usage: sudo EFW_TEST_VM=1 tests/policy/scenarios.sh <efwctl> <config.json> <netns.sh>
set -uo pipefail

EFWCTL=${1:?efwctl binary}; CFG=${2:?config}; TOPO=${3:?netns.sh}
[[ "${EFW_TEST_VM:-}" == 1 && $EUID -eq 0 ]] || { echo "needs root and EFW_TEST_VM=1 (disposable VM only)" >&2; exit 2; }
command -v curl >/dev/null && command -v python3 >/dev/null && command -v nft >/dev/null || { echo "needs curl, python3, nft" >&2; exit 2; }

W=$(mktemp -d /tmp/efw-scn.XXXX)
HTTPD="$(cd "$(dirname "$0")" && pwd)/httpd.py"
FAILS=0; PASSES=0
nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
ok()  { echo "PASS  $1"; PASSES=$((PASSES + 1)); }
bad() { echo "FAIL  $1${2:+ — $2}"; FAILS=$((FAILS + 1)); }

# http <ns> <url> → prints "code exit" ; drop ⇒ exit 28 (timeout), reject ⇒ exit 7 fast
http() { local out; out=$(nsx "$1" curl -sS -o /dev/null -g --max-time 2 -w '%{http_code}' "$2" 2>/dev/null); echo "${out:-000} $?"; }
expect_http() { # desc ns url want(200|drop|reject|refused)
  local r; r=$(http "$2" "$3"); local code=${r% *} rc=${r#* }
  case $4 in
    200)    [[ $code == 200 ]] && ok "$1" || bad "$1" "got code=$code rc=$rc" ;;
    drop)   [[ $rc == 28 ]] && ok "$1" || bad "$1" "expected timeout, got code=$code rc=$rc" ;;
    reject) [[ $rc == 7 ]] && ok "$1" || bad "$1" "expected fast reject, got code=$code rc=$rc" ;;
  esac
}
expect() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
expect_not() { local d=$1; shift; if "$@" >/dev/null 2>&1; then bad "$d"; else ok "$d"; fi; }

serve() { # serve <ns> <port> <log> : dual-stack HTTP server logging client addresses
  mkdir -p "$W/www"; echo ok > "$W/www/index.html"
  nsx "$1" python3 -I "$HTTPD" "$2" "$W/www" >"$3" 2>&1 &
}
stateless() { nsx efw-fw nft -s list table inet efw_filter; nsx efw-fw nft -s list table ip efw_nat; }
cleanup() {
  for n in efw-fw efw-inet efw-lan efw-mgmt efw-guest; do
    for p in $(ip netns pids "$n" 2>/dev/null); do kill "$p" 2>/dev/null; done
  done
  "$TOPO" down >/dev/null
  rm -rf "$W"
}
trap cleanup EXIT

# Netfilter only logs from non-initial namespaces when this is set. The
# appliance itself runs in the initial namespace and does not need it.
sysctl -qw net.netfilter.nf_log_all_netns=1

echo "== topology"
"$TOPO" up >/dev/null && "$TOPO" verify | tail -1

echo "== third-party table and policy load"
printf 'table inet thirdparty {\n\tchain c {\n\t\ttype filter hook input priority 10; policy accept;\n\t\tcounter\n\t}\n}\n' | nsx efw-fw nft -f -
expect "kernel accepts rendered ruleset (nft --check)" nsx efw-fw "$EFWCTL" policy check "$CFG"
"$EFWCTL" policy render "$CFG" > "$W/rules.nft"
expect "apply ruleset atomically" nsx efw-fw nft -f "$W/rules.nft"
stateless > "$W/applied.txt"

serve efw-inet 80   "$W/inet80.log"
serve efw-inet 9000 "$W/inet9000.log"
serve efw-lan  80   "$W/lan80.log"
serve efw-lan  9000 "$W/lan9000.log"
serve efw-fw   443  "$W/fw443.log"
wait_listen() { # wait_listen <ns> <port>
  for _ in $(seq 50); do nsx "$1" ss -Hltn "sport = :$2" | grep -q . && return 0; sleep 0.2; done
  echo "server on $1:$2 did not start" >&2; for f in "$W"/*.log; do echo "--- $f"; tail -n 5 "$f"; done >&2; return 1
}
for sp in efw-inet:80 efw-inet:9000 efw-lan:80 efw-lan:9000 efw-fw:443; do wait_listen "${sp%:*}" "${sp#*:}" || exit 2; done

echo "== LAN egress, stateful return, masquerade"
expect_http "lan -> inet v4 http allowed"        efw-lan "http://198.51.100.10/" 200
expect "inet sees masqueraded source 203.0.113.2" grep -Eq '^(::ffff:)?203\.0\.113\.2 ' "$W/inet80.log"
expect_http "lan -> inet v6 http allowed (routed)" efw-lan "http://[2001:db8:100::10]/" 200
expect "inet sees real IPv6 source (no NAT66)"    grep -q '2001:db8:10::10' "$W/inet80.log"
expect "counter of rule lan-out increased" bash -c "ip netns exec efw-fw nft list chain inet efw_filter forward | grep 'efw:rule:lan-out' | grep -qv 'packets 0 '"

echo "== WAN ingress (new connections)"
expect_http "inet -> lan v4 new connection dropped"  efw-inet "http://192.168.10.10/" drop
expect_http "inet -> lan v6 :9000 dropped"           efw-inet "http://[2001:db8:10::10]:9000/" drop
expect_http "inet -> lan v6 :80 allowed by web6-in"  efw-inet "http://[2001:db8:10::10]/" 200

echo "== Port forward (DNAT)"
expect_http "inet -> 203.0.113.2:8080 forwarded to lan:80" efw-inet "http://203.0.113.2:8080/" 200
expect "lan server sees original client 198.51.100.10" grep -Eq '^(::ffff:)?198\.51\.100\.10 ' "$W/lan80.log"
expect_http "inet -> 192.168.10.10:9000 still dropped" efw-inet "http://192.168.10.10:9000/" drop

echo "== Management access"
expect_http "mgmt -> fw:443 v4 allowed"    efw-mgmt "http://10.99.0.1:443/" 200
expect_http "mgmt -> fw:443 v6 allowed"    efw-mgmt "http://[fd00:99::1]:443/" 200
expect_http "inet -> wan:443 dropped (panel not on WAN)"     efw-inet "http://203.0.113.2:443/" drop
expect_http "inet -> wan:443 v6 dropped (panel not on WAN)"  efw-inet "http://[2001:db8:ffff::2]:443/" drop
expect_http "lan -> fw:443 dropped (lan is not a mgmt network)" efw-lan "http://192.168.10.1:443/" drop

echo "== Guest VLAN 30"
expect_http "guest -> inet:80 allowed (web)"      efw-guest "http://198.51.100.10/" 200
expect_http "guest -> inet:9000 dropped (not web/dns)" efw-guest "http://198.51.100.10:9000/" drop
expect_http "guest -> lan rejected (icmpx admin-prohibited)" efw-guest "http://192.168.10.10/" reject
expect_http "guest -> lan v6 rejected" efw-guest "http://[2001:db8:10::10]/" reject
expect "guest-no-lan logged to kernel log" bash -c "dmesg | grep -q 'efw guest-no-lan '"

echo "== ICMP and essential ICMPv6 under default drop"
expect     "lan ping fw v4 (rule lan-ping-fw)" nsx efw-lan ping -c2 -i0.2 -W2 192.168.10.1
expect     "lan ping fw v6 (rule lan-ping-fw)" nsx efw-lan ping -c2 -i0.2 -W2 2001:db8:10::1
expect_not "inet ping fw wan v4 dropped"       nsx efw-inet ping -c2 -i0.2 -W1 203.0.113.2
expect_not "mgmt ping fw dropped (no rule)"    nsx efw-mgmt ping -c2 -i0.2 -W1 10.99.0.1
nsx efw-mgmt ip -6 neigh flush dev eth0; nsx efw-fw ip -6 neigh flush dev mgmt0
expect_http "neighbour discovery works under drop (mgmt v6 after flush)" efw-mgmt "http://[fd00:99::1]:443/" 200
nsx efw-wanr ip link set inet0 mtu 1280; nsx efw-inet ip link set eth0 mtu 1280
nsx efw-lan ping -6 -c2 -i0.3 -W1 -s 1400 -M do 2001:db8:100::10 >/dev/null 2>&1
expect "Packet Too Big forwarded: lan learns PMTU 1280" bash -c "ip netns exec efw-lan ip -6 route get 2001:db8:100::10 | grep -q 'mtu 1280'"

echo "== Ownership, idempotence, atomic failure"
expect "third-party table preserved after apply" bash -c "ip netns exec efw-fw nft list tables | grep -q 'table inet thirdparty'"
expect "re-apply succeeds" nsx efw-fw nft -f "$W/rules.nft"
stateless > "$W/reapplied.txt"
expect "re-apply is idempotent (stateless listing unchanged)" diff -q "$W/applied.txt" "$W/reapplied.txt"
{ cat "$W/rules.nft"; printf 'add rule inet efw_filter input tcp dport 99999 accept\n'; } > "$W/broken.nft"
expect_not "broken batch is refused" nsx efw-fw nft -f "$W/broken.nft"
stateless > "$W/after-broken.txt"
expect "refused batch left previous ruleset intact" diff -q "$W/applied.txt" "$W/after-broken.txt"
expect "third-party table still preserved" bash -c "ip netns exec efw-fw nft list tables | grep -q 'table inet thirdparty'"
expect_http "traffic still flows after refused batch" efw-lan "http://198.51.100.10/" 200

echo "passed: $PASSES  failed: $FAILS"
[[ $FAILS -eq 0 ]]
