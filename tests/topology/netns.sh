#!/usr/bin/env bash
# Edge FWSec reference test topology built from network namespaces.
#
#   efw-inet ── efw-wanr ══(wan)══ efw-fw ══(lan0 trunk)══ efw-lan (untagged)
#                                    ║                       └─ eth0.30 → efw-guest (VLAN 30)
#                                  (mgmt)
#                                    ║
#                                 efw-mgmt
#
# efw-fw is the device under test. Every object this script creates is
# prefixed "efw-" and lives in its own namespace, so the host's interfaces,
# routes and firewall are never touched. Run it only inside a disposable VM.
#
# usage: sudo EFW_TEST_VM=1 tests/topology/netns.sh up|down|verify|status
set -euo pipefail

NS=(efw-fw efw-wanr efw-inet efw-lan efw-guest efw-mgmt)

die() { echo "netns.sh: $*" >&2; exit 1; }
guard() {
  [[ "$(uname -s)" == Linux ]] || die "Linux only"
  [[ "${EFW_TEST_VM:-}" == 1 ]] || die "refusing to run without EFW_TEST_VM=1 (disposable VM only)"
  [[ $EUID -eq 0 ]] || die "needs root"
}
nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

veth() { # veth <nsA> <ifA> <nsB> <ifB>
  ip link add "$2" netns "$1" type veth peer name "$4" netns "$3"
  nsx "$1" ip link set "$2" up
  nsx "$3" ip link set "$4" up
}

addr() { # addr <ns> <if> <cidr>  (IPv6 without DAD so tests start immediately)
  if [[ $3 == *:* ]]; then nsx "$1" ip -6 addr add "$3" dev "$2" nodad; else nsx "$1" ip addr add "$3" dev "$2"; fi
}

up() {
  for n in "${NS[@]}"; do
    ip netns add "$n"
    nsx "$n" ip link set lo up
  done

  veth efw-fw wan0 efw-wanr up0
  veth efw-fw lan0 efw-lan eth0
  veth efw-fw mgmt0 efw-mgmt eth0
  veth efw-wanr inet0 efw-inet eth0

  # WAN: documentation prefixes stand in for the ISP.
  addr efw-fw   wan0 203.0.113.2/24;  addr efw-fw   wan0 2001:db8:ffff::2/64
  addr efw-wanr up0  203.0.113.1/24;  addr efw-wanr up0  2001:db8:ffff::1/64
  # "Internet" host behind the upstream router.
  addr efw-wanr inet0 198.51.100.1/24; addr efw-wanr inet0 2001:db8:100::1/64
  addr efw-inet eth0  198.51.100.10/24; addr efw-inet eth0 2001:db8:100::10/64
  # LAN (untagged) and VLAN 30 on the same trunk.
  addr efw-fw  lan0 192.168.10.1/24;  addr efw-fw  lan0 2001:db8:10::1/64
  addr efw-lan eth0 192.168.10.10/24; addr efw-lan eth0 2001:db8:10::10/64
  nsx efw-fw  ip link add link lan0 name lan0.30 type vlan id 30
  nsx efw-lan ip link add link eth0 name eth0.30 type vlan id 30
  # The guest client gets the VLAN device in its own namespace (the parent
  # stays in efw-lan), so guest traffic really originates tagged on VLAN 30.
  nsx efw-lan ip link set eth0.30 netns efw-guest
  nsx efw-fw  ip link set lan0.30 up; nsx efw-guest ip link set eth0.30 up
  addr efw-fw    lan0.30 192.168.30.1/24;  addr efw-fw    lan0.30 2001:db8:30::1/64
  addr efw-guest eth0.30 192.168.30.10/24; addr efw-guest eth0.30 2001:db8:30::10/64
  # Management network (ULA for IPv6).
  addr efw-fw   mgmt0 10.99.0.1/24;  addr efw-fw   mgmt0 fd00:99::1/64
  addr efw-mgmt eth0  10.99.0.10/24; addr efw-mgmt eth0  fd00:99::10/64

  # Forwarding on the DUT and the upstream router.
  for n in efw-fw efw-wanr; do
    nsx "$n" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
  done
  # Routes. LAN/VLAN prefixes are routed upstream so NAT can be toggled by
  # the policy under test; the topology itself is plain routing.
  nsx efw-fw   ip route add default via 203.0.113.1
  nsx efw-fw   ip -6 route add default via 2001:db8:ffff::1
  nsx efw-wanr ip route add 192.168.0.0/16 via 203.0.113.2
  nsx efw-wanr ip route add 10.99.0.0/24 via 203.0.113.2
  nsx efw-wanr ip -6 route add 2001:db8:10::/64 via 2001:db8:ffff::2
  nsx efw-wanr ip -6 route add 2001:db8:30::/64 via 2001:db8:ffff::2
  nsx efw-inet ip route add default via 198.51.100.1
  nsx efw-inet ip -6 route add default via 2001:db8:100::1
  nsx efw-lan  ip route add default via 192.168.10.1
  nsx efw-lan  ip -6 route add default via 2001:db8:10::1
  nsx efw-guest ip route add default via 192.168.30.1
  nsx efw-guest ip -6 route add default via 2001:db8:30::1
  nsx efw-mgmt ip route add default via 10.99.0.1
  nsx efw-mgmt ip -6 route add default via fd00:99::1
}

down() {
  for n in "${NS[@]}"; do ip netns del "$n" 2>/dev/null || true; done
}

check() { # check <desc> <cmd...>
  local d=$1; shift
  if "$@" >/dev/null 2>&1; then echo "PASS  $d"; else echo "FAIL  $d"; FAILS=$((FAILS + 1)); fi
}

verify() {
  FAILS=0
  local p="ping -c3 -i0.2 -W2"  # tolerate first-packet ND/ARP resolution
  check "lan  -> fw      v4"  nsx efw-lan  $p 192.168.10.1
  check "lan  -> fw      v6"  nsx efw-lan  $p 2001:db8:10::1
  check "vlan30 -> fw    v4"  nsx efw-guest $p 192.168.30.1
  check "vlan30 -> fw    v6"  nsx efw-guest $p 2001:db8:30::1
  check "vlan30 -> inet  v4 (routed)" nsx efw-guest $p 198.51.100.10
  check "mgmt -> fw      v4"  nsx efw-mgmt $p 10.99.0.1
  check "mgmt -> fw      v6"  nsx efw-mgmt $p fd00:99::1
  check "lan  -> inet    v4 (routed)" nsx efw-lan $p 198.51.100.10
  check "lan  -> inet    v6 (routed)" nsx efw-lan $p 2001:db8:100::10
  check "inet -> lan     v4 (no policy yet)" nsx efw-inet $p 192.168.10.10
  check "fw ndp neighbour on lan0" bash -c "ip netns exec efw-fw ip -6 neigh show dev lan0 | grep -q 2001:db8:10::10"
  echo "failures: $FAILS"
  [[ $FAILS -eq 0 ]]
}

status() {
  for n in "${NS[@]}"; do
    echo "== $n"; nsx "$n" ip -br addr 2>/dev/null || echo "(absent)"
  done
}

guard
case "${1:-}" in
  up) down; up; echo "topology up" ;;
  down) down; echo "topology down" ;;
  verify) verify ;;
  status) status ;;
  *) die "usage: $0 up|down|verify|status" ;;
esac
