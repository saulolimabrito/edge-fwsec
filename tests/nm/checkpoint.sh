#!/usr/bin/env bash
# efw-agent + NetworkManager checkpoints on a real NetworkManager.
#
# Runs in the VM's root namespace (NetworkManager does not manage other
# namespaces) on veth devices named eth90..eth92: Rocky's udev rules leave
# veth unmanaged unless named eth<digit>*. Peers live in efwn-* namespaces.
# The VM's eth0 and its profile are never part of any checkpoint. nftables
# is disabled here (-nft /bin/true): a drop policy in the VM's root
# namespace would cut the test harness off; the firewall path is covered by
# tests/agent/lifecycle.sh.
#
# usage: sudo EFW_TEST_VM=1 tests/nm/checkpoint.sh <bin-dir>
set -uo pipefail
BIN=$(cd "${1:?bin dir}" && pwd)
[[ "${EFW_TEST_VM:-}" == 1 && $EUID -eq 0 ]] || { echo "needs root and EFW_TEST_VM=1 (disposable VM only)" >&2; exit 2; }
systemctl is-active -q NetworkManager || { echo "NetworkManager not running" >&2; exit 2; }

W=$(mktemp -d /tmp/efw-nm.XXXX)
export EFW_SOCKET=$W/agent.sock EFW_STATE_DIR=$W/state
FAILS=0; PASSES=0; AGENT_PID=
ok()  { echo "PASS  $1"; PASSES=$((PASSES + 1)); }
bad() { echo "FAIL  $1${2:+ — $2}"; FAILS=$((FAILS + 1)); }
expect() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
expect_not() { local d=$1; shift; if "$@" >/dev/null 2>&1; then bad "$d"; else ok "$d"; fi; }
ctl() { "$BIN/efwctl" "$@"; }
has_addr() { ip -br addr show dev "$1" 2>/dev/null | grep -q " $2"; }
no_checkpoints() { [[ $(busctl get-property org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager Checkpoints) == "ao 0" ]]; }
reach() { ip netns exec "$1" ping -c2 -i0.2 -W2 "$2"; }
wait_addr() { for _ in $(seq 50); do has_addr "$1" "$2" && return 0; sleep 0.2; done; return 1; }
export -f has_addr

start_agent() {
  "$BIN/efw-agent" -state-dir "$W/state" -socket "$EFW_SOCKET" -socket-group "" -min-timeout 2s -nft /bin/true -network nm >>"$W/agent.log" 2>&1 &
  AGENT_PID=$!
  for _ in $(seq 50); do ctl status >/dev/null 2>&1 && return 0; sleep 0.1; done
  tail -n 5 "$W/agent.log" >&2; return 1
}
stop_agent() { kill "-$1" "$AGENT_PID" 2>/dev/null; wait "$AGENT_PID" 2>/dev/null; AGENT_PID=; }

cleanup() {
  [[ -n "$AGENT_PID" ]] && stop_agent KILL
  for u in $(nmcli -t -f UUID,NAME con | awk -F: '$2 ~ /^efw-|^foreign-efwtest/ {print $1}'); do nmcli con delete "$u" >/dev/null 2>&1; done
  for d in eth90 eth91 eth92 eth91.40 efwdummy9; do ip link del "$d" 2>/dev/null; done
  for n in efwn-wan efwn-lan efwn-mgt; do ip netns del "$n" 2>/dev/null; done
  rm -rf "$W"
}
trap cleanup EXIT

# Topology: three veth pairs, peers in namespaces; VLAN 40 on the LAN trunk.
for x in wan:eth90 lan:eth91 mgt:eth92; do
  ns=efwn-${x%%:*}; dev=${x##*:}
  ip netns add "$ns"; ip -n "$ns" link set lo up
  ip link add "$dev" type veth peer name p0 netns "$ns"
  ip -n "$ns" link set p0 up
done
ip -n efwn-wan addr add 172.31.1.254/24 dev p0
ip -n efwn-lan addr add 172.31.2.10/24 dev p0
ip -n efwn-lan link add link p0 name p0.40 type vlan id 40; ip -n efwn-lan link set p0.40 up
ip -n efwn-lan addr add 172.31.4.10/24 dev p0.40
ip -n efwn-mgt addr add 172.31.3.10/24 dev p0

# A foreign profile that must never be touched.
ip link add efwdummy9 type dummy
nmcli con add type dummy ifname efwdummy9 con-name foreign-efwtest ipv4.method manual ipv4.addresses 10.250.0.1/24 >/dev/null
FOREIGN_BEFORE=$(nmcli -t -f connection.uuid,ipv4.addresses con show foreign-efwtest)
ETH0_BEFORE=$(nmcli -t -f GENERAL.CONNECTION dev show eth0)

cat > "$W/a.json" <<'EOF'
{"schema_version":1,
 "interfaces":[
  {"name":"wan","role":"wan","device":"eth90","ipv4":{"mode":"static","addresses":["172.31.1.1/24"]}},
  {"name":"lan","role":"lan","device":"eth91","ipv4":{"mode":"static","addresses":["172.31.2.1/24"]},"ipv6":{"mode":"static","addresses":["2001:db8:200::1/64"]}},
  {"name":"guest","role":"opt","device":"eth91.40","vlan":{"parent":"eth91","id":40},"ipv4":{"mode":"static","addresses":["172.31.4.1/24"]}},
  {"name":"mgmt","role":"mgmt","device":"eth92","ipv4":{"mode":"static","addresses":["172.31.3.1/24"]}}],
 "routes":[{"destination":"198.18.0.0/15","gateway":"172.31.1.254"}],
 "networks":[],"services":[],
 "admin":{"port":443,"interfaces":["mgmt"],"sources":[]},
 "firewall":{"default_input":"drop","default_forward":"drop","rules":[]},
 "nat":{"source":[],"port_forwards":[]}}
EOF
# B: LAN renumbered, guest VLAN removed, route removed.
python3 -I - "$W" <<'EOF'
import json, sys
w = sys.argv[1]; a = json.load(open(f"{w}/a.json"))
a["interfaces"][1]["ipv4"]["addresses"] = ["172.31.9.1/24"]
del a["interfaces"][2]; a["routes"] = []
json.dump(a, open(f"{w}/b.json", "w"))
EOF

echo "== first apply through NetworkManager"
expect "agent starts with NetworkManager backend" start_agent
expect "apply A (60s window)" ctl apply "$W/a.json" 60
expect "lan address configured by NM" wait_addr eth91 172.31.2.1/24
expect "lan IPv6 address configured" wait_addr eth91 2001:db8:200::1/64
expect "VLAN 40 created with address" wait_addr eth91.40 172.31.4.1/24
expect "static route installed" bash -c "ip route show 198.18.0.0/15 | grep -q 'via 172.31.1.254 dev eth90'"
expect "lan peer reaches appliance" reach efwn-lan 172.31.2.1
expect "guest VLAN peer reaches appliance" reach efwn-lan 172.31.4.1
expect "a checkpoint is pending" bash -c '! [[ $(busctl get-property org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager Checkpoints) == "ao 0" ]]'
expect "confirm A" ctl confirm 1
expect "confirm released the checkpoint" no_checkpoints
expect "profiles are persisted with efw- ids" bash -c "nmcli -t -f NAME con | grep -c '^efw-' | grep -q 4"

echo "== deadline: checkpoint rollback restores the network"
expect "apply B (3s window)" ctl apply "$W/b.json" 3
expect "lan renumbered during test" wait_addr eth91 172.31.9.1/24
expect_not "VLAN 40 removed during test" ip link show eth91.40
sleep 5
expect "lan address restored after deadline" wait_addr eth91 172.31.2.1/24
expect_not "test address gone after deadline" has_addr eth91 172.31.9.1/24
expect "VLAN 40 back after deadline" wait_addr eth91.40 172.31.4.1/24
expect "route back after deadline" bash -c "ip route show 198.18.0.0/15 | grep -q 172.31.1.254"
expect "lan peer reaches appliance again" reach efwn-lan 172.31.2.1
expect "no checkpoint left" no_checkpoints

echo "== explicit rollback"
expect "apply B (60s window)" ctl apply "$W/b.json" 60
expect "lan renumbered" wait_addr eth91 172.31.9.1/24
expect "rollback on request" ctl rollback
expect "lan restored by rollback" wait_addr eth91 172.31.2.1/24

echo "== agent killed during test, restarted"
expect "apply B (300s window)" ctl apply "$W/b.json" 300
expect "lan renumbered" wait_addr eth91 172.31.9.1/24
stop_agent KILL
expect "agent restarts" start_agent
expect "recovery rolled back the pending checkpoint" wait_addr eth91 172.31.2.1/24
expect "VLAN 40 restored by recovery" wait_addr eth91.40 172.31.4.1/24
expect "no checkpoint left after recovery" no_checkpoints

echo "== agent killed and not restarted: NetworkManager's own timer"
expect "apply B (3s window; NM timer = 3s + 30s margin)" ctl apply "$W/b.json" 3
expect "lan renumbered" wait_addr eth91 172.31.9.1/24
stop_agent KILL
sleep 36
expect "NetworkManager rolled back by itself" wait_addr eth91 172.31.2.1/24
expect "VLAN 40 restored by NetworkManager" wait_addr eth91.40 172.31.4.1/24
expect "agent restarts after NM rollback" start_agent
expect "state consistent: nothing under test, confirmed 1" bash -c "$BIN/efwctl status | grep -q 'under test          none'"

echo "== NetworkManager restarted during a test"
expect "apply B (60s window)" ctl apply "$W/b.json" 60
expect "lan renumbered" wait_addr eth91 172.31.9.1/24
systemctl restart NetworkManager; sleep 3
CP_AFTER=$(busctl get-property org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager Checkpoints)
echo "      checkpoints after NetworkManager restart: $CP_AFTER"
expect "rollback after NM restart" ctl rollback
expect "lan restored (checkpoint or confirmed profiles rewritten)" wait_addr eth91 172.31.2.1/24
expect_not "test address gone" has_addr eth91 172.31.9.1/24
expect "VLAN 40 restored" wait_addr eth91.40 172.31.4.1/24

echo "== ownership"
expect "foreign profile unchanged" bash -c "[[ \"\$(nmcli -t -f connection.uuid,ipv4.addresses con show foreign-efwtest)\" == '$FOREIGN_BEFORE' ]]"
expect "eth0 keeps its own profile" bash -c "[[ \"\$(nmcli -t -f GENERAL.CONNECTION dev show eth0)\" == '$ETH0_BEFORE' ]]"
expect "eth0 never in a checkpoint (still connected)" bash -c "nmcli -t -f DEVICE,STATE dev | grep -q '^eth0:connected'"

if [[ $FAILS -gt 0 ]]; then echo "--- agent log (tail)"; tail -n 25 "$W/agent.log"; fi
echo "passed: $PASSES  failed: $FAILS"
[[ $FAILS -eq 0 ]]
