#!/usr/bin/env bash
# Apply / confirm / rollback lifecycle of efw-agent with real traffic.
#
# The agent runs inside the efw-fw namespace of the reference topology.
# The topology configures its own interfaces and routes. NetworkManager
# checkpoints are exercised separately by tests/nm/checkpoint.sh.
# Scenarios: confirm, deadline expiry, loss of management access, invalid
# change, kill -9 during a test, reboot (empty ruleset) recovery, shutdown
# during a test, console recovery with the agent down, socket permissions.
#
# usage: sudo EFW_TEST_VM=1 tests/agent/lifecycle.sh <bin-dir> <edge.json> <netns.sh> <httpd.py>
set -uo pipefail

BIN=${1:?bin dir with efw-agent and efwctl}; CFG=${2:?config}; TOPO=${3:?netns.sh}; HTTPD=${4:?httpd.py}
[[ "${EFW_TEST_VM:-}" == 1 && $EUID -eq 0 ]] || { echo "needs root and EFW_TEST_VM=1 (disposable VM only)" >&2; exit 2; }
BIN=$(cd "$BIN" && pwd)

W=$(mktemp -d /tmp/efw-agt.XXXX)
export EFW_SOCKET=$W/agent.sock EFW_STATE_DIR=$W/state
FAILS=0; PASSES=0; AGENT_PID=
nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
ok()  { echo "PASS  $1"; PASSES=$((PASSES + 1)); }
bad() { echo "FAIL  $1${2:+ — $2}"; FAILS=$((FAILS + 1)); }
expect() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
expect_not() { local d=$1; shift; if "$@" >/dev/null 2>&1; then bad "$d"; else ok "$d"; fi; }
http_ok() { nsx "$1" curl -s -o /dev/null -g --max-time 2 -w '%{http_code}' "$2" 2>/dev/null | grep -q 200; }
ctl() { nsx efw-fw "$BIN/efwctl" "$@"; }
export -f nsx ctl; export BIN W

start_agent() {
  # Not through nsx: a backgrounded shell function gets a subshell PID, and
  # ip netns exec execs the agent so $! is the agent itself.
  ip netns exec efw-fw "$BIN/efw-agent" -network none \
    -state-dir "$W/state" -socket "$EFW_SOCKET" -socket-group "" \
    -min-timeout 2s >>"$W/agent.log" 2>&1 &
  AGENT_PID=$!
  for _ in $(seq 50); do ctl status >/dev/null 2>&1 && return 0; sleep 0.1; done
  echo "agent did not start" >&2; tail -n 5 "$W/agent.log" >&2; return 1
}
stop_agent() { # stop_agent <signal>
  kill "-$1" "$AGENT_PID" 2>/dev/null; wait "$AGENT_PID" 2>/dev/null; AGENT_PID=
  ! pgrep -x efw-agent >/dev/null || { echo "efw-agent still running" >&2; return 1; }
}
testing_rev() { ctl status | awk '/^under test/ {print $3}'; }
confirmed_rev() { ctl status | awk '/^confirmed revision/ {print $3}'; }

cleanup() {
  [[ -n "$AGENT_PID" ]] && stop_agent KILL
  for n in efw-fw efw-inet efw-lan efw-mgmt efw-guest; do
    for p in $(ip netns pids "$n" 2>/dev/null); do kill "$p" 2>/dev/null; done
  done
  "$TOPO" down >/dev/null
  rm -rf "$W"
}
trap cleanup EXIT

# Variants of the reference configuration.
python3 -I - "$CFG" "$W" <<'EOF'
import json, sys
src, out = sys.argv[1], sys.argv[2]
a = json.load(open(src))
b = json.loads(json.dumps(a)); b["firewall"]["rules"] = [r for r in b["firewall"]["rules"] if r["id"] != "lan-out"]
c = json.loads(json.dumps(a)); c["admin"]["interfaces"] = ["lan"]
d = json.loads(json.dumps(a)); d["interfaces"][2]["vlan"]["id"] = 5000
for name, v in {"a": a, "b_no_lan_out": b, "c_mgmt_lost": c, "d_invalid": d}.items():
    json.dump(v, open(f"{out}/{name}.json", "w"), indent=1)
EOF

"$TOPO" up >/dev/null && "$TOPO" verify | tail -1
mkdir -p "$W/www"; echo ok > "$W/www/index.html"
nsx efw-inet python3 -I "$HTTPD" 80 "$W/www" >/dev/null 2>&1 &
nsx efw-fw   python3 -I "$HTTPD" 443 "$W/www" >/dev/null 2>&1 &
sleep 1

echo "== first start and confirm"
expect "agent starts with an empty store" start_agent
expect "no revision confirmed yet" bash -c "[[ \$(ctl status | awk '/^confirmed/ {print \$3}') == 0 ]]"
expect "diff shows the full ruleset as additions" bash -c "ctl diff $W/a.json | grep -q '^+ .*efw:rule:lan-out'"
expect "apply revision 1 with a 30s window" ctl apply "$W/a.json" 30
expect "revision 1 is under test" bash -c "[[ \$(ctl status | awk '/^under test/ {print \$3}') == 1 ]]"
expect "lan -> inet works under test" http_ok efw-lan http://198.51.100.10/
expect "confirm revision 1" ctl confirm 1
expect "revision 1 confirmed, nothing under test" bash -c "ctl status | grep -q 'under test          none' && [[ \$(ctl status | awk '/^confirmed/ {print \$3}') == 1 ]]"

echo "== deadline expiry restores connectivity"
expect "apply revision 2 (drops lan-out) with a 3s window" ctl apply "$W/b_no_lan_out.json" 3
expect_not "lan -> inet blocked while revision 2 is under test" http_ok efw-lan http://198.51.100.10/
sleep 4.5
expect "deadline rolled back: nothing under test, confirmed still 1" bash -c "ctl status | grep -q 'under test          none' && [[ \$(ctl status | awk '/^confirmed/ {print \$3}') == 1 ]]"
expect "lan -> inet restored after rollback" http_ok efw-lan http://198.51.100.10/
expect "rollback audited with reason" bash -c "ctl history 50 | grep rollback | grep -q 'deadline expired'"
expect_not "late confirm of revision 2 is refused" ctl confirm 2

echo "== losing management access is undone by the deadline"
expect "mgmt -> fw:443 before change" http_ok efw-mgmt http://10.99.0.1:443/
expect "apply revision 3 (console moved to lan) with a 3s window" ctl apply "$W/c_mgmt_lost.json" 3
expect_not "mgmt -> fw:443 lost during test" http_ok efw-mgmt http://10.99.0.1:443/
sleep 4.5
expect "mgmt -> fw:443 back after rollback" http_ok efw-mgmt http://10.99.0.1:443/

echo "== invalid change"
expect_not "invalid config refused" ctl apply "$W/d_invalid.json" 30
expect "refusal names the field" bash -c "ctl apply $W/d_invalid.json 30 2>&1 | grep -q 'interfaces\[2\].vlan.id'"
expect "state unchanged after refusal" bash -c "ctl status | grep -q 'under test          none' && [[ \$(ctl status | awk '/^confirmed/ {print \$3}') == 1 ]]"

echo "== agent killed (-9) during a test"
expect "apply revision 4 (drops lan-out) with a 300s window" ctl apply "$W/b_no_lan_out.json" 300
stop_agent KILL
expect_not "after kill -9 the unconfirmed ruleset is still loaded" http_ok efw-lan http://198.51.100.10/
expect "agent restarts" start_agent
expect "restart recovered: nothing under test, confirmed 1" bash -c "ctl status | grep -q 'under test          none' && [[ \$(ctl status | awk '/^confirmed/ {print \$3}') == 1 ]]"
expect "lan -> inet restored by recovery" http_ok efw-lan http://198.51.100.10/
expect "recovery audited" bash -c "ctl history 50 | grep -q '^.*recover .*rev 4'"

echo "== reboot: empty ruleset at boot, agent reapplies confirmed"
stop_agent TERM
nsx efw-fw nft delete table inet efw_filter; nsx efw-fw nft delete table ip efw_nat
expect "agent starts after simulated reboot" start_agent
expect "confirmed tables present again" bash -c "ip netns exec efw-fw nft list tables | grep -q efw_filter && ip netns exec efw-fw nft list tables | grep -q efw_nat"
expect "masquerade active again (lan -> inet)" http_ok efw-lan http://198.51.100.10/

echo "== service stopped during a test"
expect "apply revision 5 (drops lan-out) with a 300s window" ctl apply "$W/b_no_lan_out.json" 300
stop_agent TERM
expect "SIGTERM rolled back before exiting (lan -> inet works)" http_ok efw-lan http://198.51.100.10/

echo "== console recovery with the agent down"
nsx efw-fw nft delete table inet efw_filter
expect "efwctl recover reapplies confirmed without the agent" ctl recover
expect "recovered ruleset present" bash -c "ip netns exec efw-fw nft list chain inet efw_filter forward | grep -q efw:rule:lan-out"
expect "agent starts again after console recovery" start_agent

echo "== socket permissions"
expect "socket mode is 0660" bash -c "[[ \$(stat -c %a $EFW_SOCKET) == 660 ]]"
expect_not "unprivileged user cannot talk to the agent" setpriv --reuid=65534 --regid=65534 --clear-groups env EFW_SOCKET="$EFW_SOCKET" "$BIN/efwctl" status
expect "state dir is 0700" bash -c "[[ \$(stat -c %a $W/state) == 700 ]]"

if [[ $FAILS -gt 0 ]]; then echo "--- agent log (tail)"; tail -n 30 "$W/agent.log"; fi
echo "passed: $PASSES  failed: $FAILS"
[[ $FAILS -eq 0 ]]
