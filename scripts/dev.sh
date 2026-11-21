#!/usr/bin/env bash
# Local development stack: efw-agent with a fake nft and no network backend,
# efw-web on https://127.0.0.1:8443 (self-signed), and a bootstrap token.
# Never changes the workstation's firewall or network.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
STATE=${EFW_DEV_STATE:-$ROOT/dist/dev-state}
mkdir -p "$STATE"
SOCK=$(mktemp -u /tmp/efw-dev-XXXX).sock   # short path: sun_path is limited
trap 'kill 0' EXIT
"$ROOT/dist/local/efw-agent" -state-dir "$STATE/agent" -socket "$SOCK" -socket-group "" \
  -nft /usr/bin/true -network none -min-timeout 10s &
sleep 0.5
if [[ ! -s "$STATE/web/users.json" ]]; then
  EFW_WEB_STATE_DIR="$STATE/web" "$ROOT/dist/local/efwctl" bootstrap 24
fi
"$ROOT/dist/local/efw-web" -listen 127.0.0.1:8443 -state-dir "$STATE/web" -agent-socket "$SOCK"
