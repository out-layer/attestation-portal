#!/usr/bin/env bash
#
# Mac-side orchestrator: install the attestation-agent on a TDX node, END-TO-END, from your laptop.
#
# The agent is a read-only collector: it reads the node's dstack-vmm over loopback and PUSHES a
# fleet snapshot to the portal's /ingest. The portal never reaches into a node. One agent per node;
# each identifies itself with a distinct NODE_ID.
#
# This lives in the portal repo (not self-hosted-tdx) because it BUILDS the agent from this repo's
# source — so a new node is provisioned from version control, never a hand-copied binary.
#
# Usage:
#   PUSH_TOKEN=<ingest-token> ./deploy/install-agent.sh --node root@<ip> --node-id node-tdx-<name>
#
# Reuse an existing node's token instead of pasting it (adding a 2nd node to the same portal):
#   ./deploy/install-agent.sh --node root@23.109.254.164 --node-id node-tdx-ams-1 \
#       --token-from root@173.237.9.76
#
# Options:
#   --node <ssh>         REQUIRED. SSH target of the TDX node (lands as root).
#   --node-id <id>       REQUIRED. Stable label for this node (portal groups pushes by it).
#   --bin <path>         Use a prebuilt agent binary instead of building (skips cargo).
#   --token-from <ssh>   Read PUSH_TOKEN from that node's /etc/attestation-agent/agent.env.
#   --portal <ssh>       Also allow this node's IP on the portal's /ingest + reload nginx.
#   --ingest-url <url>   Portal ingest endpoint (default https://workers.outlayer.ai/ingest).
#   --vmm-rpc <url>      Node dstack-vmm RPC (default http://127.0.0.1:11000 — the OutLayer vmm).
#   --user <name>        Unix user the agent runs as on the node (default outlayer).
# Env:
#   PUSH_TOKEN           The portal INGEST_TOKEN. Required unless --token-from is given.
set -euo pipefail

NODE=""; NODE_ID=""; BIN=""; TOKEN_FROM=""; PORTAL=""
INGEST_URL="https://workers.outlayer.ai/ingest"; VMM_RPC="http://127.0.0.1:11000"; RUN_USER="outlayer"
while [[ $# -gt 0 ]]; do case "$1" in
  --node)       NODE="${2:?}"; shift 2;;
  --node-id)    NODE_ID="${2:?}"; shift 2;;
  --bin)        BIN="${2:?}"; shift 2;;
  --token-from) TOKEN_FROM="${2:?}"; shift 2;;
  --portal)     PORTAL="${2:?}"; shift 2;;
  --ingest-url) INGEST_URL="${2:?}"; shift 2;;
  --vmm-rpc)    VMM_RPC="${2:?}"; shift 2;;
  --user)       RUN_USER="${2:?}"; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 1;;
esac; done
HERE="$(cd "$(dirname "$0")/.." && pwd)"

[ -n "$NODE" ]    || { echo "--node <ssh> required" >&2; exit 1; }
[ -n "$NODE_ID" ] || { echo "--node-id <id> required" >&2; exit 1; }

# Resolve the ingest token: explicit env, or pulled from a sibling node (same portal = same token).
if [ -n "$TOKEN_FROM" ]; then
  echo "[token] reading PUSH_TOKEN from $TOKEN_FROM ..."
  PUSH_TOKEN="$(ssh "$TOKEN_FROM" 'grep -E "^PUSH_TOKEN=" /etc/attestation-agent/agent.env | cut -d= -f2-')"
fi
[ -n "${PUSH_TOKEN:-}" ] || { echo "PUSH_TOKEN is required (set it, or pass --token-from <ssh>)" >&2; exit 1; }

# [1/4] agent binary — build from THIS repo unless a prebuilt one was given.
if [ -z "$BIN" ]; then
  echo "[1/4] Build attestation-agent (release) from $HERE ..."
  ( cd "$HERE" && cargo build --release -p attestation-agent )
  BIN="$HERE/target/release/attestation-agent"
fi
[ -f "$BIN" ] || { echo "agent binary not found: $BIN" >&2; exit 1; }
echo "  binary: $BIN"

# [2/4] ship the binary.
echo "[2/4] Install binary on $NODE ..."
scp -q "$BIN" "$NODE:/tmp/attestation-agent.new"
ssh "$NODE" 'install -m 755 /tmp/attestation-agent.new /usr/local/bin/attestation-agent && rm -f /tmp/attestation-agent.new'

# [3/4] env (secret, 0600) + unit. base64 avoids quoting the token through ssh.
echo "[3/4] Write env + systemd unit (NODE_ID=$NODE_ID, user=$RUN_USER) ..."
ENV_B64="$(printf 'VMM_RPC=%s\nNODE_ID=%s\nPORTAL_INGEST_URL=%s\nPUSH_TOKEN=%s\nPUSH_INTERVAL_SECS=300\nAGENT_BIND=127.0.0.1:9300\n' \
  "$VMM_RPC" "$NODE_ID" "$INGEST_URL" "$PUSH_TOKEN" | base64 | tr -d '\n')"
ssh "$NODE" "RUN_USER='$RUN_USER' ENV_B64='$ENV_B64' bash -s" <<'REMOTE'
set -euo pipefail
install -d -m 755 /etc/attestation-agent
umask 077
echo "$ENV_B64" | base64 -d > /etc/attestation-agent/agent.env
chmod 600 /etc/attestation-agent/agent.env
cat > /etc/systemd/system/attestation-agent.service <<UNIT
[Unit]
Description=OutLayer Attestation Agent (read-only fleet collector -> portal push)
After=network.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_USER
ExecStart=/usr/local/bin/attestation-agent
EnvironmentFile=/etc/attestation-agent/agent.env
Restart=on-failure
RestartSec=10
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now attestation-agent
sleep 2
systemctl is-active attestation-agent
REMOTE

# [4/4] portal-side allow (optional). The portal's nginx pins /ingest to the node egress IPs.
NODE_HOST="${NODE##*@}"
if [ -n "$PORTAL" ]; then
  echo "[4/4] Allow $NODE_HOST on the portal /ingest ..."
  ssh "$PORTAL" "bash -s" <<REMOTE
set -euo pipefail
VHOST=/etc/nginx/sites-available/workers.outlayer.ai
if grep -q "allow $NODE_HOST;" "\$VHOST"; then
  echo "  already allowed"
else
  sed -i "/allow 173.237.9.76;/a\\        allow $NODE_HOST;" "\$VHOST"
  nginx -t && systemctl reload nginx && echo "  allowed + reloaded"
fi
REMOTE
else
  echo "[4/4] SKIP portal allow (no --portal). The push will 403 until the portal's nginx"
  echo "      /ingest block allows this node's egress IP ($NODE_HOST):"
  echo "        ssh <portal> \"sed -i '/allow 173.237.9.76;/a\\        allow $NODE_HOST;' \\"
  echo "          /etc/nginx/sites-available/workers.outlayer.ai && nginx -t && systemctl reload nginx\""
fi

echo "Done. Watch: ssh $NODE 'journalctl -u attestation-agent -f'"
