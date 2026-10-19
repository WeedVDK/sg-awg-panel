#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
AGENT_SOURCE="$SOURCE_DIR/node_agent"
TARGET_DIR="/opt/sg-awg-node"
ENV_DIR="/etc/sg-awg-node"
STATE_DIR="/var/lib/sg-awg-node"
SERVICE_FILE="/etc/systemd/system/sg-awg-node-agent.service"

[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
[[ -f "$AGENT_SOURCE/agent.py" ]] || { echo "Missing node_agent/agent.py" >&2; exit 1; }

install -d -m 0755 "$TARGET_DIR"
install -d -m 0700 "$ENV_DIR" "$STATE_DIR"
install -m 0755 "$AGENT_SOURCE/agent.py" "$TARGET_DIR/agent.py"
install -m 0644 "$AGENT_SOURCE/__init__.py" "$TARGET_DIR/__init__.py"

cat > "$SERVICE_FILE" <<'UNIT'
[Unit]
Description=SG-AWG Node Agent
After=network-online.target sg-awg-server.service sg-awg-traffic.service
Wants=network-online.target sg-awg-server.service sg-awg-traffic.service
ConditionPathExists=/etc/sg-awg-node/agent.env

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/sg-awg-node/agent.py
Restart=always
RestartSec=8
User=root
Group=root
UMask=0077
Environment=PYTHONUNBUFFERED=1
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/sg-awg-node /var/lib/sg-awg-node /var/lib/sg-awg-panel /run /etc/amnezia/amneziawg

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable sg-awg-node-agent.service >/dev/null
if [[ -f "$ENV_DIR/agent.env" ]]; then
  systemctl restart sg-awg-node-agent.service
fi
