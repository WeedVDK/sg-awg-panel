#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Installing system-level fixes (dnsmasq, MSS clamping, cascade)..."

# 1. Fix dnsmasq
if [ -f "$SCRIPT_DIR/dnsmasq-fix.sh" ]; then
    bash "$SCRIPT_DIR/dnsmasq-fix.sh"
fi

# 2. Copy scripts and units
cp "$SCRIPT_DIR"/*.sh /usr/local/sbin/
cp "$SCRIPT_DIR"/*.service /etc/systemd/system/
cp "$SCRIPT_DIR"/*.timer /etc/systemd/system/ 2>/dev/null || true

chmod +x /usr/local/sbin/mss-clamping.sh /usr/local/sbin/sg-cascade-fix.sh

# 3. Enable services
systemctl daemon-reload
systemctl enable --now mss-clamping.service
systemctl enable --now sg-cascade-fix.timer

echo "==> System fixes installed and enabled."

# 4. Enable traffic tracker (new feature)
if [ -f /etc/systemd/system/sg-awg-traffic-tracker.timer ]; then
    systemctl daemon-reload
    systemctl enable --now sg-awg-traffic-tracker.timer
    echo "==> Traffic tracker timer enabled."
fi
