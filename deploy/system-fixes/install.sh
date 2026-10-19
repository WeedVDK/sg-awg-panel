#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Installing system-level fixes (MSS Clamping & Cascade Auto-fix)..."

# Копируем скрипты и юниты
cp "$SCRIPT_DIR"/*.sh /usr/local/sbin/
cp "$SCRIPT_DIR"/*.service /etc/systemd/system/
cp "$SCRIPT_DIR"/*.timer /etc/systemd/system/ 2>/dev/null || true

chmod +x /usr/local/sbin/mss-clamping.sh /usr/local/sbin/sg-cascade-fix.sh

# Включаем службы
systemctl daemon-reload
systemctl enable --now mss-clamping.service
systemctl enable --now sg-cascade-fix.timer

echo "==> System fixes installed and enabled."
