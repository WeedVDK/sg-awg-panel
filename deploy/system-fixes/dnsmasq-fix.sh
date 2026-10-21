#!/usr/bin/env bash
set -euo pipefail

echo "==> Fixing dnsmasq conflict (ubuntu-fan / bind-interfaces)..."
rm -f /etc/dnsmasq.d/ubuntu-fan
find /etc/dnsmasq.d/ -name "*.bak" -delete 2>/dev/null || true
sed -i 's/^bind-interfaces/# bind-interfaces/g' /etc/dnsmasq.d/* 2>/dev/null || true
systemctl restart dnsmasq || true
