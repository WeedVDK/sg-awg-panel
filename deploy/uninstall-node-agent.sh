#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

systemctl disable --now sg-awg-node-agent.service 2>/dev/null || true
pkill -TERM -f '^/usr/bin/python3 /opt/sg-awg-node/agent.py$' 2>/dev/null || true

# Remove every local trace of the Cluster enrollment: Agent token, node slug,
# cached jobs/heartbeats and the managed Cascade runtime. The normal awg0
# server and its ordinary clients are intentionally left installed.
if [[ -s /etc/amnezia/amneziawg/sgcascade.conf ]] && command -v awg-quick >/dev/null 2>&1; then
  awg-quick down /etc/amnezia/amneziawg/sgcascade.conf >/dev/null 2>&1 || true
fi
ip link delete sgcascade >/dev/null 2>&1 || true
nft delete table inet sg_awg_node_cascade >/dev/null 2>&1 || true
nft delete table ip sg_awg_node_cascade_nat >/dev/null 2>&1 || true
while ip rule del priority 13050 >/dev/null 2>&1; do :; done
ip route flush table 23000 >/dev/null 2>&1 || true

rm -f \
  /etc/amnezia/amneziawg/sgcascade.conf \
  /etc/systemd/system/sg-awg-node-agent.service
rm -rf \
  /etc/systemd/system/sg-awg-node-agent.service.d \
  /opt/sg-awg-node \
  /etc/sg-awg-node \
  /var/lib/sg-awg-node \
  /tmp/sg-awg-node.* \
  /tmp/sg-awg-node-enroll.*
find /etc/systemd/system -type l -name 'sg-awg-node-agent.service' -delete 2>/dev/null || true

systemctl daemon-reload
systemctl reset-failed sg-awg-node-agent.service 2>/dev/null || true

echo "SG-AWG Node connection removed completely. Agent token, identity and state were deleted."
echo "AmneziaWG awg0 and ordinary clients were left installed."
