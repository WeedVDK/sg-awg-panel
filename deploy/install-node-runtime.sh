#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$SOURCE_DIR/deploy"
# shellcheck source=deploy/install-common.sh
. "$SCRIPT_DIR/install-common.sh"

install_log_init
require_root
require_supported_ubuntu
require_supported_architecture
require_no_pending_reboot

install_info "SG-AWG Node Runtime — подготовка сервера"
run_logged "Установка AmneziaWG..." bash "$SCRIPT_DIR/install-amneziawg.sh"
wait_for_apt
run_logged "Установка компонентов SG-Node..." env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
  apt-get -o Dpkg::Use-Pty=0 install -y -qq python3 ca-certificates curl jq iproute2 util-linux nftables conntrack nginx psmisc

install -d -m 0700 /etc/sg-awg-node /var/lib/sg-awg-node
install -d -m 0755 /opt/sg-awg-node

# Clear a stale managed Cascade runtime from an interrupted previous install.
# This does not touch the standard awg0 server.
if [[ -s /etc/amnezia/amneziawg/sgcascade.conf ]]; then
  awg-quick down /etc/amnezia/amneziawg/sgcascade.conf >/dev/null 2>&1 || true
fi
nft delete table inet sg_awg_node_cascade >/dev/null 2>&1 || true
nft delete table ip sg_awg_node_cascade_nat >/dev/null 2>&1 || true
while ip rule del priority 13050 >/dev/null 2>&1; do :; done
ip route flush table 23000 >/dev/null 2>&1 || true
rm -f /etc/amnezia/amneziawg/sgcascade.conf \
      /etc/sg-awg-node/cascade.json \
      /etc/sg-awg-node/cascade.nft

cat > /etc/systemd/system/sg-awg-traffic.service <<'UNIT'
[Unit]
Description=SG-AWG Node managed traffic rules
After=network-online.target sg-awg-server.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '/usr/sbin/nft delete table inet sg_awg_node_filter 2>/dev/null || true; /usr/sbin/nft delete table ip sg_awg_node_nat 2>/dev/null || true; /usr/sbin/nft delete table inet sg_awg_node_cascade 2>/dev/null || true; /usr/sbin/nft delete table ip sg_awg_node_cascade_nat 2>/dev/null || true; if [ -s /etc/sg-awg-node/traffic.nft ]; then /usr/sbin/nft -c -f /etc/sg-awg-node/traffic.nft && /usr/sbin/nft -f /etc/sg-awg-node/traffic.nft; fi; if [ -s /etc/sg-awg-node/cascade.nft ]; then /usr/sbin/nft -c -f /etc/sg-awg-node/cascade.nft && /usr/sbin/nft -f /etc/sg-awg-node/cascade.nft; fi'
ExecReload=/bin/sh -c '/usr/sbin/nft delete table inet sg_awg_node_filter 2>/dev/null || true; /usr/sbin/nft delete table ip sg_awg_node_nat 2>/dev/null || true; /usr/sbin/nft delete table inet sg_awg_node_cascade 2>/dev/null || true; /usr/sbin/nft delete table ip sg_awg_node_cascade_nat 2>/dev/null || true; if [ -s /etc/sg-awg-node/traffic.nft ]; then /usr/sbin/nft -c -f /etc/sg-awg-node/traffic.nft && /usr/sbin/nft -f /etc/sg-awg-node/traffic.nft; fi; if [ -s /etc/sg-awg-node/cascade.nft ]; then /usr/sbin/nft -c -f /etc/sg-awg-node/cascade.nft && /usr/sbin/nft -f /etc/sg-awg-node/cascade.nft; fi'
ExecStop=/bin/sh -c '/usr/sbin/nft delete table inet sg_awg_node_filter 2>/dev/null || true; /usr/sbin/nft delete table ip sg_awg_node_nat 2>/dev/null || true; /usr/sbin/nft delete table inet sg_awg_node_cascade 2>/dev/null || true; /usr/sbin/nft delete table ip sg_awg_node_cascade_nat 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
UNIT

run_logged "Установка SG-Node Agent..." bash "$SCRIPT_DIR/install-node-agent.sh" "$SOURCE_DIR"
run_logged "Регистрация служб SG-Node..." systemctl daemon-reload

run_logged "Подготовка стандартного AWG Server на UDP 585..." bash -c '
  set -Eeuo pipefail
  conf=/etc/amnezia/amneziawg/awg0.conf
  if [[ ! -s "$conf" ]]; then
    private_key="$(awg genkey)"
    cat > "$conf" <<EOF
[Interface]
Address = 10.77.0.1/24
ListenPort = 585
PrivateKey = $private_key
MTU = 1280
Jc = 6
Jmin = 64
Jmax = 128
S1 = 48
S2 = 48
S3 = 32
S4 = 16
H1 = 1225274177-1231008464
H2 = 537566298-540327959
H3 = 2495884203-2499225783
H4 = 2752445069-2755875892
EOF
    chmod 0600 "$conf"
  fi
  actual_port="$(awk -F= '\''tolower($1) ~ /^[[:space:]]*listenport[[:space:]]*$/ {gsub(/[[:space:]]/,"",$2); print $2; exit}'\'' "$conf")"
  [[ "$actual_port" == "585" ]] || { echo "Существующий awg0.conf использует UDP ${actual_port:-неизвестно}; для SG-Node требуется 585" >&2; exit 1; }
  ext="$(ip route show default | awk '\''/ dev /{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'\'')"
  [[ "$ext" =~ ^[A-Za-z0-9_.:-]{1,32}$ ]] || { echo "Не удалось определить внешний интерфейс" >&2; exit 1; }
  cat > /etc/sg-awg-node/traffic.nft <<EOF
table inet sg_awg_node_filter {
  chain forward {
    type filter hook forward priority filter; policy drop;
    iifname "awg0" oifname "$ext" accept
    iifname "$ext" oifname "awg0" ct state established,related accept
    iifname "awg0" oifname "awg0" drop
  }
}
table ip sg_awg_node_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "$ext" ip saddr 10.77.0.0/24 masquerade
  }
}
EOF
  chmod 0600 /etc/sg-awg-node/traffic.nft
  awg-quick strip "$conf" >/dev/null
  nft -c -f /etc/sg-awg-node/traffic.nft
'
run_logged "Запуск стандартного AWG Server..." systemctl enable --now sg-awg-server.service
run_logged "Запуск Traffic runtime..." systemctl enable --now sg-awg-traffic.service
run_logged "Проверка службы sg-awg-node-agent.service..." systemctl is-enabled --quiet sg-awg-node-agent.service
run_logged "Запуск Nginx..." systemctl enable --now nginx.service

cat > /etc/sg-awg-node/runtime.env <<EOF
SG_AWG_NODE_RUNTIME_VERSION=0.7.0-RC6
SG_AWG_NODE_PREPARED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SG_AWG_NODE_UDP_PORT=585
EOF
chmod 0600 /etc/sg-awg-node/runtime.env

install_info "SG-AWG Node Runtime подготовлен."
install_info "Следующий шаг: добавьте SG-Node в Cluster и выполните показанную панелью команду подключения."
