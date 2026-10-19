#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$PROJECT_DIR/deploy"
# shellcheck source=deploy/install-common.sh
. "$SCRIPT_DIR/install-common.sh"

install_log_init
require_root
require_supported_ubuntu
require_supported_architecture
require_no_pending_reboot

if [[ ! -f /etc/sg-awg-panel/web.env ]]; then
  prompt_instance_name "SG-AWG-Panel"
  prompt_admin_password 8
  prompt_public_port 62443
fi

install_info "Этап 1/4: AmneziaWG и системные зависимости"
if ! bash "$SCRIPT_DIR/install-amneziawg.sh"; then
  install_fail "не удалось установить AmneziaWG"
fi

install_info "Этап 2/4: SG-AWG-Panel, Python и Nginx"
if ! bash "$PROJECT_DIR/install-or-upgrade.sh"; then
  install_fail "не удалось установить SG-AWG-Panel"
fi

install_info "Этап 3/4: подготовка универсального Agent"
run_logged "Установка Agent для возможного подключения к Controller..." bash "$SCRIPT_DIR/install-node-agent.sh" "$PROJECT_DIR"

install_info "Этап 4/4: финальная проверка"
run_logged "Проверка службы панели..." systemctl is-active --quiet sg-awg-panel.service
run_logged "Проверка AWG Server..." systemctl is-active --quiet sg-awg-server.service
run_logged "Проверка Nginx..." systemctl is-active --quiet nginx.service
run_logged "Проверка восстановления после reboot..." systemctl is-active --quiet sg-awg-recovery.service
run_logged "Проверка Traffic Rules..." systemctl is-active --quiet sg-awg-traffic.service
run_logged "Проверка готовности Agent..." systemctl is-enabled --quiet sg-awg-node-agent.service
run_logged "Проверка backend 127.0.0.1:18080..." curl -fsS --max-time 10 http://127.0.0.1:18080/health
PUBLIC_PORT="$(sed -n 's/^AWGPANEL_PUBLIC_PORT=//p' /etc/sg-awg-panel/web.env | tail -n 1 | tr -d "'\"")"
PUBLIC_PORT="${PUBLIC_PORT:-62443}"
run_logged "Проверка панели через Nginx на TCP ${PUBLIC_PORT}..." \
  curl -fsS --max-time 10 "http://127.0.0.1:${PUBLIC_PORT}/health"

install_info "SG-AWG-Panel v0.7.0-RC6 готова"
install_info "Откройте TCP ${PUBLIC_PORT} в AWS Security Group"

# Run system fixes installer
if [ -f "$SCRIPT_DIR/system-fixes/install.sh" ]; then
    bash "$SCRIPT_DIR/system-fixes/install.sh"
fi
