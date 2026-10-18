#!/usr/bin/env bash
set -Eeuo pipefail

RELEASE_VERSION="v0.7.0-RC6"
REPOSITORY="WeedVDK/sg-awg-panel"
PASSWORD_MIN_LENGTH=8
PUBLIC_PORT_DEFAULT=62443
LOCAL_SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR=""
TMP_DIR=""
ADMIN_PASSWORD=""
ADMIN_PASSWORD_REPEAT=""

info(){ printf '[SG-AWG-Panel] %s\n' "$*"; }
fail(){ printf '[SG-AWG-Panel] ERROR: %s\n' "$*" >&2; exit 1; }
cleanup(){
  unset AWGPANEL_ADMIN_PASSWORD AWGPANEL_INSTANCE_NAME ADMIN_PASSWORD ADMIN_PASSWORD_REPEAT || true
  [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
}
trap cleanup EXIT

panel_installation_is_active() {
  [[ -f /etc/sg-awg-panel/web.env || -f /var/lib/sg-awg-panel/panel.db ]] && return 0
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet sg-awg-panel.service 2>/dev/null; then
      return 0
    fi
    if systemctl is-active --quiet sg-awg-node-agent.service 2>/dev/null; then
      return 0
    fi
  fi
  if command -v pgrep >/dev/null 2>&1; then
    if pgrep -f '^/opt/sg-awg-panel/.venv/bin/(waitress-serve|python)' >/dev/null 2>&1; then
      return 0
    fi
    if pgrep -f '^/usr/bin/python3 /opt/sg-awg-node/agent.py$' >/dev/null 2>&1; then
      return 0
    fi
  fi
  return 1
}

cleanup_stale_panel_residue() {
  local stale=0 path unit
  local stale_paths=(
    /opt/sg-awg-panel
    /etc/sg-awg-panel
    /var/lib/sg-awg-panel
    /opt/sg-awg-node
    /etc/sg-awg-node
    /var/lib/sg-awg-node
    /etc/systemd/system/sg-awg-node-agent.service
    /etc/systemd/system/sg-awg-panel.service
    /etc/systemd/system/sg-awg-server.service
    /etc/systemd/system/sg-awg-recovery.service
    /etc/systemd/system/sg-awg-traffic.service
    /etc/systemd/system/sg-awg-backup.timer
    /etc/systemd/system/sg-awg-clients-maintenance.timer
    /etc/nginx/sites-enabled/sg-awg-panel
    /etc/nginx/sites-available/sg-awg-panel
    /etc/nginx/sites-enabled/sg-awg-panel.conf
    /etc/nginx/sites-available/sg-awg-panel.conf
  )

  for path in "${stale_paths[@]}"; do
    if [[ -e "$path" || -L "$path" ]]; then
      stale=1
      break
    fi
  done
  (( stale == 1 )) || return 0

  info "Обнаружены безопасно удаляемые остатки прежней установки; выполняется подготовка к повторной установке..."

  if command -v systemctl >/dev/null 2>&1; then
    for unit in \
      sg-awg-node-agent.service \
      sg-awg-panel.service sg-awg-server.service sg-awg-recovery.service \
      sg-awg-traffic.service sg-awg-traffic-schedule.service \
      sg-awg-traffic-schedule.timer sg-awg-clients-maintenance.service \
      sg-awg-clients-maintenance.timer sg-awg-backup.service sg-awg-backup.timer; do
      systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
  fi

  if command -v pkill >/dev/null 2>&1; then
    pkill -TERM -f '^/opt/sg-awg-panel/.venv/bin/(waitress-serve|python)' >/dev/null 2>&1 || true
    pkill -TERM -f '^/usr/bin/python3 /opt/sg-awg-node/agent.py$' >/dev/null 2>&1 || true
  fi
  if command -v ip >/dev/null 2>&1; then
    ip link delete sgcascade >/dev/null 2>&1 || true
    ip link delete awg0 >/dev/null 2>&1 || true
    while ip rule del priority 13050 >/dev/null 2>&1; do :; done
    ip route flush table 23000 >/dev/null 2>&1 || true
    for id in $(seq 1 32); do
      while ip rule del priority "$((12100 + id))" >/dev/null 2>&1; do :; done
      ip route flush table "$((21000 + id))" >/dev/null 2>&1 || true
      ip link delete "sgo${id}" >/dev/null 2>&1 || true
    done
  fi
  if command -v nft >/dev/null 2>&1; then
    nft delete table inet sg_awg_traffic >/dev/null 2>&1 || true
    nft delete table ip sg_awg_traffic_nat >/dev/null 2>&1 || true
    nft delete table inet sg_awg_node_filter >/dev/null 2>&1 || true
    nft delete table ip sg_awg_node_nat >/dev/null 2>&1 || true
    nft delete table inet sg_awg_node_cascade >/dev/null 2>&1 || true
    nft delete table ip sg_awg_node_cascade_nat >/dev/null 2>&1 || true
  fi

  rm -rf \
    /opt/sg-awg-panel \
    /etc/sg-awg-panel \
    /var/lib/sg-awg-panel \
    /opt/sg-awg-node \
    /etc/sg-awg-node \
    /var/lib/sg-awg-node \
    /etc/amnezia/amneziawg \
    /etc/systemd/system/sg-awg-panel.service.d \
    /etc/systemd/system/sg-awg-server.service.d \
    /etc/systemd/system/sg-awg-recovery.service.d \
    /etc/systemd/system/sg-awg-traffic.service.d \
    /etc/systemd/system/sg-awg-backup.timer.d \
    /etc/systemd/system/sg-awg-clients-maintenance.timer.d

  rm -f \
    /etc/systemd/system/sg-awg-node-agent.service \
    /etc/systemd/system/sg-awg-panel.service \
    /etc/systemd/system/sg-awg-server.service \
    /etc/systemd/system/sg-awg-recovery.service \
    /etc/systemd/system/sg-awg-traffic.service \
    /etc/systemd/system/sg-awg-traffic-schedule.service \
    /etc/systemd/system/sg-awg-traffic-schedule.timer \
    /etc/systemd/system/sg-awg-clients-maintenance.service \
    /etc/systemd/system/sg-awg-clients-maintenance.timer \
    /etc/systemd/system/sg-awg-backup.service \
    /etc/systemd/system/sg-awg-backup.timer \
    /etc/nginx/sites-enabled/sg-awg-panel \
    /etc/nginx/sites-available/sg-awg-panel \
    /etc/nginx/sites-enabled/sg-awg-panel.conf \
    /etc/nginx/sites-available/sg-awg-panel.conf \
    /etc/nginx/sites-enabled/sg-awg-placeholder.conf \
    /etc/nginx/sites-available/sg-awg-placeholder.conf \
    /etc/sysctl.d/90-sg-awg-panel.conf \
    /etc/dnsmasq.d/sg-awg-traffic.conf \
    /run/lock/sg-awg-panel-traffic.lock

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed >/dev/null 2>&1 || true
  fi
  info "Остатки прежней установки удалены; сервер готов к установке из этого архива."
}

[[ $EUID -eq 0 ]] || fail "запустите через sudo bash"
[[ -r /etc/os-release ]] || fail "не удалось определить операционную систему"
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || fail "поддерживается только Ubuntu"
case "${VERSION_ID:-}" in 22.04|24.04) ;; *) fail "поддерживается Ubuntu 22.04 или 24.04; обнаружена ${VERSION_ID:-unknown}" ;; esac
ARCHITECTURE="$(dpkg --print-architecture 2>/dev/null || true)"
[[ "$ARCHITECTURE" == "amd64" ]] || fail "поддерживается только архитектура amd64; обнаружена ${ARCHITECTURE:-unknown}"
[[ ! -e /var/run/reboot-required ]] || fail "после обновления Ubuntu требуется перезагрузка: выполните sudo reboot и запустите установщик снова"
if panel_installation_is_active; then
  fail "обнаружена действующая установка SG-AWG-Panel или подключённая SG-Node. Для чистой установки сначала выполните полный uninstall"
fi
cleanup_stale_panel_residue
if command -v ss >/dev/null 2>&1 && [[ -n "$(ss -H -ltn 'sport = :18080' 2>/dev/null || true)" ]]; then
  fail "backend TCP 18080 занят посторонним процессом; освободите порт и повторите установку"
fi
if command -v ss >/dev/null 2>&1 && [[ -n "$(ss -H -lun 'sport = :585' 2>/dev/null || true)" ]]; then
  ss -H -lunp 'sport = :585' 2>/dev/null >&2 || true
  fail "UDP-порт 585 уже занят; освободите стандартный порт AmneziaWG и повторите установку"
fi
[[ -r /dev/tty && -w /dev/tty ]] || fail "для безопасного ввода параметров требуется обычная SSH-сессия"

printf '\nSG-AWG-Panel %s — чистая или повторная установка после полного удаления\n\n' "$RELEASE_VERSION" >/dev/tty
while true; do
  IFS= read -r -p "Имя этого сервера [SG-AWG-Panel]: " AWGPANEL_INSTANCE_NAME </dev/tty
  AWGPANEL_INSTANCE_NAME="${AWGPANEL_INSTANCE_NAME:-SG-AWG-Panel}"
  if [[ -z "$AWGPANEL_INSTANCE_NAME" || ${#AWGPANEL_INSTANCE_NAME} -gt 64 || "$AWGPANEL_INSTANCE_NAME" == *$'\n'* || "$AWGPANEL_INSTANCE_NAME" == *$'\r'* ]]; then
    printf 'Имя должно содержать от 1 до 64 обычных символов.\n\n' >/dev/tty
    continue
  fi
  break
done
printf '\n' >/dev/tty
export AWGPANEL_INSTANCE_NAME

while true; do
  IFS= read -r -s -p "Новый пароль администратора (минимум ${PASSWORD_MIN_LENGTH} символов): " ADMIN_PASSWORD </dev/tty
  printf '\n' >/dev/tty
  IFS= read -r -s -p "Повторите пароль: " ADMIN_PASSWORD_REPEAT </dev/tty
  printf '\n' >/dev/tty
  if [[ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_REPEAT" ]]; then
    printf 'Пароли не совпадают. Повторите ввод.\n\n' >/dev/tty
    continue
  fi
  if (( ${#ADMIN_PASSWORD} < PASSWORD_MIN_LENGTH )); then
    printf 'Пароль должен содержать не менее %s символов.\n\n' "$PASSWORD_MIN_LENGTH" >/dev/tty
    continue
  fi
  break
done
unset ADMIN_PASSWORD_REPEAT
export AWGPANEL_ADMIN_PASSWORD="$ADMIN_PASSWORD"

while true; do
  IFS= read -r -p "Публичный TCP-порт панели [${PUBLIC_PORT_DEFAULT}]: " AWGPANEL_PUBLIC_PORT </dev/tty
  AWGPANEL_PUBLIC_PORT="${AWGPANEL_PUBLIC_PORT:-$PUBLIC_PORT_DEFAULT}"
  if [[ ! "$AWGPANEL_PUBLIC_PORT" =~ ^[0-9]+$ ]] || (( AWGPANEL_PUBLIC_PORT < 49152 || AWGPANEL_PUBLIC_PORT > 65535 )); then
    printf 'Укажите TCP-порт из динамического диапазона 49152–65535.\n\n' >/dev/tty
    continue
  fi
  if [[ "$AWGPANEL_PUBLIC_PORT" == "585" || "$AWGPANEL_PUBLIC_PORT" == "18080" ]]; then
    printf 'Этот порт зарезервирован компонентами SG-AWG-Panel.\n\n' >/dev/tty
    continue
  fi
  if command -v ss >/dev/null 2>&1 && [[ -n "$(ss -H -ltn "sport = :${AWGPANEL_PUBLIC_PORT}" 2>/dev/null || true)" ]]; then
    printf 'TCP-порт %s уже занят. Выберите другой.\n\n' "$AWGPANEL_PUBLIC_PORT" >/dev/tty
    continue
  fi
  break
done
printf '\n' >/dev/tty
export AWGPANEL_PUBLIC_PORT

# Archive/4PDA mode: install directly from the complete local source tree.
if [[ -f "$LOCAL_SOURCE_DIR/deploy/first-install.sh" && -f "$LOCAL_SOURCE_DIR/awgpanel/__init__.py" ]]; then
  SOURCE_DIR="$LOCAL_SOURCE_DIR"
else
  # Standalone bootstrap mode: install.sh was downloaded without the archive.
  if ! command -v curl >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
    apt-get -o Dpkg::Use-Pty=0 update -qq
    env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
      apt-get -o Dpkg::Use-Pty=0 install -y -qq curl ca-certificates tar
  fi
  TMP_DIR="$(mktemp -d /tmp/sg-awg-panel-install.XXXXXX)"
  ARCHIVE_URL="https://github.com/${REPOSITORY}/archive/refs/heads/main.tar.gz"
  info "Загрузка ${RELEASE_VERSION} из GitHub main..."
  curl -fsSL --retry 3 --connect-timeout 15 "$ARCHIVE_URL" -o "$TMP_DIR/source.tar.gz" \
    || fail "не удалось загрузить GitHub main"
  tar -xzf "$TMP_DIR/source.tar.gz" -C "$TMP_DIR" || fail "не удалось распаковать архив"
  SOURCE_DIR="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d -name 'sg-awg-panel-*' | head -n 1)"
fi

[[ -n "$SOURCE_DIR" && -f "$SOURCE_DIR/deploy/first-install.sh" ]] || fail "не найден полный установщик"
SOURCE_VERSION="$(sed -n 's/^__version__ = "\(.*\)"/v\1/p' "$SOURCE_DIR/awgpanel/__init__.py" | head -n 1)"
[[ "$SOURCE_VERSION" == "$RELEASE_VERSION" ]] || fail "версия исходников ${SOURCE_VERSION:-unknown} не совпадает с ${RELEASE_VERSION}"

bash "$SOURCE_DIR/deploy/first-install.sh" "$@"
INSTALLED_VERSION="$(/opt/sg-awg-panel/.venv/bin/python -c 'import awgpanel; print("v" + awgpanel.__version__)' 2>/dev/null || true)"
[[ "$INSTALLED_VERSION" == "$RELEASE_VERSION" ]] \
  || fail "после установки обнаружена версия ${INSTALLED_VERSION:-unknown}, ожидалась ${RELEASE_VERSION}"
unset AWGPANEL_ADMIN_PASSWORD AWGPANEL_INSTANCE_NAME ADMIN_PASSWORD
info "Установка завершена: ${INSTALLED_VERSION}"
