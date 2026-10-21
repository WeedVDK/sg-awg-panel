#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SG_AWG_PROJECT_DIR:-/opt/sg-awg-panel}"
ENV_FILE="${SG_AWG_ENV_FILE:-/etc/sg-awg-panel/web.env}"
DATA_DIR="${SG_AWG_DATA_DIR:-/var/lib/sg-awg-panel}"
SERVICE_NAME="${SG_AWG_SERVICE_NAME:-sg-awg-panel.service}"
BACKUP_ROOT="${SG_AWG_BACKUP_ROOT:-/root/sg-awg-panel-backups}"
EXPECTED_VERSION="0.7.0-RC6"
EXPECTED_UI="sgawg070rc6"
EXPECTED_MARKER="SG-AWG-Panel 0.7.0-RC6 — classic UI completion"
LOG_FILE="${SG_AWG_UPDATE_LOG:-/var/log/sg-awg-panel-update.log}"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
BACKUP_DIR="$BACKUP_ROOT/update-$STAMP"
ROLLBACK_READY=0
UPDATE_COMPLETE=0

if [[ $EUID -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi

say(){ printf '%s\n' "$*"; }
log(){ printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" >>"$LOG_FILE"; }
fail(){ say "[ОШИБКА] $*" >&2; log "ERROR: $*"; return 1; }

get_env(){
  local key="$1" default="$2" value first last
  value="$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)"
  if (( ${#value} >= 2 )); then
    first="${value:0:1}"; last="${value: -1}"
    if [[ "$first" == "'" && "$last" == "'" ]] || [[ "$first" == '"' && "$last" == '"' ]]; then
      value="${value:1:${#value}-2}"
    fi
  fi
  printf '%s' "${value:-$default}"
}

rollback(){
  local rc=$?
  if (( UPDATE_COMPLETE == 1 || ROLLBACK_READY == 0 )); then
    exit "$rc"
  fi
  trap - ERR INT TERM
  say
  say "[ОТКАТ] Обновление не завершено. Возвращаю предыдущую версию..."
  log "Rollback started"
  systemctl stop "$SERVICE_NAME" >>"$LOG_FILE" 2>&1 || true
  if [[ -f "$BACKUP_DIR/code.tar.gz" ]]; then
    find "$PROJECT_DIR" -mindepth 1 -maxdepth 1 ! -name '.venv' -exec rm -rf {} +
    tar -xzf "$BACKUP_DIR/code.tar.gz" -C "$PROJECT_DIR" >>"$LOG_FILE" 2>&1 || true
  fi
  [[ -f "$BACKUP_DIR/panel.db" ]] && install -m 0600 "$BACKUP_DIR/panel.db" "$DATA_DIR/panel.db" || true
  [[ -f "$BACKUP_DIR/web.env" ]] && install -m 0600 "$BACKUP_DIR/web.env" "$ENV_FILE" || true
  if [[ -d "$BACKUP_DIR/amneziawg" ]]; then
    mkdir -p /etc/amnezia/amneziawg
    rsync -a --delete "$BACKUP_DIR/amneziawg/" /etc/amnezia/amneziawg/ >>"$LOG_FILE" 2>&1 || true
  fi
  if [[ -f "$BACKUP_DIR/node-agent.tar.gz" ]]; then
    rm -rf /opt/sg-awg-node
    tar -xzf "$BACKUP_DIR/node-agent.tar.gz" -C / >>"$LOG_FILE" 2>&1 || true
  elif [[ -f "$BACKUP_DIR/node-agent.was-absent" ]]; then
    rm -rf /opt/sg-awg-node
  fi
  if [[ -f "$BACKUP_DIR/sg-awg-node-agent.service" ]]; then
    install -m 0644 "$BACKUP_DIR/sg-awg-node-agent.service" /etc/systemd/system/sg-awg-node-agent.service || true
  elif [[ -f "$BACKUP_DIR/node-agent-service.was-absent" ]]; then
    rm -f /etc/systemd/system/sg-awg-node-agent.service
  fi
  systemctl daemon-reload >>"$LOG_FILE" 2>&1 || true
  systemctl restart "$SERVICE_NAME" >>"$LOG_FILE" 2>&1 || true
  [[ -f /etc/sg-awg-node/agent.env ]] && systemctl restart sg-awg-node-agent.service >>"$LOG_FILE" 2>&1 || true
  say "[ОТКАТ] Предыдущая версия восстановлена. Журнал: $LOG_FILE"
  exit "$rc"
}
trap rollback ERR INT TERM

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 0600 "$LOG_FILE"
log "Update started from $SOURCE_DIR"

[[ -d "$PROJECT_DIR" && -x "$PROJECT_DIR/.venv/bin/python" && -f "$ENV_FILE" ]] \
  || fail "панель не установлена; для нового сервера используйте install.sh"
for required in \
  awgpanel/__init__.py awgpanel/templates/base.html awgpanel/templates/clients.html \
  awgpanel/templates/nodes.html awgpanel/templates/cascade.html awgpanel/static/app.css \
  awgpanel/egress.py requirements.txt pyproject.toml; do
  [[ -f "$SOURCE_DIR/$required" ]] || fail "в пакете отсутствует $required"
done
grep -Fq "$EXPECTED_MARKER" "$SOURCE_DIR/awgpanel/static/app.css" \
  || fail "пакет не содержит проверенный классический интерфейс $EXPECTED_UI"
if grep -q 'v209-ui' "$SOURCE_DIR/awgpanel/templates/base.html"; then
  fail "обнаружен отклонённый экспериментальный интерфейс 209"
fi
SOURCE_VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SOURCE_DIR/awgpanel/__init__.py" | head -n 1)"
[[ "$SOURCE_VERSION" == "$EXPECTED_VERSION" ]] \
  || fail "версия пакета ${SOURCE_VERSION:-неизвестна}, ожидалась $EXPECTED_VERSION"

INSTALLED_BEFORE="$(cd "$PROJECT_DIR" && .venv/bin/python -m awgpanel --version 2>/dev/null | awk '{print $2}' || true)"
say "SG-AWG-Panel: обновление ${INSTALLED_BEFORE:-неизвестно} → $EXPECTED_VERSION"
say "Дизайн: классический интерфейс · $EXPECTED_UI"
say

say "[1/5] Создаю резервную копию..."
mkdir -p "$BACKUP_DIR" "$DATA_DIR"
tar -czf "$BACKUP_DIR/code.tar.gz" \
  --exclude='./.venv' --exclude='./__pycache__' --exclude='*.pyc' \
  -C "$PROJECT_DIR" .
[[ -f "$ENV_FILE" ]] && cp -a "$ENV_FILE" "$BACKUP_DIR/web.env"
if [[ -f "$DATA_DIR/panel.db" ]]; then
  SOURCE_DB="$DATA_DIR/panel.db" TARGET_DB="$BACKUP_DIR/panel.db" python3 - <<'PYDB'
import os, sqlite3
source = sqlite3.connect(os.environ["SOURCE_DB"])
target = sqlite3.connect(os.environ["TARGET_DB"])
try: source.backup(target)
finally: target.close(); source.close()
PYDB
  chmod 0600 "$BACKUP_DIR/panel.db"
fi
if [[ -d /etc/amnezia/amneziawg ]]; then
  mkdir -p "$BACKUP_DIR/amneziawg"
  rsync -a /etc/amnezia/amneziawg/ "$BACKUP_DIR/amneziawg/"
fi
if [[ -d /opt/sg-awg-node ]]; then
  tar -czf "$BACKUP_DIR/node-agent.tar.gz" -C / opt/sg-awg-node
else
  touch "$BACKUP_DIR/node-agent.was-absent"
fi
if [[ -f /etc/systemd/system/sg-awg-node-agent.service ]]; then
  cp -a /etc/systemd/system/sg-awg-node-agent.service "$BACKUP_DIR/sg-awg-node-agent.service"
else
  touch "$BACKUP_DIR/node-agent-service.was-absent"
fi
ROLLBACK_READY=1

say "[2/5] Обновляю только файлы панели..."
systemctl stop "$SERVICE_NAME"
rsync -a --checksum --delete \
  --exclude '.git/' --exclude '.venv/' --exclude '__pycache__/' --exclude '*.pyc' \
  "$SOURCE_DIR/" "$PROJECT_DIR/" >>"$LOG_FILE" 2>&1
find "$PROJECT_DIR" -type f -name '*.sh' -exec chmod 0755 {} +
for critical in \
  awgpanel/templates/base.html awgpanel/templates/clients.html awgpanel/templates/nodes.html \
  awgpanel/templates/cascade.html awgpanel/static/app.css awgpanel/egress.py; do
  cmp -s "$SOURCE_DIR/$critical" "$PROJECT_DIR/$critical" || fail "$critical не был обновлён"
done
grep -Fq "$EXPECTED_MARKER" "$PROJECT_DIR/awgpanel/static/app.css" \
  || fail "классический интерфейс $EXPECTED_UI не установлен"
! grep -q 'v209-ui' "$PROJECT_DIR/awgpanel/templates/base.html" \
  || fail "после копирования остался отклонённый интерфейс 209"

say "[3/5] Обновляю Python-пакет и схему базы..."
cd "$PROJECT_DIR"
.venv/bin/pip install --disable-pip-version-check --no-cache-dir -q -r requirements.txt >>"$LOG_FILE" 2>&1
.venv/bin/pip install --disable-pip-version-check --no-cache-dir -q -e . >>"$LOG_FILE" 2>&1
DB_PATH="$(get_env AWGPANEL_DB /var/lib/sg-awg-panel/panel.db)"
AWG_CONFIG_DIR="$(get_env AWGPANEL_AWG_CONFIG_DIR /etc/amnezia/amneziawg)"
AWG_SERVICE="$(get_env AWGPANEL_AWG_SERVICE sg-awg-server)"
AWGPANEL_DB="$DB_PATH" AWGPANEL_AWG_CONFIG_DIR="$AWG_CONFIG_DIR" AWGPANEL_AWG_SERVICE="$AWG_SERVICE" \
  .venv/bin/python -m awgpanel init-db >>"$LOG_FILE" 2>&1

say "[4/5] Обновляю универсальный Agent и перезапускаю панель..."
# Agent установлен на каждой полной панели заранее и остаётся неактивным до подключения.
bash "$PROJECT_DIR/deploy/install-node-agent.sh" "$PROJECT_DIR" >>"$LOG_FILE" 2>&1
# Существующий systemd unit и Nginx не переписываются при обычном обновлении.
systemctl restart "$SERVICE_NAME"
BACKEND_PORT="$(get_env AWGPANEL_PORT 18080)"
for _ in {1..20}; do
  curl -fsS --max-time 2 "http://127.0.0.1:${BACKEND_PORT}/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS --max-time 5 "http://127.0.0.1:${BACKEND_PORT}/health" >/dev/null \
  || fail "панель не отвечает после обновления"

say "[5/5] Проверяю версию, интерфейс и сохранность данных..."
INSTALLED_AFTER="$(.venv/bin/python -m awgpanel --version 2>/dev/null | awk '{print $2}')"
[[ "$INSTALLED_AFTER" == "$EXPECTED_VERSION" ]] \
  || fail "установлена версия ${INSTALLED_AFTER:-неизвестна}, ожидалась $EXPECTED_VERSION"
grep -Fq "$EXPECTED_MARKER" "$PROJECT_DIR/awgpanel/static/app.css" \
  || fail "интерфейс $EXPECTED_UI не подтверждён"
[[ -f "$DB_PATH" && -s "$DB_PATH" ]] || fail "база данных отсутствует после обновления"
systemctl is-active --quiet "$SERVICE_NAME" || fail "служба панели не активна"
systemctl is-enabled --quiet sg-awg-node-agent.service || fail "универсальный Agent не подготовлен"
if [[ -f /etc/sg-awg-node/agent.env ]]; then
  systemctl is-active --quiet sg-awg-node-agent.service || fail "подключённый Agent не активен после обновления"
fi

UPDATE_COMPLETE=1
trap - ERR INT TERM
say
say "ГОТОВО: SG-AWG-Panel обновлена ${INSTALLED_BEFORE:-?} → $EXPECTED_VERSION"
say "ГОТОВО: классический интерфейс $EXPECTED_UI установлен и проверен"
say "Данные, Clients, Cluster, Cascade и подключение Agent сохранены"
say "Резервная копия: $BACKUP_DIR"
say "Журнал: $LOG_FILE"
