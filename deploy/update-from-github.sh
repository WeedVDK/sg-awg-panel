#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="${SG_AWG_PANEL_VERSION:-v0.7.0-RC6}"
URL="https://github.com/WeedVDK/sg-awg-panel/archive/refs/heads/main.tar.gz"
LOCAL_SOURCE_DIR="${SG_AWG_PANEL_SOURCE_DIR:-}"
PROJECT_DIR="/opt/sg-awg-panel"
ENV_FILE="/etc/sg-awg-panel/web.env"
DATA_DIR="/var/lib/sg-awg-panel"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/sg-awg-panel-backups/${STAMP}-update-rollback"
STATUS_FILE="${SG_AWG_PANEL_UPDATE_STATUS:-/var/www/sg-awg-update/status.json}"
LOG_FILE="${SG_AWG_PANEL_UPDATE_LOG:-/var/www/sg-awg-update/update.log}"
TMP="$(mktemp -d)"
ROLLBACK_NEEDED=0
NGINX_WAS_ACTIVE=0
AWG_WAS_ACTIVE=0
AWG_CONFIG_PATH=/etc/amnezia/amneziawg/awg0.conf
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$STATUS_FILE")"
: > "$LOG_FILE"
chmod 0644 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

log(){ printf '[SG-AWG-Panel] %s\n' "$*"; }
fail(){ printf '[SG-AWG-Panel] ERROR: %s\n' "$*" >&2; return 1; }
status(){ python3 - "$STATUS_FILE" "$LOG_FILE" "$1" "$VERSION" "${2:-}" <<'PY'
import json,os,sys,tempfile
from datetime import datetime,timezone
p,log_path,state,version,message=sys.argv[1:]
os.makedirs(os.path.dirname(p), exist_ok=True)
try:
    with open(log_path,'r',encoding='utf-8',errors='replace') as stream:
        log=stream.read()[-32000:]
except OSError:
    log=''
payload={
    'state':state,
    'version':version,
    'message':message,
    'log':log,
    'updatedAt':datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
}
target=os.environ.get('TARGET_URL','').strip()
if target:
    payload['targetUrl']=target
raw=json.dumps(payload,ensure_ascii=False)+'\n'
fd,tmp=tempfile.mkstemp(prefix='.status-', dir=os.path.dirname(p))
try:
    with os.fdopen(fd,'w',encoding='utf-8') as stream:
        stream.write(raw)
    os.chmod(tmp,0o644)
    os.replace(tmp,p)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
PY
}
get_env(){
  local key="$1" default="$2" value first last
  value="$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
  if (( ${#value} >= 2 )); then
    first="${value:0:1}"; last="${value: -1}"
    if [[ "$first" == "'" && "$last" == "'" ]] || [[ "$first" == '"' && "$last" == '"' ]]; then value="${value:1:${#value}-2}"; fi
  fi
  printf '%s' "${value:-$default}"
}

NGINX_PATHS=(
  /etc/nginx/sites-available/sg-awg-panel
  /etc/nginx/sites-enabled/sg-awg-panel
  /etc/nginx/sites-available/sg-awg-panel.conf
  /etc/nginx/sites-enabled/sg-awg-panel.conf
  /etc/nginx/sites-available/sg-awg-placeholder.conf
  /etc/nginx/sites-enabled/sg-awg-placeholder.conf
)

backup_path(){
  local path="$1" name
  name="$(printf '%s' "$path" | sed 's#^/##; s#/#__#g')"
  if [[ -e "$path" || -L "$path" ]]; then
    cp -a "$path" "$BACKUP_DIR/$name"
    : > "$BACKUP_DIR/$name.exists"
  fi
}
restore_path(){
  local path="$1" name
  name="$(printf '%s' "$path" | sed 's#^/##; s#/#__#g')"
  rm -rf "$path"
  if [[ -f "$BACKUP_DIR/$name.exists" ]]; then
    cp -a "$BACKUP_DIR/$name" "$path"
  fi
}

rollback(){
  local code=$?
  trap - ERR
  if (( ROLLBACK_NEEDED )); then
    status rollback "$code"
    log "Update failed; restoring previous working version"
    systemctl stop sg-awg-panel.service 2>/dev/null || true
    systemctl stop sg-awg-server.service 2>/dev/null || true
    rsync -a --delete --exclude '.venv/' "$BACKUP_DIR/project/" "$PROJECT_DIR/" || true
    [[ -f "$BACKUP_DIR/web.env" ]] && cp -a "$BACKUP_DIR/web.env" "$ENV_FILE"
    if [[ -f "$BACKUP_DIR/panel.db" ]]; then
      rm -f "$DATA_DIR/panel.db" "$DATA_DIR/panel.db-wal" "$DATA_DIR/panel.db-shm"
      cp -a "$BACKUP_DIR/panel.db" "$DATA_DIR/panel.db"
    fi
    for path in "${NGINX_PATHS[@]}"; do restore_path "$path"; done
    restore_path "$AWG_CONFIG_PATH"
    for unit in sg-awg-panel.service sg-awg-server.service sg-awg-traffic.service sg-awg-traffic-schedule.service sg-awg-traffic-schedule.timer sg-awg-clients-maintenance.service sg-awg-clients-maintenance.timer sg-awg-backup.service sg-awg-backup.timer sg-awg-recovery.service; do
      rm -f "/etc/systemd/system/$unit"
      [[ -f "$BACKUP_DIR/$unit" ]] && cp -a "$BACKUP_DIR/$unit" "/etc/systemd/system/$unit"
    done
    cd "$PROJECT_DIR" || true
    .venv/bin/pip install --no-cache-dir -q -e . || true
    systemctl daemon-reload || true
    if (( AWG_WAS_ACTIVE )) && [[ -s "$AWG_CONFIG_PATH" ]]; then systemctl restart sg-awg-server.service || true; else systemctl stop sg-awg-server.service 2>/dev/null || true; fi
    systemctl restart sg-awg-panel.service || true
    if command -v nginx >/dev/null 2>&1; then
      nginx -t >/dev/null 2>&1 || true
      if (( NGINX_WAS_ACTIVE )); then systemctl restart nginx || true; else systemctl stop nginx 2>/dev/null || true; fi
    fi
    status rolled_back "Previous version restored"
  fi
  exit "$code"
}
trap rollback ERR

[[ $EUID -eq 0 ]] || fail "run as root"
[[ -x "$PROJECT_DIR/.venv/bin/python" ]] || fail "existing installation not found"
[[ -f "$ENV_FILE" ]] || fail "missing $ENV_FILE"
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-([Aa][Ll][Pp][Hh][Aa]|[Bb][Ee][Tt][Aa]|[Rr][Cc])[0-9]+)?$ ]]; then
  fail "invalid version"
fi
for command in rsync python3; do command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"; done

if [[ -n "$LOCAL_SOURCE_DIR" ]]; then
  SOURCE_DIR="$(cd "$LOCAL_SOURCE_DIR" && pwd)"
  [[ -f "$SOURCE_DIR/awgpanel/__init__.py" && -f "$SOURCE_DIR/install-or-upgrade.sh" ]] \
    || fail "local source directory is incomplete: $SOURCE_DIR"
  status downloading "Loading local candidate source"
  log "Using local source: $SOURCE_DIR"
else
  for command in curl tar; do command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"; done
  status downloading "Downloading source"
  log "Downloading GitHub main for ${VERSION}"
  curl -fsSL "$URL" -o "$TMP/source.tar.gz"
  tar -xzf "$TMP/source.tar.gz" -C "$TMP"
  SOURCE_DIR="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -1)"
  [[ -n "$SOURCE_DIR" ]] || fail "downloaded archive is empty"
fi
SOURCE_VERSION="$(sed -n 's/^__version__ = "\(.*\)"/v\1/p' "$SOURCE_DIR/awgpanel/__init__.py" | head -n 1)"
[[ "$SOURCE_VERSION" == "$VERSION" ]] \
  || fail "downloaded source version ${SOURCE_VERSION:-unknown} does not match ${VERSION}"

mkdir -p "$BACKUP_DIR/project"
rsync -a --exclude '.venv/' "$PROJECT_DIR/" "$BACKUP_DIR/project/"
cp -a "$ENV_FILE" "$BACKUP_DIR/web.env"
if [[ -f "$DATA_DIR/panel.db" ]]; then
  SOURCE_DB="$DATA_DIR/panel.db" TARGET_DB="$BACKUP_DIR/panel.db" python3 - <<'PYDB'
import os,sqlite3
s=sqlite3.connect(os.environ['SOURCE_DB']); t=sqlite3.connect(os.environ['TARGET_DB'])
try:s.backup(t)
finally:t.close();s.close()
PYDB
fi
for path in "${NGINX_PATHS[@]}"; do backup_path "$path"; done
systemctl is-active --quiet nginx 2>/dev/null && NGINX_WAS_ACTIVE=1 || true
systemctl is-active --quiet sg-awg-server.service 2>/dev/null && AWG_WAS_ACTIVE=1 || true
backup_path "$AWG_CONFIG_PATH"
for unit in sg-awg-panel.service sg-awg-server.service sg-awg-traffic.service sg-awg-traffic-schedule.service sg-awg-traffic-schedule.timer sg-awg-clients-maintenance.service sg-awg-clients-maintenance.timer sg-awg-backup.service sg-awg-backup.timer sg-awg-recovery.service; do
  [[ -f "/etc/systemd/system/$unit" ]] && cp -a "/etc/systemd/system/$unit" "$BACKUP_DIR/$unit"
done
ROLLBACK_NEEDED=1

OLD_PORT="$(get_env AWGPANEL_PUBLIC_PORT "$(get_env AWGPANEL_PORT 8080)")"
OLD_SCHEME="$(get_env AWGPANEL_PUBLIC_SCHEME http)"
OLD_HOST="$(get_env AWGPANEL_PUBLIC_HOST '')"
OLD_PLACEHOLDER="$(get_env AWGPANEL_MANAGE_PLACEHOLDER 1)"
if [[ -n "$OLD_HOST" ]]; then
  if [[ ( "$OLD_SCHEME" == "https" && "$OLD_PORT" == "443" ) || ( "$OLD_SCHEME" == "http" && "$OLD_PORT" == "80" ) ]]; then
    TARGET_URL="${OLD_SCHEME}://${OLD_HOST}/login?updated=1"
  else
    TARGET_URL="${OLD_SCHEME}://${OLD_HOST}:${OLD_PORT}/login?updated=1"
  fi
  export TARGET_URL
fi

if [[ "$OLD_PORT" == "443" ]]; then
  fail "The current panel uses TCP 443. Before updating, change the Alpha 7 panel port to a separate port such as 62443."
fi

missing_packages=()
command -v nft >/dev/null 2>&1 || missing_packages+=(nftables)
command -v ip >/dev/null 2>&1 || missing_packages+=(iproute2)
command -v dnsmasq >/dev/null 2>&1 || missing_packages+=(dnsmasq)
command -v conntrack >/dev/null 2>&1 || missing_packages+=(conntrack)
if ((${#missing_packages[@]})); then
  log "Installing update dependencies: ${missing_packages[*]}"
  apt-get -o Dpkg::Use-Pty=0 update -qq
  env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
    apt-get -o Dpkg::Use-Pty=0 install -y -qq "${missing_packages[@]}"
fi
# A newly installed dnsmasq must not listen publicly before Traffic Rules
# generate its private AWG-bound configuration.
if [[ ! -f /etc/dnsmasq.d/sg-awg-traffic.conf ]]; then
  systemctl disable --now dnsmasq.service >/dev/null 2>&1 || true
fi

status installing "Installing panel files"
rsync -a --delete --exclude '.git/' --exclude '.venv/' --exclude '__pycache__/' "$SOURCE_DIR/" "$PROJECT_DIR/"
find "$PROJECT_DIR" -type f -name '*.sh' -exec chmod 0755 {} +
cd "$PROJECT_DIR"
.venv/bin/pip install --no-cache-dir -q -r requirements.txt
.venv/bin/pip install --no-cache-dir -q -e .
INSTALLED_VERSION="$(.venv/bin/python -c 'import awgpanel; print("v" + awgpanel.__version__)' 2>/dev/null || true)"
[[ "$INSTALLED_VERSION" == "$VERSION" ]] \
  || fail "installed package version ${INSTALLED_VERSION:-unknown} does not match ${VERSION}"

python3 - "$ENV_FILE" "$OLD_PORT" "$OLD_SCHEME" "$OLD_HOST" "$OLD_PLACEHOLDER" <<'PYENV'
from pathlib import Path
import sys
p=Path(sys.argv[1]); public_port,scheme,host,manage_placeholder=sys.argv[2:]
updates={
 'AWGPANEL_BIND_ADDRESS':'127.0.0.1',
 'AWGPANEL_PORT':'18080',
 'AWGPANEL_BACKEND_PORT':'18080',
 'AWGPANEL_PUBLIC_PORT':public_port,
 'AWGPANEL_PUBLIC_SCHEME':scheme,
 'AWGPANEL_PUBLIC_HOST':host,
 'AWGPANEL_MANAGE_PLACEHOLDER':manage_placeholder,
 'AWGPANEL_HTTPS_EMAIL':'',
 'AWGPANEL_TRUST_PROXY_HEADERS':'1',
 'AWGPANEL_SECURE_COOKIES':'1' if scheme=='https' else '0',
 'AWGPANEL_ACCESS_JOBS_DIR':'/var/lib/sg-awg-panel/access-jobs',
 'AWGPANEL_OPERATION_JOBS_DIR':'/var/lib/sg-awg-panel/operation-jobs',
 'AWGPANEL_PROJECT_DIR':'/opt/sg-awg-panel',
}
lines=p.read_text(encoding='utf-8').splitlines(); out=[]; seen=set()
for line in lines:
 k=line.split('=',1)[0] if '=' in line else ''
 if k in updates: out.append(f'{k}={updates[k]}');seen.add(k)
 else: out.append(line)
for k,v in updates.items():
 if k not in seen: out.append(f'{k}={v}')
p.write_text('\n'.join(out)+'\n',encoding='utf-8')
PYENV
chmod 600 "$ENV_FILE"

DB_PATH="$(get_env AWGPANEL_DB /var/lib/sg-awg-panel/panel.db)"
AWG_CONFIG_DIR="$(get_env AWGPANEL_AWG_CONFIG_DIR /etc/amnezia/amneziawg)"
AWG_SERVICE="$(get_env AWGPANEL_AWG_SERVICE sg-awg-server)"
AWGPANEL_DB="$DB_PATH" AWGPANEL_AWG_CONFIG_DIR="$AWG_CONFIG_DIR" AWGPANEL_AWG_SERVICE="$AWG_SERVICE" .venv/bin/python -m awgpanel init-db
AWGPANEL_DB="$DB_PATH" PUBLIC_SCHEME_SYNC="$OLD_SCHEME" PUBLIC_HOST_SYNC="$OLD_HOST" PUBLIC_PORT_SYNC="$OLD_PORT" MANAGE_PLACEHOLDER_SYNC="$OLD_PLACEHOLDER" .venv/bin/python - <<'PYSET'
import os
from awgpanel.db import connect
with connect() as con:
    con.execute(
        """UPDATE panel_settings SET public_scheme=?, public_host=?, public_port=?, https_email='', https_enabled=?, manage_placeholder=?, backend_address='127.0.0.1', backend_port=18080, updated_at=CURRENT_TIMESTAMP WHERE id=1""",
        (
            os.environ['PUBLIC_SCHEME_SYNC'], os.environ['PUBLIC_HOST_SYNC'], int(os.environ['PUBLIC_PORT_SYNC']),
            1 if os.environ['PUBLIC_SCHEME_SYNC']=='https' else 0, int(os.environ['MANAGE_PLACEHOLDER_SYNC'])
        ),
    )
PYSET

log "Ensuring AWG Server is configured"
AWGPANEL_DB="$DB_PATH" AWGPANEL_AWG_CONFIG_DIR="$AWG_CONFIG_DIR" AWGPANEL_AWG_SERVICE="$AWG_SERVICE" \
  .venv/bin/python -m awgpanel ensure-server

bash deploy/install-service.sh
bash deploy/install-backup-timer.sh
bash deploy/install-traffic-service.sh
bash deploy/install-traffic-maintenance.sh
bash deploy/install-client-maintenance.sh
bash deploy/install-recovery-service.sh
systemctl restart sg-awg-panel.service
for _ in {1..20}; do
  if curl -fsS --max-time 2 http://127.0.0.1:18080/health >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS --max-time 5 http://127.0.0.1:18080/health >/dev/null

ACCESS_ARGS=(--scheme "$OLD_SCHEME" --port "$OLD_PORT" --manage-placeholder "$OLD_PLACEHOLDER")
[[ -n "$OLD_HOST" ]] && ACCESS_ARGS+=(--domain "$OLD_HOST")
bash deploy/configure-panel-access.sh "${ACCESS_ARGS[@]}"
nginx -t
systemctl enable --now nginx sg-awg-panel.service >/dev/null
systemctl enable sg-awg-traffic.service sg-awg-recovery.service >/dev/null
systemctl enable --now sg-awg-traffic-schedule.timer sg-awg-clients-maintenance.timer >/dev/null
systemctl restart sg-awg-traffic.service
systemctl is-active --quiet sg-awg-traffic.service
systemctl restart sg-awg-recovery.service
systemctl is-active --quiet sg-awg-recovery.service
[[ -s /etc/amnezia/amneziawg/awg0.conf ]] && systemctl enable sg-awg-server.service >/dev/null || true

ROLLBACK_NEEDED=0
status success "Update completed"
log "Ready: ${INSTALLED_VERSION}"
log "Automatic rollback backup: $BACKUP_DIR"
log "Existing AWG configuration and tunnel state were preserved"
