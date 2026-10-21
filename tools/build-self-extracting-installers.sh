#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT="$(dirname "$ROOT")"
OUTPUT_DIR="${1:-$PARENT}"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$ROOT/awgpanel/__init__.py" | head -n 1)"
ROOT_NAME="${VERSION}-AWG-Panel"

[[ "$(basename "$ROOT")" == "$ROOT_NAME" ]] \
  || { echo "Ожидалась папка $ROOT_NAME, получена $(basename "$ROOT")" >&2; exit 1; }
mkdir -p "$OUTPUT_DIR"

make_header() {
  local product="$1" entry="$2" root_name="$3"
  cat <<HEADER
#!/usr/bin/env bash
set -Eeuo pipefail

PRODUCT='$product'
ENTRY='$entry'
ROOT_NAME='$root_name'
GREEN=''
RED=''
RESET=''
if [[ -t 1 && -z "\${NO_COLOR:-}" ]]; then
  GREEN=\$'\\033[1;32m'
  RED=\$'\\033[1;31m'
  RESET=\$'\\033[0m'
fi

fail(){ printf '%s[ОШИБКА]%s %s\\n' "\$RED" "\$RESET" "\$*" >&2; exit 1; }

if [[ \$EUID -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || fail 'запустите файл через sudo'
  exec sudo bash "\$0" "\$@"
fi
command -v tar >/dev/null 2>&1 || fail 'в системе отсутствует стандартная команда tar'

TMP_DIR="\$(mktemp -d /tmp/sg-awg-selfextract.XXXXXX)"
cleanup(){ rm -rf "\$TMP_DIR"; }
trap cleanup EXIT
PAYLOAD_LINE="\$(awk '/^__SG_AWG_PAYLOAD_BELOW__\$/{print NR+1; exit}' "\$0")"
[[ "\$PAYLOAD_LINE" =~ ^[0-9]+\$ ]] || fail 'не найден встроенный установочный пакет'

extract_payload(){ tail -n +"\$PAYLOAD_LINE" "\$0" | tar -xzf - -C "\$TMP_DIR"; }
if [[ -t 1 ]]; then
  extract_payload &
  pid=\$!
  frames='|/-\\'
  i=0
  started=\$SECONDS
  while kill -0 "\$pid" 2>/dev/null; do
    printf '\\r%s[SG-AWG] [%s]%s Подготовка %s (%s сек)' \
      "\$GREEN" "\${frames:i%4:1}" "\$RESET" "\$PRODUCT" "\$((SECONDS-started))"
    i=\$((i+1))
    sleep 0.20
  done
  if wait "\$pid"; then
    printf '\\r%s[SG-AWG] [OK]%s Подготовка %s\\033[K\\n' "\$GREEN" "\$RESET" "\$PRODUCT"
  else
    printf '\\r%s[SG-AWG] [ОШИБКА]%s Подготовка %s\\033[K\\n' "\$RED" "\$RESET" "\$PRODUCT" >&2
    fail 'встроенный пакет повреждён'
  fi
else
  printf '[SG-AWG] Подготовка %s...\\n' "\$PRODUCT"
  extract_payload || fail 'встроенный пакет повреждён'
fi

[[ -f "\$TMP_DIR/\$ROOT_NAME/\$ENTRY" ]] || fail "не найден \$ENTRY"
if [[ "\${1:-}" == '--verify' ]]; then
  version="\$(sed -n 's/^__version__ = "\\(.*\\)"/\\1/p' "\$TMP_DIR/\$ROOT_NAME/awgpanel/__init__.py" 2>/dev/null | head -n 1)"
  printf 'OK: встроенный пакет %s, версия %s\\n' "\$PRODUCT" "\${version:-Node}"
  exit 0
fi
exec bash "\$TMP_DIR/\$ROOT_NAME/\$ENTRY" "\$@"
exit 1
__SG_AWG_PAYLOAD_BELOW__
HEADER
}

PANEL_RUN="$OUTPUT_DIR/${VERSION}-INSTALL-SG-AWG-PANEL.run"
UPDATE_RUN="$OUTPUT_DIR/${VERSION}-UPDATE-SG-AWG-PANEL.run"
PANEL_PAYLOAD="$(mktemp /tmp/sg-awg-panel-payload.XXXXXX.tar.gz)"
trap 'rm -f "$PANEL_PAYLOAD"' EXIT

tar -czf "$PANEL_PAYLOAD" \
  --exclude='.git' --exclude='.pytest_cache' --exclude='.test-venv' --exclude='.venv' --exclude='__pycache__' --exclude='*.pyc' \
  -C "$PARENT" "$ROOT_NAME"

make_header 'SG-AWG-Panel' 'install.sh' "$ROOT_NAME" >"$PANEL_RUN"
cat "$PANEL_PAYLOAD" >>"$PANEL_RUN"
make_header 'SG-AWG-Panel Update' 'update.sh' "$ROOT_NAME" >"$UPDATE_RUN"
cat "$PANEL_PAYLOAD" >>"$UPDATE_RUN"
chmod 0755 "$PANEL_RUN" "$UPDATE_RUN"
printf '%s\n%s\n' "$PANEL_RUN" "$UPDATE_RUN"
