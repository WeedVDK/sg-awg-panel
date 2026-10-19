#!/usr/bin/env bash
set -Eeuo pipefail

CONTROLLER=""
NODE_SLUG=""
ENROLLMENT_TOKEN=""
INSECURE_TLS=0
ENV_FILE="/etc/sg-awg-node/agent.env"
TMP_RESPONSE=""

usage(){
  cat <<'EOF'
Использование:
  sudo bash 02-connect-sg-awg-node.sh --controller https://panel.example.com:62443 --node france-exit --token TOKEN

Параметр --insecure разрешён только для временного теста с самоподписанным сертификатом.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --controller) CONTROLLER="${2:-}"; shift 2 ;;
    --node) NODE_SLUG="${2:-}"; shift 2 ;;
    --token) ENROLLMENT_TOKEN="${2:-}"; shift 2 ;;
    --insecure) INSECURE_TLS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Неизвестный параметр: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Запустите через sudo bash" >&2; exit 1; }
[[ -f /opt/sg-awg-panel/awgpanel/__init__.py && -f /opt/sg-awg-node/agent.py ]] || { echo "Сначала установите полную SG-AWG-Panel тем же универсальным установщиком" >&2; exit 1; }
[[ "$CONTROLLER" =~ ^https?://[^[:space:]]+$ ]] || { echo "Некорректный адрес Controller" >&2; exit 1; }
[[ "$NODE_SLUG" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || { echo "Некорректный идентификатор SG-Node" >&2; exit 1; }
[[ ${#ENROLLMENT_TOKEN} -ge 24 ]] || { echo "Некорректный одноразовый токен" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Не найден python3" >&2; exit 1; }

TMP_RESPONSE="$(mktemp /tmp/sg-awg-node-enroll.XXXXXX)"
trap 'rm -f "$TMP_RESPONSE"' EXIT

CONTROLLER="$CONTROLLER" NODE_SLUG="$NODE_SLUG" ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN" \
INSECURE_TLS="$INSECURE_TLS" RESPONSE_FILE="$TMP_RESPONSE" python3 - <<'PY'
import ipaddress, json, os, platform, re, shutil, socket, ssl, subprocess, urllib.request, urllib.error

def run(cmd):
    try:
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=6,check=False)
        return (result.stdout+result.stderr).strip()
    except Exception:
        return ""

def private_ip():
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(("1.1.1.1",53)); value=s.getsockname()[0]; s.close(); return value
    except OSError: return ""

def public_ip():
    for url in ("https://checkip.amazonaws.com","https://api.ipify.org"):
        try:
            with urllib.request.urlopen(url,timeout=4) as response: return response.read().decode().strip()
        except Exception: pass
    return ""

def awg_runtime():
    conf = "/etc/amnezia/amneziawg/awg0.conf"
    values = {}
    try:
        section = ""
        for raw in open(conf, encoding="utf-8"):
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line.casefold()
                continue
            if section == "[interface]" and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip().casefold()] = value.strip()
    except OSError:
        return {}
    address = values.get("address", "").split(",", 1)[0].strip()
    try:
        interface = ipaddress.ip_interface(address)
        network = str(interface.network)
        interface_address = str(interface)
    except ValueError:
        network = ""
        interface_address = ""
    try:
        configured_port = int(values.get("listenport") or 0)
    except ValueError:
        configured_port = 0
    public_key = run(["awg", "show", "awg0", "public-key"]).splitlines()
    listen_port = run(["awg", "show", "awg0", "listen-port"]).splitlines()
    try:
        runtime_port = int(listen_port[0]) if listen_port else 0
    except ValueError:
        runtime_port = 0
    return {
        "configured": bool(interface_address and configured_port),
        "interface": "awg0",
        "interface_address": interface_address,
        "server_network": network,
        "listen_port": runtime_port or configured_port,
        "configured_listen_port": configured_port,
        "public_key": public_key[0].strip() if public_key else "",
        "server_public_key": public_key[0].strip() if public_key else "",
        "peers": {},
        "address_claims": [],
    }

os_release={}
try:
    for line in open('/etc/os-release',encoding='utf-8'):
        if '=' in line:
            k,v=line.rstrip().split('=',1); os_release[k]=v.strip('"')
except OSError: pass
usage=shutil.disk_usage('/')
payload={
  "node":os.environ["NODE_SLUG"],
  "token":os.environ["ENROLLMENT_TOKEN"],
  "metadata":{
    "agent_version":"0.7.0-RC6","os_name":os_release.get("NAME",platform.system()),
    "os_version":os_release.get("VERSION_ID",platform.release()),"kernel":platform.release(),
    "machine_id":(open("/etc/machine-id",encoding="utf-8").read().strip()[:128] if os.path.isfile("/etc/machine-id") else ""),
    "public_ipv4":public_ip(),"private_ipv4":private_ip(),
    "awg_version":(run(["awg","--version"]).splitlines() or [""])[0],
    "awg_runtime":awg_runtime(),
    "capabilities":{"amneziawg":True,"metrics":True,"diagnostics":True,"safe_service_restart":True,"managed_clients":True,"arbitrary_shell":False}
  }
}
data=json.dumps(payload).encode()
request=urllib.request.Request(os.environ["CONTROLLER"].rstrip('/')+"/api/cluster/v1/enroll",data=data,method='POST',headers={"Content-Type":"application/json","User-Agent":"SG-AWG-Node-Connect/1"})
context=None
if os.environ.get("INSECURE_TLS")=="1":
    context=ssl.create_default_context(); context.check_hostname=False; context.verify_mode=ssl.CERT_NONE
try:
    with urllib.request.urlopen(request,timeout=25,context=context) as response:
        body=response.read().decode('utf-8')
except urllib.error.HTTPError as exc:
    body=exc.read().decode('utf-8','replace')
    raise SystemExit(f"Controller HTTP {exc.code}: {body}")
result=json.loads(body)
if not result.get('ok') or not result.get('agent_token'):
    raise SystemExit(result.get('message') or 'Controller rejected enrollment')
open(os.environ["RESPONSE_FILE"],'w',encoding='utf-8').write(json.dumps(result))
PY

AGENT_TOKEN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["agent_token"])' "$TMP_RESPONSE")"
install -d -m 0700 /etc/sg-awg-node
cat > "$ENV_FILE" <<EOF
CONTROLLER_URL=$CONTROLLER
NODE_SLUG=$NODE_SLUG
AGENT_TOKEN=$AGENT_TOKEN
INSECURE_TLS=$INSECURE_TLS
EOF
chmod 0600 "$ENV_FILE"
unset AGENT_TOKEN ENROLLMENT_TOKEN

systemctl daemon-reload
systemctl enable --now sg-awg-node-agent.service
sleep 2
systemctl is-active --quiet sg-awg-node-agent.service || {
  journalctl -u sg-awg-node-agent.service -n 40 --no-pager >&2 || true
  exit 1
}
echo "[SG-AWG-Node] Подключение завершено. Agent active, node=$NODE_SLUG"
