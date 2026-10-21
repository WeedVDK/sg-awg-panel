from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import random
import re
import secrets
import shutil
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import db
from .db import ACTIVE_CLIENT_SQL, connect, init_db
from .errors import AWGPanelError
from .traffic import effective_allowed_ips, exported_allowed_ips, normalize_networks, validate_advertised_networks
from .traffic_modes import AWG_GATEWAY, VALID_EGRESS_MODES, normalize_egress_mode
from .server_profiles import ensure_udp_port_available, network_client_addresses

AWG_CONFIG_DIR = Path(os.environ.get("AWGPANEL_AWG_CONFIG_DIR", "/etc/amnezia/amneziawg"))
AWG_SERVICE = os.environ.get("AWGPANEL_AWG_SERVICE", "sg-awg-server")
AWG_CONFIG_PATH = AWG_CONFIG_DIR / "awg0.conf"
BACKUP_DIR = Path(os.environ.get("AWGPANEL_BACKUP_DIR", "/var/lib/sg-awg-panel/backups"))
PANEL_ACCESS_JOBS_DIR = Path(os.environ.get("AWGPANEL_ACCESS_JOBS_DIR", "/var/lib/sg-awg-panel/access-jobs"))
BACKUP_KEEP = int(os.environ.get("AWGPANEL_BACKUP_KEEP", "20"))
PLACEHOLDER_PATH = Path(os.environ.get("AWGPANEL_PLACEHOLDER_PATH", "/var/www/sg-awg-placeholder/index.html"))
PLACEHOLDER_MAX_BYTES = 256 * 1024
BACKUP_FORMAT_VERSION = 3
PANEL_ENV_PATH = Path(os.environ.get("AWGPANEL_ENV_FILE", "/etc/sg-awg-panel/web.env"))
NODE_AGENT_ENV_PATH = Path(os.environ.get("SG_AWG_NODE_ENV_FILE", "/etc/sg-awg-node/agent.env"))
NODE_AGENT_STATE_DIR = Path(os.environ.get("SG_AWG_NODE_STATE_DIR", "/var/lib/sg-awg-node"))
DNSMASQ_CONFIG_PATH = Path(os.environ.get("AWGPANEL_DNSMASQ_CONFIG", "/etc/dnsmasq.d/sg-awg-traffic.conf"))
TRAFFIC_STATE_DIR = Path(os.environ.get("AWGPANEL_TRAFFIC_STATE_DIR", "/var/lib/sg-awg-panel/traffic-rules"))
NGINX_MANAGED_PATHS = (
    Path("/etc/nginx/sites-available/sg-awg-panel"),
    Path("/etc/nginx/sites-enabled/sg-awg-panel"),
    Path("/etc/nginx/sites-available/sg-awg-panel.conf"),
    Path("/etc/nginx/sites-enabled/sg-awg-panel.conf"),
    Path("/etc/nginx/sites-available/sg-awg-placeholder.conf"),
    Path("/etc/nginx/sites-enabled/sg-awg-placeholder.conf"),
)
_PUBLIC_IP_CACHE: tuple[str, float] = ("", 0.0)
AWG_NAME_RE = re.compile(r"^[A-Za-z0-9А-Яа-яЁё_. -]{1,64}$")
CASCADE_SYSTEM_ROLE = "cascade_exit"


def _run(
    args: list[str], *, input_text: str | None = None, timeout: int = 20
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise AWGPanelError(f"Команда превысила тайм-аут {timeout} с: {' '.join(args)}") from exc


def _require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("Для управления AmneziaWG нужны права root")


def _command_path(name: str) -> str | None:
    return shutil.which(name)


def _keypair() -> tuple[str, str]:
    awg = _command_path("awg")
    if not awg:
        raise AWGPanelError("Команда awg не найдена. Сначала выполните deploy/install-amneziawg.sh")
    private = _run([awg, "genkey"]).stdout.strip()
    if not private:
        raise AWGPanelError("awg genkey не вернул закрытый ключ")
    public_result = _run([awg, "pubkey"], input_text=private + "\n")
    public = public_result.stdout.strip()
    if public_result.returncode != 0 or not public:
        raise AWGPanelError(public_result.stderr.strip() or "Не удалось получить открытый ключ AWG")
    return private, public


def _psk() -> str:
    awg = _command_path("awg")
    if not awg:
        raise AWGPanelError("Команда awg не найдена")
    result = _run([awg, "genpsk"])
    value = result.stdout.strip()
    if result.returncode != 0 or not value:
        raise AWGPanelError(result.stderr.strip() or "Не удалось создать PresharedKey")
    return value


def _random_header_ranges() -> tuple[str, str, str, str]:
    # Four separated segments guarantee that H1-H4 ranges never overlap.
    segments = (
        (100_000_000, 850_000_000),
        (950_000_000, 1_700_000_000),
        (1_800_000_000, 2_650_000_000),
        (2_750_000_000, 3_900_000_000),
    )
    ranges: list[str] = []
    for low, high in segments:
        width = secrets.randbelow(8_000_001) + 2_000_000
        start = random.SystemRandom().randint(low, high - width)
        ranges.append(f"{start}-{start + width}")
    random.SystemRandom().shuffle(ranges)
    return tuple(ranges)  # type: ignore[return-value]


def _validate_header(value: str, field: str) -> str:
    value = value.strip()
    match = re.fullmatch(r"(\d+)(?:-(\d+))?", value)
    if not match:
        raise ValueError(f"{field}: укажите число или диапазон start-end")
    start = int(match.group(1))
    end = int(match.group(2) or start)
    if not (0 <= start <= end <= 4_294_967_295):
        raise ValueError(f"{field}: диапазон должен находиться в пределах uint32")
    return f"{start}-{end}" if start != end else str(start)


def _validate_signature(value: str, field: str) -> str:
    value = value.strip()
    if len(value) > 4096:
        raise ValueError(f"{field}: значение слишком длинное")
    if "\n" in value or "\r" in value:
        raise ValueError(f"{field}: перевод строки недопустим")
    return value


def _validate_endpoint_host(value: object) -> str:
    endpoint_host = str(value).strip()
    if not endpoint_host:
        raise ValueError("Укажите публичный IP или домен AmneziaWG-сервера")
    if any(ch.isspace() for ch in endpoint_host) or any(ch in endpoint_host for ch in "/?#@"):
        raise ValueError("Endpoint должен содержать только IP-адрес или доменное имя без порта")
    candidate = endpoint_host[1:-1] if endpoint_host.startswith("[") and endpoint_host.endswith("]") else endpoint_host
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    if ":" in candidate:
        raise ValueError("UDP-порт задаётся отдельным полем")
    try:
        ascii_name = candidate.encode("idna").decode("ascii").rstrip(".")
    except UnicodeError as exc:
        raise ValueError("Некорректное доменное имя AmneziaWG-сервера") from exc
    if len(ascii_name) > 253:
        raise ValueError("Доменное имя слишком длинное")
    labels = ascii_name.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Некорректное доменное имя AmneziaWG-сервера")
    return ascii_name.lower()


def _validate_dns_servers(value: object) -> str:
    raw = str(value).strip()
    if not raw:
        raise ValueError("Укажите хотя бы один DNS-сервер")
    items = [item.strip() for item in raw.split(",")]
    if not 1 <= len(items) <= 4 or any(not item for item in items):
        raise ValueError("Укажите от одного до четырёх DNS IP-адресов через запятую")
    normalized: list[str] = []
    for item in items:
        try:
            normalized.append(str(ipaddress.ip_address(item)))
        except ValueError as exc:
            raise ValueError(f"Некорректный DNS IP-адрес: {item}") from exc
    return ", ".join(normalized)


def _validate_allowed_ips(value: object) -> str:
    raw = str(value).strip()
    if not raw:
        raise ValueError("AllowedIPs не может быть пустым")
    items = [item.strip() for item in raw.split(",")]
    if not 1 <= len(items) <= 32 or any(not item for item in items):
        raise ValueError("Укажите от одной до 32 сетей CIDR через запятую")
    normalized: list[str] = []
    for item in items:
        try:
            normalized.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError as exc:
            raise ValueError(f"Некорректная сеть AllowedIPs: {item}") from exc
    return ", ".join(normalized)


def _validate_settings(values: dict[str, object]) -> dict[str, object]:
    interface_name = str(values.get("interface_name", "awg0")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface_name):
        raise ValueError("Имя интерфейса должно содержать до 15 латинских символов, цифр, . _ или -")
    endpoint_host = _validate_endpoint_host(values.get("endpoint_host", ""))
    listen_port = int(values.get("listen_port", 585))
    if not 1 <= listen_port <= 65535:
        raise ValueError("UDP-порт должен быть от 1 до 65535")
    try:
        network = ipaddress.ip_network(str(values.get("server_network", "10.77.0.0/24")).strip(), strict=True)
    except ValueError as exc:
        raise ValueError("Сеть клиентов должна быть IPv4 CIDR, например 10.77.0.0/24") from exc
    if network.version != 4 or network.prefixlen < 16 or network.prefixlen > 30:
        raise ValueError("Для Alpha 1 используйте частную IPv4-сеть от /16 до /30")
    if not network.is_private:
        raise ValueError("Сеть клиентов должна быть частной IPv4-сетью")
    dns_servers = _validate_dns_servers(values.get("dns_servers", "1.1.1.1, 1.0.0.1"))
    mtu = int(values.get("mtu", 1280))
    if not 576 <= mtu <= 1500:
        raise ValueError("MTU должен быть от 576 до 1500")
    external_interface = str(values.get("external_interface", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", external_interface):
        raise ValueError("Укажите внешний сетевой интерфейс, например eth0 или ens5")

    jc = int(values.get("jc", 6))
    jmin = int(values.get("jmin", 64))
    jmax = int(values.get("jmax", 128))
    s1 = int(values.get("s1", 48))
    s2 = int(values.get("s2", 48))
    s3 = int(values.get("s3", 32))
    s4 = int(values.get("s4", 16))
    if not 0 <= jc <= 10:
        raise ValueError("Jc должен быть от 0 до 10 для AWG 2.0")
    if not 64 <= jmin < jmax <= 1024:
        raise ValueError("Должно выполняться 64 ≤ Jmin < Jmax ≤ 1024")
    if not 0 <= s1 <= 64 or not 0 <= s2 <= 64 or not 0 <= s3 <= 64 or not 0 <= s4 <= 32:
        raise ValueError("Для AWG 2.0 S1-S3 должны быть 0-64, а S4 — 0-32")

    headers = [_validate_header(str(values.get(f"h{i}", "")), f"H{i}") for i in range(1, 5)]
    parsed: list[tuple[int, int]] = []
    for value in headers:
        parts = value.split("-", 1)
        parsed.append((int(parts[0]), int(parts[-1])))
    for index, current in enumerate(parsed):
        for other in parsed[index + 1 :]:
            if max(current[0], other[0]) <= min(current[1], other[1]):
                raise ValueError("Диапазоны H1-H4 не должны пересекаться")

    return {
        "interface_name": interface_name,
        "endpoint_host": endpoint_host,
        "listen_port": listen_port,
        "server_network": str(network),
        "dns_servers": dns_servers,
        "mtu": mtu,
        "external_interface": external_interface,
        "isolate_clients": 1 if str(values.get("isolate_clients", "1")).lower() in {"1", "true", "yes", "on"} else 0,
        "jc": jc,
        "jmin": jmin,
        "jmax": jmax,
        "s1": s1,
        "s2": s2,
        "s3": s3,
        "s4": s4,
        **{f"h{i}": headers[i - 1] for i in range(1, 5)},
        **{f"i{i}": _validate_signature(str(values.get(f"i{i}", "")), f"I{i}") for i in range(1, 6)},
    }


def get_awg_settings():
    init_db()
    with connect() as con:
        row = con.execute("SELECT * FROM awg_settings WHERE id=1").fetchone()
    if row is None:
        raise AWGPanelError("Настройки AmneziaWG не найдены")
    return row


CLIENT_EXPIRY_WARNING_DAYS = 7
_DB_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_client_expiry(value: object | None) -> str | None:
    """Return a SQLite UTC timestamp or None for unlimited access."""
    if value is None:
        return None
    if isinstance(value, datetime):
        moment = value
    else:
        text = str(value).strip()
        if not text:
            return None
        candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
        try:
            moment = datetime.fromisoformat(candidate)
        except ValueError:
            try:
                moment = datetime.strptime(text, _DB_TIMESTAMP_FORMAT)
            except ValueError as exc:
                raise ValueError("Некорректная дата окончания доступа") from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc).replace(microsecond=0)
    return moment.strftime(_DB_TIMESTAMP_FORMAT)


def _expiry_datetime(value: object | None) -> datetime | None:
    normalized = normalize_client_expiry(value)
    if normalized is None:
        return None
    return datetime.strptime(normalized, _DB_TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)


def client_lifecycle(client: object, *, now: datetime | None = None) -> dict[str, object]:
    row = dict(client)
    current = (now or _utc_now()).astimezone(timezone.utc)
    expires = _expiry_datetime(row.get("expires_at"))
    expired = expires is not None and expires <= current
    remaining_seconds = None if expires is None else int((expires - current).total_seconds())
    expiring_soon = bool(
        expires is not None
        and not expired
        and remaining_seconds is not None
        and remaining_seconds <= CLIENT_EXPIRY_WARNING_DAYS * 86400
    )
    enabled = bool(row.get("enabled", 0))
    effective_enabled = enabled and not expired
    if not enabled:
        status = "disabled"
        status_text = "Отключён"
    elif expired:
        status = "expired"
        status_text = "Срок истёк"
    elif expiring_soon:
        status = "expiring"
        status_text = "Истекает скоро"
    else:
        status = "active"
        status_text = "Активен"

    if expires is None:
        expiry_text = "Без срока"
        expiry_iso = ""
    else:
        expiry_iso = expires.isoformat().replace("+00:00", "Z")
        if expired:
            expiry_text = "Срок истёк"
        elif remaining_seconds is not None and remaining_seconds < 86400:
            hours = max(1, (remaining_seconds + 3599) // 3600)
            expiry_text = f"Через {hours} ч"
        else:
            days = max(1, (remaining_seconds + 86399) // 86400) if remaining_seconds is not None else 0
            expiry_text = f"Через {days} дн"
    return {
        "expired": expired,
        "expiring_soon": expiring_soon,
        "effective_enabled": effective_enabled,
        "lifecycle_status": status,
        "lifecycle_status_text": status_text,
        "expires_at_iso": expiry_iso,
        "expires_at_text": expiry_text,
        "remaining_seconds": remaining_seconds,
    }


def client_is_effectively_enabled(client: object, *, now: datetime | None = None) -> bool:
    return bool(client_lifecycle(client, now=now)["effective_enabled"])


def list_awg_clients(
    *, enabled_only: bool = False, local_only: bool = False, node_id: int | None = None
):
    init_db()
    clauses: list[str] = []
    parameters: list[object] = []
    if enabled_only:
        clauses.append(ACTIVE_CLIENT_SQL)
    if local_only:
        clauses.append("node_id IS NULL")
    elif node_id is not None:
        clauses.append("node_id=?")
        parameters.append(int(node_id))
    query = "SELECT * FROM awg_clients"
    if clauses:
        query += " WHERE " + " AND ".join(f"({clause})" for clause in clauses)
    query += " ORDER BY id"
    with connect() as con:
        return con.execute(query, parameters).fetchall()


def find_awg_client(client_id: int):
    init_db()
    with connect() as con:
        row = con.execute("SELECT * FROM awg_clients WHERE id=?", (client_id,)).fetchone()
    if row is None:
        raise AWGPanelError("Клиент AmneziaWG не найден")
    return row


def detect_external_interface() -> str:
    ip = _command_path("ip")
    if not ip:
        return ""
    result = _run([ip, "route", "show", "default"])
    if result.returncode != 0:
        return ""
    match = re.search(r"\bdev\s+(\S+)", result.stdout)
    return match.group(1) if match else ""


def _url_text(request: urllib.request.Request | str, timeout: float = 2.5) -> str:
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        return response.read(256).decode("ascii", errors="ignore").strip()


def detect_public_ipv4(*, force: bool = False) -> str:
    """Best-effort public IPv4 detection without making it a hard dependency."""
    global _PUBLIC_IP_CACHE
    cached, cached_at = _PUBLIC_IP_CACHE
    cache_age = time.time() - cached_at if cached_at else float("inf")
    cache_ttl = 300 if cached else 60
    if not force and cache_age < cache_ttl:
        return cached

    def accept(candidate: str) -> str:
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return ""
        if address.version != 4 or address.is_private:
            return ""
        value = str(address)
        _PUBLIC_IP_CACHE = (value, time.time())
        return value

    try:
        token_request = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        )
        token = _url_text(token_request, timeout=1.0)
        if token:
            ip_request = urllib.request.Request(
                "http://169.254.169.254/latest/meta-data/public-ipv4",
                headers={"X-aws-ec2-metadata-token": token},
            )
            detected = accept(_url_text(ip_request, timeout=1.0))
            if detected:
                return detected
    except (OSError, urllib.error.URLError, ValueError):
        pass

    for url in ("https://checkip.amazonaws.com", "https://api.ipify.org"):
        try:
            detected = accept(_url_text(url))
        except (OSError, urllib.error.URLError, ValueError):
            continue
        if detected:
            return detected
    result = cached if not force else ""
    _PUBLIC_IP_CACHE = (result, time.time())
    return result


def _safe_reason(reason: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", reason).strip("-")
    return cleaned[:48] or "change"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _backup_version_compatible(value: str) -> bool:
    match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", str(value or ""), re.I)
    current = re.match(r"^(\d+)\.(\d+)\.(\d+)", __import__("awgpanel").__version__)
    return bool(match and current and match.group(1, 2) == current.group(1, 2))


def _backup_database_summary(path: Path) -> dict[str, object]:
    result: dict[str, object] = {"clients": 0, "nodes": 0, "cascade": False, "traffic_rules": 0}
    if not path.is_file():
        return result
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        try:
            tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "awg_clients" in tables:
                result["clients"] = int(con.execute("SELECT COUNT(*) FROM awg_clients").fetchone()[0])
            if "cluster_nodes" in tables:
                result["nodes"] = int(con.execute("SELECT COUNT(*) FROM cluster_nodes WHERE is_local=0").fetchone()[0])
            if "cascade_settings" in tables:
                row = con.execute("SELECT enabled,last_state FROM cascade_settings WHERE id=1").fetchone()
                result["cascade"] = bool(row and (int(row[0]) or str(row[1]) not in {"", "not_configured"}))
            if "traffic_rules" in tables:
                result["traffic_rules"] = int(con.execute("SELECT COUNT(*) FROM traffic_rules").fetchone()[0])
        finally:
            con.close()
    except sqlite3.Error:
        pass
    return result


def _managed_backup_sources() -> list[tuple[Path, Path]]:
    sources: list[tuple[Path, Path]] = [
        (Path("etc/sg-awg-panel/web.env"), PANEL_ENV_PATH),
        (Path("etc/sg-awg-node/agent.env"), NODE_AGENT_ENV_PATH),
        (Path("var/lib/sg-awg-node"), NODE_AGENT_STATE_DIR),
        (Path("etc/dnsmasq.d/sg-awg-traffic.conf"), DNSMASQ_CONFIG_PATH),
        (Path("var/www/sg-awg-placeholder/index.html"), PLACEHOLDER_PATH),
        (Path("var/lib/sg-awg-panel/traffic-rules"), TRAFFIC_STATE_DIR),
    ]
    for source in NGINX_MANAGED_PATHS:
        sources.append((Path(str(source).lstrip("/")), source))
    try:
        panel = get_panel_settings()
        domain = str(panel["public_host"] or "").strip()
        if bool(panel["https_enabled"]) and re.fullmatch(r"[A-Za-z0-9.-]{1,253}", domain):
            sources.extend([
                (Path(f"etc/letsencrypt/live/{domain}"), Path(f"/etc/letsencrypt/live/{domain}")),
                (Path(f"etc/letsencrypt/archive/{domain}"), Path(f"/etc/letsencrypt/archive/{domain}")),
                (Path(f"etc/letsencrypt/renewal/{domain}.conf"), Path(f"/etc/letsencrypt/renewal/{domain}.conf")),
            ])
    except Exception:
        pass
    return sources


def _copy_backup_source(source: Path, destination: Path) -> list[Path]:
    if not source.exists() and not source.is_symlink():
        return []
    copied: list[Path] = []
    actual_source = source.resolve() if source.is_symlink() else source
    if actual_source.is_dir():
        # Let's Encrypt live/<domain> is normally a directory symlink. Copy the
        # resolved certificate files as ordinary files so the backup remains
        # self-contained and does not depend on archive/ symlink targets.
        for item in actual_source.rglob("*"):
            if item.is_dir() and not item.is_symlink():
                continue
            relative = item.relative_to(actual_source)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            actual = item.resolve() if item.is_symlink() else item
            if actual.is_file():
                shutil.copy2(actual, target)
                os.chmod(target, 0o600)
                copied.append(target)
    elif actual_source.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(actual_source, destination)
        os.chmod(destination, 0o600)
        copied.append(destination)
    return copied


def _backup_file_manifest(backup: Path) -> dict[str, dict[str, object]]:
    files: dict[str, dict[str, object]] = {}
    for path in sorted(item for item in backup.rglob("*") if item.is_file() and not item.is_symlink()):
        relative = path.relative_to(backup).as_posix()
        if relative == "manifest.json":
            continue
        files[relative] = {"size": path.stat().st_size, "sha256": _sha256_file(path)}
    return files


def _write_backup_manifest(backup: Path) -> dict[str, dict[str, object]]:
    files = _backup_file_manifest(backup)
    payload = {
        "format_version": BACKUP_FORMAT_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": files,
    }
    path = backup / "manifest.json"
    temporary = path.with_suffix(".json.new")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return files


def _managed_restore_path_allowed(relative: Path) -> bool:
    parts = relative.parts
    if relative.is_absolute() or not parts or any(part in {"", ".", ".."} for part in parts):
        return False
    exact = {
        Path("etc/sg-awg-panel/web.env"),
        Path("etc/sg-awg-node/agent.env"),
        Path("etc/dnsmasq.d/sg-awg-traffic.conf"),
        Path("var/www/sg-awg-placeholder/index.html"),
        *[Path(str(path).lstrip("/")) for path in NGINX_MANAGED_PATHS],
    }
    if relative in exact:
        return True
    allowed_directories = (
        Path("var/lib/sg-awg-node"),
        Path("var/lib/sg-awg-panel/traffic-rules"),
        Path("etc/letsencrypt/live"),
        Path("etc/letsencrypt/archive"),
        Path("etc/letsencrypt/renewal"),
    )
    return any(relative != prefix and prefix in relative.parents for prefix in allowed_directories)


def _legacy_backup_manifest(metadata: dict[str, object]) -> dict[str, dict[str, object]] | None:
    raw = metadata.get("manifest") or metadata.get("files")
    if not isinstance(raw, dict) or not raw:
        return None
    result: dict[str, dict[str, object]] = {}
    for name, details in raw.items():
        if not isinstance(name, str) or not isinstance(details, dict):
            return None
        result[name] = dict(details)
    return result


def _verify_backup_path(
    backup: Path, *, update_metadata: bool = False, build_manifest: bool = False
) -> dict[str, object]:
    errors: list[str] = []
    checks: dict[str, bool] = {
        "Безопасная структура": True,
        "Manifest и SHA-256": True,
        "Совместимость версии": True,
        "База SQLite": True,
        "JSON и конфигурации": True,
        "Ключевые данные": True,
    }
    backup_root = backup.resolve()
    metadata_path = backup / "metadata.json"
    manifest_path = backup / "manifest.json"
    metadata: dict[str, object] = {}
    try:
        loaded = json.loads(metadata_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            metadata = loaded
        else:
            errors.append("metadata.json имеет неверный формат")
            checks["JSON и конфигурации"] = False
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"metadata.json: {exc}")
        checks["JSON и конфигурации"] = False

    managed_entries = metadata.get("managed_files", [])
    if not isinstance(managed_entries, list):
        errors.append("metadata.json: managed_files должен быть списком")
        checks["Безопасная структура"] = False
        managed_entries = []
    else:
        for entry in managed_entries:
            candidate = Path(str(entry))
            try:
                relative = candidate.relative_to("managed")
            except ValueError:
                relative = Path("..")
            if not _managed_restore_path_allowed(relative):
                errors.append(f"Недопустимый управляемый путь: {entry}")
                checks["Безопасная структура"] = False

    for path in backup.rglob("*"):
        try:
            resolved = path.resolve()
            if path.is_symlink() or (resolved != backup_root and backup_root not in resolved.parents):
                errors.append(f"Опасный путь в копии: {path.relative_to(backup)}")
                checks["Безопасная структура"] = False
        except (OSError, ValueError):
            errors.append(f"Не удалось проверить путь: {path}")
            checks["Безопасная структура"] = False

    backup_version = str(metadata.get("panel_version") or metadata.get("version") or "")
    if not backup_version:
        errors.append("В metadata.json отсутствует версия панели")
        checks["Совместимость версии"] = False
    elif not _backup_version_compatible(backup_version):
        errors.append(f"Версия копии {backup_version} несовместима с установленной панелью")
        checks["Совместимость версии"] = False

    database_path = backup / "panel.db"
    if bool(metadata.get("database_existed", database_path.exists())):
        if not database_path.is_file() or database_path.stat().st_size == 0:
            errors.append("panel.db отсутствует или пуст")
            checks["База SQLite"] = False
            checks["Ключевые данные"] = False
        else:
            try:
                con = sqlite3.connect(f"file:{database_path}?mode=ro&immutable=1", uri=True)
                try:
                    integrity = con.execute("PRAGMA integrity_check").fetchall()
                    tables = {str(row[0]) for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                finally:
                    con.close()
                if integrity != [("ok",)]:
                    errors.append(f"SQLite integrity_check: {integrity}")
                    checks["База SQLite"] = False
                required = {"awg_settings", "awg_clients", "panel_settings", "cluster_nodes"}
                missing = sorted(required - tables)
                if missing:
                    errors.append("В panel.db отсутствуют таблицы: " + ", ".join(missing))
                    checks["Ключевые данные"] = False
            except sqlite3.Error as exc:
                errors.append(f"panel.db: {exc}")
                checks["База SQLite"] = False

    panel_env_backup = backup / "managed/etc/sg-awg-panel/web.env"
    if bool(metadata.get("panel_env_existed", False)):
        if not panel_env_backup.is_file() or panel_env_backup.stat().st_size == 0:
            errors.append("В копии отсутствует обязательный web.env")
            checks["Ключевые данные"] = False
        else:
            try:
                env_lines = panel_env_backup.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                errors.append(f"web.env: {exc}")
                checks["Ключевые данные"] = False
            else:
                env_values = {
                    line.split("=", 1)[0].strip(): line.split("=", 1)[1].strip().strip("'\"")
                    for line in env_lines
                    if "=" in line and not line.lstrip().startswith("#")
                }
                missing_env = [
                    key for key in ("AWGPANEL_SECRET_KEY", "AWGPANEL_PASSWORD_HASH", "AWGPANEL_DB")
                    if not env_values.get(key)
                ]
                if missing_env:
                    errors.append("web.env не содержит обязательные значения: " + ", ".join(missing_env))
                    checks["Ключевые данные"] = False

    node_env_backup = backup / "managed/etc/sg-awg-node/agent.env"
    if bool(metadata.get("node_agent_env_existed", False)) and (
        not node_env_backup.is_file() or node_env_backup.stat().st_size == 0
    ):
        errors.append("В копии отсутствует обязательный agent.env подключённой SG-Node")
        checks["Ключевые данные"] = False

    config_path = backup / "awg0.conf"
    if bool(metadata.get("config_existed", False)):
        if not config_path.is_file() or config_path.stat().st_size == 0:
            errors.append("awg0.conf должен присутствовать, но отсутствует или пуст")
            checks["JSON и конфигурации"] = False
        else:
            text = config_path.read_text(encoding="utf-8", errors="replace")
            if "[Interface]" not in text or "PrivateKey" not in text:
                errors.append("awg0.conf не содержит обязательную секцию Interface и ключ")
                checks["JSON и конфигурации"] = False

    for suffix in ("-wal", "-shm"):
        (backup / f"panel.db{suffix}").unlink(missing_ok=True)

    actual_files = _backup_file_manifest(backup)
    total_size = sum(item.stat().st_size for item in backup.rglob("*") if item.is_file())
    for relative in actual_files:
        path = backup / relative
        if path.suffix.casefold() == ".json":
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"{relative}: некорректный JSON ({exc})")
                checks["JSON и конфигурации"] = False

    stored_manifest: dict[str, dict[str, object]] | None = None
    legacy_manifest = False
    if manifest_path.is_file() and not manifest_path.is_symlink():
        try:
            loaded_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            raw_files = loaded_manifest.get("files") if isinstance(loaded_manifest, dict) else None
            if isinstance(raw_files, dict):
                stored_manifest = {
                    str(name): dict(details)
                    for name, details in raw_files.items()
                    if isinstance(name, str) and isinstance(details, dict)
                }
                if len(stored_manifest) != len(raw_files):
                    stored_manifest = None
            else:
                errors.append("manifest.json имеет неверный формат")
                checks["Manifest и SHA-256"] = False
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"manifest.json: {exc}")
            checks["Manifest и SHA-256"] = False
    elif not build_manifest:
        # RC4 backups stored hashes inside metadata.json. They can be checked and
        # upgraded once, but new RC5 backups always require a separate manifest
        # that also protects metadata.json itself.
        stored_manifest = _legacy_backup_manifest(metadata)
        legacy_manifest = stored_manifest is not None
        if stored_manifest is None:
            errors.append("В резервной копии отсутствует manifest.json")
            checks["Manifest и SHA-256"] = False

    if stored_manifest is not None:
        compared_files = actual_files
        if legacy_manifest:
            compared_files = {
                name: details for name, details in actual_files.items()
                if name != "metadata.json" and name in stored_manifest
            }
        if set(stored_manifest) != set(compared_files):
            errors.append("Состав файлов не совпадает с manifest")
            checks["Manifest и SHA-256"] = False
        for name, details in compared_files.items():
            expected = stored_manifest.get(name)
            try:
                expected_size = int(expected.get("size", -1)) if isinstance(expected, dict) else -1
            except (TypeError, ValueError):
                expected_size = -1
            if (
                not isinstance(expected, dict)
                or str(expected.get("sha256") or "") != str(details["sha256"])
                or expected_size != int(details["size"])
            ):
                errors.append(f"Не совпадает контрольная сумма или размер: {name}")
                checks["Manifest и SHA-256"] = False

    if build_manifest and not errors:
        stored_manifest = _write_backup_manifest(backup)
        actual_files = stored_manifest
        total_size = sum(item.stat().st_size for item in backup.rglob("*") if item.is_file())
    elif legacy_manifest and update_metadata and not errors:
        # Upgrade a verified RC4 copy to the RC5 format. From this point onward
        # metadata.json is protected by manifest.json as well.
        stored_manifest = _write_backup_manifest(backup)
        actual_files = stored_manifest
        total_size = sum(item.stat().st_size for item in backup.rglob("*") if item.is_file())

    result = {
        "verified": not errors,
        "verification_errors": errors,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "size_bytes": total_size,
        "size_text": _human_size(total_size),
        "file_count": sum(1 for item in backup.rglob("*") if item.is_file()),
        "files": actual_files,
        "manifest": stored_manifest or {},
        "checks": checks,
        "backup_version": backup_version,
        "format_version": int(metadata.get("format_version") or (1 if legacy_manifest else 0)),
        "legacy_upgraded": bool(legacy_manifest and update_metadata and not errors),
        "summary": _backup_database_summary(database_path),
    }
    return result


def _backup_state(reason: str) -> Path:
    from . import __version__
    _require_root()
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_DIR, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    target = BACKUP_DIR / f"{stamp}-{_safe_reason(reason)}"
    target.mkdir(mode=0o700)
    database_existed = db.DB_PATH.exists()
    if database_existed:
        destination = sqlite3.connect(target / "panel.db")
        try:
            with connect() as source:
                source.backup(destination)
        finally:
            destination.close()
        os.chmod(target / "panel.db", 0o600)
    config_existed = AWG_CONFIG_PATH.exists()
    if config_existed:
        shutil.copy2(AWG_CONFIG_PATH, target / "awg0.conf")
        os.chmod(target / "awg0.conf", 0o600)
    managed_root = target / "managed"
    managed_files: list[str] = []
    for relative, source in _managed_backup_sources():
        for copied in _copy_backup_source(source, managed_root / relative):
            managed_files.append(copied.relative_to(target).as_posix())
    metadata = {
        "format_version": BACKUP_FORMAT_VERSION,
        "panel_version": __version__,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "database_existed": database_existed,
        "config_existed": config_existed,
        "panel_env_existed": PANEL_ENV_PATH.exists(),
        "node_agent_env_existed": NODE_AGENT_ENV_PATH.exists(),
        "service_state": awg_service_state(),
        "managed_files": managed_files,
        "summary": _backup_database_summary(target / "panel.db"),
    }
    (target / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(target / "metadata.json", 0o600)
    verification = _verify_backup_path(target, update_metadata=True, build_manifest=True)
    if not verification["verified"]:
        shutil.rmtree(target, ignore_errors=True)
        raise AWGPanelError("Резервная копия не прошла проверку: " + "; ".join(map(str, verification["verification_errors"])))
    backups = sorted((item for item in BACKUP_DIR.iterdir() if item.is_dir()), reverse=True)
    for old in backups[max(1, _backup_keep_value()):]:
        shutil.rmtree(old, ignore_errors=True)
    return target


def _restore_managed_files(backup: Path, metadata: dict[str, object]) -> None:
    root = backup / "managed"
    if not root.is_dir():
        return
    root_resolved = root.resolve()
    entries = metadata.get("managed_files", [])
    if not isinstance(entries, list):
        raise AWGPanelError("Некорректный список управляемых файлов в копии")
    for relative_text in entries:
        candidate = Path(str(relative_text))
        try:
            relative = candidate.relative_to("managed")
        except ValueError as exc:
            raise AWGPanelError("Некорректный путь управляемого файла в копии") from exc
        if not _managed_restore_path_allowed(relative):
            raise AWGPanelError(f"В копии запрещён путь восстановления: {relative}")
        source = root / relative
        source_resolved = source.resolve()
        if root_resolved not in source_resolved.parents or not source.is_file() or source.is_symlink():
            raise AWGPanelError(f"В копии отсутствует безопасный управляемый файл: {relative}")
        target = Path("/") / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        os.chmod(target, 0o600 if any(part in {"sg-awg-panel", "sg-awg-node", "letsencrypt"} for part in relative.parts) else 0o644)


def _restore_backup(backup: Path) -> None:
    metadata_path = backup / "metadata.json"
    metadata: dict[str, object] = {}
    if metadata_path.exists():
        loaded = json.loads(metadata_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            metadata = loaded
    previous_state = str(metadata.get("service_state", "inactive"))
    if previous_state != "active":
        stop_result = _run(["systemctl", "stop", AWG_SERVICE], timeout=30)
        if stop_result.returncode != 0 and AWG_CONFIG_PATH.exists():
            awg_quick = _command_path("awg-quick")
            if awg_quick:
                _run([awg_quick, "down", str(AWG_CONFIG_PATH)], timeout=30)
    backup_db = backup / "panel.db"
    if backup_db.exists():
        db.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        for suffix in ("", "-wal", "-shm"):
            Path(str(db.DB_PATH) + suffix).unlink(missing_ok=True)
        shutil.copy2(backup_db, db.DB_PATH)
        os.chmod(db.DB_PATH, 0o600)
    backup_config = backup / "awg0.conf"
    AWG_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if backup_config.exists():
        shutil.copy2(backup_config, AWG_CONFIG_PATH)
        os.chmod(AWG_CONFIG_PATH, 0o600)
    elif not metadata.get("config_existed", False):
        AWG_CONFIG_PATH.unlink(missing_ok=True)
    _restore_managed_files(backup, metadata)
    if previous_state == "active" and AWG_CONFIG_PATH.exists():
        _run(["systemctl", "restart", AWG_SERVICE], timeout=30)
    _reload_egress_if_available()


def _human_size(value: int) -> str:
    amount = float(max(0, value))
    units = ("B", "KiB", "MiB", "GiB")
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{value} B"


def find_backup_path(name: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise AWGPanelError("Некорректное имя резервной копии")
    backup = (BACKUP_DIR / name).resolve()
    if backup.parent != BACKUP_DIR.resolve() or not backup.is_dir():
        raise AWGPanelError("Резервная копия не найдена")
    return backup


def verify_backup(name: str) -> dict[str, object]:
    return _verify_backup_path(find_backup_path(name), update_metadata=True)


def list_backups(limit: int = 10) -> list[dict[str, object]]:
    if not BACKUP_DIR.exists():
        return []
    result: list[dict[str, object]] = []
    for item in sorted((path for path in BACKUP_DIR.iterdir() if path.is_dir()), reverse=True)[:limit]:
        metadata: dict[str, object] = {}
        try:
            loaded = json.loads((item / "metadata.json").read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                metadata = loaded
        except (OSError, json.JSONDecodeError):
            pass
        verification = _verify_backup_path(item, update_metadata=False)
        result.append({"name": item.name, "path": str(item), **metadata, **verification})
    return result


def default_placeholder_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Welcome</title>
  <style>body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,sans-serif;background:#f5f7fb;color:#1b2533}main{max-width:42rem;padding:3rem;text-align:center}h1{font-size:2.4rem;margin:0 0 1rem}p{line-height:1.6;color:#526071}</style>
</head>
<body><main><h1>Welcome</h1><p>This web server is running normally.</p></main></body>
</html>
"""


def read_placeholder_html() -> str:
    try:
        return PLACEHOLDER_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return default_placeholder_html()


def save_placeholder_html(value: str) -> Path:
    _require_root()
    html_text = str(value or "")
    raw = html_text.encode("utf-8")
    if not html_text.strip():
        raise ValueError("HTML заглушки не может быть пустым")
    if len(raw) > PLACEHOLDER_MAX_BYTES:
        raise ValueError("HTML заглушки превышает 256 KiB")
    if "\x00" in html_text:
        raise ValueError("HTML заглушки содержит недопустимый нулевой байт")
    PLACEHOLDER_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = PLACEHOLDER_PATH.with_suffix(".html.new")
    temporary.write_text(html_text, encoding="utf-8")
    os.chmod(temporary, 0o644)
    temporary.replace(PLACEHOLDER_PATH)
    return PLACEHOLDER_PATH


def reset_placeholder_html() -> Path:
    return save_placeholder_html(default_placeholder_html())

def _server_address(settings) -> str:
    network = ipaddress.ip_network(settings["server_network"], strict=True)
    return f"{next(network.hosts())}/{network.prefixlen}"


def _next_client_address(settings) -> str:
    network = ipaddress.ip_network(settings["server_network"], strict=True)
    with connect() as con:
        rows = con.execute("SELECT address FROM awg_clients WHERE node_id IS NULL").fetchall()
    used = {str(row["address"]).split("/", 1)[0] for row in rows}
    hosts = network.hosts()
    next(hosts, None)  # server gets the first usable address
    for host in hosts:
        if str(host) not in used:
            return f"{host}/32"
    raise AWGPanelError("В сети AmneziaWG больше нет свободных адресов")


def _obfuscation_lines(settings) -> list[str]:
    lines = [
        f"Jc = {settings['jc']}",
        f"Jmin = {settings['jmin']}",
        f"Jmax = {settings['jmax']}",
        f"S1 = {settings['s1']}",
        f"S2 = {settings['s2']}",
        f"S3 = {settings['s3']}",
        f"S4 = {settings['s4']}",
        f"H1 = {settings['h1']}",
        f"H2 = {settings['h2']}",
        f"H3 = {settings['h3']}",
        f"H4 = {settings['h4']}",
    ]
    for number in range(1, 6):
        value = str(settings[f"i{number}"]).strip()
        if value:
            lines.append(f"I{number} = {value}")
    return lines


def render_awg_server_config() -> str:
    settings = get_awg_settings()
    if not settings["configured"]:
        raise AWGPanelError("AmneziaWG ещё не настроен")
    ext = settings["external_interface"]
    interface_name = settings["interface_name"]
    clients = [row for row in list_awg_clients(enabled_only=True) if not row["node_id"]]
    up_commands: list[str] = []
    down_commands: list[str] = []
    if bool(settings["isolate_clients"]):
        up_commands.append(f"iptables -I FORWARD 1 -i {interface_name} -o {interface_name} -j DROP")
        down_commands.append(f"iptables -D FORWARD -i {interface_name} -o {interface_name} -j DROP")
    up_commands.extend([
        f"iptables -A FORWARD -i {interface_name} -j ACCEPT",
        f"iptables -A FORWARD -o {interface_name} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
    ])
    down_commands.extend([
        f"iptables -D FORWARD -i {interface_name} -j ACCEPT",
        f"iptables -D FORWARD -o {interface_name} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
    ])
    if bool(settings["nat_enabled"]):
        nat_sources = [str(settings["server_network"])]
        for client in clients:
            if str(client["system_role"] or "") == CASCADE_SYSTEM_ROLE or str(client["system_role"] or "").startswith("cascade_exit_"):
                source = str(client["address"] or "").strip()
                if source and source not in nat_sources:
                    nat_sources.append(source)
        for source in nat_sources:
            up_commands.append(
                f"iptables -t nat -A POSTROUTING -s {source} -o {ext} -j MASQUERADE"
            )
            down_commands.append(
                f"iptables -t nat -D POSTROUTING -s {source} -o {ext} -j MASQUERADE"
            )
    lines = [
        "[Interface]",
        f"Address = {_server_address(settings)}",
        f"ListenPort = {settings['listen_port']}",
        f"PrivateKey = {settings['private_key']}",
        f"MTU = {settings['mtu']}",
        *_obfuscation_lines(settings),
        "",
        "PostUp = " + "; ".join(up_commands),
        "PostDown = " + "; ".join(down_commands),
    ]
    for client in clients:
        peer_routes = [str(client["address"])]
        advertised = str(client["advertised_networks"] or "").strip()
        if advertised:
            peer_routes.append(advertised)
        lines.extend(
            [
                "",
                "[Peer]",
                f"# {client['name']}",
                f"PublicKey = {client['public_key']}",
                f"PresharedKey = {client['preshared_key']}",
                f"AllowedIPs = {', '.join(peer_routes)}",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _client_profile_name(client, panel=None) -> str:
    panel = panel or get_panel_settings()
    instance = str(panel["instance_name"] or "SG-AWG-Panel").strip()
    client_name = str(client["name"] or "AmneziaWG").strip()
    if not instance or instance.casefold() == "sg-awg-panel":
        return client_name
    return f"{instance}/{client_name}"


def render_awg_client_config(client_id: int) -> str:
    settings = get_awg_settings()
    client = find_awg_client(client_id)
    panel = get_panel_settings()
    if client["node_id"]:
        from .node_clients import render_remote_client_config
        return render_remote_client_config(client)
    if not settings["configured"]:
        raise AWGPanelError("AmneziaWG ещё не настроен")
    lifecycle = client_lifecycle(client)
    if not bool(client["enabled"]):
        raise AWGPanelError("Клиент отключён администратором")
    if bool(lifecycle["expired"]):
        raise AWGPanelError("Срок действия клиента истёк")
    endpoint_host = settings["endpoint_host"]
    if ":" in endpoint_host and not endpoint_host.startswith("["):
        endpoint_host = f"[{endpoint_host}]"
    additional_routes: list[str] = []
    if bool(client["include_server_lan"]) and str(settings["server_lan_networks"]).strip():
        additional_routes.append(str(settings["server_lan_networks"]))
    allowed_ips = exported_allowed_ips(
        client["allowed_ips"],
        client["excluded_ips"],
        additional_routes,
    )
    if not allowed_ips:
        raise AWGPanelError("После применения исключений у клиента не осталось маршрутов")
    dns_value = str(client["dns_servers"] or settings["dns_servers"])
    try:
        from .traffic_rules import get_dns_traffic_settings
        dns_control = get_dns_traffic_settings()
        if str(dns_control["mode"]) != "off" and bool(dns_control["advertise_to_clients"]):
            dns_value = str(next(ipaddress.ip_network(str(settings["server_network"]), strict=True).hosts()))
    except Exception:
        pass
    profile_name = _client_profile_name(client, panel)
    lines = [
        f"# Name = {profile_name}",
        f"# Client = {client['name']}",
        "# Source = SG-AWG-Panel",
        "",
        "[Interface]",
        f"Address = {client['address']}",
        f"DNS = {dns_value}",
        f"PrivateKey = {client['private_key']}",
        f"MTU = {client['mtu'] or settings['mtu']}",
        *_obfuscation_lines(settings),
        "",
        "[Peer]",
        f"PublicKey = {settings['public_key']}",
        f"PresharedKey = {client['preshared_key']}",
        f"AllowedIPs = {allowed_ips}",
        f"Endpoint = {endpoint_host}:{settings['listen_port']}",
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines).rstrip() + "\n"


def _write_server_config() -> Path:
    _require_root()
    AWG_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(AWG_CONFIG_DIR, 0o700)
    # awg-quick accepts only <valid-interface-name>.conf. A suffix such as
    # awg0.conf.tmp is rejected before validation begins.
    temporary = AWG_CONFIG_DIR / "awgtest0.conf"
    temporary.write_text(render_awg_server_config(), encoding="utf-8")
    os.chmod(temporary, 0o600)
    try:
        awg_quick = _command_path("awg-quick")
        if awg_quick:
            validation = _run([awg_quick, "strip", str(temporary)], timeout=15)
            if validation.returncode != 0:
                raise AWGPanelError(
                    validation.stderr.strip()
                    or validation.stdout.strip()
                    or "awg-quick не принял сформированную конфигурацию"
                )
        temporary.replace(AWG_CONFIG_PATH)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    os.chmod(AWG_CONFIG_PATH, 0o600)
    return AWG_CONFIG_PATH


def _prepare_awg_values(current, values: dict[str, object]) -> dict[str, object]:
    prepared = dict(values)
    if not prepared.get("endpoint_host"):
        prepared["endpoint_host"] = detect_public_ipv4()
    if not prepared.get("external_interface"):
        prepared["external_interface"] = detect_external_interface()
    if current["configured"]:
        for key in ("h1", "h2", "h3", "h4"):
            if not str(prepared.get(key, "")).strip():
                prepared[key] = current[key]
    else:
        h1, h2, h3, h4 = _random_header_ranges()
        for key, value in {"h1": h1, "h2": h2, "h3": h3, "h4": h4}.items():
            if not str(prepared.get(key, "")).strip():
                prepared[key] = value
    for key, default in {
        "interface_name": "awg0", "listen_port": 585,
        "server_network": "10.77.0.0/24", "dns_servers": "1.1.1.1, 1.0.0.1",
        "mtu": 1280, "jc": 6, "jmin": 64, "jmax": 128,
        "s1": 48, "s2": 48, "s3": 32, "s4": 16,
        "isolate_clients": 1,
        "i1": "", "i2": "", "i3": "", "i4": "", "i5": "",
    }.items():
        prepared.setdefault(key, current[key] if current["configured"] else default)
    assigned_network = str(current["server_network"] or "10.77.0.0/24") if current["configured"] else "10.77.0.0/24"
    requested_network = str(prepared.get("server_network") or assigned_network)
    if requested_network != assigned_network:
        raise ValueError(
            f"VPN-пул {assigned_network} закреплён за этим сервером и не изменяется в настройках AWG"
        )
    prepared["server_network"] = assigned_network
    return _validate_settings(prepared)


def validate_awg_settings_document(values: dict[str, object]) -> dict[str, object]:
    """Validate AWG Server JSON without changing the database or runtime."""
    current = get_awg_settings()
    validated = _prepare_awg_values(current, values)
    ensure_udp_port_available(
        int(validated["listen_port"]),
        current_port=int(current["listen_port"]) if current["configured"] else None,
    )
    if str(current["server_network"]) != str(validated["server_network"]):
        network_client_addresses(
            str(validated["server_network"]),
            len(list_awg_clients(local_only=True)),
        )
    return validated


def _migrate_client_network(old_network: str, new_network: str) -> None:
    if old_network == new_network:
        return
    clients = [
        row for row in list_awg_clients(local_only=True)
        if not str(row["system_role"] or "").strip()
    ]
    addresses = network_client_addresses(new_network, len(clients))
    with connect() as con:
        for client, address in zip(clients, addresses):
            allowed_ips = str(client["allowed_ips"])
            if allowed_ips == old_network:
                allowed_ips = new_network
            con.execute(
                "UPDATE awg_clients SET address=?, allowed_ips=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (address, allowed_ips, int(client["id"])),
            )


def _configure_awg_impl(**values):
    current = get_awg_settings()
    validated = _prepare_awg_values(current, values)
    ensure_udp_port_available(
        int(validated["listen_port"]),
        current_port=int(current["listen_port"]) if current["configured"] else None,
    )
    private_key = current["private_key"]
    public_key = current["public_key"]
    if not private_key or not public_key:
        private_key, public_key = _keypair()
    old_network = str(current["server_network"])
    with connect() as con:
        con.execute(
            """
            UPDATE awg_settings SET configured=1, interface_name=?, endpoint_host=?,
                listen_port=?, server_network=?, dns_servers=?, mtu=?, external_interface=?,
                private_key=?, public_key=?, jc=?, jmin=?, jmax=?, s1=?, s2=?, s3=?, s4=?,
                h1=?, h2=?, h3=?, h4=?, i1=?, i2=?, i3=?, i4=?, i5=?,
                isolate_clients=?, updated_at=CURRENT_TIMESTAMP WHERE id=1
            """,
            (
                validated["interface_name"], validated["endpoint_host"],
                validated["listen_port"], validated["server_network"],
                validated["dns_servers"], validated["mtu"], validated["external_interface"],
                private_key, public_key, validated["jc"], validated["jmin"],
                validated["jmax"], validated["s1"], validated["s2"],
                validated["s3"], validated["s4"], validated["h1"],
                validated["h2"], validated["h3"], validated["h4"],
                validated["i1"], validated["i2"], validated["i3"],
                validated["i4"], validated["i5"], validated["isolate_clients"],
            ),
        )
    _migrate_client_network(old_network, str(validated["server_network"]))
    _write_server_config()
    return get_awg_settings()

def configure_awg(**values):
    _require_root()
    current = get_awg_settings()
    _prepare_awg_values(current, values)
    backup = _backup_state("server-settings")
    try:
        return _configure_awg_impl(**values)
    except Exception:
        try:
            _restore_backup(backup)
        except Exception:
            pass
        raise


def configure_and_start_awg(**values) -> tuple[object, str]:
    _require_root()
    current = get_awg_settings()
    _prepare_awg_values(current, values)
    backup = _backup_state("server-apply")
    previous_state = awg_service_state()
    try:
        settings = _configure_awg_impl(**values)
        state = _service_action("restart" if previous_state == "active" else "start")
        if state != "active":
            raise AWGPanelError(f"Служба AmneziaWG не запустилась: {state}")
    except Exception:
        try:
            _restore_backup(backup)
        except Exception:
            pass
        raise

    # Rebuild Traffic Rules after the AWG service is ready. A secondary
    # policy failure must not roll back a working AWG Server.
    _reload_egress_if_available(strict=False)
    return settings, state


def ensure_default_awg_server() -> dict[str, object]:
    """Configure and start a safe default AWG server only on a fresh installation."""
    _require_root()
    current = get_awg_settings()
    if bool(current["configured"]):
        return {
            "changed": False,
            "configured": True,
            "service_state": awg_service_state(),
            "listen_port": int(current["listen_port"]),
        }

    candidates = [585, 51820]
    candidates.extend(20000 + secrets.randbelow(40001) for _ in range(12))
    selected_port: int | None = None
    for candidate in candidates:
        try:
            ensure_udp_port_available(int(candidate), current_port=None)
        except (ValueError, AWGPanelError):
            continue
        selected_port = int(candidate)
        break
    if selected_port is None:
        raise AWGPanelError("Не удалось подобрать свободный UDP-порт для AWG Server")

    settings, state = configure_and_start_awg(
        interface_name="awg0",
        listen_port=selected_port,
        server_network="10.77.0.0/24",
        dns_servers="1.1.1.1, 1.0.0.1",
        mtu=1280,
        jc=6,
        jmin=64,
        jmax=128,
        s1=48,
        s2=48,
        s3=32,
        s4=16,
        isolate_clients=1,
    )
    return {
        "changed": True,
        "configured": True,
        "service_state": state,
        "listen_port": int(settings["listen_port"]),
        "endpoint_host": str(settings["endpoint_host"]),
        "server_network": str(settings["server_network"]),
    }


def list_awg_service_clients(system_role: str) -> list[object]:
    init_db()
    role = str(system_role or "").strip()
    if not role:
        return []
    with connect() as con:
        return con.execute(
            "SELECT * FROM awg_clients WHERE node_id IS NULL AND system_role=? ORDER BY id",
            (role,),
        ).fetchall()


def add_awg_service_client(
    name: str,
    *,
    address: str,
    system_role: str,
    comment: str = "",
):
    """Create a managed peer with an explicit /32 address.

    Used for infrastructure links such as Cascade. The peer is deliberately
    excluded from ordinary access links and expiry workflows.
    """
    _require_root()
    settings = get_awg_settings()
    if not settings["configured"]:
        raise AWGPanelError("Сначала настройте сервер AmneziaWG")
    clean_name = str(name or "").strip()
    if not AWG_NAME_RE.fullmatch(clean_name):
        raise ValueError("Имя служебного клиента должно содержать от 1 до 64 обычных символов")
    role = str(system_role or "").strip()[:48]
    if not re.fullmatch(r"[a-z0-9_-]{2,48}", role):
        raise ValueError("Некорректная роль служебного клиента")
    try:
        interface = ipaddress.ip_interface(str(address or "").strip())
    except ValueError as exc:
        raise ValueError("Некорректный адрес служебного клиента") from exc
    if interface.version != 4 or interface.network.prefixlen != 32:
        raise ValueError("Служебному клиенту требуется отдельный IPv4 /32")
    if interface.ip == ipaddress.ip_interface(_server_address(settings)).ip:
        raise ValueError("Адрес служебного клиента совпадает с адресом сервера")

    backup = _backup_state("service-client-add")
    try:
        private_key, public_key = _keypair()
        preshared_key = _psk()
        with connect() as con:
            cursor = con.execute(
                """
                INSERT INTO awg_clients
                    (name, address, private_key, public_key, preshared_key, comment,
                     allowed_ips, access_token, access_enabled, system_role)
                VALUES (?, ?, ?, ?, ?, ?, '0.0.0.0/0', '', 0, ?)
                """,
                (
                    clean_name, str(interface), private_key, public_key, preshared_key,
                    str(comment or "").strip(), role,
                ),
            )
            client_id = int(cursor.lastrowid)
        _write_server_config()
        _reload_if_active()
        _reload_egress_if_available(strict=False)
        return find_awg_client(client_id)
    except sqlite3.IntegrityError as exc:
        _restore_backup(backup)
        raise AWGPanelError("Служебный клиент с таким именем или адресом уже существует") from exc
    except Exception:
        _restore_backup(backup)
        raise


def delete_awg_service_clients(system_role: str) -> list[dict[str, object]]:
    _require_root()
    rows = [dict(row) for row in list_awg_service_clients(system_role)]
    if not rows:
        return []
    backup = _backup_state("service-client-delete")
    try:
        with connect() as con:
            con.execute("DELETE FROM awg_clients WHERE system_role=?", (str(system_role),))
        _write_server_config()
        _reload_if_active()
        _reload_egress_if_available(strict=False)
        return rows
    except Exception:
        _restore_backup(backup)
        raise


def add_awg_client(
    name: str, comment: str = "", expires_at: object | None = None,
    node_id: int | None = None,
):
    _require_root()
    if node_id:
        from .node_manager import get_node
        selected_node = get_node(int(node_id))
        if not bool(selected_node.get("is_local")):
            from .node_clients import add_remote_client
            return add_remote_client(
                int(node_id), name=name, comment=comment, expires_at=expires_at
            )
    settings = get_awg_settings()
    if not settings["configured"]:
        raise AWGPanelError("Сначала настройте сервер AmneziaWG")
    name = name.strip()
    if not AWG_NAME_RE.fullmatch(name):
        raise ValueError("Имя клиента должно содержать от 1 до 64 обычных символов")
    normalized_expiry = normalize_client_expiry(expires_at)
    backup = _backup_state("client-add")
    try:
        private_key, public_key = _keypair()
        preshared_key = _psk()
        address = _next_client_address(settings)
        try:
            with connect() as con:
                cursor = con.execute(
                    """
                    INSERT INTO awg_clients
                        (name, address, private_key, public_key, preshared_key, comment,
                         allowed_ips, access_token, access_enabled, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, '0.0.0.0/0', ?, 1, ?)
                    """,
                    (name, address, private_key, public_key, preshared_key, comment.strip(),
                     secrets.token_urlsafe(24), normalized_expiry),
                )
                client_id = int(cursor.lastrowid)
                cascade = con.execute(
                    """
                    SELECT link.outbound_id
                    FROM cascade_links AS link
                    JOIN cluster_nodes AS entry_node ON entry_node.id=link.entry_node_id
                    WHERE entry_node.is_local=1 AND link.enabled=1 AND link.state='active'
                      AND link.outbound_id IS NOT NULL
                    LIMIT 1
                    """
                ).fetchone()
                if cascade is None:
                    cascade = con.execute(
                        "SELECT outbound_id FROM cascade_settings "
                        "WHERE id=1 AND enabled=1 AND outbound_id IS NOT NULL"
                    ).fetchone()
                if cascade is not None:
                    con.execute(
                        "UPDATE awg_clients SET egress_mode='outbound', outbound_id=? WHERE id=?",
                        (int(cascade["outbound_id"]), client_id),
                    )
        except Exception as exc:
            if "UNIQUE" in str(exc).upper():
                raise AWGPanelError("Клиент с таким именем уже существует") from exc
            raise
        _write_server_config()
        _reload_if_active()
        _reload_egress_if_available()
        return find_awg_client(client_id)
    except Exception:
        _restore_backup(backup)
        raise


def set_awg_client_enabled(client_id: int, enabled: bool):
    _require_root()
    current = find_awg_client(client_id)
    if current["node_id"]:
        previous = int(current["enabled"])
        with connect() as con:
            con.execute(
                "UPDATE awg_clients SET enabled=?, deployment_state='queued', "
                "deployment_error='', updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (1 if enabled else 0, int(client_id)),
            )
        try:
            from .node_clients import queue_node_client_sync
            queue_node_client_sync(int(current["node_id"]), target_client_ids=[client_id])
            return find_awg_client(client_id)
        except Exception:
            with connect() as con:
                con.execute(
                    "UPDATE awg_clients SET enabled=?, deployment_state='active', "
                    "updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (previous, int(client_id)),
                )
            raise
    backup = _backup_state("client-toggle")
    try:
        with connect() as con:
            con.execute(
                "UPDATE awg_clients SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (1 if enabled else 0, client_id),
            )
        _write_server_config()
        _reload_if_active()
        _reload_egress_if_available()
        return find_awg_client(client_id)
    except Exception:
        _restore_backup(backup)
        raise

def set_awg_client_expiry(client_id: int, expires_at: object | None):
    _require_root()
    current = find_awg_client(client_id)
    normalized = normalize_client_expiry(expires_at)
    if current["node_id"]:
        previous = current["expires_at"]
        with connect() as con:
            con.execute(
                "UPDATE awg_clients SET expires_at=?, deployment_state='queued', "
                "deployment_error='', updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (normalized, int(client_id)),
            )
        try:
            from .node_clients import queue_node_client_sync
            queue_node_client_sync(int(current["node_id"]), target_client_ids=[client_id])
            return find_awg_client(client_id)
        except Exception:
            with connect() as con:
                con.execute(
                    "UPDATE awg_clients SET expires_at=?, deployment_state='active', "
                    "updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (previous, int(client_id)),
                )
            raise
    backup = _backup_state("client-expiry")
    try:
        with connect() as con:
            con.execute(
                "UPDATE awg_clients SET expires_at=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (normalized, int(client_id)),
            )
        _write_server_config()
        _reload_if_active()
        _reload_egress_if_available()
        return find_awg_client(client_id)
    except Exception:
        _restore_backup(backup)
        raise

def bulk_update_awg_clients(
    client_ids: list[int], *, action: str, expires_at: object | None = None
) -> int:
    """Apply one lifecycle action and synchronize every affected server."""
    _require_root()
    ids = sorted({int(value) for value in client_ids if int(value) > 0})
    if not ids:
        raise ValueError("Выберите хотя бы одного клиента")
    if len(ids) > 512:
        raise ValueError("За одну операцию можно изменить не более 512 клиентов")
    placeholders = ",".join("?" for _ in ids)
    with connect() as con:
        rows = [
            dict(row)
            for row in con.execute(
                f"SELECT * FROM awg_clients WHERE id IN ({placeholders}) ORDER BY id",
                ids,
            ).fetchall()
        ]
    if len(rows) != len(ids):
        raise AWGPanelError("Один или несколько выбранных клиентов не найдены")

    normalized_action = str(action or "").strip().lower()
    backup = _backup_state("clients-bulk")
    remote_by_node: dict[int, list[int]] = {}
    remote_delete_by_node: dict[int, list[int]] = {}
    local_changed = any(not row.get("node_id") for row in rows)
    try:
        with connect() as con:
            if normalized_action == "enable":
                con.execute(
                    f"UPDATE awg_clients SET enabled=1, updated_at=CURRENT_TIMESTAMP WHERE id IN ({placeholders})",
                    ids,
                )
            elif normalized_action == "disable":
                con.execute(
                    f"UPDATE awg_clients SET enabled=0, updated_at=CURRENT_TIMESTAMP WHERE id IN ({placeholders})",
                    ids,
                )
            elif normalized_action == "clear_expiry":
                con.execute(
                    f"UPDATE awg_clients SET expires_at=NULL, updated_at=CURRENT_TIMESTAMP WHERE id IN ({placeholders})",
                    ids,
                )
            elif normalized_action == "set_expiry":
                normalized = normalize_client_expiry(expires_at)
                if normalized is None:
                    raise ValueError("Выберите дату окончания")
                con.execute(
                    f"UPDATE awg_clients SET expires_at=?, updated_at=CURRENT_TIMESTAMP WHERE id IN ({placeholders})",
                    [normalized, *ids],
                )
            elif normalized_action in {"extend_7", "extend_30", "extend_90", "extend_365"}:
                days = int(normalized_action.split("_", 1)[1])
                now = _utc_now()
                for row in rows:
                    current_expiry = _expiry_datetime(row.get("expires_at"))
                    base = current_expiry if current_expiry and current_expiry > now else now
                    value = normalize_client_expiry(base + timedelta(days=days))
                    con.execute(
                        "UPDATE awg_clients SET expires_at=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                        (value, int(row["id"])),
                    )
            elif normalized_action == "delete":
                local_ids = [int(row["id"]) for row in rows if not row.get("node_id")]
                if local_ids:
                    local_placeholders = ",".join("?" for _ in local_ids)
                    con.execute(f"DELETE FROM awg_clients WHERE id IN ({local_placeholders})", local_ids)
                remote_ids = [int(row["id"]) for row in rows if row.get("node_id")]
                if remote_ids:
                    remote_placeholders = ",".join("?" for _ in remote_ids)
                    con.execute(
                        f"UPDATE awg_clients SET enabled=0, deployment_state='deleting', "
                        f"updated_at=CURRENT_TIMESTAMP WHERE id IN ({remote_placeholders})",
                        remote_ids,
                    )
            else:
                raise ValueError("Неизвестное массовое действие")

        for row in rows:
            node_id = int(row.get("node_id") or 0)
            if not node_id:
                continue
            remote_by_node.setdefault(node_id, []).append(int(row["id"]))
            if normalized_action == "delete":
                remote_delete_by_node.setdefault(node_id, []).append(int(row["id"]))

        if local_changed:
            _write_server_config()
            _reload_if_active()
            _reload_egress_if_available()
        if remote_by_node:
            from .node_clients import queue_node_client_sync
            for node_id, target_ids in remote_by_node.items():
                queue_node_client_sync(
                    node_id,
                    target_client_ids=target_ids,
                    delete_client_ids=remote_delete_by_node.get(node_id, []),
                )
        return len(ids)
    except Exception:
        _restore_backup(backup)
        raise

def client_expiry_tick() -> dict[str, object]:
    """Reconcile local and SG-Node peers when time-based access changes."""
    _require_root()
    settings = get_awg_settings()
    clients = list_awg_clients()
    lifecycle = [client_lifecycle(row) for row in clients]
    result = {
        "clients": len(clients),
        "effective": sum(1 for item in lifecycle if item["effective_enabled"]),
        "expired": sum(1 for item in lifecycle if item["expired"]),
        "expiring_soon": sum(1 for item in lifecycle if item["expiring_soon"]),
        "changed": False,
        "remote_jobs": [],
    }

    local_clients = [row for row in clients if not row["node_id"]]
    if bool(settings["configured"]):
        desired = render_awg_server_config()
        current = AWG_CONFIG_PATH.read_text(encoding="utf-8") if AWG_CONFIG_PATH.exists() else ""
        if current != desired:
            backup = _backup_state("client-expiry-tick")
            try:
                _write_server_config()
                _reload_if_active()
                _reload_egress_if_available()
                result["changed"] = True
            except Exception:
                _restore_backup(backup)
                raise

    remote_by_node: dict[int, list[int]] = {}
    for row in clients:
        node_id = int(row["node_id"] or 0)
        if not node_id or str(row["deployment_state"]) in {"queued", "deleting"}:
            continue
        desired_enabled = 1 if client_is_effectively_enabled(row) else 0
        if desired_enabled != int(row["deployed_enabled"] or 0):
            remote_by_node.setdefault(node_id, []).append(int(row["id"]))
    if remote_by_node:
        from .node_clients import queue_node_client_sync
        for node_id, target_ids in remote_by_node.items():
            try:
                job = queue_node_client_sync(node_id, target_client_ids=target_ids)
                result["remote_jobs"].append(int(job["id"]))
                result["changed"] = True
            except (ValueError, AWGPanelError):
                # An offline Node will reconcile on the next maintenance tick.
                continue
    return result

def regenerate_awg_client(client_id: int):
    _require_root()
    current = find_awg_client(client_id)
    if current["node_id"]:
        private_key, public_key = _keypair()
        preshared_key = _psk()
        previous = (current["private_key"], current["public_key"], current["preshared_key"])
        with connect() as con:
            con.execute(
                """
                UPDATE awg_clients
                SET private_key=?, public_key=?, preshared_key=?, deployment_state='queued',
                    deployment_error='', updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (private_key, public_key, preshared_key, int(client_id)),
            )
        try:
            from .node_clients import queue_node_client_sync
            queue_node_client_sync(int(current["node_id"]), target_client_ids=[client_id])
            return find_awg_client(client_id)
        except Exception:
            with connect() as con:
                con.execute(
                    "UPDATE awg_clients SET private_key=?, public_key=?, preshared_key=?, "
                    "deployment_state='active', updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (*previous, int(client_id)),
                )
            raise
    backup = _backup_state("client-regenerate")
    try:
        private_key, public_key = _keypair()
        preshared_key = _psk()
        with connect() as con:
            con.execute(
                """
                UPDATE awg_clients
                SET private_key=?, public_key=?, preshared_key=?,
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (private_key, public_key, preshared_key, client_id),
            )
        _write_server_config()
        _reload_if_active()
        return find_awg_client(client_id)
    except Exception:
        _restore_backup(backup)
        raise

def delete_awg_client(client_id: int):
    _require_root()
    client = find_awg_client(client_id)
    if client["node_id"]:
        with connect() as con:
            con.execute(
                "UPDATE awg_clients SET enabled=0, deployment_state='deleting', "
                "deployment_error='', updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (int(client_id),),
            )
        try:
            from .node_clients import queue_node_client_sync
            queue_node_client_sync(
                int(client["node_id"]),
                target_client_ids=[client_id],
                delete_client_ids=[client_id],
            )
            return client
        except Exception:
            with connect() as con:
                con.execute(
                    "UPDATE awg_clients SET enabled=?, deployment_state='active', "
                    "updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (int(client["enabled"]), int(client_id)),
                )
            raise
    backup = _backup_state("client-delete")
    try:
        with connect() as con:
            con.execute("DELETE FROM awg_clients WHERE id=?", (client_id,))
        _write_server_config()
        _reload_if_active()
        _reload_egress_if_available()
        return client
    except Exception:
        _restore_backup(backup)
        raise

def update_awg_client_traffic(
    client_id: int,
    allowed_ips: str,
    *,
    excluded_ips: str | None = None,
    advertised_networks: str | None = None,
    include_server_lan: bool | None = None,
):
    _require_root()
    current = find_awg_client(client_id)
    settings = get_awg_settings()
    remote = bool(current["node_id"])
    if remote:
        from .node_clients import require_ready_node
        _, runtime = require_ready_node(int(current["node_id"]))
        server_network = str(runtime["server_network"])
        server_lans = ""
        same_server_clients = [
            row for row in list_awg_clients()
            if int(row["node_id"] or 0) == int(current["node_id"])
        ]
    else:
        server_network = str(settings["server_network"])
        server_lans = str(settings["server_lan_networks"])
        same_server_clients = [row for row in list_awg_clients() if not row["node_id"]]

    normalized_allowed = _validate_allowed_ips(allowed_ips)
    normalized_excluded = (
        normalize_networks(excluded_ips, allow_empty=True, field="Исключения")
        if excluded_ips is not None
        else str(current["excluded_ips"])
    )
    if advertised_networks is None:
        normalized_advertised = str(current["advertised_networks"])
    else:
        normalized_advertised = validate_advertised_networks(
            advertised_networks,
            server_network=server_network,
            existing_values=[
                (int(row["id"]), row["advertised_networks"])
                for row in same_server_clients
            ],
            client_id=client_id,
        )
    include_lan = (
        bool(current["include_server_lan"])
        if include_server_lan is None
        else bool(include_server_lan)
    )
    if remote and include_lan:
        raise ValueError("Сети сервера для клиентов SG-Node пока не объявляются автоматически")
    additional = [server_lans] if include_lan and server_lans else []
    if not effective_allowed_ips(normalized_allowed, normalized_excluded, additional):
        raise ValueError("После применения исключений у клиента не осталось маршрутов")

    if remote:
        previous = dict(current)
        with connect() as con:
            con.execute(
                """
                UPDATE awg_clients
                SET allowed_ips=?, excluded_ips=?, advertised_networks=?,
                    include_server_lan=?, deployment_state='queued',
                    deployment_error='', updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (
                    normalized_allowed,
                    normalized_excluded,
                    normalized_advertised,
                    1 if include_lan else 0,
                    client_id,
                ),
            )
        try:
            from .node_clients import queue_node_client_sync
            queue_node_client_sync(int(current["node_id"]), target_client_ids=[client_id])
            return find_awg_client(client_id)
        except Exception:
            with connect() as con:
                con.execute(
                    """
                    UPDATE awg_clients SET allowed_ips=?, excluded_ips=?,
                        advertised_networks=?, include_server_lan=?, deployment_state=?,
                        deployment_error=?, updated_at=CURRENT_TIMESTAMP WHERE id=?
                    """,
                    (
                        previous["allowed_ips"], previous["excluded_ips"],
                        previous["advertised_networks"], previous["include_server_lan"],
                        previous["deployment_state"], previous["deployment_error"],
                        int(client_id),
                    ),
                )
            raise

    backup = _backup_state("client-traffic")
    try:
        with connect() as con:
            con.execute(
                """
                UPDATE awg_clients
                SET allowed_ips=?, excluded_ips=?, advertised_networks=?,
                    include_server_lan=?, updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (
                    normalized_allowed,
                    normalized_excluded,
                    normalized_advertised,
                    1 if include_lan else 0,
                    client_id,
                ),
            )
        _write_server_config()
        _reload_if_active()
        return find_awg_client(client_id)
    except Exception:
        _restore_backup(backup)
        raise


def update_awg_client_settings(
    client_id: int, *, name: str, comment: str, dns_servers: str, mtu: str,
    expires_at: object | None = None,
):
    _require_root()
    current = find_awg_client(client_id)
    normalized_name = name.strip()
    if not AWG_NAME_RE.fullmatch(normalized_name):
        raise ValueError("Имя клиента должно содержать от 1 до 64 обычных символов")
    normalized_dns = ""
    normalized_mtu: int | None = None
    if mtu.strip():
        normalized_mtu = int(mtu)
        if not 576 <= normalized_mtu <= 1500:
            raise ValueError("MTU клиента должен быть от 576 до 1500")
    normalized_expiry = normalize_client_expiry(expires_at)

    if current["node_id"]:
        previous = dict(current)
        try:
            with connect() as con:
                con.execute(
                    """
                    UPDATE awg_clients
                    SET name=?, comment=?, dns_servers=?, mtu=?, expires_at=?,
                        deployment_state='queued', deployment_error='',
                        updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                    """,
                    (
                        normalized_name, comment.strip(), normalized_dns, normalized_mtu,
                        normalized_expiry, int(client_id),
                    ),
                )
            from .node_clients import queue_node_client_sync
            queue_node_client_sync(int(current["node_id"]), target_client_ids=[client_id])
            return find_awg_client(int(client_id))
        except Exception as exc:
            with connect() as con:
                con.execute(
                    """
                    UPDATE awg_clients SET name=?, comment=?, dns_servers=?, mtu=?,
                        expires_at=?, deployment_state=?, deployment_error=?,
                        updated_at=CURRENT_TIMESTAMP WHERE id=?
                    """,
                    (
                        previous["name"], previous["comment"], previous["dns_servers"],
                        previous["mtu"], previous["expires_at"],
                        previous["deployment_state"], previous["deployment_error"],
                        int(client_id),
                    ),
                )
            if "UNIQUE" in str(exc).upper():
                raise AWGPanelError("Клиент с таким именем уже существует") from exc
            raise

    backup = _backup_state("client-settings")
    try:
        with connect() as con:
            con.execute(
                """
                UPDATE awg_clients
                SET name=?, comment=?, dns_servers=?, mtu=?, expires_at=?,
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (normalized_name, comment.strip(), normalized_dns, normalized_mtu,
                 normalized_expiry, client_id),
            )
        _write_server_config()
        _reload_if_active()
        _reload_egress_if_available()
        return find_awg_client(int(current["id"]))
    except Exception as exc:
        _restore_backup(backup)
        if "UNIQUE" in str(exc).upper():
            raise AWGPanelError("Клиент с таким именем уже существует") from exc
        raise



def validate_awg_client_document(
    client_id: int, values: dict[str, object]
) -> dict[str, object]:
    """Validate and normalize every JSON-editable field of one client."""
    find_awg_client(client_id)
    settings = get_awg_settings()

    normalized_name = str(values.get("name", "")).strip()
    if not AWG_NAME_RE.fullmatch(normalized_name):
        raise ValueError("Имя клиента должно содержать от 1 до 64 обычных символов")
    normalized_comment = str(values.get("comment", "")).strip()
    normalized_expiry = normalize_client_expiry(values.get("expires_at"))
    normalized_dns = ""
    mtu_value = values.get("mtu")
    normalized_mtu: int | None = None
    if mtu_value is not None and str(mtu_value).strip():
        normalized_mtu = int(mtu_value)
        if not 576 <= normalized_mtu <= 1500:
            raise ValueError("MTU клиента должен быть от 576 до 1500")

    try:
        address = ipaddress.ip_interface(str(values.get("address", "")).strip())
    except ValueError as exc:
        raise ValueError("Адрес клиента должен быть корректным IPv4-адресом с /32") from exc
    if address.version != 4 or address.network.prefixlen != 32:
        raise ValueError("Адрес клиента должен быть IPv4-адресом с префиксом /32")
    server_network = ipaddress.ip_network(str(settings["server_network"]), strict=True)
    if address.ip not in server_network:
        raise ValueError("Адрес клиента должен входить в сеть AWG Server")
    server_ip = ipaddress.ip_interface(_server_address(settings)).ip
    if address.ip == server_ip:
        raise ValueError("Адрес AWG Server нельзя назначить клиенту")

    normalized_allowed = _validate_allowed_ips(values.get("allowed_ips", ""))
    normalized_excluded = normalize_networks(
        values.get("excluded_ips", ""), allow_empty=True, field="Исключения"
    )
    normalized_advertised = validate_advertised_networks(
        values.get("advertised_networks", ""),
        server_network=str(settings["server_network"]),
        existing_values=[
            (int(row["id"]), row["advertised_networks"])
            for row in list_awg_clients(local_only=True)
        ],
        client_id=client_id,
    )
    include_server_lan = bool(values.get("include_server_lan", False))
    additional = [str(settings["server_lan_networks"])] if include_server_lan else []
    if not effective_allowed_ips(normalized_allowed, normalized_excluded, additional):
        raise ValueError("После применения исключений у клиента не осталось маршрутов")

    egress_mode = normalize_egress_mode(values.get("egress_mode", AWG_GATEWAY))
    outbound_id = values.get("outbound_id")
    selected_outbound: int | None = None
    if egress_mode == "outbound":
        if outbound_id is None:
            raise ValueError("Выберите Outbound-профиль")
        selected_outbound = int(outbound_id)
        with connect() as con:
            outbound = con.execute(
                "SELECT id, enabled FROM outbounds WHERE id=?",
                (selected_outbound,),
            ).fetchone()
        if outbound is None or not bool(outbound["enabled"]):
            raise ValueError("Выбранный Outbound отсутствует или отключён")

    with connect() as con:
        duplicate = con.execute(
            "SELECT id FROM awg_clients WHERE address=? AND id<>?",
            (str(address), int(client_id)),
        ).fetchone()
    if duplicate is not None:
        raise AWGPanelError("Этот внутренний IP уже назначен другому клиенту")

    return {
        "name": normalized_name,
        "enabled": bool(values.get("enabled", True)),
        "address": str(address),
        "comment": normalized_comment,
        "expires_at": normalized_expiry,
        "dns_servers": normalized_dns,
        "mtu": normalized_mtu,
        "access_enabled": bool(values.get("access_enabled", True)),
        "allowed_ips": normalized_allowed,
        "excluded_ips": normalized_excluded,
        "advertised_networks": normalized_advertised,
        "include_server_lan": include_server_lan,
        "egress_mode": egress_mode,
        "outbound_id": selected_outbound,
    }


def update_awg_client_document(client_id: int, values: dict[str, object]):
    """Atomically update every JSON-editable field of one client."""
    _require_root()
    current = find_awg_client(client_id)
    normalized = validate_awg_client_document(client_id, values)
    backup = _backup_state("client-json")
    try:
        with connect() as con:
            con.execute(
                """
                UPDATE awg_clients
                SET name=?, enabled=?, address=?, comment=?, expires_at=?, dns_servers=?, mtu=?,
                    access_enabled=?, allowed_ips=?, excluded_ips=?,
                    advertised_networks=?, include_server_lan=?, egress_mode=?,
                    outbound_id=?, updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (
                    normalized["name"],
                    1 if normalized["enabled"] else 0,
                    normalized["address"],
                    normalized["comment"],
                    normalized["expires_at"],
                    normalized["dns_servers"],
                    normalized["mtu"],
                    1 if normalized["access_enabled"] else 0,
                    normalized["allowed_ips"],
                    normalized["excluded_ips"],
                    normalized["advertised_networks"],
                    1 if normalized["include_server_lan"] else 0,
                    normalized["egress_mode"],
                    normalized["outbound_id"],
                    int(client_id),
                ),
            )
        _write_server_config()
        _reload_if_active()
        _reload_egress_if_available()
        return find_awg_client(int(current["id"]))
    except Exception as exc:
        _restore_backup(backup)
        if "UNIQUE" in str(exc).upper():
            raise AWGPanelError("Клиент с таким именем или адресом уже существует") from exc
        raise


def validate_traffic_document(
    settings_values: dict[str, object], client_values: list[dict[str, object]]
) -> tuple[str, str, list[dict[str, object]]]:
    """Validate and normalize the complete Network JSON document."""
    current_settings = get_awg_settings()
    normalized_interface = str(settings_values.get("external_interface", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", normalized_interface):
        raise ValueError("Укажите внешний сетевой интерфейс, например eth0 или ens5")
    normalized_server_lans = normalize_networks(
        settings_values.get("server_lan_networks", ""),
        allow_empty=True,
        field="Сети сервера",
    )

    existing_clients = list_awg_clients(local_only=True)
    expected_ids = {int(row["id"]) for row in existing_clients}
    supplied_ids = {int(item["id"]) for item in client_values}
    if supplied_ids != expected_ids:
        missing = sorted(expected_ids - supplied_ids)
        unknown = sorted(supplied_ids - expected_ids)
        details: list[str] = []
        if missing:
            details.append("не указаны ID: " + ", ".join(map(str, missing)))
        if unknown:
            details.append("неизвестные ID: " + ", ".join(map(str, unknown)))
        raise ValueError(
            "Network JSON должен содержать всех текущих клиентов; " + "; ".join(details)
        )

    with connect() as con:
        enabled_outbounds = {
            int(row["id"])
            for row in con.execute(
                "SELECT id FROM outbounds WHERE enabled=1"
            ).fetchall()
        }

    normalized_clients: list[dict[str, object]] = []
    planned_advertised: list[tuple[int, str]] = []
    for item in client_values:
        client_id = int(item["id"])
        allowed = _validate_allowed_ips(item.get("allowed_ips", ""))
        excluded = normalize_networks(
            item.get("excluded_ips", ""), allow_empty=True, field="Исключения"
        )
        advertised = validate_advertised_networks(
            item.get("advertised_networks", ""),
            server_network=str(current_settings["server_network"]),
            existing_values=planned_advertised,
            client_id=client_id,
        )
        planned_advertised.append((client_id, advertised))
        include_lan = bool(item.get("include_server_lan", False))
        additional = [normalized_server_lans] if include_lan else []
        if not effective_allowed_ips(allowed, excluded, additional):
            raise ValueError(
                f"После применения исключений у клиента #{client_id} не осталось маршрутов"
            )
        mode = normalize_egress_mode(item.get("egress_mode", AWG_GATEWAY))
        outbound_id = item.get("outbound_id")
        selected: int | None = None
        if mode == "outbound":
            if outbound_id is None or int(outbound_id) not in enabled_outbounds:
                raise ValueError(
                    f"Клиент #{client_id}: выбранный Outbound отсутствует или отключён"
                )
            selected = int(outbound_id)
        normalized_clients.append(
            {
                "id": client_id,
                "allowed_ips": allowed,
                "excluded_ips": excluded,
                "advertised_networks": advertised,
                "include_server_lan": include_lan,
                "egress_mode": mode,
                "outbound_id": selected,
            }
        )
    return normalized_interface, normalized_server_lans, normalized_clients


def update_traffic_document(
    settings_values: dict[str, object], client_values: list[dict[str, object]]
) -> dict[str, object]:
    """Replace all traffic settings and client assignments as one operation."""
    _require_root()
    normalized_interface, normalized_server_lans, normalized_clients = (
        validate_traffic_document(settings_values, client_values)
    )
    backup = _backup_state("traffic-json")
    try:
        with connect() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                """
                UPDATE awg_settings
                SET isolate_clients=?, nat_enabled=?, external_interface=?,
                    server_lan_networks=?, updated_at=CURRENT_TIMESTAMP
                WHERE id=1
                """,
                (
                    1 if bool(settings_values.get("isolate_clients", True)) else 0,
                    1 if bool(settings_values.get("nat_enabled", True)) else 0,
                    normalized_interface,
                    normalized_server_lans,
                ),
            )
            for item in normalized_clients:
                con.execute(
                    """
                    UPDATE awg_clients
                    SET allowed_ips=?, excluded_ips=?, advertised_networks=?,
                        include_server_lan=?, egress_mode=?, outbound_id=?,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                    """,
                    (
                        item["allowed_ips"], item["excluded_ips"],
                        item["advertised_networks"],
                        1 if item["include_server_lan"] else 0,
                        item["egress_mode"], item["outbound_id"], item["id"],
                    ),
                )
        _write_server_config()
        _reload_if_active()
        _reload_egress_if_available()
        return {
            "settings": get_awg_settings(),
            "clients": list_awg_clients(local_only=True),
        }
    except Exception:
        _restore_backup(backup)
        raise


def update_traffic_settings(
    *,
    isolate_clients: bool,
    nat_enabled: bool | None = None,
    external_interface: str | None = None,
    server_lan_networks: str | None = None,
):
    _require_root()
    current = get_awg_settings()
    normalized_interface = (
        str(current["external_interface"])
        if external_interface is None
        else str(external_interface).strip()
    )
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", normalized_interface):
        raise ValueError("Укажите внешний сетевой интерфейс, например eth0 или ens5")
    normalized_server_lans = (
        str(current["server_lan_networks"])
        if server_lan_networks is None
        else normalize_networks(
            server_lan_networks,
            allow_empty=True,
            field="Сети сервера",
        )
    )
    nat_value = bool(current["nat_enabled"]) if nat_enabled is None else bool(nat_enabled)
    backup = _backup_state("traffic-settings")
    try:
        with connect() as con:
            con.execute(
                """
                UPDATE awg_settings
                SET isolate_clients=?, nat_enabled=?, external_interface=?,
                    server_lan_networks=?, updated_at=CURRENT_TIMESTAMP
                WHERE id=1
                """,
                (
                    1 if isolate_clients else 0,
                    1 if nat_value else 0,
                    normalized_interface,
                    normalized_server_lans,
                ),
            )
        _write_server_config()
        _reload_if_active()
        return get_awg_settings()
    except Exception:
        _restore_backup(backup)
        raise


def update_dns_servers(dns_servers: str):
    _require_root()
    normalized = _validate_dns_servers(dns_servers)
    backup = _backup_state("dns-settings")
    try:
        with connect() as con:
            con.execute(
                "UPDATE awg_settings SET dns_servers=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
                (normalized,),
            )
        return get_awg_settings()
    except Exception:
        _restore_backup(backup)
        raise


def configure_access_links(*, enabled: bool, profile_title: str):
    _require_root()
    title = str(profile_title or "").strip()
    if not title:
        raise ValueError("Укажите название профиля доступа")
    if len(title) > 80:
        raise ValueError("Название профиля доступа должно содержать не более 80 символов")
    if any(ord(ch) < 32 for ch in title):
        raise ValueError("Название профиля доступа содержит недопустимые символы")
    with connect() as con:
        con.execute(
            """
            UPDATE panel_settings
            SET access_enabled=?, access_profile_title=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=1
            """,
            (1 if enabled else 0, title),
        )
    return get_panel_settings()


def set_client_access_enabled(client_id: int, enabled: bool):
    _require_root()
    find_awg_client(client_id)
    with connect() as con:
        con.execute(
            "UPDATE awg_clients SET access_enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (1 if enabled else 0, client_id),
        )
    return find_awg_client(client_id)


def configure_access_document(*, enabled: bool, profile_title: str, client_states: dict[int, bool]):
    _require_root()
    title = str(profile_title or "").strip()
    if not title:
        raise ValueError("Укажите название профиля доступа")
    if len(title) > 80:
        raise ValueError("Название профиля доступа должно содержать не более 80 символов")
    if any(ord(ch) < 32 for ch in title):
        raise ValueError("Название профиля доступа содержит недопустимые символы")
    with connect() as con:
        current_ids = {int(row[0]) for row in con.execute("SELECT id FROM awg_clients")}
        if current_ids != set(client_states):
            raise ValueError("JSON доступа должен содержать полный текущий список клиентов")
        con.execute(
            """
            UPDATE panel_settings
            SET access_enabled=?, access_profile_title=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=1
            """,
            (1 if enabled else 0, title),
        )
        for client_id, state in client_states.items():
            con.execute(
                "UPDATE awg_clients SET access_enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (1 if state else 0, int(client_id)),
            )
    return get_panel_settings()


def regenerate_client_access_token(client_id: int):
    _require_root()
    find_awg_client(client_id)
    with connect() as con:
        con.execute(
            "UPDATE awg_clients SET access_token=?, access_downloads=0, access_last_at=NULL, "
            "access_enabled=1, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (secrets.token_urlsafe(24), client_id),
        )
    return find_awg_client(client_id)


def find_client_by_access_token(token: str):
    init_db()
    if not token or len(token) > 256:
        raise AWGPanelError("Ссылка доступа недействительна")
    with connect() as con:
        row = con.execute(
            f"SELECT * FROM awg_clients WHERE access_token=? AND access_enabled=1 AND {ACTIVE_CLIENT_SQL}",
            (token,),
        ).fetchone()
    if row is None:
        raise AWGPanelError("Ссылка доступа недействительна или отключена")
    return row


def record_client_access(client_id: int) -> None:
    with connect() as con:
        con.execute(
            "UPDATE awg_clients SET access_downloads=access_downloads+1, "
            "access_last_at=CURRENT_TIMESTAMP WHERE id=?",
            (client_id,),
        )


def create_manual_backup() -> Path:
    return _backup_state("manual")


def restore_backup(name: str) -> Path:
    _require_root()
    backup = find_backup_path(name)
    verification = _verify_backup_path(backup, update_metadata=True)
    if not verification["verified"]:
        raise AWGPanelError(
            "Резервная копия не прошла проверку: "
            + "; ".join(str(item) for item in verification["verification_errors"])
        )
    safety = _backup_state("before-restore")
    try:
        _restore_backup(backup)
        if get_awg_settings()["configured"]:
            _write_server_config()
            _reload_if_active()
        return backup
    except Exception:
        _restore_backup(safety)
        raise


def _service_action(action: str) -> str:
    _require_root()
    if action not in {"start", "stop", "restart"}:
        raise ValueError("Недопустимое действие службы")
    result = _run(["systemctl", action, AWG_SERVICE], timeout=30)
    if result.returncode != 0:
        raise AWGPanelError(result.stderr.strip() or result.stdout.strip() or f"systemctl {action} завершился ошибкой")
    return awg_service_state()


def start_awg() -> str:
    if not AWG_CONFIG_PATH.exists():
        _write_server_config()
    return _service_action("start")


def stop_awg() -> str:
    return _service_action("stop")


def restart_awg() -> str:
    _write_server_config()
    return _service_action("restart")


def _reload_if_active() -> None:
    if awg_service_state() == "active":
        restart_awg()


def _reload_egress_if_available(*, strict: bool = True) -> None:
    if not _command_path("nft") or not _command_path("ip"):
        return
    from .egress import apply_egress_runtime

    try:
        apply_egress_runtime()
    except Exception:
        if strict:
            raise


def awg_service_state() -> str:
    result = _run(["systemctl", "is-active", AWG_SERVICE])
    return result.stdout.strip() or "inactive"


def _peer_stats() -> dict[str, dict[str, int]]:
    settings = get_awg_settings()
    if not settings["configured"] or not _command_path("awg"):
        return {}
    result = _run(["awg", "show", settings["interface_name"], "dump"])
    if result.returncode != 0:
        return {}
    stats: dict[str, dict[str, int]] = {}
    lines = result.stdout.splitlines()[1:]
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        try:
            stats[parts[0]] = {
                "latest_handshake": int(parts[4] or 0),
                "rx": int(parts[5] or 0),
                "tx": int(parts[6] or 0),
            }
        except ValueError:
            continue
    return stats


def _format_handshake(timestamp: int) -> str:
    if timestamp <= 0:
        return "—"
    moment = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    age = max(0, int(time.time()) - timestamp)
    if age < 60:
        age_text = f"{age} с назад"
    elif age < 3600:
        age_text = f"{age // 60} мин назад"
    elif age < 86400:
        age_text = f"{age // 3600} ч назад"
    else:
        age_text = f"{age // 86400} дн назад"
    return f"{moment:%Y-%m-%d %H:%M UTC} · {age_text}"


def _directory_size(path: Path) -> int:
    total = 0
    try:
        for item in path.rglob("*"):
            try:
                if item.is_file() and not item.is_symlink():
                    total += item.stat().st_size
            except OSError:
                continue
    except OSError:
        return 0
    return total


def _system_uptime() -> tuple[int, str]:
    seconds = 0
    try:
        seconds = max(0, int(float(Path("/proc/uptime").read_text(encoding="ascii").split()[0])))
    except (OSError, ValueError, IndexError):
        pass
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    if days:
        text = f"{days} д. {hours} ч. {minutes} мин."
    elif hours:
        text = f"{hours} ч. {minutes} мин."
    else:
        text = f"{minutes} мин."
    return seconds, text


def _os_information() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    except OSError:
        pass
    kernel = ""
    try:
        kernel = os.uname().release
    except OSError:
        pass
    return {
        "name": values.get("PRETTY_NAME") or values.get("NAME") or "Linux",
        "version": values.get("VERSION_ID", ""),
        "kernel": kernel,
    }



def _read_positive_integer(path: Path) -> int:
    try:
        value = path.read_text(encoding="ascii").strip()
        if not value or value == "max":
            return 0
        return max(0, int(value))
    except (OSError, ValueError):
        return 0


def _service_memory_snapshot(service: str) -> dict[str, int]:
    """Return cgroup-v2 memory for a complete systemd service.

    MemoryCurrent includes the service and all child processes.  The cgroup
    memory.stat split lets the global memory dial avoid counting a service's
    file cache and kernel allocations twice.  Older/non-systemd environments
    fall back to the main process RSS.
    """
    snapshot = {
        "current": 0,
        "peak": 0,
        "anon": 0,
        "file": 0,
        "kernel": 0,
        "shmem": 0,
    }
    try:
        result = _run(
            ["systemctl", "show", service, "-p", "ControlGroup", "--value"],
            timeout=5,
        )
        control_group = result.stdout.strip() if result.returncode == 0 else ""
    except (AWGPanelError, OSError):
        control_group = ""
    if control_group and control_group != "/":
        cgroup = Path("/sys/fs/cgroup") / control_group.lstrip("/")
        snapshot["current"] = _read_positive_integer(cgroup / "memory.current")
        snapshot["peak"] = _read_positive_integer(cgroup / "memory.peak")
        try:
            for line in (cgroup / "memory.stat").read_text(encoding="ascii").splitlines():
                key, raw = line.split(None, 1)
                if key in snapshot:
                    snapshot[key] = max(0, int(raw))
        except (OSError, ValueError):
            pass
        if snapshot["current"]:
            if not snapshot["peak"]:
                snapshot["peak"] = snapshot["current"]
            return snapshot

    # Portable fallback for tests, cgroup v1, or disabled memory accounting.
    try:
        pid = _service_main_pid(service)
    except (AWGPanelError, OSError):
        pid = 0
    rss = _process_rss(pid)
    snapshot.update(current=rss, peak=rss, anon=rss)
    return snapshot


def _memory_status(used_percent: float, swap_used: int) -> tuple[str, str]:
    if swap_used > 0 or used_percent >= 95:
        return "critical", "Критическая нагрузка"
    if used_percent >= 85:
        return "high", "Памяти осталось мало"
    if used_percent >= 70:
        return "warning", "Нагрузка повышена"
    return "normal", "Память в норме"


def _build_memory_breakdown(
    values: dict[str, int],
    panel: dict[str, int],
    nginx: dict[str, int],
) -> dict[str, object]:
    """Build mutually exclusive, total-sized sectors for the memory dial."""
    kib = 1024
    total = max(0, values.get("MemTotal", 0) * kib)
    free = max(0, values.get("MemFree", 0) * kib)
    available = max(0, values.get("MemAvailable", 0) * kib)
    swap_total = max(0, values.get("SwapTotal", 0) * kib)
    swap_free = max(0, values.get("SwapFree", 0) * kib)
    swap_used = max(0, swap_total - swap_free)

    global_cache = max(
        0,
        (
            values.get("Cached", 0)
            + values.get("Buffers", 0)
            + values.get("SReclaimable", 0)
            - values.get("Shmem", 0)
        )
        * kib,
    )
    global_kernel = max(
        0,
        (
            values.get("SUnreclaim", 0)
            + values.get("KernelStack", 0)
            + values.get("PageTables", 0)
            + values.get("Percpu", 0)
        )
        * kib,
    )

    panel_current = min(total, max(0, int(panel.get("current", 0))))
    nginx_current = min(max(0, total - panel_current), max(0, int(nginx.get("current", 0))))
    service_file = max(0, int(panel.get("file", 0))) + max(0, int(nginx.get("file", 0)))
    service_kernel = max(0, int(panel.get("kernel", 0))) + max(0, int(nginx.get("kernel", 0)))
    cache = max(0, global_cache - service_file)
    kernel = max(0, global_kernel - service_kernel)

    # Keep the visual sectors strictly additive even when kernel/cgroup
    # accounting differs slightly across Linux versions.
    fixed = panel_current + nginx_current + free
    remaining = max(0, total - fixed)
    cache = min(cache, remaining)
    remaining -= cache
    kernel = min(kernel, remaining)
    remaining -= kernel
    other = remaining

    raw_segments = [
        ("panel", "SG-AWG-Panel", panel_current),
        ("nginx", "Nginx", nginx_current),
        ("kernel", "Ядро Linux и сеть", kernel),
        ("other", "ОС и остальные процессы", other),
        ("cache", "Файловый кэш", cache),
        ("free", "Свободно", free),
    ]
    cumulative = 0.0
    segments: list[dict[str, object]] = []
    for key, label, value in raw_segments:
        percent = round((value / total * 100), 1) if total else 0.0
        start = cumulative
        cumulative += (value / total * 100) if total else 0.0
        segments.append(
            {
                "key": key,
                "label": label,
                "bytes": value,
                "percent": percent,
                "start_percent": round(start, 4),
                "end_percent": round(cumulative, 4),
            }
        )
    if segments and total:
        segments[-1]["end_percent"] = 100.0

    used = max(0, total - available)
    used_percent = round((used / total * 100), 1) if total else 0.0
    available_percent = round((available / total * 100), 1) if total else 0.0
    status_class, status_label = _memory_status(used_percent, swap_used)
    return {
        "total": total,
        "used": used,
        "available": available,
        "free": free,
        "used_percent": used_percent,
        "available_percent": available_percent,
        "swap_total": swap_total,
        "swap_used": swap_used,
        "status_class": status_class,
        "status_label": status_label,
        "segments": segments,
        "panel_current": panel_current,
        "panel_peak": max(panel_current, int(panel.get("peak", 0))),
        "nginx_current": nginx_current,
        "nginx_peak": max(nginx_current, int(nginx.get("peak", 0))),
        "method": (
            "Панель и Nginx считаются по их systemd cgroup вместе с дочерними "
            "процессами. Ядро и файловый кэш берутся из /proc/meminfo. "
            "Доступная память соответствует MemAvailable."
        ),
    }


def _system_resources() -> dict[str, object]:
    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = 0.0
    cpu_count = max(1, int(os.cpu_count() or 1))
    cpu_percent = round(min(100.0, max(0.0, load1 / cpu_count * 100)), 1)
    total_kib = available_kib = 0
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, raw = line.split(":", 1)
            values[key] = int(raw.strip().split()[0])
        total_kib = values.get("MemTotal", 0)
        available_kib = values.get("MemAvailable", 0)
    except (OSError, ValueError, IndexError):
        values = {}
    used_kib = max(0, total_kib - available_kib)
    memory_percent = round((used_kib / total_kib * 100), 1) if total_kib else 0.0
    panel_memory = _service_memory_snapshot("sg-awg-panel.service")
    nginx_memory = _service_memory_snapshot("nginx.service")
    memory_breakdown = _build_memory_breakdown(values, panel_memory, nginx_memory)
    try:
        disk = shutil.disk_usage("/")
        disk_total = int(disk.total)
        disk_used = int(disk.used)
        disk_free = int(disk.free)
    except OSError:
        disk_total = disk_used = disk_free = 0
    disk_percent = round((disk_used / disk_total * 100), 1) if disk_total else 0.0
    uptime_seconds, uptime_text = _system_uptime()
    data_dir = Path(os.environ.get("AWGPANEL_DATA_DIR", "/var/lib/sg-awg-panel"))
    return {
        "cpu_count": cpu_count,
        "cpu_percent": cpu_percent,
        "load1": round(load1, 2),
        "load5": round(load5, 2),
        "load15": round(load15, 2),
        "memory_total": total_kib * 1024,
        "memory_used": used_kib * 1024,
        "memory_available": available_kib * 1024,
        "memory_percent": memory_percent,
        "memory": memory_breakdown,
        "disk_total": disk_total,
        "disk_used": disk_used,
        "disk_free": disk_free,
        "disk_percent": disk_percent,
        "uptime_seconds": uptime_seconds,
        "uptime_text": uptime_text,
        "database_size": db.DB_PATH.stat().st_size if db.DB_PATH.exists() else 0,
        "backup_size": _directory_size(BACKUP_DIR),
        "panel_data_size": _directory_size(data_dir),
        "os": _os_information(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def get_system_resources() -> dict[str, object]:
    """Return current host resources without collecting journals or network diagnostics."""
    return _system_resources()


def _format_bytes(size: int) -> str:
    if size <= 0:
        return "0 KB"
    power = 1024.0
    n = 0
    units = ["KB", "MB", "GB", "TB"]
    size = float(size) / power
    while size >= power and n < len(units) - 1:
        size /= power
        n += 1
    if n == 0:
        return f"{int(size)} KB"
    return f"{size:.1f} {units[n]}"


def _service_main_pid(service: str) -> int:
    result = _run(["systemctl", "show", "-p", "MainPID", "--value", service])
    try:
        return int(result.stdout.strip() or 0)
    except ValueError:
        return 0


def _process_rss(pid: int) -> int:
    if pid <= 0:
        return 0
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _udp_listener(listen_port: int) -> dict[str, object]:
    ss = _command_path("ss")
    if not ss:
        return {"listening": False, "lines": [], "error": "Команда ss не найдена"}
    result = _run([ss, "-H", "-lunp"], timeout=10)
    if result.returncode != 0:
        return {
            "listening": False,
            "lines": [],
            "error": result.stderr.strip() or "Не удалось проверить UDP-порт",
        }
    marker = f":{listen_port}"
    lines = [line for line in result.stdout.splitlines() if marker in line]
    return {"listening": bool(lines), "lines": lines, "error": ""}


def _service_logs(service: str, lines: int = 80) -> str:
    journalctl = _command_path("journalctl")
    if not journalctl:
        return "journalctl не найден"
    result = _run(
        [journalctl, "-u", service, "-n", str(lines), "--no-pager", "--output=short-iso"],
        timeout=15,
    )
    text = result.stdout.strip() or result.stderr.strip()
    return text[-24_000:] if text else "Журнал пока пуст."




def _systemctl_enabled(service: str) -> bool:
    result = _run(["systemctl", "is-enabled", service], timeout=10)
    return result.returncode == 0 and result.stdout.strip() in {"enabled", "static", "indirect"}


def _service_uptime(service: str) -> str:
    result = _run(
        ["systemctl", "show", service, "-p", "ActiveEnterTimestampMonotonic", "--value"],
        timeout=10,
    )
    try:
        started = int(result.stdout.strip() or 0) / 1_000_000
    except ValueError:
        return "—"
    if started <= 0:
        return "—"
    age = max(0, int(time.monotonic() - started))
    days, remainder = divmod(age, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    if days:
        return f"{days} д {hours} ч"
    if hours:
        return f"{hours} ч {minutes} мин"
    return f"{minutes} мин"


def _ip_forward_enabled() -> bool:
    try:
        return Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="ascii").strip() == "1"
    except OSError:
        return False


def _nat_rule_present(settings) -> bool:
    iptables = _command_path("iptables")
    if not iptables or not settings["configured"]:
        return False
    result = _run(
        [
            iptables, "-t", "nat", "-C", "POSTROUTING",
            "-s", str(settings["server_network"]),
            "-o", str(settings["external_interface"]),
            "-j", "MASQUERADE",
        ],
        timeout=10,
    )
    return result.returncode == 0


def _redact_diagnostic_text(text: str) -> str:
    redacted = re.sub(
        r"(?im)^(PrivateKey|PresharedKey|PublicKey)\s*=\s*.+$",
        r"\1 = [REDACTED]",
        text,
    )
    redacted = re.sub(r"(?i)(/a/)[A-Za-z0-9_-]{16,}", r"\1[REDACTED]", redacted)
    return redacted[-16_000:]


def build_diagnostic_report() -> str:
    diagnostics = get_awg_diagnostics()
    resources = diagnostics["resources"]
    lines = [
        "SG-AWG-Panel diagnostic report",
        f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        "",
        f"AWG service: {diagnostics['service_state']}",
        f"AWG enabled at boot: {diagnostics['awg_enabled']}",
        f"AWG uptime: {diagnostics['awg_uptime']}",
        f"Panel service: {diagnostics['panel_state']}",
        f"Panel enabled at boot: {diagnostics['panel_enabled']}",
        f"Panel uptime: {diagnostics['panel_uptime']}",
        f"Panel RSS: {diagnostics['panel_rss_text']}",
        f"Nginx state: {diagnostics.get('nginx_state', 'unknown')}",
        f"Nginx enabled at boot: {diagnostics.get('nginx_enabled', False)}",
        f"Recovery service: {diagnostics.get('recovery_state', 'unknown')}",
        f"Recovery enabled at boot: {diagnostics.get('recovery_enabled', False)}",
        f"Traffic Rules service: {diagnostics.get('traffic_state', 'unknown')}",
        f"Traffic Rules enabled at boot: {diagnostics.get('traffic_enabled', False)}",
        f"Traffic Rules nftables ready: {diagnostics.get('traffic', {}).get('nft_ready', False)}",
        f"Traffic Rules active outbounds: {diagnostics.get('traffic', {}).get('active_profiles', 0)}",
        f"Backend loopback only: {diagnostics.get('backend', {}).get('loopback_only', False)}",
        f"Kernel module loaded: {diagnostics['module_loaded']}",
        f"AWG tools installed: {diagnostics['installed']}",
        f"Interface present: {diagnostics['interface_present']}",
        f"UDP {diagnostics['listen_port']} listening: {diagnostics['udp']['listening']}",
        f"IPv4 forwarding: {diagnostics['ip_forward']}",
        f"NAT masquerade rule: {diagnostics['nat_rule']}",
        f"Boot persistence ready: {diagnostics['boot_ready']}",
        f"Public IPv4: {diagnostics['public_ipv4'] or 'unknown'}",
        f"External interface: {diagnostics['external_interface'] or 'unknown'}",
        f"System memory used: {resources['memory_percent']}%",
        f"Load average: {resources['load1']} / {resources['load5']} / {resources['load15']}",
        f"Config exists: {diagnostics['config_exists']}",
        f"Config path: {diagnostics['config_path']}",
        f"Backups: {len(diagnostics['backups'])}",
        "",
        "--- sg-awg-server journal ---",
        _redact_diagnostic_text(str(diagnostics['server_logs'])),
        "",
        "--- sg-awg-panel journal ---",
        _redact_diagnostic_text(str(diagnostics['panel_logs'])),
        "",
        "--- sg-awg-traffic journal ---",
        _redact_diagnostic_text(str(diagnostics.get('traffic_logs', ''))),
        "",
    ]
    return "\n".join(lines)


def _tcp_listener(port: int) -> dict[str, object]:
    ss = _command_path("ss")
    if not ss:
        return {"listening": False, "loopback_only": False, "lines": []}
    result = _run([ss, "-H", "-ltnp"], timeout=10)
    marker = f":{port}"
    lines = [line for line in result.stdout.splitlines() if marker in line]
    loopback_only = bool(lines) and all(
        ("127.0.0.1:" in line or "[::1]:" in line or "::1:" in line) for line in lines
    )
    return {"listening": bool(lines), "loopback_only": loopback_only, "lines": lines}


def get_awg_diagnostics() -> dict[str, object]:
    settings = get_awg_settings()
    panel_settings = get_panel_settings()
    state = awg_service_state()
    panel_state = _run(["systemctl", "is-active", "sg-awg-panel"]).stdout.strip() or "inactive"
    nginx_state = _run(["systemctl", "is-active", "nginx"]).stdout.strip() or "inactive"
    recovery_state = _run(["systemctl", "is-active", "sg-awg-recovery"]).stdout.strip() or "inactive"
    traffic_state = _run(["systemctl", "is-active", "sg-awg-traffic"]).stdout.strip() or "inactive"
    panel_pid = _service_main_pid("sg-awg-panel")
    panel_rss = _process_rss(panel_pid)
    listen_port = int(settings["listen_port"] or 585)
    backend_port = int(panel_settings["backend_port"] or 18080)
    panel_enabled = _systemctl_enabled("sg-awg-panel")
    awg_enabled = _systemctl_enabled(AWG_SERVICE)
    nginx_enabled = _systemctl_enabled("nginx")
    recovery_enabled = _systemctl_enabled("sg-awg-recovery")
    traffic_enabled = _systemctl_enabled("sg-awg-traffic")
    ip_forward = _ip_forward_enabled()
    nat_rule = _nat_rule_present(settings)
    config_exists = AWG_CONFIG_PATH.exists()
    interface_present = Path(f"/sys/class/net/{settings['interface_name']}").exists()
    udp = _udp_listener(listen_port)
    backend = _tcp_listener(backend_port)
    from .egress import traffic_runtime_status

    traffic = traffic_runtime_status()
    boot_ready = bool(
        panel_enabled and awg_enabled and nginx_enabled and recovery_enabled
        and traffic_enabled and traffic_state in {"active", "activating"}
        and config_exists and ip_forward and backend["loopback_only"]
    )
    return {
        "service_state": state,
        "panel_state": panel_state,
        "nginx_state": nginx_state,
        "recovery_state": recovery_state,
        "traffic_state": traffic_state,
        "panel_enabled": panel_enabled,
        "awg_enabled": awg_enabled,
        "nginx_enabled": nginx_enabled,
        "recovery_enabled": recovery_enabled,
        "traffic_enabled": traffic_enabled,
        "panel_uptime": _service_uptime("sg-awg-panel"),
        "awg_uptime": _service_uptime(AWG_SERVICE),
        "module_loaded": Path("/sys/module/amneziawg").exists(),
        "installed": bool(_command_path("awg") and _command_path("awg-quick")),
        "interface_present": interface_present,
        "external_interface": detect_external_interface(),
        "public_ipv4": detect_public_ipv4(force=True),
        "udp": udp,
        "backend": backend,
        "backend_port": backend_port,
        "listen_port": listen_port,
        "config_path": str(AWG_CONFIG_PATH),
        "config_exists": config_exists,
        "ip_forward": ip_forward,
        "nat_rule": nat_rule,
        "boot_ready": boot_ready,
        "panel_pid": panel_pid,
        "panel_rss": panel_rss,
        "panel_rss_text": _format_bytes(panel_rss),
        "resources": _system_resources(),
        "server_logs": _service_logs(AWG_SERVICE),
        "panel_logs": _service_logs("sg-awg-panel"),
        "nginx_logs": _service_logs("nginx"),
        "recovery_logs": _service_logs("sg-awg-recovery"),
        "traffic_logs": _service_logs("sg-awg-traffic"),
        "traffic": traffic,
        "backups": list_backups(),
        "panel_settings": panel_settings,
    }



def get_client_period_stats(client_id: int) -> dict[str, str]:
    """Возвращает статистику трафика клиента за день, неделю, месяц и всё время."""
    import datetime
    now = datetime.datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    week_str = (now - datetime.timedelta(days=7)).strftime("%Y-%m-%d")
    month_str = (now - datetime.timedelta(days=30)).strftime("%Y-%m-%d")

    stats = {
        "day_rx": 0, "day_tx": 0, "week_rx": 0, "week_tx": 0,
        "month_rx": 0, "month_tx": 0, "all_rx": 0, "all_tx": 0
    }
    try:
        with connect() as con:
            row = con.execute("SELECT SUM(rx_bytes), SUM(tx_bytes) FROM awg_traffic_history WHERE client_id = ? AND date_str = ?", (client_id, today_str)).fetchone()
            if row and row[0]: stats["day_rx"], stats["day_tx"] = row[0], row[1]
            row = con.execute("SELECT SUM(rx_bytes), SUM(tx_bytes) FROM awg_traffic_history WHERE client_id = ? AND date_str >= ?", (client_id, week_str)).fetchone()
            if row and row[0]: stats["week_rx"], stats["week_tx"] = row[0], row[1]
            row = con.execute("SELECT SUM(rx_bytes), SUM(tx_bytes) FROM awg_traffic_history WHERE client_id = ? AND date_str >= ?", (client_id, month_str)).fetchone()
            if row and row[0]: stats["month_rx"], stats["month_tx"] = row[0], row[1]
            row = con.execute("SELECT SUM(rx_bytes), SUM(tx_bytes) FROM awg_traffic_history WHERE client_id = ?", (client_id,)).fetchone()
            if row and row[0]: stats["all_rx"], stats["all_tx"] = row[0], row[1]
    except Exception:
        pass

    return {
        "day_rx_text": _format_bytes(stats["day_rx"]),
        "day_tx_text": _format_bytes(stats["day_tx"]),
        "week_rx_text": _format_bytes(stats["week_rx"]),
        "week_tx_text": _format_bytes(stats["week_tx"]),
        "month_rx_text": _format_bytes(stats["month_rx"]),
        "month_tx_text": _format_bytes(stats["month_tx"]),
        "all_rx_text": _format_bytes(stats["all_rx"]),
        "all_tx_text": _format_bytes(stats["all_tx"]),
    }

def get_client_traffic_history(client_id: int, days: int = 30) -> dict[str, str]:
    """Возвращает историю трафика для конкретного клиента для графиков."""
    import datetime
    import json
    now = datetime.datetime.now()
    date_from = (now - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
    
    labels = []
    rx = []
    tx = []
    try:
        with connect() as con:
            rows = con.execute(
                "SELECT date_str, rx_bytes, tx_bytes FROM awg_traffic_history WHERE client_id = ? AND date_str >= ? ORDER BY date_str ASC", 
                (client_id, date_from)
            ).fetchall()
            for r in rows:
                labels.append(r[0])
                rx.append(r[1])
                tx.append(r[2])
    except Exception:
        pass
        
    return {
        "labels": json.dumps(labels),
        "rx": json.dumps(rx),
        "tx": json.dumps(tx)
    }

def get_awg_overview() -> dict[str, object]:
    settings = get_awg_settings()
    installed = bool(_command_path("awg") and _command_path("awg-quick"))
    module_loaded = Path("/sys/module/amneziawg").exists()
    state = awg_service_state() if installed else "not-installed"
    local_stats = _peer_stats() if state == "active" else {}
    clients: list[dict[str, object]] = []
    from .node_manager import list_nodes
    known_nodes = list_nodes()
    node_cache: dict[int, dict[str, object]] = {
        int(node["id"]): node for node in known_nodes if not node.get("is_local")
    }
    local_node = next((node for node in known_nodes if node.get("is_local")), {})
    import datetime
    import json
    now = datetime.datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    week_str = (now - datetime.timedelta(days=7)).strftime("%Y-%m-%d")
    month_str = (now - datetime.timedelta(days=30)).strftime("%Y-%m-%d")
    
    daily_traffic = {}
    global_stats = {"day": (0, 0), "week": (0, 0), "month": (0, 0)}
    graph_data = {"labels": [], "rx": [], "tx": []}
    
    try:
        with connect() as con:
            # Данные для таблицы клиентов (за сегодня)
            for trow in con.execute("SELECT client_id, rx_bytes, tx_bytes FROM awg_traffic_history WHERE date_str = ?", (today_str,)).fetchall():
                daily_traffic[trow[0]] = (trow[1], trow[2])
                
            # Общие суммы за день/неделю/месяц
            for period, date_from in [("day", today_str), ("week", week_str), ("month", month_str)]:
                row = con.execute("SELECT SUM(rx_bytes), SUM(tx_bytes) FROM awg_traffic_history WHERE date_str >= ?", (date_from,)).fetchone()
                if row and row[0]:
                    global_stats[period] = (row[0], row[1])
                    
            # Данные для графика (последние 30 дней)
            rows = con.execute("SELECT date_str, SUM(rx_bytes), SUM(tx_bytes) FROM awg_traffic_history WHERE date_str >= ? GROUP BY date_str ORDER BY date_str ASC", (month_str,)).fetchall()
            for r in rows:
                graph_data["labels"].append(r[0])
                graph_data["rx"].append(r[1])
                graph_data["tx"].append(r[2])
    except Exception:
        pass

    for row in list_awg_clients():
        if str(row["system_role"] or "").strip():
            continue
        item = dict(row)
        node_id = int(item.get("node_id") or 0)
        if node_id:
            from .node_clients import remote_peer_stats
            from .node_manager import get_node
            stats = remote_peer_stats(item)
            node = node_cache.get(node_id)
            if node is None:
                node = get_node(node_id)
                node_cache[node_id] = node
            item["server_name"] = str(node.get("name") or f"SG-Node #{node_id}")
            item["server_address"] = str(node.get("public_ipv4") or node.get("public_host") or "")
            item["server_type"] = "node"
            item["server_online"] = bool(node.get("online"))
            item["server_country_code"] = str(node.get("country_code") or "")
            item["server_country_flag"] = str(node.get("country_flag") or "🌐")
            item["server_country_name"] = str(node.get("country_name") or "Страна не определена")
        else:
            stats = local_stats.get(
                row["public_key"], {"latest_handshake": 0, "rx": 0, "tx": 0}
            )
            item["server_name"] = str(local_node.get("name") or "Controller")
            item["server_address"] = str(settings["endpoint_host"] or local_node.get("public_host") or "")
            item["server_type"] = "controller"
            item["server_online"] = state == "active"
            item["server_country_code"] = str(local_node.get("country_code") or "")
            item["server_country_flag"] = str(local_node.get("country_flag") or "🌐")
            item["server_country_name"] = str(local_node.get("country_name") or "Страна не определена")
        item.update(stats)
        item.update(client_lifecycle(item))
        item["deployment_ready"] = (
            not node_id or str(item.get("deployment_state") or "active") == "active"
        )
        item["online"] = bool(
            item["deployment_ready"]
            and item["effective_enabled"]
            and int(item["latest_handshake"]) > 0
            and time.time() - int(item["latest_handshake"]) < 180
        )
        item["latest_handshake_text"] = _format_handshake(int(item["latest_handshake"]))
        item["rx_text"] = _format_bytes(int(item["rx"]))
        item["tx_text"] = _format_bytes(int(item["tx"]))
        
        # Суточный трафик
        client_id_int = int(item["id"])
        d_rx, d_tx = daily_traffic.get(client_id_int, (0, 0))
        item["daily_rx"] = d_rx
        item["daily_tx"] = d_tx
        item["daily_rx_text"] = _format_bytes(d_rx)
        item["daily_tx_text"] = _format_bytes(d_tx)
        clients.append(item)
    panel_pid = _service_main_pid("sg-awg-panel")
    panel_rss = _process_rss(panel_pid)
    endpoint_detected = "" if settings["endpoint_host"] else detect_public_ipv4()
    total_rx = sum(int(item["rx"]) for item in clients)
    total_tx = sum(int(item["tx"]) for item in clients)
    active_clients = sum(1 for item in clients if bool(item["online"]))
    backups = list_backups(limit=1)
    return {
        "installed": installed,
        "module_loaded": module_loaded,
        "configured": bool(settings["configured"]),
        "service_state": state,
        "config_path": str(AWG_CONFIG_PATH),
        "settings": settings,
        "clients": clients,
        "external_interface_detected": detect_external_interface(),
        "public_ipv4_detected": endpoint_detected,
        "panel_rss": panel_rss,
        "panel_rss_text": _format_bytes(panel_rss),
        "resources": _system_resources(),
        "total_rx": total_rx,
        "total_tx": total_tx,
        "total_rx_text": _format_bytes(total_rx),
        "total_daily_rx_text": _format_bytes(sum(v[0] for v in daily_traffic.values())),
        "total_week_rx_text": _format_bytes(global_stats["week"][0]),
        "total_week_tx_text": _format_bytes(global_stats["week"][1]),
        "total_month_rx_text": _format_bytes(global_stats["month"][0]),
        "total_month_tx_text": _format_bytes(global_stats["month"][1]),
        "graph_labels_json": json.dumps(graph_data["labels"]),
        "graph_rx_json": json.dumps(graph_data["rx"]),
        "graph_tx_json": json.dumps(graph_data["tx"]),
        "total_daily_tx_text": _format_bytes(sum(v[1] for v in daily_traffic.values())),
        "total_tx_text": _format_bytes(total_tx),
        "active_clients": active_clients,
        "latest_backup": backups[0] if backups else None,
    }


# ---------------------------------------------------------------------------
# Panel administration: access, sessions, audit log, backups and updates.
# ---------------------------------------------------------------------------

PANEL_SERVICE = os.environ.get("AWGPANEL_PANEL_SERVICE", "sg-awg-panel")
PANEL_PROJECT_DIR = Path(os.environ.get("AWGPANEL_PROJECT_DIR", "/opt/sg-awg-panel"))
PANEL_ENV_FILE = Path(os.environ.get("AWGPANEL_ENV_FILE", "/etc/sg-awg-panel/web.env"))
UPDATE_STATUS_PATH = Path(
    os.environ.get("AWGPANEL_UPDATE_STATUS", "/var/www/sg-awg-update/status.json")
)
UPDATE_LOG_PATH = Path(
    os.environ.get("AWGPANEL_UPDATE_LOG", "/var/www/sg-awg-update/update.log")
)
UPDATE_REPOSITORY = "WeedVDK/sg-awg-panel"

_BACKUP_CALENDARS = {
    "hourly": "hourly",
    "every_6_hours": "*-*-* 00,06,12,18:00:00",
    "daily": "daily",
    "weekly": "Sun *-*-* 03:00:00",
    "disabled": "",
}


def get_panel_settings():
    init_db()
    with connect() as con:
        row = con.execute("SELECT * FROM panel_settings WHERE id=1").fetchone()
    if row is None:
        raise AWGPanelError("Настройки панели не найдены")
    return row


def configure_instance_name(instance_name: object):
    _require_root()
    name = str(instance_name or "").strip()
    if not name:
        raise ValueError("Укажите имя сервера")
    if len(name) > 64:
        raise ValueError("Имя сервера должно содержать не более 64 символов")
    if any(ord(ch) < 32 for ch in name):
        raise ValueError("Имя сервера содержит недопустимые символы")
    with connect() as con:
        con.execute(
            "UPDATE panel_settings SET instance_name=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
            (name,),
        )
        # Keep the local Controller identity synchronized immediately.  The
        # next page render should never show the new name in the header and the
        # old name in Cluster or Clients.
        con.execute(
            "UPDATE cluster_nodes SET name=?, updated_at=CURRENT_TIMESTAMP WHERE is_local=1",
            (name,),
        )
    write_env_values({"AWGPANEL_INSTANCE_NAME": name})
    return get_panel_settings()


def _backup_keep_value() -> int:
    try:
        return max(1, min(365, int(get_panel_settings()["backup_keep"])))
    except (AWGPanelError, KeyError, TypeError, ValueError):
        return max(1, BACKUP_KEEP)


def _normalize_domain(value: object, *, allow_empty: bool = True) -> str:
    raw = str(value or "").strip().rstrip(".")
    if not raw and allow_empty:
        return ""
    if not raw:
        raise ValueError("Укажите домен панели")
    try:
        ascii_name = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Некорректный домен панели") from exc
    if len(ascii_name) > 253:
        raise ValueError("Домен панели слишком длинный")
    labels = ascii_name.split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Укажите полное доменное имя, например awg.example.com")
    return ascii_name


def _normalize_port(value: object, field: str = "Порт") -> int:
    try:
        port = int(str(value).strip())
    except ValueError as exc:
        raise ValueError(f"{field}: укажите число") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{field}: допустимы значения 1–65535")
    return port


def _env_quote(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:@+-]*", value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def write_env_values(values: dict[str, object]) -> None:
    _require_root()
    lines = PANEL_ENV_FILE.read_text(encoding="utf-8").splitlines() if PANEL_ENV_FILE.exists() else []
    pending = {key: str(value) for key, value in values.items()}
    output: list[str] = []
    for line in lines:
        key = line.split("=", 1)[0] if "=" in line else ""
        if key in pending:
            output.append(f"{key}={_env_quote(pending.pop(key))}")
        else:
            output.append(line)
    for key, value in pending.items():
        output.append(f"{key}={_env_quote(value)}")
    PANEL_ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    PANEL_ENV_FILE.write_text("\n".join(output) + "\n", encoding="utf-8")
    os.chmod(PANEL_ENV_FILE, 0o600)


def panel_public_url(settings=None) -> str:
    settings = settings or get_panel_settings()
    scheme = str(settings["public_scheme"])
    host = str(settings["public_host"] or detect_public_ipv4(force=False) or "SERVER_IP")
    port = int(settings["public_port"])
    default = 443 if scheme == "https" else 80
    suffix = "" if port == default else f":{port}"
    return f"{scheme}://{host}{suffix}"


def _panel_access_values(
    *,
    scheme: str,
    public_host: str,
    public_port: object,
    manage_placeholder: object = True,
) -> dict[str, object]:
    normalized_scheme = str(scheme).strip().lower()
    if normalized_scheme not in {"http", "https"}:
        raise ValueError("Режим панели должен быть HTTP или HTTPS")
    port = _normalize_port(public_port, "Публичный порт панели")
    if not 49152 <= port <= 65535:
        raise ValueError(
            "Публичный порт панели должен быть в динамическом диапазоне 49152–65535"
        )
    host = _normalize_domain(public_host, allow_empty=normalized_scheme == "http")
    if normalized_scheme == "https" and not host:
        raise ValueError("Для HTTPS требуется домен")
    placeholder = str(manage_placeholder).strip().lower() in {
        "1", "true", "yes", "on", "enabled"
    }
    return {
        "scheme": normalized_scheme,
        "public_host": host,
        "public_port": port,
        "manage_placeholder": placeholder,
    }


def _panel_access_args(values: dict[str, object]) -> list[str]:
    script = PANEL_PROJECT_DIR / "deploy" / "configure-panel-access.sh"
    if not script.exists():
        raise AWGPanelError(f"Скрипт настройки доступа не найден: {script}")
    args = [
        "/bin/bash",
        str(script),
        "--scheme",
        str(values["scheme"]),
        "--port",
        str(values["public_port"]),
        "--manage-placeholder",
        "1" if values["manage_placeholder"] else "0",
    ]
    if values["public_host"]:
        args += ["--domain", str(values["public_host"])]
    return args


def configure_panel_access(
    *,
    scheme: str,
    public_host: str,
    public_port: object,
    manage_placeholder: object = True,
):
    _require_root()
    values = _panel_access_values(
        scheme=scheme, public_host=public_host, public_port=public_port,
        manage_placeholder=manage_placeholder,
    )
    unit = f"sg-awg-panel-access-{uuid.uuid4().hex[:8]}"
    result = _run(
        ["systemd-run", "--wait", "--pipe", "--collect", f"--unit={unit}", *_panel_access_args(values)],
        timeout=1200,
    )
    if result.returncode != 0:
        raise AWGPanelError(
            result.stderr.strip()
            or result.stdout.strip()
            or "Не удалось настроить доступ к панели"
        )
    with connect() as con:
        con.execute(
            """
            UPDATE panel_settings
            SET public_scheme=?, public_host=?, public_port=?, https_email='',
                https_enabled=?, manage_placeholder=?,
                backend_address='127.0.0.1', backend_port=18080,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=1
            """,
            (
                values["scheme"], values["public_host"], values["public_port"],
                1 if values["scheme"] == "https" else 0,
                int(bool(values["manage_placeholder"])),
            ),
        )
    return get_panel_settings()


def _cleanup_panel_access_jobs(max_age_seconds: int = 86400) -> None:
    if not PANEL_ACCESS_JOBS_DIR.exists():
        return
    cutoff = time.time() - max_age_seconds
    for path in PANEL_ACCESS_JOBS_DIR.iterdir():
        try:
            if path.is_dir() and path.stat().st_mtime < cutoff:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            continue


def start_panel_access_job(
    *,
    scheme: str,
    public_host: str,
    public_port: object,
    manage_placeholder: object = True,
) -> dict[str, object]:
    """Start panel access reconfiguration and return a public progress token."""
    _require_root()
    values = _panel_access_values(
        scheme=scheme, public_host=public_host, public_port=public_port,
        manage_placeholder=manage_placeholder,
    )
    runner = PANEL_PROJECT_DIR / "deploy" / "run-panel-access-job.sh"
    if not runner.exists():
        raise AWGPanelError(f"Скрипт фоновой настройки доступа не найден: {runner}")

    PANEL_ACCESS_JOBS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(PANEL_ACCESS_JOBS_DIR, 0o700)
    _cleanup_panel_access_jobs()
    token = secrets.token_urlsafe(32)
    job_dir = PANEL_ACCESS_JOBS_DIR / token
    job_dir.mkdir(mode=0o700)

    host = str(values["public_host"] or detect_public_ipv4(force=False) or "SERVER_IP")
    default_port = 443 if values["scheme"] == "https" else 80
    suffix = "" if int(values["public_port"]) == default_port else f":{values['public_port']}"
    target_url = f"{values['scheme']}://{host}{suffix}"
    status = {
        "state": "starting",
        "message": "Подготовка настройки доступа",
        "targetUrl": target_url,
        "startedAt": datetime.now(timezone.utc).isoformat(),
    }
    (job_dir / "status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    os.chmod(job_dir / "status.json", 0o600)
    (job_dir / "access.log").write_text("", encoding="utf-8")
    os.chmod(job_dir / "access.log", 0o600)

    args = [
        "systemd-run", "--collect",
        f"--unit=sg-awg-panel-access-job-{uuid.uuid4().hex[:8]}",
        "/bin/bash", str(runner),
        "--job-token", token,
        "--scheme", str(values["scheme"]),
        "--port", str(values["public_port"]),
        "--manage-placeholder", "1" if values["manage_placeholder"] else "0",
    ]
    if values["public_host"]:
        args += ["--domain", str(values["public_host"])]
    result = _run(args, timeout=20)
    if result.returncode != 0:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise AWGPanelError(
            result.stderr.strip() or result.stdout.strip()
            or "Не удалось запустить настройку доступа"
        )
    return {"token": token, "target_url": target_url, **values}


def get_panel_access_job(token: str) -> dict[str, object] | None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,80}", str(token or "")):
        return None
    job_dir = PANEL_ACCESS_JOBS_DIR / token
    status_path = job_dir / "status.json"
    if not status_path.is_file():
        return None
    try:
        data = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    log_path = job_dir / "access.log"
    try:
        # HTTPS issuance output is intentionally returned in full. The terminal
        # is the primary progress UI and must retain every Certbot/Nginx line.
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        log_text = ""
    data["log"] = log_text
    return data


def normalize_ip_allowlist(value: object) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    networks: list[str] = []
    for item in re.split(r"[,\n\r]+", raw):
        item = item.strip()
        if not item:
            continue
        try:
            if "/" not in item:
                address = ipaddress.ip_address(item)
                item = f"{address}/{32 if address.version == 4 else 128}"
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ValueError(f"Некорректный IP или CIDR: {item}") from exc
        networks.append(str(network))
    if len(networks) > 64:
        raise ValueError("Разрешено не более 64 сетей в IP allowlist")
    return ", ".join(dict.fromkeys(networks))


def ip_is_allowed(ip_value: str, allowlist: str | None = None) -> bool:
    allowlist = str(get_panel_settings()["ip_allowlist"] if allowlist is None else allowlist)
    if not allowlist.strip():
        return True
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    for item in allowlist.split(","):
        try:
            if address in ipaddress.ip_network(item.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def update_ip_allowlist(value: object, *, current_ip: str):
    _require_root()
    normalized = normalize_ip_allowlist(value)
    if normalized and not ip_is_allowed(current_ip, normalized):
        raise ValueError(
            f"Текущий IP {current_ip} не входит в новый allowlist. Добавьте его, чтобы не потерять доступ."
        )
    with connect() as con:
        con.execute(
            "UPDATE panel_settings SET ip_allowlist=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
            (normalized,),
        )
    return get_panel_settings()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_web_session(token: str, *, ip_address: str, user_agent: str) -> None:
    settings = get_panel_settings()
    with connect() as con:
        con.execute(
            """
            INSERT INTO web_sessions
                (token_hash, auth_epoch, ip_address, user_agent, created_at, last_seen_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (_token_hash(token), int(settings["auth_epoch"]), ip_address[:128], user_agent[:512]),
        )
        con.execute(
            "DELETE FROM web_sessions WHERE revoked_at IS NOT NULL OR last_seen_at < datetime('now','-30 days')"
        )


def validate_web_session(token: str, *, touch: bool = True):
    if not token:
        return None
    settings = get_panel_settings()
    with connect() as con:
        row = con.execute(
            "SELECT * FROM web_sessions WHERE token_hash=? AND revoked_at IS NULL",
            (_token_hash(token),),
        ).fetchone()
        if row is None or int(row["auth_epoch"]) != int(settings["auth_epoch"]):
            return None
        if touch:
            con.execute(
                "UPDATE web_sessions SET last_seen_at=CURRENT_TIMESTAMP WHERE token_hash=?",
                (_token_hash(token),),
            )
    return row


def revoke_web_session(token_hash: str) -> None:
    with connect() as con:
        con.execute(
            "UPDATE web_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE token_hash=?",
            (token_hash,),
        )


def revoke_all_web_sessions(*, except_token: str = "") -> None:
    with connect() as con:
        if except_token:
            con.execute(
                "UPDATE web_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE token_hash<>? AND revoked_at IS NULL",
                (_token_hash(except_token),),
            )
        else:
            con.execute(
                "UPDATE web_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE revoked_at IS NULL"
            )


def rotate_auth_epoch(*, keep_token: str = "") -> int:
    with connect() as con:
        con.execute(
            "UPDATE panel_settings SET auth_epoch=auth_epoch+1, updated_at=CURRENT_TIMESTAMP WHERE id=1"
        )
        epoch = int(con.execute("SELECT auth_epoch FROM panel_settings WHERE id=1").fetchone()[0])
        con.execute(
            "UPDATE web_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE revoked_at IS NULL"
        )
        if keep_token:
            con.execute(
                """
                INSERT OR REPLACE INTO web_sessions
                    (token_hash, auth_epoch, ip_address, user_agent, created_at, last_seen_at, revoked_at)
                VALUES (?, ?, '', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, NULL)
                """,
                (_token_hash(keep_token), epoch),
            )
    return epoch


def list_web_sessions(*, current_token: str = ""):
    current_hash = _token_hash(current_token) if current_token else ""
    with connect() as con:
        rows = con.execute(
            """
            SELECT token_hash, ip_address, user_agent, created_at, last_seen_at
            FROM web_sessions
            WHERE revoked_at IS NULL
            ORDER BY last_seen_at DESC
            """
        ).fetchall()
    return [dict(row) | {"current": row["token_hash"] == current_hash} for row in rows]


def record_auth_event(
    event_type: str, *, ip_address: str = "", user_agent: str = "", detail: str = ""
) -> None:
    with connect() as con:
        con.execute(
            """
            INSERT INTO auth_events(event_type, ip_address, user_agent, detail)
            VALUES (?, ?, ?, ?)
            """,
            (event_type[:64], ip_address[:128], user_agent[:512], detail[:512]),
        )
        con.execute(
            "DELETE FROM auth_events WHERE id NOT IN (SELECT id FROM auth_events ORDER BY id DESC LIMIT 1000)"
        )


def list_auth_events(*, limit: int = 100):
    limit = max(1, min(500, int(limit)))
    with connect() as con:
        return con.execute(
            "SELECT * FROM auth_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def configure_backup_policy(schedule: str, keep: object):
    _require_root()
    schedule = str(schedule).strip()
    if schedule not in _BACKUP_CALENDARS:
        raise ValueError("Недопустимое расписание резервных копий")
    try:
        keep_value = int(str(keep).strip())
    except ValueError as exc:
        raise ValueError("Количество копий должно быть числом") from exc
    if not 1 <= keep_value <= 365:
        raise ValueError("Хранить можно от 1 до 365 резервных копий")
    previous = get_panel_settings()
    with connect() as con:
        con.execute(
            """
            UPDATE panel_settings SET backup_schedule=?, backup_keep=?,
                updated_at=CURRENT_TIMESTAMP WHERE id=1
            """,
            (schedule, keep_value),
        )
    script = PANEL_PROJECT_DIR / "deploy" / "install-backup-timer.sh"
    unit = f"sg-awg-backup-policy-{uuid.uuid4().hex[:8]}"
    result = _run(
        ["systemd-run", "--wait", "--pipe", "--collect", f"--unit={unit}", "/bin/bash", str(script)],
        timeout=60,
    )
    if result.returncode != 0:
        with connect() as con:
            con.execute(
                "UPDATE panel_settings SET backup_schedule=?, backup_keep=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
                (previous["backup_schedule"], previous["backup_keep"]),
            )
        raise AWGPanelError(result.stderr.strip() or "Не удалось обновить таймер копий")
    return get_panel_settings()


def backup_calendar(schedule: str | None = None) -> str:
    if schedule is None:
        schedule = str(get_panel_settings()["backup_schedule"])
    return _BACKUP_CALENDARS.get(schedule, "daily")


def _version_key(value: str) -> tuple[int, int, int, int, int]:
    match = re.fullmatch(
        r"v?(\d+)\.(\d+)\.(\d+)(?:[-.]?(alpha|beta|rc)(\d+))?", value.strip(), re.I
    )
    if not match:
        return (-1, -1, -1, -1, -1)
    major, minor, patch = (int(match.group(i)) for i in range(1, 4))
    label = (match.group(4) or "stable").lower()
    rank = {"alpha": 0, "beta": 1, "rc": 2, "stable": 3}[label]
    number = int(match.group(5) or 0)
    return (major, minor, patch, rank, number)


def check_for_updates(*, force: bool = False) -> dict[str, object]:
    from . import __version__

    current = f"v{__version__}"
    settings = get_panel_settings()
    checked_at = str(settings["latest_checked_at"] or "")
    if not force and checked_at and str(settings["latest_version"]):
        try:
            checked = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
            if (datetime.now(timezone.utc) - checked).total_seconds() < 900:
                latest = str(settings["latest_version"])
                return {
                    "current": current,
                    "latest": latest,
                    "available": _version_key(latest) > _version_key(current),
                    "checked_at": checked_at,
                    "error": str(settings["latest_error"] or ""),
                }
        except ValueError:
            pass

    # RC5 is published from the verified main branch without Releases or tags.
    # Read the package version from that exact branch so the UI and updater use
    # the same source of truth as install.sh and update-from-github.sh.
    request = urllib.request.Request(
        f"https://raw.githubusercontent.com/{UPDATE_REPOSITORY}/main/awgpanel/__init__.py",
        headers={"Accept": "text/plain", "User-Agent": "SG-AWG-Panel"},
    )
    latest = ""
    error = ""
    try:
        with urllib.request.urlopen(request, timeout=8) as response:  # nosec B310
            source = response.read(32_768).decode("utf-8")
        match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', source, re.M)
        if match is None or _version_key(match.group(1))[0] < 0:
            raise ValueError("Не удалось определить версию в GitHub main")
        latest = f"v{match.group(1)}"
    except (OSError, urllib.error.URLError, UnicodeDecodeError, ValueError) as exc:
        error = str(exc)
        latest = str(settings["latest_version"] or current)
    stamp = datetime.now(timezone.utc).isoformat()
    with connect() as con:
        con.execute(
            """
            UPDATE panel_settings SET latest_version=?, latest_checked_at=?, latest_error=?,
                updated_at=CURRENT_TIMESTAMP WHERE id=1
            """,
            (latest, stamp, error),
        )
    return {
        "current": current,
        "latest": latest,
        "available": not error and _version_key(latest) > _version_key(current),
        "checked_at": stamp,
        "error": error,
    }


def start_panel_update(version: str) -> dict[str, str]:
    _require_root()
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\d+)?", version, re.I):
        raise ValueError("Некорректная версия обновления")
    if _run(["systemctl", "is-active", "sg-awg-panel-update.service"]).returncode == 0:
        raise AWGPanelError("Обновление уже выполняется")
    UPDATE_STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    UPDATE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    UPDATE_STATUS_PATH.write_text(
        json.dumps({"state": "starting", "version": version, "started_at": datetime.now(timezone.utc).isoformat()}) + "\n",
        encoding="utf-8",
    )
    os.chmod(UPDATE_STATUS_PATH, 0o644)
    UPDATE_LOG_PATH.write_text("", encoding="utf-8")
    os.chmod(UPDATE_LOG_PATH, 0o644)
    script = PANEL_PROJECT_DIR / "deploy" / "update-from-github.sh"
    unit = "sg-awg-panel-update.service"
    command = [
        "systemd-run",
        "--unit=sg-awg-panel-update",
        "--collect",
        "--property=Type=oneshot",
        f"--setenv=SG_AWG_PANEL_VERSION={version}",
        f"--setenv=SG_AWG_PANEL_UPDATE_STATUS={UPDATE_STATUS_PATH}",
        f"--setenv=SG_AWG_PANEL_UPDATE_LOG={UPDATE_LOG_PATH}",
        "/bin/bash",
        str(script),
    ]
    result = _run(command, timeout=20)
    if result.returncode != 0:
        raise AWGPanelError(result.stderr.strip() or result.stdout.strip() or "Не удалось запустить обновление")
    return {"unit": unit, "version": version}


def get_update_status() -> dict[str, object]:
    data: dict[str, object] = {"state": "idle", "version": "", "message": ""}
    if UPDATE_STATUS_PATH.exists():
        try:
            loaded = json.loads(UPDATE_STATUS_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data.update(loaded)
        except (OSError, json.JSONDecodeError):
            data["state"] = "unknown"
    unit_state = _run(["systemctl", "is-active", "sg-awg-panel-update.service"]).stdout.strip()
    data["unit_state"] = unit_state or "inactive"
    if UPDATE_LOG_PATH.exists():
        try:
            data["log"] = UPDATE_LOG_PATH.read_text(encoding="utf-8", errors="replace")[-12_000:]
        except OSError:
            data["log"] = ""
    else:
        data["log"] = ""
    return data
