from __future__ import annotations

import contextlib
import ipaddress
import fcntl
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from collections.abc import Iterable, Iterator

from . import db
from .db import connect, init_db
from .errors import AWGPanelError
from .traffic_modes import AWG_GATEWAY, normalize_egress_mode
from .traffic_controls import get_traffic_controls_settings, nft_options
from .traffic_rules import (
    apply_dnsmasq_runtime,
    compile_rules,
    compile_rule_values,
    get_dns_traffic_settings,
    render_dnsmasq_config,
    render_rule_nft,
)
from .outbounds import (
    MAX_OUTBOUND_PROFILES,
    fwmark_for,
    interface_name_for,
    normalize_outbound_name,
    parse_amneziawg_outbound_config,
    render_nftables_script,
    traffic_table_for,
    rule_priority_for,
)

OUTBOUND_CONFIG_DIR = Path(
    os.environ.get(
        "AWGPANEL_OUTBOUND_CONFIG_DIR",
        "/etc/amnezia/amneziawg/outbounds",
    )
)
TRAFFIC_STATE_DIR = Path(
    os.environ.get("AWGPANEL_TRAFFIC_STATE_DIR", "/var/lib/sg-awg-panel/traffic-rules")
)
NFT_SCRIPT_PATH = TRAFFIC_STATE_DIR / "traffic.nft"
TRAFFIC_LOCK_PATH = Path(
    os.environ.get("AWGPANEL_TRAFFIC_LOCK", "/run/lock/sg-awg-panel-traffic.lock")
)


@contextlib.contextmanager
def _exclusive_traffic_lock() -> Iterator[None]:
    TRAFFIC_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(TRAFFIC_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.chmod(TRAFFIC_LOCK_PATH, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("Для управления маршрутизацией нужны права root")


def _run(
    args: list[str],
    *,
    input_text: str | None = None,
    timeout: int = 30,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise AWGPanelError(
            f"Команда превысила тайм-аут {timeout} с: {' '.join(args)}"
        ) from exc
    if check and result.returncode != 0:
        raise AWGPanelError(
            result.stderr.strip()
            or result.stdout.strip()
            or f"Команда завершилась ошибкой: {' '.join(args)}"
        )
    return result


def _command(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise AWGPanelError(f"Не найдена системная команда {name}")
    return path


def flush_client_connections(addresses: Iterable[object]) -> dict[str, int | bool]:
    """Drop existing conntrack flows for selected VPN client addresses.

    Routing marks are stored per connection. Removing only the affected
    clients' flows makes Direct/Outbound changes take effect immediately while
    leaving every other VPN client untouched.
    """
    conntrack = shutil.which("conntrack")
    unique: list[str] = []
    for value in addresses:
        text = str(value or "").strip()
        if not text:
            continue
        try:
            address = str(ipaddress.ip_interface(text).ip)
        except ValueError:
            try:
                address = str(ipaddress.ip_address(text))
            except ValueError:
                continue
        if address not in unique:
            unique.append(address)
    if not conntrack:
        return {"available": False, "clients": len(unique), "commands": 0}
    commands = 0
    selectors = ("--orig-src", "--orig-dst", "--reply-src", "--reply-dst")
    for address in unique:
        for selector in selectors:
            # conntrack exits with code 1 when no matching flow exists; that is
            # harmless. Checking all four tuple directions also covers NATed
            # reply traffic and makes the new route effective without
            # reconnecting the VPN tunnel.
            _run([conntrack, "-D", "-f", "ipv4", selector, address], timeout=15)
            commands += 1
    ip_cmd = shutil.which("ip")
    if ip_cmd:
        _run([ip_cmd, "route", "flush", "cache"], timeout=10)
        commands += 1
    return {"available": True, "clients": len(unique), "commands": commands}


def client_has_marked_connection(address: object, mark: int) -> bool:
    """Return True when a live client flow carries the expected route mark."""
    conntrack = shutil.which("conntrack")
    if not conntrack:
        return False
    try:
        client_ip = str(ipaddress.ip_interface(str(address or "")).ip)
    except ValueError:
        return False
    result = _run(
        [
            conntrack,
            "-L",
            "-f",
            "ipv4",
            "-s",
            client_ip,
            "--mark",
            f"0x{int(mark):x}/0xffffffff",
        ],
        timeout=15,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def list_outbounds(*, enabled_only: bool = False):
    init_db()
    query = "SELECT * FROM outbounds"
    if enabled_only:
        query += " WHERE enabled=1"
    query += " ORDER BY id"
    with connect() as con:
        return con.execute(query).fetchall()


def find_outbound(outbound_id: int):
    init_db()
    with connect() as con:
        row = con.execute(
            "SELECT * FROM outbounds WHERE id=?", (int(outbound_id),)
        ).fetchone()
    if row is None:
        raise AWGPanelError("Outbound-профиль не найден")
    return row


def _database_backup() -> Path:
    init_db()
    db.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        prefix="traffic-before-", suffix=".db", dir=str(db.DB_PATH.parent)
    )
    os.close(fd)
    target_path = Path(name)
    source = sqlite3.connect(db.DB_PATH)
    target = sqlite3.connect(target_path)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    os.chmod(target_path, 0o600)
    return target_path


def _restore_database(path: Path) -> None:
    source = sqlite3.connect(path)
    target = sqlite3.connect(db.DB_PATH)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


def _mutate_and_apply(callback):
    with _exclusive_traffic_lock():
        backup = _database_backup()
        try:
            result = callback()
            _apply_egress_runtime_unlocked()
            return result
        except Exception:
            _restore_database(backup)
            with contextlib.suppress(Exception):
                _apply_egress_runtime_unlocked()
            raise
        finally:
            backup.unlink(missing_ok=True)


def mutate_traffic_and_apply(callback):
    """Run a traffic database mutation with automatic runtime rollback."""
    _require_root()
    return _mutate_and_apply(callback)


def create_outbound(name: str, config_text: str, *, enabled: bool = True):
    _require_root()
    normalized_name = normalize_outbound_name(name)
    parsed = parse_amneziawg_outbound_config(config_text)

    def mutate():
        try:
            with connect() as con:
                con.execute("BEGIN IMMEDIATE")
                used_ids = {
                    int(row["id"])
                    for row in con.execute("SELECT id FROM outbounds").fetchall()
                }
                outbound_id = next(
                    (
                        candidate
                        for candidate in range(1, MAX_OUTBOUND_PROFILES + 1)
                        if candidate not in used_ids
                    ),
                    None,
                )
                if outbound_id is None:
                    raise ValueError(
                        f"Можно создать не более {MAX_OUTBOUND_PROFILES} outbound-профилей"
                    )
                con.execute(
                    """
                    INSERT INTO outbounds (
                        id, name, kind, enabled, config_text, endpoint, address
                    ) VALUES (?, ?, 'amneziawg', ?, ?, ?, ?)
                    """,
                    (
                        outbound_id,
                        normalized_name,
                        1 if enabled else 0,
                        parsed.config_text,
                        parsed.endpoint,
                        parsed.address,
                    ),
                )
            return find_outbound(outbound_id)
        except sqlite3.IntegrityError as exc:
            raise AWGPanelError("Outbound с таким именем уже существует") from exc

    return _mutate_and_apply(mutate)


def replace_outbound(
    outbound_id: int, *, name: str, config_text: str, enabled: bool | None = None
):
    _require_root()
    find_outbound(outbound_id)
    normalized_name = normalize_outbound_name(name)
    current = find_outbound(outbound_id)
    parsed = parse_amneziawg_outbound_config(
        config_text if str(config_text or "").strip() else str(current["config_text"])
    )

    def mutate():
        try:
            with connect() as con:
                con.execute(
                    """
                    UPDATE outbounds
                    SET name=?, enabled=?, config_text=?, endpoint=?, address=?,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                    """,
                    (
                        normalized_name,
                        int(current["enabled"]) if enabled is None else (1 if enabled else 0),
                        parsed.config_text,
                        parsed.endpoint,
                        parsed.address,
                        int(outbound_id),
                    ),
                )
            return find_outbound(outbound_id)
        except sqlite3.IntegrityError as exc:
            raise AWGPanelError("Outbound с таким именем уже существует") from exc

    return _mutate_and_apply(mutate)


def set_outbound_enabled(outbound_id: int, enabled: bool):
    _require_root()
    find_outbound(outbound_id)

    def mutate():
        with connect() as con:
            con.execute(
                "UPDATE outbounds SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (1 if enabled else 0, int(outbound_id)),
            )
            if not enabled:
                con.execute(
                    "UPDATE awg_clients SET egress_mode='awg_gateway', outbound_id=NULL, "
                    "updated_at=CURRENT_TIMESTAMP WHERE outbound_id=? AND node_id IS NULL",
                    (int(outbound_id),),
                )
        return find_outbound(outbound_id)

    return _mutate_and_apply(mutate)


def delete_outbound(outbound_id: int):
    _require_root()
    outbound = find_outbound(outbound_id)

    def mutate():
        with connect() as con:
            con.execute(
                "UPDATE awg_clients SET egress_mode='awg_gateway', outbound_id=NULL, "
                "updated_at=CURRENT_TIMESTAMP WHERE outbound_id=? AND node_id IS NULL",
                (int(outbound_id),),
            )
            con.execute("DELETE FROM outbounds WHERE id=?", (int(outbound_id),))
        return outbound

    return _mutate_and_apply(mutate)


def set_client_egress(client_id: int, mode: str, outbound_id: int | None = None):
    _require_root()
    normalized_mode = normalize_egress_mode(mode)
    init_db()
    with connect() as con:
        client = con.execute(
            "SELECT * FROM awg_clients WHERE id=?", (int(client_id),)
        ).fetchone()
    if client is None:
        raise AWGPanelError("Клиент AmneziaWG не найден")
    if client["node_id"]:
        raise ValueError("Network этой панели управляет только клиентами Controller. Для SG-Node маршрутизация настраивается на самой Node")
    with connect() as con:
        cascade = con.execute(
            """
            SELECT link.id
            FROM cascade_links AS link
            JOIN cluster_nodes AS entry_node ON entry_node.id=link.entry_node_id
            WHERE entry_node.is_local=1 AND link.enabled=1
              AND link.state IN ('preparing_entry','active')
            LIMIT 1
            """
        ).fetchone()
    if cascade is not None:
        raise ValueError(
            "Маршрутом этого сервера сейчас управляет Cascade. Сначала верните прямой выход в интернет"
        )

    selected_id: int | None = None
    if normalized_mode == "outbound":
        if outbound_id is None:
            raise ValueError("Выберите outbound-профиль")
        outbound = find_outbound(int(outbound_id))
        if not bool(outbound["enabled"]):
            raise ValueError("Выбранный outbound отключён")
        selected_id = int(outbound["id"])

    def mutate():
        with connect() as con:
            con.execute(
                """
                UPDATE awg_clients
                SET egress_mode=?, outbound_id=?, updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (normalized_mode, selected_id, int(client_id)),
            )
            return con.execute(
                "SELECT * FROM awg_clients WHERE id=?", (int(client_id),)
            ).fetchone()

    result = _mutate_and_apply(mutate)
    flush_client_connections([client["address"]])
    return result


def _managed_config_paths() -> list[Path]:
    if not OUTBOUND_CONFIG_DIR.exists():
        return []
    return sorted(
        path
        for path in OUTBOUND_CONFIG_DIR.glob("sgo*.conf")
        if re.fullmatch(r"sgo[0-9]+\.conf", path.name)
    )


def _down_config(path: Path) -> None:
    awg_quick = shutil.which("awg-quick")
    if not awg_quick:
        return
    interface_name = path.stem
    ip = shutil.which("ip")
    if ip:
        present = _run([ip, "link", "show", "dev", interface_name])
        if present.returncode != 0:
            return
    _run([awg_quick, "down", str(path)], timeout=45)


def _delete_nft_tables() -> None:
    nft = shutil.which("nft")
    if not nft:
        return
    _run([nft, "delete", "table", "inet", "sg_awg_traffic"])
    _run([nft, "delete", "table", "ip", "sg_awg_traffic_nat"])


def _delete_policy_rules(profile_ids: set[int]) -> None:
    ip = shutil.which("ip")
    if not ip:
        return
    # Патч каскада: удаляем per-client source-based правила (диапазон 200-299).
    for priority in range(200, 300):
        while _run([ip, "rule", "del", "priority", str(priority)]).returncode == 0:
            pass
    # Патч каскада: удаляем правило для dnsmasq (priority 50).
    while _run([ip, "rule", "del", "priority", "50"]).returncode == 0:
        pass
    for outbound_id in sorted(profile_ids):
        priority = str(rule_priority_for(outbound_id))
        table = str(traffic_table_for(outbound_id))
        while True:
            result = _run([ip, "rule", "del", "priority", priority])
            if result.returncode != 0:
                break
        _run([ip, "route", "flush", "table", table])


def _known_profile_ids() -> set[int]:
    result = {int(row["id"]) for row in list_outbounds()}
    for path in _managed_config_paths():
        match = re.fullmatch(r"sgo([0-9]+)\.conf", path.name)
        if match:
            result.add(int(match.group(1)))
    return result


def _clear_egress_runtime_unlocked() -> None:
    profile_ids = _known_profile_ids()
    _delete_nft_tables()
    _delete_policy_rules(profile_ids)
    for path in reversed(_managed_config_paths()):
        with contextlib.suppress(Exception):
            _down_config(path)

    # Remove the managed DNS policy file as part of a complete traffic reset.
    # dnsmasq itself is not removed here because it may be used by another
    # subsystem; only SG-AWG-Panel's drop-in is deleted and the daemon is
    # reloaded/restarted when present.
    from .traffic_rules import DNSMASQ_CONFIG_PATH

    DNSMASQ_CONFIG_PATH.unlink(missing_ok=True)
    systemctl = shutil.which("systemctl")
    if systemctl:
        with contextlib.suppress(Exception):
            _run([systemctl, "disable", "--now", "dnsmasq.service"], timeout=30)


def clear_egress_runtime() -> None:
    _require_root()
    with _exclusive_traffic_lock():
        _clear_egress_runtime_unlocked()


def _write_outbound_configs(profiles) -> dict[int, Path]:
    OUTBOUND_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(OUTBOUND_CONFIG_DIR, 0o700)
    desired: dict[int, Path] = {}
    for profile in profiles:
        outbound_id = int(profile["id"])
        path = OUTBOUND_CONFIG_DIR / f"{interface_name_for(outbound_id)}.conf"
        temporary = path.with_suffix(".conf.new")
        temporary.write_text(str(profile["config_text"]), encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(path)
        desired[outbound_id] = path
    for path in _managed_config_paths():
        match = re.fullmatch(r"sgo([0-9]+)\.conf", path.name)
        if match and int(match.group(1)) not in desired:
            path.unlink(missing_ok=True)
    return desired


def _traffic_inputs():
    init_db()
    with connect() as con:
        settings = con.execute("SELECT * FROM awg_settings WHERE id=1").fetchone()
        clients = con.execute(f"SELECT * FROM awg_clients WHERE node_id IS NULL AND {db.ACTIVE_CLIENT_SQL} ORDER BY id").fetchall()
        profiles = con.execute(
            "SELECT * FROM outbounds WHERE enabled=1 ORDER BY id"
        ).fetchall()
    if settings is None:
        raise AWGPanelError("Настройки сервера не найдены")
    return settings, clients, profiles



def validate_outbound_config_runtime(config_text: str) -> dict[str, object]:
    """Validate an outbound as awg-quick would, without creating an interface."""
    parsed = parse_amneziawg_outbound_config(config_text)
    awg_quick = _command("awg-quick")
    with tempfile.TemporaryDirectory(prefix="sg-awg-outbound-check-") as directory:
        path = Path(directory) / "outbound.conf"
        path.write_text(parsed.config_text, encoding="utf-8")
        os.chmod(path, 0o600)
        _run([awg_quick, "strip", str(path)], timeout=20, check=True)
    return {"endpoint": parsed.endpoint, "address": parsed.address, "allowedIPs": parsed.allowed_ips}


def validate_egress_runtime(
    *,
    candidate_rules: list[dict[str, object]] | None = None,
    candidate_profiles: list[dict[str, object]] | None = None,
    candidate_clients: list[dict[str, object]] | None = None,
    candidate_settings: dict[str, object] | None = None,
) -> dict[str, object]:
    """Render and system-check traffic configuration without applying it."""
    settings_row, clients_rows, profile_rows = _traffic_inputs()
    settings = dict(settings_row)
    if candidate_settings:
        settings.update(candidate_settings)
    clients = [dict(row) for row in clients_rows] if candidate_clients is None else [dict(row) for row in candidate_clients if bool(dict(row).get("enabled", True))]
    profiles = [dict(row) for row in profile_rows] if candidate_profiles is None else [dict(row) for row in candidate_profiles if bool(dict(row).get("enabled", True))]

    with tempfile.TemporaryDirectory(prefix="sg-awg-traffic-check-") as directory:
        temp_root = Path(directory)
        awg_quick = _command("awg-quick")
        for profile in profiles:
            parsed = parse_amneziawg_outbound_config(str(profile["config_text"]))
            path = temp_root / f"sgo{int(profile['id'])}.conf"
            path.write_text(parsed.config_text, encoding="utf-8")
            os.chmod(path, 0o600)
            _run([awg_quick, "strip", str(path)], timeout=20, check=True)

        profile_by_id = {int(row["id"]): row for row in profiles}
        blocked: list[str] = []
        marked: list[tuple[str, int, str]] = []
        for client in clients:
            mode = normalize_egress_mode(client.get("egress_mode") or AWG_GATEWAY)
            if mode == "block":
                blocked.append(str(client["address"]))
            elif mode == "outbound":
                outbound_id = client.get("outbound_id")
                if outbound_id is None or int(outbound_id) not in profile_by_id:
                    raise AWGPanelError(f"Клиент {client.get('name', client.get('id', '?'))} ссылается на недоступный Outbound")
                marked.append((str(client["address"]), fwmark_for(int(outbound_id)), interface_name_for(int(outbound_id))))

        policy_rules = compile_rules() if candidate_rules is None else compile_rule_values(candidate_rules)
        for rule in policy_rules:
            if rule.list_kind and not (rule.list_items or rule.inline_domains or rule.inline_cidrs):
                raise AWGPanelError(f"Traffic List в правиле {rule.name} пуст")
            if rule.action_mode == "outbound" and (rule.outbound_id is None or int(rule.outbound_id) not in profile_by_id):
                raise AWGPanelError(f"Правило {rule.name} ссылается на недоступный Outbound")

        declarations, classification, guards, domain_map = render_rule_nft(
            inbound_interface=str(settings["interface_name"]), rules=policy_rules
        )
        dns_settings = get_dns_traffic_settings()
        protection_settings = get_traffic_controls_settings()
        dns_mode = str(dns_settings["mode"])
        if domain_map and dns_mode == "off":
            raise AWGPanelError("Доменные Traffic Rules требуют включённый DNS Control")
        script = render_nftables_script(
            inbound_interface=str(settings["interface_name"]),
            server_network=str(settings["server_network"]),
            blocked_addresses=blocked,
            marked_clients=marked,
            outbound_interfaces=[interface_name_for(int(profile["id"])) for profile in profiles],
            policy_declarations=declarations,
            policy_classification=classification,
            policy_guards=guards,
            dns_redirect=dns_mode == "redirect",
            dns_block_dot=bool(dns_settings["block_dot"]) and dns_mode != "off",
            **nft_options(protection_settings),
        )
        nft_path = temp_root / "traffic.nft"
        nft_path.write_text(script, encoding="utf-8")
        _run([_command("nft"), "-c", "-f", str(nft_path)], timeout=30, check=True)

        server_address = str(next(ipaddress.ip_network(str(settings["server_network"]), strict=True).hosts()))
        dns_text = render_dnsmasq_config(
            server_address=server_address,
            upstreams=str(dns_settings["upstreams"]),
            domain_map=domain_map,
        )
        dns_path = temp_root / "dnsmasq.conf"
        dns_path.write_text(dns_text, encoding="utf-8")
        dnsmasq = shutil.which("dnsmasq")
        if dnsmasq:
            _run([dnsmasq, "--test", f"--conf-file={dns_path}"], timeout=20, check=True)
    return {"rules": len(policy_rules), "outbounds": len(profiles), "clients": len(clients), "nft": "ok", "dnsmasq": "ok"}

def _apply_egress_runtime_unlocked() -> dict[str, object]:
    settings, clients, profiles = _traffic_inputs()
    known_ids = _known_profile_ids().union(int(row["id"]) for row in profiles)

    try:
        # Keep the previous nftables kill switch active while interfaces and
        # policy rules are rebuilt. The nftables rules are replaced later in
        # one transaction, so an outbound client cannot silently fall back to
        # текущий сервер during a normal profile change.
        _delete_policy_rules(known_ids)
        for path in reversed(_managed_config_paths()):
            _down_config(path)

        configs = _write_outbound_configs(profiles)
        awg_quick = _command("awg-quick")
        for path in configs.values():
            _run([awg_quick, "strip", str(path)], timeout=20, check=True)

        if not bool(settings["configured"]):
            return traffic_runtime_status()

        ip = _command("ip")
        nft = _command("nft")

        for profile in profiles:
            outbound_id = int(profile["id"])
            path = configs[outbound_id]
            _run([awg_quick, "up", str(path)], timeout=45, check=True)
            interface_name = interface_name_for(outbound_id)
            table = str(traffic_table_for(outbound_id))
            _run(
                [
                    ip,
                    "route",
                    "replace",
                    "default",
                    "dev",
                    interface_name,
                    "table",
                    table,
                ],
                check=True,
            )
            # Reverse packets inherit the connection mark. Keep the local AWG
            # client network reachable in the same policy table, otherwise the
            # reply would follow the marked default route back into the outbound.
            _run(
                [
                    ip,
                    "route",
                    "replace",
                    str(settings["server_network"]),
                    "dev",
                    str(settings["interface_name"]),
                    "table",
                    table,
                ],
                check=True,
            )
            _run(
                [
                    ip,
                    "rule",
                    "add",
                    "priority",
                    str(rule_priority_for(outbound_id)),
                    "fwmark",
                    hex(fwmark_for(outbound_id)),
                    "lookup",
                    str(traffic_table_for(outbound_id)),
                ],
                check=True,
            )

        profile_by_id = {int(row["id"]): row for row in profiles}
        blocked: list[str] = []
        marked: list[tuple[str, int, str]] = []
        for client in clients:
            mode = normalize_egress_mode(client["egress_mode"] or AWG_GATEWAY)
            if mode == "block":
                blocked.append(str(client["address"]))
            elif mode == "outbound":
                outbound_id = client["outbound_id"]
                if outbound_id is None or int(outbound_id) not in profile_by_id:
                    raise AWGPanelError(
                        f"Клиент {client['name']} ссылается на недоступный outbound"
                    )
                marked.append(
                    (
                        str(client["address"]),
                        fwmark_for(int(outbound_id)),
                        interface_name_for(int(outbound_id)),
                    )
                )

        # === Патч каскада: source-based routing per-client ===
        # Добавляем ip rule from <client_ip> lookup <table> как независимый слой.
        # Даже если nft-маркировка потеряется при пересборке панелью, клиент
        # останется в каскаде за счёт этого правила.
        client_outbound: dict[str, int] = {}
        for client in clients:
            mode = normalize_egress_mode(client["egress_mode"] or AWG_GATEWAY)
            if mode == "outbound":
                oid = client["outbound_id"]
                if oid is not None:
                    client_outbound[str(client["address"])] = int(oid)
        for index, (address, _mark, _iface) in enumerate(marked):
            outbound_id = client_outbound.get(address)
            if outbound_id is None:
                continue
            priority = 200 + index
            table = str(traffic_table_for(outbound_id))
            while _run([ip, "rule", "del", "priority", str(priority)]).returncode == 0:
                pass
            ip_only = str(address).split("/")[0]
            _run(
                [
                    ip,
                    "rule",
                    "add",
                    "priority",
                    str(priority),
                    "from",
                    f"{ip_only}/32",
                    "lookup",
                    table,
                ],
                check=True,
            )

        # === Патч каскада: вывод dnsmasq из-под source-based routing ===
        # dnsmasq на server_address отвечает на DNS-запросы клиентов. Если его
        # трафик попадёт в policy-table каскада, ответы не смогут вернуться.
        server_address = str(
            next(ipaddress.ip_network(str(settings["server_network"]), strict=True).hosts())
        )
        while _run([ip, "rule", "del", "priority", "50"]).returncode == 0:
            pass
        _run(
            [
                ip,
                "rule",
                "add",
                "priority",
                "50",
                "from",
                server_address,
                "lookup",
                "main",
            ],
            check=True,
        )

        # === Патч каскада: разрешение DNS в INPUT ===
        # После redirect/dnat DNS-пакеты становятся локальными (INPUT).
        # UFW с policy DROP их блокирует, если нет явного ACCEPT.
        iptables = shutil.which("iptables")
        if iptables:
            inbound_iface = str(settings["interface_name"])
            for proto in ("udp", "tcp"):
                check = _run(
                    [
                        iptables,
                        "-C",
                        "INPUT",
                        "-i",
                        inbound_iface,
                        "-p",
                        proto,
                        "--dport",
                        "53",
                        "-j",
                        "ACCEPT",
                    ]
                )
                if check.returncode != 0:
                    _run(
                        [
                            iptables,
                            "-I",
                            "INPUT",
                            "1",
                            "-i",
                            inbound_iface,
                            "-p",
                            proto,
                            "--dport",
                            "53",
                            "-j",
                            "ACCEPT",
                        ],
                        check=True,
                    )

        policy_rules = compile_rules()
        for rule in policy_rules:
            if rule.list_kind and not (rule.list_items or rule.inline_domains or rule.inline_cidrs):
                raise AWGPanelError(f"Traffic List в правиле {rule.name} пуст. Обновите список перед применением.")
            if rule.action_mode == "outbound" and (
                rule.outbound_id is None or int(rule.outbound_id) not in profile_by_id
            ):
                raise AWGPanelError(f"Правило {rule.name} ссылается на недоступный Outbound")
        policy_declarations, policy_classification, policy_guards, domain_map = render_rule_nft(
            inbound_interface=str(settings["interface_name"]), rules=policy_rules
        )
        dns_settings = get_dns_traffic_settings()
        protection_settings = get_traffic_controls_settings()
        dns_mode = str(dns_settings["mode"])
        if domain_map and dns_mode == "off":
            raise AWGPanelError("Доменные Traffic Rules требуют включённый DNS Control")
        nft_script = render_nftables_script(
            inbound_interface=str(settings["interface_name"]),
            server_network=str(settings["server_network"]),
            blocked_addresses=blocked,
            marked_clients=marked,
            outbound_interfaces=[
                interface_name_for(int(profile["id"])) for profile in profiles
            ],
            policy_declarations=policy_declarations,
            policy_classification=policy_classification,
            policy_guards=policy_guards,
            dns_redirect=dns_mode == "redirect",
            dns_server_address=server_address,
            dns_block_dot=bool(dns_settings["block_dot"]) and dns_mode != "off",
            **nft_options(protection_settings),
        )
        delete_lines: list[str] = []
        if _nft_table_present("inet", "sg_awg_traffic"):
            delete_lines.append("delete table inet sg_awg_traffic")
        if _nft_table_present("ip", "sg_awg_traffic_nat"):
            delete_lines.append("delete table ip sg_awg_traffic_nat")
        nft_transaction = (
            ("\n".join(delete_lines) + "\n" if delete_lines else "") + nft_script
        )

        TRAFFIC_STATE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(TRAFFIC_STATE_DIR, 0o700)
        temporary = NFT_SCRIPT_PATH.with_suffix(".nft.new")
        temporary.write_text(nft_transaction, encoding="utf-8")
        os.chmod(temporary, 0o600)
        _run([nft, "-c", "-f", str(temporary)], check=True)
        _run([nft, "-f", str(temporary)], check=True)
        temporary.replace(NFT_SCRIPT_PATH)
        server_address = str(next(ipaddress.ip_network(str(settings["server_network"]), strict=True).hosts()))
        apply_dnsmasq_runtime(server_address=server_address, domain_map=domain_map)
        return traffic_runtime_status()
    except Exception:
        # Do not remove the previous nftables guard here. The caller restores
        # the database and reapplies the previous runtime while the old kill
        # switch remains in place.
        with contextlib.suppress(Exception):
            _delete_policy_rules(known_ids)
        for path in reversed(_managed_config_paths()):
            with contextlib.suppress(Exception):
                _down_config(path)
        raise


def apply_egress_runtime() -> dict[str, object]:
    _require_root()
    with _exclusive_traffic_lock():
        return _apply_egress_runtime_unlocked()


def _interface_up(name: str) -> bool:
    ip = shutil.which("ip")
    if not ip:
        return False
    result = _run([ip, "link", "show", "dev", name])
    if result.returncode != 0:
        return False
    first_line = result.stdout.splitlines()[0] if result.stdout else ""
    flags = re.search(r"<([^>]+)>", first_line)
    return bool(flags and "UP" in {item.strip() for item in flags.group(1).split(",")})


def _nft_table_present(family: str, name: str) -> bool:
    nft = shutil.which("nft")
    if not nft:
        return False
    return _run([nft, "list", "table", family, name]).returncode == 0


def _rule_present(priority: int, table: int) -> bool:
    ip = shutil.which("ip")
    if not ip:
        return False
    result = _run([ip, "rule", "show"])
    if result.returncode != 0:
        return False
    pattern = re.compile(
        rf"^{priority}:.*\blookup\s+{table}\b", re.MULTILINE
    )
    return bool(pattern.search(result.stdout))


def traffic_runtime_status() -> dict[str, object]:
    init_db()
    profiles = list_outbounds()
    with connect() as con:
        rows = con.execute(
            "SELECT outbound_id, COUNT(*) AS count FROM awg_clients "
            f"WHERE node_id IS NULL AND egress_mode='outbound' AND outbound_id IS NOT NULL AND {db.ACTIVE_CLIENT_SQL} "
            "GROUP BY outbound_id"
        ).fetchall()
        blocked = con.execute(
            f"SELECT COUNT(*) AS count FROM awg_clients WHERE node_id IS NULL AND egress_mode='block' AND {db.ACTIVE_CLIENT_SQL}"
        ).fetchone()
    assigned = {int(row["outbound_id"]): int(row["count"]) for row in rows}
    profile_status: list[dict[str, object]] = []
    for profile in profiles:
        outbound_id = int(profile["id"])
        interface_name = interface_name_for(outbound_id)
        enabled = bool(profile["enabled"])
        up = _interface_up(interface_name) if enabled else False
        rule = (
            _rule_present(
                rule_priority_for(outbound_id), traffic_table_for(outbound_id)
            )
            if enabled
            else False
        )
        profile_status.append(
            {
                "id": outbound_id,
                "name": str(profile["name"]),
                "kind": str(profile["kind"]),
                "enabled": enabled,
                "endpoint": str(profile["endpoint"]),
                "address": str(profile["address"]),
                "interface_name": interface_name,
                "traffic_table": traffic_table_for(outbound_id),
                "fwmark": f"0x{fwmark_for(outbound_id):x}",
                "interface_up": up,
                "rule_present": rule,
                "assigned_clients": assigned.get(outbound_id, 0),
                "healthy": enabled and up and rule,
            }
        )
    nft_ready = _nft_table_present("inet", "sg_awg_traffic") and _nft_table_present(
        "ip", "sg_awg_traffic_nat"
    )
    from .traffic_rules import dns_runtime_status, list_traffic_rules, list_traffic_lists
    return {
        "profiles": profile_status,
        "nft_ready": nft_ready,
        "blocked_clients": int(blocked["count"] if blocked else 0),
        "active_profiles": sum(1 for item in profile_status if item["healthy"]),
        "policy_rules": len(list_traffic_rules(enabled_only=True)),
        "traffic_lists": len(list_traffic_lists(enabled_only=True)),
        "dns_control": dns_runtime_status(),
    }
