from __future__ import annotations

import argparse
import getpass
import os
import secrets
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

ENV_FILE = Path("/etc/sg-awg-panel/web.env")
PROJECT_DIR = Path("/opt/sg-awg-panel")
PANEL_SERVICE = "sg-awg-panel.service"
AWG_SERVICE = "sg-awg-server.service"
NGINX_SERVICE = "nginx.service"
AGENT_SERVICE = "sg-awg-node-agent.service"
MIN_PASSWORD_LENGTH = 8
MENU_WIDTH = 70


class _Colors:
    def __init__(self) -> None:
        enabled = bool(sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
        self.reset = "\033[0m" if enabled else ""
        self.bold = "\033[1m" if enabled else ""
        self.green = "\033[1;32m" if enabled else ""
        self.cyan = "\033[1;36m" if enabled else ""
        self.yellow = "\033[1;33m" if enabled else ""
        self.red = "\033[1;31m" if enabled else ""
        self.dim = "\033[2m" if enabled else ""


C = _Colors()


def _require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Запустите команду через sudo: sudo sg-awg-panel")


def _load_env_file(path: Path = ENV_FILE) -> None:
    if not path.is_file():
        raise SystemExit(f"Не найден файл настроек панели: {path}")
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        try:
            parsed = shlex.split(value, posix=True)
            value = parsed[0] if parsed else ""
        except ValueError:
            value = value.strip("'\"")
        os.environ[key] = value
    os.environ.setdefault("AWGPANEL_ENV_FILE", str(path))


def _run(*args: str, check: bool = False, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args), text=True, capture_output=True, check=check, timeout=timeout
    )


def _service_state(name: str) -> str:
    result = _run("systemctl", "is-active", name)
    return result.stdout.strip() or result.stderr.strip() or "unknown"


def _restart(name: str) -> None:
    result = _run("systemctl", "restart", name, timeout=90)
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or result.stdout.strip()
            or f"Не удалось перезапустить {name}"
        )


def _core():
    from . import core
    from .db import init_db

    init_db()
    return core


def _new_password() -> str:
    while True:
        first = getpass.getpass(
            f"Новый пароль администратора (минимум {MIN_PASSWORD_LENGTH} символов): "
        )
        second = getpass.getpass("Повторите новый пароль: ")
        if first != second:
            print("Пароли не совпадают. Повторите ввод.\n")
            continue
        if len(first) < MIN_PASSWORD_LENGTH:
            print(f"Пароль должен содержать не менее {MIN_PASSWORD_LENGTH} символов.\n")
            continue
        return first


def _rotate_browser_access(*, password_hash: str | None = None) -> None:
    core = _core()
    values: dict[str, object] = {"AWGPANEL_SECRET_KEY": secrets.token_urlsafe(48)}
    if password_hash is not None:
        values["AWGPANEL_PASSWORD_HASH"] = password_hash
    core.write_env_values(values)
    core.rotate_auth_epoch()
    os.chmod(ENV_FILE, 0o600)
    _restart(PANEL_SERVICE)


def command_password(_args: argparse.Namespace) -> int:
    from werkzeug.security import generate_password_hash

    password = _new_password()
    _rotate_browser_access(password_hash=generate_password_hash(password))
    print(f"{C.green}OK{C.reset} Пароль изменён. Все старые браузерные сессии завершены.")
    return 0


def command_sessions(_args: argparse.Namespace) -> int:
    _rotate_browser_access()
    print(f"{C.green}OK{C.reset} Все браузерные сессии и старые CSRF-токены сброшены.")
    print("Откройте страницу панели заново и войдите по паролю.")
    return 0


def command_repair_access(_args: argparse.Namespace) -> int:
    from werkzeug.security import generate_password_hash

    values: dict[str, object] = {"AWGPANEL_SECRET_KEY": secrets.token_urlsafe(48)}
    if not os.environ.get("AWGPANEL_PASSWORD_HASH", "").strip():
        print("Хеш пароля отсутствует. Требуется новый пароль.")
        values["AWGPANEL_PASSWORD_HASH"] = generate_password_hash(_new_password())
    core = _core()
    core.write_env_values(values)
    core.rotate_auth_epoch()
    os.chmod(ENV_FILE, 0o600)
    _restart(PANEL_SERVICE)
    print(
        f"{C.green}OK{C.reset} Доступ восстановлен: секрет сессий обновлён, "
        "старые сессии завершены."
    )
    return 0


def _state_mark(state: str) -> str:
    normalized = str(state or "unknown").strip().lower()
    if normalized == "active" or normalized == "online":
        return f"{C.green}●{C.reset} {normalized}"
    if normalized in {"inactive", "offline", "disabled", "not-installed"}:
        return f"{C.yellow}●{C.reset} {normalized}"
    return f"{C.red}●{C.reset} {normalized}"


def command_status(_args: argparse.Namespace) -> int:
    from . import __version__

    core = _core()
    try:
        settings = core.get_panel_settings()
        name = str(settings["instance_name"] or "SG-AWG-Panel")
        url = core.panel_public_url(settings)
    except Exception:
        name = "SG-AWG-Panel"
        url = "не удалось определить"
    print(f"{C.bold}{name}{C.reset}")
    print(f"Версия: {__version__}")
    print(f"Адрес панели: {url}")
    print(f"Panel: {_state_mark(_service_state(PANEL_SERVICE))}")
    print(f"AmneziaWG: {_state_mark(_service_state(AWG_SERVICE))}")
    print(f"Nginx: {_state_mark(_service_state(NGINX_SERVICE))}")
    print(f"Node Agent: {_state_mark(_service_state(AGENT_SERVICE))}")
    print(f"Файл настроек: {'OK' if ENV_FILE.is_file() else 'НЕ НАЙДЕН'}")
    print(
        f"Секрет сессий: {'OK' if os.environ.get('AWGPANEL_SECRET_KEY') else 'НЕ НАСТРОЕН'}"
    )
    return 0


def command_restart(_args: argparse.Namespace) -> int:
    _restart(PANEL_SERVICE)
    print(f"{C.green}OK{C.reset} Служба панели перезапущена.")
    return 0


def command_restart_all(_args: argparse.Namespace) -> int:
    for service in (AWG_SERVICE, PANEL_SERVICE, NGINX_SERVICE):
        _restart(service)
        print(f"{service}: {_state_mark(_service_state(service))}")
    if _run("systemctl", "is-enabled", AGENT_SERVICE).returncode == 0:
        _restart(AGENT_SERVICE)
        print(f"{AGENT_SERVICE}: {_state_mark(_service_state(AGENT_SERVICE))}")
    return 0


def command_backup(_args: argparse.Namespace) -> int:
    path = _core().create_manual_backup()
    print(f"{C.green}OK{C.reset} Резервная копия создана и проверена: {path}")
    return 0


def _backups() -> list[dict[str, object]]:
    return _core().list_backups(limit=200)


def command_backups(_args: argparse.Namespace) -> int:
    items = _backups()
    if not items:
        print("Резервных копий нет.")
        return 0
    for index, item in enumerate(items, 1):
        mark = "OK" if item.get("verified") else "ОШИБКА"
        print(f"{index:>3}. {item['name']}  {item.get('size_text', '')}  {mark}")
    return 0



def command_verify_backup(args: argparse.Namespace) -> int:
    items = _backups()
    if not items:
        raise RuntimeError("Резервных копий нет")
    name = str(getattr(args, "name", None) or "").strip()
    if not name:
        command_backups(args)
        choice = input("Номер резервной копии для проверки (Enter — отмена): ").strip()
        if not choice:
            print("Отменено.")
            return 0
        if not choice.isdigit() or not 1 <= int(choice) <= len(items):
            raise RuntimeError("Некорректный номер резервной копии")
        name = str(items[int(choice) - 1]["name"])
    result = _core().verify_backup(name)
    print(f"Резервная копия: {name}")
    print(f"Файлов: {result.get('file_count', 0)}")
    print(f"Размер: {result.get('size_text') or result.get('size_bytes', 0)}")
    print(f"Версия: {result.get('backup_version') or 'не определена'}")
    checks = result.get("checks") if isinstance(result.get("checks"), dict) else {}
    for label, value in checks.items():
        print(f"{label}: {'OK' if value else 'ОШИБКА'}")
    if not result.get("verified"):
        for error in result.get("verification_errors", []):
            print(f"{C.red}ОШИБКА{C.reset} {error}")
        raise RuntimeError("Резервная копия повреждена или несовместима")
    print(f"{C.green}OK{C.reset} Резервная копия исправна. Можно восстанавливать.")
    return 0

def command_restore(args: argparse.Namespace) -> int:
    items = _backups()
    if not items:
        raise RuntimeError("Резервных копий нет")
    name = str(getattr(args, "name", None) or "").strip()
    if not name:
        command_backups(args)
        choice = input("Номер резервной копии для восстановления (Enter — отмена): ").strip()
        if not choice:
            print("Отменено.")
            return 0
        if not choice.isdigit() or not 1 <= int(choice) <= len(items):
            raise RuntimeError("Некорректный номер резервной копии")
        name = str(items[int(choice) - 1]["name"])
    phrase = input(f"Для восстановления {name} введите RESTORE: ").strip()
    if phrase != "RESTORE":
        print("Отменено.")
        return 0
    restored = _core().restore_backup(name)
    _restart(PANEL_SERVICE)
    print(f"{C.green}OK{C.reset} Восстановлено: {restored}")
    return 0


def command_logs(args: argparse.Namespace) -> int:
    lines = max(20, min(1000, int(getattr(args, "lines", 100))))
    result = _run("journalctl", "-u", PANEL_SERVICE, "-n", str(lines), "--no-pager")
    sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result.returncode


def command_server_name(args: argparse.Namespace) -> int:
    name = str(getattr(args, "name", None) or "").strip()
    if not name:
        name = input("Новое понятное имя сервера: ").strip()
    settings = _core().configure_instance_name(name)
    _restart(PANEL_SERVICE)
    print(f"{C.green}OK{C.reset} Имя сервера изменено: {settings['instance_name']}")
    return 0


def _clip(value: object, width: int) -> str:
    text = str(value or "").replace("\n", " ").strip()
    if len(text) <= width:
        return text
    return text[: max(1, width - 1)] + "…"


def command_clients(_args: argparse.Namespace) -> int:
    overview = _core().get_awg_overview()
    clients = list(overview.get("clients") or [])
    if not clients:
        print("Клиентов пока нет.")
        return 0
    online = sum(1 for item in clients if item.get("online"))
    errors = sum(1 for item in clients if str(item.get("deployment_state") or "") == "error")
    print(
        f"Всего: {len(clients)} · В сети: {online} · Ошибки применения: {errors} · "
        f"RX: {overview.get('total_rx_text', '0 B')} · TX: {overview.get('total_tx_text', '0 B')}"
    )
    print("\n ID  КЛИЕНТ                    СЕРВЕР             СОСТОЯНИЕ       МАРШРУТ")
    print(" " + "─" * 78)
    for item in clients:
        deployment = str(item.get("deployment_state") or "active")
        if deployment == "error":
            state = "Ошибка"
        elif deployment in {"queued", "deleting"}:
            state = "Ожидает"
        elif not item.get("effective_enabled"):
            state = "Отключён"
        elif item.get("online"):
            state = "В сети"
        else:
            state = "Нет handshake"
        egress = str(item.get("egress_mode") or "awg_gateway")
        route = {"awg_gateway": "Direct", "block": "Block", "outbound": "Cascade/Outbound"}.get(
            egress, egress
        )
        print(
            f"{int(item.get('id') or 0):>3}  "
            f"{_clip(item.get('name'), 25):<25} "
            f"{_clip(item.get('server_name'), 18):<18} "
            f"{state:<15} {route}"
        )
        if deployment == "error" and item.get("deployment_error"):
            print(f"     {C.red}{_clip(item.get('deployment_error'), 72)}{C.reset}")
    return 0


def command_cluster(_args: argparse.Namespace) -> int:
    from .node_manager import collapse_duplicate_nodes, list_nodes

    rows, hidden = collapse_duplicate_nodes(list_nodes())
    if not rows:
        print("Записей Cluster пока нет.")
        return 0
    remote = [item for item in rows if not item.get("is_local")]
    online = sum(1 for item in remote if item.get("online"))
    print(f"SG-Node: {len(remote)} · В сети: {online} · Скрыто старых дублей: {hidden}")
    print("\n ID  СЕРВЕР                     РОЛЬ        СОСТОЯНИЕ   АДРЕС              AGENT")
    print(" " + "─" * 86)
    for item in rows:
        role = "Controller" if item.get("is_local") else "SG-Node"
        state = "online" if item.get("is_local") else str(item.get("effective_state") or "pending")
        address = item.get("public_ipv4") or item.get("public_host") or "—"
        agent = item.get("agent_version") or ("built-in" if item.get("is_local") else "—")
        print(
            f"{int(item.get('id') or 0):>3}  {_clip(item.get('name'), 26):<26} "
            f"{role:<11} {state:<11} {_clip(address, 18):<18} {_clip(agent, 16)}"
        )
        if item.get("last_error"):
            print(f"     {C.red}{_clip(item.get('last_error'), 82)}{C.reset}")
    return 0


def command_cascade(_args: argparse.Namespace) -> int:
    from .cascade import cascade_document
    from .cluster_cascade import list_cascade_links

    data = cascade_document()
    print(f"Внешний Cascade: {'включён' if data.get('enabled') else 'выключен'}")
    print(f"Сервер выхода: {data.get('exit_name') or 'не настроен'}")
    print(f"Адрес выхода: {data.get('exit_host') or '—'}")
    print(f"Назначено клиентов: {data.get('assigned_clients') or 0}")
    print(f"Последнее состояние: {data.get('last_state') or 'not_configured'}")
    print(f"Подтверждённый внешний IP: {data.get('last_exit_ip') or '—'}")
    if data.get("last_error"):
        print(f"Ошибка сервера: {C.red}{data.get('last_error')}{C.reset}")
    if data.get("last_client_error"):
        print(f"Проверка клиента: {C.red}{data.get('last_client_error')}{C.reset}")

    links = list_cascade_links(include_disabled=True)
    print(f"\nCluster Cascade links: {len(links)}")
    for link in links:
        entry_node = link.get("entry") or {}
        exit_node = link.get("exit") or {}
        entry = entry_node.get("name") or f"Node #{link.get('entry_node_id')}"
        exit_name = exit_node.get("name") or f"Node #{link.get('exit_node_id')}"
        state = link.get("state") or "unknown"
        enabled = "ON" if link.get("enabled") else "OFF"
        print(f"  #{link.get('id')}  {entry} → {exit_name}  {enabled}  {state}")
        if link.get("last_error"):
            print(f"       {C.red}{_clip(link.get('last_error'), 72)}{C.reset}")
    return 0


def command_update(_args: argparse.Namespace) -> int:
    core = _core()
    info = core.check_for_updates(force=True)
    print(f"Текущая версия: {info.get('current')}")
    print(f"Последняя версия: {info.get('latest')}")
    if info.get("error"):
        raise RuntimeError(f"Не удалось проверить GitHub: {info.get('error')}")
    if not info.get("available"):
        print(f"{C.green}OK{C.reset} Обновление не требуется.")
        return 0
    latest = str(info.get("latest") or "")
    phrase = input(f"Для обновления до {latest} введите UPDATE: ").strip()
    if phrase != "UPDATE":
        print("Отменено.")
        return 0
    started = core.start_panel_update(latest)
    print(f"{C.green}OK{C.reset} Обновление {started['version']} запущено.")
    print("Панель создаст резервную копию и автоматически откатится при ошибке.")
    return 0


def command_myfakesite(_args: argparse.Namespace) -> int:
    print(f"\n{C.bold}--- Установка защиты MyFakeSite (Anti-Probing) ---{C.reset}")
    
    domain_input = input("У вас есть домен, привязанный к этому серверу? (y/n): ").strip().lower()
    domain = ""
    
    if domain_input in ("y", "yes", "д", "да"):
        domain = input("Введите домен (например, vpn.example.com): ").strip()
        if not domain:
            print("Домен не указан. Отмена.")
            return 1
        cert_path = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        if not cert_path.is_file():
            raise RuntimeError(f"Сертификат Let's Encrypt для {domain} не найден. Сначала выпустите его (certbot).")
        print(f"Используем домен: {domain}")
    else:
        print("Защита будет установлена без домена (с самоподписанным сертификатом).\n")

    script = PROJECT_DIR / "deploy" / "myfakesite" / "install.sh"
    if not script.is_file():
        raise RuntimeError(f"Не найден скрипт установки MyFakeSite: {script}")

    print("Запуск установки (это может занять пару минут)...")
    cmd = ["bash", str(script)]
    if domain:
        cmd.append(domain)

    # Даем 10 минут на скачивание Docker-образов и запуск
    result = _run(*cmd, timeout=600)
    
    sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)

    if result.returncode == 0:
        print(f"\n{C.green}OK{C.reset} MyFakeSite успешно установлен!")
        print("Сканеры теперь будут видеть фейковое облако MySphere.")
        return 0
    else:
        raise RuntimeError(f"Ошибка при установке MyFakeSite (код выхода {result.returncode})")


def command_uninstall(_args: argparse.Namespace) -> int:
    script = PROJECT_DIR / "uninstall.sh"
    if not script.is_file():
        raise RuntimeError(f"Не найден деинсталлятор: {script}")
    print(f"{C.red}{C.bold}ВНИМАНИЕ: будет полностью удалена панель и все её данные.{C.reset}")
    print("Следующий экран запросит длинную фразу подтверждения.")
    os.execv("/bin/bash", ["bash", str(script)])
    return 0


def _visible_len(text: str) -> int:
    # Menu labels do not contain escape sequences; this helper keeps the box code explicit.
    return len(text)


def _box_row(text: str = "") -> str:
    content = _clip(text, MENU_WIDTH - 4)
    return f"│ {content}{' ' * (MENU_WIDTH - 4 - _visible_len(content))} │"


def _menu_header() -> list[str]:
    from . import __version__

    try:
        core = _core()
        settings = core.get_panel_settings()
        name = str(settings["instance_name"] or "SG-AWG-Panel")
        url = core.panel_public_url(settings)
    except Exception:
        name = "SG-AWG-Panel"
        url = "адрес не определён"
    services = (
        f"Panel {_service_state(PANEL_SERVICE)} · AWG {_service_state(AWG_SERVICE)} · "
        f"Agent {_service_state(AGENT_SERVICE)}"
    )
    return [
        "╭" + "─" * (MENU_WIDTH - 2) + "╮",
        _box_row(f"SG-AWG-PANEL {__version__} · УПРАВЛЕНИЕ СЕРВЕРОМ"),
        "├" + "─" * (MENU_WIDTH - 2) + "┤",
        _box_row(name),
        _box_row(url),
        _box_row(services),
        "├" + "─" * (MENU_WIDTH - 2) + "┤",
    ]


def _menu_items() -> list[tuple[str, str, Callable[[argparse.Namespace], int], str]]:
    return [
        ("1", "Состояние панели и адрес", command_status, "normal"),
        ("2", "Перезапустить веб-панель", command_restart, "normal"),
        ("3", "Перезапустить Panel, AWG, Nginx и Agent", command_restart_all, "normal"),
        ("4", "Сменить пароль администратора", command_password, "accent"),
        ("5", "Сбросить браузерные сессии и CSRF", command_sessions, "accent"),
        ("6", "Проверить клиентов и подключения", command_clients, "normal"),
        ("7", "Проверить Cluster и SG-Node", command_cluster, "normal"),
        ("8", "Проверить Cascade", command_cascade, "normal"),
        ("9", "Создать резервную копию", command_backup, "normal"),
        ("10", "Проверить резервную копию", command_verify_backup, "normal"),
        ("11", "Восстановить резервную копию", command_restore, "warning"),
        ("12", "Переименовать сервер", command_server_name, "normal"),
        ("13", "Проверить и установить обновление", command_update, "warning"),
        ("14", "Полностью удалить SG-AWG-Panel", command_uninstall, "danger"),
        ("15", "Установить защиту MyFakeSite (Anti-Probing)", command_myfakesite, "normal"),
    ]


def _menu() -> int:
    actions = {key: (label, handler, kind) for key, label, handler, kind in _menu_items()}
    while True:
        if sys.stdout.isatty():
            print("\033[2J\033[H", end="")
        for line in _menu_header():
            print(f"{C.cyan}{line}{C.reset}" if line.startswith(("╭", "├", "│")) else line)
        for key, label, _handler, kind in _menu_items():
            number_color = C.red if kind == "danger" else C.yellow if kind in {"warning", "accent"} else C.cyan
            label_color = C.red if kind == "danger" else C.reset
            plain = f"{key:>2}. {label}"
            padding = " " * max(0, MENU_WIDTH - 4 - len(plain))
            print(f"{C.cyan}│{C.reset} {number_color}{key:>2}{C.reset}. {label_color}{label}{C.reset}{padding} {C.cyan}│{C.reset}")
        exit_plain = " 0. Выход"
        print(f"{C.cyan}│{C.reset} {C.dim}{exit_plain}{C.reset}{' ' * (MENU_WIDTH - 4 - len(exit_plain))} {C.cyan}│{C.reset}")
        print(f"{C.cyan}╰{'─' * (MENU_WIDTH - 2)}╯{C.reset}")
        choice = input("\nВыберите действие: ").strip()
        if choice == "0":
            return 0
        item = actions.get(choice)
        if item is None:
            print(f"{C.red}Неизвестный пункт.{C.reset}")
            time.sleep(1)
            continue
        try:
            args = argparse.Namespace(name=None, lines=100)
            item[1](args)
        except (KeyboardInterrupt, EOFError):
            print("\nОтменено.")
        except Exception as exc:
            print(f"{C.red}Ошибка: {exc}{C.reset}", file=sys.stderr)
        input("\nНажмите Enter для возврата в меню...")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sg-awg-panel", description="Администрирование SG-AWG-Panel через SSH"
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("status", help="состояние служб и адрес панели")
    sub.add_parser("password", help="сбросить пароль администратора")
    sub.add_parser("sessions", help="завершить все браузерные сессии и сбросить CSRF")
    sub.add_parser("repair-access", help="восстановить секрет сессий и доступ к панели")
    sub.add_parser("restart", help="перезапустить панель")
    sub.add_parser("restart-all", help="перезапустить основные службы")
    sub.add_parser("backup", help="создать резервную копию")
    sub.add_parser("backups", help="показать резервные копии")
    verify = sub.add_parser("verify-backup", help="проверить резервную копию без восстановления")
    verify.add_argument("name", nargs="?")
    restore = sub.add_parser("restore", help="восстановить резервную копию")
    restore.add_argument("name", nargs="?")
    logs = sub.add_parser("logs", help="показать журнал панели")
    logs.add_argument("--lines", type=int, default=100)
    sub.add_parser("clients", help="проверить клиентов и подключения")
    sub.add_parser("cluster", help="проверить Cluster и SG-Node")
    sub.add_parser("cascade", help="проверить Cascade")
    sub.add_parser("update", help="проверить и запустить обновление")
    sub.add_parser("myfakesite", help="установить защиту MyFakeSite (Anti-Probing)")
    sub.add_parser("uninstall", help="полностью удалить SG-AWG-Panel")
    rename = sub.add_parser("server-name", help="изменить имя сервера")
    rename.add_argument("name", nargs="?")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    _require_root()
    _load_env_file()
    handlers = {
        "status": command_status,
        "password": command_password,
        "sessions": command_sessions,
        "repair-access": command_repair_access,
        "restart": command_restart,
        "restart-all": command_restart_all,
        "backup": command_backup,
        "backups": command_backups,
        "verify-backup": command_verify_backup,
        "restore": command_restore,
        "logs": command_logs,
        "clients": command_clients,
        "cluster": command_cluster,
        "cascade": command_cascade,
        "update": command_update,
        "myfakesite": command_myfakesite,
        "uninstall": command_uninstall,
        "server-name": command_server_name,
    }
    if not args.command:
        return _menu()
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        print("\nОтменено.")
        return 130
    except Exception as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
