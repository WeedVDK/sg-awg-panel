
import hashlib
import json
import io
import os
import re
import secrets
import subprocess
import tarfile
import html as html_module
import threading
import time
from ua_extract import DeviceDetector
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import quote, urlsplit

from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    stream_with_context,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from markupsafe import Markup, escape

from . import __version__
from .core import (
    add_awg_client,
    build_diagnostic_report,
    bulk_update_awg_clients,
    client_lifecycle,
    configure_and_start_awg,
    configure_backup_policy,
    configure_access_document,
    configure_access_links,
    configure_instance_name,
    create_web_session,
    create_manual_backup,
    delete_awg_client,
    detect_public_ipv4,
    find_awg_client,
    find_client_by_access_token,
    get_awg_diagnostics,
    get_awg_overview,
    get_awg_settings,
    get_panel_settings,
    get_system_resources,
    get_panel_access_job,
    get_update_status,
    find_backup_path,
    list_awg_clients,
    list_auth_events,
    list_backups,
    list_web_sessions,
    read_placeholder_html,
    save_placeholder_html,
    reset_placeholder_html,
    default_placeholder_html,
    verify_backup,
    panel_public_url,
    record_auth_event,
    record_client_access,
    regenerate_awg_client,
    regenerate_client_access_token,
    render_awg_client_config,
    restart_awg,
    revoke_all_web_sessions,
    revoke_web_session,
    rotate_auth_epoch,
    restore_backup,
    set_awg_client_enabled,
    set_client_access_enabled,
    start_awg,
    start_panel_update,
    start_panel_access_job,
    stop_awg,
    update_awg_client_settings,
    update_awg_client_document,
    validate_awg_client_document,
    validate_awg_settings_document,
    update_dns_servers,
    update_ip_allowlist,
    validate_web_session,
    check_for_updates,
    ip_is_allowed,
    get_client_traffic_history,
    get_client_period_stats)
from .db import init_db
from .geography import (
    country_display, country_flag, country_flag_asset, country_name,
    detect_country_code, normalize_country_code,
)
from .cascade import (
    assign_cascade_clients,
    cascade_document,
    configure_cascade,
    configure_cascade_from_link,
    create_exit_enrollment,
    create_exit_service_client,
    disable_cascade,
    get_cascade_settings,
    get_active_exit_enrollment,
    get_exit_service_client,
    remove_exit_service_client,
    test_cascade,
    test_cascade_client,
)
from .cluster_cascade import (
    cascade_servers,
    create_cascade_link as create_cluster_cascade_link,
    disable_cascade_link as disable_cluster_cascade_link,
    get_cascade_link as get_cluster_cascade_link,
    list_cascade_links,
    reconcile_all_cascades,
    test_cascade_link as test_cluster_cascade_link,
)
from .node_clients import queue_initial_pool_sync
from .node_manager import (
    authenticate_agent,
    claim_next_job,
    cleanup_duplicate_pending_nodes,
    collapse_duplicate_nodes,
    create_node,
    delete_node,
    enroll_node,
    enrollment_command,
    ensure_local_node,
    finish_job,
    find_remote_node_by_name,
    get_node,
    heartbeat,
    list_jobs,
    list_nodes,
    queue_job,
    renew_enrollment,
    set_node_country,
    set_node_enabled,
    set_node_name,
)
from .egress import (
    apply_egress_runtime,
    create_outbound,
    delete_outbound,
    find_outbound,
    list_outbounds,
    mutate_traffic_and_apply,
    replace_outbound,
    traffic_runtime_status,
    validate_egress_runtime,
    validate_outbound_config_runtime,
    set_client_egress,
    set_outbound_enabled,
)
from .traffic_rules import (
    delete_traffic_rule,
    ensure_rule_dns_control,
    find_traffic_rule,
    list_traffic_rules,
    next_rule_priority,
    parse_traffic_rule_json_document,
    parse_rules_json_document,
    replace_rules_document,
    reorder_traffic_rules,
    traffic_rule_json_document,
    rule_supports_simple_editor,
    rules_json_document,
    save_traffic_rule,
)
from .errors import AWGPanelError
from .operation_jobs import get_operation_job, start_operation_job
from .traffic_modes import AWG_GATEWAY, egress_mode_label, normalize_egress_mode
from .config_manager import (
    apply_panel_config_document,
    generated_configs,
    panel_config_document,
    parse_panel_config_document,
    section_json_configs,
    validate_panel_config_document,
)
from .json_editors import (
    access_json_document,
    backup_json_document,
    client_json_document,
    dns_json_document,
    outbound_json_document,
    parse_access_json_document,
    parse_backup_json_document,
    parse_client_json_document,
    parse_dns_json_document,
    parse_outbound_json_document,
    parse_security_json_document,
    parse_server_json_document,
    security_json_document,
    server_json_document,
)
from .server_profiles import (
    detect_masking_profile,
    profile_values,
    readable_changes,
    server_change_summary,
)


MIN_PASSWORD_LENGTH = 8


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _safe_filename(name: str) -> str:
    value = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in name)
    return value.strip("-.") or "client"


def _qr_svg_response(value: str) -> Response:
    try:
        import qrcode
        from qrcode.image.svg import SvgPathImage
    except ImportError as exc:  # pragma: no cover - installer provides dependency
        raise RuntimeError("Модуль QR-кодов не установлен") from exc
    image = qrcode.make(value, image_factory=SvgPathImage, error_correction=qrcode.constants.ERROR_CORRECT_L)
    stream = io.BytesIO()
    image.save(stream)
    response = Response(stream.getvalue(), mimetype="image/svg+xml")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    return response


def _profile_response_headers(response: Response, *, profile_name: str, filename: str) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    response.headers["X-SG-Profile-Name"] = quote(profile_name, safe="/._-")
    response.headers["X-SG-Profile-Name-Encoding"] = "percent-utf8"
    response.headers["X-SG-Profile-Type"] = "amneziawg"
    response.headers["X-SG-Profile-Filename"] = quote(filename, safe="._-")
    return response


def _inline_content_disposition(filename: str) -> str:
    ascii_name = secure_filename(filename) or "sg-awg-profile.conf"
    encoded = quote(filename, safe="")
    return f"inline; filename=\"{ascii_name}\"; filename*=UTF-8''{encoded}"


def _write_env_value(key: str, value: str) -> None:
    env_path = Path(os.environ.get("AWGPANEL_ENV_FILE", "/etc/sg-awg-panel/web.env"))
    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    replaced = False
    output: list[str] = []
    for line in lines:
        if line.startswith(f"{key}="):
            output.append(f"{key}={value}")
            replaced = True
        else:
            output.append(line)
    if not replaced:
        output.append(f"{key}={value}")
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("\n".join(output) + "\n", encoding="utf-8")
    os.chmod(env_path, 0o600)


def _expiry_from_form(
    form, *, prefix: str = "", current_expiry: object | None = None
) -> str | None:
    mode = str(form.get(f"{prefix}expiration_mode", "unlimited")).strip().lower()
    if mode in {"", "unlimited", "none"}:
        return None
    if mode == "period":
        raw_days = str(form.get(f"{prefix}duration_days", "30")).strip()
        try:
            days = int(raw_days)
        except ValueError as exc:
            raise ValueError("Период действия должен быть указан в днях") from exc
        if days not in {1, 7, 30, 90, 365}:
            raise ValueError("Выберите поддерживаемый период действия")
        now = datetime.now(timezone.utc)
        base = now
        if current_expiry:
            try:
                current = datetime.fromisoformat(
                    str(current_expiry).replace(" ", "T").replace("Z", "+00:00")
                )
                if current.tzinfo is None:
                    current = current.replace(tzinfo=timezone.utc)
                current = current.astimezone(timezone.utc)
                if current > now:
                    base = current
            except ValueError:
                pass
        return (base + timedelta(days=days)).replace(microsecond=0).isoformat()
    if mode != "date":
        raise ValueError("Неизвестный режим срока действия")

    utc_value = str(form.get(f"{prefix}expires_at_utc", "")).strip()
    if utc_value:
        try:
            moment = datetime.fromisoformat(utc_value[:-1] + "+00:00" if utc_value.endswith("Z") else utc_value)
        except ValueError as exc:
            raise ValueError("Некорректная дата окончания доступа") from exc
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat()

    local_value = str(form.get(f"{prefix}expires_at_local", "")).strip()
    if not local_value:
        raise ValueError("Выберите дату и время окончания")
    try:
        local_moment = datetime.fromisoformat(local_value)
        offset = int(str(form.get(f"{prefix}timezone_offset", "0")))
    except (ValueError, TypeError) as exc:
        raise ValueError("Некорректная дата окончания доступа") from exc
    return (local_moment + timedelta(minutes=offset)).replace(tzinfo=timezone.utc, microsecond=0).isoformat()



def _json_reason_ru(reason: str) -> str:
    value = str(reason or "").strip()
    translations = {
        "Expecting property name enclosed in double quotes": "Ожидалось имя свойства в двойных кавычках",
        "Expecting ',' delimiter": "Ожидалась запятая",
        "Expecting ':' delimiter": "Ожидалось двоеточие",
        "Expecting value": "Ожидалось значение",
        "Extra data": "После завершения JSON обнаружены лишние данные",
    }
    if value in translations:
        return translations[value]
    if value.startswith("Unterminated string"):
        return "Незавершённая строка"
    return value

def _json_validation_error_payload(exc: Exception) -> dict[str, object]:
    message = str(exc) or "Проверка JSON завершилась ошибкой"
    payload: dict[str, object] = {"ok": False, "message": message}
    if isinstance(exc, json.JSONDecodeError):
        payload.update({
            "kind": "syntax",
            "line": int(exc.lineno),
            "column": int(exc.colno),
            "reason": _json_reason_ru(str(exc.msg)),
            "path": "$",
        })
        return payload
    syntax = re.match(
        r"^JSON: строка (\d+), столбец (\d+):\s*(.*)$",
        message,
    )
    if syntax:
        payload.update({
            "kind": "syntax",
            "line": int(syntax.group(1)),
            "column": int(syntax.group(2)),
            "reason": _json_reason_ru(syntax.group(3)),
            "path": "$",
        })
        return payload
    explicit_path = re.match(r"^([^:]{1,160}):\s*(.+)$", message)
    if explicit_path and (
        explicit_path.group(1) == "$"
        or "." in explicit_path.group(1)
        or "[" in explicit_path.group(1)
        or explicit_path.group(1).startswith("_")
    ):
        payload.update({
            "kind": "schema",
            "path": explicit_path.group(1).strip(),
            "reason": explicit_path.group(2).strip(),
        })
        return payload
    inferred_path = re.match(
        r"^([A-Za-z_$][A-Za-z0-9_$.-]*(?:\[[0-9]+\])?)\s+"
        r"(должен|должна|должно|не может|обязателен|обязательна|не совпадает)(.*)$",
        message,
    )
    if inferred_path:
        payload.update({
            "kind": "schema",
            "path": inferred_path.group(1),
            "reason": " ".join(inferred_path.groups()[1:]).strip(),
        })
    else:
        payload.update({"kind": "runtime", "reason": message})
    return payload


class CSRFTokenError(Exception):
    """Raised when a browser submits a stale or foreign panel form."""


def _session_cookie_name(secret_key: str) -> str:
    """Use an install-specific cookie name so panels never share sessions."""
    suffix = hashlib.sha256(secret_key.encode("utf-8")).hexdigest()[:12]
    return f"sg_awg_session_{suffix}"


def create_app() -> Flask:
    app = Flask(__name__)

    secret_key = os.environ.get("AWGPANEL_SECRET_KEY", "").strip()
    if not secret_key:
        raise RuntimeError(
            "AWGPANEL_SECRET_KEY is missing. Run: sudo sg-awg-panel repair-access"
        )
    app.secret_key = secret_key
    app.config.update(
        SESSION_COOKIE_NAME=os.environ.get("AWGPANEL_SESSION_COOKIE_NAME")
        or _session_cookie_name(secret_key),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=_bool_env("AWGPANEL_SECURE_COOKIES", False),
        MAX_CONTENT_LENGTH=256 * 1024,
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    )
    if _bool_env("AWGPANEL_TRUST_PROXY_HEADERS", False):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)  # type: ignore[assignment]

    init_db()
    login_attempts: dict[str, list[float]] = {}
    login_lock = threading.Lock()
    login_window = 15 * 60
    login_limit = 5

    def client_ip() -> str:
        return request.remote_addr or "unknown"

    def client_agent() -> str:
        return request.headers.get("User-Agent", "")[:512]

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            token = str(session.get("session_token", ""))
            if not session.get("authenticated") or validate_web_session(token) is None:
                session.clear()
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)

        return wrapped

    def csrf_token() -> str:
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    def require_csrf() -> None:
        expected = str(session.get("csrf_token", ""))
        provided = str(request.form.get("csrf_token", ""))
        if not expected or not provided or not secrets.compare_digest(expected, provided):
            raise CSRFTokenError

    def issue_json_validation_ticket(scope: str, source: str) -> str:
        """Bind a one-time validation ticket to the exact JSON text."""
        token = secrets.token_urlsafe(32)
        session[f"json_validation_ticket:{scope}"] = {
            "token": token,
            "digest": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        }
        session.modified = True
        return token

    def clear_json_validation_ticket(scope: str) -> None:
        session.pop(f"json_validation_ticket:{scope}", None)
        session.modified = True

    def require_json_validation_ticket(scope: str, source: str, provided: str) -> None:
        """Reject every save that was not validated for this exact text."""
        key = f"json_validation_ticket:{scope}"
        record = session.pop(key, None)
        session.modified = True
        if not isinstance(record, dict):
            raise ValueError("Сначала выполните проверку текущего JSON")
        expected_token = str(record.get("token") or "")
        expected_digest = str(record.get("digest") or "")
        actual_digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if (
            not provided
            or not expected_token
            or not secrets.compare_digest(expected_token, provided)
            or not expected_digest
            or not secrets.compare_digest(expected_digest, actual_digest)
        ):
            raise ValueError("JSON изменён после проверки. Выполните проверку ещё раз")

    def validate_json_submission(scope: str, source: str, validator):
        """Run the real validator and issue a ticket for this exact JSON text."""
        clear_json_validation_ticket(scope)
        result = validator()
        token = issue_json_validation_ticket(scope, source)
        return result, token

    def require_validated_json_submission(
        scope: str, source: str, provided: str, validator
    ):
        """Require a one-time ticket and repeat validation before applying."""
        require_json_validation_ticket(scope, source, provided)
        return validator()

    def json_editor_error(exc: Exception) -> dict[str, object]:
        return _json_validation_error_payload(exc)

    def unit_states(names: list[str]) -> dict[str, str]:
        if app.config.get("TESTING"):
            return {name: "active" for name in names}
        try:
            result = subprocess.run(
                ["systemctl", "is-active", *names], capture_output=True, text=True,
                check=False, timeout=4,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {name: "unknown" for name in names}
        values = [line.strip() or "inactive" for line in result.stdout.splitlines()]
        values.extend(["inactive"] * max(0, len(names) - len(values)))
        return dict(zip(names, values, strict=False))

    def global_system_status() -> dict[str, object]:
        # sqlite3.Row supports indexed access but not dict.get().  Convert it
        # before building the global status badge so every authenticated page
        # can render after an upgrade.
        settings = dict(get_awg_settings())
        if not bool(settings.get("configured", True)):
            return {
                "class": "warning", "label": "ПЕРВЫЙ ЗАПУСК",
                "count": 0, "href": url_for("system_page", tab="logs-diagnostics"),
            }
        units = [
            "sg-awg-panel.service", "sg-awg-server.service",
            "sg-awg-traffic.service", "nginx.service",
        ]
        raw_states = unit_states(units)
        states = {
            "panel": raw_states[units[0]],
            "server": raw_states[units[1]],
            "traffic": raw_states[units[2]],
            "nginx": raw_states[units[3]],
        }
        failed = [name for name, value in states.items() if value not in {"active", "activating"}]
        if not failed:
            css_class, label = "success", "СИСТЕМА В НОРМЕ"
        elif len(failed) == 1:
            css_class, label = "warning", "ТРЕБУЕТ ВНИМАНИЯ: 1"
        else:
            css_class, label = "danger", f"СБОЙ: {len(failed)}"
        return {
            "class": css_class, "label": label, "count": len(failed),
            "states": states, "href": url_for("system_page", tab="logs-diagnostics"),
        }

    def current_public_url(panel=None) -> str:
        panel = panel or get_panel_settings()
        scheme = str(panel["public_scheme"] or "http")
        configured_host = str(panel["public_host"] or "").strip()
        host = configured_host
        if not host:
            raw_host = request.host.split(":", 1)[0].strip("[]")
            if raw_host and raw_host not in {"127.0.0.1", "localhost", "SERVER_IP"}:
                host = raw_host
            elif app.config.get("TESTING"):
                host = raw_host or "localhost"
            else:
                host = detect_public_ipv4(force=False) or raw_host or "SERVER_IP"
        port = int(panel["public_port"] or 62443)
        default = 443 if scheme == "https" else 80
        suffix = "" if port == default else f":{port}"
        return f"{scheme}://{host}{suffix}"

    def format_size(value: object) -> str:
        try:
            amount = float(max(0, int(value or 0)))
        except (TypeError, ValueError):
            amount = 0.0
        units = ("B", "KiB", "MiB", "GiB", "TiB")
        for unit in units:
            if amount < 1024 or unit == units[-1]:
                return f"{amount:.0f} {unit}" if unit in {"B", "KiB"} else f"{amount:.1f} {unit}"
            amount /= 1024
        return "0 B"

    app.jinja_env.filters["filesize"] = format_size
    app.jinja_env.filters["country_flag"] = country_flag
    app.jinja_env.filters["country_name"] = country_name
    app.jinja_env.filters["country_display"] = country_display
    app.jinja_env.filters["country_flag_asset"] = country_flag_asset

    def country_flag_icon(value: object, title: object = "", css_class: object = "") -> Markup:
        code = normalize_country_code(value)
        label = str(title or country_name(code))
        classes = "country-flag-image"
        extra = re.sub(r"[^A-Za-z0-9_-]+", " ", str(css_class or "")).strip()
        if extra:
            classes += " " + extra
        src = url_for("static", filename=country_flag_asset(code), v=app.jinja_env.globals.get("asset_version", ""))
        alt = code if code else ""
        return Markup(
            f'<img class="{escape(classes)}" src="{escape(src)}" alt="{escape(alt)}" '
            f'title="{escape(label)}" width="24" height="24" loading="lazy">'
        )

    app.jinja_env.globals["country_flag_icon"] = country_flag_icon

    def ensure_controller_identity(panel=None, *, force_country: bool = False):
        panel = panel or get_panel_settings()
        public_ip = "" if app.config.get("TESTING") else detect_public_ipv4(force=force_country)
        current = next((item for item in list_nodes() if item.get("is_local")), None)
        code = ""
        if current and current.get("country_mode") == "manual":
            code = str(current.get("country_code") or "")
        elif public_ip:
            code = detect_country_code(public_ip, force=force_country)
        return ensure_local_node(
            name=str(panel["instance_name"] or "SG-AWG Controller"),
            public_host=str(panel["public_host"] or public_ip or ""),
            country_code=code,
        )

    @app.context_processor
    def inject_layout_context():
        if not session.get("authenticated"):
            return {}
        panel = get_panel_settings()
        public_url = current_public_url(panel)
        address = urlsplit(public_url).hostname or "SERVER_IP"
        instance_name = str(panel["instance_name"] or "SG-AWG-Panel").strip()
        local_node = None
        try:
            local_node = ensure_controller_identity(panel)
            nodes = list_nodes()
            cluster_summary = {
                "total": max(0, len(nodes) - 1),
                "online": sum(1 for item in nodes if not item.get("is_local") and item.get("online")),
            }
        except Exception:
            cluster_summary = {"total": 0, "online": 0}
        identity_label = address if instance_name.casefold() == address.casefold() else f"{instance_name} · {address}"
        return {
            "global_system_status": global_system_status(),
            "cluster_summary": cluster_summary,
            "layout_instance_name": instance_name,
            "layout_server_address": address,
            "layout_identity_label": identity_label,
            "layout_country_code": str((local_node or {}).get("country_code") or ""),
            "layout_country_flag": country_flag((local_node or {}).get("country_code")),
            "layout_ui_build": "sgawg070rc6",
        }

    def access_rows() -> list[dict[str, object]]:
        panel = get_panel_settings()
        base = current_public_url(panel)
        rows: list[dict[str, object]] = []
        for row in list_awg_clients():
            item = dict(row)
            item.update(client_lifecycle(item))
            item["access_url"] = f"{base}{url_for('public_client_config', token=row['access_token'])}"
            item["subscription_url"] = f"{base}{url_for('public_client_subscription', token=row['access_token'])}"
            item["managed_profile_url"] = f"{base}{url_for('public_client_managed_profile', token=row['access_token'])}"
            rows.append(item)
        return rows

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["panel_version"] = __version__
    app.jinja_env.globals["asset_version"] = f"{__version__}-sgawg070rc6"

    @app.errorhandler(CSRFTokenError)
    def csrf_token_error(_error):
        # A stale page, old cookie from a previous installation, or another
        # panel on the same host must never leave the user at a raw 400 page.
        session.clear()
        return redirect(url_for("login", csrf_reset="1"), code=303)

    @app.after_request
    def disable_sensitive_page_caching(response):
        if response.mimetype == "text/html":
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    @app.before_request
    def enforce_panel_allowlist():
        if request.endpoint in {
            "static", "health", "public_client_config", "public_client_download",
            "public_client_qr", "public_client_subscription", "public_client_managed_profile",
            "panel_access_job_status", "panel_access_job_events", "panel_access_job_probe",
            "panel_access_job_complete", "node_agent_enroll", "node_agent_heartbeat",
            "node_agent_next_job", "node_agent_finish_job",
            "bootstrap_node_bundle", "bootstrap_node_install_script", "bootstrap_node_connect_script",
        }:
            return None
        ip_value = client_ip()
        if not ip_is_allowed(ip_value):
            record_auth_event(
                "allowlist_denied", ip_address=ip_value,
                user_agent=client_agent(), detail=request.path,
            )
            abort(403, "Этот IP не входит в allowlist панели")
        return None

    @app.get("/login")
    def login():
        if session.get("authenticated") and validate_web_session(
            str(session.get("session_token", "")), touch=False
        ) is not None:
            return redirect(url_for("system_page"))
        if request.args.get("password_changed") == "1":
            flash("Пароль изменён. Все активные сессии завершены.", "success")
        if request.args.get("access_changed") == "1":
            flash("Новый HTTPS-адрес готов. Войдите в панель заново.", "success")
        if request.args.get("updated") == "1":
            flash("Обновление завершено. Войдите в панель заново.", "success")
        if request.args.get("csrf_reset") == "1":
            flash(
                "Сессия браузера устарела и была безопасно сброшена. Введите пароль ещё раз.",
                "warning",
            )
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        require_csrf()
        client_key = client_ip()
        agent = client_agent()
        now = time.time()
        with login_lock:
            recent = [stamp for stamp in login_attempts.get(client_key, []) if now - stamp < login_window]
            login_attempts[client_key] = recent
            if len(recent) >= login_limit:
                wait_minutes = max(1, int((login_window - (now - recent[0]) + 59) // 60))
                record_auth_event(
                    "login_blocked", ip_address=client_key,
                    user_agent=agent, detail=f"wait={wait_minutes}m",
                )
                flash(f"Слишком много неудачных попыток. Повторите через {wait_minutes} мин.", "error")
                return redirect(url_for("login"))

        password_hash = os.environ.get("AWGPANEL_PASSWORD_HASH", "")
        if not password_hash:
            record_auth_event("login_error", ip_address=client_key, user_agent=agent, detail="password hash missing")
            flash("Пароль панели не настроен. Повторите установку GUI.", "error")
            return redirect(url_for("login"))
        if not check_password_hash(password_hash, request.form.get("password", "")):
            with login_lock:
                login_attempts.setdefault(client_key, []).append(now)
            record_auth_event("login_failed", ip_address=client_key, user_agent=agent)
            flash("Неверный пароль", "error")
            return redirect(url_for("login"))
        with login_lock:
            login_attempts.pop(client_key, None)
        token = secrets.token_urlsafe(40)
        create_web_session(token, ip_address=client_key, user_agent=agent)
        session.clear()
        session.permanent = True
        session["authenticated"] = True
        session["session_token"] = token
        session["csrf_token"] = secrets.token_urlsafe(32)
        record_auth_event("login_success", ip_address=client_key, user_agent=agent)
        return redirect(url_for("system_page"))

    @app.post("/logout")
    @login_required
    def logout():
        require_csrf()
        token = str(session.get("session_token", ""))
        if token:
            revoke_web_session(hashlib.sha256(token.encode("utf-8")).hexdigest())
        record_auth_event("logout", ip_address=client_ip(), user_agent=client_agent())
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def dashboard():
        return redirect(url_for("system_page"))

    @app.get("/server")
    @login_required
    def server_page():
        awg = get_awg_overview()
        return render_template(
            "server.html",
            awg=awg,
            diagnostics=get_awg_diagnostics(),
            masking_profile=detect_masking_profile(awg["settings"]),
        )

    @app.post("/server")
    @login_required
    def server_save():
        require_csrf()
        current = get_awg_settings()
        values = {
            "interface_name": "awg0",
            "endpoint_host": request.form.get("endpoint_host", ""),
            "listen_port": request.form.get("listen_port", "585"),
            "server_network": request.form.get("server_network", "10.77.0.0/24"),
            "dns_servers": request.form.get("dns_servers", "1.1.1.1, 1.0.0.1"),
            "mtu": request.form.get("mtu", "1280"),
            "external_interface": request.form.get("external_interface", ""),
            "jc": request.form.get("jc", "6"),
            "jmin": request.form.get("jmin", "64"),
            "jmax": request.form.get("jmax", "128"),
            "s1": request.form.get("s1", "48"),
            "s2": request.form.get("s2", "48"),
            "s3": request.form.get("s3", "32"),
            "s4": request.form.get("s4", "16"),
            "h1": request.form.get("h1", ""),
            "h2": request.form.get("h2", ""),
            "h3": request.form.get("h3", ""),
            "h4": request.form.get("h4", ""),
            "i1": request.form.get("i1", ""),
            "i2": request.form.get("i2", ""),
            "i3": request.form.get("i3", ""),
            "i4": request.form.get("i4", ""),
            "i5": request.form.get("i5", ""),
            "isolate_clients": current["isolate_clients"],
        }
        profile = request.form.get("masking_profile", "custom")
        values.update(profile_values(profile))
        summary = server_change_summary(current, values)
        try:
            if (
                summary.client_addresses_change
                and list_awg_clients(local_only=True)
                and request.form.get("confirm_network_change") != "1"
            ):
                raise ValueError(
                    "Смена сети изменит адреса всех клиентов. Установите подтверждение и повторите применение."
                )
            validate_awg_settings_document(values)
            changes = ", ".join(readable_changes(summary)) or "без изменения параметров"
            title = f"Применение AWG Server: {changes}"
            job = start_operation_job(
                kind="server_config",
                title=title,
                payload={"values": values},
                success_path=url_for("server_page"),
                error_path=url_for("server_page"),
            )
            return redirect(url_for("operation_progress", token=job["token"]))
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("server_page"))

    @app.route("/server/json", methods=["GET", "POST"])
    @login_required
    def server_json_page():
        scope = "server"
        current = get_awg_settings()
        source = server_json_document(current)
        validation_passed = False
        validation_token = ""
        validation_error = None
        validation_message = ""

        def validate_source():
            values, confirm_network_change = parse_server_json_document(source)
            values["isolate_clients"] = bool(current["isolate_clients"])
            summary = server_change_summary(current, values)
            if (
                summary.client_addresses_change
                and list_awg_clients(local_only=True)
                and not confirm_network_change
            ):
                raise ValueError(
                    "_sgAwgPanel.confirmNetworkChange: установите true — "
                    "смена сети перенумерует всех клиентов"
                )
            validate_awg_settings_document(values)
            changes = ", ".join(readable_changes(summary)) or "без изменения параметров"
            return values, changes

        if request.method == "GET":
            clear_json_validation_ticket(scope)
        else:
            require_csrf()
            source = request.form.get("json_config", "")
            action = request.form.get("action", "")
            try:
                if action == "validate":
                    (_, changes), validation_token = validate_json_submission(
                        scope, source, validate_source
                    )
                    validation_passed = True
                    validation_message = (
                        f"JSON AWG Server прошёл полную проверку ({changes}). "
                        "Изменения не применены."
                    )
                elif action == "save":
                    values, changes = require_validated_json_submission(
                        scope, source, request.form.get("validation_token", ""), validate_source
                    )
                    job = start_operation_job(
                        kind="server_config",
                        title=f"Применение AWG Server из JSON: {changes}",
                        payload={"values": values},
                        success_path=url_for("server_page"),
                        error_path=url_for("server_json_page"),
                    )
                    return redirect(url_for("operation_progress", token=job["token"]))
                else:
                    raise ValueError("Неизвестное действие JSON-редактора")
            except (ValueError, PermissionError, AWGPanelError) as exc:
                clear_json_validation_ticket(scope)
                validation_error = json_editor_error(exc)
                validation_passed = False
                validation_token = ""
        return render_template(
            "server_json.html", server_json=source,
            validation_passed=validation_passed, validation_token=validation_token,
            validation_error=validation_error, validation_message=validation_message,
        )

    @app.post("/service/<action>")
    @login_required
    def service_action(action: str):
        require_csrf()
        labels = {"start": "Запуск", "stop": "Остановка", "restart": "Перезапуск"}
        if action not in labels:
            abort(404)
        return_path = request.referrer or url_for("clients_page")
        try:
            job = start_operation_job(
                kind="service_action",
                title=f"{labels[action]} AmneziaWG",
                payload={"action": action},
                success_path=return_path,
                error_path=return_path,
            )
            return redirect(url_for("operation_progress", token=job["token"]))
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
            return redirect(return_path)

    @app.get("/clients")
    @login_required
    def clients_page():
        panel = get_panel_settings()
        ensure_controller_identity(panel)
        awg = get_awg_overview()
        client_nodes = list_nodes()
        local_node = next((item for item in client_nodes if item.get("is_local")), None)
        for node in client_nodes:
            runtime = node.get("awg_runtime") if isinstance(node.get("awg_runtime"), dict) else {}
            if node.get("is_local"):
                node["client_ready"] = bool(awg.get("configured"))
                node["client_ready_reason"] = "" if node["client_ready"] else "Сначала настройте AWG Server на Controller"
                node["client_endpoint"] = f"{awg['settings']['endpoint_host'] or awg.get('public_ipv4_detected') or 'Controller'}:{awg['settings']['listen_port']}"
            else:
                try:
                    runtime_port = int(runtime.get("listen_port") or node.get("public_port") or 0)
                except (TypeError, ValueError):
                    runtime_port = 0
                node["client_ready"] = bool(
                    node.get("effective_state") == "online"
                    and node.get("service_awg") == "active"
                    and runtime_port == 585
                    and runtime.get("public_key")
                    and runtime.get("server_network")
                    and runtime.get("interface_address")
                )
                if node["client_ready"]:
                    node["client_ready_reason"] = ""
                elif node.get("effective_state") != "online":
                    node["client_ready_reason"] = "SG-Node ещё не в сети"
                elif runtime_port != 585:
                    node["client_ready_reason"] = "Ожидается работающий UDP-порт 585"
                else:
                    node["client_ready_reason"] = "Откройте SG-Node в Cluster и нажмите «Обновить подключение ноды»"
                node["client_endpoint"] = f"{node.get('public_ipv4') or node.get('public_host') or 'адрес ещё не получен'}:585"
        all_clients = list(awg["clients"])
        query = request.args.get("q", "").strip().lower()
        status_filter = request.args.get("status", "all").strip().lower()
        sort_mode = request.args.get("sort", "created").strip().lower()
        server_filter = request.args.get("server", "all").strip().lower()
        preselected_node = request.args.get("node", "").strip()
        open_add_dialog = request.args.get("open", "").strip().lower() == "add" or bool(preselected_node)

        rows = all_clients
        if server_filter == "controller":
            rows = [row for row in rows if not row.get("node_id")]
        elif server_filter.isdigit():
            rows = [row for row in rows if int(row.get("node_id") or 0) == int(server_filter)]
        if query:
            rows = [
                row for row in rows
                if query in str(row.get("name", "")).lower()
                or query in str(row.get("address", "")).lower()
                or query in str(row.get("comment", "")).lower()
            ]
        if status_filter == "active":
            rows = [row for row in rows if bool(row.get("effective_enabled")) and bool(row.get("deployment_ready"))]
        elif status_filter == "online":
            rows = [row for row in rows if bool(row.get("online"))]
        elif status_filter == "expiring":
            rows = [row for row in rows if bool(row.get("expiring_soon")) and not bool(row.get("expired"))]
        elif status_filter == "expired":
            rows = [row for row in rows if bool(row.get("expired"))]
        elif status_filter == "disabled":
            rows = [row for row in rows if not bool(row.get("enabled"))]
        elif status_filter == "unlimited":
            rows = [row for row in rows if not row.get("expires_at")]
        elif status_filter == "applying":
            rows = [row for row in rows if str(row.get("deployment_state") or "active") in {"queued", "deleting"}]
        elif status_filter == "error":
            rows = [row for row in rows if str(row.get("deployment_state") or "active") == "error"]

        if sort_mode == "name":
            rows.sort(key=lambda row: str(row.get("name", "")).casefold())
        elif sort_mode == "expiry":
            rows.sort(key=lambda row: (not bool(row.get("expires_at")), str(row.get("expires_at") or "9999"), int(row.get("id", 0))))
        elif sort_mode == "handshake":
            rows.sort(key=lambda row: int(row.get("latest_handshake", 0)), reverse=True)
        elif sort_mode == "traffic":
            rows.sort(key=lambda row: int(row.get("rx", 0)) + int(row.get("tx", 0)), reverse=True)
        else:
            rows.sort(key=lambda row: int(row.get("id", 0)), reverse=True)

        visible_awg = dict(awg)
        visible_awg["clients"] = rows
        outbound_names = {int(row["id"]): str(row["name"]) for row in list_outbounds()}
        cascade_settings = get_cascade_settings()
        cascade_outbound_id = int(cascade_settings.get("outbound_id") or 0)
        if cascade_outbound_id and cascade_settings.get("exit_name"):
            outbound_names[cascade_outbound_id] = f"Cascade → {cascade_settings['exit_name']}"
        for link in list_cascade_links(include_disabled=False):
            if link.get("entry", {}).get("is_local") and int(link.get("outbound_id") or 0):
                outbound_names[int(link["outbound_id"])] = f"Cascade → {link.get('exit', {}).get('name') or 'сервер выхода'}"
        client_stats = {
            "total": len(all_clients),
            "active": sum(1 for row in all_clients if bool(row.get("effective_enabled")) and bool(row.get("deployment_ready"))),
            "online": sum(1 for row in all_clients if bool(row.get("online"))),
            "expiring": sum(1 for row in all_clients if bool(row.get("expiring_soon")) and not bool(row.get("expired"))),
            "expired": sum(1 for row in all_clients if bool(row.get("expired"))),
            "disabled": sum(1 for row in all_clients if not bool(row.get("enabled"))),
            "unlimited": sum(1 for row in all_clients if not row.get("expires_at")),
            "applying": sum(1 for row in all_clients if str(row.get("deployment_state") or "active") in {"queued", "deleting"}),
            "error": sum(1 for row in all_clients if str(row.get("deployment_state") or "active") == "error"),
        }
        selected_client = None
        selected_value = request.args.get("client", "").strip()
        if selected_value.isdigit():
            selected_client = next((row for row in all_clients if int(row["id"]) == int(selected_value)), None)
        if selected_client is None and rows:
            selected_client = rows[0]
        selected_client_json = ""
        if selected_client is not None and not selected_client.get("node_id"):
            selected_client_json = client_json_document(selected_client, get_awg_settings())
        active_outbounds = [item for item in list_outbounds() if bool(item["enabled"])]
        traffic_rule_count = len(list_traffic_rules(include_system=False))
        return render_template(
            "clients.html",
            awg=visible_awg,
            outbound_names=outbound_names,
            client_stats=client_stats,
            query=query,
            status_filter=status_filter,
            sort_mode=sort_mode,
            server_filter=server_filter,
            client_nodes=client_nodes,
            local_node=local_node,
            has_ready_server=any(bool(item.get("client_ready")) for item in client_nodes),
            preselected_node=preselected_node,
            open_add_dialog=open_add_dialog,
            selected_client=selected_client,
            selected_client_json=selected_client_json,
            active_outbounds=active_outbounds,
            traffic_rule_count=traffic_rule_count,
            panel=panel,
        )

    @app.post("/clients/add")
    @login_required
    def client_add():
        require_csrf()
        try:
            node_value = request.form.get("node_id", "").strip()
            node_id = int(node_value) if node_value.isdigit() else None
            client = add_awg_client(
                request.form.get("name", ""),
                request.form.get("comment", ""),
                _expiry_from_form(request.form),
                node_id=node_id,
            )
            if client["node_id"]:
                flash(
                    f"Клиент {client['name']} создан. Agent применяет его на выбранной SG-Node.",
                    "success",
                )
                return redirect(url_for("clients_page", client=int(client["id"]), server=int(client["node_id"])))
            flash(f"Клиент {client['name']} создан и применён на Controller.", "success")
            return redirect(url_for("clients_page", client=int(client["id"]), server="controller"))
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("clients_page", open="add", node=request.form.get("node_id", "")))

    @app.route("/clients/<int:client_id>/edit", methods=["GET", "POST"])
    @login_required
    def client_edit(client_id: int):
        ensure_controller_identity(get_panel_settings())
        client = find_awg_client(client_id)
        if request.method == "POST":
            require_csrf()
            try:
                updated = update_awg_client_settings(
                    client_id,
                    name=request.form.get("name", ""),
                    comment=request.form.get("comment", ""),
                    dns_servers=request.form.get("dns_servers", ""),
                    mtu=request.form.get("mtu", ""),
                    expires_at=_expiry_from_form(
                        request.form, current_expiry=dict(client).get("expires_at")
                    ),
                )
                flash(f"Настройки клиента {updated['name']} сохранены и применены.", "success")
                return redirect(url_for("client_edit", client_id=client_id))
            except (ValueError, PermissionError, AWGPanelError) as exc:
                flash(str(exc), "error")
                client = find_awg_client(client_id)
        enriched = dict(client)
        enriched.update(client_lifecycle(enriched))
        for item in get_awg_overview()["clients"]:
            if int(item["id"]) == int(client_id):
                enriched.update(item)
                break
        return render_template("client_edit.html", client=enriched, settings=get_awg_settings(), client_traffic_history=get_client_traffic_history(client['id']), client_stats=get_client_period_stats(client['id']))

    @app.route("/clients/<int:client_id>/json", methods=["GET", "POST"])
    @login_required
    def client_json_page(client_id: int):
        scope = f"client:{client_id}"
        client = find_awg_client(client_id)
        if dict(client).get("node_id"):
            flash("Для клиента SG-Node используйте обычную форму. Технический JSON относится к локальному Controller.", "warning")
            return redirect(url_for("client_edit", client_id=client_id))
        source = client_json_document(client, get_awg_settings())
        validation_passed = False
        validation_token = ""
        validation_error = None
        validation_message = ""

        def validate_source():
            values = parse_client_json_document(source, expected_id=client_id)
            validate_awg_client_document(client_id, values)
            return values

        if request.method == "GET":
            clear_json_validation_ticket(scope)
        else:
            require_csrf()
            source = request.form.get("json_config", "")
            action = request.form.get("action", "")
            try:
                if action == "validate":
                    _, validation_token = validate_json_submission(scope, source, validate_source)
                    validation_passed = True
                    validation_message = (
                        "JSON клиента прошёл проверку схемы, адресов, сетей и Outbound. "
                        "Изменения не применены."
                    )
                elif action == "save":
                    values = require_validated_json_submission(
                        scope, source, request.form.get("validation_token", ""), validate_source
                    )
                    updated = update_awg_client_document(client_id, values)
                    flash(f"JSON клиента {updated['name']} сохранён и применён.", "success")
                    return redirect(url_for("client_edit", client_id=client_id))
                else:
                    raise ValueError("Неизвестное действие JSON-редактора")
            except (ValueError, PermissionError, AWGPanelError) as exc:
                clear_json_validation_ticket(scope)
                validation_error = json_editor_error(exc)
                validation_passed = False
                validation_token = ""
        enriched = dict(client)
        enriched.update(client_lifecycle(enriched))
        return render_template(
            "client_json.html", client=enriched, client_json=source,
            validation_passed=validation_passed, validation_token=validation_token,
            validation_error=validation_error, validation_message=validation_message,
        )

    @app.post("/clients/bulk")
    @login_required
    def clients_bulk():
        require_csrf()
        try:
            ids = [int(value) for value in request.form.getlist("client_ids")]
            action = request.form.get("bulk_action", "")
            expires_at = None
            if action == "set_expiry":
                expires_at = _expiry_from_form(request.form, prefix="bulk_")
            count = bulk_update_awg_clients(ids, action=action, expires_at=expires_at)
            messages = {
                "enable": "включены",
                "disable": "отключены",
                "clear_expiry": "переведены в бессрочный режим",
                "set_expiry": "получили общую дату окончания",
                "extend_7": "продлены на 7 дней",
                "extend_30": "продлены на 30 дней",
                "extend_90": "продлены на 90 дней",
                "extend_365": "продлены на 1 год",
                "delete": "удалены",
            }
            flash(f"Клиенты ({count}) {messages.get(action, 'изменены')}.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("clients_page"))

    @app.post("/clients/<int:client_id>/toggle")
    @login_required
    def client_toggle(client_id: int):
        require_csrf()
        try:
            current = find_awg_client(client_id)
            client = set_awg_client_enabled(client_id, not bool(current["enabled"]))
            state = "включён" if client["enabled"] else "отключён"
            flash(f"Клиент {client['name']} {state}.", "success")
        except (PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(request.referrer or url_for("clients_page"))

    @app.post("/clients/<int:client_id>/regenerate")
    @login_required
    def client_regenerate(client_id: int):
        require_csrf()
        try:
            client = regenerate_awg_client(client_id)
            flash(
                f"Ключи клиента {client['name']} пересозданы. Старый конфиг больше не работает.",
                "success",
            )
            return redirect(url_for("client_access", client_id=client_id))
        except (PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("clients_page"))

    @app.post("/clients/<int:client_id>/delete")
    @login_required
    def client_delete(client_id: int):
        require_csrf()
        try:
            client = delete_awg_client(client_id)
            if client["node_id"]:
                flash(f"Удаление клиента {client['name']} передано SG-Node.", "success")
            else:
                flash(f"Клиент {client['name']} удалён.", "success")
        except (PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("clients_page"))

    @app.get("/clients/<int:client_id>/config")
    @login_required
    def client_access(client_id: int):
        client = find_awg_client(client_id)
        enriched = dict(client)
        enriched.update(client_lifecycle(enriched))
        try:
            config_text = render_awg_client_config(client_id)
        except AWGPanelError as exc:
            flash(str(exc), "error")
            return redirect(url_for("client_edit", client_id=client_id))
        panel = get_panel_settings()
        base = current_public_url(panel)
        enriched["access_url"] = (
            f"{base}{url_for('public_client_config', token=client['access_token'])}"
        )
        enriched["subscription_url"] = (
            f"{base}{url_for('public_client_subscription', token=client['access_token'])}"
        )
        enriched["managed_profile_url"] = (
            f"{base}{url_for('public_client_managed_profile', token=client['access_token'])}"
        )
        return render_template(
            "client_config.html",
            client=enriched,
            config_text=config_text,
            panel=panel,
            public_url=base,
        )

    @app.get("/clients/<int:client_id>/download")
    @login_required
    def client_download(client_id: int):
        client = find_awg_client(client_id)
        try:
            config_text = render_awg_client_config(client_id)
        except AWGPanelError as exc:
            flash(str(exc), "error")
            return redirect(url_for("client_edit", client_id=client_id))
        return send_file(
            io.BytesIO(config_text.encode("utf-8")),
            mimetype="text/plain; charset=utf-8",
            as_attachment=True,
            download_name=f"{_safe_filename(client['name'])}-awg.conf",
        )

    @app.get("/clients/<int:client_id>/qr.svg")
    @login_required
    def client_qr(client_id: int):
        try:
            return _qr_svg_response(render_awg_client_config(client_id))
        except AWGPanelError:
            abort(404)

    @app.get("/access")
    @login_required
    def access_page():
        # Compatibility route. Link management now lives inside each client.
        return redirect(url_for("clients_page"))

    @app.post("/access/settings")
    @login_required
    def access_settings_save():
        require_csrf()
        try:
            panel = configure_access_links(
                enabled=request.form.get("access_enabled") == "1",
                profile_title=request.form.get("access_profile_title", "SG-AWG"),
            )
            state = "включены" if panel["access_enabled"] else "отключены"
            flash(f"Публичные ссылки {state}.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("clients_page"))

    @app.route("/access/json", methods=["GET", "POST"])
    @login_required
    def access_json_page():
        scope = "access"
        clients = list_awg_clients()
        source = access_json_document(get_panel_settings(), clients)
        validation_passed = False
        validation_token = ""
        validation_error = None
        validation_message = ""

        def validate_source():
            expected_ids = {int(row["id"]) for row in clients}
            return parse_access_json_document(source, expected_client_ids=expected_ids)

        if request.method == "GET":
            clear_json_validation_ticket(scope)
        else:
            require_csrf()
            source = request.form.get("json_config", "")
            action = request.form.get("action", "")
            try:
                if action == "validate":
                    _, validation_token = validate_json_submission(scope, source, validate_source)
                    validation_passed = True
                    validation_message = (
                        "JSON выдачи конфигураций прошёл проверку. Изменения не применены."
                    )
                elif action == "save":
                    enabled, title, client_states = require_validated_json_submission(
                        scope, source, request.form.get("validation_token", ""), validate_source
                    )
                    configure_access_document(
                        enabled=enabled, profile_title=title, client_states=client_states
                    )
                    flash("JSON доступа к конфигурациям сохранён.", "success")
                    return redirect(url_for("clients_page"))
                else:
                    raise ValueError("Неизвестное действие JSON-редактора")
            except (ValueError, PermissionError, AWGPanelError) as exc:
                clear_json_validation_ticket(scope)
                validation_error = json_editor_error(exc)
                validation_passed = False
                validation_token = ""
        return render_template(
            "section_json.html",
            section="CLIENTS / LINKS / JSON", heading="Ссылки клиентов JSON",
            subtitle="Публичные ссылки и их состояние для каждого клиента",
            format_name="ACCESS-V1", object_title="Доступ к конфигурациям",
            description="JSON содержит общие параметры ссылок и полный список клиентов. Секретные токены не отображаются.",
            back_url=url_for("clients_page"), json_config=source,
            validation_passed=validation_passed, validation_token=validation_token,
            validation_error=validation_error, validation_message=validation_message,
        )

    @app.post("/access/<int:client_id>/toggle")
    @login_required
    def access_toggle(client_id: int):
        require_csrf()
        try:
            current = find_awg_client(client_id)
            client = set_client_access_enabled(client_id, not bool(current["access_enabled"]))
            state = "включена" if client["access_enabled"] else "отключена"
            flash(f"Ссылка клиента {client['name']} {state}.", "success")
        except (PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("client_access", client_id=client_id))

    @app.post("/access/<int:client_id>/regenerate")
    @login_required
    def access_regenerate(client_id: int):
        require_csrf()
        try:
            client = regenerate_client_access_token(client_id)
            flash(f"Новая ссылка доступа для {client['name']} создана.", "success")
        except (PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("client_access", client_id=client_id))

    def _conf_to_vpn_uri(config_text: str) -> str:
        """Кодирует .conf AmneziaWG в vpn:// URI для AmneziaVPN (Base64URL, без паддинга)."""
        import base64
        raw = config_text.encode("utf-8")
        b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        return f"vpn://{b64}"

    @app.get("/a/<token>")
    def public_client_config(token: str):
        panel = get_panel_settings()
        if not bool(panel["access_enabled"]):
            abort(404)
        try:
            client = find_client_by_access_token(token)
            config_text = render_awg_client_config(int(client["id"]))
            record_client_access(int(client["id"]))
        except AWGPanelError:
            abort(404)

        lifecycle = client_lifecycle(dict(client))
        vpn_uri = _conf_to_vpn_uri(config_text)
        vpn_qr_b64 = ""
        try:
            import base64
            _qr_resp = _qr_svg_response(vpn_uri)
            vpn_qr_b64 = base64.b64encode(_qr_resp.get_data()).decode("ascii")
        except Exception:
            pass

        # --- Определение устройства по User-Agent ---
        ua_string = request.headers.get("User-Agent", "")
        device = {"os_name": "", "model": "", "download_url": "", "download_text": "", "hint": ""}
        if ua_string:
            try:
                detector = DeviceDetector(ua_string).parse()
                os_name = detector.os_name() or ""
                device_model = detector.device_model() or ""

                if not os_name and "Android" in ua_string:
                    os_name = "Android"

                device["os_name"] = os_name
                device["model"] = device_model

                if os_name == "iOS":
                    device["download_text"] = "Скачать AmneziaVPN (iOS)"
                    device["download_url"] = "https://apps.apple.com/app/amneziavpn/id1600529900"
                    device["hint"] = ("Если приложение недоступно в вашем регионе App Store, "
                                      "смените регион аккаунта или используйте DefaultVPN.")
                elif os_name == "Android":
                    device["download_text"] = "Скачать AmneziaVPN (Android)"
                    device["download_url"] = "https://play.google.com/store/apps/details?id=org.amnezia.vpn"
                    device["hint"] = ("Если Google Play недоступен, скачайте APK с "
                                      "github.com/amnezia-vpn/amnezia-client/releases/latest.")
                elif os_name == "Windows":
                    device["download_text"] = "Скачать AmneziaVPN (Windows)"
                    device["download_url"] = "https://github.com/amnezia-vpn/amnezia-client/releases/latest"
                elif os_name in ("Mac", "macOS"):
                    device["download_text"] = "Скачать AmneziaVPN (macOS)"
                    device["download_url"] = "https://github.com/amnezia-vpn/amnezia-client/releases/latest"
                    device["hint"] = "Требуется macOS 14.0 или новее."
                elif os_name == "Linux":
                    device["download_text"] = "Скачать AmneziaVPN (Linux)"
                    device["download_url"] = "https://github.com/amnezia-vpn/amnezia-client/releases/latest"
            except Exception:
                pass
        # --- Конец определения устройства ---

        response = Response(render_template(
            "public_client_config.html", client=dict(client), config_text=config_text,
            token=token, profile_title=str(panel["access_profile_title"] or "SG-AWG"),
            device=device,
            lifecycle=lifecycle,
            vpn_uri=vpn_uri,
            vpn_qr_b64=vpn_qr_b64,
        ), mimetype="text/html; charset=utf-8")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response

    @app.get("/a/<token>/download")
    def public_client_download(token: str):
        panel = get_panel_settings()
        if not bool(panel["access_enabled"]):
            abort(404)
        try:
            client = find_client_by_access_token(token)
            config_text = render_awg_client_config(int(client["id"]))
            record_client_access(int(client["id"]))
        except AWGPanelError:
            abort(404)
        profile_title = str(panel["access_profile_title"] or "SG-AWG").strip()
        filename = _safe_filename(f"{profile_title}-{client['name']}")
        response = send_file(
            io.BytesIO(config_text.encode("utf-8")),
            mimetype="text/plain; charset=utf-8",
            as_attachment=True,
            download_name=f"{filename}.conf",
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response

    @app.get("/a/<token>/qr.svg")
    def public_client_qr(token: str):
        panel = get_panel_settings()
        if not bool(panel["access_enabled"]):
            abort(404)
        try:
            client = find_client_by_access_token(token)
            config_text = render_awg_client_config(int(client["id"]))
            record_client_access(int(client["id"]))
        except AWGPanelError:
            abort(404)
        return _qr_svg_response(config_text)

    @app.get("/s/<token>")
    def public_client_subscription(token: str):
        panel = get_panel_settings()
        if not bool(panel["access_enabled"]):
            abort(404)
        try:
            client = find_client_by_access_token(token)
            config_text = render_awg_client_config(int(client["id"]))
            record_client_access(int(client["id"]))
        except AWGPanelError:
            abort(404)
        profile_title = str(panel["access_profile_title"] or "SG-AWG").strip()
        instance_name = str(panel["instance_name"] or "SG-AWG-Panel").strip()
        profile_name = str(client["name"]) if instance_name.casefold() == "sg-awg-panel" else f"{instance_name}/{client['name']}"
        filename_base = _safe_filename(f"{profile_title}-{client['name']}")
        filename = f"{filename_base}.conf"
        response = Response(config_text, mimetype="text/plain; charset=utf-8")
        response.headers["Content-Disposition"] = _inline_content_disposition(filename)
        return _profile_response_headers(response, profile_name=profile_name, filename=filename)

    @app.get("/s/<token>/managed.json")
    def public_client_managed_profile(token: str):
        panel = get_panel_settings()
        if not bool(panel["access_enabled"]):
            abort(404)
        try:
            client = find_client_by_access_token(token)
            config_text = render_awg_client_config(int(client["id"]))
            record_client_access(int(client["id"]))
        except AWGPanelError:
            abort(404)
        instance_name = str(panel["instance_name"] or "SG-AWG-Panel").strip()
        profile_name = str(client["name"]) if instance_name.casefold() == "sg-awg-panel" else f"{instance_name}/{client['name']}"
        payload = {
            "schema": "sg-client-managed-profile-v1",
            "version": 1,
            "source": "SG-AWG-Panel",
            "instance_name": instance_name,
            "profile": {
                "id": f"awg-{int(client['id'])}",
                "name": profile_name,
                "protocol": "amneziawg",
                "config": config_text,
                "updated_at": str(client["updated_at"] or ""),
            },
        }
        response = Response(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            mimetype="application/json; charset=utf-8",
        )
        filename = f"{_safe_filename(profile_name)}.json"
        return _profile_response_headers(response, profile_name=profile_name, filename=filename)

    @app.get("/outbounds")
    @login_required
    def outbounds_page():
        status = traffic_runtime_status()
        return render_template(
            "outbounds.html",
            outbounds=list_outbounds(),
            outbound_status_by_id={item["id"]: item for item in status["profiles"]},
            traffic_status=status,
        )

    @app.route("/outbounds/<int:outbound_id>/edit", methods=["GET", "POST"])
    @login_required
    def outbound_edit_page(outbound_id: int):
        outbound = find_outbound(outbound_id)
        if request.method == "POST":
            require_csrf()
            try:
                updated = replace_outbound(
                    outbound_id,
                    name=request.form.get("name", ""),
                    config_text=request.form.get("config_text", ""),
                )
                flash(f"Outbound {updated['name']} обновлён и проверен.", "success")
                return redirect(url_for("outbounds_page"))
            except (ValueError, PermissionError, AWGPanelError) as exc:
                flash(str(exc), "error")
                outbound = find_outbound(outbound_id)
        return render_template("outbound_edit.html", outbound=outbound)

    @app.route("/outbounds/json/new", methods=["GET", "POST"])
    @login_required
    def outbound_json_new_page():
        scope = "outbound:new"
        source = outbound_json_document(None)
        validation_passed = False
        validation_token = ""
        validation_error = None
        validation_message = ""

        def validate_source():
            name, config_text, enabled = parse_outbound_json_document(source)
            validate_outbound_config_runtime(config_text)
            return name, config_text, enabled

        if request.method == "GET":
            clear_json_validation_ticket(scope)
        else:
            require_csrf()
            source = request.form.get("json_config", "")
            action = request.form.get("action", "")
            try:
                if action == "validate":
                    _, validation_token = validate_json_submission(scope, source, validate_source)
                    validation_passed = True
                    validation_message = (
                        "JSON Outbound прошёл проверку схемы и awg-quick dry-run. "
                        "Профиль не создан."
                    )
                elif action == "save":
                    name, config_text, enabled = require_validated_json_submission(
                        scope, source, request.form.get("validation_token", ""), validate_source
                    )
                    outbound = create_outbound(name, config_text, enabled=enabled)
                    flash(f"Outbound {outbound['name']} создан из проверенного JSON.", "success")
                    return redirect(url_for("outbounds_page"))
                else:
                    raise ValueError("Неизвестное действие JSON-редактора")
            except (ValueError, PermissionError, AWGPanelError) as exc:
                clear_json_validation_ticket(scope)
                validation_error = json_editor_error(exc)
                validation_passed = False
                validation_token = ""
        return render_template(
            "outbound_json.html", outbound=None, outbound_json=source,
            validation_passed=validation_passed, validation_token=validation_token,
            validation_error=validation_error, validation_message=validation_message,
        )

    @app.route("/outbounds/<int:outbound_id>/json", methods=["GET", "POST"])
    @login_required
    def outbound_json_page(outbound_id: int):
        scope = f"outbound:{outbound_id}"
        outbound = find_outbound(outbound_id)
        source = outbound_json_document(outbound)
        validation_passed = False
        validation_token = ""
        validation_error = None
        validation_message = ""

        def validate_source():
            name, config_text, enabled = parse_outbound_json_document(source, current=outbound)
            validate_outbound_config_runtime(config_text)
            return name, config_text, enabled

        if request.method == "GET":
            clear_json_validation_ticket(scope)
        else:
            require_csrf()
            source = request.form.get("json_config", "")
            action = request.form.get("action", "")
            try:
                if action == "validate":
                    _, validation_token = validate_json_submission(scope, source, validate_source)
                    validation_passed = True
                    validation_message = (
                        "JSON Outbound прошёл проверку схемы и awg-quick dry-run. "
                        "Изменения не применены."
                    )
                elif action == "save":
                    name, config_text, enabled = require_validated_json_submission(
                        scope, source, request.form.get("validation_token", ""), validate_source
                    )
                    updated = replace_outbound(
                        outbound_id, name=name, config_text=config_text, enabled=enabled
                    )
                    flash(f"JSON Outbound {updated['name']} сохранён и применён.", "success")
                    return redirect(url_for("outbounds_page"))
                else:
                    raise ValueError("Неизвестное действие JSON-редактора")
            except (ValueError, PermissionError, AWGPanelError) as exc:
                clear_json_validation_ticket(scope)
                validation_error = json_editor_error(exc)
                validation_passed = False
                validation_token = ""
                outbound = find_outbound(outbound_id)
        return render_template(
            "outbound_json.html", outbound=outbound, outbound_json=source,
            validation_passed=validation_passed, validation_token=validation_token,
            validation_error=validation_error, validation_message=validation_message,
        )

    def _automatic_rule_name(action_mode: str, targets: str) -> str:
        action_names = {"block": "Block", "outbound": "Outbound"}
        lines = [line.strip() for line in str(targets).splitlines() if line.strip()]
        target = lines[0] if lines else "назначение"
        if len(lines) > 1:
            target += f" и ещё {len(lines) - 1}"
        return f"{action_names.get(action_mode, action_mode)}: {target}"[:96]

    def _traffic_rule_card(rule: object, client_names: dict[int, str]) -> dict[str, object]:
        card = dict(rule)
        domains = [line for line in str(card.get("inline_domains") or "").splitlines() if line]
        cidrs = [line for line in str(card.get("inline_cidrs") or "").splitlines() if line]
        if card.get("list_name"):
            target = str(card["list_name"])
            target_kind = "Готовый список"
        elif domains:
            target = domains[0] + (f" и ещё {len(domains) - 1}" if len(domains) > 1 else "")
            target_kind = "Домены"
        elif cidrs:
            target = cidrs[0] + (f" и ещё {len(cidrs) - 1}" if len(cidrs) > 1 else "")
            target_kind = "IP / CIDR"
        else:
            target = "Любое назначение"
            target_kind = "Все соединения"
        selected_ids = [
            int(value) for value in str(card.get("client_ids") or "").split(",") if value
        ]
        if selected_ids:
            names = [client_names.get(value, f"Клиент #{value}") for value in selected_ids]
            client_summary = ", ".join(names)
        else:
            client_summary = "Все клиенты"
        card.update(
            target_summary=target,
            target_kind=target_kind,
            client_summary=client_summary,
            simple_editor=rule_supports_simple_editor(card),
        )
        return card

    def _traffic_rules_page_context() -> dict[str, object]:
        clients = list_awg_clients(local_only=True)
        outbounds = list_outbounds()
        client_names = {int(client["id"]): str(client["name"]) for client in clients}
        rules = [
            _traffic_rule_card(rule, client_names)
            for rule in list_traffic_rules(include_system=False)
            if str(rule.get("action_mode") if isinstance(rule, dict) else rule["action_mode"]) in {"block", "outbound"}
        ]
        return {
            "clients": clients,
            "outbounds": outbounds,
            "enabled_outbounds": [item for item in outbounds if bool(item["enabled"])],
            "policy_rules": rules,
        }

    @app.get("/traffic-rules")
    @login_required
    def traffic_rules_page():
        return render_template("traffic_rules.html", **_traffic_rules_page_context())

    @app.get("/network")
    @login_required
    def network_page():
        tab = request.args.get("tab", "traffic-rules").strip().lower()
        if tab == "outbounds":
            return outbounds_page()
        return traffic_rules_page()

    def _simple_rule_form_state(rule: object | None) -> dict[str, object]:
        if request.method == "POST" and request.form.get("editor", "form") == "form":
            selected_ids = request.form.getlist("client_ids")
            return {
                "target_type": request.form.get("target_type", "domain"),
                "targets": request.form.get("targets", ""),
                "action_mode": request.form.get("action_mode", "block"),
                "outbound_id": request.form.get("outbound_id", ""),
                "client_scope": request.form.get("client_scope", "all"),
                "selected_client_ids": selected_ids,
            }
        if rule is None:
            return {
                "target_type": "domain",
                "targets": "",
                "action_mode": "block",
                "outbound_id": "",
                "client_scope": "all",
                "selected_client_ids": [],
            }
        row = dict(rule)
        domains = str(row.get("inline_domains") or "")
        cidrs = str(row.get("inline_cidrs") or "")
        selected_ids = [value for value in str(row.get("client_ids") or "").split(",") if value]
        return {
            "target_type": "domain" if domains else "cidr",
            "targets": domains or cidrs,
            "action_mode": str(row.get("action_mode") or "block"),
            "outbound_id": str(row.get("outbound_id") or ""),
            "client_scope": "selected" if selected_ids else "all",
            "selected_client_ids": selected_ids,
        }

    def _traffic_rule_simple_values(rule: object | None) -> dict[str, object]:
        target_type = request.form.get("target_type", "domain")
        if target_type not in {"domain", "cidr"}:
            raise ValueError("Выберите домены или IP / CIDR")
        targets = request.form.get("targets", "")
        if not str(targets).strip():
            raise ValueError("Укажите хотя бы одно назначение")
        action_mode = request.form.get("action_mode", "block")
        client_scope = request.form.get("client_scope", "all")
        selected_ids = request.form.getlist("client_ids")
        if client_scope == "selected" and not selected_ids:
            raise ValueError("Выберите хотя бы одного клиента или укажите «Все клиенты»")
        row = dict(rule) if rule is not None else {}
        return {
            "name": _automatic_rule_name(action_mode, targets),
            "priority": int(row.get("priority") or next_rule_priority()),
            "enabled": bool(row.get("enabled", True)),
            "client_ids": ",".join(selected_ids) if client_scope == "selected" else "",
            "list_id": "",
            "inline_domains": targets if target_type == "domain" else "",
            "inline_cidrs": targets if target_type == "cidr" else "",
            "protocol": "any",
            "ports": "",
            "invert_match": False,
            "schedule": "",
            "action_mode": action_mode,
            "outbound_id": request.form.get("outbound_id", ""),
            "allow_any": False,
        }

    def _traffic_list_form_values() -> dict[str, object]:
        source_mode = request.form.get("source_mode", request.form.get("source_type", "manual"))
        source_reference = request.form.get("source_url", "")
        if source_mode == "geo":
            source_reference = "geo:" + request.form.get("country_code", "")
        elif source_mode == "asn":
            source_reference = "asn:" + request.form.get("asn_number", "")
        return {
            "slug": request.form.get("slug", ""),
            "name": request.form.get("name", ""),
            "description": request.form.get("description", ""),
            "kind": request.form.get("kind", "domains"),
            "source_type": "manual" if source_mode == "manual" else "url",
            "source_url": source_reference,
            "source_format": request.form.get("source_format", "plain"),
            "content_text": request.form.get("content_text", ""),
            "enabled": request.form.get("enabled") == "1",
            "auto_update": request.form.get("auto_update") == "1",
        }

    @app.post("/traffic-rules/validate-json")
    @login_required
    def traffic_rule_validate_json():
        require_csrf()
        source = request.form.get("json_config", "")
        raw_rule_id = request.form.get("rule_id", "").strip()
        try:
            if raw_rule_id:
                rule_id = int(raw_rule_id)
                find_traffic_rule(rule_id)
                values = parse_traffic_rule_json_document(source, expected_id=rule_id)
                candidates = parse_rules_json_document(rules_json_document())
                replacement = dict(values)
                replacement["id"] = rule_id
                candidates = [
                    replacement if item.get("id") == rule_id else item
                    for item in candidates
                ]
                session_key = f"validated_rule_json_hash:{rule_id}"
            else:
                rule_id = None
                values = parse_traffic_rule_json_document(source)
                candidates = parse_rules_json_document(rules_json_document())
                candidate = dict(values)
                candidate["id"] = None
                candidates.append(candidate)
                session_key = "validated_rule_json_hash:new"
            validate_egress_runtime(candidate_rules=candidates)
            validation_token = issue_json_validation_ticket(session_key, source)
            return {
                "ok": True,
                "validationToken": validation_token,
                "message": "JSON прошёл проверку схемы, ссылок и nftables dry-run.",
                "checks": [
                    "Синтаксис JSON",
                    "Схема и допустимые поля",
                    "Ссылки на Clients и Outbounds",
                    "Временная генерация Traffic Rules",
                    "nft -c -f",
                ],
            }
        except (ValueError, PermissionError, AWGPanelError) as exc:
            scope = session_key if "session_key" in locals() else (f"validated_rule_json_hash:{raw_rule_id}" if raw_rule_id else "validated_rule_json_hash:new")
            clear_json_validation_ticket(scope)
            return _json_validation_error_payload(exc), 400

    @app.route("/traffic-rules/new", methods=["GET", "POST"])
    @login_required
    def traffic_rule_new_page():
        rule = None
        validation_passed = False
        validation_error = None
        validation_token = ""
        validation_message = ""
        editor = request.form.get("editor", request.args.get("view", "form"))
        source = request.form.get("json_config", "") if request.method == "POST" else ""
        if editor == "json" and not source:
            source = traffic_rule_json_document()
        if request.method == "POST":
            require_csrf()
            try:
                if editor == "json":
                    values = parse_traffic_rule_json_document(source)
                else:
                    values = _traffic_rule_simple_values(rule)
                if request.form.get("action", "save") == "validate":
                    candidates = parse_rules_json_document(rules_json_document())
                    values = dict(values)
                    values["id"] = None
                    candidates.append(values)
                    validate_egress_runtime(candidate_rules=candidates)
                    validation_token = issue_json_validation_ticket(
                        "validated_rule_json_hash:new", source
                    )
                    validation_passed = True
                    validation_message = "JSON правила прошёл проверку схемы, ссылок и nftables dry-run. Изменения не применены."
                else:
                    if editor == "json":
                        require_json_validation_ticket(
                            "validated_rule_json_hash:new",
                            source,
                            request.form.get("validation_token", ""),
                        )
                        candidates = parse_rules_json_document(rules_json_document())
                        checked = dict(values)
                        checked["id"] = None
                        candidates.append(checked)
                        validate_egress_runtime(candidate_rules=candidates)
                    def mutation():
                        saved = save_traffic_rule(None, values)
                        ensure_rule_dns_control(saved, force_redirect=True)
                        return saved
                    mutate_traffic_and_apply(mutation)
                    flash("Правило создано и применено.", "success")
                    return redirect(url_for("traffic_rules_page"))
            except (ValueError, PermissionError, AWGPanelError) as exc:
                flash(str(exc), "error")
                if editor == "json":
                    validation_token = ""
                    validation_passed = False
                    validation_error = _json_validation_error_payload(exc)
        return render_template(
            "traffic_rule_edit.html",
            rule=rule,
            editor=editor,
            rule_json=source,
            form_state=_simple_rule_form_state(rule),
            simple_editor_available=True,
            clients=list_awg_clients(local_only=True),
            outbounds=list_outbounds(enabled_only=True),
            validation_passed=validation_passed,
            validation_error=validation_error,
            validation_token=validation_token,
            validation_message=validation_message,
        )

    @app.route("/traffic-rules/<int:rule_id>/edit", methods=["GET", "POST"])
    @login_required
    def traffic_rule_edit_page(rule_id: int):
        rule = find_traffic_rule(rule_id)
        validation_passed = False
        validation_error = None
        validation_token = ""
        validation_message = ""
        editor = request.form.get("editor", request.args.get("view", "form"))
        simple_available = rule_supports_simple_editor(rule)
        if editor == "form" and not simple_available:
            editor = "json"
        source = request.form.get("json_config", "") if request.method == "POST" else ""
        if editor == "json" and not source:
            source = traffic_rule_json_document(rule_id)
        if request.method == "POST":
            require_csrf()
            try:
                if editor == "json":
                    values = parse_traffic_rule_json_document(source, expected_id=rule_id)
                else:
                    if not simple_available:
                        raise ValueError("Это правило содержит расширенные параметры и редактируется через JSON")
                    values = _traffic_rule_simple_values(rule)
                if request.form.get("action", "save") == "validate":
                    candidates = parse_rules_json_document(rules_json_document())
                    replacement = dict(values)
                    replacement["id"] = rule_id
                    candidates = [replacement if item.get("id") == rule_id else item for item in candidates]
                    validate_egress_runtime(candidate_rules=candidates)
                    validation_token = issue_json_validation_ticket(
                        f"validated_rule_json_hash:{rule_id}", source
                    )
                    validation_passed = True
                    validation_message = "JSON правила прошёл проверку схемы, ссылок и nftables dry-run. Изменения не применены."
                else:
                    if editor == "json":
                        require_json_validation_ticket(
                            f"validated_rule_json_hash:{rule_id}",
                            source,
                            request.form.get("validation_token", ""),
                        )
                        candidates = parse_rules_json_document(rules_json_document())
                        replacement = dict(values)
                        replacement["id"] = rule_id
                        candidates = [replacement if item.get("id") == rule_id else item for item in candidates]
                        validate_egress_runtime(candidate_rules=candidates)
                    def mutation():
                        saved = save_traffic_rule(rule_id, values)
                        ensure_rule_dns_control(saved, force_redirect=True)
                        return saved
                    rule = mutate_traffic_and_apply(mutation)
                    flash("Правило сохранено и применено.", "success")
                    return redirect(url_for("traffic_rules_page"))
            except (ValueError, PermissionError, AWGPanelError) as exc:
                flash(str(exc), "error")
                if editor == "json":
                    validation_token = ""
                    validation_passed = False
                    validation_error = _json_validation_error_payload(exc)
                rule = find_traffic_rule(rule_id)
        return render_template(
            "traffic_rule_edit.html",
            rule=rule,
            editor=editor,
            rule_json=source,
            form_state=_simple_rule_form_state(rule),
            simple_editor_available=simple_available,
            clients=list_awg_clients(local_only=True),
            outbounds=list_outbounds(enabled_only=True),
            validation_passed=validation_passed,
            validation_error=validation_error,
            validation_token=validation_token,
            validation_message=validation_message,
        )

    @app.post("/traffic-rules/<int:rule_id>/delete")
    @login_required
    def traffic_rule_delete_action(rule_id: int):
        require_csrf()
        try:
            mutate_traffic_and_apply(lambda: delete_traffic_rule(rule_id))
            flash("Traffic Rules Rule удалён.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("traffic_rules_page"))

    @app.post("/traffic-rules/<int:rule_id>/toggle")
    @login_required
    def traffic_rule_toggle_action(rule_id: int):
        require_csrf()
        current = find_traffic_rule(rule_id)
        values = {
            "name": current["name"], "priority": current["priority"],
            "enabled": not bool(current["enabled"]),
            "client_ids": current["client_ids"], "list_id": current["list_id"],
            "inline_domains": current["inline_domains"],
            "inline_cidrs": current["inline_cidrs"], "protocol": current["protocol"],
            "ports": current["ports"], "invert_match": bool(current["invert_match"]),
            "schedule": current["schedule"], "action_mode": current["action_mode"],
            "outbound_id": current["outbound_id"],
            "allow_any": not current["list_id"] and not current["inline_domains"] and not current["inline_cidrs"],
        }
        try:
            mutate_traffic_and_apply(lambda: save_traffic_rule(rule_id, values))
            flash("Состояние Traffic Rules Rule изменено.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("traffic_rules_page"))

    @app.post("/traffic-rules/<int:rule_id>/move/<direction>")
    @login_required
    def traffic_rule_move_action(rule_id: int, direction: str):
        require_csrf()
        ids = [int(row["id"]) for row in list_traffic_rules()]
        if rule_id in ids and direction in {"up", "down"}:
            index = ids.index(rule_id)
            target = index - 1 if direction == "up" else index + 1
            if 0 <= target < len(ids):
                ids[index], ids[target] = ids[target], ids[index]
                try:
                    mutate_traffic_and_apply(lambda: reorder_traffic_rules(ids))
                except (ValueError, PermissionError, AWGPanelError) as exc:
                    flash(str(exc), "error")
        return redirect(url_for("traffic_rules_page"))

    @app.route("/traffic-rules/json", methods=["GET", "POST"])
    @login_required
    def traffic_rules_json_page():
        scope = "traffic-rules"
        source = rules_json_document()
        validation_passed = False
        validation_token = ""
        validation_error = None
        validation_message = ""

        def validate_source():
            rules = parse_rules_json_document(source)
            validate_egress_runtime(candidate_rules=rules)
            return rules

        if request.method == "GET":
            clear_json_validation_ticket(scope)
        else:
            require_csrf()
            source = request.form.get("json_config", "")
            action = request.form.get("action", "")
            try:
                if action == "validate":
                    rules, validation_token = validate_json_submission(scope, source, validate_source)
                    validation_passed = True
                    validation_message = (
                        f"Traffic Rules JSON прошёл схему, ссылки и nftables dry-run. "
                        f"Правил: {len(rules)}. Изменения не применены."
                    )
                elif action == "save":
                    rules = require_validated_json_submission(
                        scope, source, request.form.get("validation_token", ""), validate_source
                    )
                    mutate_traffic_and_apply(lambda: replace_rules_document(rules))
                    flash("Traffic Rules JSON сохранён и применён.", "success")
                    return redirect(url_for("traffic_rules_page"))
                else:
                    raise ValueError("Неизвестное действие JSON-редактора")
            except (ValueError, PermissionError, AWGPanelError) as exc:
                clear_json_validation_ticket(scope)
                validation_error = json_editor_error(exc)
                validation_passed = False
                validation_token = ""
        return render_template(
            "traffic_rules_json.html", network_json=source,
            validation_passed=validation_passed, validation_token=validation_token,
            validation_error=validation_error, validation_message=validation_message,
        )

    @app.post("/traffic-rules/egress/<int:client_id>")
    @login_required
    def client_egress_save(client_id: int):
        require_csrf()
        mode = request.form.get("egress_mode", AWG_GATEWAY)
        outbound_value = request.form.get("outbound_id", "").strip()
        outbound_id = int(outbound_value) if outbound_value.isdigit() else None
        try:
            client = set_client_egress(client_id, mode, outbound_id)
            label = egress_mode_label(client["egress_mode"])
            flash(f"Выход клиента {client['name']} изменён: {label}.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("traffic_rules_page"))

    @app.post("/traffic-rules/outbounds")
    @app.post("/outbounds")
    @login_required
    def outbound_add():
        require_csrf()
        try:
            outbound = create_outbound(
                request.form.get("name", ""),
                request.form.get("config_text", ""),
            )
            flash(f"Outbound {outbound['name']} добавлен и проверен.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("outbounds_page"))

    @app.post("/traffic-rules/outbounds/<int:outbound_id>")
    @app.post("/outbounds/<int:outbound_id>")
    @login_required
    def outbound_update(outbound_id: int):
        require_csrf()
        action = request.form.get("action", "save")
        try:
            if action == "toggle":
                current = find_outbound(outbound_id)
                outbound = set_outbound_enabled(outbound_id, not bool(current["enabled"]))
                flash(
                    f"Outbound {outbound['name']} "
                    + ("включён." if outbound["enabled"] else "отключён."),
                    "success",
                )
            elif action == "delete":
                outbound = delete_outbound(outbound_id)
                flash(f"Outbound {outbound['name']} удалён.", "success")
            else:
                outbound = replace_outbound(
                    outbound_id,
                    name=request.form.get("name", ""),
                    config_text=request.form.get("config_text", ""),
                )
                flash(f"Outbound {outbound['name']} обновлён и проверен.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("outbounds_page"))

    @app.get("/dns")
    @login_required
    def dns_page():
        return render_template("dns.html", settings=get_awg_settings())

    @app.post("/dns")
    @login_required
    def dns_save():
        require_csrf()
        try:
            settings = mutate_traffic_and_apply(
                lambda: update_dns_servers(request.form.get("dns_servers", ""))
            )
            flash(
                f"Внешние DNS-серверы сохранены и применены: {settings['dns_servers']}.",
                "success",
            )
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("dns_page"))

    @app.route("/dns/json", methods=["GET", "POST"])
    @login_required
    def dns_json_page():
        scope = "dns"
        source = dns_json_document(get_awg_settings())
        validation_passed = False
        validation_token = ""
        validation_error = None
        validation_message = ""

        def validate_source():
            return parse_dns_json_document(source)

        if request.method == "GET":
            clear_json_validation_ticket(scope)
        else:
            require_csrf()
            source = request.form.get("json_config", "")
            action = request.form.get("action", "")
            try:
                if action == "validate":
                    _, validation_token = validate_json_submission(scope, source, validate_source)
                    validation_passed = True
                    validation_message = "DNS JSON прошёл проверку. Изменения не применены."
                elif action == "save":
                    dns_servers = require_validated_json_submission(
                        scope, source, request.form.get("validation_token", ""), validate_source
                    )
                    mutate_traffic_and_apply(lambda: update_dns_servers(dns_servers))
                    flash("JSON DNS сохранён и применён.", "success")
                    return redirect(url_for("dns_page"))
                else:
                    raise ValueError("Неизвестное действие JSON-редактора")
            except (ValueError, PermissionError, AWGPanelError) as exc:
                clear_json_validation_ticket(scope)
                validation_error = json_editor_error(exc)
                validation_passed = False
                validation_token = ""
        return render_template(
            "section_json.html", section="DNS / JSON", heading="DNS JSON",
            subtitle="Внешние DNS-серверы для автоматической обработки запросов",
            format_name="DNS-V1", object_title="Внешние DNS-серверы",
            description="Форма и JSON изменяют одни и те же внешние DNS-серверы. Клиенты используют DNS текущий сервер автоматически.",
            back_url=url_for("dns_page"), json_config=source,
            validation_passed=validation_passed, validation_token=validation_token,
            validation_error=validation_error, validation_message=validation_message,
        )

    @app.get("/config")
    @login_required
    def config_page():
        clear_json_validation_ticket("full-config")
        return render_template(
            "config.html",
            current_json=panel_config_document(),
            section_json=section_json_configs(),
            generated=generated_configs(),
            editor_active=False,
            validation_passed=False, validation_token="",
            validation_error=None, validation_message="",
        )

    @app.post("/config")
    @login_required
    def config_save():
        scope = "full-config"
        require_csrf()
        raw = request.form.get("json_config", "")
        action = request.form.get("action", "")
        validation_passed = False
        validation_token = ""
        validation_error = None
        validation_message = ""

        def validate_source():
            return validate_panel_config_document(raw)

        try:
            if action == "validate":
                result, validation_token = validate_json_submission(scope, raw, validate_source)
                validation_passed = True
                validation_message = (
                    "Полный JSON прошёл синтаксическую, семантическую и системную dry-run "
                    f"проверку. Правил: {len(result['traffic_policy_rules'])}; "
                    f"Outbounds: {len(result['outbounds'])}. Изменения не применены."
                )
            elif action == "save":
                require_validated_json_submission(
                    scope, raw, request.form.get("validation_token", ""), validate_source
                )
                apply_panel_config_document(raw, current_ip=client_ip())
                panel = get_panel_settings()
                record_auth_event(
                    "config_applied", ip_address=client_ip(), user_agent=client_agent(),
                    detail=panel_public_url(panel),
                )
                unit = f"sg-awg-panel-restart-{secrets.token_hex(4)}"
                subprocess.run(
                    [
                        "systemd-run", f"--unit={unit}", "--collect", "--on-active=2s",
                        "/bin/systemctl", "restart", "sg-awg-panel.service",
                    ],
                    check=False, capture_output=True, text=True, timeout=10,
                )
                flash("Полный JSON сохранён и применён.", "success")
                target = current_public_url(panel)
                return redirect(target + url_for("config_page") + "#full-json")
            else:
                raise ValueError("Неизвестное действие JSON-редактора")
        except (ValueError, PermissionError, AWGPanelError, OSError, subprocess.TimeoutExpired) as exc:
            clear_json_validation_ticket(scope)
            validation_error = json_editor_error(exc)
            validation_passed = False
            validation_token = ""
        return render_template(
            "config.html", current_json=raw,
            section_json=section_json_configs(), generated=generated_configs(),
            editor_active=True, validation_passed=validation_passed,
            validation_token=validation_token, validation_error=validation_error,
            validation_message=validation_message,
        )

    @app.get("/config/download")
    @login_required
    def config_download():
        payload = panel_config_document().encode("utf-8")
        return send_file(
            io.BytesIO(payload), mimetype="application/json", as_attachment=True,
            download_name=f"sg-awg-panel-{__version__}.json",
        )

    @app.get("/config/generated/<kind>/download")
    @login_required
    def generated_config_download(kind: str):
        configs = generated_configs()
        if kind not in configs:
            abort(404)
        item = configs[kind]
        return send_file(
            io.BytesIO(item["content"].encode("utf-8")),
            mimetype="text/plain; charset=utf-8", as_attachment=True,
            download_name=item["filename"],
        )


    @app.get("/config/sections/<kind>/download")
    @login_required
    def section_json_download(kind: str):
        configs = section_json_configs()
        if kind not in configs:
            abort(404)
        item = configs[kind]
        return send_file(
            io.BytesIO(item["content"].encode("utf-8")),
            mimetype="application/json; charset=utf-8", as_attachment=True,
            download_name=item["filename"],
        )

    @app.get("/system")
    @login_required
    def system_page():
        data = get_awg_diagnostics()
        settings = get_awg_settings()
        configured = bool(settings["configured"])
        traffic = data.get("traffic", {})
        web_ok = data.get("panel_state") == "active" and data.get("nginx_state") == "active"
        awg_ok = (not configured) or (
            data.get("service_state") == "active" and bool(data.get("interface_present"))
        )
        traffic_ok = data.get("traffic_state") in {"active", "activating"} and bool(traffic.get("nft_ready"))
        internet_ok = (not configured) or bool(
            awg_ok and traffic_ok and data.get("ip_forward") and data.get("nat_rule")
        )
        checks = [
            {"name": "Web-панель", "ok": web_ok, "value": "Работает" if web_ok else "Не работает"},
            {"name": "AWG Server", "ok": awg_ok, "neutral": not configured, "value": "Ожидает настройки" if not configured else ("Работает" if awg_ok else "Не работает")},
            {"name": "Traffic Rules", "ok": traffic_ok, "value": "Работают" if traffic_ok else "Не работают"},
            {"name": "Доступ клиентов в интернет", "ok": internet_ok, "neutral": not configured, "value": "Ожидает настройки" if not configured else ("Работает" if internet_ok else "Не работает")},
        ]
        problems = [item for item in checks if not item.get("ok") and not item.get("neutral")]
        requested_tab = request.args.get("tab", "resources").strip().lower()
        tab_aliases = {
            "status": "status-services",
            "services": "status-services",
            "logs": "logs-diagnostics",
            "diagnostics": "logs-diagnostics",
        }
        tab = tab_aliases.get(requested_tab, requested_tab)
        if tab not in {"resources", "status-services", "logs-diagnostics"}:
            tab = "resources"
        services = [
            {"unit": "sg-awg-panel.service", "title": "Backend панели", "state": data.get("panel_state"), "enabled": data.get("panel_enabled")},
            {"unit": "sg-awg-server.service", "title": "Интерфейс awg0", "state": data.get("service_state"), "enabled": data.get("awg_enabled")},
            {"unit": "sg-awg-traffic.service", "title": "Traffic Rules", "state": data.get("traffic_state"), "enabled": data.get("traffic_enabled")},
            {"unit": "sg-awg-recovery.service", "title": "Восстановление после reboot", "state": data.get("recovery_state"), "enabled": data.get("recovery_enabled")},
            {"unit": "nginx.service", "title": "Публичный доступ", "state": data.get("nginx_state"), "enabled": data.get("nginx_enabled")},
        ]
        return render_template(
            "system.html", diagnostics=data, checks=checks, problems=problems,
            services=services, active_tab=tab, resources=data.get("resources", {}),
            panel=get_panel_settings(),
        )

    @app.post("/system/identity")
    @login_required
    def system_identity_update():
        require_csrf()
        try:
            panel = configure_instance_name(request.form.get("instance_name", ""))
            flash(f"Имя сервера изменено: {panel['instance_name']}", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return_to = str(request.form.get("return_to") or "").strip()
        if return_to.startswith("/") and not return_to.startswith("//"):
            return redirect(return_to)
        return_tab = request.form.get("return_tab", "resources").strip().lower()
        if return_tab not in {"resources", "status-services", "logs-diagnostics"}:
            return_tab = "resources"
        return redirect(url_for("system_page", tab=return_tab))

    @app.get("/system/resources.json")
    @login_required
    def system_resources_json():
        payload = json.dumps(
            {"resources": get_system_resources()},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        response = Response(payload, mimetype="application/json")
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/diagnostics")
    @login_required
    def diagnostics():
        return redirect(url_for("system_page", tab="logs-diagnostics"))

    @app.get("/diagnostics/report")
    @login_required
    def diagnostics_report():
        report = build_diagnostic_report()
        return send_file(
            io.BytesIO(report.encode("utf-8")),
            mimetype="text/plain; charset=utf-8",
            as_attachment=True,
            download_name="sg-awg-panel-diagnostics.txt",
        )

    @app.get("/diagnostics/report.json")
    @login_required
    def diagnostics_json_report():
        data = get_awg_diagnostics()
        safe = {
            "version": __version__,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "services": {
                "panel": data.get("panel_state"),
                "awg": data.get("service_state"),
                "nginx": data.get("nginx_state"),
                "recovery": data.get("recovery_state"),
                "traffic": data.get("traffic_state"),
            },
            "checks": {
                "panelEnabled": bool(data.get("panel_enabled")),
                "awgEnabled": bool(data.get("awg_enabled")),
                "nginxEnabled": bool(data.get("nginx_enabled")),
                "recoveryEnabled": bool(data.get("recovery_enabled")),
                "trafficEnabled": bool(data.get("traffic_enabled")),
                "backendLoopbackOnly": bool(data.get("backend", {}).get("loopback_only")),
                "configExists": bool(data.get("config_exists")),
                "ipForward": bool(data.get("ip_forward")),
                "natMasquerade": bool(data.get("nat_rule")),
                "moduleLoaded": bool(data.get("module_loaded")),
                "interfacePresent": bool(data.get("interface_present")),
            },
            "network": {
                "publicIPv4": data.get("public_ipv4"),
                "externalInterface": data.get("external_interface"),
                "backendPort": data.get("backend_port"),
                "listenPort": data.get("listen_port"),
            },
            "resources": data.get("resources", {}),
            "traffic": data.get("traffic", {}),
            "backupCount": len(data.get("backups", [])),
        }
        payload = (json.dumps(safe, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        return send_file(
            io.BytesIO(payload), mimetype="application/json", as_attachment=True,
            download_name="sg-awg-panel-diagnostics.json",
        )

    @app.get("/backups")
    @login_required
    def backups_page():
        reason_labels = {
            "manual": "Ручная резервная копия",
            "scheduled": "Автоматическая резервная копия",
            "client-add": "Добавлен клиент",
            "client-delete": "Удалён клиент",
            "client-settings": "Изменены настройки клиента",
            "client-toggle": "Изменено состояние клиента",
            "client-regenerate": "Пересозданы ключи клиента",
            "server-apply": "Изменены настройки AWG Server",
            "server-json": "Применён JSON AWG Server",
            "traffic-rules": "Изменены Traffic Rules",
            "outbound-create": "Добавлен Outbound",
            "outbound-update": "Изменён Outbound",
            "outbound-delete": "Удалён Outbound",
            "pre-update": "Перед обновлением панели",
            "config-apply": "Применён полный Config",
        }
        all_backups = list_backups(limit=200)
        for item in all_backups:
            reason = str(item.get("reason") or "manual")
            item["display_reason"] = reason_labels.get(reason, reason.replace("-", " ").capitalize())
            item["category"] = (
                "automatic" if reason in {"scheduled", "timer"}
                else "manual" if reason == "manual"
                else "update" if "update" in reason
                else "change"
            )
            raw_created = str(item.get("created_at") or "")
            try:
                moment = datetime.fromisoformat(raw_created.replace("Z", "+00:00"))
                item["display_time"] = moment.astimezone(timezone.utc).strftime("%d.%m.%Y, %H:%M UTC")
            except ValueError:
                item["display_time"] = raw_created or item["name"]
        category = request.args.get("category", "all").strip().lower()
        query = request.args.get("q", "").strip().lower()
        backups = all_backups
        if category in {"automatic", "manual", "change", "update"}:
            backups = [item for item in backups if item.get("category") == category]
        else:
            category = "all"
        if query:
            backups = [
                item for item in backups
                if query in str(item.get("name", "")).lower()
                or query in str(item.get("display_reason", "")).lower()
                or query in str(item.get("display_time", "")).lower()
            ]
        panel = get_panel_settings()
        return render_template(
            "backups.html", backups=backups, all_backups=all_backups, panel=panel,
            category=category, query=query,
            latest_backup=all_backups[0] if all_backups else None,
        )

    @app.post("/backups/policy")
    @login_required
    def backup_policy_save():
        require_csrf()
        try:
            panel = configure_backup_policy(
                request.form.get("backup_schedule", "daily"),
                request.form.get("backup_keep", "20"),
            )
            flash(
                f"Расписание резервных копий сохранено. Хранится {panel['backup_keep']} копий.",
                "success",
            )
        except (ValueError, PermissionError, AWGPanelError, OSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("backups_page"))

    @app.route("/backups/json", methods=["GET", "POST"])
    @login_required
    def backups_json_page():
        scope = "backups"
        source = backup_json_document(get_panel_settings())
        validation_passed = False
        validation_token = ""
        validation_error = None
        validation_message = ""

        def validate_source():
            return parse_backup_json_document(source)

        if request.method == "GET":
            clear_json_validation_ticket(scope)
        else:
            require_csrf()
            source = request.form.get("json_config", "")
            action = request.form.get("action", "")
            try:
                if action == "validate":
                    _, validation_token = validate_json_submission(scope, source, validate_source)
                    validation_passed = True
                    validation_message = (
                        "JSON политики резервных копий прошёл проверку. "
                        "Изменения не применены."
                    )
                elif action == "save":
                    schedule, keep = require_validated_json_submission(
                        scope, source, request.form.get("validation_token", ""), validate_source
                    )
                    configure_backup_policy(schedule, keep)
                    flash("JSON политики резервных копий сохранён.", "success")
                    return redirect(url_for("backups_page"))
                else:
                    raise ValueError("Неизвестное действие JSON-редактора")
            except (ValueError, PermissionError, AWGPanelError, OSError) as exc:
                clear_json_validation_ticket(scope)
                validation_error = json_editor_error(exc)
                validation_passed = False
                validation_token = ""
        return render_template(
            "section_json.html", section="BACKUPS / JSON", heading="Резервные копии JSON",
            subtitle="Расписание и количество хранимых копий",
            format_name="BACKUPS-V1", object_title="Политика резервных копий",
            description="Создание и восстановление копий остаются отдельными действиями. JSON изменяет только постоянную политику.",
            back_url=url_for("backups_page"), json_config=source,
            validation_passed=validation_passed, validation_token=validation_token,
            validation_error=validation_error, validation_message=validation_message,
        )

    @app.post("/backups/create")
    @login_required
    def backup_create():
        require_csrf()
        try:
            backup = create_manual_backup()
            flash(f"Резервная копия создана и проверена: {backup.name}", "success")
        except (PermissionError, AWGPanelError, OSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("backups_page"))

    @app.post("/backups/<name>/verify")
    @login_required
    def backup_verify(name: str):
        require_csrf()
        try:
            result = verify_backup(name)
            if result["verified"]:
                flash(f"Резервная копия проверена: {name}", "success")
            else:
                flash("Проверка не пройдена: " + "; ".join(result["verification_errors"]), "error")
        except (PermissionError, AWGPanelError, OSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("backups_page"))

    @app.get("/backups/<name>/download")
    @login_required
    def backup_download(name: str):
        try:
            backup = find_backup_path(name)
            verification = verify_backup(name)
            if not verification["verified"]:
                raise AWGPanelError("Нельзя скачать повреждённую резервную копию")
            payload = io.BytesIO()
            with tarfile.open(fileobj=payload, mode="w:gz") as archive:
                archive.add(backup, arcname=backup.name, recursive=True)
            payload.seek(0)
            return send_file(
                payload,
                mimetype="application/gzip",
                as_attachment=True,
                download_name=f"{backup.name}.tar.gz",
                max_age=0,
            )
        except (PermissionError, AWGPanelError, OSError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("backups_page"))

    @app.post("/backups/<name>/restore")
    @login_required
    def backup_restore(name: str):
        require_csrf()
        try:
            # A lightweight verification happens before the background restore.
            verification = verify_backup(name)
            if not verification["verified"]:
                raise AWGPanelError(
                    "Проверка не пройдена: "
                    + "; ".join(verification["verification_errors"])
                )
            job = start_operation_job(
                kind="backup_restore",
                title=f"Восстановление резервной копии {name}",
                payload={"name": name},
                success_path=url_for("backups_page"),
                error_path=url_for("backups_page"),
            )
            return redirect(url_for("operation_progress", token=job["token"]))
        except (PermissionError, AWGPanelError, OSError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("backups_page"))

    @app.get("/security")
    @login_required
    def security_page():
        token = str(session.get("session_token", ""))
        tab = request.args.get("tab", "access").strip().lower()
        if tab not in {"access", "credentials", "sessions", "events"}:
            tab = "access"
        panel = get_panel_settings()
        event_labels = {
            "login_success": ("Успешный вход", "success"),
            "login_failed": ("Неверный пароль", "danger"),
            "login_blocked": ("Вход временно заблокирован", "warning"),
            "login_error": ("Ошибка входа", "danger"),
            "logout": ("Выход", "neutral"),
            "password_changed": ("Пароль изменён", "success"),
            "password_change_failed": ("Ошибка смены пароля", "danger"),
            "allowlist_changed": ("IP allowlist изменён", "warning"),
            "allowlist_change_failed": ("Ошибка IP allowlist", "danger"),
            "session_revoked": ("Сессия завершена", "warning"),
            "sessions_revoked": ("Сессии завершены", "warning"),
        }
        auth_events = []
        for row in list_auth_events(limit=100):
            item = dict(row)
            label, css_class = event_labels.get(
                str(item.get("event_type", "")),
                (str(item.get("event_type", "Событие")).replace("_", " "), "neutral"),
            )
            item["display_type"] = label
            item["display_class"] = css_class
            auth_events.append(item)
        return render_template(
            "security.html",
            secure_cookies=app.config["SESSION_COOKIE_SECURE"],
            trust_proxy=_bool_env("AWGPANEL_TRUST_PROXY_HEADERS", False),
            panel=panel,
            public_url=current_public_url(panel),
            bind_address=os.environ.get("AWGPANEL_BIND_ADDRESS", "127.0.0.1"),
            backend_port=os.environ.get("AWGPANEL_PORT", "18080"),
            sessions=list_web_sessions(current_token=token),
            auth_events=auth_events,
            current_ip=client_ip(), active_tab=tab,
        )

    @app.route("/security/placeholder", methods=["GET", "POST"])
    @login_required
    def placeholder_page():
        mode = request.args.get("mode", "simple")
        current_html = read_placeholder_html()
        if request.method == "POST":
            require_csrf()
            action = request.form.get("action", "save")
            try:
                if action == "reset":
                    reset_placeholder_html()
                    flash("Стандартная заглушка восстановлена.", "success")
                    return redirect(url_for("placeholder_page"))
                upload = request.files.get("html_file")
                if upload and upload.filename:
                    raw = upload.read(256 * 1024 + 1)
                    if len(raw) > 256 * 1024:
                        raise ValueError("Файл index.html превышает 256 KiB")
                    value = raw.decode("utf-8-sig")
                    mode = "html"
                elif request.form.get("mode") == "html":
                    value = request.form.get("html_content", "")
                    mode = "html"
                else:
                    title = str(request.form.get("title", "Welcome")).strip() or "Welcome"
                    message = str(request.form.get("message", "This web server is running normally.")).strip()
                    site_name = str(request.form.get("site_name", "")).strip()
                    link = str(request.form.get("link", "")).strip()
                    if link and not re.fullmatch(r"https?://[^\s]{3,2048}", link):
                        raise ValueError("Ссылка должна начинаться с http:// или https://")
                    link_html = ""
                    if link:
                        safe_link = html_module.escape(link, quote=True)
                        safe_label = html_module.escape(site_name or link)
                        link_html = f'<p><a href="{safe_link}">{safe_label}</a></p>'
                    safe_title = html_module.escape(title)
                    safe_message = html_module.escape(message)
                    value = (
                        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
                        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
                        f'<title>{safe_title}</title><style>'
                        'body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,sans-serif;background:#f5f7fb;color:#1b2533}'
                        'main{max-width:42rem;padding:3rem;text-align:center}h1{font-size:2.4rem;margin:0 0 1rem}'
                        'p{line-height:1.6;color:#526071}a{color:#2457d6}</style></head>\n'
                        f'<body><main><h1>{safe_title}</h1><p>{safe_message}</p>{link_html}</main></body></html>\n'
                    )
                    mode = "simple"
                save_placeholder_html(value)
                flash("Страница-заглушка сохранена.", "success")
                return redirect(url_for("placeholder_page", mode=mode))
            except (UnicodeDecodeError, ValueError, PermissionError, OSError) as exc:
                flash(str(exc), "error")
                current_html = request.form.get("html_content", current_html)
        return render_template(
            "placeholder.html",
            current_html=current_html,
            mode=mode,
            public_url=current_public_url(),
            panel=get_panel_settings(),
        )

    @app.route("/security/placeholder/json", methods=["GET", "POST"])
    @login_required
    def placeholder_json_page():
        scope = "placeholder"
        source = json.dumps(
            {"_sgAwgPanel": {"format": "placeholder-v1"}, "html": read_placeholder_html()},
            ensure_ascii=False, indent=2,
        ) + "\n"
        validation_passed = False
        validation_token = ""
        validation_error = None
        validation_message = ""

        def validate_source():
            document = json.loads(source)
            if not isinstance(document, dict):
                raise ValueError("$: JSON должен быть объектом")
            unknown = sorted(set(document) - {"_sgAwgPanel", "html"})
            if unknown:
                raise ValueError(f"$: неизвестные поля: {', '.join(unknown)}")
            if not isinstance(document.get("html"), str):
                raise ValueError("html: должно быть строкой")
            if not document["html"].strip():
                raise ValueError("html: не может быть пустым")
            meta = document.get("_sgAwgPanel", {})
            if not isinstance(meta, dict):
                raise ValueError("_sgAwgPanel: должен быть JSON-объектом")
            if meta.get("format") not in (None, "placeholder-v1"):
                raise ValueError("_sgAwgPanel.format: должен быть placeholder-v1")
            return document

        if request.method == "GET":
            clear_json_validation_ticket(scope)
        else:
            require_csrf()
            source = request.form.get("json_config", "")
            action = request.form.get("action", "")
            try:
                if action == "validate":
                    _, validation_token = validate_json_submission(scope, source, validate_source)
                    validation_passed = True
                    validation_message = "JSON заглушки прошёл проверку. Изменения не применены."
                elif action == "save":
                    document = require_validated_json_submission(
                        scope, source, request.form.get("validation_token", ""), validate_source
                    )
                    save_placeholder_html(document["html"])
                    flash("JSON заглушки сохранён.", "success")
                    return redirect(url_for("placeholder_page", mode="html"))
                else:
                    raise ValueError("Неизвестное действие JSON-редактора")
            except (json.JSONDecodeError, ValueError, PermissionError, OSError) as exc:
                clear_json_validation_ticket(scope)
                validation_error = json_editor_error(exc)
                validation_passed = False
                validation_token = ""
        return render_template(
            "section_json.html", section="SECURITY / PLACEHOLDER / JSON",
            heading="Заглушка JSON", subtitle="Полный HTML страницы на TCP 443",
            format_name="PLACEHOLDER-V1", object_title="Страница-заглушка",
            description="Сохранение атомарно заменяет только index.html. Конфигурация Nginx не редактируется.",
            back_url=url_for("placeholder_page"), json_config=source,
            validation_passed=validation_passed, validation_token=validation_token,
            validation_error=validation_error, validation_message=validation_message,
        )

    @app.route("/security/json", methods=["GET", "POST"])
    @login_required
    def security_json_page():
        scope = "security"
        source = security_json_document(get_panel_settings())
        validation_passed = False
        validation_token = ""
        validation_error = None
        validation_message = ""

        def validate_source():
            access_values, allowlist = parse_security_json_document(source)
            if allowlist and not ip_is_allowed(client_ip(), allowlist):
                raise ValueError(
                    f"security.ipAllowlist: текущий IP {client_ip()} не входит в новый allowlist"
                )
            return access_values, allowlist

        if request.method == "GET":
            clear_json_validation_ticket(scope)
        else:
            require_csrf()
            source = request.form.get("json_config", "")
            action = request.form.get("action", "")
            try:
                if action == "validate":
                    _, validation_token = validate_json_submission(scope, source, validate_source)
                    validation_passed = True
                    validation_message = (
                        "Security JSON прошёл проверку адреса, порта и IP allowlist. "
                        "Изменения не применены."
                    )
                elif action == "save":
                    access_values, allowlist = require_validated_json_submission(
                        scope, source, request.form.get("validation_token", ""), validate_source
                    )
                    update_ip_allowlist(allowlist, current_ip=client_ip())
                    job = start_panel_access_job(**access_values)
                    record_auth_event(
                        "security_json_started", ip_address=client_ip(),
                        user_agent=client_agent(), detail=str(job["target_url"]),
                    )
                    return redirect(url_for("panel_access_job_progress", token=job["token"]))
                else:
                    raise ValueError("Неизвестное действие JSON-редактора")
            except (ValueError, PermissionError, AWGPanelError, OSError, subprocess.TimeoutExpired) as exc:
                clear_json_validation_ticket(scope)
                validation_error = json_editor_error(exc)
                validation_passed = False
                validation_token = ""
        return render_template(
            "section_json.html", section="SECURITY / JSON", heading="Security JSON",
            subtitle="Публичный адрес панели и IP allowlist",
            format_name="SECURITY-V1", object_title="Постоянные настройки Security",
            description="Пароль и активные сессии не экспортируются: это отдельные защищённые действия.",
            back_url=url_for("security_page"), json_config=source,
            validation_passed=validation_passed, validation_token=validation_token,
            validation_error=validation_error, validation_message=validation_message,
        )

    @app.post("/security/password")
    @login_required
    def security_password():
        require_csrf()
        current = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirmation = request.form.get("new_password_2", "")
        current_hash = os.environ.get("AWGPANEL_PASSWORD_HASH", "")
        if not current_hash or not check_password_hash(current_hash, current):
            record_auth_event("password_change_failed", ip_address=client_ip(), user_agent=client_agent())
            flash("Текущий пароль указан неверно.", "error")
            return redirect(url_for("security_page", tab="credentials"))
        if len(new_password) < MIN_PASSWORD_LENGTH:
            flash(
                f"Новый пароль должен содержать не менее {MIN_PASSWORD_LENGTH} символов.",
                "error",
            )
            return redirect(url_for("security_page", tab="credentials"))
        if new_password != confirmation:
            flash("Новые пароли не совпадают.", "error")
            return redirect(url_for("security_page", tab="credentials"))
        new_hash = generate_password_hash(new_password)
        _write_env_value("AWGPANEL_PASSWORD_HASH", new_hash)
        os.environ["AWGPANEL_PASSWORD_HASH"] = new_hash
        rotate_auth_epoch()
        record_auth_event("password_changed", ip_address=client_ip(), user_agent=client_agent())
        session.clear()
        return redirect(url_for("login", password_changed="1"))

    @app.post("/security/allowlist")
    @login_required
    def security_allowlist():
        require_csrf()
        try:
            panel = update_ip_allowlist(
                request.form.get("ip_allowlist", ""), current_ip=client_ip()
            )
            state = panel["ip_allowlist"] or "выключен"
            record_auth_event(
                "allowlist_changed", ip_address=client_ip(),
                user_agent=client_agent(), detail=str(state),
            )
            flash("IP allowlist сохранён.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("security_page", tab="credentials"))

    @app.post("/security/sessions/<token_hash>/revoke")
    @login_required
    def security_session_revoke(token_hash: str):
        require_csrf()
        if not re.fullmatch(r"[0-9a-f]{64}", token_hash):
            abort(400)
        current_token = str(session.get("session_token", ""))
        current_hash = hashlib.sha256(current_token.encode("utf-8")).hexdigest()
        revoke_web_session(token_hash)
        record_auth_event(
            "session_revoked", ip_address=client_ip(),
            user_agent=client_agent(), detail=token_hash[:12],
        )
        if token_hash == current_hash:
            session.clear()
            return redirect(url_for("login"))
        flash("Сессия завершена.", "success")
        return redirect(url_for("security_page", tab="sessions"))

    @app.post("/security/sessions/revoke-others")
    @login_required
    def security_sessions_revoke_others():
        require_csrf()
        token = str(session.get("session_token", ""))
        revoke_all_web_sessions(except_token=token)
        record_auth_event("sessions_revoked", ip_address=client_ip(), user_agent=client_agent())
        flash("Все остальные сессии завершены.", "success")
        return redirect(url_for("security_page", tab="sessions"))

    @app.get("/settings")
    @login_required
    def settings_page():
        return redirect(url_for("system_page"))

    @app.post("/settings/access")
    @app.post("/security/access")
    @login_required
    def security_access_save():
        require_csrf()
        try:
            job = start_panel_access_job(
                scheme=request.form.get("public_scheme", "http"),
                public_host=request.form.get("public_host", ""),
                public_port=request.form.get("public_port", "62443"),
                manage_placeholder=request.form.get("manage_placeholder", "0"),
            )
            record_auth_event(
                "panel_access_started", ip_address=client_ip(),
                user_agent=client_agent(), detail=str(job["target_url"]),
            )
            return redirect(url_for("panel_access_job_progress", token=job["token"]))
        except (ValueError, PermissionError, AWGPanelError, OSError, subprocess.TimeoutExpired) as exc:
            flash(str(exc), "error")
            return redirect(url_for("security_page", tab="access"))

    @app.get("/security/access/jobs/<token>")
    def panel_access_job_progress(token: str):
        job = get_panel_access_job(token)
        if job is None:
            abort(404)
        return render_template(
            "access_progress.html",
            job_token=token,
            job=job,
            target_url=str(job.get("targetUrl") or ""),
        )

    @app.get("/operations/<token>")
    @login_required
    def operation_progress(token: str):
        job = get_operation_job(token)
        if job is None:
            abort(404)
        return render_template(
            "operation_progress.html",
            token=token,
            operation=job,
            status_url=url_for("operation_status", token=token),
        )

    @app.get("/operations/<token>/status")
    def operation_status(token: str):
        job = get_operation_job(token)
        if job is None:
            abort(404)
        response = Response(
            json.dumps(job, ensure_ascii=False),
            content_type="application/json; charset=utf-8",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/security/access/jobs/<token>/status")
    def panel_access_job_status(token: str):
        job = get_panel_access_job(token)
        if job is None:
            abort(404)
        response = Response(
            json.dumps(job, ensure_ascii=False),
            content_type="application/json; charset=utf-8",
        )
        response.headers["Cache-Control"] = "no-store"
        return response


    @app.get("/security/access/jobs/<token>/events")
    def panel_access_job_events(token: str):
        if get_panel_access_job(token) is None:
            abort(404)
        try:
            offset = max(0, int(request.args.get("offset", "0")))
        except ValueError:
            offset = 0
        last_event_id = request.headers.get("Last-Event-ID", "").strip()
        if last_event_id.isdigit():
            offset = max(offset, int(last_event_id))

        @stream_with_context
        def generate():
            nonlocal offset
            # Waitress buffers application output until its high-water mark.
            # The service is configured with a one-byte high-water mark, and
            # this initial padding forces headers and the first event to leave
            # the server immediately even through Nginx.
            yield "retry: 750\n:" + (" " * 2048) + "\n\n"
            previous_status = ""
            terminal_since = None
            while True:
                job = get_panel_access_job(token)
                if job is None:
                    yield "event: error\ndata: {\"message\": \"Задача больше недоступна\"}\n\n"
                    return
                log_text = str(job.pop("log", "") or "")
                if offset > len(log_text):
                    offset = 0
                if len(log_text) > offset:
                    chunk = log_text[offset:]
                    offset = len(log_text)
                    payload = json.dumps({"text": chunk, "offset": offset}, ensure_ascii=False)
                    yield f"id: {offset}\nevent: log\ndata: {payload}\n\n"
                status_json = json.dumps(job, ensure_ascii=False, sort_keys=True)
                if status_json != previous_status:
                    previous_status = status_json
                    yield f"event: status\ndata: {status_json}\n\n"
                state = str(job.get("state") or "")
                if state in {"success", "error"}:
                    terminal_since = terminal_since or time.monotonic()
                    if time.monotonic() - terminal_since > 1.5:
                        yield "event: end\ndata: {}\n\n"
                        return
                else:
                    terminal_since = None
                yield ": keep-alive\n\n"
                time.sleep(0.25)

        response = Response(generate(), content_type="text/event-stream; charset=utf-8")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Accel-Buffering"] = "no"
        response.headers["Content-Type"] = "text/event-stream; charset=utf-8"
        response.headers["Content-Encoding"] = "identity"
        return response

    @app.get("/security/access/jobs/<token>/alive.gif")
    def panel_access_job_alive(token: str):
        if get_panel_access_job(token) is None:
            abort(404)
        pixel = (
            b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00"
            b"\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,"
            b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
        )
        response = Response(pixel, content_type="image/gif")
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/security/access/jobs/<token>/probe.gif")
    def panel_access_job_probe(token: str):
        job = get_panel_access_job(token)
        if job is None or job.get("state") != "success":
            abort(404)
        pixel = (
            b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00"
            b"\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,"
            b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
        )
        response = Response(pixel, content_type="image/gif")
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/security/access/jobs/<token>/complete")
    def panel_access_job_complete(token: str):
        job = get_panel_access_job(token)
        if job is None or job.get("state") != "success":
            abort(404)
        old_token = str(session.get("session_token", ""))
        if old_token:
            revoke_web_session(hashlib.sha256(old_token.encode("utf-8")).hexdigest())
        session.clear()
        record_auth_event(
            "panel_access_changed", ip_address=client_ip(),
            user_agent=client_agent(), detail=str(job.get("targetUrl") or ""),
        )
        return redirect(url_for("login", access_changed="1"))

    def json_response(payload: dict[str, object], status: int = 200) -> Response:
        response = Response(
            json.dumps(payload, ensure_ascii=False),
            status=status,
            content_type="application/json; charset=utf-8",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    def agent_bearer_token() -> str:
        value = request.headers.get("Authorization", "").strip()
        if not value.lower().startswith("bearer "):
            raise PermissionError("Не передан токен SG-Node Agent")
        return value.split(None, 1)[1].strip()

    def render_node_detail_response(node_id: int, *, one_time_command: str = ""):
        node = get_node(node_id)
        jobs = list_jobs(node_id)
        node_clients = [
            item for item in get_awg_overview()["clients"]
            if (node.get("is_local") and not item.get("node_id"))
            or (not node.get("is_local") and int(item.get("node_id") or 0) == int(node_id))
        ]
        return render_template(
            "node_detail.html",
            node=node,
            jobs=jobs,
            refresh_pending=any(
                str(item.get("kind") or "") == "refresh"
                and str(item.get("state") or "") in {"queued", "claimed"}
                for item in jobs
            ),
            node_clients=node_clients,
            one_time_command=one_time_command,
            controller_url=current_public_url(),
        )

    @app.get("/bootstrap/sg-awg-node.tar.gz")
    def bootstrap_node_bundle():
        root = Path(__file__).resolve().parent.parent
        members = [
            "01-install-sg-awg-node.sh",
            "02-connect-sg-awg-node.sh",
            "deploy/install-node-runtime.sh",
            "deploy/install-node-agent.sh",
            "deploy/install-amneziawg.sh",
            "deploy/install-common.sh",
            "deploy/connect-node.sh",
            "node_agent/__init__.py",
            "node_agent/agent.py",
        ]
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w:gz") as archive:
            for relative in members:
                source = root / relative
                if not source.is_file():
                    abort(500, description=f"Bootstrap file missing: {relative}")
                archive.add(source, arcname=f"sg-awg-node/{relative}", recursive=False)
        response = Response(payload.getvalue(), mimetype="application/gzip")
        response.headers["Content-Disposition"] = 'attachment; filename="sg-awg-node.tar.gz"'
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/bootstrap/sg-awg-node-install.sh")
    def bootstrap_node_install_script():
        base = current_public_url().rstrip("/")
        bundle_url = f"{base}/bootstrap/sg-awg-node.tar.gz"
        script = "\n".join([
            "#!/usr/bin/env bash",
            "set -Eeuo pipefail",
            '[[ $EUID -eq 0 ]] || { echo "Запустите команду через sudo" >&2; exit 1; }',
            "export DEBIAN_FRONTEND=noninteractive",
            'if ! command -v curl >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq ca-certificates curl; fi',
            'tmp="$(mktemp -d /tmp/sg-awg-node.XXXXXX)"',
            "trap 'rm -rf \"$tmp\"' EXIT",
            f'curl -fsSL --connect-timeout 15 --max-time 180 {bundle_url!r} -o "$tmp/node.tar.gz"',
            'tar -xzf "$tmp/node.tar.gz" -C "$tmp"',
            'exec bash "$tmp/sg-awg-node/01-install-sg-awg-node.sh"',
            "",
        ])
        return Response(script, mimetype="text/x-shellscript; charset=utf-8", headers={"Cache-Control": "no-store"})

    @app.get("/bootstrap/sg-awg-node-connect.sh")
    def bootstrap_node_connect_script():
        path = Path(__file__).resolve().parent.parent / "deploy" / "connect-node.sh"
        if not path.is_file():
            abort(500, description="Connect script missing")
        return Response(path.read_text(encoding="utf-8"), mimetype="text/x-shellscript; charset=utf-8", headers={"Cache-Control": "no-store"})

    def render_nodes_response(*, one_time_command: str = "", one_time_node: dict[str, object] | None = None):
        panel = get_panel_settings()
        controller_url = current_public_url(panel)
        ensure_controller_identity(panel)
        cleanup_duplicate_pending_nodes()
        rows, hidden_duplicate_count = collapse_duplicate_nodes(list_nodes())
        # Cluster needs only the client registry. Avoid the broader server
        # overview here: it performs public-IP discovery and made this local
        # page depend on external network services.
        all_clients = [dict(row) for row in list_awg_clients()]
        for item in rows:
            item["client_count"] = sum(
                1 for client in all_clients
                if (not item.get("is_local") and int(client.get("node_id") or 0) == int(item["id"]))
                or (item.get("is_local") and not client.get("node_id"))
            )
        summary = {
            "total": len(rows),
            "nodes": max(0, len(rows) - 1),
            "online": sum(1 for item in rows if item.get("is_local") or item.get("online")),
            "offline": sum(1 for item in rows if not item.get("is_local") and item.get("effective_state") in {"offline", "error"}),
            "pending": sum(1 for item in rows if not item.get("is_local") and item.get("effective_state") == "pending"),
            "clients": sum(1 for client in all_clients if client.get("node_id") and str(client.get("deployment_state") or "active") == "active"),
        }
        return render_template(
            "nodes.html",
            nodes=rows,
            summary=summary,
            controller_url=controller_url,
            one_time_command=one_time_command,
            one_time_node=one_time_node,
            hidden_duplicate_count=hidden_duplicate_count,
        )

    @app.get("/cluster")
    @login_required
    def nodes_page():
        return render_nodes_response()

    @app.post("/cluster/nodes")
    @login_required
    def node_create():
        require_csrf()
        name = request.form.get("name", "")
        try:
            existing = find_remote_node_by_name(name)
            if existing is not None:
                if str(existing.get("effective_state") or "") == "online":
                    flash("SG-Node с таким именем уже подключена. Новая запись не создана.", "success")
                    return redirect(url_for("node_detail_page", node_id=int(existing["id"])))
                node, enrollment_token = renew_enrollment(int(existing["id"]))
                flash("SG-Node уже была добавлена. Создана новая команда подключения без дубликата.", "success")
            else:
                node, enrollment_token = create_node(
                    name=name,
                    public_host="",
                    public_port=585,
                )
                flash("SG-Node добавлена. Скопируйте команду ниже и выполните её на сервере.", "success")
            command = enrollment_command(
                controller_url=current_public_url(),
                slug=str(node["slug"]),
                token=enrollment_token,
            )
            return render_nodes_response(one_time_command=command, one_time_node=node)
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("nodes_page"))

    @app.get("/cluster/nodes/<int:node_id>")
    @login_required
    def node_detail_page(node_id: int):
        return render_node_detail_response(node_id)

    @app.get("/cluster/nodes/<int:node_id>/status.json")
    @login_required
    def node_status_json(node_id: int):
        try:
            node = get_node(node_id)
            return json_response({
                "ok": True,
                "id": int(node["id"]),
                "state": str(node.get("effective_state") or node.get("state") or "pending"),
                "online": bool(node.get("online")),
                "address": str(node.get("public_ipv4") or node.get("public_host") or ""),
                "last_seen_at": str(node.get("last_seen_at") or ""),
            })
        except (ValueError, PermissionError, AWGPanelError) as exc:
            return json_response({"ok": False, "message": str(exc)}, 404)

    @app.post("/cluster/nodes/<int:node_id>/renew")
    @login_required
    def node_renew(node_id: int):
        require_csrf()
        try:
            node, enrollment_token = renew_enrollment(node_id)
            command = enrollment_command(
                controller_url=current_public_url(),
                slug=str(node["slug"]),
                token=enrollment_token,
            )
            flash("Создана новая одноразовая команда подключения SG-Node.", "success")
            if request.form.get("return_to") == "cluster":
                return render_nodes_response(one_time_command=command, one_time_node=node)
            return render_node_detail_response(node_id, one_time_command=command)
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("node_detail_page", node_id=node_id))

    @app.post("/cluster/nodes/<int:node_id>/rename")
    @login_required
    def node_rename(node_id: int):
        require_csrf()
        try:
            updated = set_node_name(node_id, request.form.get("name", ""))
            flash(f"Имя SG-Node изменено: {updated['name']}", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("node_detail_page", node_id=node_id))

    @app.post("/cluster/nodes/<int:node_id>/country")
    @login_required
    def node_country_update(node_id: int):
        require_csrf()
        try:
            automatic = request.form.get("mode", request.form.get("country_mode", "")) == "auto"
            node = get_node(node_id)
            if automatic:
                public_ip = (
                    detect_public_ipv4(force=True) if node.get("is_local")
                    else str(node.get("public_ipv4") or "")
                )
                code = detect_country_code(public_ip, force=True) if public_ip else ""
                set_node_country(node_id, code, automatic=True)
                if code:
                    flash(f"Страна определена автоматически: {country_name(code)} ({code}).", "success")
                else:
                    flash("Страну определить не удалось. Показан нейтральный значок; можно указать код вручную.", "warning")
            else:
                updated = set_node_country(node_id, request.form.get("country_code", ""), automatic=False)
                flash(f"Страна сервера сохранена: {country_name(updated['country_code'])} ({updated['country_code']}).", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("node_detail_page", node_id=node_id))

    @app.post("/cluster/nodes/<int:node_id>/toggle")
    @login_required
    def node_toggle(node_id: int):
        require_csrf()
        try:
            node = get_node(node_id)
            enabled = str(node.get("effective_state")) == "disabled"
            set_node_enabled(node_id, enabled)
            flash("SG-Node включена." if enabled else "SG-Node отключена.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("node_detail_page", node_id=node_id))

    @app.post("/cluster/nodes/<int:node_id>/delete")
    @login_required
    def node_delete(node_id: int):
        require_csrf()
        try:
            delete_node(node_id)
            flash("SG-Node удалена из Cluster.", "success")
            return redirect(url_for("nodes_page"))
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("node_detail_page", node_id=node_id))

    @app.post("/cluster/nodes/<int:node_id>/jobs")
    @login_required
    def node_job_create(node_id: int):
        require_csrf()
        try:
            kind = request.form.get("kind", "refresh")
            job = queue_job(node_id, kind)
            if kind == "refresh":
                flash("Обновление подключения SG-Node запущено. Страница обновится после ответа Agent.", "success")
            else:
                flash(f"Задание #{job['id']} передано SG-Node.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("node_detail_page", node_id=node_id))

    @app.post("/api/cluster/v1/enroll")
    def node_agent_enroll():
        payload = request.get_json(silent=True) or {}
        try:
            node, agent_token = enroll_node(
                slug=str(payload.get("node") or ""),
                enrollment_token=str(payload.get("token") or ""),
                metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
            )
            return json_response({
                "ok": True,
                "node_id": int(node["id"]),
                "node": str(node["slug"]),
                "agent_token": agent_token,
                "heartbeat_seconds": 30,
            })
        except (ValueError, PermissionError, AWGPanelError) as exc:
            return json_response({"ok": False, "message": str(exc)}, 403)

    @app.post("/api/cluster/v1/nodes/<slug>/heartbeat")
    def node_agent_heartbeat(slug: str):
        payload = request.get_json(silent=True) or {}
        try:
            node = authenticate_agent(slug, agent_bearer_token())
            updated = heartbeat(int(node["id"]), payload)
            try:
                queue_initial_pool_sync(int(node["id"]))
            except (ValueError, AWGPanelError):
                pass
            return json_response({"ok": True, "state": updated["effective_state"]})
        except (ValueError, PermissionError, AWGPanelError) as exc:
            return json_response({"ok": False, "message": str(exc)}, 403)

    @app.get("/api/cluster/v1/nodes/<slug>/jobs/next")
    def node_agent_next_job(slug: str):
        try:
            node = authenticate_agent(slug, agent_bearer_token())
            job = claim_next_job(int(node["id"]))
            return json_response({"ok": True, "job": job})
        except (ValueError, PermissionError, AWGPanelError) as exc:
            return json_response({"ok": False, "message": str(exc)}, 403)

    @app.post("/api/cluster/v1/nodes/<slug>/jobs/<int:job_id>/result")
    def node_agent_finish_job(slug: str, job_id: int):
        payload = request.get_json(silent=True) or {}
        try:
            node = authenticate_agent(slug, agent_bearer_token())
            job = finish_job(
                int(node["id"]),
                job_id,
                ok=bool(payload.get("ok")),
                result=payload.get("result") if isinstance(payload.get("result"), dict) else {},
            )
            return json_response({"ok": True, "job": job})
        except (ValueError, PermissionError, AWGPanelError) as exc:
            return json_response({"ok": False, "message": str(exc)}, 403)

    def render_cascade_response(
        *, one_time_link: str = "", one_time_enrollment=None,
        one_time_config: str = "", one_time_client=None,
        cascade_mode: str | None = None,
    ):
        try:
            reconcile_all_cascades()
        except Exception:
            pass
        servers = cascade_servers()
        links = list_cascade_links(include_disabled=False)
        external = get_cascade_settings()
        exit_service = get_exit_service_client()
        if not one_time_link:
            active_enrollment = get_active_exit_enrollment()
            if active_enrollment:
                one_time_link = str(active_enrollment.get("link") or "")
                one_time_enrollment = active_enrollment
                one_time_client = active_enrollment.get("client")
        active_count = sum(1 for item in links if item.get("state") == "active")
        if external.get("enabled"):
            active_count += 1
        selected_mode = str(cascade_mode or request.args.get("mode") or "cluster").strip().lower()
        if selected_mode not in {"cluster", "external"}:
            selected_mode = "cluster"
        return render_template(
            "cascade.html",
            servers=servers,
            cascade_links=links,
            external_cascade=external,
            external_exit_service=exit_service,
            active_cascade_count=active_count,
            one_time_link=one_time_link,
            one_time_enrollment=one_time_enrollment,
            one_time_config=one_time_config,
            one_time_client=one_time_client,
            cascade_mode=selected_mode,
        )

    @app.get("/cascade")
    @login_required
    def cascade_page():
        return render_cascade_response()

    @app.post("/cascade/create")
    @login_required
    def cluster_cascade_create():
        require_csrf()
        try:
            entry_id = int(request.form.get("entry_node_id", "0"))
            exit_id = int(request.form.get("exit_node_id", "0"))
            entry_node = get_node(entry_id)
            if entry_node.get("is_local") and get_cascade_settings().get("enabled"):
                raise ValueError(
                    "На этом сервере уже включён Cascade с другим самостоятельным сервером. "
                    "Сначала верните прямой выход в интернет"
                )
            link = create_cluster_cascade_link(entry_node_id=entry_id, exit_node_id=exit_id)
            state = str(link.get("state") or "")
            if state == "active":
                flash("Серверный маршрут Cascade настроен. Переподключите клиент и выполните проверку подключения.", "success")
            else:
                flash("Настройка Cascade началась. SG-Node применяют служебное подключение автоматически.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page", mode="cluster"))

    @app.post("/cascade/<int:link_id>/disable")
    @login_required
    def cluster_cascade_disable(link_id: int):
        require_csrf()
        try:
            link = disable_cluster_cascade_link(link_id)
            if str(link.get("state")) == "disabled":
                flash("Прямой выход в интернет восстановлен.", "success")
            else:
                flash("Возврат к прямому выходу начат. SG-Node завершит его автоматически.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page", mode="cluster"))

    @app.post("/cascade/<int:link_id>/test")
    @login_required
    def cluster_cascade_test(link_id: int):
        require_csrf()
        try:
            link = test_cluster_cascade_link(link_id)
            if link.get("entry", {}).get("is_local"):
                flash(f"Серверный маршрут готов. Проверенный выходной IP: {link.get('last_exit_ip') or 'подтверждён через сервер выхода'}.", "success")
            else:
                flash("Проверка отправлена серверу подключения. Результат появится автоматически.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page", mode="cluster"))

    @app.post("/cascade/exit-client")
    @login_required
    def cascade_exit_client_create():
        require_csrf()
        try:
            enrollment = create_exit_enrollment(
                name=request.form.get("name", "sg-cascade-entry"),
                ttl_minutes=int(request.form.get("ttl_minutes", "30") or 30),
            )
            flash(
                "Одноразовая ссылка создана. Скопируйте её на сервер подключения в течение 30 минут.",
                "success",
            )
            return render_cascade_response(
                one_time_link=str(enrollment["link"]),
                one_time_enrollment=enrollment,
                one_time_client=enrollment.get("client"),
                cascade_mode="external",
            )
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page", mode="external", step="exit"))

    @app.post("/cascade/exit-client/remove")
    @login_required
    def cascade_exit_client_remove():
        require_csrf()
        try:
            removed = remove_exit_service_client()
            flash(
                "Роль Exit отключена: служебный клиент удалён." if removed else "Служебный клиент Exit уже отсутствует.",
                "success",
            )
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page", mode="external", step="exit"))

    @app.post("/cascade/configure")
    @login_required
    def cascade_configure():
        require_csrf()
        try:
            local_cluster_link = next(
                (item for item in list_cascade_links(include_disabled=False)
                 if item.get("entry", {}).get("is_local") and item.get("state") != "disabled"),
                None,
            )
            if local_cluster_link:
                raise ValueError(
                    "На этом сервере уже включён Cascade через Cluster. "
                    "Сначала верните прямой выход в интернет"
                )
            enrollment_link = request.form.get("enrollment_link", "").strip()
            if enrollment_link:
                result = configure_cascade_from_link(enrollment_link)
                enrollment = result.get("enrollment", {})
            else:
                result = configure_cascade(
                    config_text=request.form.get("config_text", ""),
                    exit_name=request.form.get("exit_name", "Exit SG-AWG"),
                    client_ids=[int(value) for value in request.form.getlist("client_id") if value.isdigit()],
                    apply_to_all=request.form.get("apply_to_all") == "1",
                )
                enrollment = {"exit_name": result.get("exit_name") or "сервер выхода"}
            check = test_cascade(probe_public_ip=not app.config.get("TESTING"))
            if check.get("ok"):
                flash(
                    f"Ссылка принята, серверный маршрут готов. Выход: {check.get('exit_ip') or enrollment.get('exit_name') or 'Outbound'}. "
                    "Выберите клиентов, откройте на клиенте любой сайт и нажмите «Проверить подключение клиента».",
                    "success",
                )
            else:
                flash(f"Ссылка принята, но серверный маршрут не готов: {check.get('message')}", "error")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page", mode="external", step="entry"))

    @app.post("/cascade/assign")
    @login_required
    def cascade_assign():
        require_csrf()
        try:
            assign_cascade_clients(
                [int(value) for value in request.form.getlist("client_id") if value.isdigit()]
            )
            flash("Выбранные клиенты сразу направлены через Cascade. Старые сетевые сессии сброшены автоматически.", "success")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page", mode="external", step="clients"))

    @app.post("/cascade/test")
    @login_required
    def cascade_test():
        require_csrf()
        try:
            result = test_cascade(probe_public_ip=not app.config.get("TESTING"))
            if result["ok"]:
                flash(
                    str(result["message"]),
                    "success" if result.get("ok") else "warning",
                )
            else:
                flash(str(result["message"]), "error")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page", mode="external", step="check", _anchor="client-check-result"))

    @app.post("/cascade/client-test")
    @login_required
    def cascade_client_test():
        require_csrf()
        try:
            result = test_cascade_client()
            flash(str(result["message"]), "success" if result.get("ok") else "warning")
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page", mode="external", step="client-check", _anchor="client-check-result"))

    @app.post("/cascade/disable")
    @login_required
    def cascade_disable():
        require_csrf()
        try:
            disable_cascade()
            flash(
                "Inbound очищен: клиенты возвращены на прямой выход, локальный служебный Outbound и policy routing удалены. "
                "Для полного сброса варианта 2 удалите служебный доступ на панели сервера выхода.",
                "success",
            )
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page", mode="external"))

    @app.post("/cascade/reset")
    @login_required
    def cascade_reset():
        require_csrf()
        try:
            previous = get_cascade_settings()
            exit_name = str(previous.get("exit_name") or "сервера выхода")
            disable_cascade()
            flash(
                f"Шаг 1 из 2 выполнен: Inbound очищен и клиенты снова используют Direct. "
                f"Теперь откройте Cascade на панели {exit_name} и удалите служебный доступ Outbound.",
                "success",
            )
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page", mode="external", reset="outbound"))

    @app.get("/cascade/json")
    @login_required
    def cascade_json_page():
        return Response(
            json.dumps(cascade_document(), ensure_ascii=False, indent=2) + "\n",
            content_type="application/json; charset=utf-8",
        )

    @app.get("/help")
    @login_required
    def help_page():
        return render_template("help.html")

    @app.get("/updates")
    @login_required
    def updates_page():
        return render_template(
            "updates.html",
            update_info=check_for_updates(force=False),
            update_status=get_update_status(),
        )

    @app.get("/maintenance")
    @login_required
    def maintenance_page():
        tab = request.args.get("tab", "backups").strip().lower()
        if tab == "updates":
            return updates_page()
        return backups_page()

    @app.post("/settings/update/check")
    @login_required
    def settings_update_check():
        require_csrf()
        info = check_for_updates(force=True)
        if info["error"]:
            flash(f"Не удалось проверить обновления: {info['error']}", "error")
        elif info["available"]:
            flash(f"Доступна версия {info['latest']}.", "success")
        else:
            flash("Установлена актуальная версия.", "success")
        return redirect(url_for("updates_page"))

    @app.post("/settings/update/start")
    @login_required
    def settings_update_start():
        require_csrf()
        version = request.form.get("version", "")
        try:
            result = start_panel_update(version)
            record_auth_event(
                "update_started", ip_address=client_ip(),
                user_agent=client_agent(), detail=result["version"],
            )
            old_token = str(session.get("session_token", ""))
            if old_token:
                revoke_web_session(hashlib.sha256(old_token.encode("utf-8")).hexdigest())
            session.clear()
            return render_template(
                "update_progress.html",
                version=result["version"],
                status_url="/sg-awg-update/status.json",
                log_url="/sg-awg-update/update.log",
                login_url=url_for("login", updated="1"),
            )
        except (ValueError, PermissionError, AWGPanelError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("updates_page"))

    @app.get("/health")
    def health():
        return Response("ok\n", mimetype="text/plain")

    return app


app = create_app()

@app.errorhandler(ValueError)
def handle_value_error(error):
    from flask import flash, redirect, url_for, request
    if "SG-Node" in str(error):
        flash(str(error), "error")
        return redirect(request.referrer or url_for('index'))
    raise error
