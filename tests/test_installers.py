from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_installer_does_not_source_password_env():
    text = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert '. "$ENV_FILE"' not in text
    assert "web.env is parsed as data and is never sourced as shell code" in text


def test_os_check_precedes_package_install():
    text = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert text.index('require_supported_ubuntu') < text.index('apt-get')


def test_first_install_validates_awg_before_web_panel():
    text = (ROOT / "deploy" / "first-install.sh").read_text(encoding="utf-8")
    assert text.index("install-amneziawg.sh") < text.index("install-or-upgrade.sh")


def test_installers_wait_only_for_real_locks():
    common = (ROOT / "deploy" / "install-common.sh").read_text(encoding="utf-8")
    assert "wait_for_apt" in common
    assert "fuser" in common
    assert "unattended-upgr" not in common
    for relative in ("install-or-upgrade.sh", "deploy/install-amneziawg.sh"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "wait_for_apt" in text


def test_updater_installs_only_missing_runtime_packages():
    text = (ROOT / "deploy" / "update-from-github.sh").read_text(encoding="utf-8")
    assert "missing_packages" in text
    assert "command -v nft" in text
    assert "command -v dnsmasq" in text
    assert "apt-get" in text
    assert "rsync" in text
    assert "init-db" in text


def test_update_and_uninstall_scripts_exist():
    assert (ROOT / "deploy" / "update-from-github.sh").exists()
    uninstall = (ROOT / "deploy" / "uninstall.sh").read_text(encoding="utf-8")
    assert "--purge-amneziawg" in uninstall


def test_automatic_backup_timer_is_installed():
    install = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    update = (ROOT / "deploy" / "update-from-github.sh").read_text(encoding="utf-8")
    timer = (ROOT / "deploy" / "install-backup-timer.sh").read_text(encoding="utf-8")
    assert "install-backup-timer.sh" in install
    assert "install-backup-timer.sh" in update
    assert "OnCalendar=$CALENDAR" in timer
    assert "backup_schedule" in timer
    assert "Persistent=true" in timer


def test_project_is_installed_into_virtualenv():
    for relative in ("install-or-upgrade.sh", "deploy/update-from-github.sh"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "--no-cache-dir -q -e ." in text
    assert (ROOT / "pyproject.toml").exists()


def test_panel_access_proxy_binds_backend_locally():
    text = (ROOT / "deploy" / "configure-panel-access.sh").read_text(encoding="utf-8")
    service = (ROOT / "deploy" / "install-service.sh").read_text(encoding="utf-8")
    assert "AWGPANEL_BIND_ADDRESS" in text
    assert "127.0.0.1" in text
    assert "certbot certonly" in text
    assert "Backend must bind only to loopback" in service


def test_update_has_automatic_rollback_and_recovery_service():
    update = (ROOT / "deploy" / "update-from-github.sh").read_text(encoding="utf-8")
    install = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert "rollback" in update
    assert "rolled_back" in update
    assert "install-recovery-service.sh" in update
    assert "install-recovery-service.sh" in install
    assert (ROOT / "deploy" / "recover-after-boot.sh").exists()


def test_quoted_python_heredocs_compile():
    """Catch malformed embedded Python before publishing shell installers."""
    import re

    for script in ROOT.rglob("*.sh"):
        text = script.read_text(encoding="utf-8")
        lines = text.splitlines()
        index = 0
        while index < len(lines):
            match = re.search(r"<<'([A-Za-z_][A-Za-z0-9_]*)'", lines[index])
            if not match:
                index += 1
                continue
            marker = match.group(1)
            body: list[str] = []
            index += 1
            while index < len(lines) and lines[index] != marker:
                body.append(lines[index])
                index += 1
            assert index < len(lines), f"Unterminated heredoc {marker} in {script}"
            if marker.startswith("PY"):
                compile("\n".join(body) + "\n", f"{script}:{marker}", "exec")
            index += 1


def test_https_uses_placeholder_on_443_and_separate_panel_port():
    text = (ROOT / "deploy" / "configure-panel-access.sh").read_text(encoding="utf-8")
    assert "listen 443 ssl" in text
    assert "listen ${PUBLIC_PORT} ssl" in text
    assert "register-unsafely-without-email" in text
    assert "--email" not in text
    assert "rm -f /etc/nginx/sites-enabled/default" not in text
    assert "sg-awg-placeholder.conf" in text
    assert "sg-awg-panel.conf" in text


def test_panel_port_validation_uses_dynamic_range():
    text = (ROOT / "deploy" / "configure-panel-access.sh").read_text(encoding="utf-8")
    assert "PUBLIC_PORT >= 49152" in text
    assert "PUBLIC_PORT <= 65535" in text
    assert "dynamic range 49152-65535" in text
    assert 'PUBLIC_PORT="62443"' in text


def test_clean_installer_is_fixed_to_beta3_and_reads_tty():
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert 'RELEASE_VERSION="v0.7.0-RC6"' in text
    assert "</dev/tty" in text
    assert "AWGPANEL_ADMIN_PASSWORD" in text
    assert "v0.1.0-alpha8" not in text
    assert "v0.1.0-alpha9" not in text


def test_clean_installer_rejects_pending_reboot_but_supports_safe_reinstall():
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "/var/run/reboot-required" in text
    assert "panel_installation_is_active" in text
    assert "cleanup_stale_panel_residue" in text
    assert "действующая установка SG-AWG-Panel" in text
    assert "повторная установка после полного удаления" in text
    assert "Остатки прежней установки удалены" in text
    assert "backend TCP 18080 занят" in text


def test_install_output_is_logged_with_live_progress():
    common = (ROOT / "deploy" / "install-common.sh").read_text(encoding="utf-8")
    first = (ROOT / "deploy" / "first-install.sh").read_text(encoding="utf-8")
    awg = (ROOT / "deploy" / "install-amneziawg.sh").read_text(encoding="utf-8")
    panel = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert "/var/log/sg-awg-panel-install.log" in common
    assert '>>"$INSTALL_LOG" 2>&1' in common
    assert "frame_index" in common
    assert "сек" in common
    assert "[OK]" in common
    assert 'install-amneziawg.sh" >>"$INSTALL_LOG"' not in first
    assert 'install-or-upgrade.sh" >>"$INSTALL_LOG"' not in first
    assert 'run_logged "Установка AmneziaWG' in awg
    assert 'run_logged "Установка Python, Nginx' in panel


def test_first_install_verifies_backend_and_nginx():
    text = (ROOT / "deploy" / "first-install.sh").read_text(encoding="utf-8")
    assert "127.0.0.1:18080/health" in text
    assert "AWGPANEL_PUBLIC_PORT" in text
    assert "127.0.0.1:${PUBLIC_PORT}/health" in text
    assert "systemctl is-active --quiet nginx.service" in text


def test_amneziawg_installer_enables_ubuntu_source_repositories():
    text = (ROOT / "deploy" / "install-amneziawg.sh").read_text(encoding="utf-8")
    assert "enable_ubuntu_source_repositories" in text
    assert "deb-src" in text
    assert "ubuntu.sources" not in text or ".sources" in text
    assert "apt-cache showsrc linux-base" in text


def test_only_install_sh_is_public_clean_installer():
    assert (ROOT / "install.sh").exists()
    assert not (ROOT / "install-from-github.sh").exists()
    installation = (ROOT / "docs" / "INSTALLATION.md").read_text(encoding="utf-8")
    assert "raw.githubusercontent.com/WeedVDK/sg-awg-panel/main/install.sh" in installation
    assert "-o /tmp/install-sg-awg-panel.sh" in installation
    assert "sudo bash /tmp/install-sg-awg-panel.sh" in installation
    assert "/install.sh | sudo bash" not in installation
    assert "install-from-github.sh" not in installation


def test_clean_installer_rejects_non_amd64_before_install():
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "dpkg --print-architecture" in text
    assert "amd64" in text
    assert text.index("dpkg --print-architecture") < text.index("apt-get")



def test_password_minimum_is_eight_everywhere():
    clean = (ROOT / "install.sh").read_text(encoding="utf-8")
    full = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    web = (ROOT / "awgpanel" / "web.py").read_text(encoding="utf-8")
    template = (ROOT / "awgpanel" / "templates" / "security.html").read_text(encoding="utf-8")
    assert "PASSWORD_MIN_LENGTH=8" in clean
    assert "PASSWORD_MIN_LENGTH=8" in full
    assert "MIN_PASSWORD_LENGTH = 8" in web
    assert 'minlength="8"' in template
    assert "минимум 10" not in clean
    assert "минимум 10" not in full
    assert 'minlength="10"' not in template


def test_recovery_is_archive_extraction_safe_and_started_last():
    unit = (ROOT / "deploy" / "install-recovery-service.sh").read_text(encoding="utf-8")
    install = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    update = (ROOT / "deploy" / "update-from-github.sh").read_text(encoding="utf-8")
    assert "ExecStart=/usr/bin/bash /opt/sg-awg-panel/deploy/recover-after-boot.sh" in unit
    assert "chmod 0755" in unit
    assert "enable --now sg-awg-recovery" not in unit
    assert "find \"$PROJECT_DIR\" -type f -name '*.sh' -exec chmod 0755 {} +" in install
    assert "find \"$PROJECT_DIR\" -type f -name '*.sh' -exec chmod 0755 {} +" in update
    assert install.index("Nginx не передаёт запросы панели") < install.index("systemctl restart sg-awg-recovery.service")


def test_apt_and_dpkg_do_not_stream_through_a_pty():
    common = (ROOT / "deploy" / "install-common.sh").read_text(encoding="utf-8")
    awg = (ROOT / "deploy" / "install-amneziawg.sh").read_text(encoding="utf-8")
    panel = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    clean = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert '>>"$INSTALL_LOG" 2>&1' in common
    for text in (awg, panel, clean):
        assert "Dpkg::Use-Pty=0" in text
    assert "NEEDRESTART_MODE=a" in awg
    assert "NEEDRESTART_MODE=a" in panel
    assert "NEEDRESTART_MODE=a" in clean


def test_password_is_requested_before_long_installation():
    first = (ROOT / "deploy" / "first-install.sh").read_text(encoding="utf-8")
    panel = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert first.index("prompt_admin_password 8") < first.index("install-amneziawg.sh")
    assert panel.index('prompt_admin_password "$PASSWORD_MIN_LENGTH"') < panel.index("apt-get")


def test_installers_do_not_print_fake_public_ip_placeholders():
    for relative in (
        "install.sh",
        "install-or-upgrade.sh",
        "deploy/configure-panel-access.sh",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "http://PUBLIC_IP:8080" not in text
        assert "SERVER_IP}:${PUBLIC_PORT}" not in text
    common = (ROOT / "deploy" / "install-common.sh").read_text(encoding="utf-8")
    assert "detect_public_ipv4" in common
    assert "169.254.169.254" in common


def test_beta9_server_status_is_simple_and_hides_internal_network_checks():
    template = (ROOT / "awgpanel" / "templates" / "server.html").read_text(encoding="utf-8")
    css = (ROOT / "awgpanel" / "static" / "app.css").read_text(encoding="utf-8")
    assert "beta9-diagnostics-hero" in template
    assert "AWG Server работает" in template
    assert "Forwarding" not in template
    assert "NAT:" not in template
    assert "Расширенные параметры" in template
    assert ".server-basic-grid" in css
    assert "@media(max-width:760px)" in css


def test_clean_installer_release_version_is_not_clobbered_by_os_release():
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert 'RELEASE_VERSION="v0.7.0-RC6"' in text
    assert '. /etc/os-release' in text
    assert 'ARCHIVE_URL="https://github.com/${REPOSITORY}/archive/refs/heads/main.tar.gz"' in text
    assert 'Загрузка ${RELEASE_VERSION} из GitHub main' in text
    assert '"$SOURCE_VERSION" == "$RELEASE_VERSION"' in text
    assert 'не совпадает с ${RELEASE_VERSION}' in text
    assert 'INSTALLED_VERSION="$(/opt/sg-awg-panel/.venv/bin/python' in text
    assert 'после установки обнаружена версия' in text
    assert not any(line.startswith('VERSION=') for line in text.splitlines())


def test_alpha16_preserves_policy_traffic_install_and_recovery():
    awg = (ROOT / "deploy" / "install-amneziawg.sh").read_text(encoding="utf-8")
    install = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    recovery = (ROOT / "deploy" / "recover-after-boot.sh").read_text(encoding="utf-8")
    traffic_unit = (ROOT / "deploy" / "install-traffic-service.sh").read_text(encoding="utf-8")
    assert "nftables" in awg
    assert "src_valid_mark=1" in awg
    assert "install-traffic-service.sh" in install
    assert "sg-awg-traffic.service" in recovery
    assert "apply-traffic" in traffic_unit
    assert "clear-traffic" in traffic_unit


def test_alpha16_uninstall_removes_policy_traffic():
    full = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
    project = (ROOT / "deploy" / "uninstall.sh").read_text(encoding="utf-8")
    for text in (full, project):
        assert "sg-awg-traffic.service" in text
        assert "sg_awg_traffic" in text
        assert "sgo${id}" in text


def test_alpha16_first_install_checks_traffic_service_and_explicit_paths():
    first = (ROOT / "deploy" / "first-install.sh").read_text(encoding="utf-8")
    install = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert "systemctl is-active --quiet sg-awg-traffic.service" in first
    assert "Traffic Rules пока не применены" not in first
    assert 'run_logged "Проверка Traffic Rules..."' in first
    assert "systemctl is-active --quiet sg-awg-traffic.service" in install
    assert "AWGPANEL_OUTBOUND_CONFIG_DIR=/etc/amnezia/amneziawg/outbounds" in install
    assert "AWGPANEL_TRAFFIC_STATE_DIR=/var/lib/sg-awg-panel/traffic-rules" in install
    assert "AWGPANEL_TRAFFIC_LOCK=/run/lock/sg-awg-panel-traffic.lock" in install


def test_alpha16_uninstall_removes_traffic_lock():
    full = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
    project = (ROOT / "deploy" / "uninstall.sh").read_text(encoding="utf-8")
    assert "/run/lock/sg-awg-panel-traffic.lock" in full
    assert "/run/lock/sg-awg-panel-traffic.lock" in project


def test_alpha16_requests_dynamic_panel_port_before_installation():
    clean = (ROOT / "install.sh").read_text(encoding="utf-8")
    first = (ROOT / "deploy" / "first-install.sh").read_text(encoding="utf-8")
    common = (ROOT / "deploy" / "install-common.sh").read_text(encoding="utf-8")
    panel = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert 'PUBLIC_PORT_DEFAULT=62443' in clean
    assert "Публичный TCP-порт панели" in clean
    assert "49152" in clean and "65535" in clean
    assert clean.index("Публичный TCP-порт панели") < clean.index("Загрузка ${RELEASE_VERSION}")
    assert "prompt_public_port 62443" in first
    assert "validate_public_port" in common
    assert "public_port_is_free" in common
    assert "AWGPANEL_PUBLIC_PORT=${AWGPANEL_PUBLIC_PORT:-62443}" in panel


def test_rc3_config_is_inside_awg_server_and_empty_settings_page_is_removed():
    base = (ROOT / "awgpanel" / "templates" / "base.html").read_text(encoding="utf-8")
    security = (ROOT / "awgpanel" / "templates" / "security.html").read_text(encoding="utf-8")
    config = (ROOT / "awgpanel" / "templates" / "config.html").read_text(encoding="utf-8")
    assert "<b>Config</b>" not in base
    assert "Сервер и конфигурация" in base
    assert "Разделы AWG Server" in config
    assert "<span>Настройки</span>" not in base
    assert not (ROOT / "awgpanel" / "templates" / "settings.html").exists()
    assert "Full JSON" in config
    assert "System Files" in config
    assert "Редактировать JSON" in config
    assert "Только чтение, копирование и скачивание" in config
    assert 'data-json-hub-tab="full"' in config
    assert 'data-json-hub-tab="generated"' in config
    assert "Section JSON" not in config
    assert "Активные конфигурации" in config
    assert "AWG Server" in config and "generated.items()" in config and "generated_config_download" in config
    assert 'name="public_port"' in security
    assert 'min="49152"' in security
    assert "security_json_page" in security


def test_beta8_installs_only_traffic_schedule_timer():
    maintenance = (ROOT / "deploy/install-traffic-maintenance.sh").read_text(encoding="utf-8")
    assert "sg-awg-traffic-schedule.timer" in maintenance
    assert "OnUnitActiveSec=60s" in maintenance
    assert "OnUnitActiveSec=6h" not in maintenance

def test_beta8_uninstall_removes_traffic_units():
    text = (ROOT / "deploy/uninstall.sh").read_text(encoding="utf-8")
    assert "sg-awg-traffic.service" in text
    assert "sg-awg-traffic-schedule.timer" in text

def test_alpha17_web_service_can_manage_dnsmasq_dropin():
    text = (ROOT / "deploy" / "install-service.sh").read_text(encoding="utf-8")
    assert "install -d -m 0755 /etc/dnsmasq.d" in text
    read_write_line = next(
        line for line in text.splitlines() if line.startswith("ReadWritePaths=")
    )
    assert "/etc/dnsmasq.d" in read_write_line


def test_beta8_updater_has_no_protection_list_refresh():
    text = (ROOT / "deploy/update-from-github.sh").read_text(encoding="utf-8")
    assert "Refreshing built-in protection lists" not in text
    assert "sg-awg-traffic.service" in text

def test_beta8_installer_has_no_protection_lists():
    text = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert "Первичное обновление защитных списков" not in text
    assert "traffic-lists.timer" not in text

def test_beta8_removes_overview_and_gateway_rule_ui():
    base = (ROOT / "awgpanel/templates/base.html").read_text(encoding="utf-8")
    traffic = (ROOT / "awgpanel/templates/traffic_rules.html").read_text(encoding="utf-8")
    assert "Overview" not in base
    assert "AWG-Gateway" not in traffic
    assert "Traffic Rules" in traffic


def test_beta3_install_and_update_auto_configure_fresh_awg_server():
    install = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    update = (ROOT / "deploy" / "update-from-github.sh").read_text(encoding="utf-8")
    cli = (ROOT / "awgpanel" / "cli.py").read_text(encoding="utf-8")
    assert "python -m awgpanel ensure-server" in install
    assert "python -m awgpanel ensure-server" in update
    assert 'sub.add_parser("ensure-server")' in cli


def test_beta3_traffic_rules_page_is_compact_and_has_one_add_button():
    text = (ROOT / "awgpanel/templates/traffic_rules.html").read_text(encoding="utf-8")
    assert "traffic-meaning-grid" not in text
    assert "traffic-status-line" not in text
    assert text.count("Добавить правило") == 1
    assert "Добавить первое правило" not in text
    assert "текущий AWG Server" in text


def test_beta3_server_hides_network_details_by_default():
    text = (ROOT / "awgpanel/templates/server.html").read_text(encoding="utf-8")
    assert "Расширенные параметры" in text
    assert '<details class="details-box server-advanced-details">' in text
    assert "Внутренняя сеть клиентов" in text
    assert "Обычно менять не требуется" in text


def test_beta3_updater_rolls_back_fresh_awg_auto_configuration():
    text = (ROOT / "deploy/update-from-github.sh").read_text(encoding="utf-8")
    assert "AWG_CONFIG_PATH=/etc/amnezia/amneziawg/awg0.conf" in text
    assert 'backup_path "$AWG_CONFIG_PATH"' in text
    assert 'restore_path "$AWG_CONFIG_PATH"' in text
    assert "AWG_WAS_ACTIVE" in text
    assert "sg-awg-server.service" in text


def test_beta9_traffic_failure_cancels_install_and_recovery_restores_it():
    install = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    recovery = (ROOT / "deploy/recover-after-boot.sh").read_text(encoding="utf-8")
    assert 'install_fail "служба Traffic Rules не запустилась"' in install
    assert "sg-awg-traffic.service" in recovery

def test_beta4_nginx_serves_resilient_restart_page_and_uninstall_removes_it():
    access = (ROOT / "deploy" / "configure-panel-access.sh").read_text(encoding="utf-8")
    full_uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
    project_uninstall = (ROOT / "deploy" / "uninstall.sh").read_text(encoding="utf-8")
    assert 'UPDATE_ROOT="/var/www/sg-awg-update"' in access
    assert "error_page 502 503 504 = /sg-awg-update/offline.html" in access
    assert "location ^~ /sg-awg-update/" in access
    assert "Проверить сейчас" in access
    assert "Проверяем запуск backend" in access
    assert "Открыть страницу входа" in access
    assert "d.targetUrl" in access
    assert "/var/www/sg-awg-update" in full_uninstall
    assert "/var/www/sg-awg-update" in project_uninstall


def test_https_background_job_streams_unbuffered_certbot_output():
    runner = (ROOT / "deploy" / "run-panel-access-job.sh").read_text(encoding="utf-8")
    assert "PYTHONUNBUFFERED=1" in runner
    assert "stdbuf -oL -eL" in runner
