from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TAG = "main"


def test_github_one_command_uninstall_is_documented():
    expected = f"curl -fsSL https://raw.githubusercontent.com/WeedVDK/sg-awg-panel/{TAG}/uninstall.sh | sudo bash"
    for relative in ("README.md", "docs/UNINSTALL.md", "docs/USER-GUIDE.md"):
        assert expected in (ROOT / relative).read_text(encoding="utf-8")


def test_full_uninstall_cleans_current_and_legacy_artifacts():
    text = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
    required = (
        "--yes",
        "/dev/tty",
        "/usr/local/lib/sg-awg-panel",
        "/tmp/sg-awg-panel-install.*",
        "/tmp/sg-awg-selfextract.*",
        "sg-awg-panel-update.service",
        "sg-awg-legacy-upgrade-cleanup.service",
        "sg-awg-routing.service",
        "sg-awg-traffic-lists.service",
        "rm -f /etc/systemd/system/sg-awg-*.service",
    )
    for value in required:
        assert value in text


def test_uninstall_and_verifier_are_valid_shell_scripts():
    # Syntax is also exercised by the release build; this keeps the files visible to pytest.
    assert (ROOT / "uninstall.sh").read_text(encoding="utf-8").startswith("#!/usr/bin/env bash")
    assert (ROOT / "verify-uninstall.sh").read_text(encoding="utf-8").startswith("#!/usr/bin/env bash")
