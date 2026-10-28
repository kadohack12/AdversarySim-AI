"""Tests for the rich CLI layer.

The Sliver backend and the LLM are mocked; the tests assert that the
human-in-the-loop gate is always consulted before an action runs.
"""

from __future__ import annotations

from typer.testing import CliRunner

from adversary_sim import cli, sliver

runner = CliRunner()


def test_help_lists_commands():
    result = runner.invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    for command in (
        "status",
        "sessions",
        "beacons",
        "jobs",
        "discover",
        "generate",
        "ask",
        "shell",
    ):
        assert command in result.stdout


def test_version_command():
    result = runner.invoke(cli.app, ["version"])
    assert result.exit_code == 0
    assert "AdversarySim-AI" in result.stdout


def test_parse_json_rows_returns_none_for_plain_text():
    assert cli._parse_json_rows("No active Sliver sessions.") is None


def test_parse_json_rows_parses_list_of_dicts():
    rows = cli._parse_json_rows('[{"ID": "1", "Name": "mtls"}]')
    assert rows == [{"ID": "1", "Name": "mtls"}]


def test_run_action_skips_operation_when_refused(monkeypatch):
    monkeypatch.setenv("ADVERSARYSIM_DRY_RUN", "true")
    called = []

    def _operation():
        called.append(True)
        return "ran"

    result = cli.run_action("Generate implant", _operation)
    assert called == []
    assert result.startswith("Cancelled:")


def test_run_action_executes_when_approved(monkeypatch):
    monkeypatch.setenv("ADVERSARYSIM_ASSUME_YES", "1")
    result = cli.run_action("List sessions", lambda: "ok")
    assert result == "ok"


def test_status_command_calls_sliver(monkeypatch):
    monkeypatch.setenv("ADVERSARYSIM_ASSUME_YES", "1")
    monkeypatch.setattr(sliver, "sliver_status", lambda: "client ok")
    result = runner.invoke(cli.app, ["status"])
    assert result.exit_code == 0
    assert "client ok" in result.stdout


def test_sessions_command_uses_gate(monkeypatch):
    monkeypatch.setenv("ADVERSARYSIM_DRY_RUN", "true")
    called = []

    def _sessions():
        called.append(True)
        return "should not run"

    monkeypatch.setattr(sliver, "sliver_list_sessions", _sessions)
    result = runner.invoke(cli.app, ["sessions"])
    assert result.exit_code == 0
    assert called == []
    assert "Cancelled" in result.stdout


def test_generate_command_rejects_suspicious_lhost(monkeypatch):
    monkeypatch.setenv("ADVERSARYSIM_ASSUME_YES", "1")
    result = runner.invoke(
        cli.app, ["generate", "--os", "linux", "--lhost", "10.0.0.1; rm -rf /", "--lport", "80"]
    )
    assert result.exit_code == 2
    assert "Refused" in result.stdout


def test_generate_command_runs_when_approved(monkeypatch):
    monkeypatch.setenv("ADVERSARYSIM_ASSUME_YES", "1")
    captured = {}

    def _generate(**kwargs):
        captured.update(kwargs)
        return "generated"

    monkeypatch.setattr(sliver, "sliver_generate_payload", _generate)
    result = runner.invoke(
        cli.app, ["generate", "--os", "windows", "--lhost", "10.0.0.1", "--lport", "8888"]
    )
    assert result.exit_code == 0
    assert captured == {
        "os": "windows",
        "lhost": "10.0.0.1",
        "lport": 8888,
        "format": "",
        "beacon": False,
    }
    assert "generated" in result.stdout


def test_discover_command_runs_when_approved(monkeypatch):
    monkeypatch.setenv("ADVERSARYSIM_ASSUME_YES", "1")
    captured = {}

    def _discovery(session_id, command):
        captured["session_id"] = session_id
        captured["command"] = command
        return "Ran on session ab12cd34: whoami\n\nTarget output:\nroot"

    monkeypatch.setattr(sliver, "sliver_run_discovery", _discovery)
    result = runner.invoke(cli.app, ["discover", "ab12cd34", "whoami"])
    assert result.exit_code == 0
    assert captured == {"session_id": "ab12cd34", "command": "whoami"}
    assert "root" in result.stdout


def test_discover_command_uses_safety_gate(monkeypatch):
    monkeypatch.setenv("ADVERSARYSIM_DRY_RUN", "true")
    called = []
    monkeypatch.setattr(sliver, "sliver_run_discovery", lambda *a, **k: called.append(a) or "x")
    result = runner.invoke(cli.app, ["discover", "s1", "whoami"])
    assert result.exit_code == 0
    assert called == []  # dry-run refuses, so nothing ran
    assert "would" in result.stdout.lower()


def test_render_table_handles_empty_rows():
    # Should not raise.
    cli.render_table([], "Empty")


def test_print_banner_runs():
    # Should not raise.
    cli.print_banner()


def test_brand_identity_is_kadohack12():
    assert cli.BRAND == "kadohack12"
    assert "kadohack12" in cli.CREDIT
    # The banner, credit and safety-gate marker are wired into the dark theme.
    assert cli.DARK_THEME is not None
    result = runner.invoke(cli.app, ["version"])
    assert "kadohack12" in result.stdout


def test_dark_theme_defines_expected_styles():
    for token in ("brand", "accent", "muted", "ok", "warn", "danger"):
        assert token in cli.DARK_THEME.styles


def test_risk_styles_cover_all_levels():
    from adversary_sim.safety import RiskLevel

    for level in RiskLevel:
        assert level in cli.RISK_STYLE


# --- MITRE ATT&CK emulation ------------------------------------------------


def test_mitre_list_shows_catalogue():
    result = runner.invoke(cli.app, ["mitre", "list"])
    assert result.exit_code == 0
    for tid in ("T1082", "T1083", "T1057", "T1016"):
        assert tid in result.stdout
    assert "state-changing" in result.stdout


def test_mitre_run_rejects_unknown_technique():
    result = runner.invoke(cli.app, ["mitre", "run", "T9999"])
    assert result.exit_code == 2
    assert "Unknown technique" in result.stdout


def test_detect_mitre_request_matches_known_technique():
    tech = cli._detect_mitre_request("Lance le test MITRE T1082")
    assert tech is not None and tech.id == "T1082"


def test_detect_mitre_request_ignores_plain_chat():
    assert cli._detect_mitre_request("Bonjour, comment vas-tu ?") is None
    # An id without the word "mitre" must not trigger the flow.
    assert cli._detect_mitre_request("liste T1082 s'il te plaît") is None


def test_detect_mitre_request_ignores_unknown_id():
    assert cli._detect_mitre_request("MITRE T9999") is None


def test_render_techniques_table_runs():
    # Should not raise.
    cli.render_techniques_table()


def test_mitre_run_auto_selects_target_and_writes_report(monkeypatch, tmp_path):
    monkeypatch.setenv("ADVERSARYSIM_ASSUME_YES", "1")
    monkeypatch.delenv("ADVERSARYSIM_DRY_RUN", raising=False)
    monkeypatch.setenv("ADVERSARYSIM_REPORTS_DIR", str(tmp_path))

    captured = {}

    def _discovery(session_id, command):
        captured["session_id"] = session_id
        captured["command"] = command
        return "Ran on session ab12cd34: uname -a\n\nTarget output:\nLinux target 6.1"

    monkeypatch.setattr(sliver, "sliver_run_discovery", _discovery)
    # Auto-resolve the active target without a real Sliver server.
    monkeypatch.setattr(sliver, "sliver_resolve_target", lambda: "ab12cd34")
    monkeypatch.setattr(sliver, "is_target_id", lambda candidate: candidate == "ab12cd34")

    result = runner.invoke(cli.app, ["mitre", "run", "T1082", "--no-report"])
    assert result.exit_code == 0
    assert captured == {"session_id": "ab12cd34", "command": "uname"}
    assert "Purple Team" in result.stdout
    reports_written = list(tmp_path.glob("T1082_*.md"))
    assert len(reports_written) == 1
    assert "System Information Discovery" in reports_written[0].read_text(encoding="utf-8")


def test_mitre_run_reports_no_target(monkeypatch, tmp_path):
    monkeypatch.setenv("ADVERSARYSIM_REPORTS_DIR", str(tmp_path))
    monkeypatch.setattr(
        sliver, "sliver_resolve_target", lambda: "No active Sliver beacon or session"
    )
    monkeypatch.setattr(sliver, "is_target_id", lambda candidate: False)

    result = runner.invoke(cli.app, ["mitre", "run", "T1082"])
    assert result.exit_code == 0
    assert "No target" in result.stdout
    assert list(tmp_path.glob("*.md")) == []


def test_mitre_run_uses_safety_gate(monkeypatch, tmp_path):
    monkeypatch.setenv("ADVERSARYSIM_DRY_RUN", "true")
    monkeypatch.setenv("ADVERSARYSIM_REPORTS_DIR", str(tmp_path))
    called = []
    monkeypatch.setattr(sliver, "sliver_run_discovery", lambda *a, **k: called.append(a) or "x")
    monkeypatch.setattr(sliver, "sliver_resolve_target", lambda: "ab12cd34")
    monkeypatch.setattr(sliver, "is_target_id", lambda candidate: candidate == "ab12cd34")

    result = runner.invoke(cli.app, ["mitre", "run", "T1082", "--no-report"])
    assert result.exit_code == 0
    assert called == []  # dry-run refuses, nothing ran, no report written
    assert list(tmp_path.glob("*.md")) == []
