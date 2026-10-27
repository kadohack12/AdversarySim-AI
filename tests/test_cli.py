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
    for command in ("status", "sessions", "beacons", "jobs", "generate", "ask", "shell"):
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


def test_render_table_handles_empty_rows():
    # Should not raise.
    cli.render_table([], "Empty")


def test_print_banner_runs():
    # Should not raise.
    cli.print_banner()
