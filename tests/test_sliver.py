"""Unit tests for the standalone Sliver C2 wrapper.

All Sliver invocations are mocked; no real client or server is required.
"""

from __future__ import annotations

import pytest

from adversary_sim import sliver

# --- Sample outputs captured from the real sliver-client console ---

SESSIONS_OUTPUT = """
[*] Active sessions: 1

 ID         Name       Transport   Remote Address   Hostname   Username   Process (PID)        Operating System   Last Message   Health
========== ========== =========== ================ ========== ========== ==================== ================== ============== ========
 ab12cd34   CLIENT-1   mtls        10.0.0.15:52344  dc01       ADMIN      implant.exe (4120)  windows/amd64      3s ago         [ALIVE]
"""

BEACONS_OUTPUT = """
[*] Active beacons: 1

 ID         Name       Tasks   Transport   Remote Address   Hostname   Username   Process (PID)       Operating System   Last Check-in   Next Check-in
========== ========== ======= =========== ================ ========== ========== =================== ================== =============== ===============
 ef56gh78   BEACON-1   1/1     https       10.0.0.20:49812  web01      root       beacon (3312)       linux/amd64        1m12s ago       45s
"""

JOBS_OUTPUT = """
 ID   Name        Protocol   Port   Domains
==== =========== ========== ====== =========
 1    mtls        mtls       8888
 2    https       https      443    cdn.example.com
"""

CONNECTION_REFUSED = (
    "connection to server failed: rpc error: code = Unavailable desc = connection refused"
)


@pytest.fixture
def fake_client(monkeypatch):
    """Pretend sliver-client is installed on PATH."""
    monkeypatch.setattr(sliver, "_client_path", lambda: "/usr/local/bin/sliver-client")


@pytest.fixture
def stub_run(monkeypatch):
    """Return a helper that replaces the shell runner with a fixed output."""

    def _make(output):
        captured = {}

        def _fake(commands, timeout=sliver._LIST_TIMEOUT):
            captured["commands"] = list(commands)
            captured["timeout"] = timeout
            return output

        monkeypatch.setattr(sliver, "_run_sliver_commands", _fake)
        return captured

    return _make


# --- sliver_status ---


def test_status_reports_missing_client(monkeypatch):
    monkeypatch.setattr(sliver, "_client_path", lambda: None)
    out = sliver.sliver_status()
    assert "was not found on PATH" in out
    assert "ADVERSARYSIM_SLIVER_CLIENT" in out


def test_status_reports_reachable_server(fake_client, stub_run):
    stub_run("1.6.0")
    out = sliver.sliver_status()
    assert "sliver-client found" in out
    assert "1.6.0" in out
    assert "reachable" in out


def test_status_detects_daemon_down(fake_client, stub_run):
    stub_run(CONNECTION_REFUSED)
    out = sliver.sliver_status()
    assert "not reachable" in out
    assert "sliver-server" in out


def test_status_handles_runner_exception(fake_client, monkeypatch):
    def _boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(sliver, "_run_sliver_commands", _boom)
    out = sliver.sliver_status()
    assert "running it failed" in out


# --- sliver_list_sessions ---


def test_list_sessions_parses_rows(fake_client, stub_run):
    stub_run(SESSIONS_OUTPUT)
    out = sliver.sliver_list_sessions()
    assert "Active Sliver sessions (1)" in out
    assert "ID=ab12cd34" in out
    assert "Name=CLIENT-1" in out
    assert "Transport=mtls" in out
    assert "Hostname=dc01" in out
    assert "Operating System=windows/amd64" in out
    # Separator line must not be treated as a data row.
    assert "=====" not in out


def test_list_sessions_handles_none(fake_client, stub_run):
    stub_run("[*] Active sessions: 0\n")
    assert sliver.sliver_list_sessions() == "No active Sliver sessions."


def test_list_sessions_daemon_down(fake_client, stub_run):
    stub_run(CONNECTION_REFUSED)
    assert "not reachable" in sliver.sliver_list_sessions()


def test_list_sessions_missing_client(monkeypatch):
    monkeypatch.setattr(sliver, "_client_path", lambda: None)
    assert "was not found on PATH" in sliver.sliver_list_sessions()


def test_list_sessions_runner_exception(fake_client, monkeypatch):
    def _boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(sliver, "_run_sliver_commands", _boom)
    assert "Failed to list Sliver sessions" in sliver.sliver_list_sessions()


# --- sliver_list_beacons ---


def test_list_beacons_parses_rows(fake_client, stub_run):
    stub_run(BEACONS_OUTPUT)
    out = sliver.sliver_list_beacons()
    assert "Sliver beacons (1)" in out
    assert "ID=ef56gh78" in out
    assert "Tasks=1/1" in out
    assert "Next Check-in=45s" in out


def test_list_beacons_handles_none(fake_client, stub_run):
    stub_run("")
    assert sliver.sliver_list_beacons() == "No Sliver beacons registered."


def test_list_beacons_missing_client(monkeypatch):
    monkeypatch.setattr(sliver, "_client_path", lambda: None)
    assert "was not found on PATH" in sliver.sliver_list_beacons()


# --- sliver_list_jobs ---


def test_list_jobs_parses_rows(fake_client, stub_run):
    stub_run(JOBS_OUTPUT)
    out = sliver.sliver_list_jobs()
    assert "Active Sliver listeners (jobs) (2)" in out
    assert "ID=1" in out
    assert "Protocol=mtls" in out
    assert "Port=8888" in out
    assert "Domains=cdn.example.com" in out


def test_list_jobs_no_listeners(fake_client, stub_run):
    stub_run("[*] No active jobs\n")
    assert sliver.sliver_list_jobs() == "No active Sliver listeners."


def test_list_jobs_missing_client(monkeypatch):
    monkeypatch.setattr(sliver, "_client_path", lambda: None)
    assert "was not found on PATH" in sliver.sliver_list_jobs()


# --- sliver_generate_payload ---


def test_generate_payload_builds_expected_command(fake_client, stub_run, monkeypatch):
    captured = stub_run("[*] Implant saved")
    monkeypatch.setattr(sliver, "_workspace_dir", lambda: "/tmp/ws")

    out = sliver.sliver_generate_payload(os="windows", lhost="10.0.0.1", lport=8888)
    cmd = captured["commands"][0]
    assert cmd.startswith("generate ")
    assert "--os windows" in cmd
    assert "--mtls 10.0.0.1:8888" in cmd
    assert "--format exe" in cmd
    assert "--save /tmp/ws/sliver_implant_windows_8888.exe" in cmd
    assert captured["timeout"] == sliver._GENERATE_TIMEOUT
    assert "Implant saved" in out


def test_generate_beacon_uses_beacon_subcommand(fake_client, stub_run, monkeypatch):
    captured = stub_run("ok")
    monkeypatch.setattr(sliver, "_workspace_dir", lambda: "/tmp/ws")

    sliver.sliver_generate_payload(
        os="linux", lhost="10.0.0.1", lport=443, format="elf", beacon=True
    )
    assert captured["commands"][0].startswith("generate beacon ")


@pytest.mark.parametrize(
    ("os_name", "expected"),
    [
        ("freebsd", "Unsupported os"),
        ("WINDOWS", None),  # normalised, accepted
    ],
)
def test_generate_payload_validates_os(fake_client, stub_run, monkeypatch, os_name, expected):
    monkeypatch.setattr(sliver, "_workspace_dir", lambda: "/tmp/ws")
    if expected is None:
        stub_run("ok")
    out = sliver.sliver_generate_payload(os=os_name, lhost="10.0.0.1", lport=80)
    if expected:
        assert expected in out
    else:
        assert "Ran: generate " in out


def test_generate_payload_rejects_bad_format(fake_client):
    out = sliver.sliver_generate_payload(os="linux", lhost="10.0.0.1", lport=80, format="exe")
    assert "Unsupported format 'exe' for linux" in out


@pytest.mark.parametrize("bad_port", ["0", "70000", "notanumber"])
def test_generate_payload_rejects_bad_port(fake_client, bad_port):
    out = sliver.sliver_generate_payload(os="linux", lhost="10.0.0.1", lport=bad_port)
    assert "lport" in out


def test_generate_payload_rejects_bad_lhost(fake_client):
    out = sliver.sliver_generate_payload(os="linux", lhost="10.0.0.1; rm -rf /", lport=80)
    assert "Invalid lhost" in out


def test_generate_payload_missing_client(monkeypatch):
    monkeypatch.setattr(sliver, "_client_path", lambda: None)
    out = sliver.sliver_generate_payload(os="linux", lhost="1.1.1.1", lport=80)
    assert "was not found on PATH" in out


def test_generate_payload_daemon_down(fake_client, stub_run, monkeypatch):
    stub_run(CONNECTION_REFUSED)
    monkeypatch.setattr(sliver, "_workspace_dir", lambda: "/tmp/ws")
    out = sliver.sliver_generate_payload(os="linux", lhost="10.0.0.1", lport=80)
    assert "not reachable" in out


def test_generate_payload_runner_exception(fake_client, monkeypatch):
    def _boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(sliver, "_run_sliver_commands", _boom)
    monkeypatch.setattr(sliver, "_workspace_dir", lambda: "/tmp/ws")
    out = sliver.sliver_generate_payload(os="linux", lhost="10.0.0.1", lport=80)
    assert "Failed to generate Sliver implant" in out


# --- client configuration ---


def test_client_binary_default(monkeypatch):
    monkeypatch.delenv(sliver._CLIENT_ENV, raising=False)
    assert sliver._client_binary() == "sliver-client"


def test_client_binary_override(monkeypatch):
    monkeypatch.setenv(sliver._CLIENT_ENV, "/opt/sliver/sliver-client")
    assert sliver._client_binary() == "/opt/sliver/sliver-client"


def test_workspace_dir_override(monkeypatch):
    monkeypatch.setenv("ADVERSARYSIM_WORKSPACE", "/srv/implants")
    assert sliver._workspace_dir() == "/srv/implants"


# --- helper coverage ---


def test_strip_ansi_removes_colour_codes():
    assert sliver._strip_ansi("\x1b[32m[ALIVE]\x1b[0m") == "[ALIVE]"


def test_find_header_columns_missing_label_returns_none():
    assert sliver._find_header_columns("ID  Name", ["ID", "Transport"]) is None


def test_tokenize_row_splits_on_multiple_spaces():
    assert sliver._tokenize_row(" ab12cd34   CLIENT-1   mtls ") == ["ab12cd34", "CLIENT-1", "mtls"]


def test_map_row_folds_overflow_into_last_column():
    row = sliver._map_row(["1", "http", "a.com", "b.com"], ["ID", "Name", "Domains"])
    assert row == {"ID": "1", "Name": "http", "Domains": "a.com b.com"}


def test_map_row_pads_missing_columns_with_empty_strings():
    row = sliver._map_row(["1"], ["ID", "Name", "Domains"])
    assert row == {"ID": "1", "Name": "", "Domains": ""}


def test_is_separator_line():
    assert sliver._is_separator_line("==== ===========")
    assert not sliver._is_separator_line("ab12cd34   CLIENT-1")


SESSIONS_COMPACT_OUTPUT = """
 ID         Transport   Remote Address   Hostname   Username   Operating System   Health
========== =========== ================ ========== ========== ================== ========
 ab12cd34   mtls        10.0.0.15:52344  dc01       ADMIN      windows/amd64      [ALIVE]
"""


def test_parse_table_handles_compact_layout():
    rows = sliver._parse_table(
        SESSIONS_COMPACT_OUTPUT,
        (sliver._SESSION_HEADERS_FULL, sliver._SESSION_HEADERS_COMPACT),
    )
    assert len(rows) == 1
    assert rows[0]["ID"] == "ab12cd34"
    assert rows[0]["Operating System"] == "windows/amd64"
    # Compact layout has no Name column.
    assert "Name" not in rows[0]


def test_parse_table_empty_input():
    assert sliver._parse_table("", (sliver._JOB_HEADERS,)) == []
