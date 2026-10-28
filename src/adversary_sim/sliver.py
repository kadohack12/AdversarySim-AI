"""Standalone Sliver C2 (Bishop Fox) client wrapper.

This module drives the ``sliver-client`` command-line interface in
non-interactive mode. It has **no dependency on any other project** beyond the
Python standard library, so it can be reused or vendored on its own.

Design notes
------------
* The client is invoked by piping the requested console commands into
  ``sliver-client console`` through stdin. Sliver reads stdin as a command
  script when stdin is not a TTY, which is exactly the case here.
* Every public function degrades gracefully: if ``sliver-client`` is missing or
  the server is unreachable, a clear, actionable message is returned instead of
  raising.
* Table parsing tokenises rows on runs of two or more spaces (go-pretty pads
  every column with at least two) and maps the tokens onto the known header
  labels, which is robust against the variable column widths Sliver produces.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from collections.abc import Iterable

__all__ = [
    "sliver_status",
    "sliver_list_sessions",
    "sliver_list_beacons",
    "sliver_list_jobs",
    "sliver_generate_payload",
    "sliver_run_discovery",
    "sliver_resolve_target",
    "is_target_id",
    "DISCOVERY_COMMANDS",
]

# Path/name of the sliver client binary. Overridable for custom installs.
_CLIENT_ENV = "ADVERSARYSIM_SLIVER_CLIENT"
_DEFAULT_CLIENT = "sliver-client"

# Timeouts (seconds) for the different classes of operation.
_LIST_TIMEOUT = 30
_GENERATE_TIMEOUT = 300

# ANSI escape sequences emitted by Sliver's coloured output.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Substrings that indicate the client could not reach the server/daemon.
_CONNECTION_ERROR_MARKERS = (
    "connection to server failed",
    "connection refused",
    "no config files found",
    "multiple configs found",
    "context deadline exceeded",
    "transport: error while dialing",
    "unavailable",
    "dial tcp",
)

# Header label sets used to locate table columns. Ordered as Sliver prints them.
_SESSION_HEADERS_FULL = (
    "ID",
    "Name",
    "Transport",
    "Remote Address",
    "Hostname",
    "Username",
    "Process (PID)",
    "Operating System",
    "Last Message",
    "Health",
)
_SESSION_HEADERS_COMPACT = (
    "ID",
    "Transport",
    "Remote Address",
    "Hostname",
    "Username",
    "Operating System",
    "Health",
)
_BEACON_HEADERS_FULL = (
    "ID",
    "Name",
    "Tasks",
    "Transport",
    "Remote Address",
    "Hostname",
    "Username",
    "Process (PID)",
    "Operating System",
    "Last Check-in",
    "Next Check-in",
)
_BEACON_HEADERS_COMPACT = (
    "ID",
    "Name",
    "Transport",
    "Hostname",
    "Username",
    "Operating System",
    "Last Check-in",
    "Next Check-in",
)
_JOB_HEADERS = ("ID", "Name", "Protocol", "Port", "Domains")

# Order in which :func:`sliver_resolve_target` looks for a target: beacons
# (asynchronous implants) first, then interactive sessions.
_TARGET_LISTERS: tuple[tuple[str, tuple[tuple[str, ...], ...]], ...] = (
    ("beacons", (_BEACON_HEADERS_FULL, _BEACON_HEADERS_COMPACT)),
    ("sessions", (_SESSION_HEADERS_FULL, _SESSION_HEADERS_COMPACT)),
)

# Supported implant generation formats per target OS.
_ALLOWED_FORMATS = {
    "windows": {"exe", "shared", "shellcode", "service", "dll"},
    "linux": {"elf", "shared", "shellcode"},
    "darwin": {"macho", "shared", "shellcode"},
}
_ALLOWED_OS = tuple(_ALLOWED_FORMATS)

# Default output format when the caller does not specify one.
_DEFAULT_FORMAT = {"windows": "exe", "linux": "elf", "darwin": "macho"}

# Strict allow-list of read-only host discovery commands. Only these exact
# commands may run on a target; anything else is refused before it reaches the
# target. Grouped by MITRE ATT&CK technique:
#   T1082 — System Information Discovery (whoami, id, uname, hostname, uptime)
#   T1083 — File and Directory Discovery (pwd, ls, and a fixed canary read)
#   T1057 — Process Discovery (ps)
#   T1016 — System Network Configuration Discovery (ip, route)
DISCOVERY_COMMANDS: dict[str, str] = {
    # T1082 — System Information Discovery
    "whoami": "whoami",
    "id": "id",
    "uname": "uname -a",
    "hostname": "hostname",
    "uptime": "uptime",
    # T1083 — File and Directory Discovery. Paths are fixed literals, never
    # operator- or model-supplied, so discovery cannot be aimed at arbitrary
    # files on the target.
    "pwd": "pwd",
    "ls": "ls -la",
    "canary": "cat /tmp/canary_data.txt",
    # T1057 — Process Discovery. Fixed flags, no target selector: it can only
    # enumerate processes, never signal or kill one.
    "ps": "ps aux",
    # T1016 — System Network Configuration Discovery. Read-only, no arguments.
    "ip": "ip a",
    "route": "route -n",
}

# Accept both the short keys above and the literal command strings operators or
# models may pass (e.g. "uname -a").
_DISCOVERY_ALIASES: dict[str, str] = {
    **{key: key for key in DISCOVERY_COMMANDS},
    **{value: key for key, value in DISCOVERY_COMMANDS.items()},
}

# A canary read is the one discovery command that varies: operators may seed
# decoy files under /tmp/ (T1083). The directory is fixed and the file name must
# match a strict pattern, so this can never be aimed at an arbitrary path.
_CANARY_READ_RE = re.compile(r"^cat\s+/tmp/(canary_[A-Za-z0-9_]{1,64}\.txt)$")

# Timeout for a single discovery command executed on a session.
_DISCOVERY_TIMEOUT = 60

_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _client_binary() -> str:
    """Return the configured sliver-client binary name or path."""
    return os.getenv(_CLIENT_ENV, _DEFAULT_CLIENT).strip() or _DEFAULT_CLIENT


def _client_path() -> str | None:
    """Return the resolved path to sliver-client, or None when unavailable."""
    return shutil.which(_client_binary())


def _strip_ansi(text: str) -> str:
    """Remove ANSI colour codes so output can be parsed reliably."""
    return _ANSI_RE.sub("", text or "")


def _looks_like_connection_error(text: str) -> bool:
    """Heuristically detect that the client could not reach the server."""
    lowered = (text or "").lower()
    return any(marker in lowered for marker in _CONNECTION_ERROR_MARKERS)


def _not_installed_message() -> str:
    """Build a helpful message when the client binary is not on PATH."""
    binary = _client_binary()
    return (
        f"Sliver client '{binary}' was not found on PATH.\n"
        "Install the Sliver client (see https://github.com/BishopFox/sliver) "
        f"or point AdversarySim at it with the {_CLIENT_ENV} environment variable, "
        f"e.g. {_CLIENT_ENV}=/opt/sliver/sliver-client."
    )


def _daemon_down_message(detail: str) -> str:
    """Build a helpful message when the Sliver server/daemon is unreachable."""
    hint = (
        "Sliver server/daemon is not reachable. Start it with "
        "`sliver-server` (or `sliver-server daemon`) and import an operator "
        "config with `sliver-client import <file.cfg>` before retrying."
    )
    detail = _strip_ansi(detail).strip()
    return f"{hint}\n\nClient output:\n{detail}" if detail else hint


def _run_sliver_commands(commands: Iterable[str], timeout: int = _LIST_TIMEOUT) -> str:
    """Run one or more Sliver console commands non-interactively.

    The commands are piped into ``sliver-client console`` via stdin, which
    Sliver executes as a script and then exits.

    Args:
        commands: Sliver console commands to execute, in order.
        timeout: Maximum time in seconds to wait for the client.

    Returns:
        str: Raw combined client output (stdout, or stderr when stdout is
        empty).
    """
    lines = [line for line in commands if line and line.strip()]
    if not lines:
        return ""
    script = "\n".join(lines) + "\n"
    binary = _client_binary()
    try:
        proc = subprocess.run(
            [binary, "console"],
            input=script,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return _not_installed_message()
    except subprocess.TimeoutExpired:
        return f"Sliver client timed out after {timeout}s while running: {'; '.join(lines)}"

    output = proc.stdout or ""
    if not output.strip():
        output = proc.stderr or ""
    return output


def _find_header_columns(header_line: str, headers: Iterable[str]) -> list[tuple[str, int]] | None:
    """Locate the character offset of each header label within *header_line*.

    Returns a list of ``(label, start_index)`` in the order given, or ``None``
    when one of the labels cannot be found.
    """
    lowered = header_line.lower()
    columns: list[tuple[str, int]] = []
    cursor = 0
    for label in headers:
        idx = lowered.find(label.lower(), cursor)
        if idx == -1:
            return None
        columns.append((label, idx))
        cursor = idx + len(label)
    return columns


def _is_separator_line(line: str) -> bool:
    """Return True for go-pretty table separator lines (e.g. ``====  ====``)."""
    stripped = line.strip()
    return bool(stripped) and all(ch in "=-+| " for ch in stripped)


# go-pretty pads every column with at least two spaces, while individual cell
# values only ever contain single spaces. Splitting on 2+ spaces therefore
# recovers the exact column values even though the header labels are centred.
_COLUMN_SPLIT_RE = re.compile(r"\s{2,}")


def _tokenize_row(line: str) -> list[str]:
    """Split a go-pretty table row into its column values."""
    return [cell.strip() for cell in _COLUMN_SPLIT_RE.split(line.strip())]


def _map_row(cells: list[str], headers: list[str]) -> dict[str, str]:
    """Map positional column values onto their header labels.

    Values that legitimately contain a double space are folded back into the
    final column; missing tokens yield empty strings.
    """
    row: dict[str, str] = {}
    for idx, header in enumerate(headers):
        row[header] = cells[idx] if idx < len(cells) else ""
    if len(cells) > len(headers):
        row[headers[-1]] = " ".join(cells[len(headers) - 1 :])
    return row


def _parse_table(text: str, header_sets: Iterable[Iterable[str]]) -> list[dict[str, str]]:
    """Parse a Sliver fixed-width table into a list of row dictionaries.

    Args:
        text: Raw client output (may contain ANSI codes and banner text).
        header_sets: Candidate header label sets; the first one whose labels are
            all present, in order, on a single line wins. This accommodates
            Sliver's full/compact table layouts.

    Returns:
        list[dict[str, str]]: One dict per data row, keyed by header label.
        Empty when no header/rows are found.
    """
    lines = [_strip_ansi(line).rstrip() for line in (text or "").splitlines()]
    lines = [line for line in lines if line.strip()]
    if not lines:
        return []

    for headers in header_sets:
        header_list = list(headers)
        for line_idx, line in enumerate(lines):
            if _find_header_columns(line, header_list) is None:
                continue
            rows: list[dict[str, str]] = []
            for row_line in lines[line_idx + 1 :]:
                if _is_separator_line(row_line):
                    continue
                cells = _tokenize_row(row_line)
                if not cells:
                    continue
                rows.append(_map_row(cells, header_list))
            return rows
    return []


def _format_rows(rows: list[dict[str, str]], title: str, empty_hint: str) -> str:
    """Render parsed rows as a readable, compact report."""
    if not rows:
        return empty_hint
    out = [f"{title} ({len(rows)}):"]
    for row in rows:
        fields = ", ".join(f"{k}={v}" for k, v in row.items() if v)
        out.append(f"  - {fields}")
    return "\n".join(out)


def _workspace_dir() -> str:
    """Return the directory generated implants are saved into.

    Defaults to ``./implants`` relative to the current working directory and can
    be overridden with ``ADVERSARYSIM_WORKSPACE``.
    """
    return os.getenv("ADVERSARYSIM_WORKSPACE", os.path.join(os.getcwd(), "implants"))


def _implant_save_path(target_os: str, port: int, fmt: str) -> str:
    """Compute the workspace path an implant should be saved to.

    Kept as a module-level helper so the tool function can accept a parameter
    named ``os`` without shadowing the ``os`` module it depends on.
    """
    ext = {
        "shellcode": "bin",
        "shared": "so" if target_os == "linux" else "dll",
        "elf": "elf",
        "macho": "macho",
    }.get(fmt, fmt)
    return os.path.join(_workspace_dir(), f"sliver_implant_{target_os}_{port}.{ext}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sliver_status() -> str:
    """Check whether the Sliver client and server/daemon are available.

    Use this before other Sliver operations to confirm the tooling is usable.

    Returns:
        str: A human-readable status report describing whether the
        sliver-client binary is installed, its version, and whether the Sliver
        server/daemon is reachable.
    """
    path = _client_path()
    if not path:
        return _not_installed_message()

    try:
        version_out = _strip_ansi(_run_sliver_commands(["version"], timeout=_LIST_TIMEOUT)).strip()
    except Exception as exc:  # noqa: BLE001 - keep the assistant loop alive
        return f"Sliver client found at {path}, but running it failed: {exc}"

    client_line = f"sliver-client found: {path}"
    if version_out:
        client_line += f" (version: {version_out.splitlines()[0].strip()})"

    if _looks_like_connection_error(version_out):
        return f"{client_line}\n{_daemon_down_message(version_out)}"

    try:
        sessions_out = _run_sliver_commands(["sessions"], timeout=_LIST_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        return f"{client_line}\nServer check failed: {exc}"

    if _looks_like_connection_error(sessions_out):
        return f"{client_line}\n{_daemon_down_message(sessions_out)}"

    return f"{client_line}\nSliver server/daemon is reachable and responding."


def _collect_rows(
    command: str, header_sets: Iterable[Iterable[str]]
) -> tuple[list[dict[str, str]], str]:
    """Run a Sliver list command and return ``(rows, error)``.

    ``error`` is empty on success; otherwise it holds a human-readable message
    (client missing, daemon down, or the runner failed) and ``rows`` is empty.
    """
    if not _client_path():
        return [], _not_installed_message()
    try:
        output = _run_sliver_commands([command], timeout=_LIST_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        return [], f"Failed to list Sliver {command}: {exc}"
    if _looks_like_connection_error(output):
        return [], _daemon_down_message(output)
    return _parse_table(output, header_sets), ""


def sliver_list_sessions() -> str:
    """List active interactive Sliver sessions.

    Sessions are real-time implants connected back to the server. Returns a
    parsed summary of each session (id, name, transport, remote address,
    hostname, username and operating system).

    Returns:
        str: A formatted list of active sessions, or a clear message when no
        sessions are available or the server is unreachable.
    """
    rows, error = _collect_rows("sessions", (_SESSION_HEADERS_FULL, _SESSION_HEADERS_COMPACT))
    if error:
        return error
    return _format_rows(rows, "Active Sliver sessions", "No active Sliver sessions.")


def sliver_list_beacons() -> str:
    """List registered Sliver beacons.

    Beacons are asynchronous implants that check in on an interval rather than
    holding a persistent connection.

    Returns:
        str: A formatted list of beacons, or a clear message when none are
        registered or the server is unreachable.
    """
    rows, error = _collect_rows("beacons", (_BEACON_HEADERS_FULL, _BEACON_HEADERS_COMPACT))
    if error:
        return error
    return _format_rows(rows, "Sliver beacons", "No Sliver beacons registered.")


def sliver_list_jobs() -> str:
    """List active Sliver listeners (jobs).

    Jobs are the server-side listeners such as mTLS, HTTP, HTTPS and DNS that
    receive implant callbacks.

    Returns:
        str: A formatted list of active listeners, or a clear message when none
        are running or the server is unreachable.
    """
    rows, error = _collect_rows("jobs", (_JOB_HEADERS,))
    if error:
        return error
    return _format_rows(rows, "Active Sliver listeners (jobs)", "No active Sliver listeners.")


def sliver_generate_payload(
    os: str,
    lhost: str,
    lport: int,
    format: str = "",
    beacon: bool = False,
) -> str:
    """Generate a Sliver implant (session or beacon) for authorised testing.

    The implant is saved into the workspace. This builds the payload only; it
    does not deploy or execute it.

    Args:
        os: Target operating system. One of: windows, linux, darwin.
        lhost: Listener host (IP address or hostname) the implant calls back to.
        lport: Listener port the implant calls back to (1-65535).
        format: Output format. Defaults to a sensible per-OS value. Windows:
            exe, shared, shellcode, service, dll. Linux: elf, shared, shellcode.
            Darwin: macho, shared, shellcode.
        beacon: When True, generate an asynchronous beacon instead of an
            interactive session implant.

    Returns:
        str: The command that was run and the client output, including the path
        where the implant was saved, or a clear error message.
    """
    if not _client_path():
        return _not_installed_message()

    target_os = str(os).strip().lower()
    if target_os not in _ALLOWED_FORMATS:
        return f"Unsupported os '{os}'. Allowed values: {', '.join(_ALLOWED_OS)}."

    fmt = str(format).strip().lower() or _DEFAULT_FORMAT[target_os]
    if fmt not in _ALLOWED_FORMATS[target_os]:
        allowed = ", ".join(sorted(_ALLOWED_FORMATS[target_os]))
        return f"Unsupported format '{format}' for {target_os}. Allowed: {allowed}."

    try:
        port = int(lport)
    except (TypeError, ValueError):
        return f"Invalid lport '{lport}': must be an integer between 1 and 65535."
    if port < 1 or port > 65535:
        return f"Invalid lport {port}: must be between 1 and 65535."

    host = str(lhost).strip()
    if not _HOSTNAME_RE.match(host):
        return f"Invalid lhost '{lhost}': expected an IP address or hostname."

    save_path = _implant_save_path(target_os, port, fmt)

    prefix = "generate beacon" if beacon else "generate"
    command = (
        f"{prefix} --os {target_os} --mtls {host}:{port} "
        f"--format {fmt} --save {shlex.quote(save_path)}"
    )

    try:
        output = _strip_ansi(_run_sliver_commands([command], timeout=_GENERATE_TIMEOUT)).strip()
    except Exception as exc:  # noqa: BLE001
        return f"Failed to generate Sliver implant: {exc}"

    if _looks_like_connection_error(output):
        return _daemon_down_message(output)

    header = f"Ran: {command}\nRequested implant saved (if generation succeeded) to: {save_path}\n"
    return f"{header}\nClient output:\n{output}" if output else header


def _resolve_discovery_command(command: str) -> str | None:
    """Resolve an operator/model-supplied discovery command to a safe literal.

    Returns the exact command string to run on the target, or ``None`` when the
    request is not on the allow-list. Accepts the short keys in
    :data:`DISCOVERY_COMMANDS`, their literal forms, and a canary read of any
    ``/tmp/canary_*.txt`` file (MITRE T1083).
    """
    requested = str(command).strip()
    key = _DISCOVERY_ALIASES.get(requested) or _DISCOVERY_ALIASES.get(requested.lower())
    if key is not None:
        return DISCOVERY_COMMANDS[key]

    canary = _CANARY_READ_RE.match(requested)
    if canary:
        return f"cat /tmp/{canary.group(1)}"
    return None


def sliver_run_discovery(session_id: str, command: str) -> str:
    """Run one read-only discovery command on a Sliver session.

    This emulates a narrow slice of adversary discovery on an authorised target:

    - **MITRE T1082 — System Information Discovery**: ``whoami``, ``id``,
      ``uname -a``, ``hostname``, ``uptime``.
    - **MITRE T1083 — File and Directory Discovery**: ``pwd``, ``ls -la`` and a
      canary read (``cat /tmp/canary_*.txt``).
    - **MITRE T1057 — Process Discovery**: ``ps aux``.
    - **MITRE T1016 — System Network Configuration Discovery**: ``ip a``,
      ``route -n``.

    To keep the action defensible it accepts only a strict allow-list of
    read-only commands (see :data:`DISCOVERY_COMMANDS`). Paths are fixed literals
    — a canary read is confined to ``/tmp/canary_*.txt`` — so discovery can never
    be aimed at arbitrary files. Anything else is refused before any command
    reaches the target.

    The command is dispatched through the Sliver session console as
    ``use <session_id>; <command>``. This function performs no approval itself —
    the caller (the CLI) must route it through the human-in-the-loop Safety Gate,
    which classifies it as ``state-changing`` and requires ``[y/N]``.

    Args:
        session_id: The Sliver session to run the command on (id, name or index).
        command: One of the allow-listed discovery commands, either the short
            key (``whoami``, ``ls``, ``canary``) or the literal command string
            (``uname -a``, ``ls -la``, ``cat /tmp/canary_data.txt``).

    Returns:
        str: The command that ran and the target's output, or a clear refusal or
        error message.
    """
    if not _client_path():
        return _not_installed_message()

    session = str(session_id).strip()
    if not session or not _SESSION_ID_RE.match(session):
        return (
            f"Invalid session id '{session_id}': expected 1-64 characters of "
            "letters, digits, underscore or hyphen."
        )

    resolved = _resolve_discovery_command(command)
    if resolved is None:
        allowed = ", ".join(sorted(DISCOVERY_COMMANDS))
        return (
            f"Refused: '{command}' is not an allowed discovery command. "
            f"Allowed: {allowed}, or cat /tmp/canary_*.txt."
        )

    console_commands = [f"use {session}", resolved]
    try:
        output = _strip_ansi(
            _run_sliver_commands(console_commands, timeout=_DISCOVERY_TIMEOUT)
        ).strip()
    except Exception as exc:  # noqa: BLE001
        return f"Failed to run discovery command '{resolved}': {exc}"

    if _looks_like_connection_error(output):
        return _daemon_down_message(output)

    header = f"Ran on session {session}: {resolved}\n"
    return f"{header}\nTarget output:\n{output}" if output else f"{header}\n(no output)"


def sliver_resolve_target() -> str:
    """Resolve the active implant to operate on when none was supplied.

    Lists beacons first (asynchronous implants), then falls back to interactive
    sessions. Returns the first target's id, or a clear message explaining that
    nothing is available or the server is unreachable.

    Returns:
        str: A bare target id when a candidate is found, otherwise a
        human-readable message (which callers should treat as "no target").
    """
    for command, headers in _TARGET_LISTERS:
        rows, error = _collect_rows(command, headers)
        if error:
            return error
        if rows:
            target_id = rows[0].get("ID", "").strip()
            if target_id:
                return target_id

    return "No active Sliver beacon or session found. Deploy an implant first."


def is_target_id(candidate: str) -> bool:
    """Return True when *candidate* looks like a bare Sliver target id.

    Lets callers distinguish a real id returned by :func:`sliver_resolve_target`
    from a human-readable "nothing available" / error message.
    """
    return bool(_SESSION_ID_RE.match(str(candidate).strip()))
