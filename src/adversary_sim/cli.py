"""Modern terminal interface for AdversarySim-AI.

Built with ``rich`` for readable, colourised output and ``typer`` for argument
parsing. Every Sliver action is routed through :mod:`adversary_sim.safety` so
nothing runs without explicit operator approval.
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from . import reports, sliver, techniques
from .core import (
    DEFAULT_MODEL,
    DEFAULT_SYSTEM_PROMPT,
    ChatMessage,
    ChatReply,
    OllamaClient,
    OllamaError,
    ToolCall,
    parse_tool_calls_from_text,
)
from .safety import Action, RiskLevel, SafetyError, confirm, screen_text
from .techniques import Technique

__all__ = ["app", "main"]

# ---------------------------------------------------------------------------
# Hyper-dark visual identity — by Kadohack12
# ---------------------------------------------------------------------------

# Neon-on-black palette: blood-red for the brand, amber for warnings, cyan for
# structure. Kept deliberately tight so the whole UI reads as one dark theme.
BRAND = "kadohack12"
RED = "#ff2d55"
AMBER = "#ffb000"
CYAN = "#00e5ff"
GREEN = "#39ff14"

DARK_THEME = Theme(
    {
        "brand": f"bold {RED}",
        "brand.dim": f"dim {RED}",
        "accent": f"bold {CYAN}",
        "muted": "dim grey62",
        "ok": "bold green",
        "warn": f"bold {AMBER}",
        "danger": f"bold {RED}",
    }
)

console = Console(theme=DARK_THEME)

BANNER = r"""
   _       _                          _              ____  _
  / \   __| |_   _____ _ __ __ _  ___| |__  _   _   / ___|(_)_ __ ___
 / _ \ / _` \ \ / / _ \ '__/ _` |/ __| '_ \| | | |  \___ \| | '_ ` _ \
/ ___ \ (_| |\ V /  __/ | | (_| | (__| | | | |_| |   ___) | | | | | | |
/_/   \_\__,_| \_/ \___|_|  \__,_|\___|_| |_|\__, |  |____/|_|_| |_| |_|
                                             |___/
"""

TAGLINE = "Purple-team assistant · Sliver C2 + local LLMs · human-in-the-loop"
CREDIT = f"by {BRAND}"

SYSTEM_PROMPT = DEFAULT_SYSTEM_PROMPT

RISK_BY_TOOL = {
    "sliver_status": RiskLevel.READ_ONLY,
    "sliver_list_sessions": RiskLevel.READ_ONLY,
    "sliver_list_beacons": RiskLevel.READ_ONLY,
    "sliver_list_jobs": RiskLevel.READ_ONLY,
    "sliver_run_discovery": RiskLevel.STATE_CHANGING,
    "sliver_generate_payload": RiskLevel.DESTRUCTIVE,
}

# Sliver tools the local model may invoke through tool calling. Every name here
# must be a function in :mod:`adversary_sim.sliver`; the CLI still routes each
# call through the Safety Gate. Resolved dynamically so the binding always
# reflects the current module state.
TOOL_NAMES = frozenset(
    {
        "sliver_status",
        "sliver_list_sessions",
        "sliver_list_beacons",
        "sliver_list_jobs",
        "sliver_run_discovery",
        "mitre_run_technique",
    }
)

# Tools that accept arguments from the model (name -> ordered parameter names).
# Tools absent from this map are invoked with no arguments. ``mitre_run_technique``
# is handled specially (its arguments are optional and it writes a report), so it
# is intentionally not listed here.
TOOL_ARGUMENTS: dict[str, tuple[str, ...]] = {
    "sliver_run_discovery": ("session_id", "command"),
}


def _resolve_tool(name: str):
    """Return the sliver function for *name*, or None if not allowed."""
    if name not in TOOL_NAMES:
        return None
    return getattr(sliver, name, None)


app = typer.Typer(
    add_completion=False,
    help="AdversarySim-AI — purple-team assistant for Sliver C2 and local LLMs.",
    no_args_is_help=False,
)

mitre_app = typer.Typer(
    add_completion=False,
    help="MITRE ATT&CK emulation: list allow-listed techniques, run one, write a report.",
    no_args_is_help=True,
)
app.add_typer(mitre_app, name="mitre")


def print_banner() -> None:
    """Render the startup banner with the Kadohack12 dark identity."""
    console.print(Text(BANNER, style=BRAND), highlight=False)
    subtitle = Text()
    subtitle.append("  AdversarySim-AI", style="accent")
    subtitle.append("  ·  ", style="muted")
    subtitle.append(CREDIT, style="brand.dim")
    console.print(Panel(subtitle, border_style=RED, style="on black", padding=(0, 1)))
    console.print(Text(f"  {TAGLINE}", style="muted"))
    console.print()


def render_table(rows: list[dict[str, str]], title: str) -> None:
    """Render parsed Sliver rows as a hyper-dark rich table."""
    if not rows:
        console.print(f"[warn]{title}: none[/warn]")
        return
    table = Table(
        title=Text(title, style="accent"),
        header_style=f"bold {RED}",
        border_style="grey35",
        title_justify="left",
        row_styles=["none", "on #0a0a0a"],
    )
    columns = list(rows[0].keys())
    for column in columns:
        table.add_column(column, style="grey85")
    for row in rows:
        table.add_row(*[row.get(column, "") for column in columns])
    console.print(table)


def _parse_json_rows(output: str) -> list[dict[str, str]] | None:
    """Best-effort extraction of JSON rows from a tool's text output.

    Returns None when the output is not JSON, in which case callers should print
    the raw text instead.
    """
    candidate = output.strip()
    if not candidate.startswith("["):
        return None
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, list) and all(isinstance(item, dict) for item in parsed):
        return parsed
    return None


# Visual accent per risk level, used to frame the Safety Gate prompt.
RISK_STYLE = {
    RiskLevel.READ_ONLY: ("ok", "READ-ONLY"),
    RiskLevel.STATE_CHANGING: ("warn", "STATE-CHANGING"),
    RiskLevel.DESTRUCTIVE: ("danger", "DESTRUCTIVE"),
}


def run_action(
    summary: str,
    operation,
    *,
    risk: RiskLevel = RiskLevel.STATE_CHANGING,
    command: str = "",
    assume_yes: bool | None = None,
    dry_run: bool | None = None,
) -> str:
    """Confirm an action with the operator, then run it.

    Returns the operation's output, or a cancellation notice when refused.
    """
    action = Action(summary=summary, command=command, risk=risk)
    style, label = RISK_STYLE.get(risk, ("warn", risk.value.upper()))
    console.print(
        Text.assemble(
            ("  ▚ SAFETY GATE ", "brand"),
            ("· ", "muted"),
            (label, style),
        )
    )
    if not confirm(action, assume_yes=assume_yes, dry_run=dry_run):
        return f"Cancelled: {summary}"
    return operation()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def status() -> None:
    """Check that the Sliver client and server are reachable."""
    print_banner()
    result = run_action(
        "Check Sliver client and server status",
        sliver.sliver_status,
        risk=RISK_BY_TOOL["sliver_status"],
    )
    console.print(Panel(result, title=Text("Sliver status", style="accent"), border_style=CYAN))


@app.command()
def sessions() -> None:
    """List active Sliver sessions."""
    _list_command("sessions", "Active Sliver sessions")


@app.command()
def beacons() -> None:
    """List registered Sliver beacons."""
    _list_command("beacons", "Sliver beacons")


@app.command()
def jobs() -> None:
    """List active Sliver listeners (jobs)."""
    _list_command("jobs", "Active Sliver listeners (jobs)")


@app.command()
def discover(
    session: str = typer.Argument(..., help="Target session id, name or index."),
    command: str = typer.Argument(
        ...,
        help="Discovery command: whoami, id, uname -a, hostname or uptime.",
    ),
) -> None:
    """Run one read-only discovery command on a session (MITRE T1082).

    Operator approval is required: the action is classified ``state-changing``.
    Only the allow-listed commands are accepted; anything else is refused.
    """
    print_banner()
    result = run_action(
        f"Run discovery command '{command}' on session {session}",
        lambda: sliver.sliver_run_discovery(session, command),
        risk=RISK_BY_TOOL["sliver_run_discovery"],
        command=f"sliver_run_discovery session={session} command={command}",
    )
    console.print(Panel(result, title=Text("System discovery", style="accent"), border_style=GREEN))


# ---------------------------------------------------------------------------
# MITRE ATT&CK emulation
# ---------------------------------------------------------------------------

_MITRE_ID_RE = re.compile(r"\b[Tt](\d{4})\b")


def _detect_mitre_request(text: str) -> Technique | None:
    """Return the technique referenced in *text*, or None.

    Keeps the agent *open*: any MITRE ATT&CK id (``T1033``, ``T1082``, ...) is
    honoured, whether or not it is in the curated catalogue. Curated ids resolve
    to their entry; anything else becomes a generic technique so the operator can
    still run a defensible discovery emulation and get a report.

    Triggers only when the operator mentions "mitre", so ordinary chat is
    unaffected. The id is taken from an explicit ``T####`` token.
    """
    if "mitre" not in text.lower():
        return None
    for match in _MITRE_ID_RE.finditer(text):
        technique = techniques.technique_or_generic(f"T{match.group(1)}")
        if technique is not None:
            return technique
    return None


def render_techniques_table() -> None:
    """Render the allow-listed MITRE technique catalogue as a dark table."""
    table = Table(
        title=Text("MITRE ATT&CK emulation catalogue", style="accent"),
        header_style=f"bold {RED}",
        border_style="grey35",
        title_justify="left",
        row_styles=["none", "on #0a0a0a"],
    )
    table.add_column("ID", style=f"bold {AMBER}")
    table.add_column("Technique", style="grey85")
    table.add_column("Tactic", style="grey62")
    table.add_column("Sliver command", style=f"{CYAN}")
    table.add_column("Safety", style="grey85")
    for technique in techniques.list_techniques():
        table.add_row(
            technique.id,
            technique.name,
            technique.tactic,
            sliver.DISCOVERY_COMMANDS.get(technique.command, technique.command),
            f"[warn]{technique.risk}[/warn]",
        )
    console.print(table)
    console.print("[muted]Every technique runs through the Safety Gate and requires [y/N].[/muted]")


async def run_mitre_technique(
    technique: Technique,
    session: str = "",
    *,
    client: OllamaClient | None = None,
    model: str = DEFAULT_MODEL,
    use_llm: bool = True,
) -> str:
    """Run one MITRE technique end to end and write an audit report.

    Resolves the target (auto-selecting the active beacon when *session* is
    empty), routes the command through the Safety Gate, executes it, and writes a
    Markdown report. Returns a summary string (also used as a tool result).
    """
    target = (session or "").strip()
    if not target:
        resolved = sliver.sliver_resolve_target()
        if not sliver.is_target_id(resolved):
            console.print(
                Panel(resolved, title=Text("No target", style="danger"), border_style=RED)
            )
            return f"Error: could not resolve a target — {resolved}"
        target = resolved
        console.print(
            f"[muted]No session given — auto-selected target[/muted] [accent]{target}[/accent]"
        )

    console.print(
        Text.assemble(
            ("  ▚ MITRE ", "brand"),
            (f"{technique.id} ", "accent"),
            (technique.name, "muted"),
        )
    )
    result = run_action(
        f"MITRE {technique.id} — {technique.name} on {target}",
        lambda: sliver.sliver_run_discovery(target, technique.command),
        risk=RISK_BY_TOOL["sliver_run_discovery"],
        command=f"mitre {technique.id} -> sliver_run_discovery {target} {technique.command}",
    )
    console.print(
        Panel(
            result,
            title=Text(f"{technique.id} · execution", style="accent"),
            border_style=GREEN,
        )
    )
    if result.startswith("Cancelled:"):
        return result

    if not use_llm and client is None:
        report = await reports.generate_report(
            technique, target=target, evidence=result, use_llm=False
        )
    else:
        owned = client is None
        active = client or OllamaClient(model=model)
        try:
            report = await reports.generate_report(
                technique, target=target, evidence=result, client=active, use_llm=use_llm
            )
        finally:
            if owned:
                await active.aclose()

    note = "" if report.llm_used else " [muted](détections curatées)[/muted]"
    console.print(
        Panel(
            f"Rapport écrit : [accent]{report.path}[/accent]{note}",
            title=Text("Purple Team report", style="accent"),
            border_style=CYAN,
        )
    )
    return f"{result}\n\nRapport Purple Team écrit : {report.path}"


@mitre_app.command("list")
def mitre_list() -> None:
    """List the allow-listed MITRE ATT&CK emulation techniques."""
    print_banner()
    render_techniques_table()


@mitre_app.command("run")
def mitre_run(
    technique_id: str = typer.Argument(..., help="Technique id, e.g. T1082 or T1033."),
    session: str = typer.Argument("", help="Optional target session/beacon id."),
    report: bool = typer.Option(
        True, "--report/--no-report", help="Write a Markdown audit report."
    ),
    model: str = typer.Option(DEFAULT_MODEL, "--model", help="Ollama model for the report."),
) -> None:
    """Run any MITRE technique (Safety Gate) and write a Purple Team report.

    Curated ids (T1082, T1083, T1057, T1016) map to their dedicated discovery
    command. Any other valid id (e.g. T1033) is emulated with a defensible
    read-only discovery command and labelled as a generic mapping.
    """
    print_banner()
    technique = techniques.technique_or_generic(technique_id)
    if technique is None:
        console.print(
            f"[danger]'{technique_id}' is not a valid MITRE technique id "
            "(expected e.g. T1033).[/danger]"
        )
        render_techniques_table()
        raise typer.Exit(code=2)
    if techniques.get_technique(technique_id) is None:
        console.print(
            f"[warn]{technique.id} is not in the curated catalogue — "
            f"running a generic read-only discovery emulation.[/warn]"
        )
    asyncio.run(run_mitre_technique(technique, session, model=model, use_llm=report))


def _list_command(kind: str, title: str) -> None:
    operation = getattr(sliver, f"sliver_list_{kind}")
    result = run_action(
        f"List Sliver {kind}",
        operation,
        risk=RISK_BY_TOOL.get(f"sliver_list_{kind}", RiskLevel.READ_ONLY),
    )
    rows = _parse_json_rows(result)
    if rows is not None:
        render_table(rows, title)
    else:
        console.print(Panel(result, title=Text(title, style="accent"), border_style=GREEN))


@app.command()
def generate(
    os: str = typer.Option(..., "--os", help="Target OS: windows, linux or darwin."),
    lhost: str = typer.Option(..., "--lhost", help="Callback host for the implant."),
    lport: int = typer.Option(..., "--lport", help="Callback port (1-65535)."),
    format: str = typer.Option("", "--format", help="Output format (per-OS default if empty)."),
    beacon: bool = typer.Option(False, "--beacon", help="Generate a beacon, not a session."),
) -> None:
    """Generate a Sliver implant (operator approval required)."""
    command = f"generate --os {os} --mtls {lhost}:{lport} --format {format or 'default'}"
    reasons = screen_text(lhost, forbidden=("..", "/"))
    if reasons:
        console.print("[danger]Refused: suspicious input.[/danger]")
        for reason in reasons:
            console.print(f"  - {reason}")
        raise typer.Exit(code=2)

    result = run_action(
        f"Generate {'beacon' if beacon else 'session'} implant for {os}",
        lambda: sliver.sliver_generate_payload(
            os=os, lhost=lhost, lport=lport, format=format, beacon=beacon
        ),
        risk=RISK_BY_TOOL["sliver_generate_payload"],
        command=command,
    )
    console.print(
        Panel(result, title=Text("Implant generation", style="accent"), border_style=GREEN)
    )


@app.command()
def ask(
    prompt: str = typer.Argument(..., help="Question for the local model."),
    model: str = typer.Option(DEFAULT_MODEL, "--model", help="Ollama model name."),
) -> None:
    """Ask the local LLM a question (no tool execution)."""
    asyncio.run(_ask(prompt, model))


async def _ask(prompt: str, model: str) -> None:
    client = OllamaClient(model=model, system_prompt=SYSTEM_PROMPT)
    try:
        with console.status(f"Thinking with {model}…"):
            reply = await client.chat(prompt)
    except OllamaError as exc:
        console.print(f"[danger]{exc}[/danger]")
        console.print("[muted]Is Ollama running? Try `ollama serve`.[/muted]")
        raise typer.Exit(code=1) from exc
    finally:
        await client.aclose()
    console.print(Markdown(reply))


@app.command()
def shell() -> None:
    """Start an interactive session (LLM chat + Sliver shortcuts)."""
    asyncio.run(_shell())


async def _shell() -> None:
    print_banner()
    client = OllamaClient(system_prompt=SYSTEM_PROMPT)
    available = await client.is_available()
    if available:
        console.print(f"[ok]Ollama ready[/ok] · model [bold]{client.model}[/bold]")
    else:
        console.print(
            f"[warn]Ollama not reachable at {client.host}[/warn] — "
            "chat disabled, Sliver shortcuts still work."
        )
    console.print(
        "[muted]Commands: /status /sessions /beacons /jobs /mitre /help /quit"
        '  ·  or ask in natural language (e.g. "Lance le test MITRE T1082")[/muted]\n'
    )

    history: list[ChatMessage] = []
    try:
        while True:
            try:
                raw = Prompt.ask(f"[{RED}]▚[/] [accent]adversarysim[/accent]").strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                break
            if not raw:
                continue
            if raw.startswith("/"):
                slash_parts = shlex.split(raw)
                if len(slash_parts) >= 2 and slash_parts[0].lower() == "/mitre":
                    technique = techniques.technique_or_generic(slash_parts[1])
                    if technique is None:
                        console.print(
                            f"[danger]'{slash_parts[1]}' is not a valid MITRE "
                            "technique id (expected e.g. T1033).[/danger]"
                        )
                        render_techniques_table()
                        continue
                    try:
                        await run_mitre_technique(technique, client=client)
                    except OllamaError as exc:
                        console.print(f"[danger]{exc}[/danger]")
                    continue
                if _handle_slash(raw):
                    break
                continue
            technique = _detect_mitre_request(raw)
            if technique is not None:
                try:
                    await run_mitre_technique(technique, client=client)
                except OllamaError as exc:
                    console.print(f"[danger]{exc}[/danger]")
                continue
            if not available:
                console.print("[warn]LLM unavailable; use /commands or start Ollama.[/warn]")
                continue
            history.append(ChatMessage("user", raw))
            mark = len(history) - 1
            try:
                await _converse(client, history)
            except OllamaError as exc:
                console.print(f"[danger]{exc}[/danger]")
                del history[mark:]
    finally:
        await client.aclose()


async def _converse(
    client: OllamaClient,
    history: list[ChatMessage],
    *,
    max_tool_rounds: int = 5,
) -> None:
    """Drive one operator turn, resolving any tool calls the model requests.

    Tool calls are detected from both the structured ``tool_calls`` field and,
    as a fallback, from raw JSON embedded in the message text (some local models
    emit ``{"name": "sliver_list_beacons", "arguments": {}}`` as content). Every
    detected call is routed through the Safety Gate before the Sliver function
    runs; the real output is then fed back to the model, which synthesises the
    final answer in natural language.

    Conversation state is appended to *history* in place.
    """
    with console.status("Thinking…"):
        reply = await client.continue_chat(history)

    for _ in range(max_tool_rounds):
        calls = _detect_tool_calls(reply)
        if not calls:
            break
        history.append(
            ChatMessage(
                "assistant",
                reply.content,
                tool_calls=[call.as_dict() for call in calls],
            )
        )
        for call in calls:
            result = await _execute_tool_call_async(call)
            history.append(
                ChatMessage("tool", _tool_result_message(call, result), tool_name=call.name)
            )
        with console.status("Thinking…"):
            reply = await client.continue_chat(history)

    if reply.content:
        console.print(Markdown(reply.content))
    history.append(ChatMessage("assistant", reply.content))


def _detect_tool_calls(reply: ChatReply) -> list[ToolCall]:
    """Return the tool calls in *reply*, structured or embedded in text.

    Prefers the structured ``tool_calls`` field; when that is empty it falls back
    to parsing a JSON tool invocation out of the raw ``content`` string, so a
    model that answers with ``{"name": "sliver_list_beacons", "arguments": {}}``
    as plain text still triggers execution instead of being echoed back.
    """
    if reply.tool_calls:
        return list(reply.tool_calls)
    return parse_tool_calls_from_text(reply.content)


def _tool_result_message(call: ToolCall, result: str) -> str:
    """Format a tool result as context for the model's synthesis turn."""
    return (
        f"Résultat de l'outil {call.name} :\n{result}\n"
        "Réponds maintenant à la question initiale de l'opérateur en français."
    )


def _execute_tool_call(call: ToolCall) -> str:
    """Approve and run a model-requested Sliver tool, returning its result.

    Unknown tools are refused without touching Sliver; known tools are screened
    by the Safety Gate before the underlying function runs. The MITRE tool is
    dispatched to the async handler by the caller (see :func:`_execute_tool_call_async`).
    """
    operation = _resolve_tool(call.name)
    if operation is None:
        console.print(f"[danger]Refused: unknown tool '{call.name}'.[/danger]")
        return f"Error: tool '{call.name}' is not available."

    console.print(f"[muted]→ model requested tool[/muted] [bold]{call.name}[/bold]")
    summary = f"Run Sliver tool '{call.name}' requested by the local model"
    command = call.name

    argument_names = TOOL_ARGUMENTS.get(call.name)
    if argument_names:
        missing = [name for name in argument_names if name not in call.arguments]
        if missing:
            return f"Error: tool '{call.name}' is missing argument(s): {', '.join(missing)}."
        kwargs = {name: call.arguments[name] for name in argument_names}
        command = f"{call.name} " + " ".join(f"{k}={v!r}" for k, v in kwargs.items())

        def operation(  # noqa: ANN202 - closure over resolved tool + args
            _name=call.name, _kwargs=kwargs
        ):
            return _resolve_tool(_name)(**_kwargs)

    return run_action(
        summary,
        operation,
        risk=RISK_BY_TOOL.get(call.name, RiskLevel.READ_ONLY),
        command=command,
    )


async def _execute_tool_call_async(call: ToolCall) -> str:
    """Async wrapper around :func:`_execute_tool_call`.

    The MITRE tool needs to await the report generator, so it cannot go through
    the synchronous path; every other tool is executed synchronously.
    """
    if call.name == "mitre_run_technique":
        return await _execute_mitre_tool_call(call)
    return _execute_tool_call(call)


async def _execute_mitre_tool_call(call: ToolCall) -> str:
    """Handle a model-requested MITRE technique run (any ``T####`` id).

    Resolves the technique dynamically (curated or generic), routes the discovery
    command through the Safety Gate, and writes the Purple Team report. The
    underlying ``run_mitre_technique`` coroutine owns the approval + report flow.
    """
    technique_id = str(call.arguments.get("technique_id", "")).strip()
    if not technique_id:
        return "Error: tool 'mitre_run_technique' requires a 'technique_id'."
    technique = techniques.technique_or_generic(
        technique_id,
        name=str(call.arguments.get("name", "")),
    )
    if technique is None:
        return f"Error: '{technique_id}' is not a valid MITRE technique id."

    console.print(f"[muted]→ model requested MITRE technique[/muted] [bold]{technique.id}[/bold]")
    session = str(call.arguments.get("session_id", "")).strip()
    try:
        return await run_mitre_technique(technique, session)
    except Exception as exc:  # noqa: BLE001
        return f"Failed to run MITRE {technique.id}: {exc}"


def _handle_slash(raw: str) -> bool:
    """Handle an interactive slash command. Returns True to exit."""
    parts = shlex.split(raw)
    name = parts[0].lower()
    if name in {"/quit", "/exit", "/q"}:
        return True
    if name == "/help":
        console.print(
            f"[accent]Available commands[/accent]\n"
            f"  [{CYAN}]/status[/]     check Sliver client + server\n"
            f"  [{CYAN}]/sessions[/]   list active sessions\n"
            f"  [{CYAN}]/beacons[/]    list beacons\n"
            f"  [{CYAN}]/jobs[/]       list listeners\n"
            f"  [{CYAN}]/mitre[/]      list MITRE ATT&CK techniques\n"
            f"  [{CYAN}]/mitre T1082[/]  run a technique (Safety-Gated) + report\n"
            f"  [{CYAN}]/help[/]       show this help\n"
            f"  [{CYAN}]/quit[/]       exit\n"
            f'[muted]  or ask in natural language — e.g. "Lance le test MITRE T1082".[/muted]'
        )
        return False
    if name == "/mitre":
        render_techniques_table()
        return False
    mapping = {
        "/status": ("sliver_status", "Sliver status"),
        "/sessions": ("sliver_list_sessions", "Active Sliver sessions"),
        "/beacons": ("sliver_list_beacons", "Sliver beacons"),
        "/jobs": ("sliver_list_jobs", "Active Sliver listeners (jobs)"),
    }
    if name in mapping:
        func_name, title = mapping[name]
        operation = getattr(sliver, func_name)
        result = run_action(
            f"List Sliver {func_name.removeprefix('sliver_list_').removeprefix('sliver_')}",
            operation,
            risk=RISK_BY_TOOL.get(func_name, RiskLevel.READ_ONLY),
        )
        rows = _parse_json_rows(result)
        if rows is not None:
            render_table(rows, title)
        else:
            console.print(Panel(result, title=Text(title, style="accent"), border_style=GREEN))
        return False
    console.print(f"[danger]Unknown command: {name}[/danger] (try /help)")
    return False


@app.command()
def version() -> None:
    """Print the AdversarySim-AI version."""
    from . import __version__

    console.print(
        Text.assemble(
            ("AdversarySim-AI ", "accent"),
            (f"v{__version__}", "brand"),
            ("   ", "muted"),
            (CREDIT, "brand.dim"),
        )
    )


def main() -> None:
    """Console-script entry point."""
    try:
        app()
    except SafetyError as exc:
        console.print(f"[danger]{exc}[/danger]")
        raise typer.Exit(code=130) from exc


if __name__ == "__main__":
    main()
