"""Modern terminal interface for AdversarySim-AI.

Built with ``rich`` for readable, colourised output and ``typer`` for argument
parsing. Every Sliver action is routed through :mod:`adversary_sim.safety` so
nothing runs without explicit operator approval.
"""

from __future__ import annotations

import asyncio
import json
import shlex

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from . import sliver
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
    }
)

# Tools that accept arguments from the model (name -> ordered parameter names).
# Tools absent from this map are invoked with no arguments.
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
    console.print("[muted]Commands: /status /sessions /beacons /jobs /help /quit[/muted]\n")

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
                if _handle_slash(raw):
                    break
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
            result = _execute_tool_call(call)
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
    by the Safety Gate before the underlying function runs.
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
            f"  [{CYAN}]/help[/]       show this help\n"
            f"  [{CYAN}]/quit[/]       exit\n"
            f"[muted]  or just ask in natural language — discovery tools are "
            f"Safety-Gated.[/muted]"
        )
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
