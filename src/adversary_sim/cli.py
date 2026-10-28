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

console = Console()

BANNER = r"""
   _       _                          _              ____  _
  / \   __| |_   _____ _ __ __ _  ___| |__  _   _   / ___|(_)_ __ ___
 / _ \ / _` \ \ / / _ \ '__/ _` |/ __| '_ \| | | |  \___ \| | '_ ` _ \
/ ___ \ (_| |\ V /  __/ | | (_| | (__| | | | |_| |   ___) | | | | | | |
/_/   \_\__,_| \_/ \___|_|  \__,_|\___|_| |_|\__, |  |____/|_|_| |_| |_|
                                             |___/
"""

TAGLINE = "Purple-team assistant · Sliver C2 + local LLMs · human-in-the-loop"

SYSTEM_PROMPT = DEFAULT_SYSTEM_PROMPT

RISK_BY_TOOL = {
    "sliver_status": RiskLevel.READ_ONLY,
    "sliver_list_sessions": RiskLevel.READ_ONLY,
    "sliver_list_beacons": RiskLevel.READ_ONLY,
    "sliver_list_jobs": RiskLevel.READ_ONLY,
    "sliver_generate_payload": RiskLevel.DESTRUCTIVE,
}

# Sliver tools the local model may invoke through tool calling. Every name here
# must be a zero-argument, read-only function in :mod:`adversary_sim.sliver`;
# the CLI still routes each call through the Safety Gate. Resolved dynamically
# so the binding always reflects the current module state.
TOOL_NAMES = frozenset(
    {
        "sliver_status",
        "sliver_list_sessions",
        "sliver_list_beacons",
        "sliver_list_jobs",
    }
)


def _resolve_tool(name: str):
    """Return the read-only sliver function for *name*, or None if not allowed."""
    if name not in TOOL_NAMES:
        return None
    return getattr(sliver, name, None)


app = typer.Typer(
    add_completion=False,
    help="AdversarySim-AI — purple-team assistant for Sliver C2 and local LLMs.",
    no_args_is_help=False,
)


def print_banner() -> None:
    """Render the startup banner."""
    console.print(Text(BANNER, style="bold cyan"), highlight=False)
    console.print(Panel(TAGLINE, style="dim"))


def render_table(rows: list[dict[str, str]], title: str) -> None:
    """Render parsed Sliver rows as a rich table."""
    if not rows:
        console.print(f"[yellow]{title}: none[/yellow]")
        return
    table = Table(title=title, header_style="bold magenta")
    columns = list(rows[0].keys())
    for column in columns:
        table.add_column(column)
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
    console.print(Panel(result, title="Sliver status", border_style="cyan"))


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
        console.print(Panel(result, title=title, border_style="green"))


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
        console.print("[red]Refused: suspicious input.[/red]")
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
    console.print(Panel(result, title="Implant generation", border_style="green"))


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
        console.print(f"[red]{exc}[/red]")
        console.print("[dim]Is Ollama running? Try `ollama serve`.[/dim]")
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
        console.print(f"[green]Ollama ready[/green] · model [bold]{client.model}[/bold]")
    else:
        console.print(
            f"[yellow]Ollama not reachable at {client.host}[/yellow] — "
            "chat disabled, Sliver shortcuts still work."
        )
    console.print("[dim]Commands: /status /sessions /beacons /jobs /help /quit[/dim]\n")

    history: list[ChatMessage] = []
    try:
        while True:
            try:
                raw = Prompt.ask("[bold cyan]adversarysim[/bold cyan]").strip()
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
                console.print("[yellow]LLM unavailable; use /commands or start Ollama.[/yellow]")
                continue
            history.append(ChatMessage("user", raw))
            mark = len(history) - 1
            try:
                await _converse(client, history)
            except OllamaError as exc:
                console.print(f"[red]{exc}[/red]")
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
        console.print(f"[red]Refused: unknown tool '{call.name}'.[/red]")
        return f"Error: tool '{call.name}' is not available."

    console.print(f"[dim]→ model requested tool[/dim] [bold]{call.name}[/bold]")
    summary = f"Run Sliver tool '{call.name}' requested by the local model"
    return run_action(
        summary,
        operation,
        risk=RISK_BY_TOOL.get(call.name, RiskLevel.READ_ONLY),
        command=call.name,
    )


def _handle_slash(raw: str) -> bool:
    """Handle an interactive slash command. Returns True to exit."""
    parts = shlex.split(raw)
    name = parts[0].lower()
    if name in {"/quit", "/exit", "/q"}:
        return True
    if name == "/help":
        console.print(
            "[bold]Available commands[/bold]\n"
            "  /status     check Sliver client + server\n"
            "  /sessions   list active sessions\n"
            "  /beacons    list beacons\n"
            "  /jobs       list listeners\n"
            "  /help       show this help\n"
            "  /quit       exit"
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
            console.print(Panel(result, title=title, border_style="green"))
        return False
    console.print(f"[red]Unknown command: {name}[/red] (try /help)")
    return False


@app.command()
def version() -> None:
    """Print the AdversarySim-AI version."""
    from . import __version__

    console.print(f"AdversarySim-AI [bold]{__version__}[/bold]")


def main() -> None:
    """Console-script entry point."""
    try:
        app()
    except SafetyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=130) from exc


if __name__ == "__main__":
    main()
