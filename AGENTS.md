# AGENTS.md — AdversarySim-AI

Purple-team assistant for Sliver C2 + a **local** LLM (Ollama), with a strict
Human-in-the-Loop **Safety Gate** on every action.

## Commands

```bash
python -m pytest                     # full suite (currently 199 passing)
python -m ruff format . && python -m ruff check .
python -m adversary_sim.cli --help   # CLI entry point
```

## Architecture (mental model)

`cli.py` (typer + rich) → Safety Gate (`safety.py`) → `sliver.py` → Sliver C2.
The LLM lives in `core.py` (async Ollama client) and can only *request* tools;
`cli.py` intercepts and routes each request through the Safety Gate.

- `_converse` is **async**, so tool execution must be awaited:
  `_execute_tool_call_async` (async wrapper) → `_execute_tool_call` (sync) or
  `_execute_mitre_tool_call` (async, writes the report). Never call
  `asyncio.run()` inside `_converse` — it is already in an event loop.
- `TOOL_NAMES` / `TOOL_ARGUMENTS` / `RISK_BY_TOOL` in `cli.py` gate what the model
  may invoke. Keep them in sync with `TOOL_SCHEMAS` in `core.py`.

## Sliver console syntax (important)

Sliver's console has its **own** interpreter: a bare Linux command like `uname -a`
fails with "unknown command". `DISCOVERY_COMMANDS` in `sliver.py` therefore stores
*Sliver console* commands — native where Sliver has one (`whoami`, `ls -la`, `ps`),
otherwise `execute -o <cmd>` (`-o` is required to capture stdout).
`_resolve_discovery_command` also accepts the bare Linux form and the Sliver form as
aliases, so callers can pass either.

## Dynamic MITRE agent

Any valid `T####` id is supported (not just the curated four). `techniques.py`
exposes `generic_technique()` / `technique_or_generic()`: curated ids use their
dedicated command, out-of-catalogue ids fall back to a read-only `DEFAULT_COMMAND_KEY`
and the report is labelled generic. **A technique id is a label, never a command** —
the allow-list still governs what can run.

## Docs

- `docs/WALKTHROUGH.md` — 5-minute end-to-end lab reproduction (Sliver mTLS listener
  → podman sandbox → generate → deploy → `beacons` → cleanup).
- `README.md` — "🧠 The Role of Local AI in AdversarySim" (privacy-first, three roles)
  and the ASCII architecture diagram. Keep the test-count badge in sync when tests change.
