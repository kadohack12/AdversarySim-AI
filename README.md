# AdversarySim-AI

![Python 3.12 | 3.13](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue)
![Tests](https://img.shields.io/badge/tests-102%20passing-brightgreen)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Zero Telemetry](https://img.shields.io/badge/telemetry-zero-blueviolet)

> A lightweight, safety-first AI assistant for **purple teaming** and **adversary emulation** with
> [Sliver C2](https://github.com/BishopFox/sliver) and **local LLMs** via [Ollama](https://ollama.com).

AdversarySim-AI is an open-source project that helps defenders think like attackers — in a
controlled, auditable way. It pairs a native Sliver C2 connector with a locally hosted language
model so your operator notes, session data and target details never leave your machine.

**Nothing executes without explicit operator approval.** Every action passes through a
human-in-the-loop gate before it runs.

> 📖 **New here?** Follow the [5-minute lab walkthrough](docs/WALKTHROUGH.md) to reproduce a
> complete purple-teaming loop — listener, sandbox, implant, telemetry, cleanup — end to end.

---

## Architecture

```text
                        ┌──────────────────────────────────────────────┐
                        │                 Operator                     │
                        │        (human-in-the-loop, approves)         │
                        └───────────────────────┬──────────────────────┘
                                                │  CLI / interactive shell
                                                ▼
              ┌───────────────────────────────────────────────────────────┐
              │             AdversarySim-AI CLI  +  Local LLM             │
              │   ┌─────────────────────┐      ┌─────────────────────┐    │
              │   │  typer + rich CLI   │◄────►│  Ollama (local LLM) │    │
              │   │  /status /beacons   │      │  reason & propose   │    │
              │   └──────────┬──────────┘      └─────────────────────┘    │
              └──────────────┼────────────────────────────────────────────┘
                             │  every action is screened
                             ▼
              ┌───────────────────────────────────────────────────────────┐
              │                     Safety Gate (HITL)                    │
              │   read-only → allow   ·   state-changing → deny           │
              │   destructive → deny  ·   dry-run → print only            │
              └──────────────────────────┬────────────────────────────────┘
                                         │  approved actions only
                                         ▼
              ┌───────────────────────────────────────────────────────────┐
              │                    Sliver C2 Server                       │
              │            mTLS / HTTP(S) listeners · jobs                 │
              └──────────────────────────┬────────────────────────────────┘
                                         │  callback (loopback only)
                                         ▼
              ┌───────────────────────────────────────────────────────────┐
              │                    Sandbox Target                         │
              │        disposable container (podman/docker --rm)          │
              └───────────────────────────────────────────────────────────┘
```

The operator drives everything. The local LLM reasons and proposes, the Safety Gate
decides what may run, and Sliver executes only what the operator approved — against a
throwaway sandbox.

---

## Why

Purple teams need to reproduce real adversary behaviour to validate detection and response. That
work is powerful, so it needs guardrails. AdversarySim-AI is built around three principles:

1. **Operator control first.** Destructive actions default to *deny*; the operator must explicitly
   approve them. Read-only enumeration defaults to *allow*, but is still confirmed.
2. **Local by default.** The LLM runs on your own hardware through Ollama. No API keys, no
   telemetry, no data leaving your environment.
3. **Defensive research.** The goal is to improve detection and hardening, not to build a
   turnkey attack platform.

### Safety model

| Risk level      | Examples                        | Default on Enter |
| --------------- | ------------------------------- | ---------------- |
| `read-only`     | list sessions, beacons, jobs    | **allow** `[Y/n]` |
| `state-changing`| run a command, modify state     | **deny** `[y/N]`  |
| `destructive`   | generate / deploy an implant    | **deny** `[y/N]`  |

Two environment switches make automation and audits easier:

- `ADVERSARYSIM_DRY_RUN=true` — never execute; print exactly what *would* run.
- `ADVERSARYSIM_ASSUME_YES=true` — auto-approve (use only in a sandbox you fully control).

Interactive implant control (`interact`, `shell`, `execute`) is **deliberately out of scope**.
AdversarySim-AI enumerates and generates; it does not drive live implants.

---

## Features

- **Native Sliver C2 integration** — `sliver_status`, `sliver_list_sessions`,
  `sliver_list_beacons`, `sliver_list_jobs`, `sliver_generate_payload`.
- **Local LLM connector** — async client for Ollama's `/api/chat` (streaming and non-streaming),
  defaulting to `qwen2.5-coder:7b`.
- **LLM tool calling** — the local model can invoke the read-only Sliver tools
  (`sliver_status`, `sliver_list_sessions`, `sliver_list_beacons`, `sliver_list_jobs`)
  directly from the interactive shell, with every call routed through the Safety Gate.
- **Human-in-the-loop safety layer** — a single approval gate that every action goes through.
- **Modern terminal UI** — a `rich` banner, colourised tables for sessions and jobs, and an
  interactive shell with slash commands.
- **Graceful degradation** — if `sliver-client` is missing or the server is down, you get a clear,
  actionable message instead of a traceback.
- **Small dependency surface** — `httpx`, `pydantic`, `rich`, `typer`.

---

## 🧠 The Role of Local AI in AdversarySim

The language model is the reasoning layer of AdversarySim-AI — not an execution
engine. It runs entirely on your own hardware through
[Ollama](https://ollama.com) and is deliberately kept on a short leash.

### Privacy-First / Zero-Telemetry architecture

Offensive and purple-team work generates exactly the data you can never afford to
leak: target IP addresses, internal hostnames, usernames, listener ports, payload
paths, and the audit trail of what you emulated. Sending any of that to a
third-party API would hand an external provider a map of your environment and the
timeline of your exercise.

AdversarySim therefore talks **only** to a local Ollama instance
(`OLLAMA_HOST`, default `http://127.0.0.1:11434`). There are:

- **no API keys** and no provider SDKs,
- **no outbound calls** to any hosted model,
- **no telemetry** or usage reporting of any kind.

Your prompts, session data and detection notes stay on the machine. That is what
makes the tool usable in a regulated or air-gapped audit.

### Role #1 — Context assistant & purple teaming

The model is a context-aware teammate for the operator. Given the Sliver
telemetry AdversarySim surfaces (beacons, sessions, listeners), it can explain
what an action looks like on the wire and suggest matching detection logic —
**Sigma** rules, **auditd** policies, or **YARA** signatures — that correspond to
the Sliver behaviour just observed.

```bash
adversarysim ask "Suggest an auditd rule for an ELF beacon executing from /tmp."
```

It proposes; the detection engineer decides. This is the purple-team loop: emulate,
observe, and turn the observation into a detection.

### Role #2 — Conversational interface

Inside `adversarysim shell`, the model is a natural-language interface to the lab.
You can ask it to summarise the current state — "how many beacons are checking in,
and over which transport?" — and it reasons over the same data the CLI exposes.

Through **Ollama tool calling**, the model can go further than narrating: when a
question needs live data, it requests the matching read-only Sliver tool
(`sliver_status`, `sliver_list_sessions`, `sliver_list_beacons`, `sliver_list_jobs`)
by name. AdversarySim intercepts that request, runs it through the Safety Gate for
`[Y/n]` approval, executes the Sliver function, and feeds the real output back so
the model can answer precisely. Detection is robust: it accepts both the
structured `tool_calls` field and a tool invocation the model emits as raw JSON in
its text (e.g. `{"name": "sliver_list_beacons", "arguments": {}}`), so the call is
never merely echoed back:

```text
adversarysim> Sur quelle machine se trouve mon implant ?
→ model requested tool sliver_list_beacons
  Run Sliver tool 'sliver_list_beacons' requested by the local model
  command: sliver_list_beacons
  risk: read-only
Proceed? [Y/n] y
Ton implant tourne sur target-node (transport mtls).
```

It **coexists with the slash shortcuts** rather than replacing them: `/status`,
`/beacons`, `/jobs`, `/sessions` and `/help` remain deterministic, instant, and
model-independent, so you always have a reliable path when the model is slow or
unavailable.

```text
adversarysim> /beacons                 # deterministic Sliver query
adversarysim> où est mon implant ?     # LLM + tool calling, Safety-Gated
```

### Role #3 — Strict separation of execution (Safety Gate)

The model **reasons and proposes; it never executes.** Even when it uses tool
calling, it can only *request* a tool by name — AdversarySim intercepts the call
and routes it through the [Safety Gate](#safety-model) for explicit human
approval before the Sliver function runs. The model has no ability to run a
system command, generate a payload, or drive a C2 channel on its own, and it
cannot invoke anything outside the four read-only tools declared to it
(`sliver_generate_payload` is deliberately **not** exposed as a tool).

The LLM can describe *how* to generate an implant; only the operator's `y` at the
confirmation prompt lets AdversarySim actually build one. There is no path from
"the model said so" to "the system did it" that bypasses the operator
(**strict Human-in-the-Loop**).

---

## Requirements

- Python **3.11+**
- [`sliver-client`](https://github.com/BishopFox/sliver) on your `PATH` (only for Sliver features)
- [Ollama](https://ollama.com) running locally (only for LLM features)

---

## Installation

```bash
git clone https://github.com/kadohack12/AdversarySim-AI.git
cd AdversarySim-AI

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv venv && uv pip install -e ".[dev]"
```

### Set up the LLM (optional)

```bash
ollama serve
ollama pull qwen2.5-coder:7b
```

### Set up Sliver (optional)

Start a Sliver server, generate an operator config, and import it into the client:

```bash
sliver-server
sliver-client import operator.cfg
```

---

## Usage

> Prefer a guided tour? The [5-minute walkthrough](docs/WALKTHROUGH.md) runs the whole
> loop — listener, sandbox, implant, telemetry, cleanup — step by step.

```bash
adversarysim --help
```

### Check the Sliver connection

```bash
adversarysim status
```

### Enumerate sessions, beacons and listeners

```bash
adversarysim sessions
adversarysim beacons
adversarysim jobs
```

### Generate an implant (operator approval required)

```bash
adversarysim generate --os windows --lhost 10.0.0.1 --lport 8888
adversarysim generate --os linux --lhost 10.0.0.1 --lport 443 --format elf --beacon
```

Generated implants are written to `./implants` by default. Override with
`ADVERSARYSIM_WORKSPACE=/path/to/dir`.

### Ask the local model

```bash
adversarysim ask "Summarise the detection opportunities for an mTLS beacon over HTTPS."
```

### Interactive shell

```bash
adversarysim shell
```

Inside the shell:

| Command     | Action                              |
| ----------- | ----------------------------------- |
| `/status`   | check Sliver client and server      |
| `/sessions` | list active sessions                |
| `/beacons`  | list beacons                        |
| `/jobs`     | list listeners                      |
| `/help`     | show help                           |
| `/quit`     | exit                                |

---

## Configuration

| Variable                        | Default                  | Purpose                                      |
| ------------------------------- | ------------------------ | -------------------------------------------- |
| `ADVERSARYSIM_SLIVER_CLIENT`    | `sliver-client`          | Path or name of the Sliver client binary.    |
| `ADVERSARYSIM_WORKSPACE`        | `./implants`             | Where generated implants are written.        |
| `ADVERSARYSIM_MODEL`            | `qwen2.5-coder:7b`       | Ollama model to use.                         |
| `OLLAMA_HOST`                   | `http://127.0.0.1:11434` | Ollama server URL.                           |
| `ADVERSARYSIM_DRY_RUN`          | `false`                  | Print actions without executing them.        |
| `ADVERSARYSIM_ASSUME_YES`       | `false`                  | Auto-approve actions (sandbox use only).     |

---

## Project layout

```
src/adversary_sim/
├── __init__.py     # package metadata
├── cli.py          # rich + typer terminal interface
├── core.py         # async Ollama connector
├── safety.py       # human-in-the-loop approval gate
└── sliver.py       # standalone sliver-client wrapper
tests/
├── test_cli.py
├── test_core.py
├── test_safety.py
├── test_sliver.py
└── test_tool_calling.py  # LLM tool calling through the Safety Gate
docs/
└── WALKTHROUGH.md  # end-to-end purple-teaming lab guide
```

The Sliver wrapper in `src/adversary_sim/sliver.py` has **no dependency on the rest of the
project** beyond the standard library, so it can be reused or vendored on its own.

---

## Development

```bash
pytest                # run the test suite
ruff check .          # lint
ruff format .         # format
```

All Sliver and LLM calls in the test suite are mocked, so the tests run offline and require
neither a Sliver server nor Ollama.

---

## Legal and ethical use

AdversarySim-AI is intended **only** for authorised security testing, purple-team exercises,
detection engineering and education on systems you own or have explicit written permission to
test. Using it against systems without authorisation is illegal in most jurisdictions and is not
supported by this project. You are responsible for complying with all applicable laws and for
obtaining the necessary authorisation before you begin.

---

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2026 kadohack12.
