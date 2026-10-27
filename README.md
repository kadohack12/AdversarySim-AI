# AdversarySim-AI

> A lightweight, safety-first AI assistant for **purple teaming** and **adversary emulation** with
> [Sliver C2](https://github.com/BishopFox/sliver) and **local LLMs** via [Ollama](https://ollama.com).

AdversarySim-AI is an open-source project that helps defenders think like attackers — in a
controlled, auditable way. It pairs a native Sliver C2 connector with a locally hosted language
model so your operator notes, session data and target details never leave your machine.

**Nothing executes without explicit operator approval.** Every action passes through a
human-in-the-loop gate before it runs.

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
- **Human-in-the-loop safety layer** — a single approval gate that every action goes through.
- **Modern terminal UI** — a `rich` banner, colourised tables for sessions and jobs, and an
  interactive shell with slash commands.
- **Graceful degradation** — if `sliver-client` is missing or the server is down, you get a clear,
  actionable message instead of a traceback.
- **Small dependency surface** — `httpx`, `pydantic`, `rich`, `typer`.

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
└── test_sliver.py
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
