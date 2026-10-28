"""Allow-listed MITRE ATT&CK emulation catalogue.

This module is the single source of truth for the *safe* subset of MITRE
ATT&CK techniques AdversarySim-AI can emulate. Every technique maps to one
read-only command already present in :data:`adversary_sim.sliver.DISCOVERY_COMMANDS`,
so the catalogue can never widen the attack surface: if a command is not on the
Sliver allow-list, no technique can reach it.

Each entry carries:

* the technique **ID**, name and tactic (as published by MITRE ATT&CK);
* a short operator-facing **description**;
* the **Sliver command** used to emulate it (a discovery allow-list key);
* suggested **detections** (Sigma / auditd / YARA guidance) for the blue team.

Nothing here executes anything. The CLI resolves a technique, routes the command
through the human-in-the-loop Safety Gate, and only then runs it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .sliver import DISCOVERY_COMMANDS

__all__ = [
    "Technique",
    "TECHNIQUES",
    "get_technique",
    "list_techniques",
    "resolve_technique_command",
]


@dataclass(frozen=True)
class Technique:
    """A single allow-listed MITRE ATT&CK emulation technique."""

    id: str
    name: str
    tactic: str
    description: str
    command: str
    detections: tuple[str, ...] = field(default_factory=tuple)

    @property
    def risk(self) -> str:
        """Safety classification shown in the ``mitre list`` table."""
        return "state-changing"

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-friendly view of the technique."""
        return {
            "id": self.id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "command": self.command,
            "risk": self.risk,
            "detections": list(self.detections),
        }


# The catalogue. Commands reference :data:`DISCOVERY_COMMANDS` keys; the module
# import below asserts that invariant at import time.
TECHNIQUES: tuple[Technique, ...] = (
    Technique(
        id="T1082",
        name="System Information Discovery",
        tactic="Discovery",
        description=(
            "Identify the host's user, kernel, hostname and uptime to build a "
            "picture of the target before further action."
        ),
        command="uname",
        detections=(
            "auditd: watch execve of whoami/hostname/uname spawned by an implant "
            "parent (-a always,exit -F arch=b64 -S execve -k discovery).",
            "Sigma: process_creation where ParentImage is an implant path and "
            "Image endswith /whoami or /hostname or /uname.",
            "Correlate a burst of identity commands from a single process tree "
            "within a short window — normal admin shells rarely chain all of them.",
        ),
    ),
    Technique(
        id="T1083",
        name="File and Directory Discovery",
        tactic="Discovery",
        description=(
            "Enumerate the working directory, /tmp contents and read a decoy "
            "(canary) file to understand the filesystem layout."
        ),
        command="ls",
        detections=(
            "auditd: audit reads of sensitive directories and canary files "
            "(-w /tmp/canary_data.txt -p r -k canary_read).",
            "Sigma: file_access where the accessing process is an implant and "
            "the target path is under /tmp or a known sensitive directory.",
            "Honeytoken: alert immediately on any read of a canary file — no "
            "legitimate process should ever touch it.",
        ),
    ),
    Technique(
        id="T1057",
        name="Process Discovery",
        tactic="Discovery",
        description=(
            "List running processes to identify security tooling, other implants "
            "or high-value targets (databases, agents)."
        ),
        command="ps",
        detections=(
            "auditd: record execve of ps/top/htop with a non-shell parent "
            "(-a always,exit -F arch=b64 -S execve -k process_discovery).",
            "Sigma: process_creation of ps with ParentImage not in the known "
            "interactive shell set.",
            "Baseline the frequency of process listings per host; a sudden spike "
            "from an unexpected parent is a strong discovery signal.",
        ),
    ),
    Technique(
        id="T1016",
        name="System Network Configuration Discovery",
        tactic="Discovery",
        description=(
            "Read interface addresses and the routing table to map the network "
            "and plan lateral movement."
        ),
        command="ip",
        detections=(
            "auditd: watch execve of ip/route/ifconfig/ss/netstat "
            "(-a always,exit -F arch=b64 -S execve -k net_discovery).",
            "Sigma: process_creation of ip a / route -n from an implant parent process.",
            "Network flow: correlate host-side interface enumeration with "
            "subsequent outbound scanning from the same process.",
        ),
    ),
)

# Build the lookup table once, and fail fast if a technique points at a command
# that is not on the Sliver allow-list.
_BY_ID: dict[str, Technique] = {tech.id.upper(): tech for tech in TECHNIQUES}

for _tech in TECHNIQUES:
    if _tech.command not in DISCOVERY_COMMANDS:
        raise ValueError(
            f"Technique {_tech.id} references '{_tech.command}', which is not in "
            "the Sliver DISCOVERY_COMMANDS allow-list."
        )


def get_technique(technique_id: str) -> Technique | None:
    """Return the technique for *technique_id*, or ``None`` when unknown.

    Matching is case-insensitive and tolerates a leading ``attack.`` or ``t``
    prefix (``T1082``, ``t1082`` and ``attack.t1082`` all resolve).
    """
    key = str(technique_id).strip().upper()
    if key.startswith("ATTACK."):
        key = key.removeprefix("ATTACK.")
    return _BY_ID.get(key)


def list_techniques() -> tuple[Technique, ...]:
    """Return every allow-listed technique, ordered by ID."""
    return TECHNIQUES


def resolve_technique_command(technique_id: str) -> str | None:
    """Return the Sliver discovery command for *technique_id*, or ``None``."""
    tech = get_technique(technique_id)
    return DISCOVERY_COMMANDS[tech.command] if tech else None
