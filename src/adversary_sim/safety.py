"""Human-in-the-Loop (HITL) safety layer.

Every action that touches a target — running a Sliver command, generating an
implant, or letting the LLM propose a step — must pass through this module
before it executes. Nothing runs without an explicit operator decision.

The gate is deliberately conservative:

* Destructive or high-impact actions default to **deny** (the prompt shows
  ``[y/N]`` and pressing Enter refuses).
* Read-only enumeration actions default to **allow** (``[Y/n]``).
* A ``dry-run`` mode approves nothing automatically but prints exactly what
  *would* run, which is useful for audits and CI.
"""

from __future__ import annotations

import enum
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field


class RiskLevel(enum.StrEnum):
    """How much damage an action could cause if it went wrong."""

    READ_ONLY = "read-only"
    STATE_CHANGING = "state-changing"
    DESTRUCTIVE = "destructive"


@dataclass(frozen=True)
class Action:
    """A single operation awaiting operator approval."""

    summary: str
    command: str = ""
    risk: RiskLevel = RiskLevel.STATE_CHANGING
    details: tuple[str, ...] = field(default_factory=tuple)

    @property
    def default_allow(self) -> bool:
        """Whether pressing Enter should approve this action.

        Only read-only actions are approved by default; anything that changes
        state or could be destructive requires a deliberate ``y``.
        """
        return self.risk is RiskLevel.READ_ONLY


class SafetyError(RuntimeError):
    """Raised when an action is refused or cannot be confirmed."""


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _format_action(action: Action) -> str:
    """Render an action for display in a confirmation prompt."""
    lines = [action.summary]
    if action.command:
        lines.append(f"  command: {action.command}")
    lines.extend(f"  {detail}" for detail in action.details)
    lines.append(f"  risk: {action.risk.value}")
    return "\n".join(lines)


def confirm(
    action: Action,
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    assume_yes: bool | None = None,
    dry_run: bool | None = None,
) -> bool:
    """Ask the operator to approve *action*.

    Args:
        action: The operation to approve.
        input_fn: Callable used to read the operator's answer (injectable for
            tests).
        output_fn: Callable used to display the prompt (injectable for tests).
        assume_yes: Skip the prompt and approve everything. Defaults to the
            ``ADVERSARYSIM_ASSUME_YES`` environment variable.
        dry_run: Never execute; report what would run and refuse. Defaults to
            the ``ADVERSARYSIM_DRY_RUN`` environment variable.

    Returns:
        bool: True when the operator approved, False otherwise.

    Raises:
        SafetyError: If the action is destructive and no interactive prompt is
            available (e.g. stdin is not a TTY) and ``assume_yes`` is not set.
    """
    if assume_yes is None:
        assume_yes = _env_flag("ADVERSARYSIM_ASSUME_YES")
    if dry_run is None:
        dry_run = _env_flag("ADVERSARYSIM_DRY_RUN")

    if dry_run:
        output_fn(f"[dry-run] would run:\n{_format_action(action)}")
        return False

    if assume_yes:
        output_fn(f"[assume-yes] {action.summary}")
        return True

    suffix = "[Y/n]" if action.default_allow else "[y/N]"
    output_fn("")
    output_fn(_format_action(action))
    try:
        answer = input_fn(f"Proceed? {suffix} ").strip().lower()
    except EOFError as exc:
        if action.default_allow:
            return True
        raise SafetyError(
            f"Refusing {action.risk.value} action with no interactive input: {action.summary}"
        ) from exc

    if not answer:
        return action.default_allow
    return answer in {"y", "yes"}


def require_approval(
    action: Action,
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    assume_yes: bool | None = None,
    dry_run: bool | None = None,
) -> None:
    """Confirm *action* and raise :class:`SafetyError` when refused.

    Use this as the hard gate in front of any real operation.
    """
    if not confirm(
        action,
        input_fn=input_fn,
        output_fn=output_fn,
        assume_yes=assume_yes,
        dry_run=dry_run,
    ):
        raise SafetyError(f"Operator refused action: {action.summary}")


def guard(
    action: Action,
    operation: Callable[[], str],
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    assume_yes: bool | None = None,
    dry_run: bool | None = None,
) -> str:
    """Confirm *action*, then run *operation* and return its result.

    When the operator refuses, returns a short "cancelled" message instead of
    raising so callers in an interactive loop can keep going.
    """
    if not confirm(
        action,
        input_fn=input_fn,
        output_fn=output_fn,
        assume_yes=assume_yes,
        dry_run=dry_run,
    ):
        return f"Cancelled: {action.summary}"
    return operation()


def screen_text(text: str, forbidden: Iterable[str] = ()) -> list[str]:
    """Return reasons *text* looks unsafe to send to an execution backend.

    This is a lightweight sanity check, not a sandbox. It flags obvious
    attempts to chain shell metacharacters into a generated command.
    """
    reasons: list[str] = []
    lowered = (text or "").lower()
    for token in forbidden:
        if token.lower() in lowered:
            reasons.append(f"contains forbidden token: {token}")
    for meta in (";", "&&", "||", "`", "$(", "\n"):
        if meta in (text or ""):
            reasons.append(f"contains shell metacharacter: {meta!r}")
    return reasons
