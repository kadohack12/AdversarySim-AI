"""Tests for the human-in-the-loop safety gate."""

from __future__ import annotations

import pytest

from adversary_sim import safety
from adversary_sim.safety import Action, RiskLevel, SafetyError


def _collector():
    lines: list[str] = []
    return lines, lines.append


def test_read_only_action_defaults_to_allow_on_empty_input():
    lines, output = _collector()
    action = Action("List sessions", risk=RiskLevel.READ_ONLY)
    assert safety.confirm(action, input_fn=lambda _p: "", output_fn=output) is True


def test_state_changing_action_defaults_to_deny_on_empty_input():
    lines, output = _collector()
    action = Action("Generate implant", risk=RiskLevel.STATE_CHANGING)
    assert safety.confirm(action, input_fn=lambda _p: "", output_fn=output) is False


def test_destructive_action_defaults_to_deny_on_empty_input():
    lines, output = _collector()
    action = Action("Deploy implant", risk=RiskLevel.DESTRUCTIVE)
    assert safety.confirm(action, input_fn=lambda _p: "", output_fn=output) is False


@pytest.mark.parametrize("answer", ["y", "Y", "yes", "YES", " yes "])
def test_explicit_yes_approves_destructive_action(answer):
    lines, output = _collector()
    action = Action("Deploy implant", risk=RiskLevel.DESTRUCTIVE)
    assert safety.confirm(action, input_fn=lambda _p: answer, output_fn=output) is True


@pytest.mark.parametrize("answer", ["n", "no", "nope"])
def test_explicit_no_refuses_read_only_action(answer):
    lines, output = _collector()
    action = Action("List sessions", risk=RiskLevel.READ_ONLY)
    assert safety.confirm(action, input_fn=lambda _p: answer, output_fn=output) is False


def test_prompt_uses_correct_default_suffix():
    prompts: list[str] = []

    def _input(prompt: str) -> str:
        prompts.append(prompt)
        return ""

    lines, output = _collector()
    safety.confirm(
        Action("List sessions", risk=RiskLevel.READ_ONLY),
        input_fn=_input,
        output_fn=output,
    )
    assert any("[Y/n]" in prompt for prompt in prompts)

    prompts.clear()
    lines, output = _collector()
    safety.confirm(
        Action("Generate", risk=RiskLevel.STATE_CHANGING),
        input_fn=_input,
        output_fn=output,
    )
    assert any("[y/N]" in prompt for prompt in prompts)


def test_dry_run_never_approves_and_reports():
    lines, output = _collector()
    action = Action("Generate implant", command="generate --os linux")
    result = safety.confirm(action, input_fn=lambda _p: "y", output_fn=output, dry_run=True)
    assert result is False
    assert any("dry-run" in line for line in lines)


def test_assume_yes_approves_everything():
    lines, output = _collector()
    action = Action("Deploy implant", risk=RiskLevel.DESTRUCTIVE)
    assert safety.confirm(action, output_fn=output, assume_yes=True) is True


def test_env_dry_run_is_honoured(monkeypatch):
    monkeypatch.setenv("ADVERSARYSIM_DRY_RUN", "true")
    lines, output = _collector()
    assert safety.confirm(Action("Generate"), output_fn=output) is False


def test_env_assume_yes_is_honoured(monkeypatch):
    monkeypatch.setenv("ADVERSARYSIM_ASSUME_YES", "1")
    lines, output = _collector()
    assert safety.confirm(Action("Generate"), output_fn=output) is True


def test_eof_refuses_destructive_action():
    def _eof(_prompt):
        raise EOFError

    lines, output = _collector()
    action = Action("Deploy implant", risk=RiskLevel.DESTRUCTIVE)
    with pytest.raises(SafetyError):
        safety.confirm(action, input_fn=_eof, output_fn=output)


def test_eof_allows_read_only_action():
    def _eof(_prompt):
        raise EOFError

    lines, output = _collector()
    action = Action("List sessions", risk=RiskLevel.READ_ONLY)
    assert safety.confirm(action, input_fn=_eof, output_fn=output) is True


def test_require_approval_raises_when_refused():
    lines, output = _collector()
    action = Action("Generate implant", risk=RiskLevel.STATE_CHANGING)
    with pytest.raises(SafetyError):
        safety.require_approval(action, input_fn=lambda _p: "n", output_fn=output)


def test_require_approval_passes_when_approved():
    lines, output = _collector()
    action = Action("Generate implant", risk=RiskLevel.STATE_CHANGING)
    safety.require_approval(action, input_fn=lambda _p: "y", output_fn=output)


def test_guard_runs_operation_when_approved():
    lines, output = _collector()
    action = Action("List sessions", risk=RiskLevel.READ_ONLY)
    result = safety.guard(action, lambda: "ok", input_fn=lambda _p: "y", output_fn=output)
    assert result == "ok"


def test_guard_does_not_run_operation_when_refused():
    called = []

    def _operation():
        called.append(True)
        return "ok"

    lines, output = _collector()
    action = Action("Generate implant", risk=RiskLevel.STATE_CHANGING)
    result = safety.guard(action, _operation, input_fn=lambda _p: "n", output_fn=output)
    assert called == []
    assert result.startswith("Cancelled:")


def test_screen_text_flags_metacharacters():
    reasons = safety.screen_text("10.0.0.1; rm -rf /")
    assert any("metacharacter" in reason for reason in reasons)


def test_screen_text_accepts_clean_input():
    assert safety.screen_text("10.0.0.1") == []


def test_screen_text_flags_forbidden_tokens():
    reasons = safety.screen_text("../../etc/passwd", forbidden=("..",))
    assert any("forbidden token" in reason for reason in reasons)
