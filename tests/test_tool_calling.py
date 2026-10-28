"""Tests for LLM tool calling routed through the Safety Gate.

These exercise the real :class:`~adversary_sim.core.OllamaClient` (via an httpx
mock transport) and the real ``cli._converse`` loop, so the full path is covered:
model requests a tool → Safety Gate approves/refuses → Sliver runs → result is
fed back → model synthesises a natural-language answer.
"""

from __future__ import annotations

import json

import httpx
import pytest

from adversary_sim import cli, sliver
from adversary_sim.core import (
    ChatMessage,
    ChatReply,
    OllamaClient,
    ToolCall,
    parse_tool_calls_from_text,
)
from adversary_sim.safety import RiskLevel


def _client(handler) -> OllamaClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://test")
    return OllamaClient(client=http, system_prompt=cli.SYSTEM_PROMPT)


def _tool_call_response(name: str, arguments: dict | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": name, "arguments": arguments or {}}}],
            },
            "done": True,
        },
    )


def _text_response(content: str) -> httpx.Response:
    return httpx.Response(200, json={"message": {"role": "assistant", "content": content}})


# ---------------------------------------------------------------------------
# core.py — schema + parsing
# ---------------------------------------------------------------------------


def test_tool_schemas_expose_expected_functions():
    from adversary_sim.core import TOOL_SCHEMAS

    names = {entry["function"]["name"] for entry in TOOL_SCHEMAS}
    assert names == {
        "sliver_status",
        "sliver_list_sessions",
        "sliver_list_beacons",
        "sliver_list_jobs",
        "sliver_run_discovery",
    }
    for entry in TOOL_SCHEMAS:
        assert entry["type"] == "function"
        assert entry["function"]["parameters"]["type"] == "object"


def test_default_system_prompt_is_security_engineer_persona():
    from adversary_sim.core import DEFAULT_SYSTEM_PROMPT

    assert "AdversarySim" in DEFAULT_SYSTEM_PROMPT
    assert "outils" in DEFAULT_SYSTEM_PROMPT
    assert cli.SYSTEM_PROMPT == DEFAULT_SYSTEM_PROMPT


@pytest.mark.asyncio
async def test_chat_with_tools_sends_schemas_and_parses_tool_calls():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return _tool_call_response("sliver_list_beacons")

    client = _client(handler)
    reply = await client.chat_with_tools("Sur quelle machine se trouve mon implant ?")
    assert reply.wants_tools is True
    assert reply.tool_calls == [ToolCall(name="sliver_list_beacons", arguments={})]
    # The tool schemas are actually transmitted to Ollama.
    assert {t["function"]["name"] for t in seen["body"]["tools"]} == set(cli.TOOL_NAMES)
    await client.aclose()


@pytest.mark.asyncio
async def test_chat_with_tools_parses_string_arguments():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {"function": {"name": "sliver_list_beacons", "arguments": '{"a": 1}'}}
                    ],
                }
            },
        )

    client = _client(handler)
    reply = await client.chat_with_tools("hi")
    assert reply.tool_calls[0].arguments == {"a": 1}
    await client.aclose()


@pytest.mark.asyncio
async def test_chat_with_tools_returns_plain_text_when_no_tools():
    def handler(_request: httpx.Request) -> httpx.Response:
        return _text_response("Aucun implant actif.")

    client = _client(handler)
    reply = await client.chat_with_tools("hi")
    assert reply.wants_tools is False
    assert reply.content == "Aucun implant actif."
    await client.aclose()


# ---------------------------------------------------------------------------
# cli.py — full conversation flow through the Safety Gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_question_triggers_beacon_lookup_and_precise_answer(monkeypatch):
    """The headline scenario: asking where the implant runs must call
    sliver_list_beacons through the Safety Gate, then answer with the hostname.
    """
    monkeypatch.setenv("ADVERSARYSIM_ASSUME_YES", "1")
    monkeypatch.delenv("ADVERSARYSIM_DRY_RUN", raising=False)

    called = {"beacons": 0}

    def _beacons() -> str:
        called["beacons"] += 1
        return "Sliver beacons (1):\n  - ID=abc, Transport=mtls, Hostname=target-node"

    monkeypatch.setattr(sliver, "sliver_list_beacons", _beacons)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls["n"] += 1
        if calls["n"] == 1:
            # First turn: model asks to run the beacon enumeration tool.
            return _tool_call_response("sliver_list_beacons")
        # Second turn: the tool result must be present in the history.
        tool_msgs = [m for m in body["messages"] if m["role"] == "tool"]
        assert tool_msgs and tool_msgs[-1]["tool_name"] == "sliver_list_beacons"
        assert "target-node" in tool_msgs[-1]["content"]
        return _text_response("Ton implant tourne sur target-node.")

    client = _client(handler)
    history: list[ChatMessage] = [ChatMessage("user", "Sur quelle machine se trouve mon implant ?")]
    await cli._converse(client, history)
    await client.aclose()

    # The Safety-Gated tool actually ran exactly once.
    assert called["beacons"] == 1
    # The conversation ends with the model's synthesised, precise answer.
    assert history[-1].role == "assistant"
    assert "target-node" in history[-1].content
    # The tool result was recorded for the audit trail.
    tool_turns = [m for m in history if m.role == "tool"]
    assert tool_turns and tool_turns[0].tool_name == "sliver_list_beacons"


@pytest.mark.asyncio
async def test_tool_call_respects_safety_gate_refusal(monkeypatch):
    """In dry-run the Safety Gate refuses, so Sliver must not run."""
    monkeypatch.setenv("ADVERSARYSIM_DRY_RUN", "true")
    monkeypatch.delenv("ADVERSARYSIM_ASSUME_YES", raising=False)

    called = {"beacons": 0}

    def _beacons() -> str:
        called["beacons"] += 1
        return "should not run"

    monkeypatch.setattr(sliver, "sliver_list_beacons", _beacons)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return _tool_call_response("sliver_list_beacons")
        body = json.loads(request.content)
        tool_msgs = [m for m in body["messages"] if m["role"] == "tool"]
        assert tool_msgs and "Cancelled:" in tool_msgs[-1]["content"]
        return _text_response("Je n'ai pas pu consulter les beacons.")

    client = _client(handler)
    history: list[ChatMessage] = [ChatMessage("user", "Où est mon implant ?")]
    await cli._converse(client, history)
    await client.aclose()

    assert called["beacons"] == 0


@pytest.mark.asyncio
async def test_unknown_tool_is_refused(monkeypatch):
    monkeypatch.setenv("ADVERSARYSIM_ASSUME_YES", "1")

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return _tool_call_response("sliver_delete_everything")
        body = json.loads(request.content)
        tool_msgs = [m for m in body["messages"] if m["role"] == "tool"]
        assert "not available" in tool_msgs[-1]["content"]
        return _text_response("Outil inconnu, je ne peux pas l'exécuter.")

    client = _client(handler)
    history: list[ChatMessage] = [ChatMessage("user", "efface tout")]
    await cli._converse(client, history)
    await client.aclose()

    assert history[-1].role == "assistant"


def test_resolve_tool_only_returns_read_only_functions():
    assert cli._resolve_tool("sliver_list_beacons") is sliver.sliver_list_beacons
    assert cli._resolve_tool("sliver_generate_payload") is None
    assert cli._resolve_tool("rm -rf /") is None


# ---------------------------------------------------------------------------
# Regression: model emits the tool call as raw JSON text (not message.tool_calls)
# ---------------------------------------------------------------------------


def test_parse_tool_calls_from_text_recovers_bare_json():
    calls = parse_tool_calls_from_text('{"name": "sliver_list_beacons", "arguments": {}}')
    assert calls == [ToolCall(name="sliver_list_beacons", arguments={})]


def test_parse_tool_calls_from_text_handles_common_shapes():
    assert parse_tool_calls_from_text('{"tool": "sliver_status"}') == [
        ToolCall(name="sliver_status", arguments={})
    ]
    nested = parse_tool_calls_from_text(
        '{"type": "function", "function": {"name": "sliver_list_jobs", "arguments": {}}}'
    )
    assert nested == [ToolCall(name="sliver_list_jobs", arguments={})]
    embedded = parse_tool_calls_from_text(
        'Je vais vérifier. {"name": "sliver_list_beacons", "arguments": {}} Un instant.'
    )
    assert embedded == [ToolCall(name="sliver_list_beacons", arguments={})]


def test_parse_tool_calls_from_text_ignores_plain_prose_and_data():
    assert parse_tool_calls_from_text("Aucun implant actif sur le lab.") == []
    assert parse_tool_calls_from_text('{"count": 3, "status": "ok"}') == []


@pytest.mark.asyncio
async def test_raw_json_text_tool_call_triggers_execution(monkeypatch):
    """The reported bug: the model returns the tool call as raw JSON text.

    Before the fix, ``_converse`` echoed the JSON back as text and never ran the
    tool. This proves the fallback detects it, runs it through the Safety Gate,
    and produces a final natural-language answer.
    """
    monkeypatch.setenv("ADVERSARYSIM_ASSUME_YES", "1")
    monkeypatch.delenv("ADVERSARYSIM_DRY_RUN", raising=False)

    called = {"beacons": 0}

    def _beacons() -> str:
        called["beacons"] += 1
        return "Sliver beacons (1):\n  - ID=abc, Transport=mtls, Hostname=target-node"

    monkeypatch.setattr(sliver, "sliver_list_beacons", _beacons)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls["n"] += 1
        if calls["n"] == 1:
            # Tool call delivered as plain text content, NOT in tool_calls.
            return _text_response('{"name": "sliver_list_beacons", "arguments": {}}')
        # Second turn must carry the real tool output back to the model.
        tool_msgs = [m for m in body["messages"] if m["role"] == "tool"]
        assert tool_msgs and tool_msgs[-1]["tool_name"] == "sliver_list_beacons"
        assert "target-node" in tool_msgs[-1]["content"]
        assert "Résultat de l'outil sliver_list_beacons" in tool_msgs[-1]["content"]
        return _text_response("Ton implant tourne sur target-node.")

    client = _client(handler)
    history: list[ChatMessage] = [ChatMessage("user", "Sur quelle machine se trouve mon implant ?")]
    await cli._converse(client, history)
    await client.aclose()

    # The tool actually ran (previously it never did).
    assert called["beacons"] == 1
    # The raw JSON was NOT echoed as the final answer.
    assert history[-1].role == "assistant"
    assert "target-node" in history[-1].content
    assert '{"name"' not in history[-1].content
    # A tool turn was recorded for the audit trail.
    tool_turns = [m for m in history if m.role == "tool"]
    assert tool_turns and tool_turns[0].tool_name == "sliver_list_beacons"


def test_detect_tool_calls_prefers_structured_field():
    structured = ChatReply(
        content="",
        tool_calls=[ToolCall(name="sliver_status", arguments={})],
    )
    assert cli._detect_tool_calls(structured) == [ToolCall(name="sliver_status", arguments={})]
    # Fallback path when the structured field is empty.
    as_text = ChatReply(content='{"name": "sliver_list_jobs"}')
    assert cli._detect_tool_calls(as_text) == [ToolCall(name="sliver_list_jobs", arguments={})]


def test_tool_result_message_format():
    msg = cli._tool_result_message(ToolCall(name="sliver_list_beacons"), "Sliver beacons (1):")
    assert "Résultat de l'outil sliver_list_beacons" in msg
    assert "Sliver beacons (1):" in msg
    assert "en français" in msg


# ---------------------------------------------------------------------------
# MITRE T1082 — System Information Discovery via the Safety Gate
# ---------------------------------------------------------------------------


def test_discovery_tool_is_exposed_and_state_changing():
    from adversary_sim.core import TOOL_SCHEMAS

    names = {e["function"]["name"] for e in TOOL_SCHEMAS}
    assert "sliver_run_discovery" in names
    assert cli.RISK_BY_TOOL["sliver_run_discovery"] is RiskLevel.STATE_CHANGING
    schema = next(e for e in TOOL_SCHEMAS if e["function"]["name"] == "sliver_run_discovery")
    params = schema["function"]["parameters"]
    assert params["required"] == ["session_id", "command"]
    assert params["properties"]["command"]["enum"] == [
        "whoami",
        "id",
        "uname -a",
        "hostname",
        "uptime",
    ]


@pytest.mark.asyncio
async def test_discovery_question_runs_whoami_through_safety_gate(monkeypatch):
    """The headline scenario: "Qui est l'utilisateur sur la session ?" must run
    whoami via the Safety Gate and return the model's analysed answer.
    """
    monkeypatch.setenv("ADVERSARYSIM_ASSUME_YES", "1")
    monkeypatch.delenv("ADVERSARYSIM_DRY_RUN", raising=False)

    captured = {}

    def _discovery(session_id, command):
        captured["session_id"] = session_id
        captured["command"] = command
        return "Ran on session ab12cd34: whoami\n\nTarget output:\nroot"

    monkeypatch.setattr(sliver, "sliver_run_discovery", _discovery)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls["n"] += 1
        if calls["n"] == 1:
            return _tool_call_response(
                "sliver_run_discovery",
                {"session_id": "ab12cd34", "command": "whoami"},
            )
        tool_msgs = [m for m in body["messages"] if m["role"] == "tool"]
        assert tool_msgs and tool_msgs[-1]["tool_name"] == "sliver_run_discovery"
        assert "root" in tool_msgs[-1]["content"]
        return _text_response("L'utilisateur de la session ab12cd34 est root.")

    client = _client(handler)
    history: list[ChatMessage] = [ChatMessage("user", "Qui est l'utilisateur sur la session ?")]
    await cli._converse(client, history)
    await client.aclose()

    # The allow-listed command ran with the model-supplied arguments.
    assert captured == {"session_id": "ab12cd34", "command": "whoami"}
    # The final answer is the model's natural-language analysis.
    assert history[-1].role == "assistant"
    assert "root" in history[-1].content
    # An audit turn was recorded.
    assert any(m.role == "tool" and m.tool_name == "sliver_run_discovery" for m in history)


@pytest.mark.asyncio
async def test_discovery_tool_respects_safety_gate_refusal(monkeypatch):
    """In dry-run the Safety Gate refuses, so nothing runs on the target."""
    monkeypatch.setenv("ADVERSARYSIM_DRY_RUN", "true")
    monkeypatch.delenv("ADVERSARYSIM_ASSUME_YES", raising=False)

    called = {"n": 0}

    def _discovery(session_id, command):
        called["n"] += 1
        return "should not run"

    monkeypatch.setattr(sliver, "sliver_run_discovery", _discovery)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return _tool_call_response(
                "sliver_run_discovery", {"session_id": "s1", "command": "id"}
            )
        body = json.loads(request.content)
        tool_msgs = [m for m in body["messages"] if m["role"] == "tool"]
        assert tool_msgs and "Cancelled:" in tool_msgs[-1]["content"]
        return _text_response("Je n'ai pas pu exécuter la commande.")

    client = _client(handler)
    history: list[ChatMessage] = [ChatMessage("user", "id de la session ?")]
    await cli._converse(client, history)
    await client.aclose()

    assert called["n"] == 0


@pytest.mark.asyncio
async def test_discovery_tool_missing_arguments_is_refused(monkeypatch):
    """A tool call without required arguments is refused, not executed."""
    monkeypatch.setenv("ADVERSARYSIM_ASSUME_YES", "1")

    called = {"n": 0}

    def _discovery(session_id, command):
        called["n"] += 1
        return "should not run"

    monkeypatch.setattr(sliver, "sliver_run_discovery", _discovery)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return _tool_call_response("sliver_run_discovery", {"session_id": "s1"})
        body = json.loads(request.content)
        tool_msgs = [m for m in body["messages"] if m["role"] == "tool"]
        assert tool_msgs and "missing argument" in tool_msgs[-1]["content"]
        return _text_response("Arguments manquants.")

    client = _client(handler)
    history: list[ChatMessage] = [ChatMessage("user", "lance whoami")]
    await cli._converse(client, history)
    await client.aclose()

    assert called["n"] == 0
