"""Tests for the Ollama connector.

Uses httpx's mock transport so no real Ollama server is required.
"""

from __future__ import annotations

import json

import httpx
import pytest

from adversary_sim.core import ChatMessage, OllamaClient, OllamaError


def _client(handler, **kwargs) -> OllamaClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://test")
    return OllamaClient(client=http, **kwargs)


def test_defaults_from_environment(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama.local:11434/")
    monkeypatch.setenv("ADVERSARYSIM_MODEL", "llama3:8b")
    client = OllamaClient()
    assert client.host == "http://ollama.local:11434"
    assert client.model == "llama3:8b"


def test_environment_defaults_when_unset(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("ADVERSARYSIM_MODEL", raising=False)
    client = OllamaClient()
    assert client.host == "http://127.0.0.1:11434"
    assert client.model == "qwen2.5-coder:7b"


@pytest.mark.asyncio
async def test_list_models_parses_tags():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/tags"
        return httpx.Response(200, json={"models": [{"name": "a"}, {"name": "b"}]})

    client = _client(handler)
    assert await client.list_models() == ["a", "b"]
    await client.aclose()


@pytest.mark.asyncio
async def test_list_models_raises_on_http_error():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    client = _client(handler)
    with pytest.raises(OllamaError):
        await client.list_models()
    await client.aclose()


@pytest.mark.asyncio
async def test_is_available_true_when_reachable():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"models": []})

    client = _client(handler)
    assert await client.is_available() is True
    await client.aclose()


@pytest.mark.asyncio
async def test_is_available_false_on_error():
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = _client(handler)
    assert await client.is_available() is False
    await client.aclose()


@pytest.mark.asyncio
async def test_chat_returns_content_and_sends_system_prompt():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"message": {"role": "assistant", "content": "hi"}})

    client = _client(handler, system_prompt="be safe", model="m")
    reply = await client.chat("hello")
    assert reply == "hi"
    assert seen["body"]["model"] == "m"
    assert seen["body"]["stream"] is False
    assert seen["body"]["messages"][0] == {"role": "system", "content": "be safe"}
    assert seen["body"]["messages"][-1] == {"role": "user", "content": "hello"}
    await client.aclose()


@pytest.mark.asyncio
async def test_chat_includes_history():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"message": {"content": "ok"}})

    client = _client(handler)
    history = [ChatMessage("user", "previous"), ChatMessage("assistant", "reply")]
    await client.chat("next", history=history)
    roles = [m["role"] for m in seen["body"]["messages"]]
    assert roles == ["user", "assistant", "user"]
    await client.aclose()


@pytest.mark.asyncio
async def test_chat_raises_on_empty_response():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {"content": ""}})

    client = _client(handler)
    with pytest.raises(OllamaError):
        await client.chat("hello")
    await client.aclose()


@pytest.mark.asyncio
async def test_chat_raises_on_transport_error():
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = _client(handler)
    with pytest.raises(OllamaError):
        await client.chat("hello")
    await client.aclose()


@pytest.mark.asyncio
async def test_stream_chat_yields_chunks():
    lines = [
        json.dumps({"message": {"content": "Hel"}, "done": False}),
        json.dumps({"message": {"content": "lo"}, "done": False}),
        json.dumps({"message": {"content": ""}, "done": True}),
    ]
    body = "\n".join(lines) + "\n"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body)

    client = _client(handler)
    chunks = [chunk async for chunk in client.stream_chat("hi")]
    assert chunks == ["Hel", "lo"]
    await client.aclose()


@pytest.mark.asyncio
async def test_stream_chat_ignores_malformed_lines():
    body = "not json\n" + json.dumps({"message": {"content": "ok"}, "done": True}) + "\n"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body)

    client = _client(handler)
    chunks = [chunk async for chunk in client.stream_chat("hi")]
    assert chunks == ["ok"]
    await client.aclose()
