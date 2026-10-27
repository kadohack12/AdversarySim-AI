"""Async connector to a local Ollama server.

This is the only place the project talks to an LLM. It deliberately speaks the
plain Ollama HTTP API over ``httpx`` instead of pulling in a provider SDK, so
the dependency surface stays small and everything runs locally by default.

Typical use::

    client = OllamaClient()
    reply = await client.chat("Summarise these Sliver sessions.")
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass, field
from typing import Any

import httpx

__all__ = ["ChatMessage", "OllamaClient", "OllamaError"]

DEFAULT_HOST = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen2.5-coder:7b"


class OllamaError(RuntimeError):
    """Raised when Ollama cannot be reached or returns an error."""


@dataclass
class ChatMessage:
    """A single chat turn."""

    role: str
    content: str

    def as_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass
class OllamaClient:
    """Minimal async client for the Ollama ``/api/chat`` endpoint.

    Args:
        host: Base URL of the Ollama server. Defaults to the
            ``OLLAMA_HOST`` environment variable or ``http://127.0.0.1:11434``.
        model: Model name. Defaults to the ``ADVERSARYSIM_MODEL`` environment
            variable or ``qwen2.5-coder:7b``.
        timeout: Request timeout in seconds.
        system_prompt: Optional system prompt prepended to every conversation.
        client: Optional pre-built ``httpx.AsyncClient`` (injectable for tests).
    """

    host: str = ""
    model: str = ""
    timeout: float = 120.0
    system_prompt: str = ""
    client: httpx.AsyncClient | None = None
    _owned_client: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        self.host = (self.host or os.getenv("OLLAMA_HOST") or DEFAULT_HOST).rstrip("/")
        self.model = self.model or os.getenv("ADVERSARYSIM_MODEL") or DEFAULT_MODEL
        if self.client is None:
            self.client = httpx.AsyncClient(base_url=self.host, timeout=self.timeout)
            self._owned_client = True

    # -- lifecycle ---------------------------------------------------------

    async def aclose(self) -> None:
        """Close the underlying HTTP client if we created it."""
        if self.client is not None and self._owned_client:
            await self.client.aclose()

    async def __aenter__(self) -> OllamaClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    # -- helpers -----------------------------------------------------------

    def _build_messages(
        self, prompt: str, history: Iterable[ChatMessage] = ()
    ) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = []
        if self.system_prompt:
            messages.append(ChatMessage("system", self.system_prompt).as_dict())
        messages.extend(msg.as_dict() for msg in history)
        messages.append(ChatMessage("user", prompt).as_dict())
        return messages

    def _payload(self, messages: list[dict[str, str]], stream: bool) -> dict[str, Any]:
        return {"model": self.model, "messages": messages, "stream": stream}

    @staticmethod
    def _extract_content(data: dict[str, Any]) -> str:
        message = data.get("message") or {}
        return str(message.get("content", ""))

    # -- public API --------------------------------------------------------

    async def list_models(self) -> list[str]:
        """Return the names of models available on the server."""
        assert self.client is not None
        try:
            response = await self.client.get("/api/tags")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise OllamaError(f"Could not reach Ollama at {self.host}: {exc}") from exc
        models = response.json().get("models", [])
        return [m.get("name", "") for m in models if m.get("name")]

    async def is_available(self) -> bool:
        """Return True when the server responds to a lightweight request."""
        try:
            await self.list_models()
            return True
        except OllamaError:
            return False

    async def chat(self, prompt: str, history: Iterable[ChatMessage] = ()) -> str:
        """Send *prompt* and return the model's full reply."""
        assert self.client is not None
        messages = self._build_messages(prompt, history)
        try:
            response = await self.client.post(
                "/api/chat", json=self._payload(messages, stream=False)
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise OllamaError(f"Ollama chat request failed: {exc}") from exc

        content = self._extract_content(response.json())
        if not content:
            raise OllamaError("Ollama returned an empty response.")
        return content

    async def stream_chat(
        self, prompt: str, history: Iterable[ChatMessage] = ()
    ) -> AsyncIterator[str]:
        """Yield the model's reply incrementally as it is generated."""
        assert self.client is not None
        messages = self._build_messages(prompt, history)
        try:
            async with self.client.stream(
                "POST", "/api/chat", json=self._payload(messages, stream=True)
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    piece = self._extract_content(chunk)
                    if piece:
                        yield piece
                    if chunk.get("done"):
                        break
        except httpx.HTTPError as exc:
            raise OllamaError(f"Ollama streaming request failed: {exc}") from exc
