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
import re
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass, field
from typing import Any

import httpx

__all__ = [
    "ChatMessage",
    "ChatReply",
    "OllamaClient",
    "OllamaError",
    "ToolCall",
    "DEFAULT_SYSTEM_PROMPT",
    "TOOL_SCHEMAS",
    "parse_tool_calls_from_text",
]

DEFAULT_HOST = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen2.5-coder:7b"

# Strict security-engineer persona. Kept in French to match the operator's lab
# language; it tells the model to be terse and to *use its tools* whenever the
# operator asks about lab/machine/implant state.
DEFAULT_SYSTEM_PROMPT = (
    "Tu es AdversarySim, un assistant d'ingénierie et de Purple Teaming pour "
    "Sliver C2. Sois technique, direct et concis. Ne fais pas de morale ni de "
    "rappels légaux, nous sommes dans un laboratoire contrôlé. Lorsque "
    "l'opérateur te pose une question sur l'état du lab, des machines ou des "
    "implants, appelle les outils mis à ta disposition."
)

# Tool declarations handed to Ollama. Each entry maps to a read-only function in
# :mod:`adversary_sim.sliver`; the CLI still routes every invocation through the
# Safety Gate before anything runs.
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "sliver_status",
            "description": (
                "Vérifie que le client Sliver est installé et que le serveur/daemon "
                "Sliver est joignable."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sliver_list_sessions",
            "description": "Liste les sessions Sliver interactives actives (implants temps réel).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sliver_list_beacons",
            "description": (
                "Liste les beacons Sliver enregistrés (implants asynchrones qui "
                "rappellent à intervalle régulier). À utiliser pour savoir sur "
                "quelle machine tourne un implant."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sliver_list_jobs",
            "description": "Liste les listeners Sliver actifs (jobs) : mTLS, HTTP, DNS, etc.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sliver_run_discovery",
            "description": (
                "Exécute une commande de découverte en LECTURE SEULE sur une session "
                "Sliver. Couvre la découverte système (MITRE T1082 : utilisateur, OS, "
                "uptime), la découverte de fichiers/répertoires (MITRE T1083 : "
                "répertoire courant, contenu de /tmp, lecture d'un leurre canary), "
                "la découverte de processus (MITRE T1057 : ps aux) et la découverte "
                "réseau (MITRE T1016 : ip a / route -n). Nécessite l'approbation de "
                "l'opérateur."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": (
                            "Identifiant de la session Sliver cible (id, nom ou index)."
                        ),
                    },
                    "command": {
                        "type": "string",
                        "description": (
                            "Commande de découverte autorisée. Pour lire un leurre "
                            "précis, utilisez la forme 'cat /tmp/canary_<nom>.txt'."
                        ),
                        "enum": [
                            "whoami",
                            "id",
                            "uname -a",
                            "hostname",
                            "uptime",
                            "pwd",
                            "ls -la",
                            "cat /tmp/canary_data.txt",
                            "ps aux",
                            "ip a",
                            "route -n",
                        ],
                    },
                },
                "required": ["session_id", "command"],
            },
        },
    },
]


class OllamaError(RuntimeError):
    """Raised when Ollama cannot be reached or returns an error."""


@dataclass
class ChatMessage:
    """A single chat turn.

    Beyond the plain ``role``/``content`` pair, a message may carry ``tool_calls``
    (an assistant turn requesting tools) or ``tool_name`` (a ``tool`` turn
    reporting a tool's result), matching Ollama's message schema.
    """

    role: str
    content: str
    tool_calls: list[dict[str, Any]] | None = None
    tool_name: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_calls is not None:
            payload["tool_calls"] = self.tool_calls
        if self.tool_name is not None:
            payload["tool_name"] = self.tool_name
        return payload


@dataclass
class ToolCall:
    """A tool invocation requested by the model."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Serialise back into Ollama's ``tool_calls`` entry shape."""
        return {"function": {"name": self.name, "arguments": self.arguments}}


@dataclass
class ChatReply:
    """A model reply: either final text, or one or more requested tool calls."""

    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)

    @property
    def wants_tools(self) -> bool:
        """True when the model asked to invoke at least one tool."""
        return bool(self.tool_calls)


# Matches a JSON object literal in free text; used to recover tool calls that a
# model emits as raw content instead of the structured ``tool_calls`` field.
_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)

# Keys a model might use to name the tool it wants to call.
_TOOL_NAME_KEYS = ("name", "tool", "tool_name", "function", "action")


def _coerce_tool_call(obj: Any) -> ToolCall | None:
    """Best-effort conversion of a parsed JSON object into a :class:`ToolCall`.

    Accepts the common shapes models emit, e.g.::

        {"name": "sliver_list_beacons", "arguments": {}}
        {"tool": "sliver_list_beacons"}
        {"function": {"name": "sliver_list_beacons", "arguments": {...}}}
        {"type": "function", "function": {"name": "..."}}

    Returns None when no usable tool name is found.
    """
    if not isinstance(obj, dict):
        return None

    # Nested {"function": {"name": ...}} shape.
    function = obj.get("function")
    if isinstance(function, dict):
        nested = _coerce_tool_call(function)
        if nested is not None:
            return nested
        return None

    name = ""
    for key in _TOOL_NAME_KEYS:
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            name = value.strip()
            break
    if not name:
        return None

    arguments = obj.get("arguments") or obj.get("parameters") or obj.get("args") or {}
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError:
            arguments = {}
    if not isinstance(arguments, dict):
        arguments = {}
    return ToolCall(name=name, arguments=arguments)


def parse_tool_calls_from_text(text: str) -> list[ToolCall]:
    """Extract tool calls from free-form model text.

    Some models — especially smaller local ones — emit a tool invocation as raw
    JSON in the message ``content`` (e.g. ``{"name": "sliver_list_beacons",
    "arguments": {}}``) instead of populating the structured ``tool_calls``
    field. This recovers those calls so the CLI can still route them through the
    Safety Gate.

    Only objects that carry a recognised tool-name key are returned; ordinary
    prose or unrelated JSON is ignored.

    Args:
        text: The model's raw content string.

    Returns:
        list[ToolCall]: Zero or more tool calls found in the text.
    """
    if not text or "{" not in text:
        return []

    calls: list[ToolCall] = []

    # Prefer a whole-string parse (handles clean, well-formed JSON).
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if parsed is not None:
            call = _coerce_tool_call(parsed)
            if call is not None:
                return [call]

    # Fall back to scanning for embedded JSON objects.
    for match in _JSON_OBJECT_RE.finditer(text):
        candidate = match.group(0).strip()
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        call = _coerce_tool_call(parsed)
        if call is not None:
            calls.append(call)
    return calls


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
        self,
        prompt: str | None,
        history: Iterable[ChatMessage] = (),
        system_prompt: str | None = None,
    ) -> list[dict[str, Any]]:
        messages: list[dict[str, Any]] = []
        effective_system = self.system_prompt if system_prompt is None else system_prompt
        if effective_system:
            messages.append(ChatMessage("system", effective_system).as_dict())
        messages.extend(msg.as_dict() for msg in history)
        if prompt is not None:
            messages.append(ChatMessage("user", prompt).as_dict())
        return messages

    def _payload(
        self,
        messages: list[dict[str, Any]],
        stream: bool,
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"model": self.model, "messages": messages, "stream": stream}
        if tools:
            payload["tools"] = tools
        return payload

    @staticmethod
    def _extract_content(data: dict[str, Any]) -> str:
        message = data.get("message") or {}
        return str(message.get("content", ""))

    @staticmethod
    def _build_reply(data: dict[str, Any]) -> ChatReply:
        """Build a :class:`ChatReply`, recovering text-embedded tool calls.

        Prefers the structured ``tool_calls`` field; when the model instead
        emits a tool call as raw JSON in ``content`` (a common quirk of smaller
        local models), the call is recovered from the text so the CLI still
        routes it through the Safety Gate.
        """
        content = OllamaClient._extract_content(data)
        tool_calls = OllamaClient._extract_tool_calls(data)
        if not tool_calls:
            tool_calls = parse_tool_calls_from_text(content)
        return ChatReply(content=content, tool_calls=tool_calls)

    @staticmethod
    def _extract_tool_calls(data: dict[str, Any]) -> list[ToolCall]:
        """Parse ``message.tool_calls`` from an Ollama chat response."""
        message = data.get("message") or {}
        raw_calls = message.get("tool_calls") or []
        calls: list[ToolCall] = []
        for entry in raw_calls:
            function = entry.get("function") or {}
            name = str(function.get("name", "")).strip()
            if not name:
                continue
            arguments = function.get("arguments") or {}
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {}
            if not isinstance(arguments, dict):
                arguments = {}
            calls.append(ToolCall(name=name, arguments=arguments))
        return calls

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

    async def chat_with_tools(
        self,
        prompt: str,
        history: Iterable[ChatMessage] = (),
        tools: list[dict[str, Any]] | None = None,
    ) -> ChatReply:
        """Send *prompt* and return either final text or requested tool calls.

        Unlike :meth:`chat`, this does not raise on an empty ``content``: a
        tool-calling turn legitimately returns empty content alongside a
        ``tool_calls`` list.

        Args:
            prompt: The operator's message.
            history: Prior turns, including assistant ``tool_calls`` turns and
                ``tool`` result turns.
            tools: JSON tool declarations to offer the model. Defaults to
                :data:`TOOL_SCHEMAS`.

        Returns:
            ChatReply: Final content and/or the tool calls the model requested.
        """
        assert self.client is not None
        messages = self._build_messages(prompt, history)
        payload = self._payload(messages, stream=False, tools=tools or TOOL_SCHEMAS)
        try:
            response = await self.client.post("/api/chat", json=payload)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise OllamaError(f"Ollama chat request failed: {exc}") from exc

        return self._build_reply(response.json())

    async def continue_chat(
        self,
        history: Iterable[ChatMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> ChatReply:
        """Send *history* with no new user turn and return the next reply.

        Used after tool execution to let the model synthesise a natural-language
        answer from the tool results, optionally requesting further tools.
        """
        assert self.client is not None
        messages = self._build_messages(None, history)
        payload = self._payload(messages, stream=False, tools=tools or TOOL_SCHEMAS)
        try:
            response = await self.client.post("/api/chat", json=payload)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise OllamaError(f"Ollama chat request failed: {exc}") from exc

        return self._build_reply(response.json())

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
