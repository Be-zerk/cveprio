"""Model providers. Each returns raw text; validation happens in ``validate.py``.

* ``none``              — no model; reports say the AI assessment was not run.
* ``ollama``            — local Ollama via its native API (sets the context window per
                          request and refuses prompts that would not fit).
* ``openai_compatible`` — any ``/v1/chat/completions`` server (Ollama, OpenAI,
                          vLLM, LM Studio...). Configured by the operator, not by
                          retrieved content, so the base URL may be localhost.
* ``anthropic``         — Claude via the official ``anthropic`` SDK with
                          structured outputs (``output_config.format``).
* ``scripted``          — offline demo only: hand-written example outputs from
                          ``fixtures/demo/scripted_llm``. Always labelled as
                          scripted, never presented as model output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

from cveprio.config import Settings


class ProviderError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind  # not_configured | auth | rate_limited | network | refused | bad_response | unavailable


@dataclass
class ProviderResponse:
    text: str
    model: str
    scripted: bool = False


class Provider(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str | None: ...

    def complete(self, cve_id: str, system: str, user: str, schema: dict[str, Any]) -> ProviderResponse: ...


class NoProvider:
    name, model = "none", None

    def complete(self, cve_id: str, system: str, user: str, schema: dict[str, Any]) -> ProviderResponse:
        raise ProviderError("not_configured", "No model provider configured (CVEPRIO_LLM_PROVIDER=none).")


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(self, base_url: str, model: str, api_key: str | None, timeout_s: float = 300.0,
                 transport: httpx.BaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.client = httpx.Client(timeout=timeout_s, headers=headers, transport=transport)

    def _post(self, body: dict[str, Any]) -> httpx.Response:
        try:
            return self.client.post(f"{self.base_url}/chat/completions", json=body)
        except httpx.TimeoutException as exc:
            raise ProviderError("network", f"model request timed out: {exc}") from exc
        except httpx.TransportError as exc:
            raise ProviderError("unavailable", f"cannot reach model server at {self.base_url}: {exc}") from exc

    def complete(self, cve_id: str, system: str, user: str, schema: dict[str, Any]) -> ProviderResponse:
        base = {"model": self.model, "temperature": 0,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        resp = self._post({**base, "response_format": {"type": "json_schema", "json_schema": {
            "name": "cve_assessment", "schema": schema, "strict": True}}})
        if resp.status_code == 400:  # server may not support json_schema; fall back to JSON mode
            resp = self._post({**base, "response_format": {"type": "json_object"}})
        if resp.status_code in (401, 403):
            raise ProviderError("auth", f"model server rejected credentials (HTTP {resp.status_code})")
        if resp.status_code == 429:
            raise ProviderError("rate_limited", "model server rate limit (HTTP 429)")
        if resp.status_code >= 400:
            raise ProviderError("bad_response", f"model server error HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            data = resp.json()
            text = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError("bad_response", f"unexpected chat-completions response shape: {exc}") from exc
        return ProviderResponse(text=text or "", model=str(data.get("model") or self.model))


def estimate_tokens(*texts: str) -> int:
    """Deliberately pessimistic (JSON tokenises worse than prose): ~3 characters per token."""
    return sum(len(t) for t in texts) // 3 + 1


class OllamaProvider:
    """Ollama's native /api/chat. Unlike its OpenAI-compatible endpoint, it lets us set the context
    window per request; otherwise Ollama silently truncates long prompts from the start (observed
    during development: a 5.7k-token prompt cut to 2k, dropping the system prompt)."""

    name = "ollama"

    def __init__(self, base_url: str, model: str, num_ctx_max: int = 16384, timeout_s: float = 600.0,
                 transport: httpx.BaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.num_ctx_max = num_ctx_max
        self.client = httpx.Client(timeout=timeout_s, transport=transport)

    def complete(self, cve_id: str, system: str, user: str, schema: dict[str, Any]) -> ProviderResponse:
        needed = estimate_tokens(system, user) + 2048  # room for the answer
        if needed > self.num_ctx_max:
            raise ProviderError("prompt_too_large", f"prompt needs ~{needed} tokens of context; limit is "
                                f"{self.num_ctx_max} (CVEPRIO_LLM_NUM_CTX_MAX). Refusing rather than truncating.")
        num_ctx = min(self.num_ctx_max, max(4096, 1 << (needed - 1).bit_length()))
        body = {"model": self.model, "stream": False, "format": schema,
                "options": {"temperature": 0, "num_ctx": num_ctx},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        try:
            resp = self.client.post(f"{self.base_url}/api/chat", json=body)
        except httpx.TimeoutException as exc:
            raise ProviderError("network", f"Ollama request timed out: {exc}") from exc
        except httpx.TransportError as exc:
            raise ProviderError("unavailable", f"cannot reach Ollama at {self.base_url}: {exc}") from exc
        if resp.status_code == 404:
            raise ProviderError("not_configured", f"model {self.model!r} not found; run: ollama pull {self.model}")
        if resp.status_code >= 400:
            raise ProviderError("bad_response", f"Ollama error HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            data = resp.json()
            text = data["message"]["content"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ProviderError("bad_response", f"unexpected Ollama response shape: {exc}") from exc
        if data.get("done_reason") == "length":
            raise ProviderError("bad_response", "model output was cut off (length limit)")
        used = data.get("prompt_eval_count")
        if isinstance(used, int) and used >= num_ctx - 8:
            raise ProviderError("bad_response", f"prompt filled the whole context ({used}/{num_ctx} tokens); "
                                "it may have been truncated")
        return ProviderResponse(text=text or "", model=str(data.get("model") or self.model))


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str | None, model: str, fallbacks: bool = True):
        if not api_key:
            raise ProviderError("not_configured",
                                "ANTHROPIC_API_KEY is not set. It is a separate pay-as-you-go API key from "
                                "console.anthropic.com; a Claude or Claude Code subscription does not supply it.")
        try:
            import anthropic
        except ImportError as exc:  # optional dependency
            raise ProviderError("not_configured", "Install the optional dependency: pip install '.[anthropic]'") from exc
        self._anthropic = anthropic
        self.client = anthropic.Anthropic(api_key=api_key, max_retries=2, timeout=300.0)
        self.model = model
        # Server-side refusal fallback (beta): if a safety classifier declines (security topics can trip
        # the cyber classifier), the API retries on a fallback model inside the same call.
        self.extra: dict[str, Any] = {}
        if fallbacks:
            self.extra = {"extra_headers": {"anthropic-beta": "server-side-fallback-2026-07-01"},
                          "extra_body": {"fallbacks": "default"}}

    def complete(self, cve_id: str, system: str, user: str, schema: dict[str, Any]) -> ProviderResponse:
        a = self._anthropic
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=16000,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_config={"effort": "medium", "format": {"type": "json_schema", "schema": schema}},
                **self.extra,
            )
        except a.AuthenticationError as exc:
            raise ProviderError("auth", "Anthropic API rejected the API key") from exc
        except a.RateLimitError as exc:
            raise ProviderError("rate_limited", "Anthropic API rate limit") from exc
        except a.BadRequestError as exc:
            raise ProviderError("bad_response", f"Anthropic API bad request: {exc.message}") from exc
        except a.APIStatusError as exc:
            raise ProviderError("unavailable", f"Anthropic API error {exc.status_code}") from exc
        except a.APIConnectionError as exc:
            raise ProviderError("unavailable", "cannot reach the Anthropic API") from exc
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            raise ProviderError("refused", f"model declined the request (category: {category})")
        if response.stop_reason == "max_tokens":
            raise ProviderError("bad_response", "model output was truncated (max_tokens)")
        text = next((b.text for b in response.content if getattr(b, "type", "") == "text"), "")
        return ProviderResponse(text=text, model=response.model)


class ScriptedProvider:
    """Offline demo: replays hand-written example outputs. Never used in live mode."""

    name = "scripted"
    model = "scripted-example"

    def __init__(self, root: Path):
        self.root = root

    def complete(self, cve_id: str, system: str, user: str, schema: dict[str, Any]) -> ProviderResponse:
        path = self.root / f"{cve_id}.json"
        if not path.is_file():
            raise ProviderError("not_configured", f"no scripted example for {cve_id}")
        doc = json.loads(path.read_text())
        return ProviderResponse(text=json.dumps(doc["output"]), model=self.model, scripted=True)


def make_provider(settings: Settings, name: str | None = None, scripted_root: Path | None = None) -> Provider:
    choice = (name or settings.llm_provider or "none").lower()
    if choice == "none":
        return NoProvider()
    if choice == "openai_compatible":
        return OpenAICompatibleProvider(settings.llm_base_url, settings.llm_model, settings.llm_api_key)
    if choice == "ollama":
        return OllamaProvider(settings.ollama_url, settings.llm_model, settings.llm_num_ctx_max)
    if choice == "anthropic":
        return AnthropicProvider(settings.anthropic_api_key, settings.anthropic_model, settings.anthropic_fallbacks)
    if choice == "scripted":
        if scripted_root is None:
            raise ProviderError("not_configured", "scripted provider is only available in offline demo mode")
        return ScriptedProvider(scripted_root)
    raise ProviderError("not_configured", f"unknown provider {choice!r}")
