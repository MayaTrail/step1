"""
Provider abstraction for the AI features.

Each provider is a small object in a registry (PROVIDERS) that knows how to
(a) test its credentials and (b) stream a grounded chat completion. Key-based
providers (OpenAI, Anthropic) call the REST APIs directly with `requests`, so no
provider SDK is required. Amazon Bedrock uses boto3's Converse API with the
temporary AWS credentials the caller derived from the user's assumed role.

Credentials are passed as a provider-specific dict so the dispatch is uniform
regardless of whether a provider authenticates with an API key or AWS SigV4:

    key-based: {"api_key": "..."}
    bedrock:   {"region", "access_key_id", "secret_access_key", "session_token"}
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import boto3
import requests
from botocore.exceptions import BotoCoreError, ClientError

OPENAI_BASE = "https://api.openai.com/v1"
ANTHROPIC_BASE = "https://api.anthropic.com/v1"
ANTHROPIC_VERSION = "2023-06-01"

# Sentinel prefix marking a streamed error chunk, so callers can distinguish a
# provider failure from normal output without parsing HTTP status mid-stream.
STREAM_ERROR_PREFIX = "\x00ERROR\x00"

# Bedrock surfaces failures mid-stream as their own event keys (not HTTP status).
_BEDROCK_STREAM_ERRORS = (
    "internalServerException",
    "modelStreamErrorException",
    "validationException",
    "throttlingException",
    "serviceUnavailableException",
)


# ── shared helpers ──

def _http_test_result(resp: requests.Response) -> tuple[bool, str]:
    """Map a key-based provider's test response to (ok, detail)."""
    if resp.status_code == 200:
        return True, "Connection successful."
    if resp.status_code in (401, 403):
        return False, "Invalid API key."
    return False, f"Provider returned HTTP {resp.status_code}."


def _http_error_detail(status_code: int) -> str:
    """Human-readable detail for a non-200 streaming start."""
    if status_code in (401, 403):
        return "Invalid API key."
    return f"Provider returned HTTP {status_code}."


def _aws_detail(exc: Exception) -> str:
    """Return a human-readable, secret-free detail from a boto3 error."""
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code = err.get("Code", "")
        message = err.get("Message", "")
        if code == "ResourceNotFoundException":
            return "Model not found in this region (check the model id / inference profile)."
        if code == "ThrottlingException":
            return "Throttled by Bedrock. Try again shortly."
        if code in ("AccessDeniedException", "UnauthorizedException"):
            # AWS's own message names the real cause (IAM, model access, or a
            # billing/payment-instrument problem) and carries no secrets, so
            # surface it rather than masking it behind a generic hint.
            return (
                f"Access denied: {message}"
                if message
                else "Access denied. Check the role's Bedrock permissions, model access, "
                "and that the AWS account has a valid payment method."
            )
        return message or str(exc)
    return f"Could not reach Bedrock ({exc.__class__.__name__})."


# ── provider interface ──

class BaseProvider:
    """Common interface for an LLM provider."""

    name: str = ""
    # Curated suggested model ids. The Settings UI mirrors these; the `model`
    # field accepts any non-empty string so newer ids are never blocked.
    models: list[str] = []

    def test(self, creds: dict, timeout: int = 10) -> tuple[bool, str]:
        """
        Make a minimal, non-billable request to confirm the credentials.

        Never raises; network or auth problems are returned as (False, detail).
        """
        raise NotImplementedError

    def stream(
        self,
        creds: dict,
        model: str,
        system: str,
        messages: list[dict],
        max_tokens: int = 1024,
        timeout: int = 60,
    ) -> Iterator[str]:
        """
        Stream a multi-turn chat completion, yielding text deltas as they arrive.

        On a provider/transport failure, yields a single chunk prefixed with
        STREAM_ERROR_PREFIX and stops.
        """
        raise NotImplementedError


class _KeyProvider(BaseProvider):
    """
    Shared shape for key-based REST providers (OpenAI, Anthropic).

    Both authenticate with an API key, list models for a cheap test, and stream
    Server-Sent Events. Subclasses supply the headers, URLs, request body, and
    per-event text extraction; this base owns the transport and SSE loop.
    """

    def _headers(self, api_key: str) -> dict:
        """Auth headers for this provider."""
        raise NotImplementedError

    def _test_url(self) -> str:
        """A cheap authenticated GET used to validate the key."""
        raise NotImplementedError

    def _chat_request(
        self, model: str, system: str, messages: list[dict], max_tokens: int
    ) -> tuple[str, dict]:
        """Return (url, json_body) for a streaming chat completion."""
        raise NotImplementedError

    def _extract(self, event: dict) -> str | None:
        """Pull the text delta out of one SSE event, or None."""
        raise NotImplementedError

    def _is_stop(self, event: dict) -> bool:
        """True when this event marks the end of the stream (provider-specific)."""
        return False

    def test(self, creds: dict, timeout: int = 10) -> tuple[bool, str]:
        api_key = creds.get("api_key", "")
        try:
            resp = requests.get(self._test_url(), headers=self._headers(api_key), timeout=timeout)
        except requests.RequestException as exc:
            return False, f"Could not reach provider ({exc.__class__.__name__})."
        return _http_test_result(resp)

    def stream(self, creds, model, system, messages, max_tokens=1024, timeout=60):
        api_key = creds.get("api_key", "")
        url, body = self._chat_request(model, system, messages, max_tokens)
        headers = {**self._headers(api_key), "Content-Type": "application/json"}
        try:
            resp = requests.post(url, headers=headers, json=body, stream=True, timeout=timeout)
        except requests.RequestException as exc:
            yield f"{STREAM_ERROR_PREFIX}Could not reach provider ({exc.__class__.__name__})."
            return

        if resp.status_code != 200:
            resp.close()
            yield f"{STREAM_ERROR_PREFIX}{_http_error_detail(resp.status_code)}"
            return

        try:
            for raw in resp.iter_lines(decode_unicode=True):
                if not raw or not raw.startswith("data:"):
                    continue
                data = raw[len("data:"):].strip()
                if data == "[DONE]":  # OpenAI end-of-stream sentinel
                    break
                try:
                    event = json.loads(data)
                except ValueError:
                    continue
                if self._is_stop(event):
                    break
                text = self._extract(event)
                if text:
                    yield text
        except requests.RequestException as exc:
            yield f"{STREAM_ERROR_PREFIX}Stream interrupted ({exc.__class__.__name__})."
        finally:
            resp.close()


class OpenAIProvider(_KeyProvider):
    """OpenAI Chat Completions over the REST API."""

    name = "openai"
    models = ["gpt-4o", "gpt-4o-mini", "o4-mini"]

    def _headers(self, api_key: str) -> dict:
        return {"Authorization": f"Bearer {api_key}"}

    def _test_url(self) -> str:
        return f"{OPENAI_BASE}/models"

    def _chat_request(self, model, system, messages, max_tokens):
        return f"{OPENAI_BASE}/chat/completions", {
            "model": model,
            "max_tokens": max_tokens,
            "stream": True,
            "messages": [{"role": "system", "content": system}, *messages],
        }

    def _extract(self, event: dict) -> str | None:
        return (event.get("choices") or [{}])[0].get("delta", {}).get("content")


class AnthropicProvider(_KeyProvider):
    """Anthropic Messages over the REST API."""

    name = "anthropic"
    models = ["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"]

    def _headers(self, api_key: str) -> dict:
        return {"x-api-key": api_key, "anthropic-version": ANTHROPIC_VERSION}

    def _test_url(self) -> str:
        return f"{ANTHROPIC_BASE}/models"

    def _chat_request(self, model, system, messages, max_tokens):
        return f"{ANTHROPIC_BASE}/messages", {
            "model": model,
            "max_tokens": max_tokens,
            "stream": True,
            "system": system,
            "messages": messages,
        }

    def _extract(self, event: dict) -> str | None:
        if event.get("type") == "content_block_delta":
            return event.get("delta", {}).get("text")
        return None

    def _is_stop(self, event: dict) -> bool:
        return event.get("type") == "message_stop"


class BedrockProvider(BaseProvider):
    """
    Amazon Bedrock via boto3's Converse API.

    Authenticates with temporary AWS credentials (from the caller's assumed
    role) rather than a stored key. The Converse message shape uses the same
    'user'/'assistant' roles as the persisted history, so no role remapping is
    needed; only the content is wrapped in a {"text": ...} block.
    """

    name = "bedrock"
    # US cross-region inference-profile ids (the `model` field accepts any
    # string, so other regions' profiles — e.g. apac.* / eu.* — also work).
    models = [
        "us.anthropic.claude-sonnet-4-6",
        "us.anthropic.claude-opus-4-8",
        "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    ]

    def _client(self, creds: dict, service: str):
        """Build a region-scoped boto3 client from temporary credentials."""
        return boto3.client(
            service,
            region_name=creds.get("region"),
            aws_access_key_id=creds.get("access_key_id"),
            aws_secret_access_key=creds.get("secret_access_key"),
            aws_session_token=creds.get("session_token"),
        )

    def test(self, creds: dict, timeout: int = 10) -> tuple[bool, str]:
        if not creds.get("region"):
            return False, "An AWS region is required for Bedrock."
        try:
            # Cheap, non-billable control-plane call: lists models in the region.
            self._client(creds, "bedrock").list_foundation_models()
        except (ClientError, BotoCoreError) as exc:
            return False, _aws_detail(exc)
        return True, "Connection successful."

    def stream(self, creds, model, system, messages, max_tokens=1024, timeout=60):
        if not creds.get("region"):
            yield f"{STREAM_ERROR_PREFIX}An AWS region is required for Bedrock."
            return

        converse_messages = [
            {"role": m["role"], "content": [{"text": m["content"]}]} for m in messages
        ]
        try:
            resp = self._client(creds, "bedrock-runtime").converse_stream(
                modelId=model,
                system=[{"text": system}],
                messages=converse_messages,
                inferenceConfig={"maxTokens": max_tokens},
            )
        except (ClientError, BotoCoreError) as exc:
            yield f"{STREAM_ERROR_PREFIX}{_aws_detail(exc)}"
            return

        try:
            for event in resp["stream"]:
                if "contentBlockDelta" in event:
                    text = event["contentBlockDelta"]["delta"].get("text")
                    if text:
                        yield text
                elif "messageStop" in event:
                    break
                else:
                    for key in _BEDROCK_STREAM_ERRORS:
                        if key in event:
                            yield f"{STREAM_ERROR_PREFIX}{event[key].get('message', key)}"
                            return
        except (ClientError, BotoCoreError) as exc:
            yield f"{STREAM_ERROR_PREFIX}{_aws_detail(exc)}"


# ── registry ──

PROVIDERS: dict[str, BaseProvider] = {
    p.name: p for p in (OpenAIProvider(), AnthropicProvider(), BedrockProvider())
}

# Suggested models per provider (the Settings UI mirrors this; the `model` field
# accepts any non-empty string so newer ids are not blocked).
MODELS: dict[str, list[str]] = {name: p.models for name, p in PROVIDERS.items()}

SUPPORTED_PROVIDERS = frozenset(PROVIDERS)


def get_provider(name: str) -> BaseProvider | None:
    """Return the registered provider, or None if unsupported."""
    return PROVIDERS.get(name)


def test_connection(provider: str, creds: dict, timeout: int = 10) -> tuple[bool, str]:
    """
    Validate credentials for `provider`. Never raises.

    Args:
        provider: a key in PROVIDERS.
        creds:    provider-specific credentials dict.
        timeout:  per-request timeout in seconds.

    Returns:
        (ok, human-readable detail).
    """
    handler = PROVIDERS.get(provider)
    if handler is None:
        return False, f"Unsupported provider '{provider}'."
    return handler.test(creds, timeout)


def stream_chat(
    provider: str,
    creds: dict,
    model: str,
    system: str,
    messages: list[dict],
    max_tokens: int = 1024,
    timeout: int = 60,
) -> Iterator[str]:
    """
    Stream a chat completion from `provider`, yielding text deltas.

    Args:
        provider: a key in PROVIDERS.
        creds:    provider-specific credentials dict.
        model:    provider model id.
        system:   grounding system prompt (rebuilt from the MANIFEST, not stored).
        messages: prior turns as [{"role": "user"|"assistant", "content": str}].
        max_tokens: response token ceiling.
        timeout:  per-request timeout in seconds.

    Yields:
        Plain text chunks. On failure, a single STREAM_ERROR_PREFIX chunk.
    """
    handler = PROVIDERS.get(provider)
    if handler is None:
        yield f"{STREAM_ERROR_PREFIX}Unsupported provider '{provider}'."
        return
    yield from handler.stream(creds, model, system, messages, max_tokens, timeout)
