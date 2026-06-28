"""
Provider abstraction for the AI features.

Connection test and streaming chat both live here. Calls use `requests`
directly so no provider SDK dependency is required.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import requests

OPENAI_BASE = "https://api.openai.com/v1"
ANTHROPIC_BASE = "https://api.anthropic.com/v1"
ANTHROPIC_VERSION = "2023-06-01"

# Sentinel prefix marking a streamed error chunk, so callers can distinguish a
# provider failure from normal output without parsing HTTP status mid-stream.
STREAM_ERROR_PREFIX = "\x00ERROR\x00"

# Curated suggested models per provider (the Settings UI mirrors this list; the
# `model` field itself accepts any non-empty string so newer ids are not blocked).
MODELS: dict[str, list[str]] = {
    "openai": ["gpt-4o", "gpt-4o-mini", "o4-mini"],
    "anthropic": ["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
}

SUPPORTED_PROVIDERS = frozenset(MODELS)


def test_connection(provider: str, api_key: str, timeout: int = 10) -> tuple[bool, str]:
    """
    Make a minimal, non-billable request to confirm the API key is valid.

    Lists the provider's models (a cheap authenticated GET). Never raises;
    network or HTTP problems are returned as (False, detail).

    Args:
        provider: 'openai' or 'anthropic'.
        api_key:  the plaintext API key to test.
        timeout:  per-request timeout in seconds.

    Returns:
        (ok, human-readable detail).
    """
    try:
        if provider == "openai":
            resp = requests.get(
                f"{OPENAI_BASE}/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
        elif provider == "anthropic":
            resp = requests.get(
                f"{ANTHROPIC_BASE}/models",
                headers={"x-api-key": api_key, "anthropic-version": ANTHROPIC_VERSION},
                timeout=timeout,
            )
        else:
            return False, f"Unsupported provider '{provider}'."
    except requests.RequestException as exc:
        return False, f"Could not reach provider ({exc.__class__.__name__})."

    if resp.status_code == 200:
        return True, "Connection successful."
    if resp.status_code in (401, 403):
        return False, "Invalid API key."
    return False, f"Provider returned HTTP {resp.status_code}."


def stream_chat(
    provider: str,
    api_key: str,
    model: str,
    system: str,
    messages: list[dict],
    max_tokens: int = 1024,
    timeout: int = 60,
) -> Iterator[str]:
    """
    Stream a multi-turn chat completion, yielding text deltas as they arrive.

    Args:
        provider: 'openai' or 'anthropic'.
        api_key:  the plaintext API key.
        model:    provider model id.
        system:   grounding system prompt (rebuilt from the MANIFEST, not stored).
        messages: prior turns as [{"role": "user"|"assistant", "content": str}].
        max_tokens: response token ceiling.
        timeout:  per-request timeout in seconds.

    Yields:
        Plain text chunks. On a provider/transport failure, yields a single
        chunk prefixed with STREAM_ERROR_PREFIX and stops.
    """
    try:
        if provider == "openai":
            resp = requests.post(
                f"{OPENAI_BASE}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "max_tokens": max_tokens,
                    "stream": True,
                    "messages": [{"role": "system", "content": system}, *messages],
                },
                stream=True,
                timeout=timeout,
            )
        elif provider == "anthropic":
            resp = requests.post(
                f"{ANTHROPIC_BASE}/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": ANTHROPIC_VERSION,
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": max_tokens,
                    "stream": True,
                    "system": system,
                    "messages": messages,
                },
                stream=True,
                timeout=timeout,
            )
        else:
            yield f"{STREAM_ERROR_PREFIX}Unsupported provider '{provider}'."
            return
    except requests.RequestException as exc:
        yield f"{STREAM_ERROR_PREFIX}Could not reach provider ({exc.__class__.__name__})."
        return

    if resp.status_code != 200:
        detail = (
            "Invalid API key."
            if resp.status_code in (401, 403)
            else f"Provider returned HTTP {resp.status_code}."
        )
        resp.close()
        yield f"{STREAM_ERROR_PREFIX}{detail}"
        return

    try:
        for raw in resp.iter_lines(decode_unicode=True):
            if not raw or not raw.startswith("data:"):
                continue
            data = raw[len("data:"):].strip()
            if data == "[DONE]":
                break
            try:
                event = json.loads(data)
            except ValueError:
                continue
            if provider == "openai":
                choices = event.get("choices") or [{}]
                delta = choices[0].get("delta", {}).get("content")
                if delta:
                    yield delta
            else:  # anthropic
                event_type = event.get("type")
                if event_type == "content_block_delta":
                    text = event.get("delta", {}).get("text")
                    if text:
                        yield text
                elif event_type == "message_stop":
                    break
    except requests.RequestException as exc:
        yield f"{STREAM_ERROR_PREFIX}Stream interrupted ({exc.__class__.__name__})."
    finally:
        resp.close()
