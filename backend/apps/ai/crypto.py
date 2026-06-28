"""
Symmetric encryption for stored LLM API keys.

Uses Fernet (AES-128-CBC + HMAC) with a key from settings.LLM_FERNET_KEY. The
key is read lazily so the app still imports when AI is unconfigured; encrypt and
decrypt raise a clear error only when actually used without a configured key.
"""

from __future__ import annotations

from cryptography.fernet import Fernet
from django.conf import settings


class EncryptionNotConfigured(RuntimeError):
    """Raised when LLM_FERNET_KEY is missing but encryption is requested."""


def _fernet() -> Fernet:
    """Build a Fernet from the configured key, or raise EncryptionNotConfigured."""
    key = getattr(settings, "LLM_FERNET_KEY", "") or ""
    if not key:
        raise EncryptionNotConfigured(
            "LLM_FERNET_KEY is not set. Generate one with "
            '`python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"` and add it to the backend environment.'
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt(plaintext: str) -> bytes:
    """Encrypt a plaintext secret, returning the Fernet token bytes."""
    return _fernet().encrypt(plaintext.encode())


def decrypt(token: bytes) -> str:
    """
    Decrypt a Fernet token back to plaintext.

    Raises cryptography.fernet.InvalidToken if the token was tampered with or the
    key does not match.
    """
    return _fernet().decrypt(bytes(token)).decode()
