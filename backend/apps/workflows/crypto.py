"""
Symmetric encryption for stored webhook secrets.

Deliberately not the ai app's helper, despite the same Fernet mechanics. That
one is keyed on LLM_FERNET_KEY, and importing it here would mean a deployment
could not accept SIEM alerts without first configuring the AI feature. The two
secrets have different lifecycles and different owners, so they get different
keys.

The key is read lazily so the app still imports when workflows are unconfigured;
encrypt and decrypt raise a clear error only when actually used.
"""

from __future__ import annotations

from cryptography.fernet import Fernet
from django.conf import settings


class EncryptionNotConfigured(RuntimeError):
    """Raised when WORKFLOW_FERNET_KEY is missing but encryption is requested."""


def _fernet() -> Fernet:
    """
    Build a Fernet from the configured key.

    Returns:
        A Fernet instance.

    Raises:
        EncryptionNotConfigured: When no key is set, with the command to make one.
    """
    key = getattr(settings, "WORKFLOW_FERNET_KEY", "") or ""
    if not key:
        raise EncryptionNotConfigured(
            "WORKFLOW_FERNET_KEY is not set. Generate one with "
            '`python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"` and add it to the backend environment.'
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt(plaintext: str) -> bytes:
    """
    Encrypt a webhook secret for storage.

    Args:
        plaintext: The secret as generated.

    Returns:
        Fernet token bytes, written to AlertEndpoint.secret_encrypted.
    """
    return _fernet().encrypt(plaintext.encode())


def decrypt(token: bytes) -> str:
    """
    Recover a stored webhook secret in order to verify a signature.

    Args:
        token: The stored Fernet token.

    Returns:
        The secret as plaintext.

    Raises:
        cryptography.fernet.InvalidToken: If the stored value was tampered with
            or the key has changed.
    """
    return _fernet().decrypt(token).decode()
