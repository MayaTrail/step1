"""
S3 persistence for the advisory library.

Layout under s3://{THREATINTEL_BUCKET}/{THREATINTEL_ADVISORY_PREFIX}:

    index.json    Card metadata for every dossier — what the list API serves.
    <stem>.md     One dossier, served verbatim by the detail API.

The index is built at upload time by `manage.py sync_advisories`, never on a
request. Parsing 30+ markdown documents per list call would mean one S3 GET per
dossier on every cache miss, in every gunicorn worker; the index makes the list
endpoint the same single-object read the feed endpoint already is.

The prefix is a sibling of THREATINTEL_PREFIX rather than a child: the RSS
snapshot and the dossiers are unrelated content that happen to share a bucket.
As in storage.py the bucket is provisioned out of band, and an unreadable
library is reported as an empty one rather than taking the page down.

Deliberately mirrors storage.py rather than importing from it: that module owns
the RSS prefix, this one owns the advisory prefix, and a shared helper
parameterised by prefix would make each call site read less clearly. Parsing
lives in dossier.py, which stays free of boto3 so the test job can import it.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from django.conf import settings

logger = logging.getLogger(__name__)

INDEX_KEY = "index.json"


def _prefix() -> str:
    """
    Return the advisory key prefix, normalised to end with exactly one slash.

    Returns:
        e.g. "advisory/". Empty string when no prefix is configured.
    """
    prefix = (settings.THREATINTEL_ADVISORY_PREFIX or "").strip("/")
    return f"{prefix}/" if prefix else ""


def _client():
    """
    Build an S3 client for the threat intel bucket's region.

    Returns:
        A boto3 S3 client using the platform credentials from the environment.
    """
    return boto3.client("s3", region_name=settings.THREATINTEL_BUCKET_REGION)


def is_configured() -> bool:
    """
    Report whether a destination bucket has been set.

    Returns:
        True when THREATINTEL_BUCKET is non-empty.
    """
    return bool(settings.THREATINTEL_BUCKET)


def uri(key: str) -> str:
    """
    Build the s3:// URI for one advisory object, for logs and command output.

    Args:
        key: Key relative to the advisory prefix.

    Returns:
        e.g. "s3://mayatrail-threatintel/advisory/apt29.md".
    """
    return f"s3://{settings.THREATINTEL_BUCKET}/{_prefix()}{key}"


def put_object(key: str, body: bytes, content_type: str) -> None:
    """
    Write one object under the advisory prefix.

    Args:
        key: Key relative to the advisory prefix.
        body: Encoded object body.
        content_type: MIME type to store.

    Raises:
        ClientError, BotoCoreError: Propagated so the sync command reports the
            failure rather than claiming a successful upload.
    """
    _client().put_object(
        Bucket=settings.THREATINTEL_BUCKET,
        Key=f"{_prefix()}{key}",
        Body=body,
        ContentType=content_type,
    )


def write_index(index: dict[str, Any]) -> str:
    """
    Persist the library index.

    Args:
        index: Payload from dossier.build_index.

    Returns:
        The s3:// URI written.
    """
    put_object(
        INDEX_KEY,
        json.dumps(index, ensure_ascii=False, indent=2).encode("utf-8"),
        "application/json",
    )
    return uri(INDEX_KEY)


def _read(key: str) -> bytes | None:
    """
    Read one object from under the advisory prefix.

    Args:
        key: Key relative to the advisory prefix.

    Returns:
        The object body, or None when the bucket is unconfigured, the object
        does not exist, or S3 refused the read. All three reach the UI as the
        same empty library, so the page never fails on a storage problem a
        reader cannot act on.
    """
    if not is_configured():
        logger.warning(
            "Advisory library unavailable — THREATINTEL_BUCKET is unset. "
            "Point it at the intel bucket (e.g. mayatrail-threatintel) to enable advisories."
        )
        return None

    try:
        response = _client().get_object(
            Bucket=settings.THREATINTEL_BUCKET,
            Key=f"{_prefix()}{key}",
        )
        return response["Body"].read()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404"):
            logger.info("No advisory object at %s%s", _prefix(), key)
        else:
            logger.error("Could not read advisory object %s: %s", key, exc)
        return None
    except (BotoCoreError, KeyError) as exc:
        logger.error("Could not read advisory object %s: %s", key, exc)
        return None


def read_index() -> dict[str, Any] | None:
    """
    Read the library index written by the last sync.

    Returns:
        The index payload, or None when no sync has run or the object is
        unreadable.
    """
    body = _read(INDEX_KEY)
    if body is None:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.error("Advisory index is not valid JSON: %s", exc)
        return None


def read_dossier(file_name: str) -> str | None:
    """
    Read one dossier document.

    Args:
        file_name: Object name taken from an index entry's `file` — never
            built from request input.

    Returns:
        The markdown, or None when the object is missing or unreadable.
    """
    body = _read(file_name)
    if body is None:
        return None
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as exc:
        logger.error("Advisory %s is not valid UTF-8: %s", file_name, exc)
        return None
