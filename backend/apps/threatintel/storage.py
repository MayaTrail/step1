"""
S3 persistence for the threat intel feed.

Layout under s3://{THREATINTEL_BUCKET}/{THREATINTEL_PREFIX}:

    latest.json            The rolling window the API serves.
    daily/YYYY-MM-DD.json  One immutable snapshot per ingest run, kept as the
                           audit trail of what each day's fetch actually saw.

The bucket is *not* created here. Like STATE_BUCKET it is provisioned out of
band; a missing bucket or a denied request is logged and reported as an empty
library, mirroring how the guardrails registry returns [] rather than taking
the page down.
"""

from __future__ import annotations

import json
import logging
from datetime import date
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from django.conf import settings

logger = logging.getLogger(__name__)

LATEST_KEY = "latest.json"
DAILY_PREFIX = "daily"


def _prefix() -> str:
    """
    Return the configured key prefix, normalised to end with exactly one slash.

    Returns:
        e.g. "rss-feed/". Empty string when no prefix is configured.
    """
    prefix = (settings.THREATINTEL_PREFIX or "").strip("/")
    return f"{prefix}/" if prefix else ""


def _client():
    """
    Build an S3 client for the threat intel bucket's region.

    Deliberately does not reuse STATE_BUCKET_REGION: the intel bucket is a
    separate resource and may not live in ap-south-1.

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


def _put_json(key: str, payload: dict[str, Any]) -> None:
    """
    Write one JSON object to S3.

    Args:
        key: Key relative to the configured prefix.
        payload: JSON-serialisable body.

    Raises:
        ClientError, BotoCoreError: Propagated so the caller's run report
            records the failure.
    """
    _client().put_object(
        Bucket=settings.THREATINTEL_BUCKET,
        Key=f"{_prefix()}{key}",
        Body=json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),
        ContentType="application/json",
    )


def write_snapshot(payload: dict[str, Any], *, on: date | None = None) -> dict[str, str]:
    """
    Persist one ingest run as both the daily snapshot and the latest pointer.

    Args:
        payload: The run's items plus its fetch report.
        on: Snapshot date; defaults to the payload's own date, then today.

    Returns:
        Dict of the two s3:// URIs written.
    """
    day = on or date.fromisoformat(payload.get("fetchedOn") or date.today().isoformat())
    daily_key = f"{DAILY_PREFIX}/{day.isoformat()}.json"

    _put_json(daily_key, payload)
    _put_json(LATEST_KEY, payload)

    bucket = settings.THREATINTEL_BUCKET
    return {
        "daily": f"s3://{bucket}/{_prefix()}{daily_key}",
        "latest": f"s3://{bucket}/{_prefix()}{LATEST_KEY}",
    }


def read_latest() -> dict[str, Any] | None:
    """
    Read the most recent ingest run.

    Returns:
        The stored payload, or None when the bucket is unconfigured, the object
        does not exist yet (no run has completed), or S3 refused the read. All
        three are surfaced to the UI as the same empty state, so the page never
        fails on a storage problem it cannot act on.
    """
    if not is_configured():
        logger.warning(
            "Threat intel feed unavailable — THREATINTEL_BUCKET is unset. "
            "Point it at the intel bucket (e.g. mayatrail-threatintel) to enable the feed."
        )
        return None

    try:
        response = _client().get_object(
            Bucket=settings.THREATINTEL_BUCKET,
            Key=f"{_prefix()}{LATEST_KEY}",
        )
        return json.loads(response["Body"].read().decode("utf-8"))
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404"):
            logger.info("No threat intel snapshot yet at %s%s", _prefix(), LATEST_KEY)
        else:
            logger.error("Could not read threat intel snapshot: %s", exc)
        return None
    except (BotoCoreError, json.JSONDecodeError, KeyError) as exc:
        logger.error("Could not read threat intel snapshot: %s", exc)
        return None
