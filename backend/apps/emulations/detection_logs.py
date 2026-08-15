"""
Reading the detection log archive for one emulation run.

Objects live under s3://{DETECTIONS_BUCKET}/{DETECTIONS_PREFIX} partitioned by
date:

    detections/year=YYYY/month=MM/day=DD/HHMMSS-<eventID>.json

Each object holds one archived detection: a `detection` envelope written by the
notifier (disposition, severity, actor, is_emulation) wrapping the full
`cloudtrail` event. The CloudTrail half is what the Sigma rules match on, so it
is handed to detection_check unchanged.

Only the partitions the run actually spans are listed, never the whole prefix.
The bucket is provisioned out of band; a missing bucket or a denied request is
logged and reported as no records rather than failing the run, so a logging
problem never turns a successful emulation into a failed one.

Kept apart from detection_check.py so the correlation rules stay importable
without boto3, which the CI test job does not install.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from django.conf import settings

from .detection_check import in_window, normalise, partition_prefixes

logger = logging.getLogger(__name__)


def is_configured() -> bool:
    """
    Report whether the archive is wired up.

    Returns:
        True when DETECTIONS_BUCKET is set. When it is not, the coverage check
        is skipped and the Live Emulation tile keeps its plain guidance.
    """
    return bool(getattr(settings, "DETECTIONS_BUCKET", ""))


def _prefix() -> str:
    """
    Return the configured key prefix, normalised to end with exactly one slash.

    Returns:
        e.g. "detections/". Empty string when no prefix is configured.
    """
    prefix = (getattr(settings, "DETECTIONS_PREFIX", "") or "").strip("/")
    return f"{prefix}/" if prefix else ""


def read_records(start: datetime, end: datetime) -> list[dict[str, Any]]:
    """
    Read every archived detection inside a run's window.

    Args:
        start: Window start, UTC.
        end: Window end, UTC.

    Returns:
        Normalised records sorted oldest first. An unreadable archive returns an
        empty list, which the report renders as zero events rather than an error.
    """
    if not is_configured():
        return []

    bucket = settings.DETECTIONS_BUCKET
    client = boto3.client(
        "s3", region_name=getattr(settings, "DETECTIONS_BUCKET_REGION", None) or None
    )

    start_iso = start.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = end.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    records: list[dict[str, Any]] = []
    for prefix in partition_prefixes(start, end, _prefix()):
        try:
            pages = client.get_paginator("list_objects_v2").paginate(
                Bucket=bucket, Prefix=prefix
            )
            keys = [obj["Key"] for page in pages for obj in page.get("Contents", [])]
        except (BotoCoreError, ClientError) as exc:
            logger.error("Could not list detection archive %s/%s: %s", bucket, prefix, exc)
            continue

        for key in keys:
            try:
                body = client.get_object(Bucket=bucket, Key=key)["Body"].read()
                document = json.loads(body)
            except (BotoCoreError, ClientError, json.JSONDecodeError) as exc:
                logger.warning("Skipping unreadable detection object %s: %s", key, exc)
                continue

            record = normalise(document)
            if record and in_window(record, start_iso, end_iso):
                records.append(record)

    records.sort(key=lambda record: record["eventTime"])
    logger.info(
        "Detection archive: %d record(s) between %s and %s", len(records), start_iso, end_iso
    )
    return records
