"""
Guardrail registry, auto-discovers the policy documents in this directory.

Every guardrail is a plain AWS policy document under policies/.  MANIFEST.py
names each one and records the repository it came from.  Everything else the
catalogue exposes is read out of the policy body itself:

    type      RCP when any statement carries a Principal element, else SCP.
    services  Display labels for the service prefixes of the Action entries.

Deriving those two rather than recording them means they cannot fall out of
step with the JSON.  A policy is described in exactly one place: the document
for its behaviour, MANIFEST.py for the sentence a human had to write.

Call discover() to get the full catalogue, ordered by type then purpose.
Policies missing a MANIFEST entry, and MANIFEST entries missing a file, are
skipped with a warning; the backend corpus test turns either into a failure at
PR time so neither can reach a release.
"""

from __future__ import annotations

import json
import logging
import pathlib
import re
from typing import Any

from .MANIFEST import POLICIES, SOURCES
from .services import label_for

logger = logging.getLogger(__name__)

POLICIES_DIRNAME = "policies"

# Tag applied instead of the enumerated prefixes when a policy constrains every
# service rather than a named few.  See _derive for when that applies.
ALL_SERVICES = "All services"

# Any run of characters that cannot appear in a URL path segment.
_NON_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(filename: str) -> str:
    """
    Build the catalogue id, and therefore the URL segment, for a policy file.

    Upstream filenames carry commas, parentheses and mixed case
    ("S3-Deny-users-from-modifying-S3-Block-Public-Access-(Account-Level).json").
    Collapsing everything outside [a-z0-9] to single hyphens keeps the id
    readable and safe to place in a route without encoding.

    Args:
        filename: Policy filename, with or without the .json extension.

    Returns:
        A lowercase hyphenated id, e.g. "s3-deny-sse-c".
    """
    stem = pathlib.Path(filename).stem.lower()
    return _NON_SLUG.sub("-", stem).strip("-")


def _statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Return a policy's statements as a list.

    The Statement element is a list in most documents but is allowed to be a
    single object, so normalise it before iterating.

    Args:
        document: A parsed policy document.

    Returns:
        The statements, or an empty list when the element is absent.
    """
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    return statements if isinstance(statements, list) else []


def _derive(document: dict[str, Any]) -> tuple[str, list[str]]:
    """
    Read the policy type and the services it constrains out of a policy body.

    Type: a service control policy attaches to a principal and so cannot name
    one, while a resource control policy attaches to a resource and always
    carries Principal.  The presence of that element is therefore an exact
    discriminator, not a heuristic.

    Services: normally the prefixes of the Action entries.  Two shapes mean the
    policy reaches further than its Action list suggests, and both are tagged
    ALL_SERVICES instead:

      * Action "*", which is org-wide on its face.
      * NotAction, which denies everything *except* what it enumerates, so the
        listed services are the exemptions rather than the targets.  Tagging
        those prefixes would label the policy with the only services it does
        not constrain.

    Args:
        document: A parsed policy document.

    Returns:
        A (type, services) pair, services sorted and de-duplicated.
    """
    statements = _statements(document)
    kind = "RCP" if any("Principal" in s for s in statements) else "SCP"

    prefixes: set[str] = set()
    constrains_everything = False
    for statement in statements:
        if "NotAction" in statement:
            constrains_everything = True
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if action == "*":
                constrains_everything = True
            elif ":" in action:
                prefixes.add(action.split(":", 1)[0].lower())

    if constrains_everything:
        return kind, [ALL_SERVICES]

    # Distinct prefixes can share a display name (bedrock and bedrock-mantle,
    # the two cognito prefixes), so de-duplicate after mapping, not before.
    labels = sorted({label_for(prefix) for prefix in prefixes})
    return kind, labels or [ALL_SERVICES]


def discover() -> list[dict[str, Any]]:
    """
    Scan policies/ and return the guardrail catalogue.

    Each entry contains:
        id        URL-safe slug derived from the filename.
        file      Policy filename, for tracing an entry back to disk.
        type      "SCP" or "RCP", derived from the document.
        purpose   The one-line description authored in MANIFEST.py.
        services  Display labels for the services the policy constrains.
        source    {"label", "url"} for the upstream repository.
        code      The policy document verbatim, as it sits on disk.

    A document that cannot be read or parsed is skipped and logged rather than
    failing the whole catalogue, so one malformed file cannot take the library
    offline in production.

    Returns:
        Catalogue entries sorted by type then purpose.
    """
    policies_dir = pathlib.Path(__file__).resolve().parent / POLICIES_DIRNAME
    if not policies_dir.is_dir():
        logger.error("Guardrail policies directory not found: %s", policies_dir)
        return []

    on_disk = {path.name for path in policies_dir.iterdir() if path.suffix == ".json"}
    for filename in sorted(on_disk - POLICIES.keys()):
        logger.warning("Skipping guardrail %s, no purpose authored in MANIFEST.py", filename)
    for filename in sorted(POLICIES.keys() - on_disk):
        logger.warning("Skipping guardrail %s, named in MANIFEST.py but not on disk", filename)

    entries: list[dict[str, Any]] = []
    for filename in sorted(POLICIES.keys() & on_disk):
        purpose, source_key = POLICIES[filename]
        try:
            code = (policies_dir / filename).read_text(encoding="utf-8")
            document = json.loads(code)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Skipping guardrail %s, could not read policy: %s", filename, exc)
            continue

        kind, services = _derive(document)
        entries.append({
            "id": _slug(filename),
            "file": filename,
            "type": kind,
            "purpose": purpose,
            "services": services,
            "source": SOURCES[source_key],
            "code": code.rstrip("\n"),
        })

    entries.sort(key=lambda entry: (entry["type"], entry["purpose"].lower()))
    logger.info("Guardrails registry loaded: %d policy document(s)", len(entries))
    return entries
