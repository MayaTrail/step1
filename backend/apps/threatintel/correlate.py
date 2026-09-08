"""
Matching feed items against the emulation catalogue.

An aggregated blog feed is only worth reading inside MayaTrail if it answers
the question its reader already has: does this post describe something we can
emulate and detect? This module answers that by matching each item against
metadata the emulation MANIFESTs already carry, so no new data is introduced.

Three join keys are used, in descending order of precision:

    cited      The item's link is already listed in an emulation's
               references[]. This is a fact, not an inference.
    technique  An ATT&CK technique id in the item text is mapped by an
               emulation's mitre_mappings[].
    campaign   A distinctive campaign name from name/display_name/aliases
               appears in the item text.

Service and tag matching are deliberately excluded. Twenty of the fifty
emulations list IAM in `services`, so an item that merely mentions IAM would
match 40 percent of the catalogue. A wrong match costs more than a missing one:
it teaches the reader to ignore every match, including the correct ones.

Kept free of Django models, the network and the filesystem, so the rules are
testable against a fabricated index in the same way parser.py and window.py
are testable against fixture XML.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

# Technique ids are pulled out of the item text in one pass and then looked up
# by exact key. Doing it the other way round, one regex per catalogue id, is
# wrong: "." is a word boundary, so a pattern for T1059 also matches inside the
# string "T1059.009" and a post about the sub-technique would light up the
# parent's emulation. Both ids are in the catalogue, so this is a live case.
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Word-shaped campaign tokens are matched by set intersection, which needs the
# item text broken into the same shape.
_WORD_RE = re.compile(r"[a-z0-9_]+")

# A campaign token is only evidence if its appearance in prose is unlikely to
# be a coincidence. Short names collide with ordinary words and with acronyms.
MIN_CAMPAIGN_TOKEN = 6

# Bounds the stored document against a roundup post that enumerates a dozen
# technique ids. Such a post really does relate to every one of them, but
# storage.py keeps latest.json to a few hundred KB and the UI shows only the
# first few anyway.
MAX_MATCHES_PER_ITEM = 6

MATCH_CITED = "cited"
MATCH_TECHNIQUE = "technique"
MATCH_CAMPAIGN = "campaign"

# Applied when an item reaches the same emulation by more than one route, and
# to order the matches shown against an item.
_KIND_RANK = {MATCH_CITED: 0, MATCH_TECHNIQUE: 1, MATCH_CAMPAIGN: 2}


@dataclass(frozen=True)
class EmulationIndex:
    """
    Lookup tables over the emulation catalogue, built once per ingest run.

    Attributes:
        by_reference: Normalised reference URL to the emulation ids citing it.
        by_technique: ATT&CK technique id to the emulation ids mapping it.
        by_campaign: Lower-cased campaign token to the emulation ids it names.
        meta: Emulation id to the fields an item's match carries to the UI.
    """

    by_reference: dict[str, list[str]]
    by_technique: dict[str, list[str]]
    by_campaign: dict[str, list[str]]
    meta: dict[str, dict[str, Any]]


def normalise_url(url: str) -> str:
    """
    Reduce a URL to a comparable key.

    A publisher's RSS link and the URL an author pasted into a MANIFEST rarely
    agree on scheme, a leading "www.", a trailing slash, or tracking query
    parameters, so all four are discarded before comparison.

    Args:
        url: Any absolute URL, or an empty string.

    Returns:
        "host/path" in lower case, or an empty string when there is no host.
    """
    if not url:
        return ""
    parts = urlsplit(url.strip())
    host = parts.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    if not host:
        return ""
    return f"{host}{parts.path.rstrip('/').lower()}"


def _service_tokens(catalogue: list[dict[str, Any]]) -> set[str]:
    """
    Collect the cloud service names the catalogue uses, as campaign exclusions.

    An emulation named after the service it targets, say a display_name of
    "CloudTrail", would otherwise be indexed as a campaign token and match
    every post that mentions the service. Deriving the exclusions from the
    catalogue's own `services` values keeps the guard correct as the catalogue
    grows, rather than freezing a guessed word list.

    Args:
        catalogue: Registry entries.

    Returns:
        Lower-cased single-word service names.
    """
    return {
        service.lower()
        for entry in catalogue
        for service in entry.get("services", [])
        if service and " " not in service
    }


def _campaign_tokens(entry: dict[str, Any], excluded: set[str]) -> set[str]:
    """
    Extract the distinctive names an emulation can be recognised by in prose.

    Only single tokens qualify. Multi-word values are descriptive titles such
    as "Backdoor IAM User with Additional Access Key", which never appear
    verbatim in an article, so indexing them adds keys that can never match.
    What remains is campaign names (scarleteel, ambersquid, codefinger) and
    upstream technique ids (aws.persistence.iam-backdoor-user), both of which
    do appear in security writing.

    Args:
        entry: One registry entry.
        excluded: Service names that must not become campaign tokens.

    Returns:
        Lower-cased tokens, possibly empty.
    """
    candidates = [entry.get("name", ""), entry.get("display_name", "")]
    candidates.extend(re.split(r"[·,;|]", entry.get("aliases", "") or ""))

    tokens: set[str] = set()
    for candidate in candidates:
        token = (candidate or "").strip().lower()
        if " " in token or len(token) < MIN_CAMPAIGN_TOKEN or token in excluded:
            continue
        tokens.add(token)
    return tokens


def build_index(catalogue: list[dict[str, Any]]) -> EmulationIndex:
    """
    Build the lookup tables an ingest run matches against.

    Args:
        catalogue: Registry entries, as returned by list_emulations().

    Returns:
        An EmulationIndex. An entry without an id is skipped rather than
        indexed under an empty key.
    """
    by_reference: dict[str, list[str]] = {}
    by_technique: dict[str, list[str]] = {}
    by_campaign: dict[str, list[str]] = {}
    meta: dict[str, dict[str, Any]] = {}

    excluded = _service_tokens(catalogue)

    for entry in catalogue:
        emulation_id = entry.get("name")
        if not emulation_id:
            continue

        meta[emulation_id] = {
            "emulationId": emulation_id,
            "displayName": entry.get("display_name") or emulation_id,
            "platform": entry.get("platform", "aws"),
            "severity": entry.get("severity", ""),
        }

        for reference in entry.get("references", []):
            key = normalise_url(reference.get("url", "") if isinstance(reference, dict) else "")
            if key:
                by_reference.setdefault(key, []).append(emulation_id)

        for mapping in entry.get("mitre_mappings", []):
            technique = (mapping.get("id", "") if isinstance(mapping, dict) else "").strip().upper()
            if technique:
                by_technique.setdefault(technique, []).append(emulation_id)

        for token in _campaign_tokens(entry, excluded):
            by_campaign.setdefault(token, []).append(emulation_id)

    return EmulationIndex(
        by_reference=by_reference,
        by_technique=by_technique,
        by_campaign=by_campaign,
        meta=meta,
    )


def _item_text(item: dict[str, Any]) -> str:
    """
    Join the fields of an item that may name a technique or campaign.

    Args:
        item: A normalised feed item.

    Returns:
        Title, summary and tags as one lower-cased string.
    """
    parts = [item.get("title", ""), item.get("summary", "")]
    parts.extend(item.get("tags", []))
    return " ".join(part for part in parts if part).lower()


def match_item(item: dict[str, Any], index: EmulationIndex) -> list[dict[str, Any]]:
    """
    Find the emulations one feed item relates to.

    Args:
        item: A normalised feed item.
        index: The catalogue index for this run.

    Returns:
        Up to MAX_MATCHES_PER_ITEM match dicts, each carrying the emulation's
        display metadata plus the `kind` of match and the `evidence` that
        produced it. Ordered by precision then name, so the stored document is
        stable across runs that see the same input.
    """
    text = _item_text(item)
    best: dict[str, tuple[str, str]] = {}

    def record(emulation_id: str, kind: str, evidence: str) -> None:
        """
        Keep the best route to a given emulation.

        Higher precision wins. Ties are broken on the longer evidence string,
        then alphabetically. That is not cosmetic: an emulation can carry
        several campaign tokens, they come out of a set, and set iteration
        order varies with string hashing between processes. Without a total
        order the stored evidence flips between runs on identical input. The
        longer string is also the better one to show, since "aws.persistence
        .iam-backdoor-user" says more to a reader than "dangerdev" does.
        """
        current = best.get(emulation_id)
        if current is None:
            best[emulation_id] = (kind, evidence)
            return

        current_kind, current_evidence = current
        if _KIND_RANK[kind] != _KIND_RANK[current_kind]:
            if _KIND_RANK[kind] < _KIND_RANK[current_kind]:
                best[emulation_id] = (kind, evidence)
        elif (len(evidence), evidence) > (len(current_evidence), current_evidence):
            best[emulation_id] = (kind, evidence)

    link = normalise_url(item.get("link", ""))
    if link:
        for emulation_id in index.by_reference.get(link, []):
            record(emulation_id, MATCH_CITED, item.get("link", ""))

    for technique in set(_TECHNIQUE_RE.findall(text.upper())):
        for emulation_id in index.by_technique.get(technique, []):
            record(emulation_id, MATCH_TECHNIQUE, technique)

    # Word-shaped tokens are compared as whole words so "ecscape" does not fire
    # on "ecscapes". Tokens carrying "." or "-" survive that split, so they are
    # checked as substrings instead; they are long enough that a partial hit is
    # not a realistic false positive.
    words = set(_WORD_RE.findall(text))
    for token, emulation_ids in index.by_campaign.items():
        hit = token in text if ("." in token or "-" in token) else token in words
        if hit:
            for emulation_id in emulation_ids:
                record(emulation_id, MATCH_CAMPAIGN, token)

    matches = [
        {**index.meta[emulation_id], "kind": kind, "evidence": evidence}
        for emulation_id, (kind, evidence) in best.items()
        if emulation_id in index.meta
    ]
    matches.sort(key=lambda match: (_KIND_RANK[match["kind"]], match["displayName"]))
    return matches[:MAX_MATCHES_PER_ITEM]


def annotate(items: list[dict[str, Any]], index: EmulationIndex) -> list[dict[str, Any]]:
    """
    Attach emulation matches to every item in the rolling window.

    Applied to the whole window rather than only to freshly fetched items.
    Emulations are added to the catalogue over time, and a post ingested before
    its emulation existed should light up on the next run instead of staying
    dark forever. Re-annotating makes the result a function of the window and
    the catalogue rather than of ingest order.

    Args:
        items: The merged window.
        index: The catalogue index for this run.

    Returns:
        New item dicts carrying a `matches` list, which is empty for an item
        that relates to nothing in the catalogue.
    """
    return [{**item, "matches": match_item(item, index)} for item in items]
