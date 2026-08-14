"""
Dossier parsing for the advisory library.

An advisory is an APT threat-actor dossier: one markdown document per actor,
generated out of band by merging MITRE ATT&CK, CISA KEV and MISP galaxy. This
module reduces a dossier to the card metadata the library list serves, and is a
pure function over text — no S3, no settings. advisories.py owns the storage
half, the same split parser.py and storage.py already use for the RSS feed.

The parser accepts what the generator actually emits rather than a strict
schema: two H1 spellings are in use, the `> Generated:` line moves depending on
whether a MITRE group ID is known, and five of the section headings are absent
from at least one file. Every field is therefore optional and defaults to empty.
"""

from __future__ import annotations

import re
from typing import Any

# Cards show the opening of the Intelligence Overview; the full prose is on the
# detail page. Cut at a sentence boundary near this length rather than mid-word.
SUMMARY_MAX_CHARS = 320

# Origin and motivation are the two filter axes on the panel, and the upstream
# sources spell the same value several ways ("Russia" / "Russian Federation",
# "financial" / "financial crime"). Left raw, the dropdowns list one country
# twice. Anything unmapped passes through unchanged.
ORIGIN_ALIASES = {
    "russian federation": "Russia",
    "people's republic of china": "China",
    "iran (islamic republic of)": "Iran",
    "korea (democratic people's republic of)": "North Korea",
    "democratic people's republic of korea": "North Korea",
    "united states of america": "United States",
}

MOTIVATION_ALIASES = {
    "financial": "financial crime",
}

# Placeholders the generator writes for an unpopulated table cell.
_EMPTY_VALUES = {"", "—", "-", "n/a", "unknown", "none"}


def _canonical(value: str, aliases: dict[str, str]) -> str:
    """
    Map one spelling of a value onto its canonical form.

    Args:
        value: Raw cell text from the dossier's Overview table.
        aliases: Lowercased-key alias map to apply.

    Returns:
        The canonical spelling, or `value` unchanged when unmapped.
    """
    return aliases.get(value.strip().lower(), value.strip())


def slugify(name: str) -> str:
    """
    Build a URL- and key-safe id from a dossier filename stem.

    Args:
        name: Filename stem, e.g. "lapsus$" or "lazarus_group".

    Returns:
        Lowercase `[a-z0-9-]`, e.g. "lapsus", "lazarus-group". Empty when the
        stem contains nothing usable.
    """
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", name.lower())).strip("-")


def _title(markdown: str) -> str:
    """
    Read the actor name from the leading H1.

    Both "# Threat Actor : APT29" and "# Threat Actor Dossier: KillNet" are in
    use, and the name is whatever follows the separator.

    Args:
        markdown: Whole dossier document.

    Returns:
        The actor name, or "" when there is no H1.
    """
    match = re.search(r"^#\s+(.+)$", markdown, re.MULTILINE)
    if not match:
        return ""
    heading = match.group(1).strip()
    parts = re.split(r"\s*:\s*", heading, maxsplit=1)
    return (parts[1] if len(parts) == 2 else heading).strip()


def _section(markdown: str, heading: str) -> str:
    """
    Extract the body of one H2 section.

    Args:
        markdown: Whole dossier document.
        heading: Exact H2 text, e.g. "TTP Table".

    Returns:
        Everything between that heading and the next H2, or "" when the
        section is absent (several dossiers omit TTP Table or Campaigns).
    """
    pattern = rf"^##\s+{re.escape(heading)}\s*$(.*?)(?=^##\s+|\Z)"
    match = re.search(pattern, markdown, re.MULTILINE | re.DOTALL)
    return match.group(1).strip() if match else ""


def _table_rows(section: str) -> list[list[str]]:
    """
    Parse the body rows of a GitHub-flavoured markdown table.

    Args:
        section: Section text containing exactly one table.

    Returns:
        One list of trimmed cells per row, excluding the header and the
        `|---|` separator. Non-table lines are ignored.
    """
    rows: list[list[str]] = []
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|") or set(line) <= set("|-: "):
            continue
        rows.append([cell.strip() for cell in line.strip("|").split("|")])

    # The first surviving row is the header ("| Field | Value |").
    return rows[1:] if rows else []


def _overview_fields(markdown: str) -> dict[str, str]:
    """
    Read the Overview table into a plain dict.

    Args:
        markdown: Whole dossier document.

    Returns:
        Lowercased field name to raw value, e.g. {"origin": "China"}. Every
        dossier carries this table, but a missing one yields {}.
    """
    fields: dict[str, str] = {}
    for row in _table_rows(_section(markdown, "Overview")):
        if len(row) < 2:
            continue
        key = row[0].strip("* ").lower()
        if key:
            fields[key] = row[1].strip()
    return fields


def _split_list(value: str) -> list[str]:
    """
    Split a comma-separated table cell, dropping placeholder values.

    Args:
        value: Raw cell text, e.g. "Cozy Bear, NOBELIUM" or "—".

    Returns:
        Trimmed entries; [] for an empty or placeholder cell.
    """
    if value.strip().lower() in _EMPTY_VALUES:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _optional(value: str) -> str:
    """
    Normalise a single-value cell, collapsing placeholders to "".

    Args:
        value: Raw cell text.

    Returns:
        The trimmed value, or "" when the generator wrote a placeholder.
    """
    return "" if value.strip().lower() in _EMPTY_VALUES else value.strip()


def _summary(markdown: str) -> str:
    """
    Build the card summary from the Intelligence Overview.

    Args:
        markdown: Whole dossier document.

    Returns:
        The opening prose truncated at a sentence boundary, or "" when the
        dossier has no Intelligence Overview (two of them do not).
    """
    body = _section(markdown, "Intelligence Overview")
    paragraph = next(
        (block.strip() for block in body.split("\n\n") if block.strip() and not block.lstrip().startswith(">")),
        "",
    )
    paragraph = " ".join(paragraph.split())
    if len(paragraph) <= SUMMARY_MAX_CHARS:
        return paragraph

    cut = paragraph[:SUMMARY_MAX_CHARS]
    stop = cut.rfind(". ")
    return f"{cut[: stop + 1]}" if stop > SUMMARY_MAX_CHARS // 2 else f"{cut.rstrip()}…"


def _tactics(markdown: str) -> tuple[list[str], int]:
    """
    Read the MITRE tactics and technique count from the TTP table.

    Args:
        markdown: Whole dossier document.

    Returns:
        Tuple of (unique tactics in first-seen order, technique row count).
        ([], 0) when the dossier has no TTP table.
    """
    seen: list[str] = []
    count = 0
    for row in _table_rows(_section(markdown, "TTP Table")):
        if len(row) < 2 or not row[0].strip():
            continue
        count += 1
        tactic = row[1].strip()
        if tactic and tactic not in seen:
            seen.append(tactic)
    return seen, count


def _generated_at(markdown: str) -> str:
    """
    Read the generator's timestamp line.

    Args:
        markdown: Whole dossier document.

    Returns:
        e.g. "2026-08-14 21:54 UTC", or "" when the line is absent. Kept as
        written rather than reformatted — it is provenance, not a sort key.
    """
    match = re.search(r"^>\s*Generated:\s*([^|]+)", markdown, re.MULTILINE)
    return match.group(1).strip() if match else ""


def _sources(markdown: str) -> list[str]:
    """
    Read the upstream feeds credited on the generator's timestamp line.

    Args:
        markdown: Whole dossier document.

    Returns:
        e.g. ["cisa", "mitre_attack"]; [] when the line names none.
    """
    match = re.search(r"^>\s*Generated:.*?\|\s*Sources:\s*(.+)$", markdown, re.MULTILINE)
    return _split_list(match.group(1)) if match else []


def _first_seen(value: str) -> str:
    """
    Keep a first-seen year only when the generator actually knew one.

    Nineteen of the thirty-three dossiers carry the same full ISO timestamp in
    this cell, dated after the run that produced them — a placeholder the
    generator writes when the upstream record has no first-seen date, not an
    observation. Rendering it would put a precise, wrong date on the card, so
    only a bare year (or year range) survives.

    Args:
        value: Raw cell text, e.g. "2008" or "2026-08-20T00:00:00+00:00".

    Returns:
        The year as written, or "" when the cell holds a placeholder.
    """
    trimmed = _optional(value)
    return trimmed if re.fullmatch(r"\d{4}(\s*[-–]\s*\d{4})?", trimmed) else ""


def parse_dossier(stem: str, markdown: str) -> dict[str, Any]:
    """
    Reduce one dossier to the card metadata the library list serves.

    Args:
        stem: Source filename without its extension, e.g. "apt29".
        markdown: The dossier document.

    Returns:
        One index entry. `file` is the S3 object name, which the detail view
        resolves through the index rather than deriving from the request path,
        so a caller can never reach an arbitrary key.
    """
    fields = _overview_fields(markdown)
    tactics, technique_count = _tactics(markdown)
    group_id = re.search(r"MITRE ATT&CK Group ID:\s*\*{0,2}(G\d+)", markdown)

    # A file named apt10.md carries the H1 "menuPass": the generator titles each
    # dossier with the MITRE-canonical name, which for six actors is not the
    # name the file is filed under. Both are kept — `name` leads on the card,
    # `reference` is shown beside it and is searchable, so "apt10" still finds it.
    reference = stem.replace("_", " ").upper()
    name = _title(markdown) or reference

    return {
        "id": slugify(stem),
        "file": f"{stem}.md",
        "name": name,
        "reference": reference,
        "groupId": group_id.group(1) if group_id else "",
        "summary": _summary(markdown),
        "origin": _canonical(_optional(fields.get("origin", "")), ORIGIN_ALIASES),
        "firstSeen": _first_seen(fields.get("first seen", "")),
        "motivations": [
            _canonical(m, MOTIVATION_ALIASES) for m in _split_list(fields.get("motivations", ""))
        ],
        "aliases": _split_list(fields.get("also known as", "")),
        "tactics": tactics,
        "techniqueCount": technique_count,
        "cveCount": len(_table_rows(_section(markdown, "Known Exploited CVEs (CISA KEV)"))),
        "malwareCount": len(_table_rows(_section(markdown, "Associated Malware / Tools"))),
        "sectors": [
            line.lstrip("- ").strip()
            for line in _section(markdown, "Targeted Sectors").splitlines()
            if line.strip().startswith("-")
        ],
        "generatedAt": _generated_at(markdown),
        "sources": _sources(markdown),
    }


def build_index(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Assemble the library index from parsed dossiers.

    Args:
        entries: Output of `parse_dossier`, one per document.

    Returns:
        The index.json payload, advisories sorted by display name.
    """
    ordered = sorted(entries, key=lambda entry: entry["name"].lower())
    return {"advisories": ordered, "totalCount": len(ordered)}
