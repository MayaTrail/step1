#!/usr/bin/env python3
"""Validate emulation Sigma detection files.

Usage:
    python validate_sigma.py                      # all emulations
    python validate_sigma.py "<glob>"             # a subset
    python validate_sigma.py "emulations/aws_persistence_*/detections/*.yml"

Requires PyYAML:  pip install pyyaml

ERRORS (exit 1) — mechanical faults that make a rule non-functional:
  * YAML that does not parse
  * a correlation referencing a `name:` that does not exist in the file
  * a malformed rule id (must be a plain-ASCII UUID)
  * duplicate rule ids across the corpus
  * a stale auto-derived TODO header

WARNINGS (exit 0) — judgement calls a human should confirm:
  * a bare `condition: selection` at medium-or-above severity with no
    discriminator beyond eventSource/eventName. Legitimate for genuinely rare
    administrative writes (EnableSerialConsoleAccess, CreateTrustAnchor,
    GuardDuty finding matches) — justify it in a comment above the rule.
  * a `level: low` rule whose description does not say it is a base rule
  * a correlation with no `timespan`
"""
import glob
import re
import sys
from collections import Counter

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required:  pip install pyyaml")

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
CORRELATION_TYPES = {"event_count", "value_count", "temporal", "temporal_ordered"}

pattern = sys.argv[1] if len(sys.argv) > 1 else "**/detections/*.yml"
files = sorted(glob.glob(pattern, recursive=True))

if not files:
    sys.exit(f"No files matched: {pattern}")

errors: list[str] = []
warnings: list[str] = []
all_ids: Counter = Counter()

for path in files:
    raw = open(path, encoding="utf-8").read()

    try:
        docs = [d for d in yaml.safe_load_all(raw) if d]
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{path}: YAML PARSE FAIL: {exc}")
        continue

    if "auto-derived" in raw and "not auto-derived" not in raw:
        errors.append(f"{path}: stale auto-derived TODO header still present")

    names = {d.get("name") for d in docs if d.get("name")}
    refs: set[str] = set()

    for d in docs:
        title = d.get("title", "<untitled>")

        if not d.get("title"):
            errors.append(f"{path}: a document has no title")

        rid = d.get("id")
        if rid:
            all_ids[rid] += 1
            if not UUID_RE.fullmatch(str(rid)):
                errors.append(f"{path}: malformed id {rid!r} (not a plain-ASCII UUID)")

        corr = d.get("correlation")
        if corr:
            refs |= set(corr.get("rules", []))
            ctype = corr.get("type")
            if ctype not in CORRELATION_TYPES:
                errors.append(f"{path}: '{title}' unknown correlation type {ctype!r}")
            if not corr.get("timespan"):
                warnings.append(f"{path}: '{title}' correlation has no timespan")
            if ctype == "value_count" and "field" not in (corr.get("condition") or {}):
                errors.append(
                    f"{path}: '{title}' value_count needs `field` INSIDE `condition`"
                )

        det = d.get("detection")
        if not det:
            continue

        level = d.get("level")
        cond = det.get("condition")

        # Sub-selection blocks referenced by the condition must exist as siblings.
        if isinstance(cond, str):
            for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", cond):
                if token in {"and", "or", "not", "all", "of", "them", "1", "any"}:
                    continue
                if token not in det:
                    errors.append(
                        f"{path}: '{title}' condition references '{token}' "
                        "which is not a sibling block under detection:"
                    )

        if cond == "selection" and level in ("medium", "high", "critical"):
            sel = det.get("selection", {}) or {}
            if not (set(sel) - {"eventSource", "eventName"}):
                warnings.append(
                    f"{path}: '{title}' is a bare condition:selection at "
                    f"level:{level} with no discriminator — justify or add one"
                )

        if level == "low":
            desc = (d.get("description") or "").lower()
            if "base rule" not in desc and "not for direct alerting" not in desc:
                warnings.append(
                    f"{path}: '{title}' is level:low but its description does "
                    "not say it is a base rule"
                )

    missing = refs - names
    if missing:
        errors.append(
            f"{path}: correlation references undefined rule name(s): {sorted(missing)}"
        )

    print(f"{len(docs):2d} docs  {path}")

dupes = {i: n for i, n in all_ids.items() if n > 1}
if dupes:
    errors.append(f"duplicate rule ids across corpus: {dupes}")

print()
if warnings:
    print(f"WARNINGS ({len(warnings)}) — confirm each is intentional:")
    for w in warnings:
        print("  ?", w)
    print()

if errors:
    print(f"ERRORS ({len(errors)}):")
    for e in errors:
        print("  x", e)
    sys.exit(1)

print(f"All {len(files)} file(s) OK" + (f" ({len(warnings)} warning(s))" if warnings else ""))
