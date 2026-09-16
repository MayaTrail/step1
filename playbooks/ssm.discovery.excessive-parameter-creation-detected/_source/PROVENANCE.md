# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, threshold, window, group-by keys and MITRE labels |
| Scope captured | One alert — the volume rule this playbook is written against |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alert captured

| Alert | Priority | Source MITRE label | Threshold | Window | Group-by |
|-------|----------|--------------------|-----------|--------|----------|
| Excessive Parameter Creation Detected | P4 | T1082 / TA0007 | 10 | 5m | `userIdentity.sessionContext.sessionIssuer.userName` |

## No merge

One source rule, one use case, one playbook — the default in `07-TIERS.md`.
Neither merge test applies.

The temptation here is merge test 1 against
`ssm.impact.parameter-deletion-detected`: both alerts fire on Parameter Store
writes to the same resource type, and the two could plausibly be read as "the
parameter changed". They are not the same observable — `PutParameter` and
`DeleteParameter*` are different APIs with different request shapes — and, more
decisively, the **response differs completely**. A poisoned parameter is compared
against its own version history and restored, and the consumers are restarted; a
deleted parameter has no history left to compare against and must be reconstructed
from an external source. Test 1 requires the same observable *and* the same
response.

The sibling `Excessive Document Creation Detected` alert shares this one's
threshold, window, group-by key, priority and MITRE label exactly, which is the
closest this set comes to a threshold variant — but again the observable and the
response are different, so it ships separately as
`ssm.discovery.excessive-document-creation-detected`.

## Tier

**Tier 2 (lean).** None of the five Tier-1 tests applies. Account takeover is not
one hop away — a poisoned parameter influences whatever reads it, which is an
application-level compromise, not an IAM one. The response has no ordering hazard
beyond pulling `get-parameter-history` before overwriting, which is one sentence.
The blast radius is in the events and in `DescribeParameters`'
`LastModifiedUser`. The evidence is not destroyed by the remediation, provided the
history is captured first — and the 100-version cap that could destroy it is a
property of the *attack*, not of the fix. The detection blind spot, whether the
parameter value reaches CloudTrail, is a paragraph.

## The source rule's MITRE label

Recorded in the extract as `T1082/TA0007` and disputed in §6 of `../PLAYBOOK.md`.
Writing a parameter discovers nothing; overwriting one is T1565.001 (*Data
Manipulation: Stored Data Manipulation*) under Impact (TA0040). One genuinely
Discovery-shaped signal does live in this use case — the `ParameterAlreadyExists`
name oracle — and it is tagged T1526 on its own rule rather than folded into the
primary mapping. The source label is carried in `original_rules.yml` so the
dispute is checkable against the extract.

## Directory naming

The slug preserves the source rule's own tactic label (`discovery`) so the
register stays navigable against the alert set, even though §6 disputes it. The
same convention is applied across all five Systems Manager use cases.

## Attribution and de-identification

**No source, vendor, product or repository is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim"
instruction (workflow step 0) deliberately. The originals are packaged in a
proprietary format whose scaffolding — payload field lists, entity labels,
product-specific field prefixes, internal enums and packaging metadata —
identifies the source on sight while bearing on nothing about whether the rules
are correct. What is retained is the complete detection logic: name, priority,
type, MITRE label, the Lucene query verbatim, threshold, window and group-by.
Every claim in the "Detection Rule Quality Notes" table in `../PLAYBOOK.md` §2 is
checkable against it.

One shared extractor change was needed for this alert family and is carried
corpus-wide: the extractor's alert-name prefix list had no entry for this service,
so the service-name prefix survived into the extract where every sibling family
has it stripped. The entry was added; the change is additive and regenerates every
existing extract unchanged.

The shipped `references:` blocks in `detections/` cite public MITRE and AWS
documentation only — a deployed rule travels outside the organisation that wrote
it, and an internal path is not resolvable to whoever receives it.

## A note on the file's shape

`threshold: 10.0  window: 5m` puts two mapping keys on one line and is therefore
not strictly parseable YAML — a corpus-wide property of the extractor's output
format, left alone rather than fixed here so this technique does not diverge from
the rest (rule E5). The file is read by people and diffed against the shipped
rules; nothing parses it.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
