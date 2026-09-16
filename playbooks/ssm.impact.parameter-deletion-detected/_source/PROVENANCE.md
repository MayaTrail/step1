# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, type, group-by keys and MITRE labels |
| Scope captured | One alert — the immediate-type rule this playbook is written against |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alert captured

| Alert | Priority | Type | Source MITRE label | Threshold | Group-by |
|-------|----------|------|--------------------|-----------|----------|
| Parameter Deletion Detected | P3 | `logs_immediate` | T1485 / TA0040 | none — fires on every match | none |

The absence of a threshold and of a group-by key is recorded deliberately: both
are findings, and §2 of `../PLAYBOOK.md` argues from them. An immediate-type alert
carries a query and no volume condition at all, so "no threshold" here is the
extractor reporting a fact rather than dropping a field.

## No merge

One source rule, one use case, one playbook — the default in `07-TIERS.md`.
Neither merge test applies. The closest candidate is
`ssm.discovery.excessive-parameter-creation-detected`, which touches the same
resource type, but `PutParameter` and `DeleteParameter*` are different observables
and the responses diverge completely: a poisoned parameter is diffed against its
own version history and restored, while a deleted parameter has no history left to
diff and must be reconstructed from an external source. Test 1 requires the same
observable *and* the same response.

## Tier

**Tier 2 (lean).** Test 4 of `07-TIERS.md` — *the evidence is destroyed by the
remediation* — is the one worth examining, and it does not apply: the evidence is
destroyed by the **attack**, before any responder acts, and nothing in the response
destroys anything further. That is a different situation, and it makes the playbook
shorter rather than longer, because there is no forensic ordering to get right and
no window to race. The other four tests fail plainly: no account takeover is one
hop away, the response has no severing step, the blast radius is enumerable from
the events plus `DescribeParameters`, and the detection's blind spots — the
unlogged `ParameterNotFound` and the policy-driven expiry — are two paragraphs, not
a page.

## The source rule's MITRE label

Recorded in the extract as `T1485/TA0040`, and it is **correct** — the only one of
the five Systems Manager alerts whose mapping needs no dispute. `../PLAYBOOK.md` §6
says so rather than passing over it, because a corpus that only ever reports
mapping errors reads as though it never checks the ones that are right.

## Directory naming

The slug carries the source rule's tactic label (`impact`), which here agrees with
the corrected mapping. The same convention is applied across all five Systems
Manager use cases; where the labels disagree — the two `ssm.discovery.*` use cases
and `ssm.initial-access.*` — the slug still keeps the source label and §6 carries
the correction.

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

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
