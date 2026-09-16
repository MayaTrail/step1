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
| Excessive Document Creation Detected | P4 | T1082 / TA0007 | 10 | 5m | `userIdentity.sessionContext.sessionIssuer.userName` |

## No merge

One source rule, one use case, one playbook — the default in `07-TIERS.md`.
Neither merge test applies. The sibling `Excessive Parameter Creation Detected`
alert shares this one's threshold, window, group-by key and MITRE label, which
makes merge test 1 tempting, but the observable is a different API on a different
resource and the **response is entirely different**: a document is a payload you
inspect, dispatch-check and delete, while a parameter is configuration you compare
against a known-good value and restore. Test 1 requires the same observable *and*
the same response. They ship separately as this directory and
`ssm.discovery.excessive-parameter-creation-detected`.

## Tier

**Tier 2 (lean).** None of the five Tier-1 tests applies. Account takeover is not
one hop away — the document runs with the permissions of the node's instance
profile or the automation's `assumeRole`, which is a host- and role-scoped blast
radius, not an account one. The response has no ordering hazard beyond capturing
the content before deleting the document, which is one sentence. The blast radius
*is* in the events: `SendCommand`, `StartAutomationExecution`, `StartSession` and
`CreateAssociation` are all management events naming the document, so what ran and
where is directly queryable. The remediation destroys no evidence provided the
content is captured first. And the detection blind spot — whether
`requestParameters.content` is recorded — is a paragraph, not a page.

## The source rule's MITRE label

Recorded in the extract as `T1082/TA0007` and disputed in §6 of `../PLAYBOOK.md`.
Creating an SSM document discovers nothing; it stages a payload for execution
through a cloud management service, which is T1651 (*Cloud Administration
Command*) under Execution (TA0002). The label is carried in `original_rules.yml`
so the dispute is checkable against the extract rather than taken on the
playbook's word.

## Directory naming

The slug preserves the source rule's own tactic label (`discovery`) so the
register stays navigable against the alert set, even though §6 disputes it. The
same convention is applied across all five Systems Manager use cases; where the
source label and the corrected mapping agree — as they do for
`ssm.credential-access.*` and `ssm.impact.*` — nothing needs saying.

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
