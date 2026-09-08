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
| High Number of SSM Parameters Retrieval | P3 | T1552 / TA0006 | 50 | 5m | `userIdentity.arn` |

## No merge

One source rule, one use case, one playbook — the default in `07-TIERS.md`.
Neither merge test applies: the four sibling Systems Manager alerts observe
different events with different responses, and none of them is a threshold
variant of this one. They ship as
`ssm.discovery.excessive-document-creation-detected`,
`ssm.discovery.excessive-parameter-creation-detected`,
`ssm.impact.parameter-deletion-detected` and
`ssm.initial-access.excessive-failed-document-retrieval-attempts`.

## Tier

**Tier 1 (full).** Promoted on test 1 of `07-TIERS.md` — *account takeover is
reachable in one further hop* — and test 3 also applies.

Test 1: `SecureString` parameters are where database passwords, third-party API
keys and long-lived tokens are kept. Bulk decryption hands the actor working
credentials to systems outside AWS's own authorisation boundary, and any IAM
access key stored as a parameter is a direct further hop. The credential-theft
case is named explicitly in that test.

Test 3: the blast radius is not in the event. `GetParametersByPath` returns up
to ten parameters per call and the response is not logged, so the set of
disclosed parameters has to be reconstructed from `DescribeParameters` at
response time or from the `PARAMETER_ARN` encryption context on the paired
`kms:Decrypt` events. `DescribeParameters` answers *as of now*, so once the
hierarchy is edited — including by the remediation — the answer stops being
recoverable.

## The source rule's MITRE label

Recorded in the extract as `T1552/TA0006` and disputed in §6 of
`../PLAYBOOK.md`. T1552 (*Unsecured Credentials*) is the parent family;
T1555.006 (*Credentials from Password Stores: Cloud Secrets Management Stores*)
is the precise fit. The label is carried in `original_rules.yml` so the dispute
is checkable against the extract rather than taken on the playbook's word.

## Directory naming

The slug preserves the source rule's own tactic label (`credential-access`) so
the register stays navigable against the alert set. Here the source label and
the corrected mapping agree on the tactic; where they do not — the two
`ssm.discovery.*` use cases and `ssm.initial-access.*` — the slug still carries
the source label and §6's mapping note carries the correction.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this
project — including this one.**

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
corpus-wide: the extractor's alert-name prefix list had no entry for this
service, so the service-name prefix was surviving into the extract where every
sibling family has it stripped. The entry was added; the change is additive and
regenerates every existing extract unchanged.

The shipped `references:` blocks in `detections/` cite public MITRE and AWS
documentation only — a deployed rule travels outside the organisation that wrote
it, and an internal path is not resolvable to whoever receives it.

## A note on the file's shape

`threshold: 50.0  window: 5m` puts two mapping keys on one line and is therefore
not strictly parseable YAML — a corpus-wide property of the extractor's output
format, left alone rather than fixed here so this technique does not diverge
from the rest (rule E5). The file is read by people and diffed against the
shipped rules; nothing parses it.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.
