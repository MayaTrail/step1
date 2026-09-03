# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The single "Multiple Tables Deleted" alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alert captured

| Alert | Priority | Type | Threshold | Window | Unique-count key | Source MITRE label |
|-------|----------|------|-----------|--------|------------------|--------------------|
| Multiple Tables Deleted | P3 | unique count | 5 (fires above) | 1m | `requestParameters.tableName` | T1490/TA0040 |

The threshold, window and keypath in that row are the evidence for two of the defects in
`../PLAYBOOK.md` §2, and they are in the extract only because the extractor was fixed first —
see the last section of this file. The alert's own prose describes "More than 5 in 10 minutes";
its configuration says more than 5 in **1** minute. Both figures are recorded so the
disagreement is auditable rather than asserted.

## Merge decision — no merge

This use case ships **on its own**. Both merge tests in `07-TIERS.md` §"When merging is
legitimate" were applied and both fail.

**Test 1 — same observable, same response, differing only in threshold or priority.** The
tempting pairing is `../../dynamodb.impact.multiple-tables-created/`, because the two alerts
are structurally identical twins: same alert type, same unique-count keypath
(`requestParameters.tableName`), same threshold, same window, and event names that differ only
in the verb. They are **not** a singular/plural pair and they are not merge candidates. They
match **different events** — `DeleteTable` and `CreateTable` — in **opposite directions**, and
the response to each is the opposite of the response to the other: here you restore what was
destroyed and there you remove what was created. Merging them would also commit the recurring
defect of bundling a `Create*` and a `Delete*` into one rule, which inverts the signal.

There is no volume-variant partner for this rule anywhere in the set, which is itself the
finding: the per-event case that test 1 would normally merge in **does not exist**, and
`../detections/sigma_t1485.yml` supplies it rather than inheriting it.

**Test 2 — a FLOW/correlation rule that is purely the composition of building blocks already
shipped.** Not applicable: the source rule is a standalone unique-count alert, not a flow rule.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../dynamodb.impact.multiple-tables-created/` | **Separate.** Identical rule *shape*, opposite event and opposite response. Not a singular/plural pair — see above |
| `../../dynamodb.stealth.deletion-protection-disabled/` | **Separate.** That is the precondition, this is the act. Joined by the `temporal_ordered` correlation shipped in that directory, which is how a sequence should be expressed |
| `../../dynamodb.impact.backup-was-deleted/` | **Separate.** Different observable (`DeleteBackup`), different blast radius (a recovery point, not the live data), different recovery path. Its base rule is duplicated into `../detections/sigma_t1485.yml` because a Sigma correlation can only resolve rules defined in the same file — that duplication is a Sigma packaging constraint, not a merge |
| `../../dynamodb.impact.table-items-modified-or-destroyed/` | **Separate.** Destroying rows and destroying the table are different events on different planes: item deletion is a CloudTrail **data** event, off by default, and `DeleteTable` is a management event logged by default. Nothing about the response is shared |

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals are
packaged in a proprietary format whose scaffolding — payload field lists, entity labels,
product-specific field prefixes, internal enums and packaging metadata — identifies the source
on sight while bearing on nothing about whether the rule is correct. What is retained is the
complete detection logic: name, priority, type, MITRE label, the query verbatim, threshold,
window, unique-count keypath and group-by.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation
only.

## A finding about the extractor, not about this rule

The shared extractor read the threshold and window only from the threshold-shaped alert keys.
The **unique-count** shape names both under its own keys — the count as a maximum rather than a
threshold, and the window under a differently-named field — so this extract originally emitted
`threshold: None  window: None`, leaving unauditable exactly the two numbers this playbook
disputes. The extractor also dropped the unique-count **keypath**, which is what makes a
threshold mean "5 distinct tables" rather than "5 events" — without it, the entire
distinct-versus-event argument in §2 rests on assertion. This is the same failure class the
tool's own inline comments already record for two other alert shapes. The extractor was fixed
to read both keys and to emit the keypath, and every extract in this batch was regenerated; the
change is additive, and regenerating an existing extract from another service produced a
byte-identical result. Reported upward rather than left in place.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
