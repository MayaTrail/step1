# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The single "Deletion Protection Disabled" alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alert captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| Deletion Protection Disabled | P3 | per-event | — |

The currency gate exempts
`original_rules.yml` for exactly this reason: an extract records what the source actually
said, and rewriting the label there would destroy the evidence for the mapping dispute in
`../PLAYBOOK.md` §6.

## Merge decision — no merge

This use case ships **on its own**, as its own directory. Both merge tests in
`07-TIERS.md` §"When merging is legitimate" were applied and both fail.

**Test 1 — same observable, same response, differing only in threshold or priority.** The
nearest candidate is `../../dynamodb.defense-evasion.table-configuration-modified/`, and
the temptation is real: both source rules match the **identical event name**,
`eventName:"UpdateTable"`, at the same priority (P3). They are still two use cases, and the
reason is that a shared event name is not a shared observable. This rule requires
`requestParameters.deletionProtectionEnabled` to be present *and* false; the volume rule
matches `UpdateTable` with that field absent as readily as present. The two never describe the
same event shape — one is a strict subset defined by a field the other never reads.

The **response test** is what settles it, and it settles it decisively. Here the response is
to re-enable deletion protection on the named table, confirm the table still exists, and hunt
for the `DeleteTable` that the disable was preparing for. There, the response is to enumerate
*which* parameter each `UpdateTable` changed — capacity, encryption key, Streams, or a
cross-Region replica — because the volume rule cannot say, and each answer leads to a
different remediation. Different containment, different eradication, different residual risk.
Test 1 explicitly excludes that: "If the *response* differs at all — different containment,
different eradication — they are two use cases."

**Test 2 — a FLOW/correlation rule that is purely the composition of building blocks already
shipped.** Not applicable: this source rule is a per-event alert, not a flow rule, and it
introduces an observable (the parameter value) that no other rule in the set inspects.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../dynamodb.defense-evasion.table-configuration-modified/` | **Separate.** Same event name, different observable and different response — see above. The relationship is documented as a cross-reference in both playbooks instead |
| `../../dynamodb.impact.multiple-tables-deleted/` | **Separate.** That use case is the destruction; this one is the precondition. They are joined by the `temporal_ordered` correlation shipped in `../detections/sigma_t1685.yml`, which is the correct way to express a sequence — not by collapsing two observables into one playbook |
| `../../dynamodb.impact.backup-was-deleted/` | **Separate.** Also a precondition for unrecoverable destruction, but by a different mechanism (removing the recovery point rather than the guard), with a different containment and a different recovery path |

## A finding about the extractor, not about this rule

The shared extractor read the threshold and window only from the threshold-shaped alert keys.
The **unique-count** shape names both under its own keys (`maxUniqueCount`, and a distinct
time-window key), so for every fan-out alert in this set the extract emitted
`threshold: None  window: None` — silently unauditable for exactly the rules whose threshold
is the thing under dispute. This is the same failure class the tool's own inline comments
already record twice, in a third shape. The extractor was fixed to read the unique-count keys
and to emit the unique-count **keypath**, which is what makes a threshold mean "5 distinct
tables" rather than "5 events", and every extract in this batch was regenerated. The fix is
additive; regenerating an existing extract from another service produced a byte-identical
result. Reported upward rather than left in place.

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
only — a deployed rule travels outside the organisation that wrote it, and an internal path is
not resolvable to whoever receives it.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
