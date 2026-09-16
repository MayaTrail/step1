# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The four Lambda alerts touching function permissions and configuration |
| Retrieved | 2026-08-28 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | MITRE carried |
|-------|----------|---------------|
| Resource-based Policy Modified by IAM User | P4 | T1584 / TA0042 |
| IAM Policy Was Configured | P3 | none |
| Function Modified by IAM User | P4 | T1584 / TA0042 |
| Settings of a Lambda Function Modified | P4 | T1584 / TA0042 |

The first two are this technique. The last two are adjacent and belong elsewhere:
`UpdateFunctionCode` is the code-overwrite technique worked in `reference/PLAYBOOK.md`,
and `UpdateFunctionConfiguration` is the layer/environment tampering route. They are kept
in the extract because the defect analysis in `../PLAYBOOK.md` §2 cites them as internal
evidence — they match the event name with a trailing `.*` that absorbs the CloudTrail
version suffix, which the two rules for this technique do not, and that inconsistency is
checkable only if all four are present.

The alert named *IAM Policy Was Configured* does not concern an IAM identity policy. It
matches `AddPermission` / `RemovePermission` on `lambda.amazonaws.com`, which are
**resource**-based policy operations. The name will send a responder to
`list-user-policies` and the IAM console, where nothing will be found. That is recorded as
a defect row rather than corrected silently in the extract.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project
— including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately. The originals are packaged in a proprietary format whose
scaffolding — payload field lists, entity labels, product-specific field prefixes,
internal enums and packaging metadata — identifies the source on sight while bearing on
nothing about whether the rules are correct. What is retained is the complete detection
logic: name, priority, type, MITRE labels, the Lucene query verbatim, threshold, window
and group-by. Every claim in the "Detection Rule Quality Notes" table in `../PLAYBOOK.md`
§2 is checkable against it.

The extract was produced by the shared de-identifying extractor, not by hand, so that the
retained fields are the same set every technique in this project retains.

The shipped `references:` blocks in `detections/` cite public MITRE and AWS documentation
only — a deployed rule travels outside the organisation that wrote it, and an internal
path is not resolvable to whoever receives it.

**Merge test — applied, not assumed. Two source rules, one use case.** `Resource-based Policy
Modified by IAM User` and `IAM Policy Was Configured` both match `AddPermission` / `RemovePermission`
on `lambda.amazonaws.com` — the same operation on the same resource, differing only in that one adds
a `userIdentity.type:"IAMUser"` filter and the other does not. They share a response entirely, so
they merge; the identity filter is a defect corrected here rather than a distinction worth a second
playbook.

**Two further source rules were removed from this directory rather than merged.** They were carried
in `_source/` with no corresponding detection, which is a quieter failure than aggregation — the
scope looked covered and was not. `UpdateFunctionCode` is now
`../../lambda.persistence.function-code-overwritten/` and `UpdateFunctionConfiguration` is now
`../../lambda.defense-evasion.function-configuration-modified/`. Changing a function's code, its
configuration, and who may invoke it are three techniques with three different responses.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.
