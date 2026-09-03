# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, threshold, window, group-by keys and MITRE labels |
| Scope captured | One alert — `Snapshot Made Public` |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Window | Group-by | Source MITRE label |
|-------|----------|------|--------|----------|--------------------|
| Snapshot Made Public | P2 | threshold, `> 0` | 10m | `userIdentity.arn` | T1526/TA0010 |

A `logs_threshold` alert with a threshold of `0` is a per-event alert wearing a volume
shape: it fires on the first matching document in the window. The window and group-by
suppress repeats from one principal for ten minutes; they do not raise a bar.

## Merge decision — NO MERGE

Neither test in `07-TIERS.md` §"When merging is legitimate" applies, so this source rule
ships as its own playbook.

**Test 1 (same observable, same response, differing only in threshold or priority)** fails
on the observable. The nearest neighbour in the source set, `Database Instance/Cluster Made
Public`, matches `requestParameters.publiclyAccessible` on instance and cluster
create/modify calls. This rule matches `attributeName: restore` with a share-list value on
`ModifyDBSnapshotAttribute`. Different API, different field, different resource type — and
the responses diverge completely: one revokes a network exposure on a live endpoint and
leaves the data where it is, the other revokes a share on a **copy** of the data that a
third party may already hold. Neither is a threshold variant of the other.

**Test 2 (a FLOW rule that is purely the composition of building blocks already shipped)**
does not apply: this is not a correlation rule.

## Tier decision — TIER 1 (promoted)

Written at Tier 1 under `07-TIERS.md`. Three of the five promotion tests hold, and each is
load-bearing on a different part of the response:

**Test 3 — the blast radius is not in the event, and getting it after containment is
impossible.** The event's `requestParameters.valuesToAdd` names only what *this* call added.
The authoritative answer to "who can restore this snapshot right now" is the full attribute
list, which lives only in the live `DescribeDBSnapshotAttributes` state. Every account added
by an earlier call — inside or outside CloudTrail retention — is in that list and in no
event you still have.

**Test 4 — the evidence is destroyed by the remediation.** Removing the share is a
`ModifyDBSnapshotAttribute … --values-to-remove`, and once it lands the attribute list is
empty. The identity of everyone who held restore rights is gone with it. The enumeration
must therefore run **before** containment, which makes this test 2 as well: an ordering that
severs something a later step needs.

**Test 5 — a structural blind spot worth a page of honesty.** A foreign account that copies
or restores the shared snapshot does so with its own credentials; the API call is recorded
in *its* trail, not yours, and RDS raises no event and sends no notification to the owner.
There is no API that enumerates consumers. The playbook says so rather than implying the
absence of events is the absence of consumption.

Test 1 (account takeover one hop away) is **not** claimed. It holds only when the database
itself stores credentials for other systems, which is common but not structural, and the
playbook treats it as a conditional finding in the impact assessment rather than as the
grounds for promotion.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../rds.exfiltration.database-instancecluster-made-public/` | **Separate.** Different API, different field, different resource. Making a live instance reachable exposes the running database behind a network control you still own; sharing a snapshot hands out an offline full copy that leaves your control entirely. Containment, eradication and residual risk share nothing |
| `../../rds.stealth.database-instancecluster-was-created-with-no-encryption/` | **Separate, and a precondition.** A snapshot encrypted with the default `aws/rds` key cannot be shared at all, and a snapshot encrypted with a customer-managed key cannot be shared with `all`. The unencrypted-create use case is what makes this one reachable; it is a different observable with a different response, cross-referenced from §2 and §6 rather than merged |
| `../../rds.exfiltration.rds-snapshot-export/` | **Separate.** `StartExportTask` moves the data into S3 in your own account, where it stays under your controls and your logging. Sharing moves the restore right to a party outside your account. One response is an S3 exposure review, the other is a share revocation and a credential rotation |
| The source set's `RDS Snapshot Restored` alert | **Separate, and mostly blind here.** It matches restores in **your** account. The restore that matters after a public share happens in the consumer's account and never reaches your trail — see the residual-risk section of `../PLAYBOOK.md` |

## MITRE label dispute

The source labels this rule **T1526 / TA0010** — *Cloud Service Discovery*, paired with the
Exfiltration tactic. T1526 is live but wrong on the merits: making a snapshot restorable by
another account discovers nothing. The corrected primary is **T1537 — Transfer Data to Cloud
Account**, whose own description covers sharing a snapshot with an account the adversary
controls, and the secondary is **T1578.001 — Create Snapshot**, which is the first half of
the create-then-share chain the playbook's correlation looks for. The reasoning is in
`../PLAYBOOK.md` §6.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals
are packaged in a proprietary format whose scaffolding — payload field lists, entity labels,
product-specific field prefixes, internal enums and packaging metadata — identifies the
source on sight while bearing on nothing about whether the rules are correct. What is
retained is the complete detection logic: name, priority, type, MITRE label, the query
verbatim, threshold, window and group-by.

One artefact of that verbatim retention is worth flagging rather than editing away. The
query's third clause is `valueToAdd_Extracted:"all"` — **not a CloudTrail field**. It is a
parser-derived field produced upstream of the rule, so the rule is portable only to a
pipeline that produces it and is silently dead everywhere else. That is a detection defect,
it is recorded as such in `../PLAYBOOK.md` §2, and it is left in the extract because
removing it would make the quality note unauditable.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation
only — a deployed rule travels outside the organisation that wrote it, and an internal path
is not resolvable to whoever receives it.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
