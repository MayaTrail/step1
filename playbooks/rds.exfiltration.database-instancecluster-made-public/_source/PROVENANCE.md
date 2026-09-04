# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, threshold, window, group-by keys and MITRE labels |
| Scope captured | One alert — `Database Instance/Cluster Made Public` |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Window | Group-by | Source MITRE label |
|-------|----------|------|--------|----------|--------------------|
| Database Instance/Cluster Made Public | P2 | threshold, `> 0` | 10m | `userIdentity.arn` | T1530/TA0010 |

A `logs_threshold` alert with a threshold of `0` is a per-event alert wearing a volume
shape: it fires on the first matching document in the window.

## Merge decision — NO MERGE

Neither test in `07-TIERS.md` §"When merging is legitimate" applies.

**Test 1** fails on the observable. `Snapshot Made Public` is the only source rule with a
similar name, and it matches a different API (`ModifyDBSnapshotAttribute`), a different
field (`attributeName` plus a share-list value), and a different resource (an offline copy
rather than a live endpoint). Its response is a share revocation and a credential rotation;
this one's is a network-reachability teardown. Not a threshold variant.

**Test 2** does not apply: this is not a correlation rule. The source set does carry two
FLOW rules (`Destructive Action`, `Resource Discovery`), but neither composes this alert.

## Tier decision — TIER 2

None of the five promotion tests in `07-TIERS.md` holds. The blast radius **is** in the
event and in live state you still own after containment (`DescribeDBInstances` keeps
answering `PubliclyAccessible` and the attached security groups long after the flag is
flipped back), the remediation destroys no evidence, and the response has no ordering hazard
beyond the ordinary "contain the principal before you undo the change". The structural
honesty this use case needs — that the flag alone is not exposure — fits in §2's Quality
Notes and one investigation query, not a page.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../rds.exfiltration.snapshot-made-public/` | **Separate.** See above: offline copy versus live endpoint, and the snapshot leaves your control entirely while the instance never does |
| `../../rds.impact.rds-security-group-creation-or-deletion-legacy/` | **Separate, and the other half of the same exposure.** `PubliclyAccessible: true` is necessary but not sufficient — the security group is the second condition. That playbook covers the firewall half and this one covers the addressing half, and the two are cross-referenced in §2 and §3 rather than merged, because the containment differs: one revokes an ingress rule, the other flips an instance attribute and incurs a reboot-class modification |
| `../../_superseded/aws.initial-access.sg-remote-management-open/` | **Separate.** That playbook covers `ec2:AuthorizeSecurityGroupIngress` opening a management or database port to `0.0.0.0/0` on any resource. It is the generic firewall case; this one is the RDS-specific addressing case. Query 2 here reuses its shared reachability walk rather than restating it |
| The source set's `RDS Instance Creation` / `RDS Cluster Creation` alerts (P4) | **Separate.** They match every create with no exposure condition at all. Merging would drown the exposure signal in routine provisioning |

## MITRE label dispute

The source labels this rule **T1530 / TA0010** — *Data from Cloud Storage*, paired with the
Exfiltration tactic. Both halves are wrong. T1530 is live but its scope is object storage
(S3, Azure Storage, GCS); a relational database reached over its native wire protocol is not
that. And T1530's own tactic is Collection, not Exfiltration, so the pairing is internally
inconsistent. The corrected primary is **T1578.005 — Modify Cloud Compute Configurations**
(Defense Impairment), which is exactly what flipping `publiclyAccessible` is, with
**T1133 — External Remote Services** (Initial Access) as the genuine second mapping: an
internet-reachable database endpoint is an external remote service. **T1686.001 — Cloud
Firewall** covers the security-group half and is cited in §6 rather than tagged, because
this rule does not observe a firewall change. Reasoning in `../PLAYBOOK.md` §6.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals
are packaged in a proprietary format whose scaffolding identifies the source on sight while
bearing on nothing about whether the rules are correct. What is retained is the complete
detection logic: name, priority, type, MITRE label, the query verbatim, threshold, window
and group-by.

Two artefacts of that verbatim retention are recorded as defects in `../PLAYBOOK.md` §2
rather than edited away here. The query's event-name list includes
`CreateDBClusterFromSnapshot`, which is **not an RDS API action** — the real call is
`RestoreDBClusterFromSnapshot`, which also appears in the same list — so one disjunct is
dead. And the query carries **no success filter**: alone among the five RDS rules in this
batch that ought to have one, it omits `NOT _exists_:errorCode`, so a denied attempt fires
the same P2 as a successful exposure.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation
only — a deployed rule travels outside the organisation that wrote it, and an internal path
is not resolvable to whoever receives it.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
