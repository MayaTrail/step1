# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, threshold, window, group-by keys and MITRE labels |
| Scope captured | One alert — `RDS Security Group Creation OR Deletion (Legacy)` |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Window | Group-by | Source MITRE label |
|-------|----------|------|--------|----------|--------------------|
| RDS Security Group Creation OR Deletion (Legacy) | P2 | threshold, `> 0` | 10m | `userIdentity.arn`, `eventName` | — |

## The central finding: this rule cannot fire

The rule matches `CreateDBSecurityGroup` or `DeleteDBSecurityGroup` **and requires the absence of
an error code**. Those APIs manage **DB security groups**, an EC2-Classic construct. AWS carries
the same note verbatim on `CreateDBSecurityGroup`, `DeleteDBSecurityGroup`,
`DescribeDBSecurityGroups`, `AuthorizeDBSecurityGroupIngress` and the CloudFormation resource:
*"A DB security group controls access to EC2-Classic DB instances that are not in a VPC"* and
*"EC2-Classic was retired on August 15, 2022."*

`CreateDBSecurityGroup` documents the error **`DBSecurityGroupNotSupported`** (400) — *"A DB
security group isn't allowed for this action"* — which is what a VPC-only account gets, and every
account created since the retirement is VPC-only. The rule's success filter therefore excludes the
only outcome the API can produce. `DeleteDBSecurityGroup` can only succeed against a DB security
group that exists, and none can be created.

**What could not be verified:** AWS publishes no statement that the operation *always* fails now,
and this analysis had no AWS account in which to test a 2026 call. An account with a surviving
EC2-Classic estate might still succeed. That uncertainty is recorded in `../PLAYBOOK.md` §2 rather
than resolved by assumption, and the shipped rules are written to fire on the **call** rather than
on its success — correct under either reading.

The use case is therefore shipped, not skipped, but **inverted**: in an account with no EC2-Classic
estate, a `CreateDBSecurityGroup` call in 2026 is worth seeing *because* nothing legitimate emits
it, and the playbook also covers the observable the source rule was reaching for and does not have
— `ModifyDBInstance` replacing a database's VPC security groups.

## Merge decision — NO MERGE

Neither test in `07-TIERS.md` §"When merging is legitimate" applies.

**Test 1** fails on the observable. No other rule in the source set touches the DB security group
APIs. The set's `Building Block - DB Security Groups Viewed` matches `DescribeDBSecurityGroups`,
which is the read half of the same retired construct — a closer relative than anything else here —
and it is still a different observable with a different response: enumeration produces nothing to
remediate, while a successful mutation would mean this account has an EC2-Classic estate. It is
shipped as an `informational` base rule inside this playbook's Sigma rather than merged, which is
the treatment `07-TIERS.md` prescribes for a component that feeds a correlation.

**Test 2** does not apply: this is not a correlation rule. The set's `Resource Discovery` FLOW rule
does compose the DB-security-groups-viewed building block with others, but it is a discovery
correlation over five unrelated read APIs and adds no observable this playbook covers.

## Tier decision — TIER 2

None of the five promotion tests holds, and the legacy half of the use case is close to having no
response at all. The modern half — a database's security groups being replaced — has blast radius
that is readable from live state after containment, no ordering hazard, and no evidence destroyed
by the remediation. The one thing that would have argued for Tier 1, a structural blind spot worth
a page of honesty, is real but is about the *source rule* rather than about the technique, and it
fits in §2's Quality Notes.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| The source set's `Building Block - DB Security Groups Viewed` | **Not merged, shipped as a component.** Different observable (read vs mutate) and no response of its own. It ships as the `rds_legacy_dbsecuritygroup_read_bb` base rule and feeds the enumerate-then-call correlation |
| `../../_superseded/aws.initial-access.sg-remote-management-open/` | **Separate, and it owns the other half.** That playbook covers `ec2:AuthorizeSecurityGroupIngress` — the rules *inside* a security group — including port-range containment and the nested `ipPermissions.items[]` request form. This one covers which groups are *attached* to a database. Cross-referenced from §2 and §3 rather than duplicated |
| `../../rds.exfiltration.database-instancecluster-made-public/` | **Separate, and the complementary condition.** A database is reachable only when it is publicly addressable **and** a permitting group is attached. That playbook owns the addressing half and this one the attachment half; the containment differs and so does the eradication |

## MITRE label dispute

It was re-parented in the same restructure and is now
**T1686.001 — Disable or Modify System Firewall: Cloud Firewall**, under the new **Defense
Impairment** tactic. That is the corrected primary and it is the ID the corpus already uses in
`../../_superseded/aws.initial-access.sg-remote-management-open/`.
**T1578.005 — Modify Cloud Compute Configurations** is the second mapping for the modern half. The
directory's `impact` segment tracks the source's tactic label, not the corrected one.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction (workflow
step 0) deliberately, for the reason given in the authoring brief: the originals are packaged in a
proprietary format whose scaffolding identifies the source on sight while bearing on nothing about
whether the rules are correct.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation only —
a deployed rule travels outside the organisation that wrote it, and an internal path is not
resolvable to whoever receives it.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
