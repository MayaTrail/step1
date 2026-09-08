# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The single cluster-deletion alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Threshold | Group-by | Source MITRE label |
|-------|----------|------|-----------|----------|--------------------|
| Cluster Is Deleted | P1 | threshold | `> 0` in 10m | `userIdentity.arn` | T1578/TA0005 |

## Merge decision — no merge

**One source rule, one playbook.** Neither of `07-TIERS.md`'s two merge tests is met by any
other rule in the source set, and the tests were applied rather than assumed:

| Candidate | Test 1 — same observable, same response, differing only in threshold? | Test 2 — pure composition of shipped building blocks? | Verdict |
|-----------|------|------|---------|
| `../../ecs.stealth.service-is-deleted/` | **No.** Different event (`DeleteService` vs `DeleteCluster`), different request shape, and — decisively — a different **position in the kill chain**: ECS refuses `DeleteCluster` while the cluster still holds active services, registered container instances or running tasks, so a *successful* cluster deletion proves the services were already gone. The service deletion is the destructive act; the cluster deletion is the tidy-up behind it. Containment differs (there is nothing left running to scale down), eradication differs (a cluster is recreated in one call, a service is not) and residual risk differs | No | **Separate** |
| `../../ecs.stealth.service-is-created/` | No — opposite direction, and the response is to remove a resource rather than restore one | No | **Separate** |

The source rule's own `threshold: > 0 in 10m` grouped by `userIdentity.arn` is a per-event
rule wearing volume clothing: any count above zero fires, so the window and threshold add
nothing except a ten-minute batching delay on a P1. That is a defect recorded in
`../PLAYBOOK.md` §2, not a second observable that could justify a merge.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `Deregister`/`StopTask` activity that must precede a successful `DeleteCluster` | **Not a source rule at all.** The source set carries no alert on `DeregisterContainerInstance`, `StopTask` or `DeregisterTaskDefinition`, so there is nothing to merge — it is a **coverage gap**, and it is recorded as one in `../PLAYBOOK.md` §2 and §6. The gap matters here specifically because those calls are where the destruction actually happens |
| The source set's `RegisterTaskDefinition` alert | **Separate, and out of scope for this batch.** It matches only resource magnitude (`cpu`/`memory` digit counts) and never inspects `image`, `command` or `taskRoleArn`, so the persistence path a task definition really provides is uncovered. Recorded as a gap in `../PLAYBOOK.md` §6 |

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project
— including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals
are packaged in a proprietary format whose scaffolding — payload field lists, entity
labels, product-specific field prefixes, internal enums and packaging metadata —
identifies the source on sight while bearing on nothing about whether the rules are
correct. What is retained is the complete detection logic: name, priority, type, MITRE
label, the query verbatim, threshold, window and group-by.

No substitution was needed in this extract.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS
documentation only — a deployed rule travels outside the organisation that wrote it, and
an internal path is not resolvable to whoever receives it.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
