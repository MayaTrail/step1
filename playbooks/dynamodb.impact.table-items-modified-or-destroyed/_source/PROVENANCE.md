# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rules over query strings |
| Scope captured | Two rules: A Table Item Was Deleted, A Table Item Was Updated |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

**Merge test — applied, not assumed. Two source rules, one use case.** Item deletion and item
modification are the same operation class against the same resource, they share the same
data-event precondition, and they share a response — establish what changed, restore from PITR,
contain the principal. They are shipped as separate rules within one directory because the recovery
differs in detail (a deletion is restored; a modification needs the previous values, which usually
means DynamoDB Streams), but the procedure is one.

**Both rules are data-plane and neither says so.** AWS splits DynamoDB's CloudTrail coverage
explicitly: `DeleteItem`, `BatchWriteItem`, `UpdateItem` and `TransactWriteItems` are data-plane
events, and *"to enable logging of the following API actions in CloudTrail files, you must enable
logging of data plane API activity in CloudTrail."* Data events are off by default and billable. So
**both source rules are inert in a default account**, and a responder reading no results from them
cannot distinguish "it did not happen" from "it was never recorded".

**So the routable detections here are the control-plane preconditions**, which are logged by default
and which decide whether destruction is recoverable at all: `UpdateContinuousBackups` disabling
point-in-time recovery, `UpdateTable` removing deletion protection, and `UpdateTimeToLive`. Those
fire in every account. The item rules ship alongside them, rated lower, and say plainly what they
require.

**PartiQL is a complete bypass of any item-level rule.** The same writes are reachable as
`ExecuteStatement`, `BatchExecuteStatement` and `ExecuteTransaction` — AWS states CloudTrail captures
calls *"using both PartiQL and the classic API"*. A `DELETE FROM` issued through `ExecuteStatement`
does exactly what `DeleteItem` does and matches neither source rule. All three names are included
here.

**And TTL deletions are never logged.** AWS: *"DynamoDB Time to Live data plane actions are not
logged by CloudTrail."* No data event, no management event, nothing — even with data events fully
enabled. An actor who sets a short TTL causes bulk deletion leaving only the `UpdateTimeToLive`
configuration event behind, which is why that ships at high and why the playbook reads the affected
item population rather than waiting for deletions that will never appear.

**A smaller defect worth recording:** both rules filter on `NOT _exists_:errorMessage` rather than
`errorCode`. CloudTrail's canonical failure field is `errorCode`; `errorMessage` is not always
present on a failure, so the filter admits some failed calls as successes.

**MITRE:** the source maps both rules to `T1505 — Server Software Component` under **Persistence**.
That technique is about web shells and server software modules and has nothing to do with writing
rows to a table. `T1485 — Data Destruction` for deletion and `T1565.001 — Stored Data Manipulation`
for modification are the correct mappings. All verified live 2026-08-30.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `dynamodb.*` playbook is in `../../_ground-truth/dynamodb.md`, audited
2026-08-30. §1 covers the control/data plane split, §2 PartiQL and §3 the TTL blind spot.
