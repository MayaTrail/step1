# Amazon DynamoDB — verified service behaviour

Audited 2026-08-30 against AWS documentation. Every claim below is quoted or directly derived from
a cited page. Shared by every `dynamodb.*` playbook; do not restate it in each one.

Source: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html

---

## 1. Three of the five source rules depend on data events, which are off by default

AWS splits DynamoDB's CloudTrail coverage explicitly.

**Control plane — "logged by default":** `CreateTable`, `UpdateTable`, `DeleteTable`, `CreateBackup`,
`DeleteBackup`, `RestoreTableFromBackup`, `RestoreTableToPointInTime`, `UpdateTimeToLive`,
`ListTables`, `DescribeTable`, `TagResource`, and the DAX and Streams describe/list operations.

**Data plane — "you must enable logging of data plane API activity in CloudTrail":** `GetItem`,
`PutItem`, `UpdateItem`, `DeleteItem`, `BatchGetItem`, `BatchWriteItem`, `Query`, `Scan`,
`TransactGetItems`, `TransactWriteItems`, plus the Streams `GetRecords` and `GetShardIterator`.

So the source rules for item deletion, item update and table scanning are **inert unless DynamoDB
data events were purchased**, and none of them says so. A responder reading "no results" from any of
those three cannot distinguish "it did not happen" from "it was never recorded".

## 2. PartiQL is a complete bypass of any item-level rule

The same operations are reachable under entirely different event names:

| Classic API | PartiQL equivalent |
|---|---|
| `PutItem` / `UpdateItem` / `DeleteItem` | **`ExecuteStatement`** |
| batched writes | **`BatchExecuteStatement`** |
| `TransactWriteItems` | **`ExecuteTransaction`** |

AWS states CloudTrail captures calls *"using both PartiQL and the classic API"*. A rule matching
`DeleteItem` or `UpdateItem` sees none of the PartiQL forms, and a `DELETE FROM` issued through
`ExecuteStatement` does exactly the same thing. All three PartiQL names are data-plane events too, so
they carry the same enablement precondition.

## 3. TTL deletions are invisible, and the configuration change is not

> **DynamoDB Time to Live data plane actions are not logged by CloudTrail**

This is the sharpest finding in the service. An actor who sets a short TTL attribute causes DynamoDB
to delete items in bulk, on its own schedule, **producing no CloudTrail record of any deletion at
all** — not a data event, not a management event, nothing.

What *is* logged is `UpdateTimeToLive`, a control-plane event on by default. So the configuration
change is detectable and its consequence is not, which makes the change itself the only opportunity.
This is structurally identical to the ECR lifecycle-policy case in `../_ground-truth/ecr.md` §5.

## 4. Data-event volume is inflated by AWS's own internal traffic

> When you log `GetRecords` data events, you might see `GetRecords` calls from DynamoDB internal
> operations, such as global tables replication. Although you are not charged by DynamoDB for these
> `GetRecords` calls, **you are charged by CloudTrail for the data event logs.**

AWS's remedy: the *Exclude AWS service-initiated events* selector template, or an advanced selector
filtering `userIdentity.arn` `NotStartsWith` `AWSServiceRoleFor`. Worth knowing before recommending
data events be turned on — the cost objection is real and has a documented answer.

Note also that selecting `AWS::DynamoDB::Table` as a data resource type **logs stream events too by
default**; excluding them needs an explicit additional filter.

## 5. `createtable` is not an event name

The `Multiple Tables Created` rule matches `eventName:"createtable"`. CloudTrail emits `CreateTable`.
On a case-sensitive field the lowercase form matches nothing — the same defect class found in the
ECR, KMS and Secrets Manager source rules, and the ninth instance across this source set.

## 6. `UpdateTable` is not an item update

The rule named `Multiple Update Operation Performed` matches `UpdateTable` — a **control-plane**
call that changes throughput, indexes, stream settings or deletion protection. It has nothing to do
with `UpdateItem`, which is the data-plane operation its name suggests. The rule is correct about
what it matches and misleading about what it is called, and a reviewer scanning the rule list would
reasonably believe item updates were covered twice.

## 7. Recovery exists, and depends on configuration made beforehand

- **Point-in-time recovery (PITR)** allows `RestoreTableToPointInTime` to any second in the retention
  window. Off by default per table.
- **On-demand backups** via `CreateBackup` / `RestoreTableFromBackup`.
- **Deletion protection** blocks `DeleteTable` outright.

All three are control-plane and logged by default, so their *removal* is detectable — and their
absence is what turns an item-destruction incident from recoverable into permanent.

---

## MITRE currency, verified 2026-08-30

| ID | Status | Name | Tactic |
|---|---|---|---|
| `T1485` | live | Data Destruction | Impact |
| `T1565` | live | Data Manipulation | Impact |
| `T1565.001` | live | Data Manipulation: Stored Data Manipulation | Impact |
| `T1530` | live | Data from Cloud Storage | Collection |
| `T1496` | live | Resource Hijacking | Impact |
| `T1578.005` | live | Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations | Defense Evasion |

The source pack maps every item rule to `T1505 — Server Software Component` under Persistence, which
is about web shells and server software modules and has nothing to do with writing rows to a table.
It maps table scanning to `T1596 — Search Open Technical Databases`, a **Reconnaissance** technique
about public sources such as WHOIS and passive DNS — scanning your own DynamoDB table is not that.
Both are among the worst mappings in this source set.
