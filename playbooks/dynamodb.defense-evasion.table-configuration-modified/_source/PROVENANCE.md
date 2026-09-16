# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One rule: Multiple Update Operation Performed |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

**The rule's name and its logic describe different things.** It is called *Multiple Update Operation
Performed* and it matches `UpdateTable` — a **control-plane** call changing throughput, indexes,
stream settings, encryption and deletion protection. It has nothing to do with `UpdateItem`, the
data-plane operation the name suggests. A reviewer scanning the rule list would reasonably conclude
that item updates were covered twice; they are covered once, in
`../../dynamodb.impact.table-items-modified-or-destroyed/`.

**It has no content check on a call that changes seven different things.** The two that matter to a
defender:

- **`StreamSpecification.StreamEnabled` → false.** DynamoDB Streams is frequently the only record of
  what an item held *before* it was modified — CloudTrail records that `UpdateItem` happened, never
  the previous values. Disabling the stream removes that for every future write.
- **`SSESpecification` changed.** Moving off a customer-managed KMS key removes the ability to revoke
  access by disabling the key, and removes the KMS grant trail showing who decrypted. The table stays
  encrypted throughout, so a compliance check still passes.

A throughput adjustment and a stream being switched off arrive as the same alert.

**What it gets right, and it is the only one of its kind in this source set:** it excludes
`userAgent:autoscaling.amazonaws.com`. Application Auto Scaling calls `UpdateTable` continuously on
any table with provisioned capacity and scaling policies, and without that exclusion the rule would
be pure noise. That is a considered filter and it is kept here unchanged.

**`UpdateTable` is control-plane and logged by default**, unlike three of the five DynamoDB source
rules. That is exactly why disabling Streams through it is quiet: the act is recorded, and the
consequence is that item history simply stops being kept.

**MITRE:** the source maps this to `T1505 — Server Software Component` under Persistence, the same
mapping it applies to the item rules, and it is equally wrong — that technique is about web shells
and server modules. `T1685.002 — Disable or Modify Cloud Log` is used here for the Streams case:
Streams is the change record for item writes, and removing it is removing the log of what happened.
`T1600 — Weaken Encryption` covers the SSE change. Both verified live 2026-08-30. `T1578.005 —
Modify Cloud Compute Configurations` was considered and set aside because DynamoDB is a managed data
store rather than compute.

**Merge test:** not applicable — one source rule, one use case. Deletion protection appears in both
this directory and `../../dynamodb.impact.table-items-modified-or-destroyed/`; that directory owns it,
because its consequence is destruction rather than reduced visibility, and this one cross-references
rather than duplicating the response.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `dynamodb.*` playbook is in `../../_ground-truth/dynamodb.md`, audited
2026-08-30. §6 covers the name/logic mismatch.
