# Detection Note — T1685.002 (Disable or Modify Tools: Disable or Modify Cloud Log)

**Signal:** `UpdateTable` — specifically the two settings that reduce what can be reconstructed
later, among seven the source rule treats identically.

## The name and the logic describe different things

The rule is called *Multiple Update Operation Performed* and matches `UpdateTable`, a control-plane
call. It has nothing to do with `UpdateItem`. A reviewer scanning the rule list would reasonably
conclude item updates were covered twice; they are covered once, in
`../../dynamodb.impact.table-items-modified-or-destroyed/`.

## Two of seven settings matter, and they arrive as the same alert

| Setting | Effect |
|---|---|
| `StreamSpecification.StreamEnabled` → false | The change record for every future item write is gone |
| `SSESpecification` changed | Who can read the table at rest changes; it stays "encrypted" throughout |
| throughput, indexes, table class | Operational |

**Streams is the one that matters most.** CloudTrail records that `UpdateItem` happened — it never
records what the item held before. DynamoDB Streams with a view type of `OLD_IMAGE` or
`NEW_AND_OLD_IMAGES` is frequently the only source of previous values, and that view type was chosen
when the stream was created, long before anyone needed it.

Disabling the stream does not delete what is already in it — but the stream's own retention is 24
hours, which is a much shorter window than most investigations.

## The autoscaling exclusion is correct and worth keeping

The rule excludes `userAgent:autoscaling.amazonaws.com`. Application Auto Scaling calls `UpdateTable`
continuously on any table with provisioned capacity and scaling policies, and without that exclusion
the rule would be pure noise.

That is a considered filter and it is the only one of its kind in this source set. It is kept
unchanged here.

## Response levers

**Check the stream view type before assuming recovery is possible.** A stream configured
`KEYS_ONLY` or `NEW_IMAGE` never carried previous values, so disabling it changed nothing about what
was recoverable — the loss happened at configuration time, years earlier.

**An encryption change is directional and the event does not say which way.** Moving *to* a
customer-managed key is an improvement and produces the same event as moving away from one.
`describe-table` gives the current state; the previous one comes from the event history.

**Deletion protection is owned elsewhere.** It appears in this call, but its consequence is
destruction rather than reduced visibility, so
`../../dynamodb.impact.table-items-modified-or-destroyed/` carries the response.

**`UpdateTable` is control-plane and logged by default** — unlike three of the five DynamoDB rules in
this source set. That is exactly why disabling Streams through it is quiet: the act is recorded, and
the consequence is that item history simply stops being kept.

**MITRE:** the source maps this to `T1505 — Server Software Component` under Persistence, the same
mapping it gives the item rules and equally wrong. `T1685.002 — Disable or Modify Cloud Log` is used
for the Streams case, since Streams is the change record for item writes; `T1600 — Weaken Encryption`
covers the SSE change. `T1578.005` was considered and set aside because DynamoDB is a managed data
store rather than compute. All verified live 2026-08-30.

**GuardDuty:** no finding type covers DynamoDB.

**Files here:**
- `sigma_t1685_002.yml` — four documents: `dynamodb_streams_disabled` (high),
  `dynamodb_table_encryption_changed` (high), `dynamodb_table_config_changed` (informational base
  rule, retaining the autoscaling exclusion), and an `event_count` correlation at five changes in ten
  minutes (medium).
- `kql_t1685_002.kql` — separates the seven settings, and states inline why Streams is the one that
  matters and why the autoscaling exclusion is load-bearing.

Full response procedure is in `../PLAYBOOK.md`.
