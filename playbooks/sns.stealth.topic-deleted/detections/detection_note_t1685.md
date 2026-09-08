# Detection Note — T1685 (Disable or Modify Tools)

**Signal:** `DeleteTopic` — and specifically, whether the topic was carrying alerts.

A currency check that tests reachability passes
it; only a check comparing the ID against a name catches it.

The redirect target, `T1685 — Disable or Modify Tools`, is the correct parent. `T1489 — Service Stop`
covers the availability half.

## Nothing tells you the notification went nowhere

> "CloudWatch doesn't test or validate the actions that you specify, nor does it detect any Amazon EC2
> Auto Scaling or Amazon SNS errors resulting from an attempt to invoke nonexistent actions. Make sure
> that your alarm actions exist."

The alarm still evaluates. It still transitions to `ALARM`. It still reports itself as healthy in the
console. The notification is dropped, silently, with no error anywhere — which is what makes this a
stealth technique rather than an outage, and why the source rule's P4 is wrong.

One topic is frequently the path for CloudWatch alarms, GuardDuty finding notifications, Config rules,
Security Hub and Budgets at once. Deleting it removes several independent controls in one call.

## The call cannot fail

AWS: "This action is **idempotent**, so deleting a topic that does not exist does not result in an
error."

Combined with the source rule's `NOT _exists_:errorCode` filter, an actor spraying guessed ARNs
produces a stream of alerts that all look like successful deletions. A responder counting them will
overstate the damage. The only way to separate them is an inventory of which topics existed.

## Recovery is not recreating the topic

`DeleteTopic` "deletes a topic **and all its subscriptions**". Every subscription must be recreated,
and email and HTTP/S endpoints must be **re-confirmed by the subscriber** — which the responder cannot
do alone. Recreating under the same name is also delayed: SNS rejects reuse of a recently deleted ARN
for a period.

## Response levers

**Rebuild the alarm inventory, not the topic list.** The authoritative question is which alarms and
which services published to the deleted ARN, and `describe-alarms` still names it even though the
topic is gone. That is the one place the loss is visible.

**Name matching is a proxy and it is imperfect.** The Sigma rule keys on topic names containing
`alarm`, `security` and so on because a rule cannot reach the CloudWatch inventory. The playbook's §5
does it properly.

**Delete-then-create is usually a redeploy** — but SNS delays reuse of a recently deleted ARN, so the
recreation may itself have failed and left the gap open.

**MITRE:** `T1685 — Disable or Modify Tools` (verified live 2026-08-31) for the alerting path removed;
`T1489 — Service Stop` (verified live 2026-08-31) for the availability half.

**GuardDuty:** no finding type covers SNS topic deletion — and if GuardDuty notifications published to
the deleted topic, GuardDuty will keep producing findings that nobody receives.

**Files here:**
- `sigma_t1685.yml` — four documents: an alerting topic deleted (critical), `sns_topic_deleted` as the
  base rule (low), a three-topics-in-thirty-minutes correlation (high), and the refused case that the
  source rule's error filter excludes (medium).
- `kql_t1685.kql` — separates alerting topics by name, flags the redeploy shape, and states inline why
  a successful deletion is not evidence the topic existed.

Full response procedure is in `../PLAYBOOK.md`.
