# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Immediate rule over a query string |
| Scope captured | One rule: A Topic Was Deleted |
| Retrieved | 2026-08-31 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

A currency check that tests reachability passes it; only a check that
compares the ID against a **name** catches it.

The redirect target, `T1685 — Disable or Modify Tools`, is the right parent here, and it is used.
`T1489 — Service Stop` covers the availability half. Both verified live 2026-08-31.

## Why deleting a topic is defence impairment rather than an outage

An SNS topic is frequently the notification path for several independent controls at once — CloudWatch
alarms, GuardDuty finding notifications, Config rules, Security Hub, Budgets. Deleting it removes all
of them in one call.

And nothing reports the loss. AWS is explicit:

> "CloudWatch doesn't test or validate the actions that you specify, nor does it detect any Amazon EC2
> Auto Scaling or Amazon SNS errors resulting from an attempt to invoke nonexistent actions. Make sure
> that your alarm actions exist."

The alarm still evaluates, still transitions to `ALARM`, and still shows as healthy in the console.
The notification is dropped silently, with no error anywhere. That is what makes this a stealth
technique and not a service interruption, and it is why P4 is the wrong rating.

## Two properties of the API the rule does not account for

**It deletes the subscriptions too.** AWS: "Deletes a topic **and all its subscriptions**." Recovery
is therefore not "recreate the topic" — every subscription has to be recreated, and email and HTTP/S
endpoints must be **re-confirmed by the subscriber**, which is not something the responder can do
alone. Recreating the topic under the same name is also delayed: SNS returns a stale-tag error for a
period after a resource with that ARN is removed.

**It cannot fail.** AWS: "This action is **idempotent**, so deleting a topic that does not exist does
not result in an error." Combined with the rule's `NOT _exists_:errorCode` filter, an actor spraying
guessed topic ARNs produces a stream of alerts that all look like successful deletions — and a
responder counting them will overstate the damage. The distinction is only recoverable by checking
whether each ARN was ever present in an inventory.

## What the rule gets right

The event name is correctly cased, which two sibling SNS rules in this source set do not manage — see
`../../_ground-truth/sns.md` §5.

## What it lacks

No threshold, so one decommission and a sweep across every topic in the account are the same alert.
No principal dimension. And no notion that some topics matter more than others: the topic carrying
security notifications and the topic carrying build notifications are rated identically.

**Merge test:** not applicable — one source rule, one use case. Topic policy changes are
`../../sns.persistence.topic-policy-modified/`; encryption changes are
`../../sns.impact.server-side-encryption-for-aws-sns-topics-was-disabled/`. Deletion is the only
irreversible one and it owns its own response.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for the `sns.*` playbooks authored against it is in `../../_ground-truth/sns.md`,
audited 2026-08-31. §3 covers subscriptions and idempotency; §4 covers the silent CloudWatch failure.
