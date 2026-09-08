# Provenance

**Use case:** SNS Topic Was Created with Public Subscribe Permissions
**Retrieved:** 2026-08-29
**Extract:** `original_rules.yml` — de-identified, logic-only, produced by the shared
extractor. Name, priority, type, ATT&CK mapping, query verbatim, threshold, window and
group-by are kept; all platform scaffolding is stripped. No source, vendor, product or
repository is named here or in any shipped file.

## Merge decision — NOT merged

This use case stays separate from
`sns.collection.sns-topic-was-created-with-public-publish-permissions`. Neither test in
`07-TIERS.md` §"When merging is legitimate" is met:

- **Test 1 (same observable, same response, differing only in threshold or priority)
  fails on both halves.** The difference is a discriminating *field value* — the `Action`
  token inside the policy document — not a threshold or a priority. And the response
  genuinely differs. Subscribe rights let an outsider attach **their own endpoint** and
  receive every future message, so eradication is enumerate-and-delete over
  `ListSubscriptionsByTopic`, and closing the policy removes nothing that is already
  attached. Publish rights let an outsider inject, so eradication there is a downstream
  *consumer* integrity review with no subscription work at all. The evidence paths differ
  too: `Subscribe` is a CloudTrail **management** event, so `lookup-events` answers "was it
  used" directly, whereas `Publish` is a **data** event that is off by default and answers
  nothing without a data-event trail.
- **Test 2 (a flow rule that is purely the composition of building blocks already
  shipped)** does not apply — this is not a flow rule.

`07-TIERS.md`: "If the *response* differs at all — different containment, different
eradication — they are two use cases." It does, in both directions.

## Tier

Tier 2 (lean). Tier-1 test 3 was considered and rejected: the blast radius here is the
subscription list, which is *not* in the triggering event — but it remains readable from
`ListSubscriptionsByTopic` after containment, because fixing the policy does not delete
subscriptions. Nothing forces the responder to collect it before acting, so the promotion
test is not met.

## Siblings

- `sns.collection.sns-topic-was-created-with-public-publish-permissions` — the write side.
- `sns.persistence.topic-policy-modified` — the broader policy-change signal,
  including the `AddPermission` write path.

**Tier:** 1, on criterion 3 of `07-TIERS.md` — *the blast radius is not in the event*.
