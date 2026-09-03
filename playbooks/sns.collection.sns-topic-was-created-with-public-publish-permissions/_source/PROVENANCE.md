# Provenance

**Use case:** SNS Topic Was Created with Public Publish Permissions
**Retrieved:** 2026-08-29
**Extract:** `original_rules.yml` — de-identified, logic-only, produced by the shared
extractor. Name, priority, type, ATT&CK mapping, query verbatim, threshold, window and
group-by are kept; all platform scaffolding is stripped. No source, vendor, product or
repository is named here or in any shipped file.

## Merge decision — NOT merged

This use case stays separate from its nearest sibling,
`sns.collection.sns-topic-was-created-with-public-subscribe-permissions`.

Neither test in `07-TIERS.md` §"When merging is legitimate" is met:

- **Test 1 (same observable, same response, differing only in threshold or priority)
  fails on both halves.** The two rules differ in a discriminating *field value* — the
  `Action` token inside the policy document — not in a threshold or a priority. And the
  response differs materially. A public **publish** grant admits messages *into* the
  topic, so eradication is a downstream-consumer integrity review: every subscriber that
  processed an attacker-authored message must be treated as having processed untrusted
  input, and the "was it used" pivot is `NumberOfMessagesPublished` because `Publish` is
  a CloudTrail **data** event. A public **subscribe** grant lets an outsider attach their
  own endpoint, so eradication is enumerate-and-delete over `ListSubscriptionsByTopic`,
  and the "was it used" pivot is the `Subscribe` **management** event plus the live
  subscription list. Different eradication, different evidence source, opposite direction
  of data flow.
- **Test 2 (a flow rule that is purely the composition of building blocks already
  shipped)** does not apply — this is not a flow rule.

`07-TIERS.md` is explicit that "if the *response* differs at all — different containment,
different eradication — they are two use cases." It does.

## Tier

Tier 2 (lean). None of the five Tier-1 promotion tests applies: account takeover is not
one hop away from an SNS grant, the containment steps have no ordering hazard, the blast
radius is recoverable after containment (the policy and the subscription list both
survive the fix), and no evidence is destroyed by the remediation.

## Siblings

- `sns.collection.sns-topic-was-created-with-public-subscribe-permissions` — the read side.
- `sns.persistence.topic-policy-modified` — the broader "policy changed at all"
  signal, which also covers the `AddPermission` write path.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
