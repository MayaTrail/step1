# Provenance

**Use case:** Server-Side Encryption for AWS SNS Topics Was Disabled
**Retrieved:** 2026-08-29
**Extract:** `original_rules.yml` — de-identified, logic-only, produced by the shared
extractor. Name, priority, type, ATT&CK mapping, query verbatim, threshold, window and
group-by are kept; all platform scaffolding is stripped. No source, vendor, product or
repository is named here or in any shipped file.

## Merge decision — NOT merged (the closer of the two calls)

This use case stays separate from
`sns.impact.a-less-secure-server-side-encryption-policy-created`. The two rules match the
**same event and the same `attributeName`** — `SetTopicAttributes` with
`KmsMasterKeyId` — and differ only in the value of `requestParameters.attributeValue`:
empty here, `alias/aws/sns` there. That is a much closer call than the publish/subscribe
pair, and it deserves the specific reasoning rather than a reflex.

**Test 1 is not met, on both halves.**

- *"Differing only in threshold or priority"* — they do not. The difference is a
  discriminating **field value**, which is not what test 1 describes. Test 1's own worked
  example is a volume variant of an identical observable ("queue deleted" and "excessive
  queue deletion"); a different value in the discriminator field is a different condition,
  not a different threshold on the same one.
- *"Same response"* — they do not, and the divergence points in **opposite directions**:
  - Disabling SSE removes the KMS layer entirely. Two things follow that have no analogue
    in the downgrade case. First, the KMS key policy stops being a second, independent gate
    on the topic, so a principal who also widened the topic policy now has unimpeded access
    — which makes "check for a topic-policy change by the same principal in the same
    session" a required eradication step here and noise there. Second, the CMK's own
    CloudTrail record of `GenerateDataKey`/`Decrypt` for this topic **stops**, removing a
    corroborating audit trail the responder would otherwise use to reconstruct usage.
  - Downgrading to the AWS-managed key keeps encryption and *tightens* cross-account
    access, because an AWS-managed key policy cannot be edited to grant anyone. Its
    distinctive consequence is therefore an **availability** one: cross-account and
    cross-service publishers that were granted use of the customer-managed key start
    failing with `KMSAccessDenied`, and the required extra step is a publisher-breakage
    check against `NumberOfNotificationsFailed`. That step is meaningless here.

Containment (`SetTopicAttributes` back to the expected CMK) and the recovery assertion are
genuinely identical. If a deployer's environment has no cross-account or cross-service
publishers and no CMK-scoped KMS auditing, the two responses collapse and merging them
under test 1 would be defensible — but that is an environment-specific simplification, not
the general case, and `07-TIERS.md` sets the bar at "if the response differs **at all**".

**Test 2** does not apply — neither is a flow rule.

## Tier

Tier 2 (lean). Tier-1 test 2 (ordering that can go wrong) was considered: restoring the CMK
fails if the key's policy no longer grants `sns.amazonaws.com`, so key-policy repair
precedes the topic write. That is one ordered pair, handled inside a single containment
step, not the multi-step ordering hazard the test describes.

## Siblings

- `sns.impact.a-less-secure-server-side-encryption-policy-created` — the downgrade variant.
- `sns.persistence.topic-policy-modified` — the policy change that often accompanies
  a disable, and the reason the two-step correlation in `detections/sigma_t1600.yml` exists.

**Tier:** 1, on criterion 2 of `07-TIERS.md` — *the response has ordering that can go wrong*.
