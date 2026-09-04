# Provenance

**Use case:** A Less Secure Server-Side Encryption Policy Created
**Retrieved:** 2026-08-29
**Extract:** `original_rules.yml` — de-identified, logic-only, produced by the shared
extractor. Name, priority, type, ATT&CK mapping, query verbatim, threshold, window and
group-by are kept; all platform scaffolding is stripped. No source, vendor, product or
repository is named here or in any shipped file.

## Merge decision — NOT merged (the closer of the two calls)

This use case stays separate from
`sns.impact.server-side-encryption-for-aws-sns-topics-was-disabled`. The two rules match the
**same event and the same `attributeName`** — `SetTopicAttributes` with `KmsMasterKeyId` —
and differ only in the value of `requestParameters.attributeValue`: `alias/aws/sns` here,
empty there. That is a far closer call than the publish/subscribe pair and deserves the
specific reasoning rather than a reflex.

**Test 1 is not met, on both halves.**

- *"Differing only in threshold or priority"* — they do not. The difference is a
  discriminating **field value**. Test 1's worked example is a volume variant of an
  identical observable ("queue deleted" / "excessive queue deletion"); a different value in
  the discriminator field is a different condition, not a different threshold on one.
- *"Same response"* — they do not, and the divergence points in **opposite directions**:
  - Moving to the AWS-managed key **keeps** encryption and tightens cross-account access,
    because an AWS-managed key policy cannot be edited to grant anyone. Its distinctive
    consequence is therefore an **availability** one: cross-account and cross-service
    publishers that were granted use of the customer-managed key start failing with
    `KMSAccessDenied`, so the required extra step is a publisher-breakage check against
    `NumberOfNotificationsFailed` and the publishers' own error codes. That step is
    meaningless in the disable case.
  - Clearing the key removes the KMS layer entirely, so the key policy stops gating the
    topic and the CMK's `GenerateDataKey`/`Decrypt` audit trail for that topic **ends**.
    The required extra step there is "check for an access-policy change by the same
    principal in the same session", because clearing the key is the enabling half of that
    two-step. That step is noise here — the downgrade does not widen anything.

Containment (`SetTopicAttributes` back to the expected CMK) and the recovery assertion are
genuinely identical. If a deployer has no cross-account or cross-service publishers and no
CMK-scoped KMS auditing, the two responses collapse and merging under test 1 would be
defensible — but that is an environment-specific simplification, and `07-TIERS.md` sets the
bar at "if the response differs **at all**".

**Test 2** does not apply — neither is a flow rule.

## Tier

Tier 2 (lean). None of the five Tier-1 promotion tests applies: no account takeover is one
hop away, the containment is a single ordered pair inside one step, the blast radius stays
readable after containment, and the remediation destroys no evidence.

## Siblings

- `sns.impact.server-side-encryption-for-aws-sns-topics-was-disabled` — the removal variant,
  and the one whose severity is higher.
- `sns.persistence.topic-policy-modified` — the policy-change signal that
  distinguishes a benign key change from the enabling half of a two-step.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
