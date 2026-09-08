# Detection Note — T1600 (SNS topic encryption downgraded to the AWS-managed key)

**Signal:** `SetTopicAttributes` pointing a topic's `KmsMasterKeyId` at the AWS-managed SNS
key, `alias/aws/sns`, where the topic previously used a customer-managed key.

**The original rule has no before-state, and that inverts it half the time.** It fires on the
destination value alone and calls the result "a less secure encryption policy". Whether it is
less secure depends entirely on what the topic had a moment earlier:

| Before | After | Reality |
|---|---|---|
| customer-managed key | `alias/aws/sns` | a genuine downgrade |
| no encryption at all | `alias/aws/sns` | encryption being **turned on** |

CloudTrail records the **new value only** — there is no `oldValue` field and no attribute
version history — so the single event cannot separate those, and the rule as written pages
somebody for improving the account's posture. In most accounts the second row is the majority
of matches. That is the defect worth fixing, and it is fixed structurally rather than with
prose: the single-event rule is demoted to `medium`, and a `temporal_ordered` correlation
supplies the before-state by requiring a customer-managed key to have been set on the *same*
topic first. The KQL does the same reconstruction with `prev()` over the topic's own history.

**Two case errors, both fatal.** The original matched `eventName:"settopicattributes"` and
`attributeName:"kmsmasterkeyid"`. CloudTrail writes `SetTopicAttributes`, and SNS validates
the attribute name case-sensitively as `KmsMasterKeyId`. On a case-sensitive keyword field
either one alone reduces the rule to zero matches.

## What is actually lost, and what is not

Encryption is still on. Message bodies are still encrypted at rest. What changes is **who
controls the key**, and the losses are specific:

- **You cannot edit an AWS-managed key's policy.** So you lose the ability to restrict use of
  the topic by key policy — a second, independent gate alongside the topic policy — and you
  lose the ability to revoke access by amending that policy during an incident.
- **You cannot disable or schedule deletion of an AWS-managed key.** The emergency
  "freeze this topic by making its key unusable" lever is gone.
- **You cannot grant an AWS-managed key to another account or to a service principal.** This
  is the availability consequence, and it is the one that distinguishes this use case from
  its sibling: cross-account publishers, and AWS services publishing on your behalf, were
  working because the *customer-managed* key policy granted them. After the downgrade they
  fail, and the failure surfaces as `KMSAccessDenied` on their side and as
  `NumberOfNotificationsFailed` on the topic.

What does **not** change is the scope of what SSE ever covered. AWS is explicit that SSE
encrypts the **body of a message** and nothing else — not topic metadata, not message
metadata (subject, message id, timestamp, message attributes), not the data protection
policy, not per-topic metrics. A downgrade does not narrow that scope; it changes custody.

## The gap no log rule can close

The AWS-managed key can be named by **key id or key ARN** as well as by the `alias/aws/sns`
alias, and those forms are opaque strings with nothing to match on. A downgrade written that
way is invisible to every rule here and to the KQL, which classifies it as
`customer-managed-or-opaque`. Resolving it requires `kms:DescribeKey` and reading
`KeyMetadata.KeyManager == "AWS"` — an API call, not a log field. Query 2 of the playbook
does exactly that against the live state, and it is the authoritative answer; the log rules
are the tripwire.

The correlation's 30-day timespan is a **retention-shaped figure, not a behavioural one**.
Key changes on a topic are typically months apart, so a non-match means "no evidence in the
window", never "not a downgrade". This is stated in the rule's own description because a
deployer tuning the window needs to know it is not derived from attacker behaviour.

## "Was it used"

There is no "use" of a downgrade in the way there is for a public grant — the change is the
harm. The two questions worth answering are what the topic carried while custody was wrong,
and whether anything broke:

- CloudWatch `AWS/SNS` `NumberOfMessagesPublished`, dimension `TopicName`, bounds the volume.
  `sns:Publish` is a CloudTrail **data** event, off by default, so `lookup-events` returns
  zero for it forever without a data-event trail — that zero is "not logged", never "nothing
  was published".
- CloudWatch `AWS/SNS` `NumberOfNotificationsFailed`, same dimension, catches the publisher
  breakage the downgrade causes. Unlike the sibling use case, the KMS trail does **not** stop
  here — it moves to the AWS-managed key — so `kms:GenerateDataKey` events carrying
  `kms:EncryptionContext:aws:sns:topicArn` remain available for the whole window.

## Response levers

**Error strings:** SNS does not use `AccessDenied`; a denied call is **`AuthorizationError`** (403).
`SetTopicAttributes` throws `AuthorizationError`, `InternalError`, `InvalidParameter`,
`InvalidSecurity` and `NotFound`; a key identifier SNS cannot resolve comes back as
`InvalidParameter`. On the publish path, a topic whose key has become unusable for a given
publisher throws `KMSAccessDenied`, `KMSDisabled`, `KMSInvalidState` (note: **not**
`KMSInvalidStateException`), `KMSNotFound`, `KMSOptInRequired` or `KMSThrottling`.
`KMSAccessDenied` on a cross-account or cross-service publisher is the signature of this
downgrade, not of an attack.

**No oversized-document companion rule ships.** Nothing on this path is a policy document —
`KmsMasterKeyId` is a short key identifier, nowhere near CloudTrail's 100 KB
`requestParameters` omission threshold, so there is no size-based evasion route at all.

**GuardDuty:** No GuardDuty finding type is specific to SNS encryption changes. Do not list GuardDuty as a
detection source for this use case.

**MITRE:** The source rule maps this to **T1565 (Data Manipulation)** under Impact. That is a poor fit:
nothing is manipulated, inserted or deleted — control of a protective key is transferred away
from the defender. **T1600 — Weaken Encryption**, tactic Defense Impairment (TA0112), is the
precise technique and is live as of 2026-08-29; its two published sub-techniques (Reduce Key
Space, Disable Crypto Hardware) are network-device specific, so the parent is correct. Tagged
`attack.defense-impairment` — `attack.defense-evasion` is retired, TA0005 having been renamed
Stealth. The directory name preserves the source rule's tactic label.

**Severity:** **Medium** for the single event, **High** for the correlated downgrade — and this split is
the point. The source rule rates it P4 uniformly. P4 is defensible for the event in
isolation, because most matches are a topic being encrypted for the first time; it is far too
low for a confirmed transfer of key custody away from the account, which removes two
incident-response levers (revoke by key policy, freeze by disabling the key) and can silently
break cross-account publishing. Rating the ambiguous event and the confirmed downgrade the
same is what makes the original rule unactionable in both directions at once.

**Files here:**

- `sigma_t1600.yml` — four documents: `sns_sse_set_aws_managed` (medium, the ambiguous single
  event), `sns_sse_set_customer_managed` (low, base rule establishing the before-state and
  carrying its own success filter), a `temporal_ordered` correlation that is the real finding
  (high), and a `value_count` sweep across distinct topics (medium, `gte: 2`).
- `kql_t1600.kql` — reconstructs the previous key with `prev()` over each topic's own history
  and grades on the **transition**, explicitly labelling the improvement case so an analyst
  is not sent after it.

Full response procedure is in `../PLAYBOOK.md`. The removal variant — higher severity, and
the one that ends the KMS audit trail — is
`../../sns.impact.server-side-encryption-for-aws-sns-topics-was-disabled/`.

Full response procedure is in `../PLAYBOOK.md`.
