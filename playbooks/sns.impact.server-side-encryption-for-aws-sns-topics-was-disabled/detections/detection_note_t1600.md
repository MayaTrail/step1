# Detection Note — T1600 (SNS topic server-side encryption disabled)

**Signal:** `SetTopicAttributes` with `AttributeName=KmsMasterKeyId` and an empty or absent
`AttributeValue` — the only API shape that removes server-side encryption from an SNS topic.

**The original rule's one flaw is invisible, and it is a false negative.** It tested
`NOT _exists_:requestParameters.attributeValue` — the field being **absent**. AWS documents
`AttributeValue` as `Required: No`, so an omitted value is legal; but a caller that sends an
**empty string** sends the parameter, and CloudTrail then records `attributeValue: ""`,
which *exists*. `aws sns set-topic-attributes --attribute-value ""` is exactly that shape.
On an absence-only test, that call never fires the rule. Both shapes are matched here, as
**sibling blocks OR'd in the condition** — they are mutually exclusive on a single event, so
putting them in one block would AND them and the rule would never fire at all.

**Not verified, and it matters.** AWS documents that a topic's encryption *can* be disabled
— "Any encrypted message remains encrypted even if the encryption of its topic is disabled"
— but does **not** document the wire form that does it. The only shape the API surface
permits is `SetTopicAttributes` with `AttributeName=KmsMasterKeyId` and `AttributeValue`
empty or omitted. Whether CloudTrail records `""` or omits the key is **observed, not
documented**, which is precisely why both are matched rather than one being chosen. Confirm
against a real event in your own account before tuning either branch away.

**Two case errors, both fatal.** The original matched `eventName:"settopicattributes"` and
`attributeName:"kmsmasterkeyid"`. CloudTrail writes `SetTopicAttributes`, and the attribute
name is `KmsMasterKeyId` — SNS validates it case-sensitively against its documented
attribute list. On a case-sensitive keyword field each of those alone reduces the rule to
zero matches.

## What SSE actually protected — scope the disclosure correctly

AWS is explicit that SSE encrypts the **body of a message** and nothing else. It does not
encrypt:

- topic metadata (topic name and attributes),
- message metadata — **subject, message id, timestamp and message attributes**,
- the data protection policy,
- per-topic metrics.

So a responder who scopes this incident as "everything about these messages was exposed" is
over-scoping, and one who assumes the subject line was protected is simply wrong: it never
was. The exposure is bounded on both sides as well — SNS does not retroactively encrypt
backlogged messages, and any message already encrypted **stays** encrypted after the
disable. The window is exactly *disable → restore*, and only for message bodies.

## Why the two-step matters more than the disable

A customer-managed key's policy is a **second, independent gate** on the topic: a principal
granted `sns:Subscribe` still reads nothing unless the key policy also permits the SNS
service principal to decrypt on their behalf. That is why the `temporal_ordered` correlation
in the Sigma file — encryption removed, then the access policy rewritten, same topic, inside
an hour — is the document that earns `high`. The disable alone is often a misguided cost or
compatibility change. The disable *followed by* a policy widening is a deliberate sequence,
and the order is not arbitrary: doing it the other way round leaves the new principal locked
out by KMS.

The disable also removes a **second audit trail**. While a CMK is in use, every publish and
every delivery produces `kms:GenerateDataKey` / `kms:Decrypt` events under that key,
carrying `kms:EncryptionContext:aws:sns:topicArn`. Those are management events and are
logged by default — which makes them the one usage record for a topic whose own `Publish`
events are not logged. Disabling SSE ends them. Note that this loss is specific to the
disable case; the sibling downgrade use case keeps a KMS trail, just under the AWS-managed
key.

## "Was it used" — the pivot, and the trap

`sns:Publish` is a CloudTrail **data** event (`eventCategory: "Data"`,
`managementEvent: false`, resource type `AWS::SNS::Topic`) and is **off by default**. A
`lookup-events` query for `Publish` returns zero forever without a data-event trail, and
that zero is "not logged", never "nothing was published while unencrypted". The pivot is
CloudWatch `AWS/SNS` `NumberOfMessagesPublished` on dimension `TopicName` across the disable
window; a zero *there* is a real zero. Corroborate with the KMS key's own event history
before the disable, which establishes the topic's normal publish rhythm.

## Response levers

**Error strings:** SNS does not use `AccessDenied`; a denied call surfaces as **`AuthorizationError`** (403).
`SetTopicAttributes` throws `AuthorizationError`, `InternalError`, `InvalidParameter`,
`InvalidSecurity` and `NotFound`. A denied disable attempt is worth a P2 on its own — it is
permission probing against the control that matters — and the rules here filter to success
deliberately, so pair them with an error-code view rather than assuming failures are noise.

On the publish path, a topic whose key has become unusable throws `KMSAccessDenied`,
`KMSDisabled`, `KMSInvalidState`, `KMSNotFound`, `KMSOptInRequired` or `KMSThrottling` —
note the exact spellings: `KMSInvalidState`, not `KMSInvalidStateException`. Those are the
codes to watch during recovery, because restoring the CMK fails open into publisher
breakage if the key policy no longer grants `sns.amazonaws.com`.

**No oversized-document companion rule ships.** Nothing on this path is a policy document:
`KmsMasterKeyId` is a short key identifier, far below CloudTrail's 100 KB `requestParameters`
omission threshold. There is no size-based evasion route here at all.

**GuardDuty:** No GuardDuty finding type is specific to SNS encryption changes. Do not list GuardDuty as a
detection source for this use case.

**MITRE:** The source rule maps this to **T1565 (Data Manipulation)** under Impact. That is a poor fit:
nothing is manipulated, inserted or deleted — a protective control is removed.
**T1600 — Weaken Encryption**, under the Defense Impairment tactic (TA0112), is the precise
technique and is live as of 2026-08-29. T1600's two published sub-techniques (Reduce Key
Space, Disable Crypto Hardware) are network-device specific, so the parent is correct here.
The directory name preserves the source rule's tactic label; these rules and the playbook
carry the corrected mapping, tagged `attack.defense-impairment` — note that
`attack.defense-evasion` is retired, TA0005 having been renamed Stealth.

**Severity:** **High**, against the source rule's P4. P4 routes an account's encryption control being
switched off to a queue nobody reads before morning, and the exposure window *is* the
response time — every message published between the disable and the restore is stored
without your key, and no later action recovers that. The disable is also the enabling step
for cross-account access to a CMK-encrypted topic, so treating it as a compliance ticket
misses the sequence it usually belongs to.

**Files here:**

- `sigma_t1600.yml` — four documents: `sns_sse_disabled` (high, both value shapes),
  `sns_topic_policy_written` (low, base rule carrying its own success filter so a denied
  policy write cannot raise the correlation), a `temporal_ordered` correlation for the
  disable-then-widen sequence (high), and a `value_count` correlation for a multi-topic
  sweep (high, `gte: 2` — the legitimate baseline for one principal in one hour is exactly
  one topic).
- `kql_t1600.kql` — joins each disable to any topic-policy write on the same topic within
  the hour, and reconstructs the previous key from the events still in the window.

Full response procedure is in `../PLAYBOOK.md`. The downgrade variant is
`../../sns.impact.a-less-secure-server-side-encryption-policy-created/`; the policy-change
half of the two-step is `../../sns.persistence.topic-policy-modified/`.

Full response procedure is in `../PLAYBOOK.md`.
