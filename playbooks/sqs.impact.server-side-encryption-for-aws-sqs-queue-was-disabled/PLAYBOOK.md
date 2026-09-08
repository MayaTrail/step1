# IR Playbook: SQS Server-Side Encryption Disabled — Unencrypted Storage and Anonymous Access via `sqs:SetQueueAttributes`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defence impairment (a queue's encryption at rest is removed, which also removes the control that rejects anonymous requests) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, against the source rule's **P4**. Two things happen in one call: messages written from that moment are stored unencrypted, and the control AWS documents as rejecting anonymous `SendMessage`/`ReceiveMessage` is gone. The second is the one that gets undersold — it can convert a queue that required a credential into one that does not, through an event most change reviews read as a configuration tweak |
| MITRE Tactics | Defense Impairment (TA0112), Persistence (TA0003) |
| MITRE Techniques | T1600 (primary), T1098 (secondary) — both verified live 2026-08-29 |
| Services in Scope | SQS, KMS, CloudTrail (management + SQS data events), CloudWatch (`AWS/SQS`), IAM, Organizations (SCP) |

**What the technique does:** the actor calls `sqs:SetQueueAttributes` with either `KmsMasterKeyId` set
to an empty string or `SqsManagedSseEnabled` set to `false`. There is no fallback — AWS:
*"turning off KMS-SSE, will not automatically enable SQS-SSE"* — so the queue ends with **no
encryption at all**, and the default SSE-SQS option does not save it because that default
applies *"only when you create a queue without specifying encryption attributes"*. Two things
follow. Messages sent from now on are stored in the clear, while *"any encrypted message
remains encrypted even if the encryption of its queue is disabled"*, so the exposure is
bounded to the window. And because *"with SSE enabled, anonymous `SendMessage` and
`ReceiveMessage` requests to the encrypted queue will be rejected"*, removing encryption is
the documented **precondition for anonymous access**: pair it with a wildcard queue policy
and the queue needs no credential at all.

**Detection thesis.** The discriminator is `requestParameters.attributes.KmsMasterKeyId`
arriving **present and empty** *without* `SqsManagedSseEnabled=true` in the same call — that
combination is a migration, not a disable — **or** `SqsManagedSseEnabled` arriving `false`.
The source rule tests only the first of those two paths, and matches the event name in lower
case where every sibling rule uses the documented casing.

> The wildcard-policy half of the anonymous-access chain is
> `../sqs.collection.an-sqs-queue-attributes-were-changed/`, which fires on the same event
> name and a different attribute.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing SQS **management** events (`SetQueueAttributes`,
  `CreateQueue` and nine others). `ReceiveMessage`/`SendMessage`/`DeleteMessage` — and also
  `ListQueues`/`GetQueueUrl`/`GetQueueAttributes` — are SQS **data** events, off by default,
  so **enumeration and encryption-configuration reads produce no management event at all**
- Field shape: `requestParameters.attributes.KmsMasterKeyId`, `.SqsManagedSseEnabled`,
  `.KmsDataKeyReusePeriodSeconds` and `requestParameters.queueUrl`. Top-level names are
  lower-camel; **map keys keep their documented casing**, and attribute **values are strings**
  (`'false'`, not the boolean). AWS publishes no management-event example for this API —
  confirm against one real event. There is **no `responseElements`** (HTTP 200, empty body)
- **KMS CloudTrail events for the queue's key.** While SSE-KMS is on, each data-key fetch
  produces a `kms:GenerateDataKey`; those stop when encryption is removed — corroboration
  that survives losing the `SetQueueAttributes` event itself
- CloudWatch `AWS/SQS` retained, in particular `NumberOfMessagesSent` (dimension `QueueName`
  only) — the only way to count what was written during the window — plus an inventory of
  which queues are **expected** to be encrypted and under which key

**Alerting (must be pre-configured)**
- **`SetQueueAttributes` clearing `KmsMasterKeyId` without `SqsManagedSseEnabled=true` in the same call → P0**
- **`SetQueueAttributes` setting `SqsManagedSseEnabled=false` → P0**
- **Encryption removed and then a wildcard principal admitted to the queue policy within 30 minutes → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- Which principals and automation roles touch this service at all. In most estates the list is short, which makes an unfamiliar caller a finding before any threshold is evaluated.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `SetQueueAttributes` with `attributes.KmsMasterKeyId` empty and no `SqsManagedSseEnabled=true` | CloudTrail (management) | T1600 |
| P0 | `SetQueueAttributes` with `attributes.SqsManagedSseEnabled` = `false` | CloudTrail (management) | T1600 |
| P1 | Encryption disabled, then a wildcard principal admitted to the queue policy, same principal, within 30 minutes | CloudTrail (management) | T1600 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `CreateQueue` with `attributes.SqsManagedSseEnabled` = `false` — opts out of default encryption at birth | CloudTrail (management) | T1600 |
| P2 | `attributes.KmsMasterKeyId` set to `alias/aws/sqs`, replacing a customer-managed key | CloudTrail (management) | T1600 |
| P2 | `kms:GenerateDataKey` on a queue's key stops with no matching fall in `NumberOfMessagesSent` | CloudTrail + CloudWatch | T1600 |
| P3 | `attributes.KmsDataKeyReusePeriodSeconds` raised to 86400 — KMS telemetry suppression without a disable | CloudTrail (management) | T1600 |

### Detection Rule Quality Notes

The source rule is the only one of the six SQS rules that inspects a request field rather
than an event name — and it still cannot fire on half the technique.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `eventName:"setqueueattributes"` in **lower case**, where the five sibling rules in the same set use `SetQueueAttributes` | Against a case-sensitive keyword field this matches zero events, forever. The rule looks deployed and detects nothing | Match the documented casing |
| Requires `attributes.KmsMasterKeyId` to be present-and-empty | A call that turns off SSE-SQS sends `SqsManagedSseEnabled=false` and carries no `KmsMasterKeyId` at all, so the condition cannot be met. The entire SSE-SQS path is uncovered — and SSE-SQS is the *default* scheme, so it is the more common queue state | Carry both disable paths as sibling blocks, OR-ed, never ANDed in one block |
| No `CreateQueue` coverage, and P4 priority | A queue created with `SqsManagedSseEnabled=false` opts out of default encryption at birth and never produces a `SetQueueAttributes` event, so it stays unencrypted for its whole life with no rule firing — while the disable itself is triaged below a queue deletion | Ship the `CreateQueue` rule; High for the disable |

**Recommended detection — queue encryption turned off, by either path.**

```yaml
# SQS Server-Side Encryption Disabled (T1600 / T1098)
#
# WHAT "DISABLED" ACTUALLY MEANS. AWS states it outright: "Amazon SQS allows you to turn off
# all queue encryption. Therefore, turning off KMS-SSE, will not automatically enable
# SQS-SSE. If you wish to enable SQS-SSE after turning off KMS-SSE, you must add an
# attribute change in the request." Clearing `KmsMasterKeyId` does NOT fall back to the
# SQS-managed key — the queue ends up with no encryption at all. The default SSE-SQS option
# applies only "when you create a queue without specifying encryption attributes", so it is
# no safety net for a queue whose attributes are being set deliberately.
#
# THE SOURCE RULE HAS TWO DEFECTS AND BOTH ARE VISIBLE WITHOUT LEAVING THE QUERY.
# (1) It matches `eventName:"setqueueattributes"` in lower case where every sibling rule in
#     the same set matches `SetQueueAttributes`. Against a case-sensitive keyword field that
#     is zero events, forever.
# (2) It requires `KmsMasterKeyId` to be present and empty. A call that turns off SSE-SQS
#     sends `SqsManagedSseEnabled=false` and does not carry `KmsMasterKeyId` at all, so the
#     condition cannot be met and the whole SSE-SQS path is uncovered. Rule 1 below carries
#     BOTH paths as sibling blocks, OR-ed — they are alternative shapes of one event and
#     must never be ANDed into a single block.
# The rule's one correct instinct is kept: `SqsManagedSseEnabled=true` in the SAME call is a
# MIGRATION from SSE-KMS to SSE-SQS, and the queue stays encrypted. That exclusion is why
# `migrating_to_sse_sqs` exists below.
#
# WHY IT MATTERS BEYOND "DATA AT REST". AWS: "With SSE enabled, anonymous SendMessage and
# ReceiveMessage requests to the encrypted queue will be rejected... If you wish to send
# anonymous requests to an Amazon SQS queue, make sure you disable SSE." Encryption is
# therefore also an authentication control on this service, and turning it off is the
# precondition for anonymous access. Paired with a wildcard queue policy it makes the queue
# readable with no credential at all — the `sqs_sse_disabled_then_opened` correlation.
#
# FIELD SHAPE. `{"Attributes": {"<Name>": "<value>"}, "QueueUrl": "..."}`. CloudTrail
# lower-cases the first character of top-level parameter names (AWS's own SQS CloudTrail
# example shows `requestParameters.queueUrl`); the KEYS INSIDE the map keep their documented
# casing. Attribute values are always STRINGS, so `SqsManagedSseEnabled` is `'false'`, not
# the boolean false. AWS publishes no management-event example for SetQueueAttributes —
# confirm the path against one real event before deploying.
title: SQS queue encryption turned off
id: 1adf398e-7301-45cc-bbab-847f58f1c4a0
name: sqs_sse_disabled
status: experimental
description: >-
  A queue's server-side encryption was removed — either by clearing `KmsMasterKeyId` without
  enabling the SQS-managed key in the same call, or by setting `SqsManagedSseEnabled` to
  false. Messages written from this moment on are stored unencrypted, and anonymous
  `SendMessage`/`ReceiveMessage` requests, which SSE rejects, become possible.
references:
  - https://attack.mitre.org/techniques/T1600/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html  # retrieved 2026-08-29
tags:
  - attack.defense_impairment
  - attack.t1600
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sqs.amazonaws.com'
    eventName: 'SetQueueAttributes'
  # The two disable paths. They are ALTERNATIVE shapes of the same event, so they are
  # sibling blocks OR-ed in the condition. Putting them in one block would AND them and the
  # rule would fire on neither.
  kms_key_cleared:
    requestParameters.attributes.KmsMasterKeyId: ''
  sqs_managed_sse_off:
    requestParameters.attributes.SqsManagedSseEnabled: 'false'
  # Clearing the KMS key WHILE enabling the SQS-managed key is a migration between two
  # encryption schemes, not a disable. Excluded from the KMS path only.
  migrating_to_sse_sqs:
    requestParameters.attributes.SqsManagedSseEnabled: 'true'
  success:
    errorCode: null
  condition: selection and success and ((kms_key_cleared and not migrating_to_sse_sqs) or sqs_managed_sse_off)
falsepositives:
  - >-
    A deliberate move to anonymous access — AWS documents disabling SSE as the prerequisite
    for it. That is a true positive about an unauthenticated queue, not a false one.
  - >-
    An IaC drift correction where the encryption attribute was never in the template. The
    queue is still unencrypted afterwards; fix the template rather than filtering the rule.
level: high
---
# The default SSE-SQS option is "only effective when you create a queue without specifying
# encryption attributes". A CreateQueue that explicitly passes SqsManagedSseEnabled=false
# opts out of it at birth, and no SetQueueAttributes event ever exists for that queue — so
# the rule above never fires and the queue is unencrypted for its whole life.
title: SQS queue created with encryption explicitly disabled
id: 13c72d3d-3031-4ebe-bdad-a185ac7469e0
name: sqs_queue_created_unencrypted
status: experimental
description: >-
  A queue was created with `SqsManagedSseEnabled` explicitly false, opting out of the
  default SQS-managed encryption that would otherwise have applied.
references:
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-sqs-sse-queue.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html  # retrieved 2026-08-29
tags:
  - attack.defense_impairment
  - attack.t1600
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sqs.amazonaws.com'
    eventName: 'CreateQueue'
  sse_opted_out:
    requestParameters.attributes.SqsManagedSseEnabled: 'false'
  success:
    errorCode: null
  condition: selection and sse_opted_out and success
falsepositives:
  - >-
    A queue intended to receive anonymous or cross-account traffic from a service that
    cannot use SSE. Record it in the §1 baseline so the next one remains signal.
level: medium
---
# Swapping a customer-managed key for the AWS-managed key `alias/aws/sqs` leaves the queue
# encrypted and reads as harmless, but it removes the two controls that made the CMK worth
# having: you no longer own the key policy, and you can no longer disable or schedule
# deletion of the key to cut off access to the ciphertext. It is a downgrade dressed as a
# configuration change.
title: SQS queue downgraded from a customer-managed key to the AWS-managed key
id: 807352c3-9605-4767-80fa-da5b17e129f0
name: sqs_kms_key_downgraded
status: experimental
description: >-
  A queue's `KmsMasterKeyId` was set to the AWS-managed SQS key. The queue stays encrypted,
  but the key policy and the ability to revoke access by disabling the key both move out of
  your control.
references:
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html  # retrieved 2026-08-29
tags:
  - attack.defense_impairment
  - attack.t1600
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sqs.amazonaws.com'
    eventName: 'SetQueueAttributes'
  # The alias of the AWS-managed key for SQS is documented as always `alias/aws/sqs`; the
  # key ARN and key ID forms are also accepted, so this matches the alias form only and the
  # analyst confirms the resolved key in Query 2.
  aws_managed_key:
    requestParameters.attributes.KmsMasterKeyId: 'alias/aws/sqs'
  success:
    errorCode: null
  condition: selection and aws_managed_key and success
falsepositives:
  - A queue being moved off a CMK for cost reasons. Legitimate, and still a control downgrade.
level: medium
---
# Base rule — sequence component only, not for direct alerting. Carries the success filter so
# a denied policy write cannot compose into the high-severity correlation below.
#
# This duplicates the primary rule of ../../sqs.collection.an-sqs-queue-attributes-were-changed/
# under a distinct name and id, because a Sigma correlation resolves its components by `name:`
# within the same file. Deploy this one at `informational`; the sibling directory's copy is the
# one that alerts.
title: SQS queue policy opened to a wildcard principal
id: 4c34e550-6817-4f9c-ae8e-6c97ec63d41c
name: sqs_queue_policy_wildcard_for_anon_access
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sqs.amazonaws.com'
    eventName: 'SetQueueAttributes'
  # The `\\?` groups make the escaping optional so the pattern matches whether the platform
  # indexes the parsed field or the raw serialised event.
  wildcard_principal:
    requestParameters.attributes.Policy|re: '\\?"Principal\\?"\s*:\s*(\{\s*\\?"AWS\\?"\s*:\s*)?(\[\s*)?\\?"\*\\?"'
  success:
    errorCode: null
  condition: selection and wildcard_principal and success
level: informational
---
# Threshold basis — derived from documented behaviour, not an observed count. There is no
# count to tune: this is an ORDERED PAIR and the technique's baseline is one of each. AWS
# documents that SSE rejects anonymous SendMessage and ReceiveMessage, so removing encryption
# and then admitting a wildcard principal are the two halves of ONE move — making the queue
# readable with no credential. Thirty minutes spans a hand-driven two-step without spanning
# an unrelated change later in the day; shorten it if one IaC apply legitimately does both,
# which would otherwise make every such apply a hit. Ordering is conveyed by the correlation
# TYPE — do not add an `ordered:` key.
title: SQS queue encryption removed and then opened to anonymous access
id: 5e9d47d5-0358-4429-ba5f-c5bd94b5d91c
status: experimental
description: >-
  One principal turned a queue's encryption off and then admitted a wildcard principal to its
  access policy inside thirty minutes. Encryption is what rejects anonymous requests on this
  service, so together these two changes make the queue readable and writable with no
  credential at all.
references:
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html  # retrieved 2026-08-29
tags:
  - attack.defense_impairment
  - attack.t1600
correlation:
  type: temporal_ordered
  rules:
    - sqs_sse_disabled
    - sqs_queue_policy_wildcard_for_anon_access
  group-by:
    - userIdentity.arn
  timespan: 30m
level: high
```

The rule cannot tell you *what was exposed* — that is a metric question
(`NumberOfMessagesSent` over the window), because reads and writes are data-plane — and it
cannot separate a cost-driven `KmsDataKeyReusePeriodSeconds` increase from deliberate KMS
telemetry suppression. `detections/kql_t1600.kql` pairs each disable with the next
policy-opening change on the same queue and reports the sequence as one row.

---

### Key Investigation Queries

> SQS is regional — run these in the queue's region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: who changed encryption, on which queue, and in which direction

```bash
REGION="us-east-1"
RAW=$(for EV in SetQueueAttributes CreateQueue; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region,"
  echo "    or missing cloudtrail:LookupEvents. This is NOT 'encryption was never changed'."
else
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "sqs.amazonaws.com") | (.requestParameters.attributes // {}) as $a |
    select(($a|has("KmsMasterKeyId")) or ($a|has("SqsManagedSseEnabled")) or ($a|has("KmsDataKeyReusePeriodSeconds"))) |
    {time: .eventTime, caller_arn: .userIdentity.arn, access_key: .userIdentity.accessKeyId,
     event: .eventName,
     queue_url: (.requestParameters.queueUrl // .responseElements.queueUrl),
     queue_name: (.requestParameters.queueName //
                  ((.requestParameters.queueUrl // "") | split("/") | last)),
     kms_key_sent: ($a|has("KmsMasterKeyId")), kms_key: ($a.KmsMasterKeyId // null),
     sqs_sse: ($a.SqsManagedSseEnabled // null), reuse: ($a.KmsDataKeyReusePeriodSeconds // null),
     verdict: (if ($a.SqsManagedSseEnabled == "false") then "SSE-SQS OFF"
               elif (($a|has("KmsMasterKeyId")) and ($a.KmsMasterKeyId == "")
                     and ($a.SqsManagedSseEnabled != "true")) then "SSE-KMS CLEARED, NO FALLBACK"
               elif ($a.KmsMasterKeyId == "alias/aws/sqs") then "CMK DOWNGRADED TO AWS-MANAGED KEY"
               else "ENCRYPTION ATTRIBUTE CHANGED - read the values" end),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | jq -s 'sort_by(.time)'
fi
```

`kms_key_sent` is the field that separates "sent as empty" from "not sent at all" — the
distinction the source rule collapses, and the reason it misses the SSE-SQS path. Take the
**first** `SSE-*` verdict's `time` as the start of the exposure window and the next
re-enable (or now) as its end; that pair is what Query 2 counts over. Record `queue_name`,
`caller_arn` and `access_key` as IOCs.

#### Query 2 — Live encryption state of every queue, and how much was written in the clear

```bash
REGION="us-east-1"
for Q in $(aws sqs list-queues --region "$REGION" --query 'QueueUrls[]' --output text); do
  # QueueArn is requested alongside the two SSE attributes on purpose. get-queue-attributes
  # omits attributes that are not set, so an empty Attributes map is ambiguous between "no
  # encryption" and "the call failed". QueueArn always exists, so its presence proves the
  # call ran and its absence proves it did not.
  A=$(aws sqs get-queue-attributes --queue-url "$Q" --region "$REGION" --output json \
        --attribute-names QueueArn KmsMasterKeyId SqsManagedSseEnabled)
  ARN=$(printf '%s' "$A" | jq -r '.Attributes.QueueArn // empty')
  KEY=$(printf '%s' "$A" | jq -r '.Attributes.KmsMasterKeyId // empty')
  SSE=$(printf '%s' "$A" | jq -r '.Attributes.SqsManagedSseEnabled // "absent"')
  if   [ -z "$ARN" ];           then echo "[!] INCONCLUSIVE $Q - the read did not return QueueArn; the call failed"
  elif [ -n "$KEY" ];           then echo "[OK] $Q encrypted with KMS key $KEY"
  elif [ "$SSE" = "true" ];     then echo "[OK] $Q encrypted with the SQS-managed key"
  else                               echo "[!] $Q is UNENCRYPTED (KmsMasterKeyId unset, SqsManagedSseEnabled=$SSE)"; fi
done

# How many messages were written in the clear? Sends are DATA-plane, so this is a metric,
# never lookup-events. Bound it by the window Query 1 established.
WINDOW_START="<iso8601-time-of-the-disable-from-Query-1>"
WINDOW_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"   # or the re-enable time, if there was one
SENT=$(aws cloudwatch get-metric-statistics --namespace AWS/SQS --period 3600 --statistics Sum \
  --metric-name NumberOfMessagesSent --region "$REGION" --output json \
  --dimensions Name=QueueName,Value="<queue-name-from-Query-1>" \
  --start-time "$WINDOW_START" --end-time "$WINDOW_END")
[ -z "$SENT" ] && echo "[!] INCONCLUSIVE - CloudWatch call failed; the exposed count is unknown, not zero"
printf '%s' "$SENT" | jq -r '[.Datapoints[].Sum] | add // 0 | "messages written unencrypted: \(.)"'
```

Every `[!] ... UNENCRYPTED` line is a queue in scope, not just the one that alerted — and
`[!] INCONCLUSIVE` is deliberately a different outcome from `[OK]`, because
`get-queue-attributes` returns an empty map both when nothing is set and when the call fails.
The metric total is the size of the exposure: messages sent **before** the disable stayed
encrypted, and messages sent after the re-enable are encrypted again, so this window is the
whole of it.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="CreateQueue SetQueueAttributes"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "sqs.amazonaws.com") |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'group_by(.caller) | map({caller: .[0].caller, calls: length,
                                       events: (map(.event) | unique),
                                       keys: (map(.access_key) | unique),
                                       first: (map(.time) | min), last: (map(.time) | max)})
             | sort_by(-.calls)'
```

The alerting event named one resource; this asks whether the same principal did the same thing
elsewhere, and whether anyone else did it too. Grouped by caller rather than by resource,
because the question eradication needs answered is *how much of this is one actor's work* — a
per-resource list cannot say. `access_key` is emitted because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` whether or not it happened; the preamble's caveat applies.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-3>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique),
                               errors: (map(.error) | unique),
                               ips: (map(.ip) | unique | .[0:5])})'
```

Keyed on the access key rather than the ARN: one credential is used across many sessions, and
the key identifies the credential. The per-service grouping answers what this playbook cannot —
whether this technique was the objective or one stop on a tour. A service in that list with no
business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID, so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Re-enable encryption first — it is one call, it stops the exposure growing, and it restores
the rejection of anonymous requests. Then check the queue policy in the same breath: if a
wildcard principal was admitted while encryption was off, the queue was anonymously
reachable and that is the other half of the incident.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Re-enable encryption explicitly, and check what else changed

```bash
REGION="us-east-1"; QUEUE_URL="<queue-url-from-Query-1>"
CMK="<arn-or-alias-of-the-queue-s-customer-managed-key>"   # empty string to use SSE-SQS instead

# Nothing re-enables itself: AWS requires an explicit attribute change. Use the CMK if the
# queue had one, otherwise turn the SQS-managed key back on.
if [ -n "$CMK" ]; then
  aws sqs set-queue-attributes --queue-url "$QUEUE_URL" --region "$REGION" \
    --attributes "KmsMasterKeyId=$CMK,KmsDataKeyReusePeriodSeconds=300"
else
  aws sqs set-queue-attributes --queue-url "$QUEUE_URL" --region "$REGION" \
    --attributes "SqsManagedSseEnabled=true"
fi
echo "[i] encryption re-enabled - asserted in Recovery; changes take up to 60s to propagate"

# The other half: did the policy open while encryption was off?
POL=$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names Policy \
        --region "$REGION" --output json | jq -r '.Attributes.Policy // empty')
if [ -z "$POL" ]; then
  echo "[i] no queue policy set - no resource-based grant exists (or the read failed; re-run to be sure)"
elif printf '%s' "$POL" | grep -qE '"Principal"[[:space:]]*:[[:space:]]*(\{[[:space:]]*"AWS"[[:space:]]*:[[:space:]]*)?(\[[[:space:]]*)?"\*"'; then
  echo "[FAIL] the queue policy admits a wildcard principal - while encryption was off this"
  echo "       queue was reachable anonymously. Work ../sqs.collection.an-sqs-queue-attributes-were-changed/ too."
else
  echo "[OK] no wildcard principal in the live queue policy"
fi
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["sqs:SetQueueAttributes","sqs:AddPermission","sqs:RemovePermission"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenySqsAdmin" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenySqsAdmin" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied SQS administration for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or"
     echo "    a service principal. Contain manually; neither branch above applies.";;
esac
```

> `aws:TokenIssueTime` revokes only sessions issued **before** the cutoff; a credential
> re-fetched afterwards gets a newer issue time and is not denied.

---

## 4. Eradication

### Remove Attacker Access

- **Re-encrypt every queue Query 2 flagged `[!] ... UNENCRYPTED`**, not only the one that
  alerted. Re-enabling does not retro-encrypt anything: AWS states that backlogged messages
  are not encrypted when SSE is turned on, so any message still sitting in the queue from the
  exposure window remains in the clear until it is consumed or expires.
- **Treat everything written during the window as exposed**, sized by the `NumberOfMessagesSent`
  total from Query 2. If the queue carries regulated data, that number is the notification
  scope, and `HIDDEN_DUE_TO_SECURITY_REASONS` means you cannot narrow it by inspecting bodies.
- **Undo the collateral changes in the same event**, if any: a `KmsDataKeyReusePeriodSeconds`
  raised toward 86,400 suppresses the KMS telemetry that would otherwise corroborate this
  incident, and an `alias/aws/sqs` downgrade silently removes your key policy and your ability
  to revoke access by disabling the key.
- **Right-size the permission.** `sqs:SetQueueAttributes` belongs to the deployment pipeline
  and the break-glass role. Denying it also protects the queue policy, so one control covers
  this playbook and `../sqs.collection.an-sqs-queue-attributes-were-changed/`.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3
  could have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
# A principal that is neither user nor role must reach INCONCLUSIVE, never the clean branch.
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenySqsAdmin EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenySqsAdmin"
    LEFT=$(aws iam list-user-policies --user-name "$N" --query 'PolicyNames[]' --output text);;
  *) N=""; LEFT="UNCHECKED";;
esac
case "$LEFT" in
  UNCHECKED)   echo "[!] INCONCLUSIVE - neither user nor role; check manually";;
  *Emergency*) echo "[FAIL] an emergency policy is still attached: $LEFT";;
  *)           echo "[OK] no emergency policy remains on $N";;
esac
```

---

## 5. Recovery

### Restore Clean State

#### Verify the queue is encrypted again

```bash
REGION="us-east-1"; QUEUE_URL="<queue-url-from-Query-1>"
# QueueArn is requested alongside so an empty Attributes map cannot be read as "unencrypted"
# when the real cause was a failed call. This assertion still has something to test after the
# remediation: get-queue-attributes returns the live encryption state either way.
A=$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" --region "$REGION" --output json \
      --attribute-names QueueArn KmsMasterKeyId SqsManagedSseEnabled)
ARN=$(printf '%s' "$A" | jq -r '.Attributes.QueueArn // empty')
KEY=$(printf '%s' "$A" | jq -r '.Attributes.KmsMasterKeyId // empty')
SSE=$(printf '%s' "$A" | jq -r '.Attributes.SqsManagedSseEnabled // "absent"')
if   [ -z "$ARN" ];       then echo "[!] INCONCLUSIVE - the read did not return QueueArn; the call failed"
elif [ -n "$KEY" ];       then echo "[OK] encrypted with KMS key $KEY"
elif [ "$SSE" = "true" ]; then echo "[OK] encrypted with the SQS-managed key"
else echo "[FAIL] still UNENCRYPTED - KmsMasterKeyId unset and SqsManagedSseEnabled=$SSE"; fi
```

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     SetQueueAttributes / sqs.amazonaws.com / no errorCode, with EITHER"
echo "  attributes.KmsMasterKeyId = \"\" and no SqsManagedSseEnabled=true in the same call,"
echo "  OR attributes.SqsManagedSseEnabled = \"false\" (the path the source rule cannot reach)."
echo "MUST NOT fire on: KmsMasterKeyId=\"\" WITH SqsManagedSseEnabled=\"true\" - that is a"
echo "  migration from SSE-KMS to SSE-SQS and the queue stays encrypted; nor on a denied call."
echo "EXPECTED FP, by design: a deliberate move to anonymous access. AWS documents disabling"
echo "  SSE as its prerequisite, so that is a true positive about an unauthenticated queue."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the deployment pipeline could remove a queue's encryption | `sqs:SetQueueAttributes` granted broadly; no SCP confining who may change encryption attributes |
| The disable was not detected | The alert matched the event name in the wrong case and tested only one of the two disable paths, so neither shape reached an analyst |
| Nobody could say how many messages were exposed | Sends are data-plane; without `NumberOfMessagesSent` retained over the window there is no count, and message bodies are redacted even where data events are on |
| The queue may have been anonymously reachable | Encryption was treated purely as a data-at-rest control, so its role in rejecting anonymous requests was not part of the change review |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the value is wildcarded: Deny + StringNotEquals against
// a wildcarded ARN matches every principal and denies queue administration outright.
{
  "Effect": "Deny",
  "Action": ["sqs:SetQueueAttributes", "sqs:CreateQueue"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- The SCP reaches the caller, which is always an in-organisation principal here — AWS states
  cross-account permissions do not apply to `SetQueueAttributes` or `CreateQueue`. Pair it
  with a scheduled reconciliation of live queue encryption against the §1 inventory, because
  the SCP cannot see a queue that was created unencrypted before it was deployed.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1600 — Weaken Encryption (primary); T1098 — Account Manipulation (secondary) |
| Primary API | `sqs:SetQueueAttributes` writing `KmsMasterKeyId` or `SqsManagedSseEnabled`; `sqs:CreateQueue` opting out at creation |
| Event source | `sqs.amazonaws.com`, **management** plane, regional — verified against AWS's SQS CloudTrail documentation |
| Key discriminator | `attributes.KmsMasterKeyId` **present and empty** without `SqsManagedSseEnabled=true` in the same call, or `attributes.SqsManagedSseEnabled` = `false`. Presence-versus-emptiness is the distinction the source rule collapses |
| "Was it used" pivot | **Data plane.** Sends and receives are SQS data events, off by default; `lookup-events` returns zero for them forever. Use CloudWatch `AWS/SQS` `NumberOfMessagesSent` bounded by the disable and re-enable times. A stop in `kms:GenerateDataKey` on the queue's key corroborates the disable independently |
| Blast radius | Every message **sent** between the disable and the re-enable. Backlogged messages stay encrypted (SSE does not encrypt a backlog when enabled, and encrypted messages stay encrypted when it is disabled), so the window bounds it on both sides. Queue metadata, message metadata and message attributes were never encrypted at all |
| Error strings | `AccessDeniedException` and `NotAuthorized` are both documented denials; the bare `AccessDenied` form is widely observed but is **not** in SQS's documented list — match all three. Operation-specific: `InvalidAddress`, `InvalidAttributeName`, `InvalidAttributeValue`, `InvalidSecurity`, `OverLimit`, `QueueDoesNotExist`, `RequestThrottled`, `UnsupportedOperation`. A malformed KMS key identifier surfaces as `InvalidAttributeValue`, not as a KMS error |

**MITRE mapping note.** The source maps T1565 / TA0040 (Data Manipulation, Impact); nothing
is manipulated and nothing becomes unavailable, so that is wrong on the merits. T1600's
canonical name describes the act exactly, but ATT&CK lists its platforms as **Network
Devices**, so this is a mapping by intent — there is currently no IaaS-scoped technique for
disabling encryption at rest on a cloud data store. T1685 (Disable or Modify Tools) was
considered and rejected: its scope is security tooling, and SSE is not a tool. The `impact`
segment in this directory's name tracks the source's tactic label.

### Residual Risk

Every message written during the window was stored unencrypted and **cannot be identified
individually** — sends were not logged and bodies are redacted even where data events are on,
so the exposure is a count, never a list. Re-enabling does not retro-encrypt: AWS does not
encrypt a backlog when SSE is turned on, so messages still queued from the window stay in the
clear until consumed or expired. If the policy was opened in the same window the queue was
reachable with no credential, and the identity of whoever read it exists in no log you hold.
And queue metadata, message metadata and message attributes — where applications routinely
put correlation IDs, tenant identifiers and routing keys — were never covered by SSE at all.
