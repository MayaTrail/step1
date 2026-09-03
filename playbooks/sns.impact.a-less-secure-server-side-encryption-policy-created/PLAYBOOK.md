# IR Playbook: SNS Topic Encryption Downgraded to the AWS-Managed Key — key custody transferred via `sns:SetTopicAttributes` `KmsMasterKeyId`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment / weakened encryption (a topic's `KmsMasterKeyId` is moved from a customer-managed key to `alias/aws/sns`, so messages stay encrypted but the account loses the ability to restrict, revoke or delegate the key) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **Medium** for the single event, **High** once the downgrade is confirmed — and the split is the point. The source rule rates it P4 uniformly. P4 is defensible for the bare event, because most matches are a topic being encrypted for the first time, but far too low for a confirmed transfer of key custody: it removes two incident-response levers (revoke by key policy, freeze by disabling the key) and can silently break every cross-account and cross-service publisher. Rating the ambiguous event and the confirmed downgrade the same is what makes the original rule unactionable in both directions at once. |
| MITRE Tactics | Defense Impairment (TA0112), Impact |
| MITRE Techniques | T1600 (the source rule maps T1565 — see the mapping note in `detections/detection_note_t1600.md`) |
| Services in Scope | SNS, KMS, CloudTrail, CloudWatch metrics, IAM, plus every cross-account and cross-service publisher of the topic |

**What the technique does:** the actor calls `SetTopicAttributes` with `AttributeName=KmsMasterKeyId`
and `AttributeValue=alias/aws/sns`. Encryption stays on and message bodies are still
encrypted at rest — what moves is **custody of the key**. An AWS-managed key's policy cannot
be edited, disabled or scheduled for deletion by you, and it cannot be granted to another
account or to a service principal. So the topic loses its second, independent access gate;
the emergency "freeze this topic by making its key unusable" lever disappears; and any
cross-account or cross-service publisher that was working because the customer-managed key
policy granted it starts failing with `KMSAccessDenied`.

**Detection thesis.** The discriminator is not the destination value but the **transition**:
`alias/aws/sns` is a downgrade only if the topic previously held a customer-managed key, and
is an improvement if it was previously unencrypted. CloudTrail records the new value only —
there is no `oldValue` field and no attribute version history — so the source rule, which
matches the destination alone, pages somebody for improving the account's posture in what is
usually the majority of its matches.

---

## 1. Preparation

**Logging & Visibility**

- **CloudTrail management events**, on by default, `eventSource: sns.amazonaws.com`.
  `SetTopicAttributes` and `CreateTopic` are on AWS's published management-event list.
- **Field shapes, and they differ by API.** `SetTopicAttributes` carries the key **flat** in
  `requestParameters.attributeValue`, discriminated by `requestParameters.attributeName`;
  `CreateTopic` **nests** it under `requestParameters.attributes.KmsMasterKeyId`. A query
  that reads only one path silently loses half the events. `SetTopicAttributes` returns
  `responseElements: null`.
- **CloudTrail records the NEW value only.** No `oldValue`, no attribute version history.
  The previous key is recoverable only from earlier `SetTopicAttributes` / `CreateTopic`
  events still inside retention, from infrastructure-as-code state, or from the live API.
  Keep the expected `KmsMasterKeyId` per topic in the §1 baseline.
- **KMS management events survive this change** — unlike the removal variant, the
  `kms:GenerateDataKey` / `kms:Decrypt` trail carrying
  `kms:EncryptionContext:aws:sns:topicArn` continues under the AWS-managed key, so usage
  remains observable throughout.
- **`sns:Publish` is a CloudTrail DATA event** (`eventCategory: "Data"`,
  `managementEvent: false`, type `AWS::SNS::Topic`), **off by default** — `lookup-events`
  returns zero for it forever without a data-event trail, and that zero is "not logged".
- **CloudWatch `AWS/SNS`** — `NumberOfMessagesPublished` and, critically for this use case,
  `NumberOfNotificationsFailed`, dimension `TopicName`, 1-minute resolution.

**Alerting (must be pre-configured)**

- **A topic given a customer-managed key and later moved to `alias/aws/sns`, same topic → P0**
- **`NumberOfNotificationsFailed` non-zero on a topic within an hour of a `KmsMasterKeyId` change → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- Which principals and automation roles touch this service at all. In most estates the list is short, which makes an unfamiliar caller a finding before any threshold is evaluated.
- **The normal value for this measure, per resource, from a quiet week.** The rule compares against a resource's own history rather than a fleet average, so without the baseline the threshold is a guess.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | A topic given a customer-managed key and later moved to `alias/aws/sns`, same topic | CloudTrail (management) | T1600 |
| P1 | `NumberOfNotificationsFailed` non-zero on a topic within an hour of a `KmsMasterKeyId` change | CloudWatch (`AWS/SNS`) | T1600 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `SetTopicAttributes` with `attributeName=KmsMasterKeyId` and `attributeValue=alias/aws/sns`, previous key unknown | CloudTrail (management) | T1600 |
| P2 | Two or more distinct topics moved to the AWS-managed key by one principal within an hour | CloudTrail (management) | T1600 |
| P2 | A live topic whose `KmsMasterKeyId` resolves to `KeyManager: AWS` but whose baseline names a customer-managed key | KMS API (live state) | T1600 |
| P3 | `KMSAccessDenied` reported by a cross-account or cross-service publisher of the topic | Publisher-side logs | T1600 |

### Detection Rule Quality Notes

The source rule fires on the destination value and never asks what the topic had before.

| Issue | Impact | Correction |
|-------|--------|-----------|
| No before-state at all | **Inverts the rule half the time.** `alias/aws/sns` is a downgrade from a customer-managed key and an *improvement* from no encryption, and CloudTrail carries only the new value. In most accounts the improvement case is the majority of matches, so the rule pages somebody for hardening a topic | Single-event rule demoted to `medium`; a `temporal_ordered` correlation requires a customer-managed key on the **same** topic first, which is the real finding at `high` |
| `eventName:"settopicattributes"` and `attributeName:"kmsmasterkeyid"` in lower case | Zero matches on case-sensitive keyword fields. CloudTrail writes `SetTopicAttributes`; SNS validates the attribute name case-sensitively as `KmsMasterKeyId` | Exact-case matches on both |
| Matches only the literal `alias/aws/sns` | The AWS-managed key can be named by key id or key ARN, and those are opaque strings. A downgrade written that way is invisible to any log rule | Live resolution via `kms:DescribeKey` and `KeyMetadata.KeyManager == "AWS"` in Query 2 — an API call, not a log field |
| Reads only `requestParameters.attributeValue` | The `CreateTopic` path nests the key under `attributes.KmsMasterKeyId`; a topic created directly on the AWS-managed key never matches | Both paths read in Query 1 and in the KQL |
| No volume view | One principal moving many topics is a sweep, reported as N unrelated alerts | `value_count` correlation, `gte: 2` — the legitimate baseline for one principal in one hour is exactly one topic |
| Rated P4, mapped to T1565 / Impact | P4 for a confirmed transfer of key custody buries a change that removes two IR levers. And nothing is *manipulated* — control of a key is transferred | Medium bare / high correlated; remapped to T1600 — Weaken Encryption, tactic Defense Impairment (TA0112) |

**Recommended detection — a topic's encryption key changed to the AWS-managed SNS key.**

```yaml
# SNS topic encryption downgraded to the AWS-managed key (T1600)
#
# THE ORIGINAL RULE HAS NO BEFORE-STATE, AND THAT INVERTS IT HALF THE TIME. It fires on
# `SetTopicAttributes` setting KmsMasterKeyId to `alias/aws/sns`, and calls that a "less
# secure encryption policy". Whether it IS less secure depends entirely on what the topic
# had a moment earlier:
#     customer-managed key  ->  alias/aws/sns   = a real downgrade
#     no encryption at all  ->  alias/aws/sns   = encryption being TURNED ON
# CloudTrail records the NEW value only — there is no `oldValue` field and no attribute
# version history — so the single event cannot tell those apart, and the rule as written
# alerts on somebody improving the account's posture. That is the defect worth fixing, and
# it is fixed structurally: the single-event rule is demoted to `medium`, and a correlation
# supplies the before-state by requiring a customer-managed key to have been set on the SAME
# topic first.
#
# Two case errors, both fatal on a case-sensitive keyword field: the original matched
# `eventName:"settopicattributes"` and `attributeName:"kmsmasterkeyid"`. CloudTrail writes
# `SetTopicAttributes`, and SNS validates the attribute name case-sensitively as
# `KmsMasterKeyId`.
#
# WHAT THIS RULE SET STRUCTURALLY CANNOT SEE: the AWS-managed key can also be named by key
# id or key ARN rather than by the `alias/aws/sns` alias, and those forms are opaque strings
# with nothing to match on. Distinguishing them requires `kms:DescribeKey` and reading
# `KeyMetadata.KeyManager == "AWS"`, which is an API call, not a log field. Query 2 of the
# playbook does it; no Sigma rule can.
title: SNS topic encryption changed to the AWS-managed key
id: 2484a22e-3632-4160-9988-e5c44a6264b3
name: sns_sse_set_aws_managed
status: experimental
description: >-
  SetTopicAttributes pointing a topic's KmsMasterKeyId at the AWS-managed SNS key. On its
  own this is ambiguous — it is a downgrade only if the topic previously used a
  customer-managed key, and an improvement if it was previously unencrypted — so it is
  medium, and the correlation below supplies the missing before-state.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html
  - https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html
  - https://attack.mitre.org/techniques/T1600/
tags:
  - attack.defense-impairment
  - attack.impact
  - attack.t1600
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sns.amazonaws.com'
    eventName: 'SetTopicAttributes'
  kms_attribute:
    requestParameters.attributeName: 'KmsMasterKeyId'
  aws_managed:
    requestParameters.attributeValue|re: '(?i)(^|[:/])alias/aws/sns$'
  success:
    errorCode: null
  condition: selection and kms_attribute and aws_managed and success
falsepositives:
  - A topic being encrypted for the FIRST time with the AWS-managed key. This is an
    improvement, not an incident, and it is the majority of this rule's matches — which is
    why it is medium and why the correlation exists. Triage by reading the previous key.
level: medium
---
title: SNS topic encryption set to a customer-managed key
id: 1008b98f-cec3-4305-8d63-0c08b970b6cd
name: sns_sse_set_customer_managed
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. SetTopicAttributes setting
  KmsMasterKeyId to anything that is not the AWS-managed SNS alias and is not empty. It
  exists to establish the BEFORE-state the downgrade correlation needs, and it carries the
  success filter so a denied key change cannot satisfy the first half of that sequence.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html
  - https://attack.mitre.org/techniques/T1600/
tags:
  - attack.defense-impairment
  - attack.t1600
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sns.amazonaws.com'
    eventName: 'SetTopicAttributes'
  kms_attribute:
    requestParameters.attributeName: 'KmsMasterKeyId'
  has_value:
    requestParameters.attributeValue|re: '\S'
  aws_managed:
    requestParameters.attributeValue|re: '(?i)(^|[:/])alias/aws/sns$'
  success:
    errorCode: null
  condition: selection and kms_attribute and has_value and success and not aws_managed
level: low
---
title: SNS topic downgraded from a customer-managed key to the AWS-managed key
id: e8190bdb-5313-474e-adb2-e09c3e7c755b
status: experimental
description: >-
  The same topic given a customer-managed key and then moved to the AWS-managed SNS key.
  This is the real finding the single-event rule cannot express: it supplies the before-state
  CloudTrail omits, so it separates a genuine downgrade from a topic being encrypted for the
  first time. Timespan basis — 30 days is a retention-shaped figure, not a behavioural one:
  the two events are usually months apart, and the window is set to the longest span a
  correlation engine will realistically hold rather than to any property of the technique.
  Treat a non-match as "no evidence in the window", never as "not a downgrade", and read the
  live key with kms:DescribeKey instead. Grouped on requestParameters.topicArn, which both
  component rules emit — the CreateTopic path is deliberately excluded, because it carries
  the topic ARN in responseElements and would silently never group.
references:
  - https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html
  - https://attack.mitre.org/techniques/T1600/
tags:
  - attack.defense-impairment
  - attack.impact
  - attack.t1600
correlation:
  type: temporal_ordered
  rules:
    - sns_sse_set_customer_managed
    - sns_sse_set_aws_managed
  group-by:
    - requestParameters.topicArn
  timespan: 30d
level: high
---
title: Repeated SNS topic encryption changes across distinct topics
id: 2a38ef25-1600-4b6e-8188-2ac62c436a01
status: experimental
description: >-
  Two or more DISTINCT topics moved to the AWS-managed key by the same principal inside an
  hour. Threshold basis — a key change is a deliberate, individually justified act, so the
  legitimate baseline for one principal in one hour is exactly one topic; `gte: 2` fires on
  the first event that exceeds that baseline rather than falling through it. A bulk
  migration will trip this; suppress the migration's role for its window rather than raising
  the count, because raising it hides the sweep this exists to catch.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html
  - https://attack.mitre.org/techniques/T1600/
tags:
  - attack.defense-impairment
  - attack.t1600
correlation:
  type: value_count
  rules:
    - sns_sse_set_aws_managed
  group-by:
    - userIdentity.arn
  field: requestParameters.topicArn
  timespan: 1h
  condition:
    gte: 2
level: medium
```

This rule is deliberately `medium` and deliberately over-matches: it cannot see the previous
key, so it fires on the improvement case too. The correlation in the same file supplies the
before-state and is the document to page on. Its 30-day timespan is **retention-shaped, not
behavioural** — key changes are typically months apart, so a non-match means "no evidence in
the window", never "not a downgrade". The authoritative answer is the live read in Query 2.

---

### Key Investigation Queries

> SNS is regional and topic ARNs are region-scoped — run both queries per region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page**; Query 1 pages on `NextToken` rather than silently truncating.

#### Query 1 — Reconstruct: every key change on every topic, in order

```bash
REGION="<region>"; START="<ISO8601-start>"; END="<ISO8601-end>"

for EN in SetTopicAttributes CreateTopic; do
  TOKEN=""
  while : ; do
    PAGE=$(aws cloudtrail lookup-events --region "$REGION" --output json --max-results 50 \
             --lookup-attributes AttributeKey=EventName,AttributeValue="$EN" \
             --start-time "$START" --end-time "$END" ${TOKEN:+--next-token "$TOKEN"} 2>&1)
    if ! printf '%s' "$PAGE" | jq -e 'has("Events")' >/dev/null 2>&1; then
      echo "[!] INCONCLUSIVE $EN — lookup-events returned no Events key: $PAGE"; break
    fi
    # SetTopicAttributes carries the key FLAT; CreateTopic NESTS it under attributes.
    # Reading only one path silently loses half the history.
    printf '%s' "$PAGE" | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.eventSource == "sns.amazonaws.com")
      | select(.eventName == "CreateTopic"
               or .requestParameters.attributeName == "KmsMasterKeyId")
      | {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
         ip: .sourceIPAddress, err: (.errorCode // "none"),
         topicArn: (.responseElements.topicArn // .requestParameters.topicArn // "unknown"),
         key: (.requestParameters.attributeValue
               // .requestParameters.attributes.KmsMasterKeyId // "<NONE>")}'
    TOKEN=$(printf '%s' "$PAGE" | jq -r '.NextToken // empty')
    [ -n "$TOKEN" ] || break
  done
done | sort -t'"' -k4
```

Sort the output by `topicArn` and read each topic's rows in time order — that sequence is the
before-state CloudTrail does not give you in any single event. A row whose `key` ends
`alias/aws/sns` immediately after a row with a different non-empty `key` on the same topic is
the **downgrade**. The same row immediately after `<NONE>`, or as the topic's first row, is
encryption being turned on and is **not** an incident. If a topic's first row in the window
is already the downgrade, the previous key is outside retention — record it as unknown and
resolve it in Query 2, never as "the topic was unencrypted". `err` of `AuthorizationError` is
a denied attempt; SNS never emits `AccessDenied`. `topicArn`, `caller` and `time` feed every
step below.

#### Query 2 — Inspect: resolve every topic's live key and ask KMS who manages it

```bash
REGION="<region>"; OUT="/tmp/sns_topics_$REGION.ndjson"
EXPECTED_KEY="<expected-cmk-arn-or-alias>"      # from the §1 baseline

if ! bash tools/sns_collect_topic_policies.sh "$REGION" > "$OUT"; then
  echo "[!] INCONCLUSIVE — topic enumeration failed; nothing here is a clean result."
else
  for T in $(jq -r '.grantee' "$OUT"); do
    A=$(aws sns get-topic-attributes --region "$REGION" --topic-arn "$T" --output json 2>&1)
    # GetTopicAttributes always returns an Attributes map for a topic that exists, so an
    # absent key is a failed call — never a topic with "no configuration".
    if ! printf '%s' "$A" | jq -e '.Attributes' >/dev/null 2>&1; then
      echo "[!] INCONCLUSIVE $T — get-topic-attributes failed: $A"; continue
    fi
    K=$(printf '%s' "$A" | jq -r '.Attributes.KmsMasterKeyId // ""')
    if [ -z "$K" ]; then
      echo "[!] UNENCRYPTED $T — see the sibling use case, sns.impact.server-side-encryption-...-was-disabled"
      continue
    fi
    # THE AUTHORITATIVE TEST. alias/aws/sns is only one of three ways to name the AWS-managed
    # key; key id and key ARN are opaque strings no log rule can classify. KeyManager can.
    D=$(aws kms describe-key --region "$REGION" --key-id "$K" --output json 2>&1)
    if ! printf '%s' "$D" | jq -e '.KeyMetadata.KeyManager' >/dev/null 2>&1; then
      echo "[!] INCONCLUSIVE $T — cannot resolve key $K: $D"; continue
    fi
    MGR=$(printf '%s' "$D" | jq -r '.KeyMetadata.KeyManager')
    if [ "$MGR" = "AWS" ]; then
      echo "[!] AWS-MANAGED $T  key=$K  — no key-policy control, no disable, no cross-account grant"
    elif [ "$K" = "$EXPECTED_KEY" ]; then
      echo "[OK] $T  key=$K (customer-managed, matches baseline)"
    else
      echo "[?] CUSTOMER-MANAGED but off-baseline  $T  key=$K  expected=$EXPECTED_KEY"
    fi
  done
fi
```

`[!] AWS-MANAGED` is the live finding and the work-list for §3 — and because it asks KMS
rather than pattern-matching a string, it catches the key-id and key-ARN forms that every log
rule misses. Cross-reference each hit against Query 1: if a customer-managed key appears
earlier for the same topic, the downgrade is confirmed and this is a P0. If nothing appears,
the change predates retention and the §1 baseline is the only remaining source of truth.
`[?] CUSTOMER-MANAGED but off-baseline` is a different finding — the key moved sideways, not
down — and needs the same triage but not this playbook's containment.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="SetTopicAttributes"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "sns.amazonaws.com") |
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

Restore the expected customer-managed key, but check the key is usable **first**: pointing a
topic at a disabled, deleted or asymmetric key fails every subsequent publish, which converts
a custody problem into an outage. Note what this containment does *not* fix — messages
published while the AWS-managed key was in force stay encrypted under that key, and you never
gain retrospective control of it.

> Run under the **break-glass responder credentials**, not the principal under investigation.

#### Step 1 — Confirm the key is usable, then restore it

```bash
REGION="<region>"; TOPIC="<topic-arn-from-Query-1>"; CMK="<expected-cmk-arn-or-alias>"

KEY=$(aws kms describe-key --region "$REGION" --key-id "$CMK" --output json 2>&1)
if ! printf '%s' "$KEY" | jq -e '.KeyMetadata.KeyState' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — cannot read $CMK: $KEY"
  echo "    Do NOT set the attribute yet; a topic pointed at an unusable key fails every publish."
elif [ "$(printf '%s' "$KEY" | jq -r '.KeyMetadata.KeyState')" != "Enabled" ]; then
  echo "[FAIL] $CMK is $(printf '%s' "$KEY" | jq -r '.KeyMetadata.KeyState') — enable it first"
elif [ "$(printf '%s' "$KEY" | jq -r '.KeyMetadata.KeySpec')" != "SYMMETRIC_DEFAULT" ]; then
  echo "[FAIL] $CMK is $(printf '%s' "$KEY" | jq -r '.KeyMetadata.KeySpec') — SNS supports symmetric keys only"
elif [ "$(printf '%s' "$KEY" | jq -r '.KeyMetadata.KeyManager')" != "CUSTOMER" ]; then
  echo "[FAIL] $CMK is AWS-managed — restoring to it re-creates the very condition being contained"
else
  echo "[OK] $CMK is an enabled, symmetric, customer-managed key"
  aws sns set-topic-attributes --region "$REGION" --topic-arn "$TOPIC" \
    --attribute-name KmsMasterKeyId --attribute-value "$CMK"
  NOW=$(aws sns get-topic-attributes --region "$REGION" --topic-arn "$TOPIC" --output json 2>&1)
  if printf '%s' "$NOW" | jq -e '.Attributes' >/dev/null 2>&1; then
    LIVE=$(printf '%s' "$NOW" | jq -r '.Attributes.KmsMasterKeyId // ""')
    [ "$LIVE" = "$CMK" ] && echo "[OK] $TOPIC restored to $LIVE" \
                         || echo "[FAIL] $TOPIC reports $LIVE after the write, expected $CMK"
  else
    echo "[!] INCONCLUSIVE — could not re-read $TOPIC to confirm the write: $NOW"
  fi
fi
```

#### Step 2 — Contain the principal

```bash
CALLER="<caller-arn-from-Query-1>"
FREEZE='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["sns:SetTopicAttributes","sns:CreateTopic"],"Resource":"*"}]}'
case "$CALLER" in
  *":user/"*)          # IAM user: the name is $NF. Disable keys before attaching the deny.
    UNAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$UNAME" \
                 --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$UNAME" --access-key-id "$K" --status Inactive
    done
    aws iam put-user-policy --user-name "$UNAME" --policy-name IR-SNS-Freeze \
      --policy-document "$FREEZE" && echo "[OK] contained IAM user $UNAME" ;;
  *":assumed-role/"*)  # Role name is the 2nd '/' segment; $NF is the SESSION name.
    RNAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$RNAME" --policy-name IR-SNS-Freeze \
      --policy-document "$FREEZE" && echo "[OK] contained IAM role $RNAME" ;;
  *)
    echo "[!] $CALLER is root, federated or a service principal — contain manually." ;;
esac
```

---

## 4. Eradication

### Remove Attacker Access

- **Sweep every region.** Re-run Query 2 account-wide: the `value_count` correlation only
  tells you more than one topic was touched, and the key-id and key-ARN forms of the
  AWS-managed key are invisible to every log rule — only the `KeyManager` read finds them.
- **Check every cross-account and cross-service publisher of each affected topic.** This is
  the step specific to a *downgrade* rather than a removal: an AWS-managed key policy cannot
  be granted to another account or to a service principal, so S3 event notifications,
  cross-account CloudWatch alarms, EventBridge rules and any partner account that was
  publishing were silently failing for the whole window. Their symptom is `KMSAccessDenied`
  on their side and `NumberOfNotificationsFailed` on the topic — and messages they failed to
  publish were **never delivered to anyone**, so this is a data-loss review as well as a
  security one.
- **Do not treat this as a disclosure.** Message bodies stayed encrypted throughout, and SSE
  never covered topic metadata, message metadata (subject, message id, timestamp, message
  attributes), the data protection policy or per-topic metrics — before or after. Scope the
  incident as loss of key custody and of the two IR levers it carried, not as exposure of
  message content.
- **Right-size the permission** — see the guardrail bullets in §6.
- **Remove the emergency deny once clean** — `delete-user-policy` or `delete-role-policy` for
  `IR-SNS-Freeze`. Containment could have attached either, so check both paths, and confirm
  with the §5 assertion rather than by assuming the delete succeeded.

---

## 5. Recovery

### Restore Clean State

#### Verify every topic's live key is customer-managed and matches the baseline

```bash
REGION="<region>"; OUT="/tmp/sns_recovery_$REGION.ndjson"
EXPECTED_KEY="<expected-cmk-arn-or-alias>"
# The signal survives the remediation: DescribeKey reports KeyManager for whatever key the
# topic points at, so this check can still emit AWS-managed after the fix — [FAIL] is
# reachable, not zero by construction.
if ! bash tools/sns_collect_topic_policies.sh "$REGION" > "$OUT"; then   # exits 2 on read failure
  echo "[!] INCONCLUSIVE — could not enumerate topics; nothing is certified clean"
else
  BAD=0
  for T in $(jq -r '.grantee' "$OUT"); do
    A=$(aws sns get-topic-attributes --region "$REGION" --topic-arn "$T" --output json 2>&1)
    if ! printf '%s' "$A" | jq -e '.Attributes' >/dev/null 2>&1; then
      echo "[!] INCONCLUSIVE $T — get-topic-attributes failed: $A"; BAD=2; continue
    fi
    K=$(printf '%s' "$A" | jq -r '.Attributes.KmsMasterKeyId // ""')
    if [ -z "$K" ]; then
      echo "[FAIL] $T has no KmsMasterKeyId at all"; [ "$BAD" = 2 ] || BAD=1; continue
    fi
    D=$(aws kms describe-key --region "$REGION" --key-id "$K" --output json 2>&1)
    if ! printf '%s' "$D" | jq -e '.KeyMetadata.KeyManager' >/dev/null 2>&1; then
      echo "[!] INCONCLUSIVE $T — cannot resolve $K: $D"; BAD=2; continue
    fi
    if [ "$(printf '%s' "$D" | jq -r '.KeyMetadata.KeyManager')" != "CUSTOMER" ]; then
      echo "[FAIL] $T still points at an AWS-managed key ($K)"; [ "$BAD" = 2 ] || BAD=1
    elif [ "$K" != "$EXPECTED_KEY" ]; then
      echo "[FAIL] $T uses $K, expected $EXPECTED_KEY"; [ "$BAD" = 2 ] || BAD=1
    fi
  done
  case "$BAD" in
    0) echo "[OK] every topic in $REGION uses the expected customer-managed key" ;;
    1) echo "[FAIL] at least one topic is on an AWS-managed or off-baseline key" ;;
    *) echo "[!] INCONCLUSIVE — at least one topic or key could not be read; nothing certified" ;;
  esac
fi
```

#### Verify the publishers that the downgrade broke are delivering again

```bash
REGION="<region>"; TOPIC="<topic-arn-from-Query-1>"
TOPIC_NAME=$(printf '%s' "$TOPIC" | awk -F':' '{print $NF}')
# Asked AFTER the restore, of a metric that can still move: if the restored CMK's key policy
# does not grant kms:GenerateDataKey and kms:Decrypt to sns.amazonaws.com for this topic ARN,
# publishing fails and this check reports it rather than certifying silence.
FAILED=$(aws cloudwatch get-metric-statistics --region "$REGION" \
  --namespace AWS/SNS --metric-name NumberOfNotificationsFailed \
  --dimensions Name=TopicName,Value="$TOPIC_NAME" \
  --start-time "<ISO8601-restore-time>" --end-time "<ISO8601-now>" \
  --period 300 --statistics Sum --output json 2>&1)
if ! printf '%s' "$FAILED" | jq -e 'has("Datapoints")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — get-metric-statistics returned no Datapoints key: $FAILED"
else
  N=$(printf '%s' "$FAILED" | jq '[.Datapoints[].Sum] | add // 0')
  if [ "$N" = "0" ]; then
    echo "[OK] no delivery failures since the key was restored"
  else
    echo "[FAIL] $N delivery failure(s) since the restore — confirm the CMK key policy grants"
    echo "       kms:GenerateDataKey and kms:Decrypt to sns.amazonaws.com for $TOPIC"
  fi
fi
```

#### Confirm the corrected detection fires

```bash
echo 'MUST fire (medium) on: SetTopicAttributes, sns.amazonaws.com, no errorCode,'
echo '   attributeName = "KmsMasterKeyId", attributeValue = "alias/aws/sns"'
echo 'CORRELATION must fire (high) on: attributeValue = a customer-managed key on a topic,'
echo '   THEN attributeValue = "alias/aws/sns" on the SAME requestParameters.topicArn.'
echo 'MUST NOT fire on: attributeName = "KmsMasterKeyId" with a customer-managed key value.'
echo 'MUST NOT fire on: an EMPTY attributeValue — that is the sibling use case,'
echo '   sns.impact.server-side-encryption-for-aws-sns-topics-was-disabled.'
echo 'EXPECTED FP, by design: a topic encrypted for the FIRST time with alias/aws/sns fires'
echo '   the medium rule. That is an improvement, not an incident, and it is why the'
echo '   single-event rule is medium and the correlation carries the page.'
echo 'EXPECTED FN, by design: the AWS-managed key named by key id or key ARN instead of the'
echo '   alias. Opaque to every log rule; only the kms:DescribeKey KeyManager read in'
echo '   Query 2 finds it.'
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A topic's key was moved from customer-managed to AWS-managed by a principal outside the deployment role | `sns:SetTopicAttributes` on `Resource: "*"` was reachable outside deployment, and nothing distinguishes a key change from a display-name change at the API |
| Whether it was a downgrade or an improvement could not be told from the alert | CloudTrail records the new value only, and no per-topic expected-key baseline existed to compare against |
| Cross-account and cross-service publishers failed silently for the whole window | `NumberOfNotificationsFailed` was not alarmed per topic, so an outage introduced by a security-relevant change went unnoticed |
| The change was indistinguishable from routine topic maintenance at the API | `SetTopicAttributes` carries the attribute name in the request, but the rule matched the call rather than the attribute, so display-name edits and key changes were rated alike |
| Recovery could not be verified without knowing the intended key | No per-topic expected-key record existed, so restoring meant asking the owning team rather than reading a baseline |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// An SCP is the right instrument here, unlike the public-grant use cases: the actor is one
// of your OWN principals calling SetTopicAttributes, so it is in scope for an SCP; the
// resource-side RCP that constrains outside principals does not reach this at all.
// Failure direction: Deny + StringNotLike denies every SetTopicAttributes whose caller is
// not the deployment role — the intent — so a wrong role ARN takes the pipeline offline
// rather than leaving the gap open. StringNotEquals would be WRONG here because the value
// carries a wildcard: * is expanded only by the *Like operators, so StringNotEquals against
// ".../deploy-*" matches nothing and therefore denies everyone.
{
  "Sid": "DenyTopicAttributeWritesOutsideDeploy",
  "Effect": "Deny",
  "Action": ["sns:SetTopicAttributes", "sns:CreateTopic"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/deploy-*" }
  }
}
```

- Put the control **on the SNS side, not the KMS side**. A key policy cannot stop this:
  nothing in the technique touches the key, only the topic's pointer to it. Denying
  `sns:SetTopicAttributes` outside the deployment role is the control that applies.
- Maintain the per-topic expected-`KmsMasterKeyId` baseline named in §1 and diff
  `GetTopicAttributes` + `kms:DescribeKey` against it on a schedule. That diff is the only
  control that resolves the key-id and key-ARN forms, and the only one that supplies the
  before-state CloudTrail omits.
- Alarm `NumberOfNotificationsFailed` per topic. It is the fastest signal that a key change
  broke a publisher, and it fires whether the change was hostile or a mistake.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1600 — Weaken Encryption, tactic Defense Impairment (TA0112). Tagged `attack.defense-impairment`; `attack.defense-evasion` is retired, TA0005 having been renamed Stealth |
| Primary API | `sns:SetTopicAttributes` with `AttributeName=KmsMasterKeyId` and `AttributeValue=alias/aws/sns`; `sns:CreateTopic` with `Attributes.KmsMasterKeyId` for the create path. Event source `sns.amazonaws.com`, **management** plane, on by default |
| Key discriminator | The **transition**, not the destination — `alias/aws/sns` is a downgrade only from a customer-managed key, and an improvement from none. CloudTrail carries no `oldValue`, so the before-state comes from the correlation, from Query 1's ordered history, or from the baseline |
| Ground-truth signal | `requestParameters.attributeValue` (SetTopicAttributes, **flat**) or `requestParameters.attributes.KmsMasterKeyId` (CreateTopic, **nested**) — both paths are real |
| "Was it used" pivot | Not applicable; the change *is* the harm. Bound the window with CloudWatch `NumberOfMessagesPublished` by `TopicName`, and detect the breakage with `NumberOfNotificationsFailed`. The KMS trail survives this change — `kms:GenerateDataKey` continues under the AWS-managed key |
| Blast radius | Loss of key custody: no key-policy restriction, no revoke-by-disable, no cross-account or cross-service grant. Message bodies stay encrypted throughout — this is **not** a content disclosure |
| Error strings | `AuthorizationError` (403 — SNS does **not** use `AccessDenied`), `InvalidParameter` (including an unresolvable key identifier), `InvalidSecurity`, `InternalError`, `NotFound`. Publisher-side: `KMSAccessDenied`, `KMSDisabled`, `KMSInvalidState` (not `…Exception`), `KMSNotFound`, `KMSOptInRequired`, `KMSThrottling` — `KMSAccessDenied` on a cross-account publisher is this downgrade's signature |
| Document size | Not applicable — `KmsMasterKeyId` is a short key identifier, nowhere near CloudTrail's 100 KB `requestParameters` omission threshold, so **no oversized-document companion rule ships** |

### Residual Risk

Restoring the customer-managed key does not retroactively re-encrypt anything. Every message
published while the topic pointed at the AWS-managed key remains encrypted **under that key**,
and you will never hold the policy, the disable switch or the deletion schedule for it — so
for that window the two incident-response levers this playbook exists to protect stay
permanently unavailable, no matter what you do now. Messages that cross-account and
cross-service publishers failed to send during the window were never delivered to anyone and
are not recoverable from SNS; whether they were retried is a property of each publisher, not
of SNS, and has to be established publisher by publisher. Finally, if the change predates your
CloudTrail retention, no query in this playbook can tell you the original key — the §1
baseline is the only remaining record, and if it does not exist, the topic's correct key is
now a matter of reconstruction rather than evidence.
