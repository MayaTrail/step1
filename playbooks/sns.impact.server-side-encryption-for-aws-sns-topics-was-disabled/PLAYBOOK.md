# IR Playbook: SNS Topic Encryption Disabled — protective control removed via `sns:SetTopicAttributes` `KmsMasterKeyId`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment / weakened encryption (a topic's `KmsMasterKeyId` is cleared, so message bodies published from that moment are stored without a KMS key, and the key policy stops acting as a second gate on the topic) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, against the source rule's P4. P4 routes an account's encryption control being switched off to a queue nobody reads before morning — and here the response time *is* the exposure window, because every message published between the disable and the restore is stored without your key and no later action recovers that. It is also the enabling step for cross-account access to a CMK-encrypted topic, so rating it as a compliance ticket misses the sequence it usually belongs to. Not P0 only because no credential is exposed and the blast radius is bounded on both sides by what SNS does and does not retroactively encrypt. |
| MITRE Tactics | Defense Impairment (TA0112), Impact |
| MITRE Techniques | T1600 (the source rule maps T1565 — see the mapping note in `detections/detection_note_t1600.md`) |
| Services in Scope | SNS, KMS, CloudTrail, CloudWatch metrics, IAM, Organizations, and every publisher and subscriber of the topic |

**What the technique does:** the actor calls `SetTopicAttributes` with `AttributeName=KmsMasterKeyId`
and an empty or omitted `AttributeValue`. SNS accepts it and stops encrypting. From that
instant, message bodies published to the topic are stored without a KMS key, and — where the
topic used a **customer-managed** key — the key policy stops gating who can use the topic at
all. That second effect is usually the point: a principal granted `sns:Subscribe` on a
CMK-encrypted topic still reads nothing unless the key policy also lets SNS decrypt on their
behalf, so an actor widening access has to clear the key first.

**Detection thesis.** The discriminator is `requestParameters.attributeName` — the event
name alone cannot tell an encryption change from a policy change, a display-name change or a
delivery-policy change, because `SetTopicAttributes` carries all of them. The source rule
gets that right and then loses the finding twice: it matches `settopicattributes` and
`kmsmasterkeyid` in lower case against case-sensitive values, and it tests only for
`attributeValue` being **absent**, so the empty-string form that `--attribute-value ""`
produces is a silent false negative.

---

## 1. Preparation

**Logging & Visibility**

- **CloudTrail management events**, on by default, `eventSource: sns.amazonaws.com`.
  `SetTopicAttributes` is on AWS's published management-event list.
- **Field shapes.** `requestParameters.attributeName` and `requestParameters.attributeValue`
  are **flat siblings** of `requestParameters.topicArn`, not nested under an `attributes`
  map — that nesting belongs to `CreateTopic`, which carries `attributes.KmsMasterKeyId`
  instead. `SetTopicAttributes` returns `responseElements: null`, so there is no
  response-side value to compare against.
- **CloudTrail records the NEW value only.** There is no `oldValue` field and no version
  history on a topic attribute, so "what key was this before?" is answerable only from
  earlier `SetTopicAttributes` / `CreateTopic` events still inside your retention, from
  infrastructure-as-code state, or from the KMS key's own usage history. Keep the expected
  `KmsMasterKeyId` per topic in the §1 baseline; without it this incident has no known-good.
- **KMS management events** — while a customer-managed key is in use, every publish and
  delivery produces `kms:GenerateDataKey` / `kms:Decrypt` carrying
  `kms:EncryptionContext:aws:sns:topicArn`. These are management events, logged by default,
  and they are the **only** usage record for a topic whose own `Publish` events are not
  logged. The disable ends them.
- **`sns:Publish` is a CloudTrail DATA event** (`eventCategory: "Data"`,
  `managementEvent: false`, type `AWS::SNS::Topic`), **off by default** — `lookup-events`
  returns zero for it forever without a data-event trail, and that zero is "not logged".
- **CloudWatch `AWS/SNS`** — `NumberOfMessagesPublished` and `NumberOfNotificationsFailed`,
  dimension `TopicName`, 1-minute resolution. This is the pivot that actually answers
  "was anything published while unencrypted".

**Alerting (must be pre-configured)**

- **`SetTopicAttributes` with `attributeName=KmsMasterKeyId` and an empty or absent `attributeValue` → P0**
- **Encryption removed and the topic's access policy rewritten within an hour, same topic → P0**
- **Two or more distinct topics stripped of encryption by one principal within an hour → P0**
- **A denied encryption change — `AuthorizationError` on `SetTopicAttributes` with `attributeName=KmsMasterKeyId` → P1**

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
| P0 | `SetTopicAttributes` with `attributeName=KmsMasterKeyId` and an empty or absent `attributeValue` | CloudTrail (management) | T1600 |
| P0 | Encryption removed and the topic's access policy rewritten within an hour, same topic | CloudTrail (management) | T1600, T1098 |
| P0 | Two or more distinct topics stripped of encryption by one principal within an hour | CloudTrail (management) | T1600 |
| P1 | A denied encryption change — `AuthorizationError` on `SetTopicAttributes` with `attributeName=KmsMasterKeyId` | CloudTrail (management) | T1600 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `kms:GenerateDataKey` with `kms:EncryptionContext:aws:sns:topicArn` for a topic stopping abruptly | CloudTrail (management) | T1600 |
| P2 | `NumberOfMessagesPublished` non-zero on a topic during a window in which its encryption was off | CloudWatch (`AWS/SNS`) | T1600 |

### Detection Rule Quality Notes

The source rule has the right discriminator and then loses the finding twice on field shape.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Tests only `NOT _exists_:requestParameters.attributeValue` | Silent false negative on the empty-string form. `AttributeValue` is documented `Required: No`, but a caller sending `""` **sends the parameter**, so CloudTrail records `attributeValue: ""`, which exists. `aws sns set-topic-attributes --attribute-value ""` is exactly that call | Two **sibling** blocks, `value_absent` and `value_empty`, OR'd in the condition — they cannot co-occur on one event, so ANDing them in a single block would mean the rule never fires |
| `eventName:"settopicattributes"` and `attributeName:"kmsmasterkeyid"` in lower case | Zero matches on case-sensitive keyword fields. CloudTrail writes `SetTopicAttributes`; SNS validates the attribute name case-sensitively as `KmsMasterKeyId` | Exact-case matches on both |
| Fires on the disable in isolation | The disable alone is often a misguided cost or compatibility change. The disable **followed by** an access-policy widening is a deliberate sequence, and the order is forced — reversed, the new principal is still locked out by KMS | `temporal_ordered` correlation over the two, grouped on `requestParameters.topicArn`, which both component rules emit |
| No volume view | One principal clearing encryption across many topics is a sweep, and the single-event rule reports it as N unrelated P0s | `value_count` correlation, `gte: 2` — the legitimate baseline for one principal in one hour is exactly one topic |
| Rated P4, mapped to T1565 / Impact | P4 routes the loss of an encryption control to an overnight queue while the exposure window runs. And nothing is *manipulated* — a protective control is removed | High; remapped to T1600 — Weaken Encryption, tactic Defense Impairment (TA0112) |

**Recommended detection — server-side encryption cleared from an SNS topic.**

```yaml
# Server-side encryption disabled on an SNS topic (T1600)
#
# The original rule is closer to correct than most in this set, and its one structural flaw
# is invisible: it matched `NOT _exists_:requestParameters.attributeValue`, i.e. the field
# being ABSENT. SetTopicAttributes documents `AttributeValue` as `Required: No`, so an
# omitted value is legal — but a caller that sends an EMPTY STRING sends the parameter, and
# CloudTrail then records `attributeValue: ""`, which EXISTS. `aws sns set-topic-attributes
# --attribute-value ""` is exactly that shape. On the absence-only test that call is a
# silent false negative, and a false negative on the one rule that watches encryption is the
# worst kind. These rules OR the two shapes as SIBLING blocks — they are mutually exclusive
# on a single event, so ANDing them in one block would mean the rule never fires at all.
#
# Two case errors, both fatal on a case-sensitive keyword field: the original matched
# `eventName:"settopicattributes"` and `attributeName:"kmsmasterkeyid"`. CloudTrail writes
# `SetTopicAttributes`, and the attribute name is `KmsMasterKeyId` — SNS validates that
# value case-sensitively against its documented attribute list.
#
# NOT VERIFIED, and it matters: AWS documents that a topic's encryption CAN be disabled
# ("Any encrypted message remains encrypted even if the encryption of its topic is
# disabled") but does NOT document the wire form that does it. The only shape the API
# surface permits is SetTopicAttributes with AttributeName=KmsMasterKeyId and AttributeValue
# empty or omitted. Whether CloudTrail then records `attributeValue: ""` or omits the key is
# OBSERVED, not documented — which is precisely why both shapes are matched here rather than
# one being chosen. Confirm against a real event in your own account before tuning.
title: SNS topic server-side encryption disabled
id: 8efa359f-4f1d-4344-8444-8032c494196e
name: sns_sse_disabled
status: experimental
description: >-
  SetTopicAttributes clearing KmsMasterKeyId — the only API shape that removes server-side
  encryption from a topic. Matches both the empty-string and the omitted-value form,
  because which one CloudTrail records is not documented.
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
  value_absent:
    requestParameters.attributeValue: null
  value_empty:
    requestParameters.attributeValue: ''
  success:
    errorCode: null
  condition: selection and kms_attribute and success and (value_absent or value_empty)
falsepositives:
  - A deliberate migration away from SSE — should be rare, planned, and performed by the
    deployment role. Allowlist the role in the base rule below, not this one.
level: high
---
title: SNS topic access policy written by any principal
id: fd12f99f-d891-4cee-81eb-7067e2540d2d
name: sns_topic_policy_written
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. Any successful write to a
  topic's Policy attribute. Carries the success filter so a DENIED policy write followed by
  a legitimate encryption change cannot raise the correlation below to high.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html
  - https://attack.mitre.org/techniques/T1098/
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sns.amazonaws.com'
    eventName: 'SetTopicAttributes'
  policy_attribute:
    requestParameters.attributeName: 'Policy'
  success:
    errorCode: null
  condition: selection and policy_attribute and success
level: low
---
title: SNS topic encryption disabled and then its access policy rewritten
id: 95953d89-88ec-480f-815c-1ef21d8c5c3b
status: experimental
description: >-
  A topic's server-side encryption removed and its access policy rewritten within the hour,
  in that order, on the same topic. This is the two-step that makes the disable worth a P0
  rather than a compliance ticket: a customer-managed key's policy is a second, independent
  gate on the topic, so an actor widening access to a CMK-encrypted topic must remove the
  key first or the new principal still cannot read anything. Timespan basis — the two calls
  are consecutive steps of one script and normally land seconds apart; an hour is generous
  and short enough that an unrelated planned policy edit rarely lands inside it. Grouped on
  requestParameters.topicArn, which both component rules emit.
references:
  - https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html
  - https://attack.mitre.org/techniques/T1600/
tags:
  - attack.defense-impairment
  - attack.impact
  - attack.t1600
  - attack.t1098
correlation:
  type: temporal_ordered
  rules:
    - sns_sse_disabled
    - sns_topic_policy_written
  group-by:
    - requestParameters.topicArn
  timespan: 1h
level: high
---
title: Repeated SNS topic encryption removal across distinct topics
id: 79c1c968-cf31-45af-99ff-1fa5c90f375e
status: experimental
description: >-
  Two or more DISTINCT topics stripped of server-side encryption by the same principal
  inside an hour. Threshold basis — disabling encryption is a deliberate, individually
  justified act, so the legitimate baseline for one principal in one hour is exactly one
  topic; `gte: 2` therefore fires on the first event that exceeds the legitimate baseline
  rather than falling through it. Raise the count only if a documented bulk migration
  exists, and prefer suppressing that migration's role.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html
  - https://attack.mitre.org/techniques/T1600/
tags:
  - attack.defense-impairment
  - attack.impact
  - attack.t1600
correlation:
  type: value_count
  rules:
    - sns_sse_disabled
  group-by:
    - userIdentity.arn
  field: requestParameters.topicArn
  timespan: 1h
  condition:
    gte: 2
level: high
```

The rule deliberately filters to success, so denied attempts — which are permission probing
against exactly the control that matters — need the companion error-code view in Query 1.
What no rule can supply is the **previous** key: CloudTrail records the new value only, with
no `oldValue` field, so whether this was a customer-managed key or the AWS-managed one is
answerable only from earlier events, from IaC state, or from the §1 baseline. Query 1
reconstructs what it can; Query 2 reads the live state.

---

### Key Investigation Queries

> SNS is regional and topic ARNs are region-scoped — run both queries per region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page**; Query 1 pages on `NextToken` rather than silently truncating.

#### Query 1 — Reconstruct: every attribute write on the topic, successes and denials alike

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
    printf '%s' "$PAGE" | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.eventSource == "sns.amazonaws.com")
      | {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
         ip: .sourceIPAddress, ua: .userAgent, err: (.errorCode // "none"),
         topicArn: (.responseElements.topicArn // .requestParameters.topicArn // "unknown"),
         attributeName: (.requestParameters.attributeName // "-"),
         newKey: (.requestParameters.attributeValue // .requestParameters.attributes.KmsMasterKeyId // "<EMPTY-OR-ABSENT>")}'
    TOKEN=$(printf '%s' "$PAGE" | jq -r '.NextToken // empty')
    [ -n "$TOKEN" ] || break
  done
done
```

Read it as a timeline per `topicArn`. A row with `attributeName` of `KmsMasterKeyId` and
`newKey` of `<EMPTY-OR-ABSENT>` is the disable; the **most recent earlier** row for the same
topic with a non-empty `newKey` is the key it had, and if none appears the previous key is
outside retention — record that as unknown rather than as "never encrypted". A row with
`attributeName` of `Policy` within an hour of the disable is the two-step; note its `caller`
and compare it with the disabler's. `err` of `AuthorizationError` is a denied attempt — SNS
never emits `AccessDenied` — and denials on `KmsMasterKeyId` are the probing that precedes
the successful call. `topicArn`, `caller` and `time` feed every step below.

#### Query 2 — Inspect: live encryption state of every topic, and what the KMS trail says

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
      echo "[!] UNENCRYPTED  $T"
    elif [ "$K" = "$EXPECTED_KEY" ]; then
      echo "[OK] $T  key=$K"
    else
      echo "[?] DIFFERENT KEY  $T  key=$K  expected=$EXPECTED_KEY"
    fi
  done
fi

# Corroborate from the key side: while a CMK is in use, every publish and delivery emits a
# GenerateDataKey carrying the topic ARN in the encryption context. These ARE management
# events, so unlike Publish they are logged by default — and they STOP at the disable.
aws cloudtrail lookup-events --region "$REGION" --output json --max-results 50 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GenerateDataKey \
  --start-time "$START" --end-time "$END" 2>&1 \
| jq -r 'if has("Events") then (.Events[].CloudTrailEvent | fromjson
    | select((.requestParameters.encryptionContext["aws:sns:topicArn"] // "") != "")
    | {time: .eventTime, topicArn: .requestParameters.encryptionContext["aws:sns:topicArn"],
       keyId: .requestParameters.keyId, caller: .userIdentity.arn, err: (.errorCode // "none")})
  else "[!] INCONCLUSIVE — GenerateDataKey lookup returned no Events key" end'
```

`[!] UNENCRYPTED` is the live finding and the work-list for §3. `[?] DIFFERENT KEY` is the
sibling condition — a topic moved to another key rather than stripped of one; if the value is
`alias/aws/sns` that is the downgrade use case, not this one. On the KMS side, the last
`GenerateDataKey` bearing a topic's ARN marks when encrypted traffic stopped, which brackets
the exposure window from the other end; a topic whose KMS trail simply ends with no
corresponding `SetTopicAttributes` in Query 1 means the disable predates your retention.

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

Restore the key **before** anything else, because the exposure accrues per message published.
One ordering hazard: the write fails, or succeeds and then breaks every publisher, if the
CMK's key policy no longer grants `kms:GenerateDataKey` and `kms:Decrypt` to
`sns.amazonaws.com`. Check the key policy first, then write the topic attribute, then confirm
publishers are still delivering.

> Run under the **break-glass responder credentials**, not the principal under investigation.

#### Step 1 — Confirm the key is usable, then restore it

```bash
REGION="<region>"; TOPIC="<topic-arn-from-Query-1>"; CMK="<expected-cmk-arn-or-alias>"

KEY=$(aws kms describe-key --region "$REGION" --key-id "$CMK" --output json 2>&1)
if ! printf '%s' "$KEY" | jq -e '.KeyMetadata.KeyState' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — cannot read $CMK: $KEY"
  echo "    Do NOT set the attribute yet; a topic pointed at an unusable key fails every publish."
elif [ "$(printf '%s' "$KEY" | jq -r '.KeyMetadata.KeyState')" != "Enabled" ]; then
  echo "[FAIL] $CMK is $(printf '%s' "$KEY" | jq -r '.KeyMetadata.KeyState') — enable it or pick another key first"
elif [ "$(printf '%s' "$KEY" | jq -r '.KeyMetadata.KeySpec')" != "SYMMETRIC_DEFAULT" ]; then
  echo "[FAIL] $CMK is $(printf '%s' "$KEY" | jq -r '.KeyMetadata.KeySpec') — SNS supports symmetric encryption keys only"
else
  echo "[OK] $CMK is an enabled symmetric key"
  aws sns set-topic-attributes --region "$REGION" --topic-arn "$TOPIC" \
    --attribute-name KmsMasterKeyId --attribute-value "$CMK"
  NOW=$(aws sns get-topic-attributes --region "$REGION" --topic-arn "$TOPIC" --output json 2>&1)
  if printf '%s' "$NOW" | jq -e '.Attributes' >/dev/null 2>&1; then
    LIVE=$(printf '%s' "$NOW" | jq -r '.Attributes.KmsMasterKeyId // ""')
    [ -n "$LIVE" ] && echo "[OK] $TOPIC now encrypted with $LIVE" \
                   || echo "[FAIL] $TOPIC still reports no KmsMasterKeyId after the write"
  else
    echo "[!] INCONCLUSIVE — could not re-read $TOPIC to confirm the write: $NOW"
  fi
fi
```

#### Step 2 — Contain the principal

```bash
CALLER="<caller-arn-from-Query-1>"
FREEZE='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["sns:SetTopicAttributes","sns:AddPermission","sns:RemovePermission","sns:CreateTopic"],"Resource":"*"}]}'
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

- **Sweep every region.** Re-run Query 2 account-wide: a scripted disable clears the key on
  every topic `ListTopics` returns, and the `value_count` correlation only tells you there
  was more than one.
- **Check the topic policy of every affected topic for a change by the same principal in the
  same session.** This is the step that is specific to a *disable* rather than a downgrade:
  clearing a customer-managed key removes the second gate, and it is normally done in order
  to make a widened access policy actually work. If Query 1 shows a `Policy` write near the
  disable, treat this as `../sns.persistence.topic-policy-modified/` as well.
- **Scope the disclosure to message BODIES published inside the window only.** AWS is
  explicit that SSE never encrypted topic metadata, message metadata — subject, message id,
  timestamp, message attributes — the data protection policy or per-topic metrics, and that
  messages encrypted before the disable stay encrypted. Over-scoping here wastes the
  response; assuming the subject line was protected is simply wrong.
- **Rotate anything a message body carried that is a secret**, bounded by the
  `NumberOfMessagesPublished` count for the window. A zero there is a real zero; a zero from
  `lookup-events` on `Publish` is not.
- **Right-size the permission** — see the guardrail bullets in §6.
- **Remove the emergency deny once clean** — `delete-user-policy` or `delete-role-policy` for
  `IR-SNS-Freeze`. Containment could have attached either, so check both paths, and confirm
  with the §5 assertion rather than by assuming the delete succeeded.

---

## 5. Recovery

### Restore Clean State

#### Verify every topic in the region reports an encryption key

```bash
REGION="<region>"; OUT="/tmp/sns_recovery_$REGION.ndjson"
EXPECTED_KEY="<expected-cmk-arn-or-alias>"
# The signal survives the remediation: GetTopicAttributes reports KmsMasterKeyId whether or
# not it is set, so this check can still emit UNENCRYPTED after the fix — [FAIL] is
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
      echo "[FAIL] $T has no KmsMasterKeyId"; [ "$BAD" = 2 ] || BAD=1
    elif [ "$K" != "$EXPECTED_KEY" ]; then
      echo "[FAIL] $T uses $K, expected $EXPECTED_KEY"; [ "$BAD" = 2 ] || BAD=1
    fi
  done
  case "$BAD" in
    0) echo "[OK] every topic in $REGION is encrypted with $EXPECTED_KEY" ;;
    1) echo "[FAIL] at least one topic is unencrypted or on the wrong key" ;;
    *) echo "[!] INCONCLUSIVE — at least one topic could not be read; nothing is certified" ;;
  esac
fi
```

#### Verify restoring the key did not break the publishers

```bash
REGION="<region>"; TOPIC="<topic-arn-from-Query-1>"
TOPIC_NAME=$(printf '%s' "$TOPIC" | awk -F':' '{print $NF}')
# Ask this AFTER the restore, and only of a metric that can still move: a CMK whose policy
# no longer grants sns.amazonaws.com fails every publish with KMSAccessDenied, which is an
# outage introduced by the remediation itself.
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
    echo "[FAIL] $N delivery failure(s) since the restore — check the CMK key policy grants"
    echo "       kms:GenerateDataKey and kms:Decrypt to sns.amazonaws.com for this topic ARN"
  fi
fi
```

#### Confirm the corrected detection fires

```bash
echo 'MUST fire on:     SetTopicAttributes, sns.amazonaws.com, no errorCode, with'
echo '   requestParameters.attributeName = "KmsMasterKeyId" and attributeValue = ""'
echo 'MUST ALSO fire on: the same event with requestParameters.attributeValue ABSENT —'
echo '   both shapes are legal and which one CloudTrail records is undocumented.'
echo 'MUST NOT fire on: attributeName = "KmsMasterKeyId" with a non-empty value (that is'
echo '   an encryption CHANGE — if the value is alias/aws/sns see the sibling use case).'
echo 'MUST NOT fire on: attributeName = "DisplayName" or "Policy" with an empty value.'
echo 'CORRELATION must fire on: the disable, then a Policy write on the SAME'
echo '   requestParameters.topicArn within 1h, in that order.'
echo 'EXPECTED FN, by design: the rule filters to success, so a DENIED disable does not fire'
echo '   it. That is the P1 error-code trigger in the table, not this rule.'
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A topic's `KmsMasterKeyId` was cleared by a non-administrative principal | `sns:SetTopicAttributes` on `Resource: "*"` was reachable outside the deployment role, and no control distinguishes clearing the key from setting a display name |
| The previous key had to be reconstructed from CloudTrail | No per-topic expected-key baseline existed, and CloudTrail records only the new value — there is no `oldValue` field and no attribute version history |
| The KMS-side corroborating trail ended at the same moment | The only usage record for a topic whose `Publish` events are not logged is the CMK's own `GenerateDataKey` events, and disabling SSE ends them — the disable degrades two signals at once |
| Whether anything was published while unencrypted was not answerable from CloudTrail | No data-event trail on `AWS::SNS::Topic`; the question had to be routed to a CloudWatch metric |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// An SCP is the right instrument here, unlike the public-grant use cases: the actor is one
// of your OWN principals calling SetTopicAttributes, so it is in scope for an SCP. The
// resource-side RCP that constrains outside principals does not reach this at all.
// Failure direction: Deny + StringNotLike denies every SetTopicAttributes whose caller is
// not the deployment role — which is the intent — so an incorrect role ARN takes the
// deployment pipeline offline rather than leaving the gap open. StringNotEquals would be
// wrong here because the value carries a wildcard: * is expanded only by the *Like
// operators, so StringNotEquals against ".../deploy-*" never matches and denies everyone.
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

- Put the durable control **on the SNS side, not the KMS side**. A key policy or SCP denying
  `kms:ScheduleKeyDeletion` and `kms:DisableKey` does not stop this: nothing in the technique
  touches the key, only the topic's pointer to it. Denying `sns:SetTopicAttributes` outside
  the deployment role is the control that applies.
- Maintain the per-topic expected-`KmsMasterKeyId` baseline named in §1 and diff
  `GetTopicAttributes` against it on a schedule. That diff is the only control that survives
  the loss of both the SNS and the KMS event trails.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1600 — Weaken Encryption, tactic Defense Impairment (TA0112). Tagged `attack.defense-impairment`; `attack.defense-evasion` is retired, TA0005 having been renamed Stealth |
| Primary API | `sns:SetTopicAttributes` with `AttributeName=KmsMasterKeyId` and `AttributeValue` empty or omitted. Event source `sns.amazonaws.com`, **management** plane, on by default |
| Key discriminator | `requestParameters.attributeName` — the event name alone cannot tell an encryption change from a policy, display-name or delivery-policy change, since `SetTopicAttributes` carries all of them |
| Ground-truth signal | `requestParameters.attributeValue` empty **or absent** — both shapes are legal and which one CloudTrail records is observed, not documented |
| "Was it used" pivot | CloudWatch `AWS/SNS` `NumberOfMessagesPublished`, dimension `TopicName`, across the disable window. **Not** `lookup-events` — `Publish` is a data event, off by default. Corroborate with the CMK's `kms:GenerateDataKey` events, which carry `kms:EncryptionContext:aws:sns:topicArn` and stop at the disable |
| Blast radius | Message **bodies** published between the disable and the restore, stored without your key. Bounded on both sides: SNS does not retroactively encrypt backlogged messages, and messages already encrypted stay encrypted. Plus the loss of the key policy as a second gate on the topic |
| What SSE never protected | Topic metadata; message metadata — subject, message id, timestamp, message attributes; the data protection policy; per-topic metrics. Do not scope the disclosure as if these were covered |
| Error strings | `AuthorizationError` (403 — SNS does **not** use `AccessDenied`), `InvalidParameter`, `InvalidSecurity`, `InternalError`, `NotFound`. On the publish path a broken key throws `KMSAccessDenied`, `KMSDisabled`, `KMSInvalidState` (not `…Exception`), `KMSNotFound`, `KMSOptInRequired`, `KMSThrottling` |
| Document size | Not applicable — `KmsMasterKeyId` is a short key identifier, nowhere near CloudTrail's 100 KB `requestParameters` omission threshold, so **no oversized-document companion rule ships** |

### Residual Risk

Restoring the key protects nothing that was already published. Every message body written to
the topic between the disable and the restore is stored without your key and stays that way —
re-enabling encryption is not retroactive, exactly as AWS states in the other direction for
messages encrypted before a disable. Anything secret that transited the topic in that window
must be rotated on the assumption it was readable, and the count of affected messages comes
from a CloudWatch metric rather than from any record of the messages themselves, so you can
bound the volume but never enumerate the contents. The KMS-side trail for that window does
not exist either, so there is no way to prove after the fact who read what. And if the
disable was the first half of a two-step, the access-policy change it enabled may still be in
place: §4's policy check is not optional, and the grant it finds outlives everything done
here.
