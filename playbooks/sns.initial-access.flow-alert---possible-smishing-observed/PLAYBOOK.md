# IR Playbook: Outbound SMS Abuse from a Compromised Account — smishing setup via `sns:SetSMSAttributes` and the SMS sandbox APIs

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Service abuse for outbound phishing (an actor prepares the account's SMS configuration — spend limit, sandbox destinations, sender id — and sends phishing SMS to third parties from your originating number, at your cost) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, against the source rule's P2. P2 is defensible for one ambiguous signal, but this is the only use case here where the damage accrues to people who cannot detect it, cannot be warned, and are not your users — at a rate bounded only by the account's SMS spend quota, with every hour of delay meaning more messages delivered. The financial exposure is incurred as the messages send. It is not P0 only because no data leaves the account and this technique exposes no credential; the compromise that produced the access is a separate and probably higher-priority incident. |
| MITRE Tactics | Initial Access (against the recipients), Resource Development, Discovery |
| MITRE Techniques | T1566, T1584.006, T1526 (see the mapping note in `detections/detection_note_t1566.md`) |
| Services in Scope | SNS, CloudWatch metrics, CloudWatch Logs, IAM, CloudTrail, Service Quotas, AWS Support (spend quota), plus your carrier and brand-protection contacts |

**What the technique does:** the actor enumerates the account's SMS posture — `GetSMSAttributes`,
`GetSMSSandboxAccountStatus`, `ListOriginationNumbers`, `ListPhoneNumbersOptedOut` — then
prepares it. `SetSMSAttributes` raises the account-wide `MonthlySpendLimit`, which is
**1.00 USD by default** and therefore the single hardest constraint on volume, and can set a
`DefaultSenderID` so the messages arrive under a name of the attacker's choosing. If the
account is still in the SMS sandbox, `CreateSMSSandboxPhoneNumber` and
`VerifySMSSandboxPhoneNumber` register each destination one at a time; if it is out of the
sandbox, that step is unnecessary and the actor sends to anyone. Then `Publish` with a
`PhoneNumber` and no `TopicArn` delivers the phishing text.

**Detection thesis.** The discriminator has to be a **management-plane configuration change
by a principal that does not normally touch SMS**, because the sending step is not observable:
AWS states that `AWS::SNS::PhoneNumber` is not logged by CloudTrail under any trail
configuration, and `Publish` is a data event that is off by default in any case. The source
rule stakes its second stage on exactly that unobservable event, so the flow never completes
— and its group-by is empty, so even if it did, the two stages would not be bound to the same
principal.

---

## 1. Preparation

**Logging & Visibility**

- **CloudTrail management events**, on by default, `eventSource: sns.amazonaws.com`.
  `SetSMSAttributes`, `GetSMSAttributes`, `GetSMSSandboxAccountStatus`,
  `CreateSMSSandboxPhoneNumber`, `VerifySMSSandboxPhoneNumber`,
  `DeleteSMSSandboxPhoneNumber`, `OptInPhoneNumber`, `CheckIfPhoneNumberIsOptedOut`,
  `ListPhoneNumbersOptedOut`, `ListOriginationNumbers` and `ListSMSSandboxPhoneNumbers` are
  all on AWS's published management-event list. **This is the entire detectable surface.**
- **`AWS::SNS::PhoneNumber` is not logged by CloudTrail.** AWS says so explicitly. A
  `Publish` to a phone number with no topic produces no CloudTrail record under any
  configuration, including a fully enabled SNS data-event trail. Never present a zero from
  `lookup-events` as evidence that nothing was sent.
- **Message content is never available.** Even for topic-based publishes with data events on,
  `requestParameters.message`, `.subject` and `.messageAttributes` are recorded as the
  literal `HIDDEN_DUE_TO_SECURITY_REASONS`. Obtain the phishing text from a recipient.
- **SMS delivery-status logging must already be on** — it is the only per-recipient record
  that exists. Configure the delivery-status IAM role via `SetSMSAttributes`; logs land in
  CloudWatch Logs groups `sns/<region>/<account-id>/DirectPublishToPhoneNumber` and
  `.../DirectPublishToPhoneNumber/Failure`, carrying `delivery.destination`,
  `delivery.priceInUSD`, `delivery.smsType`, `delivery.providerResponse` and `status`. With
  no success sample rate set, AWS logs all successful deliveries. Entries can take **up to 72
  hours** to appear.
- **CloudWatch `AWS/SNS`** — `SMSMonthToDateSpentUSD` (valid dimensions: **none**, so it is
  account-wide and never per-recipient), plus `NumberOfMessagesPublished` and `SMSSuccessRate`
  on dimension `PhoneNumber`, which AWS defines as the number used when publishing SMS
  directly without a topic.
- **Known IOC baseline.** Record the account's current SMS spend quota, its sandbox status,
  its origination numbers and the roles that legitimately call `SetSMSAttributes`. An account
  still at the 1.00 USD default is largely self-limiting; one raised for a real campaign is
  the one exposed here.

**Alerting (must be pre-configured)**

- **`SetSMSAttributes` by a principal outside the messaging-platform allowlist → P0**
- **SMS reconnaissance followed within 24h by an SMS configuration change by the same principal → P0**
- **`SMSMonthToDateSpentUSD` exceeding its own 30-day maximum → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- CloudWatch Logs Insights access for the log group named in **Logging & Visibility**, and the patience for `start-query` to settle before reading results.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- The contents of `known_admins`, `known_publishers` from the shipped rules. Each is populated before deployment and is the whole tuning cost of the detection.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `SetSMSAttributes` by a principal outside the messaging-platform allowlist | CloudTrail (management) | T1566 |
| P0 | SMS reconnaissance followed within 24h by an SMS configuration change by the same principal | CloudTrail (management) | T1566, T1526 |
| P1 | `SMSMonthToDateSpentUSD` exceeding its own 30-day maximum | CloudWatch (`AWS/SNS`) | T1566 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `CreateSMSSandboxPhoneNumber` / `VerifySMSSandboxPhoneNumber` outside the allowlist | CloudTrail (management) | T1566 |
| P2 | `NumberOfMessagesPublished` on dimension `PhoneNumber` for destinations absent from the baseline | CloudWatch (`AWS/SNS`) | T1566 |
| P3 | SMS enumeration by a principal that has never performed it before | CloudTrail (management) | T1526 |

### Detection Rule Quality Notes

The source flow's second stage keys on an event AWS does not log, so the flow never completes.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Stage 2 matches `eventName:("Publish")` | `Publish` is a CloudTrail **data** event (`eventCategory: "Data"`, `managementEvent: false`), off by default — so on a default trail the stage never matches and **the flow never fires at all** | Both stages moved to management events that are on by default and cannot be disabled |
| Enabling SNS data events would not fix it | AWS logs data events only for `AWS::SNS::Topic` and `AWS::SNS::PlatformEndpoint`, and states that **`AWS::SNS::PhoneNumber` is not logged by CloudTrail**. A direct-to-phone `Publish` — the technique itself — has no CloudTrail record under any configuration | Detection targets the management-plane setup; the sending is evidenced from CloudWatch metrics and the SMS delivery-status log group instead |
| The flow's `group_by` is empty | The two stages are not bound to the same principal, so an enumeration by one identity plus an unrelated publish by a legitimate application satisfies it account-wide | Correlation grouped on `userIdentity.arn` |
| No coverage of `SetSMSAttributes` | The account SMS spend quota defaults to **1.00 USD/month** and AWS stops sending within minutes of it being exceeded, so raising it is close to mandatory for volume abuse — and it was not watched at all | Primary `high` rule on `SetSMSAttributes` outside the allowlist |
| No coverage of the SMS sandbox APIs | In the sandbox an account may only send to numbers it has verified. `CreateSMSSandboxPhoneNumber` / `VerifySMSSandboxPhoneNumber` are the boundary between "cannot send to strangers" and "can", one event per destination, with the number in the request | `sns_sms_sandbox_change` rule at `medium` |
| Rated P2 | Routes an outbound campaign harming third parties, at your cost, to a queue that tolerates hours of delay while messages keep sending | High |

**Recommended detection — SNS SMS spend or delivery configuration changed.**

```yaml
# Outbound SMS abuse from a compromised AWS account — smishing (T1566 / T1584.006)
#
# THE ORIGINAL FLOW CANNOT FIRE, AND THE REASON IS STRUCTURAL RATHER THAN A TYPO.
# Its second stage matches `eventName:("Publish")`. AWS documents `Publish` and
# `PublishBatch` as CloudTrail DATA events — the published example carries
# `"eventCategory": "Data"` and `"managementEvent": false` — and data events are OFF by
# default. On a default trail the second stage never matches, so the flow never completes.
#
# Worse, enabling SNS data events does not fix it. AWS lists the loggable SNS data-event
# resource types as AWS::SNS::Topic and AWS::SNS::PlatformEndpoint, and states plainly:
# "SNS resource type AWS::SNS::PhoneNumber is not logged by CloudTrail." A Publish carrying
# a PhoneNumber and no TopicArn — which is precisely what sending an SMS to a stranger is —
# produces NO CloudTrail record under ANY trail configuration. The sending step of this
# technique is invisible to CloudTrail by design, and no Sigma rule over CloudTrail can
# recover it. Even for topic-based publishes, `requestParameters.message` and `.subject` are
# recorded as the literal HIDDEN_DUE_TO_SECURITY_REASONS, so the phishing text is never
# available either.
#
# A third defect is independent of all that: the flow's own group-by is EMPTY, so its two
# stages are not bound to the same principal. An enumeration by one identity and an unrelated
# publish by a legitimate service would satisfy it account-wide.
#
# SO THESE RULES MOVE THE DETECTION ENTIRELY ONTO THE MANAGEMENT PLANE, where the setup for
# bulk SMS is fully logged by default and cannot be turned off:
#   * reconnaissance of the SMS configuration and sandbox status,
#   * raising the monthly SMS spend limit via SetSMSAttributes — the single most reliable
#     precursor, because the account default is 1.00 USD and no volume campaign fits in it,
#   * escaping the SMS sandbox by registering and verifying destination numbers.
# The correlation below binds them to ONE principal, which the original flow did not do, and
# fires on a default trail, which the original flow could not.
title: SNS SMS spend or delivery configuration changed
id: 336be6e7-a985-432f-a9a5-42003b45141f
name: sns_sms_attributes_changed
status: experimental
description: >-
  SetSMSAttributes by a principal outside the messaging-platform allowlist. This call sets
  the account-wide MonthlySpendLimit, the default sender id, the default SMS type and the
  delivery-status logging role — every lever a bulk-SMS campaign needs. The account default
  spend quota is 1.00 USD, so raising it is close to mandatory for volume abuse and is
  logged as a management event whether or not any data-event trail exists.
references:
  - https://docs.aws.amazon.com/sns/latest/dg/sms_preferences.html
  - https://docs.aws.amazon.com/sns/latest/dg/logging-using-cloudtrail.html
  - https://attack.mitre.org/techniques/T1566/
tags:
  - attack.initial-access
  - attack.resource-development
  - attack.t1566
  - attack.t1584.006
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sns.amazonaws.com'
    eventName: 'SetSMSAttributes'
  known_admins:
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/ci-cd'
      - ':role/messaging-platform'
  success:
    errorCode: null
  condition: selection and success and not known_admins
falsepositives:
  - A planned spend-limit increase before a legitimate campaign. Rare, scheduled, and
    performed by the messaging-platform role — allowlist that role rather than the event.
level: high
---
title: SNS SMS configuration and sandbox reconnaissance
id: 7d8fd630-e9d9-42ca-9c47-97257669ed19
name: sns_sms_reconnaissance
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. Read-only enumeration of the
  account's SMS posture: spend attributes, sandbox status, origination numbers, opt-out
  lists. Individually these are routine console and support activity; they matter only as
  the first half of the sequence below. Carries the success filter so a denied probe cannot
  satisfy the correlation's first stage.
references:
  - https://docs.aws.amazon.com/sns/latest/dg/logging-using-cloudtrail.html
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sns.amazonaws.com'
    eventName:
      - 'GetSMSAttributes'
      - 'GetSMSSandboxAccountStatus'
      - 'ListOriginationNumbers'
      - 'ListPhoneNumbersOptedOut'
      - 'ListSMSSandboxPhoneNumbers'
      - 'CheckIfPhoneNumberIsOptedOut'
  success:
    errorCode: null
  condition: selection and success
level: low
---
title: SNS SMS sandbox destination registered or verified
id: 51b5a830-b9ee-4dfe-beee-62f9c6227994
name: sns_sms_sandbox_change
status: experimental
description: >-
  Registration, verification or removal of an SMS sandbox destination number. In the SMS
  sandbox an account may only send to numbers it has verified, so an actor must either
  verify each destination — visible here, one event per number — or get the account out of
  the sandbox entirely. Either way this is the boundary between "cannot send to strangers"
  and "can", and it is a management event logged by default.
references:
  - https://docs.aws.amazon.com/sns/latest/dg/logging-using-cloudtrail.html
  - https://attack.mitre.org/techniques/T1566/
tags:
  - attack.initial-access
  - attack.resource-development
  - attack.t1566
  - attack.t1584.006
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sns.amazonaws.com'
    eventName:
      - 'CreateSMSSandboxPhoneNumber'
      - 'VerifySMSSandboxPhoneNumber'
      - 'DeleteSMSSandboxPhoneNumber'
  known_admins:
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/ci-cd'
      - ':role/messaging-platform'
  success:
    errorCode: null
  condition: selection and success and not known_admins
falsepositives:
  - A developer verifying their own handset while building an SMS feature. Expect this in
    non-production accounts; it should be rare and attributable in production.
level: medium
---
title: SMS reconnaissance followed by an SMS configuration change by the same principal
id: 0fc02b1f-55b0-47e8-b3a7-9cd41d55ddd6
status: experimental
description: >-
  One principal enumerating the account's SMS posture and then changing it within a day.
  This replaces the original flow's second stage, which keyed on Publish and therefore could
  never fire, with a management-plane event that is logged by default — and unlike the
  original it is GROUPED BY PRINCIPAL, so an unrelated legitimate change elsewhere in the
  account cannot complete the sequence. Timespan basis — 24h is carried over from the source
  rule deliberately: it is the only tuning figure in the original worth keeping, and it
  matches the observed shape of this activity, where reconnaissance and setup happen in one
  working session. Shorten it before lengthening it.
references:
  - https://docs.aws.amazon.com/sns/latest/dg/sms_preferences.html
  - https://attack.mitre.org/techniques/T1566/
tags:
  - attack.initial-access
  - attack.discovery
  - attack.t1566
  - attack.t1526
correlation:
  type: temporal_ordered
  rules:
    - sns_sms_reconnaissance
    - sns_sms_attributes_changed
  group-by:
    - userIdentity.arn
  timespan: 24h
level: high
---
title: SNS publish to a topic by a principal outside the publishing allowlist
id: 98f05bf3-feb8-4b1d-9091-45224ad69833
name: sns_publish_unexpected_principal
status: experimental
description: >-
  DATA EVENT — this rule is INERT unless a CloudTrail data-event trail exists on
  resources.type AWS::SNS::Topic, and it can never see the direct-to-phone form of this
  technique at all, because AWS does not log AWS::SNS::PhoneNumber to CloudTrail under any
  configuration. It is shipped for accounts that publish SMS through a topic with sms
  subscriptions, where it is the only event-level view of sending. Message content is not
  available even here: requestParameters.message and .subject are recorded as the literal
  HIDDEN_DUE_TO_SECURITY_REASONS. Treat a zero from this rule as "not logged", never as
  "nothing was sent", and use the CloudWatch pivots in the playbook instead.
references:
  - https://docs.aws.amazon.com/sns/latest/dg/logging-using-cloudtrail.html
  - https://attack.mitre.org/techniques/T1566/
tags:
  - attack.initial-access
  - attack.t1566
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sns.amazonaws.com'
    eventName:
      - 'Publish'
      - 'PublishBatch'
  known_publishers:
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/app-publisher'
      - ':role/messaging-platform'
  success:
    errorCode: null
  condition: selection and success and not known_publishers
falsepositives:
  - Any application publisher missing from the allowlist. Populate the allowlist from a
    baseline before enabling, or this fires on ordinary traffic.
level: low
```

The rule filters to success, so denied attempts — permission probing against exactly this
control — need the error-code view in Query 1. What no rule here can do is observe the
sending: that is not a tuning limitation but an absence of telemetry, and Query 2 goes to
CloudWatch for it. The `sns_publish_unexpected_principal` document in the same file is
shipped deliberately marked `low` and inert-by-default, so that a deployer enabling SNS data
events gets *something* for topic-based SMS, without anyone mistaking it for coverage of the
direct-to-phone form.

---

### Key Investigation Queries

> SNS SMS configuration is **regional** — run Query 1 in every region that supports SMS, not just your primary. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page**; Query 1 pages on `NextToken` rather than silently truncating.

#### Query 1 — Reconstruct: the whole SMS management timeline, successes and denials

```bash
REGION="<region>"; START="<ISO8601-start>"; END="<ISO8601-end>"

for EN in GetSMSAttributes GetSMSSandboxAccountStatus ListOriginationNumbers \
          ListPhoneNumbersOptedOut ListSMSSandboxPhoneNumbers CheckIfPhoneNumberIsOptedOut \
          SetSMSAttributes CreateSMSSandboxPhoneNumber VerifySMSSandboxPhoneNumber \
          DeleteSMSSandboxPhoneNumber OptInPhoneNumber; do
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
         phoneNumber: (.requestParameters.phoneNumber // "-"),
         spendLimit: (.requestParameters.attributes.MonthlySpendLimit // "-"),
         senderId: (.requestParameters.attributes.DefaultSenderID // "-"),
         smsType: (.requestParameters.attributes.DefaultSMSType // "-"),
         deliveryRole: (.requestParameters.attributes.DeliveryStatusIAMRole // "-")}'
    TOKEN=$(printf '%s' "$PAGE" | jq -r '.NextToken // empty')
    [ -n "$TOKEN" ] || break
  done
done
```

Read it as one timeline per `caller`. The sequence that matters is enumeration followed by
configuration change by the **same** principal — that binding is what the source flow lacked.
A non-`-` `spendLimit` is the strongest single indicator: the account default is 1.00 USD, so
any raise is a volume-campaign precursor. A non-`-` `senderId` means the messages arrive under
a name the actor chose. Each `phoneNumber` on a `CreateSMSSandboxPhoneNumber` or
`VerifySMSSandboxPhoneNumber` row is a destination the actor intends to reach, and is a
recoverable IOC even when nothing else about the campaign is. `err` of `AuthorizationError`
is a denied attempt — SNS never emits `AccessDenied`. **The `attributes.*` paths are inferred
from CloudTrail's map convention rather than from a published SNS event example; if they come
back `-` on an event you know set a spend limit, dump the raw `requestParameters` and correct
them.** `caller`, `time` and `phoneNumber` feed every step below.

#### Query 2 — Inspect: what was actually sent, since CloudTrail cannot say

```bash
REGION="<region>"; ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>&1)
START="<ISO8601-start>"; END="<ISO8601-end>"

# 1. Account-wide spend. Valid dimensions: NONE — this is the whole account, never per
#    recipient. It is also the metric AWS uses to stop sending at the quota.
SPEND=$(aws cloudwatch get-metric-statistics --region "$REGION" \
  --namespace AWS/SNS --metric-name SMSMonthToDateSpentUSD \
  --start-time "$START" --end-time "$END" --period 3600 --statistics Maximum \
  --output json 2>&1)
if ! printf '%s' "$SPEND" | jq -e 'has("Datapoints")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — SMSMonthToDateSpentUSD query failed: $SPEND"
else
  printf '%s' "$SPEND" | jq -r '.Datapoints | sort_by(.Timestamp)[]
    | "\(.Timestamp)  month-to-date USD \(.Maximum)"'
  printf '%s' "$SPEND" | jq -r 'if (.Datapoints | length) == 0
    then "[!] no SMSMonthToDateSpentUSD datapoints in the window — either no SMS was sent, or the window is wrong. Confirm against a window you know had traffic before concluding."
    else "[i] peak month-to-date spend: \([.Datapoints[].Maximum] | max)" end'
fi

# 2. The per-recipient record — the ONLY one. Off unless a delivery-status role was
#    configured, so an empty result here is ambiguous and must be reported as such.
LG="sns/$REGION/$ACCOUNT/DirectPublishToPhoneNumber"
DESC=$(aws logs describe-log-groups --region "$REGION" --log-group-name-prefix "$LG" \
         --output json 2>&1)
if ! printf '%s' "$DESC" | jq -e 'has("logGroups")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — describe-log-groups failed: $DESC"
elif [ "$(printf '%s' "$DESC" | jq '.logGroups | length')" = "0" ]; then
  echo "[!] NO DELIVERY-STATUS LOGS EXIST for $LG."
  echo "    This is NOT evidence that nothing was sent. SMS delivery-status logging is off"
  echo "    until a DeliveryStatusIAMRole is configured, and there is no other per-recipient"
  echo "    record anywhere in AWS. Report the recipient list as unrecoverable."
else
  aws logs filter-log-events --region "$REGION" --log-group-name "$LG" \
    --start-time "<epoch-millis-start>" --end-time "<epoch-millis-end>" \
    --output json 2>&1 \
  | jq -r 'if has("events") then (.events[].message | fromjson
      | "\(.notification.timestamp)  \(.delivery.destination)  \(.delivery.smsType)  USD \(.delivery.priceInUSD)  \(.status)  \(.delivery.providerResponse)")
    else "[!] INCONCLUSIVE — filter-log-events returned no events key" end'
fi
```

The spend curve bounds the campaign in money and time; a step change that starts near the
`SetSMSAttributes` from Query 1 is the campaign beginning. The delivery-status log is the
recipient list, `delivery.destination` by `delivery.destination`, with `priceInUSD` per
message — sum it and compare against the spend metric to check you have the whole picture. If
the log group does not exist, say so plainly in the incident record: the recipients are
unrecoverable from AWS, and the only remaining route to the phishing text is a recipient who
reports it. Note the up-to-72-hour delay before entries appear, so re-run this query the next
day before closing.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="CheckIfPhoneNumberIsOptedOut CreateSMSSandboxPhoneNumber DeleteSMSSandboxPhoneNumber GetSMSAttributes GetSMSSandboxAccountStatus ListOriginationNumbers ListPhoneNumbersOptedOut ListSMSSandboxPhoneNumbers"
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
elsewhere, and whether anyone else did it too. Group by caller rather than by resource: the
question the eradication phase needs answered is *how much of this is one actor's work*, and a
per-resource list cannot say. `access_key` is emitted here because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` regardless of whether it happened — see the caveat in the preamble.

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

Keyed on the access key rather than the ARN, because one credential is used across many
sessions and the key is what identifies the credential. The per-service grouping answers the
question this playbook cannot: whether this technique was the objective or one stop on a tour.
A service in that list with no business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID — so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Stop the sending before investigating anything, because the meter runs and the messages land
while you read. The fastest lever is the account spend quota — AWS stops publishing SMS
within minutes of it being exceeded — and it is faster than revoking the principal, because
it does not depend on identifying them first. Do that, then contain the principal.

> Run under the **break-glass responder credentials**, not the principal under investigation.

#### Step 1 — Cut the spend limit to floor the campaign

```bash
REGION="<region>"
BEFORE=$(aws sns get-sms-attributes --region "$REGION" --output json 2>&1)
if printf '%s' "$BEFORE" | jq -e 'has("attributes")' >/dev/null 2>&1; then
  printf '%s' "$BEFORE" | jq -r '.attributes | to_entries[] | "[i] before  \(.key)=\(.value)"'
else
  echo "[!] INCONCLUSIVE — cannot read the current SMS attributes; record this and continue: $BEFORE"
fi

# AWS stops publishing SMS within minutes of the month-to-date spend exceeding this value.
# Setting it BELOW what has already been spent this month halts sending almost immediately.
aws sns set-sms-attributes --region "$REGION" \
  --attributes MonthlySpendLimit=1 2>&1

AFTER=$(aws sns get-sms-attributes --region "$REGION" --output json 2>&1)
if ! printf '%s' "$AFTER" | jq -e 'has("attributes")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — cannot confirm the new spend limit: $AFTER"
else
  LIM=$(printf '%s' "$AFTER" | jq -r '.attributes.MonthlySpendLimit // ""')
  if [ -z "$LIM" ]; then
    echo "[!] INCONCLUSIVE — MonthlySpendLimit is absent from the response; confirm in the console"
  elif [ "$LIM" = "1" ]; then
    echo "[OK] MonthlySpendLimit is now $LIM USD — sending stops within minutes of the cap"
  else
    echo "[FAIL] MonthlySpendLimit reads $LIM, expected 1 — the write did not take effect"
  fi
fi
```

#### Step 2 — Contain the principal

```bash
CALLER="<caller-arn-from-Query-1>"
FREEZE='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["sns:Publish","sns:SetSMSAttributes","sns:CreateSMSSandboxPhoneNumber","sns:VerifySMSSandboxPhoneNumber","sns:OptInPhoneNumber"],"Resource":"*"}]}'
case "$CALLER" in
  *":user/"*)          # IAM user: the name is $NF. Disable keys before attaching the deny.
    UNAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$UNAME" \
                 --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$UNAME" --access-key-id "$K" --status Inactive
    done
    aws iam put-user-policy --user-name "$UNAME" --policy-name IR-SNS-SMS-Freeze \
      --policy-document "$FREEZE" && echo "[OK] contained IAM user $UNAME" ;;
  *":assumed-role/"*)  # Role name is the 2nd '/' segment; $NF is the SESSION name.
    RNAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$RNAME" --policy-name IR-SNS-SMS-Freeze \
      --policy-document "$FREEZE" && echo "[OK] contained IAM role $RNAME" ;;
  *)
    echo "[!] $CALLER is root, federated or a service principal — contain manually." ;;
esac
```

---

## 4. Eradication

### Remove Attacker Access

- **Revert every SMS attribute the actor set**, using the `[i] before` lines captured in §3
  Step 1: `DefaultSenderID` in particular, because it controls what recipients see as the
  sender and a hostile value keeps working until it is changed back.
- **Delete every sandbox destination number the actor registered.** Each
  `CreateSMSSandboxPhoneNumber` / `VerifySMSSandboxPhoneNumber` row from Query 1 names one;
  remove them with `aws sns delete-sms-sandbox-phone-number --phone-number "<number>"`. Left
  in place they are a standing list of pre-verified targets for the next attempt.
- **Check whether the account was moved out of the SMS sandbox**, with
  `aws sns get-sms-sandbox-account-status`. Leaving the sandbox is a support-driven change
  rather than an API call, so if the account is out and nobody remembers requesting it, that
  is its own investigation and it is not reversible from the CLI.
- **Do this in every region.** SMS attributes and sandbox state are regional, so containment
  in one region says nothing about the others.
- **Right-size the permission** — see the guardrail bullets in §6.
- **Remove the emergency deny once clean** — `delete-user-policy` or `delete-role-policy` for
  `IR-SNS-SMS-Freeze`. Containment could have attached either, so check both paths, and
  confirm with the §5 assertion rather than by assuming the delete succeeded.
- **Notify outward.** This is the eradication step with no AWS command: the recipients were
  phished under your sender identity. Brand protection, the carrier relationship and — where
  the recipient list is recoverable from the delivery-status log — the recipients themselves
  are all downstream of this incident, and none of them learn about it from AWS.

---

## 5. Recovery

### Restore Clean State

#### Verify the SMS spend limit and sender id are back to their expected values

```bash
REGION="<region>"
EXPECTED_LIMIT="<expected-monthly-spend-limit>"; EXPECTED_SENDER="<expected-sender-id-or-empty>"
# get-sms-attributes always returns an attributes map for an account that exists, so an
# absent key is a failed call — it must not reach the same branch as "restored".
ATTRS=$(aws sns get-sms-attributes --region "$REGION" --output json 2>&1)
if ! printf '%s' "$ATTRS" | jq -e 'has("attributes")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — cannot read SMS attributes in $REGION: $ATTRS"
else
  LIM=$(printf '%s' "$ATTRS" | jq -r '.attributes.MonthlySpendLimit // ""')
  SND=$(printf '%s' "$ATTRS" | jq -r '.attributes.DefaultSenderID // ""')
  BAD=0
  [ "$LIM" = "$EXPECTED_LIMIT" ] || { echo "[FAIL] MonthlySpendLimit is '$LIM', expected '$EXPECTED_LIMIT'"; BAD=1; }
  [ "$SND" = "$EXPECTED_SENDER" ] || { echo "[FAIL] DefaultSenderID is '$SND', expected '$EXPECTED_SENDER'"; BAD=1; }
  [ "$BAD" = "0" ] && echo "[OK] SMS attributes in $REGION match the baseline"
fi
```

#### Verify no attacker-registered sandbox destination remains

```bash
REGION="<region>"
KNOWN_NUMBERS="<space-separated-expected-e164-numbers>"   # from the §1 baseline
SB=$(aws sns list-sms-sandbox-phone-numbers --region "$REGION" --output json 2>&1)
# The account may legitimately be OUT of the sandbox, in which case this call fails — that
# is a distinct state from "no numbers registered" and must not be reported as clean.
if ! printf '%s' "$SB" | jq -e 'has("PhoneNumbers")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — list-sms-sandbox-phone-numbers did not return PhoneNumbers."
  echo "    If the account is OUT of the sandbox this call does not apply, and the account can"
  echo "    send to anyone — confirm with get-sms-sandbox-account-status. Raw: $SB"
else
  UNKNOWN=0
  for N in $(printf '%s' "$SB" | jq -r '.PhoneNumbers[].PhoneNumber'); do
    case " $KNOWN_NUMBERS " in
      *" $N "*) ;;
      *) echo "[FAIL] unrecognised sandbox destination still registered: $N"; UNKNOWN=1 ;;
    esac
  done
  [ "$UNKNOWN" = "0" ] && echo "[OK] every registered sandbox destination is on the baseline"
fi
```

#### Confirm the corrected detection fires

```bash
echo 'MUST fire on:     SetSMSAttributes, sns.amazonaws.com, no errorCode, by a principal'
echo '   whose userIdentity.arn is outside the messaging-platform allowlist.'
echo 'CORRELATION must fire on: GetSMSAttributes or GetSMSSandboxAccountStatus, THEN'
echo '   SetSMSAttributes by the SAME userIdentity.arn within 24h.'
echo 'MUST NOT fire on: the same calls by the allowlisted messaging-platform role.'
echo 'MUST NOT fire on: an enumeration with no configuration change following it.'
echo 'CANNOT fire at all, by AWS design, on: Publish to a PhoneNumber. AWS does not log'
echo '   AWS::SNS::PhoneNumber to CloudTrail under any trail configuration. Verify this'
echo '   detection from the CloudWatch pivots in Query 2, never from a CloudTrail zero.'
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the messaging platform could raise the account SMS spend limit | `sns:SetSMSAttributes` was reachable outside the messaging role, and the spend quota was treated as a billing setting rather than as the security control it is |
| The campaign's recipients could not be enumerated | SMS delivery-status logging was not configured, and it is the only per-recipient record AWS produces — `AWS::SNS::PhoneNumber` is not logged to CloudTrail at all |
| The alert intended to catch this could never fire | The detection was built on `Publish`, a data event that is off by default and, for the direct-to-phone form, not loggable under any configuration |
| Spend was noticed after the fact rather than during | `SMSMonthToDateSpentUSD` was not alarmed, so the one always-on signal of an in-progress campaign went unwatched |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// An SCP is the right instrument: the actor is one of YOUR principals calling SNS, so it is
// in scope. Note this denies the SMS control plane, not sns:Publish — denying Publish
// outright breaks every legitimate notification path in the account.
// Failure direction: Deny + StringNotLike denies the call for every principal that is not
// the messaging role — the intent — so a wrong ARN blocks legitimate SMS configuration
// rather than leaving the gap open. StringNotEquals would be WRONG here: the value carries a
// wildcard, and * is expanded only by the *Like operators, so StringNotEquals against
// ".../messaging-*" matches nothing and denies everyone.
{
  "Sid": "DenySmsControlPlaneOutsideMessagingRole",
  "Effect": "Deny",
  "Action": [
    "sns:SetSMSAttributes",
    "sns:CreateSMSSandboxPhoneNumber",
    "sns:VerifySMSSandboxPhoneNumber",
    "sns:OptInPhoneNumber"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/messaging-*" }
  }
}
```

- **Treat the SMS spend quota as a security control.** It defaults to 1.00 USD per month and
  AWS stops publishing within minutes of it being exceeded. A value set above the account's
  service quota does not raise it — that needs a support case — so the quota is a hard
  ceiling an attacker cannot lift from the API. Keep it at the smallest figure the business
  actually needs, and alarm `SMSMonthToDateSpentUSD` against its own trailing maximum.
- **Turn on SMS delivery-status logging before you need it.** Without it there is no
  recipient list, no per-message price and no provider response — and it cannot be enabled
  retroactively for messages already sent.
- **Stay in the SMS sandbox in every account that does not need to leave it.** In the sandbox
  the account can only reach numbers it has verified one at a time, which converts a silent
  bulk campaign into a visible sequence of `VerifySMSSandboxPhoneNumber` events.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1566 — Phishing (retained as primary, from the recipients' perspective); T1584.006 — Compromise Infrastructure: Web Services (precise for what happens in *your* account); T1526 — Cloud Service Discovery (the reconnaissance stage). All verified live 2026-08-29 |
| Primary API | `sns:GetSMSAttributes` / `sns:GetSMSSandboxAccountStatus` → `sns:SetSMSAttributes` (`MonthlySpendLimit`, `DefaultSenderID`) → `sns:CreateSMSSandboxPhoneNumber` / `sns:VerifySMSSandboxPhoneNumber` → `sns:Publish` with `PhoneNumber`. Event source `sns.amazonaws.com`; every call except the last is a **management** event, on by default |
| Key discriminator | An SMS **configuration change** by a principal that does not normally touch SMS — because the sending itself is not observable |
| "Was it used" pivot | **Not CloudTrail.** `AWS::SNS::PhoneNumber` is not logged under any configuration, and `Publish` is a data event that is off by default. Use CloudWatch `AWS/SNS` `SMSMonthToDateSpentUSD` (dimensions: none) for spend, the same namespace's `NumberOfMessagesPublished` / `SMSSuccessRate` on dimension `PhoneNumber` for per-destination volume, and the CloudWatch Logs group `sns/<region>/<account-id>/DirectPublishToPhoneNumber` for the recipient list — the last of which exists only if delivery-status logging was configured beforehand |
| Blast radius | Third parties who received a phishing SMS under your originating number or sender id; the account's SMS spend up to the quota; the account's sender reputation with carriers; and any pre-verified sandbox destinations left registered |
| Error strings | `AuthorizationError` (403 — SNS does **not** use `AccessDenied`), `InvalidParameter`, `InvalidSecurity`, `InternalError`, `NotFound`; `Throttled` on the 1-TPS hard limits for `SetSMSAttributes`, `CreateSMSSandboxPhoneNumber`, `DeleteSMSSandboxPhoneNumber`, `VerifySMSSandboxPhoneNumber` and `ListOriginationNumbers`. `Publish` adds `ParameterValueInvalid` and `Validation` for a malformed E.164 number |
| Document size | Not applicable — the largest request parameter here is a phone number or a spend limit, nowhere near CloudTrail's 100 KB `requestParameters` omission threshold, so **no oversized-document companion rule ships** |

### Residual Risk

Nothing above un-sends a message. Every phishing SMS that left the account has been delivered
to a handset, read by a person who has no relationship with you and no way to know the sender
was compromised, and it carries your originating number or sender id — so the reputational
damage is to your brand and lands on people you cannot identify unless delivery-status logging
happened to be on. If it was not, the recipient list is unrecoverable from AWS and you cannot
warn anyone; the only route to the phishing text itself is a recipient who reports it, because
AWS records message content as `HIDDEN_DUE_TO_SECURITY_REASONS` in every configuration.

The financial exposure is already incurred: SMS is billed as it sends, AWS's own stop engages
only at the spend quota, and the documentation warns that because SNS is distributed you may
exceed the quota during the minutes it takes to take effect. Expect a bill above the cap.

Carrier-side consequences outlive the incident and are not in your control: a sender id or
origination number associated with spam can be filtered or blocked, degrading your
*legitimate* SMS delivery for weeks, and that is remedied through the carrier relationship
rather than through AWS. Finally, if the account was moved out of the SMS sandbox during the
incident it stays out — a support-driven change, not an API call — so its capacity to reach
arbitrary numbers persists after every step here is complete.
