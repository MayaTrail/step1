# IR Playbook: Bedrock Invocation Logging Removed — `DeleteModelInvocationLoggingConfiguration` while the invocations continue

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment (the only record of what was sent to and returned by foundation models stops, while the models keep being invoked) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. The model invocation log is the only source of prompts, responses and token counts, and it cannot be applied retroactively — so the gap it opens is permanent regardless of how quickly it is closed. One configuration per account per Region means one call blinds a whole Region. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | Bedrock, Bedrock Runtime, S3, CloudWatch Logs, IAM, CloudTrail |

**What the technique does:** three routes. `DeleteModelInvocationLoggingConfiguration` removes the
configuration outright — prompts, responses and token counts stop, while CloudTrail keeps recording
that invocations happen. `PutModelInvocationLoggingConfiguration` with a modality disabled is the
quiet version: the configuration is present, the console shows logging enabled, both log streams
keep producing records, and only the *content* for that modality stops. Or the destination is
removed, leaving the configuration reporting healthy with nothing landing and no error event at the
moment delivery fails.

**Why the usual reflexes miss it — and why this service is the exception.** Everywhere else in this
corpus, "the log stopped" is ambiguous and an absence rule has to be demoted to a corroborator.
Bedrock records the same activity in **two independent places**, and the deletion stops only one of
them. So `invocation log quiet + CloudTrail busy` is unambiguous, and the absence rule here is the
primary detection rather than a fallback. The reflex that does fail is treating the alarm as an
availability signal, which is what the source entry is.

**Detection thesis:** compare the two sources. Their divergence is the finding. And detect the
modality change separately, because that path produces no divergence at all.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **Model invocation logging enabled**, with an S3 destination for large data and every relevant
  modality selected. Off by default, not retroactive — this is what determines whether an incident
  can be reconstructed at all.
- **CloudTrail data events for `bedrock-runtime.amazonaws.com`.** This is the second witness that
  makes the divergence check possible. Without it this playbook's central detection does not work.
- **CloudTrail management events for `bedrock.amazonaws.com` and `s3.amazonaws.com`.**
- **A scheduled `get-model-invocation-logging-configuration` snapshot per Region**, stored with
  history. Logging is off by default, so "never enabled" and "removed" are indistinguishable from
  the log streams alone and only a stored baseline separates them.

**Alerting (must be pre-configured)**
- **`DeleteModelInvocationLoggingConfiguration` by a principal outside the provisioning allowlist → P0**
- **`PutModelInvocationLoggingConfiguration` with any modality set to false → P0**
- **CloudTrail showing ≥ 20 invocations in an hour with zero corresponding invocation-log records → P0**
- **`DeleteBucket` / `DeleteBucketPolicy` on the invocation log destination → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- The intended logging configuration per Region — destinations and modalities — written down.
  Restoring from memory is how a modality stays off.

**Known IOC Baselines**
- Which roles legitimately manage Bedrock configuration. Short list, and the tuning surface for all
  three rules.
- The expected ratio of invocation-log records to CloudTrail invocations in a healthy period. It
  should be close to one, and knowing what it actually is turns the divergence query from a
  judgement into a comparison.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | CloudTrail shows ≥ 20 `bedrock-runtime` invocations in an hour with zero invocation-log records for the same Region and window | CloudTrail + invocation logs | T1685.002 |
| P0 | `DeleteModelInvocationLoggingConfiguration` by a principal outside the provisioning allowlist | CloudTrail (`bedrock`) | T1685.002 |
| P0 | `PutModelInvocationLoggingConfiguration` with `textDataDeliveryEnabled`, `imageDataDeliveryEnabled` or `embeddingDataDeliveryEnabled` set to false | CloudTrail (`bedrock`) | T1685.002 |
| P1 | `DeleteBucket`, `DeleteBucketPolicy` or `PutBucketPolicy` on the invocation log destination | CloudTrail (`s3`) | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | The invocation-log to CloudTrail ratio falling below 0.5 over an hour — a partial loss | CloudTrail + invocation logs | T1685.002 |
| P2 | A Region with Bedrock invocations and no logging configuration at all, in the scheduled state sweep | `get-model-invocation-logging-configuration` | T1685.002 |
| P3 | `PutLifecycleConfiguration` on the destination bucket shortening retention on the data prefix | CloudTrail (`s3`) | T1685.002 |

### Detection Rule Quality Notes

The source entry is a **building block with no query, no threshold and no grouping** — a CloudWatch
metric alarm on invocation volume. There is no logic to audit, so this table records what the source
provides against what a security detection needs, rather than inventing defects in an empty rule.

| Issue | Impact | Correction |
|-------|--------|-----------|
| The source entry carries no detection logic at all | Nothing fires, and the security reading of "volume dropped" — that the *log* stopped rather than the traffic — is not expressed anywhere | The two-source divergence query as the primary detection, plus three control-plane rules |
| A volume alarm cannot distinguish a stopped workload from a removed log | Both look identical to a single-source count, and they are completely different incidents | Compare the invocation log against CloudTrail. `quiet + quiet` is availability; `quiet + busy` is removal. This service is the one place in the corpus where absence is unambiguous |
| No coverage of a disabled modality | Logging is per modality. Turning one off leaves the configuration present, the console green, **both** log streams producing records, and one class of invocation with no body — so it produces no divergence at all | `bedrock_invocation_logging_narrowed`, at the same level as deletion because it is quieter and invisible to the primary check |
| No coverage of destination failure | The configuration reads healthy while nothing lands, and **no Bedrock event fires at the moment delivery fails** | Three S3 events shipped alongside, plus a destination read in §5 because no event exists for the failure moment |
| No account of logging being off by default | An account that never enabled it is indistinguishable from one where it was removed, by the log streams alone | A state sweep with stored history in §1, which is what separates the two |
| A metric alarm has no actor | It says the account's invocation volume changed, not who changed the configuration — which is the only fact containment needs | The control-plane rules carry `userIdentity.arn` and the Region |

**Recommended detection — the control-plane acts, with the divergence query in the KQL.**

```yaml
# Model invocation logging removed, or invocations stopped (T1685.002)
#
# THE SOURCE ENTRY IS A BUILDING BLOCK WITH NO LOGIC — no query, no threshold, no grouping. It is a
# CloudWatch metric alarm for availability: invocation volume dropped. There is nothing to correct,
# and ../PLAYBOOK.md §2 says so rather than manufacturing defects in an empty rule.
#
# THE SECURITY READING OF "VOLUME DROPPED" IS THAT THE LOG STOPPED, NOT THE TRAFFIC — AND THIS
# SERVICE CAN TELL THE DIFFERENCE, WHICH ALMOST NONE OF THE OTHERS IN THIS CORPUS CAN.
#
# Bedrock invocations are recorded in two independent places:
#   the model invocation log       -> who, which model, how many tokens, AND the prompt and response
#   CloudTrail bedrock-runtime     -> who and which model, never the content
#
# DeleteModelInvocationLoggingConfiguration stops the first and leaves the second untouched. So:
#   invocation log quiet AND CloudTrail quiet  -> the workload stopped. Availability.
#   invocation log quiet AND CloudTrail busy   -> LOGGING WAS REMOVED WHILE INVOCATIONS CONTINUE.
#
# That second state is the finding, and it is unambiguous in a way an absence rule over a single
# source never is. Every other *.stealth.no-logs-* playbook in this corpus has to argue about what
# silence means; this one has a second witness. The correlation cannot be expressed in Sigma — it
# spans two log sources — so the rules below detect the control-plane act and kql_t1685_002.kql
# carries the divergence query.
#
# LOGGING IS OFF BY DEFAULT, WHICH CHANGES WHAT DELETION MEANS. AWS: "Model invocation logging is
# disabled by default." So an account that never enabled it is indistinguishable from one where it
# was removed — by the log stream alone. The control-plane events below distinguish them, and the
# state read in §2 of the playbook covers accounts where the deletion predates the trail.
title: Bedrock model invocation logging deleted
id: 6a2f81d3-49c7-4b05-92e1-7d3608ca5f41
name: bedrock_invocation_logging_deleted
status: experimental
description: >-
  DeleteModelInvocationLoggingConfiguration removed the configuration. Prompts, responses and token
  counts stop being recorded from that moment, while CloudTrail continues to show that invocations
  are happening — so the divergence between the two sources is immediate and detectable. There is
  one configuration per account per Region, so this single call blinds the whole Region. It cannot
  be applied retroactively either, which means the gap it opens is permanent regardless of how
  quickly it is restored.
references:
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'bedrock.amazonaws.com'
    eventName: 'DeleteModelInvocationLoggingConfiguration'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the roles that own Bedrock configuration.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    A logging destination being changed, which is done by deleting and re-creating the
    configuration. Expect a PutModelInvocationLoggingConfiguration within minutes; a deletion with
    no re-creation is the finding.
level: high
---
title: Bedrock model invocation logging reconfigured with reduced coverage
id: b95d072e-3c86-4a17-8f40-25e6109bd3ca
name: bedrock_invocation_logging_narrowed
status: experimental
description: >-
  PutModelInvocationLoggingConfiguration submitted with a modality disabled. Logging is enabled per
  modality — text, image, embedding, video — and AWS records bodies only for the modalities
  selected. So turning one off is a partial blinding that leaves the configuration present, the
  console showing logging enabled, and one class of invocation with no body recorded. This is the
  quiet version of the deletion above and it produces no divergence between the two sources at all,
  because CloudTrail and the invocation log both continue: only the CONTENT for that modality stops.
references:
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'bedrock.amazonaws.com'
    eventName: 'PutModelInvocationLoggingConfiguration'
  success:
    errorCode: null
  text_disabled:
    requestParameters.loggingConfig.textDataDeliveryEnabled: false
  image_disabled:
    requestParameters.loggingConfig.imageDataDeliveryEnabled: false
  embedding_disabled:
    requestParameters.loggingConfig.embeddingDataDeliveryEnabled: false
  condition: selection and success and (text_disabled or image_disabled or embedding_disabled)
falsepositives:
  - >-
    A deliberate reduction for cost or for privacy — image logging in particular is expensive and
    is sometimes disabled on purpose. Legitimate as a recorded exception; the cost of the exception
    is that invocations of that modality have no body in the record.
level: high
---
title: Bedrock invocation log destination removed or blocked
id: 3e6c14b8-70fa-42d9-a851-c9b0472e35d7
name: bedrock_log_destination_tampered
status: experimental
description: >-
  The logging configuration still exists and its destination does not accept writes. Deleting the
  S3 bucket or the CloudWatch log group, or replacing the bucket policy so the bedrock.amazonaws.com
  service principal can no longer PutObject, stops delivery while
  GetModelInvocationLoggingConfiguration still returns a healthy configuration. There is no
  Bedrock-side error event when delivery starts failing — nothing is called — so this is the path a
  configuration check alone will not find.
references:
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'DeleteBucket'
      - 'DeleteBucketPolicy'
      - 'PutBucketPolicy'
      - 'PutLifecycleConfiguration'
  success:
    errorCode: null
  # ADJUST to the bucket naming used for Bedrock invocation log destinations in this estate.
  log_bucket:
    requestParameters.bucketName|contains:
      - 'bedrock-logs'
      - 'bedrock-invocation'
      - 'modelinvocation'
  condition: selection and success and log_bucket
falsepositives:
  - >-
    Lifecycle or policy maintenance on the log bucket. Worth reading every time: an expiry rule on
    the data prefix destroys the bodies over 100 KB, which are stored as separate objects there and
    are exactly the large prompts most worth keeping.
level: medium
```

What this set structurally cannot do: it cannot recover the gap. Invocation logging is not
retroactive, so the prompts and responses for the affected period do not exist and never will —
restoring the configuration restores the future only.

---

### Key Investigation Queries

> Query 1 is the divergence check and needs both sources. Queries 2–4 read the Bedrock, S3 and
> CloudTrail APIs. Bedrock configuration is per-Region: run the state queries in every Region where
> Bedrock is used.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: do the two sources agree

```bash
REGION="us-east-1"
LOG_GROUP="/aws/bedrock/modelinvocations"
SINCE=$(date -u -v-24H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)
START=$(date -u -v-24H +%s 2>/dev/null || date -u -d '24 hours ago' +%s)
END=$(date -u +%s)

TRAIL=$(for EV in InvokeModel InvokeModelWithResponseStream Converse ConverseStream; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson | select(.errorCode == null) | .eventTime'
done | wc -l | tr -d ' ')

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string 'fields @timestamp | stats count() as logged' 2>/dev/null)
if [ -n "$QID" ]; then
  until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
             --output text --query status)" != "Running" ]; do sleep 3; done
  LOGGED=$(aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
           jq -r '.results[0][0].value // "0"')
else
  LOGGED="0"
  echo "[!] could not query $LOG_GROUP — it may not exist, which is itself the finding"
fi

echo "[i] CloudTrail invocations: $TRAIL"
echo "[i] Invocation-log records:  $LOGGED"
if [ "$TRAIL" -ge 20 ] && [ "$LOGGED" -eq 0 ]; then
  echo "[FAIL] LOGGING REMOVED WHILE INVOCATIONS CONTINUE — the unambiguous case"
elif [ "$TRAIL" -ge 20 ] && [ "$LOGGED" -lt $((TRAIL / 2)) ]; then
  echo "[FAIL] PARTIAL LOSS — check for a disabled modality or a failing destination"
elif [ "$TRAIL" -eq 0 ] && [ "$LOGGED" -eq 0 ]; then
  echo "[i] no invocations at all — availability or a quiet period, not a security finding"
else
  echo "[OK] both sources broadly agree"
fi
```

This is the detection that other services in this corpus cannot have. `quiet + quiet` is a workload
that stopped; `quiet + busy` is a log that was removed. The counts do not need to match exactly —
delivery latency and the sampling of a lookback both introduce skew — but a ratio near zero with
substantial CloudTrail volume has one explanation.

#### Query 2 — Sweep: the configuration state, per Region

```bash
for REGION in us-east-1 eu-west-1 ap-southeast-2; do
  aws bedrock get-model-invocation-logging-configuration --region "$REGION" --output json 2>/dev/null | \
    jq -r --arg r "$REGION" '.loggingConfig |
      if . == null then "[FAIL] \($r) NO logging configuration"
      else "[\(if (.textDataDeliveryEnabled and .imageDataDeliveryEnabled and .embeddingDataDeliveryEnabled) then "OK]  " else "!]   " end) \($r) text=\(.textDataDeliveryEnabled) image=\(.imageDataDeliveryEnabled) embedding=\(.embeddingDataDeliveryEnabled) s3=\(.s3Config.bucketName // "-") cw=\(.cloudWatchConfig.logGroupName // "-")"
      end' \
    || echo "[FAIL] $REGION could not read the configuration"
done
echo "[!] A modality set to false is a class of invocation with no body recorded — and it produces"
echo "    NO divergence in Query 1, because both sources keep producing records."
echo "[!] A [FAIL] with no configuration is either removal or never-enabled. Only the stored"
echo "    snapshot from §1, or Query 4's control-plane events, separates those."
```

#### Query 3 — Inspect: is the destination receiving

```bash
REGION="us-east-1"
BUCKET="<invocation-log-bucket>"
LOG_GROUP="/aws/bedrock/modelinvocations"

echo "== S3 destination =="
aws s3api list-objects-v2 --bucket "$BUCKET" --region "$REGION" \
  --query 'reverse(sort_by(Contents,&LastModified))[:5].[Key,LastModified,Size]' \
  --output text 2>/dev/null || echo "[FAIL] cannot list $BUCKET — deleted, or the policy no longer permits delivery"

echo
echo "== can the Bedrock service principal still write =="
aws s3api get-bucket-policy --bucket "$BUCKET" --region "$REGION" --output json 2>/dev/null | \
  jq -r '.Policy | fromjson | .Statement[]
    | select((.Principal.Service // "") == "bedrock.amazonaws.com")
    | "allow \(.Action | tostring) on \(.Resource | tostring)"' \
  || echo "[FAIL] no statement for bedrock.amazonaws.com — delivery to S3 will be failing silently"

echo
echo "== lifecycle on the data prefix, where bodies over 100 KB live =="
aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET" --region "$REGION" --output json 2>/dev/null | \
  jq -r '.Rules[] | select(.Status == "Enabled") | "rule=\(.ID) expiry=\(.Expiration.Days // "-")d prefix=\(.Filter.Prefix // "*")"' \
  || echo "[i] no lifecycle configuration"

echo
echo "== CloudWatch destination =="
aws logs describe-log-streams --log-group-name "$LOG_GROUP" --order-by LastEventTime --descending \
  --max-items 3 --region "$REGION" --output json 2>/dev/null | \
  jq -r '.logStreams[] | "\(.logStreamName)\tlast=\(.lastEventTimestamp)"' \
  || echo "[FAIL] cannot read $LOG_GROUP"
```

The lifecycle check matters more here than in most services: bodies over 100 KB and all binary data
are stored as separate objects under the data prefix, so an expiry rule there destroys exactly the
large prompts most worth keeping while leaving the inline records intact.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in DeleteModelInvocationLoggingConfiguration PutModelInvocationLoggingConfiguration; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId, region: .awsRegion,
       text: (.requestParameters.loggingConfig.textDataDeliveryEnabled // "-"),
       image: (.requestParameters.loggingConfig.imageDataDeliveryEnabled // "-"),
       embedding: (.requestParameters.loggingConfig.embeddingDataDeliveryEnabled // "-"),
       bucket: (.requestParameters.loggingConfig.s3Config.bucketName // "-"),
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'sort_by(.time)'
```

Read the pairs. A `Delete` followed by a `Put` within minutes is a destination change. A `Put` whose
`text`, `image` or `embedding` reads `false` is the quiet path, and it will not appear in Query 1 at
all. A `Delete` with no `Put` after it is the loud one, and Query 1 will already have shown it.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore recording, then establish what was invoked while it was off — CloudTrail still knows *that*,
even though nothing knows *what*.

> Run every command under the **break-glass responder credentials** from §1.

#### Step 1 — Restore the logging configuration, with every modality

```bash
REGION="us-east-1"
BUCKET="<invocation-log-bucket>"
LOG_GROUP="/aws/bedrock/modelinvocations"
ROLE_ARN="<bedrock-logging-role-arn>"

aws bedrock put-model-invocation-logging-configuration --region "$REGION" \
  --logging-config "{
    \"textDataDeliveryEnabled\": true,
    \"imageDataDeliveryEnabled\": true,
    \"embeddingDataDeliveryEnabled\": true,
    \"s3Config\": {\"bucketName\": \"$BUCKET\", \"keyPrefix\": \"bedrock\"},
    \"cloudWatchConfig\": {\"logGroupName\": \"$LOG_GROUP\", \"roleArn\": \"$ROLE_ARN\",
                           \"largeDataDeliveryS3Config\": {\"bucketName\": \"$BUCKET\", \"keyPrefix\": \"bedrock-large\"}}
  }" \
  && aws bedrock get-model-invocation-logging-configuration --region "$REGION" --output json | \
     jq -r '.loggingConfig | "[OK] text=\(.textDataDeliveryEnabled) image=\(.imageDataDeliveryEnabled) embedding=\(.embeddingDataDeliveryEnabled)"'
```

Every modality is set explicitly, because the call **replaces** the configuration — omitting one
disables it, which is the same quiet path this playbook exists to detect. `largeDataDeliveryS3Config`
matters too: without it, bodies over 100 KB have nowhere to go.

#### Step 2 — Prove records are landing

```bash
echo "[i] Invoke a model once from a principal you control, then confirm a record appears in the"
echo "    destination. Configuration returning healthy is not delivery — Query 3 checks the"
echo "    destination itself, and the newest object or stream timestamp is the real answer."
```

#### Step 3 — Establish what was invoked during the gap

Run Query 4 for the deletion time, then run the CloudTrail-only view from
`../bedrock.impact.high-invocation-count/` §Query 2 over the gap. CloudTrail still records **who**
invoked **which model** and **how often** — so the exposure can be bounded even though the content
cannot be recovered. That distinction is worth stating precisely in the incident: the parties and
the volume are known, the content is not.

#### Step 4 — Contain the principal

Use the standard procedure in §3 Step 4 of `../vpc.stealth.no-logs-from-amazon-vpc-flow-logs/`,
which is identical and not restated here. Then read what the same principal did **after** the
deletion — that is what the gap was opened for, and CloudTrail still has it.

---

## 4. Eradication

### Remove Attacker Access

#### Enable logging in every Region where Bedrock is used

Query 2's `[FAIL]` lines are Regions with no configuration. Most will be Regions nobody enabled
rather than Regions where it was removed, and both are the same gap.

#### Restore every disabled modality

A `[!]` line in Query 2 is a class of invocation whose body is not recorded. Each needs either
restoring or recording as an accepted exception — image logging in particular is sometimes disabled
deliberately for cost, and that decision should be visible rather than assumed.

#### Repair the destination

If Query 3 showed no recent objects or a missing bucket-policy statement for
`bedrock.amazonaws.com`, delivery is broken independently of the configuration and there is no event
that will tell you when it started.

#### Right-size who can change Bedrock logging

`bedrock:DeleteModelInvocationLoggingConfiguration` and
`bedrock:PutModelInvocationLoggingConfiguration` belong to an infrastructure or security role.
Query 4's principal is the starting point.

---

## 5. Recovery

### Restore Clean State

#### Verify configuration and modalities in every Region

Re-run Query 2. Every Region with Bedrock usage should show `[OK]` with all three modalities true.

#### Verify the divergence has closed

```bash
# Assert the divergence has actually closed. Both counts come from re-running §2 Query 1 over the
# last hour; export them before running this.
: "${INVOCATION_LOGS:?count of Bedrock invocation-log records in the last hour}"
: "${CLOUDTRAIL_CALLS:?count of InvokeModel events in the same hour}"

if [ "$CLOUDTRAIL_CALLS" -eq 0 ]; then
  echo "[FAIL] no InvokeModel calls in the window — this proves nothing either way, re-run under load"
elif [ "$((INVOCATION_LOGS * 100 / CLOUDTRAIL_CALLS))" -ge 90 ]; then
  echo "[OK] $INVOCATION_LOGS / $CLOUDTRAIL_CALLS — invocation logging has resumed"
else
  echo "[FAIL] $INVOCATION_LOGS / $CLOUDTRAIL_CALLS — divergence persists."
  echo "       The configuration is present but records are not arriving: check the DESTINATION"
  echo "       (bucket policy, CloudWatch log group, KMS key), not the configuration."
fi
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  eventSource=bedrock.amazonaws.com"
echo "  eventName=DeleteModelInvocationLoggingConfiguration  no errorCode"
echo "and MUST fire on the path that produces NO divergence:"
echo "  eventName=PutModelInvocationLoggingConfiguration with imageDataDeliveryEnabled=false"
echo "  (configuration present, console green, both log streams still producing records —"
echo "   only the image bodies stop, and only this event shows it)"
echo "The rule MUST NOT fire on:"
echo "  PutModelInvocationLoggingConfiguration with all three modalities true, by the"
echo "  provisioning role"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| Prompts and responses stopped being recorded | `DeleteModelInvocationLoggingConfiguration` was available to a principal outside the platform function |
| The alarm read it as an availability event | The only Bedrock rule was a metric alarm on invocation volume, which cannot separate a stopped workload from a removed log |
| A disabled modality would have gone unnoticed | Both log streams keep producing records, so it produces no divergence and only the control-plane event shows it |
| The gap could not be sized | No scheduled snapshot of the logging configuration existed, and logging is off by default so "never enabled" and "removed" looked the same |
| Delivery failure would have been invisible | No Bedrock event fires when delivery starts failing, and the destination was not checked |

### Recommended Guardrails

**Fence the logging configuration and its destination**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["bedrock:DeleteModelInvocationLoggingConfiguration",
             "bedrock:PutModelInvocationLoggingConfiguration",
             "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketPolicy"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Enable invocation logging in the provisioning module for every Region where Bedrock is used, with
  all modalities and a large-data S3 destination. It is off by default and not retroactive.
- Deliver to a bucket in a separate account whose policy the workload account cannot modify.
  Stopping the logging and destroying it should require different access.
- Snapshot the configuration per Region on a schedule. It is the only thing that distinguishes
  "removed" from "never enabled", which the log streams cannot.
- Set the lifecycle on the data prefix deliberately. Bodies over 100 KB live there as separate
  objects, and an expiry rule destroys the large prompts while leaving the inline records intact.

**Detection improvements**
- Compare the two sources. This is the one service in the corpus where absence is unambiguous, and
  not using that is leaving the strongest available signal on the table.
- Alert on a disabled **modality**, not only on deletion. It is the path that produces no divergence
  and leaves every dashboard green.
- Check the destination on a schedule. No event fires when delivery starts failing, so a scheduled
  read is the only thing that finds it.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log |
| MITRE tactic | Defense Impairment (TA0112) |
| Primary API | `bedrock:DeleteModelInvocationLoggingConfiguration`; `PutModelInvocationLoggingConfiguration` with a modality disabled |
| Event source | bedrock.amazonaws.com and s3.amazonaws.com; the divergence check reads the invocation log against CloudTrail `bedrock-runtime` data events |
| Key discriminator | Invocation-log records at or near zero while CloudTrail shows substantial `bedrock-runtime` volume for the same Region and window |
| Ground-truth signal | `get-model-invocation-logging-configuration` for the state, and the newest object or stream in the destination for whether delivery works |
| "Was it used" pivot | CloudTrail over the gap — it still records who invoked which model and how often, so the exposure is bounded even though the content is not recoverable |
| Blast radius | Every prompt and response for the affected period and Region, permanently. Token counts too, which are the cost measure |
| Error strings | None on the calls themselves. A failing destination produces **no Bedrock event at all** — its only symptom is the absence of new objects or streams |

**MITRE mapping note:** the source entry maps to nothing and carries no detection logic — it is a
CloudWatch metric building block. `T1685.002 — Disable or Modify Cloud Log` is correct here and the
sub-technique choice is deliberate: the model invocation log is a **log**, so `.002`, where
`../guardduty.stealth.no-logs-from-amazon-guardduty/` uses `.001` because GuardDuty is a security
**tool**. Verified live 2026-08-30.

### Residual Risk

Invocation logging cannot be applied retroactively, so the prompts and responses for the gap do not
exist and never will — restoring the configuration restores the future only. Where the concern is
what was generated using the organisation's models, or what data was placed into a prompt, that
question is permanently unanswerable for the affected period; CloudTrail bounds it by naming the
principals, the models and the volume, and describes none of it. If a modality was disabled rather
than the configuration deleted, the gap is narrower, longer-lived and produced no divergence at any
point. And bodies over 100 KB live as separate S3 objects under the data prefix, so a lifecycle
rule there removes the largest prompts while every inline record still looks complete.
