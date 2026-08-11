# IR Playbook - Invoke Bedrock Model for Resource Exhaustion - LLM Cost Abuse via `bedrock:InvokeModel`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Impact / Resource Hijacking (LLM inference cost abuse, "LLMjacking") |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, foundation-model inference is expensive; sustained abuse runs up large bills fast and can exhaust account model quotas, denying service to legitimate workloads |
| MITRE Tactics | Impact |
| MITRE Techniques | T1496 |
| Services in Scope | Bedrock, CloudWatch (Bedrock metrics), CloudTrail, Cost Explorer / Cost Anomaly Detection, IAM |
| Infrastructure Created | None, the emulation only requires Bedrock model access enabled in the region |

**What the emulation does:** calls `bedrock:InvokeModel` (via the `bedrock-runtime` client) against a foundation model in a loop, generating inference cost. This is the LLM analogue of cryptomining: the attacker burns the victim's paid inference capacity, for cost damage, quota exhaustion (denial of service to real workloads), or to resell stolen model access ("LLMjacking").

**What the telemetry does and doesn't give you.** `bedrock:InvokeModel` (and `Converse`/`ConverseStream`) **is** logged as a CloudTrail **management event** by default, a standard multi-region trail captures each call with `userIdentity.arn`, `requestParameters.modelId`, region, and source IP, at no extra cost. So CloudTrail *is* a valid primary source for **volume and per-principal attribution**. What CloudTrail management events do **not** carry is the *token counts*, *throttle counts*, and *prompt/response content*, those come from other sources. Use each for what it is good at:
- **CloudTrail management events**, per-call identity, model, region, source IP → volume + attribution (default, no cost). This is the fastest detection path
- **CloudWatch `AWS/Bedrock` metrics**, `Invocations`, `InputTokenCount`, `OutputTokenCount`, `InvocationThrottles` (on by default, per model, **no** per-principal dimension) → token-level cost signal and quota-throttle signal
- **Bedrock model invocation logging**, opt-in, to S3/CloudWatch → prompt/response *content* and richer per-invocation detail
- **Cost Anomaly Detection / Cost Explorer** on Bedrock spend → the backstop that catches abuse even if logging is disabled

The shipped rule's real defect is therefore **noise, not blindness**: it matches `InvokeModel` with no `eventSource` scoping and no volume threshold, so a single benign call fires it, not that it "never fires." (Note: a few Bedrock operations, `InvokeModelWithBidirectionalStream`, async-invoke, and Agent-runtime calls like `InvokeAgent`/`Retrieve`, are *data events*, not management events, and need data-event logging enabled; but `InvokeModel`, which is what this technique uses, is a management event.)

**Control-plane precursors are also in CloudTrail.** Model-access enumeration (`ListFoundationModels`), model-access requests (`PutUseCaseForModelAccess` / `CreateFoundationModelAgreement`), and, critically, an attacker **disabling invocation logging** (`PutModelInvocationLoggingConfiguration` / `DeleteModelInvocationLoggingConfiguration`) to blind the content capture. Those are the earliest signals.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail multi-region trail**, captures `InvokeModel`/`Converse`/`ConverseStream` as management events with `userIdentity.arn`, `modelId`, region, and source IP, by default and at no extra cost. This is your primary per-principal volume/attribution source; confirm the trail exists and covers every Bedrock-enabled region
- **CloudWatch `AWS/Bedrock` metrics** are on by default, build dashboards/alarms on `Invocations`, `InputTokenCount`, `OutputTokenCount`, `InvocationThrottles` per `ModelId`. These add the *token-level* and *throttle* signal CloudTrail lacks (but have no per-principal dimension)
- **Bedrock model invocation logging** (opt-in, to S3/CloudWatch), enable it for prompt/response *content* and richer detail; it is the source for *what was asked*, not for *whether/who invoked* (CloudTrail already gives that)
- **AWS Cost Anomaly Detection** monitor scoped to the Bedrock service, the backstop that catches cost abuse even if invocation logging is disabled

**Alerting (must be pre-configured)**
- CloudWatch alarm: `AWS/Bedrock` `Invocations` or `InputTokenCount` exceeding a baseline multiple (e.g. >3× rolling average) per model → alert
- CloudWatch alarm: `InvocationThrottles` spiking → the account is hitting model quota (abuse in progress or DoS to real workloads)
- **P0: `bedrock:PutModelInvocationLoggingConfiguration` / `DeleteModelInvocationLoggingConfiguration` disabling or unencrypting logging** → an attacker blinding you before abuse
- Cost Anomaly Detection: Bedrock spend anomaly → alert
- `bedrock:InvokeModel` by a principal not on the ML-workload allowlist, visible directly in the default CloudTrail management-event trail (with `userIdentity.arn`); no invocation logging or data events required for this

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` installed
- The list of principals/roles that legitimately invoke Bedrock, and per-model baseline invocation/token volumes
- Knowledge of which models are enabled in which regions (abuse often targets the most capable/expensive models)

**Known IOC Baselines**
- Baseline per-model invocation and token volume, and which principals invoke, a sudden spike, a new principal, or an off-hours surge is the signal
- Baseline the set of regions with Bedrock enabled; invocation in an unexpected region is anomalous (attackers enable access in quiet regions)

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Sustained `AWS/Bedrock` `Invocations` / `InputTokenCount` spike far above baseline for a model | CloudWatch metrics | T1496 |
| P0 | Bedrock model invocation logging disabled/unencrypted (`Put/DeleteModelInvocationLoggingConfiguration`) | CloudTrail | T1496 |
| P0 | Bedrock cost anomaly not explained by a known workload | Cost Anomaly Detection | T1496 |
| P1 | `bedrock:InvokeModel` at volume by a principal not on the ML-workload allowlist | CloudTrail (management events) + CloudWatch metrics | T1496 |
| P1 | `InvocationThrottles` spiking (quota exhaustion in progress) | CloudWatch metrics | T1496 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `ListFoundationModels` / model-access enumeration then a burst of invocations | CloudTrail + metrics | T1496 |
| P2 | Model-access request (`PutUseCaseForModelAccess` / `CreateFoundationModelAgreement`) by a non-provisioning principal | CloudTrail | T1496 |
| P2 | Invocation in a region with no normal Bedrock workload | CloudWatch metrics (per region) | T1496 |
| P2 | `bedrock:InvokeModel` denied at volume (`errorCode = AccessDeniedException`), access probing | CloudTrail (management events) | T1496 |
| P3 | Modest invocation volume from an allowlisted ML principal within baseline | metrics / logging | T1496 |

### Detection Rule Quality Notes

The rules in `detections/` are too coarse, they fire on every invocation. These are noise/precision defects (the rule *does* fire; it just can't tell abuse from normal use).

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `EventName == "InvokeModel"` with `condition: selection`, no threshold | Noise. `InvokeModel` *is* a CloudTrail management event, so the rule fires, but on **every** call, including the constant legitimate traffic of any real ML workload. It cannot distinguish abuse (volume) from normal use, so it gets muted | Add a per-principal count threshold over a window (the technique is defined by *volume*, not occurrence) |
| KQL rule omits `eventSource` | Matching a bare `InvokeModel` across all sources is imprecise and risks name collisions | Scope to `eventSource: bedrock.amazonaws.com` (the runtime calls log under this source) |
| Aggregate cost/throttle signal absent | CloudTrail shows calls but not token volume or quota exhaustion; the biggest-bill and DoS signals live in CloudWatch metrics | Add CloudWatch `AWS/Bedrock` `InputTokenCount` / `InvocationThrottles` alarms alongside the CloudTrail rule |
| The disable-logging precursor is not detected | An attacker who disables invocation logging blinds the *content* capture | Add a P0 rule on `Put/DeleteModelInvocationLoggingConfiguration` |
| Header TODO "verify acronym casing"; `level: medium` on a HIGH-severity cost technique | Stale marker; under-rated | Resolve TODO; thresholded volume rule → `level: high` |

**Recommended detections.** Deploy three complementary controls:

1. **A CloudTrail volume rule**, the primary, zero-config detection. `InvokeModel` is a management event, so a thresholded correlation over the default trail works out of the box:

```yaml
# Base rule: a Bedrock invocation (management event)
title: Bedrock InvokeModel
id: 3e1a7c94-2f60-4b85-9d02-6c8a1b7e0f53
name: bedrock_invoke_base
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'bedrock.amazonaws.com'
    eventName:
      - 'InvokeModel'
      - 'InvokeModelWithResponseStream'
      - 'Converse'
      - 'ConverseStream'
  condition: selection
level: low
---
# Correlation: high invocation volume from one principal (the abuse shape)
title: Bedrock invocation flood from a single principal
status: experimental
correlation:
  type: event_count
  rules:
    - bedrock_invoke_base
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gt: 100          # tune to the workload baseline; the emulation loops rapidly
level: high
```

2. **CloudWatch alarms** on `AWS/Bedrock` `InputTokenCount` and `InvocationThrottles` per model, the token-cost and quota-exhaustion signals CloudTrail can't provide.
3. **A Sigma rule on the disable-logging precursor** (attacker blinding content capture):

```yaml
title: Bedrock model invocation logging disabled or altered
id: 2c7f9a13-6b48-4e02-9d15-8a3c0b7e5f41
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'bedrock.amazonaws.com'
    eventName:
      - 'DeleteModelInvocationLoggingConfiguration'
      - 'PutModelInvocationLoggingConfiguration'   # review: was logging weakened?
  condition: selection
level: high
```

Back all three with Cost Anomaly Detection on Bedrock spend.

**On error strings:** Bedrock denials surface as `AccessDeniedException`; throttling as `ThrottlingException`. Not `Client.`-prefixed like EC2. Match those forms and confirm against a sample event.

---

### Key Investigation Queries

> `InvokeModel` **is** a CloudTrail management event, so Query 1 attributes the abuse per-principal straight from the default trail. CloudWatch metrics (Query 2) add the token/throttle volume CloudTrail lacks; invocation logging adds prompt/response content. CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

#### Query 1 - Who invoked, and how much? (CloudTrail: the fastest attribution path)

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=InvokeModel \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "bedrock.amazonaws.com") |
    {arn: .userIdentity.arn, access_key: .userIdentity.accessKeyId,
     model: .requestParameters.modelId, ip: .sourceIPAddress,
     error: (.errorCode // "SUCCESS")}' | \
  jq -s 'group_by(.arn) | map({
      principal: .[0].arn,
      access_keys: ([.[].access_key] | unique),        # feeds ACCESS_KEY_ID in Query 6
      invocations: length,
      models: ([.[].model] | unique),
      source_ips: ([.[].ip] | unique),
      denied: ([.[] | select(.error!="SUCCESS")] | length)
    }) | sort_by(-.invocations)'
# Also check Converse/ConverseStream/InvokeModelWithResponseStream the same way,
# they are management events too.
```

The principal with an anomalously high `invocations` count is the abuser, and its
`access_keys` feed Query 6. (`lookup-events` paginates but caps returned volume;
for the true count use Query 2's CloudWatch `Invocations` metric, which sums every
call.)

#### Query 2: Quantify token burn and throttling (CloudWatch metrics)

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
MODEL_ID="anthropic.claude-3-sonnet-20240229-v1:0"   # the abused model from cost/metrics

# Invocation count over the incident window, hourly
aws cloudwatch get-metric-statistics --namespace AWS/Bedrock \
  --metric-name Invocations --region "$REGION" \
  --dimensions Name=ModelId,Value="$MODEL_ID" \
  --start-time "$START" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 3600 --statistics Sum --output table

# Token consumption (drives the bill) and throttling (quota exhaustion)
for M in InputTokenCount OutputTokenCount InvocationThrottles; do
  echo "=== $M ==="
  aws cloudwatch get-metric-statistics --namespace AWS/Bedrock \
    --metric-name "$M" --region "$REGION" \
    --dimensions Name=ModelId,Value="$MODEL_ID" \
    --start-time "$START" \
    --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --period 3600 --statistics Sum --output table
done
```

A sharp, sustained rise in `Invocations`/`InputTokenCount`, especially with
`InvocationThrottles` climbing, confirms abuse. Repeat per enabled model and
region.

#### Query 3: Retrieve prompt/response content (invocation logging, if enabled)

Query 1 already gave the *who/how-much* from CloudTrail. Invocation logging adds
the one thing CloudTrail doesn't: the *content* of each request/response, useful
to understand what the attacker was doing (data exfil via prompts, resale probes,
jailbreak attempts). It is opt-in; if it is off, skip this, you still have
attribution from Query 1 and volume from Query 2.

```bash
REGION="us-east-1"

# Is invocation logging enabled, and where does it deliver?
aws bedrock get-model-invocation-logging-configuration --region "$REGION" \
  --query 'loggingConfig.{S3:s3Config.bucketName,CW:cloudWatchConfig.logGroupName,
           EmbeddingsData:embeddingDataDeliveryEnabled,TextData:textDataDeliveryEnabled}' \
  --output json

# If CloudWatch invocation logging is on, pull the logged records (each carries
# identity, model, region, and - if textDataDeliveryEnabled: the prompt/response)
LOG_GROUP="<bedrock-invocation-log-group-from-above>"
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%s 2>/dev/null \
        || date -u -v-24H +%s)
aws logs filter-log-events --log-group-name "$LOG_GROUP" \
  --start-time "${START}000" --region "$REGION" \
  --query 'events[*].message' --output text 2>/dev/null | \
  jq -r 'fromjson? | {arn: .identity.arn, model: .modelId, region: .region}' 2>/dev/null | \
  jq -s 'group_by(.arn) | map({principal: .[0].arn, invocations: length,
         models: ([.[].model] | unique)}) | sort_by(-.invocations)'
```

**Handle the retrieved prompts/responses as sensitive**, they may contain the
data the attacker was extracting.

#### Query 4: Control-plane precursors (CloudTrail management events)

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

# Attacker disabling/altering invocation logging (blinding you): P0
for EV in DeleteModelInvocationLoggingConfiguration PutModelInvocationLoggingConfiguration; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$START" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId, ip: .sourceIPAddress}'

# Model-access enumeration / requests preceding the abuse
for EV in ListFoundationModels PutUseCaseForModelAccess CreateFoundationModelAgreement; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$START" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, caller: .userIdentity.arn, ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

#### Query 5: Cost impact

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START_DATE=$(date -u -d '14 days ago' +%Y-%m-%d 2>/dev/null \
        || date -u -v-14d +%Y-%m-%d)

# Bedrock spend by day: quantify the damage and confirm it is dropping post-containment
aws ce get-cost-and-usage --granularity DAILY \
  --time-period Start=$START_DATE,End=$(date -u +%Y-%m-%d) \
  --metrics UnblendedCost \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Bedrock"]}}' \
  --query 'ResultsByTime[].{Date:TimePeriod.Start,Cost:Total.UnblendedCost.Amount}' \
  --output table
```

#### Query 6: Full session reconstruction of the abusing principal

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

ACCESS_KEY_ID="<access-key-from-Query-1 (or Query-4 for the control-plane actor)>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$START" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

#### Query 7: Multi-region metric sweep (abuse often hides in quiet regions)

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  SUM=$(aws cloudwatch get-metric-statistics --namespace AWS/Bedrock \
    --metric-name Invocations --region "$REGION" \
    --start-time "$START" \
    --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --period 86400 --statistics Sum \
    --query 'Datapoints[0].Sum' --output text 2>/dev/null)
  [ -n "$SUM" ] && [ "$SUM" != "None" ] && [ "$SUM" != "0.0" ] && \
    echo "[!] $REGION, $SUM Bedrock invocations in 24h"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The damage is billing/quota, accruing continuously while the principal can invoke.
Cut the principal's invoke access immediately; the invocations stop the moment the
credential can no longer call `InvokeModel`.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1: Contain the abusing principal

Query 1 (CloudTrail) attributes the abuse to a principal directly. Contain that
principal; if attribution is ambiguous (e.g. a shared role), cross-check the
prompt/response detail from Query 3 (invocation logging, if enabled) and use the
cost/metric drop after containment to confirm you got the right one.

```bash
SUSPECT_ARN="<principal-arn>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')          # user ARN: name = last segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] Disabled key $K for $U"
  done
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')           # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]}'
  echo "[OK] Revoked sessions for role $R"
fi
```

#### Step 2: Deny Bedrock invocation by the principal (targeted)

If the principal is a production role that must keep other functions, deny only
Bedrock invocation rather than all actions. (For an IAM user, `put-user-policy`
with the same document; users are also contained by the key disable in Step 1.)

```bash
SUSPECT_ROLE="<role-name>"    # role principals; for an IAM user use put-user-policy
aws iam put-role-policy --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenyBedrock" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":["bedrock:InvokeModel","bedrock:InvokeModelWithResponseStream","bedrock:Converse","bedrock:ConverseStream"],"Resource":"*"}]
  }'
echo "[OK] Bedrock invocation denied for $SUSPECT_ROLE"
```

#### Step 3: Account-wide brake if attribution is unclear or abuse is broad

If you cannot pin the principal quickly and cost is climbing, apply an
organization/account SCP denying Bedrock invocation to all but the known ML
workload roles, stops the bleeding while you investigate. (Decision, not reflex:
it also stops legitimate Bedrock workloads.)

```bash
# SCP (apply via Organizations): deny Bedrock invoke to all but allowlisted roles
cat <<'JSON'
{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Deny",
    "Action":["bedrock:InvokeModel","bedrock:InvokeModelWithResponseStream","bedrock:Converse","bedrock:ConverseStream"],
    "Resource":"*",
    "Condition":{"StringNotLike":{"aws:PrincipalArn":["arn:aws:iam::*:role/ml-workload","arn:aws:iam::*:role/BreakGlassAdmin"]}}
  }]
}
JSON
echo "Apply the above as an SCP if broad containment is warranted."
```

#### Step 4: Restore invocation logging if the attacker disabled it

If Query 4 showed logging disabled, re-enable it so continued/renewed abuse is
captured.

```bash
REGION="us-east-1"
echo "Re-enable Bedrock model invocation logging (S3/CloudWatch, encrypted) via"
echo "PutModelInvocationLoggingConfiguration, and lock down who can change it."
```

---

## 4. Eradication

### Remove Attacker Access

#### Right-size Bedrock permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove bedrock:InvokeModel* from principals with no ML workload need. Where
# needed, scope to specific model ARNs (Resource - arn:aws:bedrock:*::foundation-model/<id>)
# rather than Resource: *.
```

#### Confirm the credential/session cannot invoke, across regions

Bedrock is regional; ensure the deny/containment is effective everywhere the
attacker invoked (Query 7).

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-1H +%Y-%m-%dT%H:%M:%SZ)

# Confirm CloudWatch Invocations has dropped to baseline in every region from Query 7
ABUSE_REGIONS="<space-separated-regions-from-Query-7>"
for REGION in $ABUSE_REGIONS; do
  SUM=$(aws cloudwatch get-metric-statistics --namespace AWS/Bedrock \
    --metric-name Invocations --region "$REGION" \
    --start-time "$START" \
    --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --period 3600 --statistics Sum --query 'Datapoints[0].Sum' --output text 2>/dev/null)
  echo "$REGION: ${SUM:-0} invocations in the last hour (expect near baseline)"
done
```

#### If it was a compromised static key, treat it as a broader compromise

LLMjacking commonly follows a leaked long-lived key. Rotate it (delete + reissue
via IAM), and review everything else that key did (Query 6) - Bedrock abuse may
be one facet of a wider compromise.

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenyBedrock" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
# Remove the account SCP from Step 3 once the principal is contained and scoped
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify invocations have returned to baseline

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-1H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
MODEL_ID="<abused-model-id>"

SUM=$(aws cloudwatch get-metric-statistics --namespace AWS/Bedrock \
  --metric-name Invocations --region "$REGION" \
  --dimensions Name=ModelId,Value="$MODEL_ID" \
  --start-time "$START" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 3600 --statistics Sum --query 'Datapoints[0].Sum' --output text 2>/dev/null)
echo "Invocations in the last hour: ${SUM:-0}"
echo "[Confirm this is at/near the pre-incident baseline; a still-elevated number"
echo " means containment did not fully stop the abuse.]"
```

#### Verify invocation logging is enabled and encrypted

```bash
REGION="us-east-1"
CFG=$(aws bedrock get-model-invocation-logging-configuration --region "$REGION" \
  --query 'loggingConfig.{S3:s3Config.bucketName,CW:cloudWatchConfig.logGroupName}' --output json 2>/dev/null)
echo "$CFG"
echo "$CFG" | jq -e '(.S3 != null and .S3 != "") or (.CW != null and .CW != "")' >/dev/null \
  && echo "[OK] Bedrock invocation logging is configured" \
  || echo "[FAIL] Bedrock invocation logging is OFF, invocations are unattributable"
```

#### Verify the credential is dead

```bash
SUSPECT_ARN="<principal-arn>"
if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  ACTIVE=$(aws iam list-access-keys --user-name "$U" \
    --query 'AccessKeyMetadata[?Status==`Active`]' --output text)
  [ -z "$ACTIVE" ] && echo "[OK] No active keys for $U" || echo "[FAIL] $U still has active keys"
fi
```

#### Verify Bedrock cost has returned to baseline

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START_DATE=$(date -u -d '3 days ago' +%Y-%m-%d 2>/dev/null \
        || date -u -v-3d +%Y-%m-%d)

aws ce get-cost-and-usage --granularity DAILY \
  --time-period Start=$START_DATE,End=$(date -u +%Y-%m-%d) \
  --metrics UnblendedCost \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Bedrock"]}}' \
  --query 'ResultsByTime[].{Date:TimePeriod.Start,Cost:Total.UnblendedCost.Amount}' \
  --output table
echo "Confirm daily Bedrock cost has dropped back to baseline."
```

#### Confirm the corrected detection is viable

```bash
# Confirm the corrected detection path across all three sources:
echo "1. CloudTrail: a re-run's InvokeModel calls appear in lookup-events with the"
echo "   test principal's userIdentity.arn, and the thresholded volume rule fires."
echo "2. CloudWatch AWS/Bedrock Invocations/InputTokenCount alarm breaches on the re-run."
echo "3. Bedrock invocation logging is ON (Query 3) and Cost Anomaly Detection monitors Bedrock."
echo "The shipped rule's fix is a per-principal THRESHOLD (it already matched the"
echo "event; it just fired on every benign call) plus eventSource scoping."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could invoke Bedrock models at will | `bedrock:InvokeModel` granted broadly (often via a leaked static key) rather than scoped to ML workloads and specific models |
| Abuse under-detected | The shipped rule matched `InvokeModel` but with no `eventSource` scoping and no volume threshold, so it fired on every benign call and was muted; no CloudWatch token/throttle alarm or cost-anomaly detection existed to catch the abuse volume |
| No per-principal attribution | Bedrock model invocation logging was off, so invocations could not be tied to an identity |
| Cost impact noticed late | No Cost Anomaly Detection on Bedrock |
| Attacker could have blinded logging | No alert on `Put/DeleteModelInvocationLoggingConfiguration` |

### Recommended Guardrails

**Scope Bedrock invocation tightly**

```json
// Restrict InvokeModel to ML-workload roles and specific models
{
  "Effect": "Deny",
  "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:Converse", "bedrock:ConverseStream"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/ml-workload", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- Scope the *allow* side to specific model ARNs (`arn:aws:bedrock:*::foundation-model/<id>`), not `Resource: *`
- Keep Bedrock model access **disabled** in regions with no ML workload, attackers enable it in quiet regions

**Make abuse visible and bounded**
- Enable Bedrock model invocation logging (S3+CloudWatch, KMS-encrypted) in every Bedrock-enabled region, and alert on any attempt to disable it
- CloudWatch alarms on `Invocations`/`InputTokenCount`/`InvocationThrottles` per model; Cost Anomaly Detection on Bedrock spend
- Set Service Quotas / provisioned-throughput limits conservatively so runaway invocation throttles rather than bills unbounded

**Detection improvements**
- Use CloudTrail management events as the primary per-principal `InvokeModel` signal (default, no cost), add a **volume threshold + `eventSource` scoping** so it isn't muted by benign traffic, layer CloudWatch `AWS/Bedrock` token/throttle alarms for the cost/quota signal, and back with Cost Anomaly Detection
- P0 alert on `Put/DeleteModelInvocationLoggingConfiguration`

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1496 - Resource Hijacking |
| MITRE tactic | Impact (TA0040) |
| Primary API | `bedrock:InvokeModel` (also `InvokeModelWithResponseStream`, `Converse`, `ConverseStream`), logged as **management events** |
| Telemetry sources | CloudTrail management events (per-call identity/model/region, volume + attribution, default/no-cost); CloudWatch `AWS/Bedrock` metrics (token counts, throttles, no principal dim); invocation logging (prompt/response content); Cost Anomaly Detection (cost backstop) |
| Shipped-rule defect | It DOES fire (InvokeModel is a management event) but on every call, missing `eventSource` scoping + a volume threshold. Noise, not blindness |
| Data-event-only ops (need data-event logging) | `InvokeModelWithBidirectionalStream`, async-invoke, Agent-runtime (`InvokeAgent`/`Retrieve`/`InvokeFlow`) - NOT plain `InvokeModel` |
| Control-plane precursors (in CloudTrail) | `ListFoundationModels`, `PutUseCaseForModelAccess`, `Put/DeleteModelInvocationLoggingConfiguration` |
| Error strings (not `Client.`-prefixed) | `AccessDeniedException`, `ThrottlingException` |
| Resources created | None, invocations complete and are billed; nothing to destroy |
| Related | Analogous to cryptomining resource-hijacking (the EC2-launch playbook); shares the cost-anomaly backstop |

### Revert

The emulation creates no infrastructure and the invocations cannot be "reverted"
- they completed and are billed. `pulumi destroy` is a no-op. After a **real**
incident, there is nothing to tear down; the response is to contain the principal
(§3), scope Bedrock permissions (§4), and quantify/accept the cost impact. If a
leaked static key drove it, treat the key as a broader compromise and rotate it.
