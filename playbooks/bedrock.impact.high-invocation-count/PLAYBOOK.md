# IR Playbook: Stolen Credentials Used for Model Compute — `InvokeModel` volume, breadth and Region

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Resource hijacking (a credential is used to run foundation-model inference at the account owner's expense) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. The cost is uncapped and accrues per token, and the activity slips past three categories of control at once: nothing is exfiltrated, no instance is launched, and the spend lands in a service most accounts have no budget alarm on. The first indication is frequently the bill. |
| MITRE Tactics | Impact |
| MITRE Techniques | T1496 |
| Services in Scope | Bedrock, Bedrock Runtime, IAM, STS, CloudTrail, Cost Explorer |

**What the technique does:** an attacker obtains a credential — from a repository, a phishing kit, a
compromised laptop, an exposed environment file — and finds it carries `bedrock:InvokeModel`. They
then use it for inference: reselling access, generating content at scale, or running their own
workload on somebody else's account. There is no exploit and no persistence to install. The
credential does exactly what it is permitted to do, at a volume nobody budgeted for.

**Why the usual reflexes miss it.** Data-loss controls see nothing leave. Compute-abuse controls see
no instance launched. Cost anomaly detection is usually tuned to EC2 and S3, and Bedrock spend is
new enough in most estates to be unmonitored. And model invocation logging — the only source of
prompts, responses and token counts — is **off by default**, so an account that has never enabled it
cannot reconstruct what was generated even after the fact.

**Detection thesis:** volume is the obvious signal and the late one. **Model breadth** is the early
one: a legitimate workload uses one model or a small fixed set chosen at design time, while a
credential being explored is tried against everything it can reach.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **Model invocation logging enabled**, with an S3 destination configured for large data. It is
  disabled by default and cannot be applied retroactively, so this single decision determines
  whether an incident can be reconstructed. Note the modality selection — Text, Image, Embedding,
  Video — because an unselected modality is a class of invocation with no body recorded.
- **CloudTrail data events for `bedrock-runtime.amazonaws.com`.** This is what most accounts
  actually have, and it carries the principal, the model, the Region and the source address.
- **A cost anomaly detector or budget alarm scoped to Bedrock**, separate from the account-wide one.
  Bedrock spend is small enough to hide inside a general threshold and large enough to matter.
- **A baseline of which principals invoke which models**, from a normal week. Every rule here is a
  comparison against a principal's own history rather than a fleet average.

**Alerting (must be pre-configured)**
- **One principal invoking five or more distinct models within six hours → P0**
- **An invocation recorded in a Region not on the expected list → P0**
- **One principal exceeding 1,000 invocations in an hour, against its own baseline → P1**
- **Output tokens exceeding input tokens by more than twenty times across more than fifty calls → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- Cost Explorer access, since token counts do not exist without invocation logging and the spend
  question then has only one answer.
- The credential revocation runbook — this is an ordinary credential-misuse incident once the
  service-specific triage is done.

**Known IOC Baselines**
- Which principals legitimately invoke models, and which models. Batch inference and evaluation
  harnesses are genuinely high-volume and genuinely broad, and they are the entire false-positive
  surface for both correlations.
- The Regions in which Bedrock is actually used. Short, stable, and the tuning surface for the
  Region rule.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | One `identity.arn` invoking ≥ 5 distinct `modelId` values within 6 hours | Bedrock invocation logs / CloudTrail (correlation) | T1526 |
| P0 | An invocation in a Region not on the expected list | Bedrock invocation logs / CloudTrail | T1078.004 |
| P1 | One principal exceeding 1,000 invocations in an hour, against its own baseline | Bedrock invocation logs / CloudTrail (correlation) | T1496 |
| P1 | Output tokens exceeding input tokens by more than 20× across more than 50 calls | Bedrock invocation logs | T1496 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A principal with no prior invocation history beginning to invoke models | Bedrock invocation logs / CloudTrail | T1078.004 |
| P2 | A Bedrock cost anomaly with no corresponding deployment or workload change | Cost Explorer / Budgets | T1496 |
| P3 | `PutFoundationModelEntitlement` or model access enabled for a model nobody requested | CloudTrail (`bedrock`) | T1526 |

### Detection Rule Quality Notes

The source entry is a **building block with no query, no threshold and no grouping** — a CloudWatch
metric alarm for cost and availability rather than a detection. There is no logic to audit, so this
table records what the source provides and what a security detection needs instead, rather than
inventing defects in an empty rule.

| Issue | Impact | Correction |
|-------|--------|-----------|
| The source entry carries no detection logic at all | Nothing to tune, nothing to correct, and nothing that fires. Bedrock has no security detection in the pack — the gap is total rather than defective | Four documents built on the invocation log schema, covering volume, model breadth, Region and the token ratio |
| A cost or count alarm has no actor | A CloudWatch metric alarm on invocation count tells you the account is spending and not which principal is spending it, which is the only fact containment needs | Group by `identity.arn`, which AWS captures automatically and names as the attribution field |
| Volume alone is the late signal | By the time a volume threshold trips, the abuse is already expensive. A credential being explored makes few calls against many models | Model breadth as the primary rule at high, firing within a handful of calls |
| No account of logging being off by default | AWS: *"Model invocation logging is disabled by default."* A rule written only against invocation logs is inapplicable to most accounts, silently | Both planes shipped: the invocation-log view and a CloudTrail-only view, with what each can and cannot answer stated |
| `requestMetadata` is available and inviting | AWS: it is *"the only field supplied by the caller"*. Using it to group or to allowlist means trusting a field the attacker sets | Projected for context, never used as a key or a filter. `identity.arn` is the only actor field |
| Bodies over 100 KB are not in the log entry | Large prompts and all binary data are stored as separate S3 objects. Any rule inspecting prompt text misses exactly the large prompts | Noted here and load-bearing in the sibling playbook that inspects content; this playbook counts rather than reads |

**Recommended detection — breadth first, volume second, Region as a one-shot.**

```yaml
# Stolen credentials used for model compute — "LLMjacking" (T1496 / T1078.004)
#
# THE SOURCE RULE CARRIES NO LOGIC. All four Bedrock entries in the source pack are BUILDING BLOCKS
# with no query, no threshold and no group-by — CloudWatch metric alarms for cost and availability
# rather than detections. There is therefore nothing to correct here, and this file does not pretend
# otherwise: it is a new security use case built on the service's actual exposure, and the
# Issue/Impact/Correction table in ../PLAYBOOK.md §2 says so rather than inventing defects.
#
# THE EXPOSURE IS REAL AND SPECIFIC. A credential with bedrock:InvokeModel is a credential that
# spends money at the account owner's expense and produces text on demand. Unlike stolen compute for
# mining, this leaves the instance count unchanged and the bill in a service nobody watches — and
# unlike data theft, nothing is exfiltrated, so data-loss controls see nothing at all.
#
# MODEL INVOCATION LOGGING IS OFF BY DEFAULT. AWS: "Model invocation logging is disabled by
# default." Without it, CloudTrail records THAT a model was invoked and by whom, and the prompt and
# response exist nowhere. Both planes are shipped below because they answer different questions and
# most accounts have only the CloudTrail one.
#
# identity.arn IS THE ACTOR FIELD AND requestMetadata IS NOT. AWS: identity.arn is "captured
# automatically", while requestMetadata is "the only field supplied by the caller". Caller-supplied
# means attacker-supplied when the caller is the attacker, so it must never be a grouping key or a
# trust signal in a security rule. It is projected for context and nothing else.
#
# THE 100 KB RULE MATTERS FOR THE NEXT RULE IN THIS SET AND IS NOTED HERE ONCE. Input and output
# bodies over 100 KB, and all binary data, are stored as separate S3 objects rather than inline —
# so any rule inspecting prompt text misses exactly the large prompts that carry bulk data.
title: Bedrock model invoked by a principal with no invocation history
id: 5c81f2a4-9de0-4736-b1a5-27309ce4b8d6
name: bedrock_new_principal_invocation
status: experimental
description: >-
  A principal invoked a foundation model. Shipped as a base rule for the correlations below and as
  the inventory of who calls Bedrock at all, which most accounts do not have. The security question
  is not that an invocation happened but that a principal which has never invoked a model before
  starts doing so at volume — the shape of a credential leaked into a repository or a phishing kit
  and then monetised. group-by in the correlations is identity.arn because AWS captures it
  automatically and names it as the attribution field; requestMetadata is caller-supplied and is
  never used for grouping.
references:
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
  - https://attack.mitre.org/techniques/T1496/
tags:
  - attack.impact
  - attack.t1496
logsource:
  product: aws
  service: bedrock
detection:
  invocation:
    operation:
      - 'InvokeModel'
      - 'InvokeModelWithResponseStream'
      - 'Converse'
      - 'ConverseStream'
  condition: invocation
level: informational
---
title: Sustained Bedrock invocation volume from one principal
id: a0374e91-6b28-4c5d-83f7-1e069b5ca247
status: experimental
description: >-
  One principal drove an unusual number of model invocations in a short window. This is the volume
  signal for a stolen credential being used for model compute — the attacker pays nothing, the
  account owner pays per token, and no instance is launched so no compute-oriented control notices.
  The threshold is deliberately expressed as a count over a window rather than as a cost figure,
  because token pricing varies by model and a cost threshold ages badly. Compare against the
  principal's own history rather than against a fleet average: a batch pipeline legitimately makes
  thousands of calls and a human-facing application does not.
references:
  - https://attack.mitre.org/techniques/T1496/
tags:
  - attack.impact
  - attack.t1496
correlation:
  type: event_count
  rules:
    - bedrock_new_principal_invocation
  group-by:
    - identity.arn
  timespan: 1h
  condition:
    gte: 1000
falsepositives:
  - >-
    Batch inference, evaluation harnesses and load tests, all of which are legitimately high volume
    and all of which run on a schedule somebody can name. Exclude by principal, not by raising the
    threshold — raising it only moves the line an attacker has to stay under.
level: high
---
title: One principal invoking an unusual number of distinct models
id: 7e2b0d63-45fa-49c1-a806-3d5187ce9024
status: experimental
description: >-
  Model breadth rather than call volume. A legitimate workload uses one model, or a small fixed set
  chosen at design time; a credential being explored is used against everything it can reach, to
  find which models are enabled and which give the most capable output for the price. This fires
  earlier than the volume rule and on a much smaller number of calls, which makes it the better of
  the two for a credential that has just been picked up.
references:
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
correlation:
  type: value_count
  rules:
    - bedrock_new_principal_invocation
  group-by:
    - identity.arn
  timespan: 6h
  condition:
    field: modelId
    gte: 5
falsepositives:
  - >-
    A model evaluation or routing layer that deliberately compares outputs across models. Real, and
    a small named set of principals — the same exclusion list as the volume rule.
level: high
---
title: Bedrock model invoked from outside the expected Regions
id: 91cd48b7-30e6-42a9-b57d-6f0821eac935
name: bedrock_unexpected_region_invocation
status: experimental
description: >-
  An invocation recorded in a Region the organisation does not use for Bedrock. Model access is
  enabled per Region and per model, so an actor exploring a stolen credential naturally spreads
  across Regions looking for one where a capable model is already enabled — and a Region nobody
  operates in is a Region nobody watches the bill for. This needs no threshold: one invocation in an
  unused Region is the finding, and the tuning surface is the short list of Regions actually in use.
references:
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
  - https://attack.mitre.org/techniques/T1078/004/
tags:
  - attack.defense-impairment
  - attack.t1078.004
logsource:
  product: aws
  service: bedrock
detection:
  invocation:
    operation:
      - 'InvokeModel'
      - 'InvokeModelWithResponseStream'
      - 'Converse'
      - 'ConverseStream'
  # POPULATE BEFORE DEPLOYING with the Regions this organisation actually uses for Bedrock. The
  # list is short and stable, and leaving it as the example makes the rule fire on everything —
  # which is the correct failure direction for a coverage rule but noisy on day one.
  expected_regions:
    region:
      - 'us-east-1'
      - 'eu-west-1'
  condition: invocation and not expected_regions
falsepositives:
  - >-
    A team adopting a model only available in a new Region, which is a real and frequent reason to
    expand. It should arrive with a request; the alert is how you find out it did not.
level: medium
```

What this set structurally cannot do: without invocation logging enabled beforehand it cannot show
prompts, responses or token counts at all — and that cannot be applied retroactively. It cannot see
invocations made through endpoints other than `bedrock-runtime`, which AWS documents as not covered.
And it cannot trust `requestMetadata`, because the caller supplies it.

---

### Key Investigation Queries

> Query 1 assumes model invocation logging is enabled; Query 2 is the CloudTrail equivalent for
> accounts where it is not. Field names follow `../_ground-truth/bedrock.md` §3. Extraction uses
> `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events
> per page** — paginate on `NextToken` or use your log platform.

#### Query 1 — Reconstruct: what this principal called, and what it cost

```bash
REGION="us-east-1"
LOG_GROUP="/aws/bedrock/modelinvocations"
PRINCIPAL="<identity-arn-from-the-alert>"
START=$(date -u -v-7d +%s 2>/dev/null || date -u -d '7 days ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string "fields @timestamp, identity.arn, modelId, operation,
                         input.inputTokenCount, output.outputTokenCount, region
                  | filter identity.arn like '${PRINCIPAL}'
                  | stats count() as calls,
                          sum(input.inputTokenCount) as in_tokens,
                          sum(output.outputTokenCount) as out_tokens
                          by modelId, operation, region
                  | sort calls desc
                  | limit 100")

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'
```

The model list is the triage. One or two models is an application; five or more is exploration.
`out_tokens` far exceeding `in_tokens` is content generation rather than an application answering
questions. If this query returns nothing, invocation logging was not enabled — go to Query 2 and
record in the incident that prompts and responses do not exist for this period.

#### Query 2 — The CloudTrail-only view, for accounts without invocation logging

```bash
REGION="us-east-1"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in InvokeModel InvokeModelWithResponseStream Converse ConverseStream; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       model: (.requestParameters.modelId // "-"),
       region: .awsRegion, ip: .sourceIPAddress,
       error: (.errorCode // "SUCCESS")}'
done | jq -s 'group_by(.caller) | map({caller: .[0].caller, calls: length,
                                       models: (map(.model) | unique),
                                       regions: (map(.region) | unique),
                                       ips: (map(.ip) | unique | .[0:10]),
                                       first: (map(.time) | min), last: (map(.time) | max)})'
```

This is what most accounts have. It gives the principal, the models, the Regions and the source
addresses — and no tokens and no content. `ips` is the field the invocation log does not carry and
is often the fastest route to "this is not our workload": an application calls from a known egress
range, and a resold credential does not.

#### Query 3 — Inspect: what the credential is, and what else it can do

```bash
PRINCIPAL="<caller-arn-from-Query-2>"

if echo "$PRINCIPAL" | grep -q ":user/"; then
  U=$(echo "$PRINCIPAL" | awk -F'/' '{print $NF}')       # user ARN: name = last segment
  echo "== IAM user $U =="
  aws iam list-access-keys --user-name "$U" --output json | \
    jq -r '.AccessKeyMetadata[] | "key=\(.AccessKeyId) status=\(.Status) created=\(.CreateDate)"'
  aws iam list-attached-user-policies --user-name "$U" --output json | \
    jq -r '.AttachedPolicies[] | "attached: \(.PolicyName)"'
  aws iam list-user-policies --user-name "$U" --output json | jq -r '.PolicyNames[] | "inline: \(.)"'
elif echo "$PRINCIPAL" | grep -q ":assumed-role/"; then
  R=$(echo "$PRINCIPAL" | awk -F'/' '{print $2}')        # role ARN: name = 2nd segment
  echo "== IAM role $R =="
  aws iam get-role --role-name "$R" --output json | jq '.Role.AssumeRolePolicyDocument'
  aws iam list-attached-role-policies --role-name "$R" --output json | \
    jq -r '.AttachedPolicies[] | "attached: \(.PolicyName)"'
else
  echo "[i] $PRINCIPAL is neither an IAM user nor an assumed-role — root or federated"
fi

echo
echo "== which models are enabled in this account, and when access was granted =="
aws bedrock list-foundation-models --region "$REGION" --output json 2>/dev/null | \
  jq -r '.modelSummaries[] | select(.modelLifecycle.status == "ACTIVE") | .modelId' | head -20
```

A credential that reaches Bedrock usually reaches other things. The attached policies say what else
to worry about, and an access key created shortly before the first invocation is a different
incident — persistence rather than a leaked key.

#### Query 4 — Quantify the spend

```bash
START=$(date -u -v-30d +%Y-%m-%d 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%d)
END=$(date -u +%Y-%m-%d)

aws ce get-cost-and-usage \
  --time-period Start="$START",End="$END" \
  --granularity DAILY --metrics UnblendedCost \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Bedrock"]}}' \
  --output json 2>/dev/null | \
  jq -r '.ResultsByTime[] | "\(.TimePeriod.Start)\t\(.Total.UnblendedCost.Amount) \(.Total.UnblendedCost.Unit)"' \
  || echo "[!] Cost Explorer not available to this principal — request it; without invocation logging this is the only spend figure"
```

Without invocation logging there are no token counts, so this is the only quantification available.
The daily series also dates the start of the abuse more precisely than a log query with a fixed
lookback.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

This is a credential-misuse incident with a service-specific triage in front of it. The triage
decides scope; the containment is ordinary.

> Run every command under the **break-glass responder credentials** from §1.

#### Step 1 — Revoke the credential

```bash
PRINCIPAL="<caller-arn-from-Query-2>"

if echo "$PRINCIPAL" | grep -q ":user/"; then
  U=$(echo "$PRINCIPAL" | awk -F'/' '{print $NF}')       # user ARN: name = last segment
  for K in $(aws iam list-access-keys --user-name "$U" --output json | jq -r '.AccessKeyMetadata[].AccessKeyId'); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive \
      && echo "[OK] deactivated $K"
  done
  aws iam put-user-policy --user-name "$U" --policy-name IR-Deny-All \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
elif echo "$PRINCIPAL" | grep -q ":assumed-role/"; then
  R=$(echo "$PRINCIPAL" | awk -F'/' '{print $2}')        # role ARN: name = 2nd segment
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$R" --policy-name AWSRevokeOlderSessions \
    --policy-document file:///tmp/revoke.json \
    && echo "[OK] sessions issued before now denied on $R"
  echo "[!] If the role is assumable by something the attacker still controls, they simply assume"
  echo "    it again. Check the trust policy from Query 3 before treating this as containment."
else
  echo "[i] $PRINCIPAL is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

#### Step 2 — Establish whether the credential leaked or was minted

Query 3's key creation dates decide this. A key created long before the abuse and used from a new
address is a leaked credential — the response ends with rotation. A key created shortly before the
first invocation is **persistence**, which means the attacker already had access to create it and
the incident is much larger than Bedrock.

#### Step 3 — Cap the exposure that remains

Bedrock has no per-principal spend limit, so a credential that survives revocation for any reason
keeps costing. The available levers are removing the permission and, where the workload allows,
restricting `bedrock:InvokeModel` to specific model ARNs — which turns unrestricted access into a
small enumerated set and makes the model-breadth rule far harder to trip legitimately.

#### Step 4 — Record what cannot be recovered

If invocation logging was not enabled, the prompts and responses for this period do not exist and
never will. State that explicitly in the incident: what was generated with the account's models is
unknowable, which matters if the concern is content produced in the organisation's name rather than
the cost.

---

## 4. Eradication

### Remove Attacker Access

#### Find where the credential leaked from

A repository, a build log, a container image layer, an environment file in an artifact. The
credential reached the attacker somehow, and rotating without finding the source means rotating
again shortly.

#### Right-size the Bedrock permission

`bedrock:InvokeModel` on `*` grants every model in every Region the account has enabled. Scoping it
to the model ARNs a workload actually uses is the single most effective control here, and it makes
the model-breadth detection far more precise as a side effect.

#### Enable invocation logging if it was not enabled

This is the item that determines what the next incident looks like. It cannot be applied
retroactively, and the S3 destination for large data must be configured or bodies over 100 KB have
nowhere to go.

#### Remove emergency policies once clean

Delete `IR-Deny-All` and `AWSRevokeOlderSessions` once the principal is rebuilt or retired.

---

## 5. Recovery

### Restore Clean State

#### Verify invocation logging is on, in every Region in use

```bash
for REGION in us-east-1 eu-west-1; do
  aws bedrock get-model-invocation-logging-configuration --region "$REGION" --output json 2>/dev/null | \
    jq -r --arg r "$REGION" '.loggingConfig |
      if . == null then "[FAIL] \($r) model invocation logging NOT configured"
      else "[OK]   \($r) logging on — s3=\(.s3Config.bucketName // "-") cw=\(.cloudWatchConfig.logGroupName // "-") text=\(.textDataDeliveryEnabled) image=\(.imageDataDeliveryEnabled) embedding=\(.embeddingDataDeliveryEnabled)" end' \
    || echo "[FAIL] $REGION could not read the logging configuration"
done
echo "[i] A modality set to false is a class of invocation whose body is never recorded."
```

#### Verify no principal has unrestricted model access

```bash
for P in $(aws iam list-policies --scope Local --output json | jq -r '.Policies[].Arn'); do
  V=$(aws iam get-policy --policy-arn "$P" --output json | jq -r '.Policy.DefaultVersionId')
  aws iam get-policy-version --policy-arn "$P" --version-id "$V" --output json | \
    jq -e '.PolicyVersion.Document.Statement
      | (if type == "object" then [.] else . end)
      | map(select(.Effect == "Allow"))
      | map(select((.Action // []) | (if type == "string" then [.] else . end)
            | any(. == "*" or . == "bedrock:*" or . == "bedrock:InvokeModel")))
      | map(select((.Resource // "*") | (if type == "string" then [.] else . end) | any(. == "*")))
      | length > 0' >/dev/null 2>&1 && echo "[!] $P allows bedrock:InvokeModel on *"
done
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire at high on:"
echo "  one identity.arn invoking 6 distinct modelId values within 6 hours"
echo "  (a handful of calls — this fires long before any cost or volume threshold)"
echo "and MUST fire on:"
echo "  an invocation with region=ap-southeast-2 when only us-east-1 and eu-west-1 are expected"
echo "The rule MUST NOT fire on:"
echo "  2,000 invocations of ONE model by a batch pipeline on the exclusion list"
echo "and note the rule MUST NOT use requestMetadata for grouping or allowlisting —"
echo "  AWS documents it as the only caller-supplied field in the record."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A credential could invoke every model in every enabled Region | `bedrock:InvokeModel` granted on `*` rather than on specific model ARNs |
| The abuse was found by the bill | No Bedrock-scoped cost alarm, and no detection on invocation behaviour |
| Prompts and responses could not be reviewed | Model invocation logging was off — it is disabled by default and cannot be applied retroactively |
| A new Region went unnoticed | Monitoring was scoped to the Regions in use, which is where the workload is and not where an attacker goes |
| The credential's leak point was unknown | No secret scanning on repositories, build logs or image layers |

### Recommended Guardrails

**Restrict model invocation by Region and by principal**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream",
             "bedrock:Converse", "bedrock:ConverseStream"],
  "Resource": "*",
  "Condition": { "StringNotEquals": { "aws:RequestedRegion": ["us-east-1", "eu-west-1"] } }
}
```

**Protect the invocation logging configuration**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["bedrock:DeleteModelInvocationLoggingConfiguration",
             "bedrock:PutModelInvocationLoggingConfiguration"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Enable model invocation logging before it is needed, with an S3 destination for large data and
  every relevant modality selected. It is the one control here that cannot be applied after the
  fact.
- Scope `bedrock:InvokeModel` to the model ARNs a workload uses. It removes the exploration surface
  and makes the breadth detection far more precise.
- Put a cost anomaly detector on Bedrock specifically. Its spend is small enough to hide inside an
  account-wide threshold and large enough to matter.
- Scan repositories, build logs and image layers for credentials. The leak is upstream of everything
  in this playbook.

**Detection improvements**
- Alert on model **breadth** before volume. Breadth fires within a handful of calls; volume fires
  once the abuse is expensive.
- Alert on Region as a one-shot with no threshold. Model access is per-Region, so an unused Region
  is both where an attacker goes and where nobody watches the bill.
- Never group or allowlist on `requestMetadata`. AWS documents it as the only caller-supplied field
  in the record, which makes it attacker-controlled in exactly this scenario.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1496 — Resource Hijacking |
| MITRE tactic | Impact (TA0040) |
| Primary API | `bedrock:InvokeModel`, `InvokeModelWithResponseStream`, `Converse`, `ConverseStream` |
| Event source | Bedrock model invocation logs (**off by default**); `bedrock-runtime.amazonaws.com` data events in CloudTrail |
| Key discriminator | Distinct `modelId` count per `identity.arn` — a workload uses one model or a small fixed set, an explored credential is tried against everything reachable |
| Ground-truth signal | The invocation records themselves, with `inputTokenCount` and `outputTokenCount` for spend. Without invocation logging, Cost Explorer is the only quantification |
| "Was it used" pivot | Not applicable — the invocations **are** the abuse. The equivalent question is what else the credential could reach, which is Query 3 |
| Blast radius | The uncapped cost, plus whatever else the credential permits — and anything generated in the organisation's name, which is unknowable without invocation logging |
| Error strings | `AccessDeniedException` on a model the principal cannot reach, and `ValidationException` on a model not enabled in the Region — both covered in `../bedrock.discovery.high-number-of-invocation-errors/` |

**MITRE mapping note:** the source entry maps to nothing, and carries no detection logic at all —
it is a CloudWatch metric building block. `T1496 — Resource Hijacking` describes the outcome:
compute consumed at the owner's expense. `T1526 — Cloud Service Discovery` covers the model-breadth
rule, which observes enumeration rather than consumption, and `T1078.004 — Valid Accounts: Cloud
Accounts` the unused-Region rule. All verified live 2026-08-30.

### Residual Risk

If model invocation logging was not enabled, the prompts and responses for the entire period do not
exist and cannot be recovered — so what was generated using the organisation's models is unknowable,
which matters most where the concern is content produced in its name rather than the cost. Token
counts are unavailable for the same reason, leaving Cost Explorer as the only measure. Invocations
made through endpoints other than `bedrock-runtime` are documented by AWS as not captured by
invocation logging at all. And revoking the credential ends this use of it and not the leak: unless
the source is found, the next credential follows the same path.
