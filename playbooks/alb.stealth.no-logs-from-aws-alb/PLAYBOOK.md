# IR Playbook: Load Balancer Access Logging Disabled — `ModifyLoadBalancerAttributes` sets `access_logs.s3.enabled` to false

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment (the request-level record of everything reaching the application stops) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. Nothing is destroyed and nothing is accessed, which makes it easy to under-rate — but every `alb.*` detection reads from this source, and so does any WAF investigation that needs to correlate a blocked request with what the application actually received. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | Elastic Load Balancing, S3, IAM, AWS Config, CloudTrail |

**What the technique does:** three paths to one outcome. `ModifyLoadBalancerAttributes` sets
`access_logs.s3.enabled` to `false`. The destination bucket is deleted, or its policy replaced so
the ELB log-delivery principal can no longer write — and the attribute still reads `true` while
nothing lands. Or a load balancer is simply created and never given logging at all, because
**logging is off by default**.

**Why the usual reflexes miss it.** The reflex is an absence alert, and access logs are the worst
telemetry in this corpus to build one on. An idle load balancer writes *nothing* — there is no
`NODATA` record as there is in VPC flow logs — so silence is the ordinary state of anything
unused. AWS states outright that the logs are best-effort and *"not a complete accounting of all
requests"*, so the count is approximate in both directions. And because logging is off by default,
a load balancer that never logged is indistinguishable from one just silenced.

**Detection thesis:** move the detection to the control plane, where the act is recorded and
attributed. Treat the default-off state as its own finding via a creation-coverage rule. Keep
absence as a corroborator, grouped per load balancer, and never as the alert.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail management events for `elasticloadbalancing.amazonaws.com` and
  `s3.amazonaws.com`.** There is no logging-specific event source: access logging is an attribute,
  so the signal is `ModifyLoadBalancerAttributes`.
- **AWS Config recording `AWS::ElasticLoadBalancingV2::LoadBalancer`.** The only source that can
  answer "when did this change" once the trail's retention window has passed.
- **A scheduled `describe-load-balancer-attributes` snapshot across every load balancer and
  Region**, stored with history. This answers both "is it on now" and "has this one ever had it
  on" — neither of which any log carries.
- **A log destination bucket in a separate account**, with a bucket policy the workload account
  cannot modify. This separates the ability to stop logging from the ability to destroy what was
  already logged.

**Alerting (must be pre-configured)**
- **`ModifyLoadBalancerAttributes` setting `access_logs.s3.enabled` to `false` → P0**
- **`DeleteBucket` or `DeleteBucketPolicy` on a load balancer log destination → P0**
- **`PutBucketPolicy` or `PutLifecycleConfiguration` on a log destination bucket → P1**
- **`CreateLoadBalancer` with no attribute call enabling logging within minutes → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- The standard log destination bucket name and prefix, ready to paste — re-enabling logging during
  an incident from memory is how it gets pointed at the wrong bucket.

**Known IOC Baselines**
- Which roles legitimately modify load balancer attributes. This should be one infrastructure role.
- The complete inventory of load balancers with their logging state, from the scheduled snapshot.
  Without it, "which one stopped" is unanswerable after the fact.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ModifyLoadBalancerAttributes` with `access_logs.s3.enabled` = `false`, principal outside the provisioning allowlist | CloudTrail (`elasticloadbalancing`) | T1685.002 |
| P0 | `DeleteBucket` or `DeleteBucketPolicy` on a bucket used as a load balancer log destination | CloudTrail (`s3`) | T1685.002 |
| P1 | `PutBucketPolicy` or `PutLifecycleConfiguration` on a log destination bucket | CloudTrail (`s3`) | T1685.002 |
| P1 | `CreateLoadBalancer` with no `ModifyLoadBalancerAttributes` enabling logging within minutes | CloudTrail (`elasticloadbalancing`) | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A load balancer with `access_logs.s3.enabled` = `false` in the scheduled state sweep | `describe-load-balancer-attributes` | T1685.002 |
| P2 | A load balancer whose attribute reads `true` but whose destination has received no object in 24h | S3 inventory | T1685.002 |
| P3 | No access log entries for a specific load balancer for two hours — corroborating only, never the alert | ALB access logs (per load balancer) | T1685.002 |

### Detection Rule Quality Notes

The source rule is `_exists_:"elb"` counted over two hours with an empty `group_by`, so every row
below is auditable against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `group_by` is empty — the count is account-wide | Disabling logs on one load balancer among several changes the total by a fraction and the rule never fires. The blind spot scales with everything else still logging | Detect on `ModifyLoadBalancerAttributes`, which names the load balancer and the principal. Where absence is kept, group by load balancer |
| Absence used as the control on telemetry AWS calls a sample | *"Elastic Load Balancing logs requests on a best-effort basis. We recommend that you use access logs to understand the nature of the requests, not as a complete accounting of all requests."* Delivery is eventually consistent and *"the load balancer can deliver multiple logs for the same period"* — records can be missing **and** duplicated | The control-plane event is exact and attributed. Absence is demoted to a P3 corroborator with the approximation stated |
| No handling of the default-off state | *"Access logs is an optional feature... disabled by default."* A load balancer that never logged is indistinguishable from one just silenced, and the absence rule cannot tell them apart at all | `elb_created_without_logging` turns the default into an event, plus a state sweep that finds load balancers which never had logging |
| No coverage of destination tampering | Deleting the bucket or its policy stops delivery while the attribute still reads `true`. A check reading only the attribute is satisfied, and **there is no ELB-side error event** when delivery starts failing | Three S3 events shipped alongside, and a scheduled destination check in §5 because no event exists for the failure moment |
| Two-hour window on a service where silence is normal | An ALB with no requests writes nothing — there is no `NODATA` equivalent — so a quiet load balancer trips the rule and a busy one that just lost logging may not, if others cover the account total | Window kept only for the corroborating view, explicitly not treated as conclusive |
| Treats logging as a separate resource | There is no `DeleteAccessLog` API. Logging is a key/value pair inside an attributes list, so a rule reading a flat field matches nothing | Match `attributes.key` and `attributes.value`; the KQL uses `mv-apply` to prove the pair belongs to one array element |

**Recommended detection — the three control-plane paths, including the default nobody set.**

```yaml
# Application Load Balancer access logging disabled (T1685.002)
#
# AN ABSENCE ALERT'S INPUT IS WHAT THE ATTACKER REMOVED, AND FOR THIS SERVICE AWS SAYS THE INPUT
# WAS NEVER RELIABLE. The source rule counts records where the `elb` field exists, fewer than one
# in two hours, grouped by nothing. Four properties of ALB access logs, each documented, make that
# unusable:
#
#   1. group_by IS EMPTY. The count is account-wide, so disabling access logs on ONE load balancer
#      in an account with several changes the total by a fraction and the rule never fires. The
#      blind spot scales with everything else still logging.
#   2. AWS STATES THE LOGS ARE A SAMPLE. "Elastic Load Balancing logs requests on a best-effort
#      basis. We recommend that you use access logs to understand the nature of the requests, not
#      as a complete accounting of all requests." A count over a best-effort sample is a lower
#      bound with no published error, in either direction.
#   3. ACCESS LOGS ARE DISABLED BY DEFAULT. "Access logs is an optional feature of Elastic Load
#      Balancing that is disabled by default." So a load balancer that has NEVER logged is
#      indistinguishable from one whose logging was just turned off — and only one of those is an
#      incident.
#   4. A QUIET LOAD BALANCER PRODUCES NOTHING AT ALL. Unlike VPC flow logs, which emit a NODATA
#      record for an idle interface, an ALB with no requests writes no entries. Silence is the
#      normal state of a load balancer nobody is using, so absence carries even less information
#      here than it does there.
#
# THE AUTHORITATIVE SIGNAL IS ModifyLoadBalancerAttributes. Access logging is a load balancer
# ATTRIBUTE, not a separate resource, so there is no DeleteAccessLog API to watch — turning it off
# is a key/value pair inside an attributes list. That nesting is why a rule reading a flat field
# matches nothing, and it is the shape the first rule below is built around.
title: Load balancer access logging disabled
id: 3d81f0a6-47c2-4b95-8e13-5a70cd29b64f
name: elb_access_logging_disabled
status: experimental
description: >-
  ModifyLoadBalancerAttributes set access_logs.s3.enabled to false. This is the event the absence
  rule can only infer, recorded directly and attributed to a principal, and it fires whether or not
  other load balancers in the account keep logging. Note the shape — attributes arrive as a list of
  key/value pairs, so the key and the value are separate fields inside the same array element and a
  rule reading requestParameters.enabled matches nothing.
references:
  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'elasticloadbalancing.amazonaws.com'
    eventName: 'ModifyLoadBalancerAttributes'
  success:
    errorCode: null
  logging_key:
    requestParameters.attributes.key:
      - 'access_logs.s3.enabled'
      - 'connection_logs.s3.enabled'
  disabled_value:
    requestParameters.attributes.value: 'false'
  # POPULATE BEFORE DEPLOYING with the infrastructure-as-code roles that own load balancer
  # attributes. An empty list reports every change once, which is how the list is built.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and logging_key and disabled_value and not known_provisioners
falsepositives:
  - >-
    A load balancer being decommissioned, or moved to the newer CloudWatch Logs delivery path.
    Both are real and both should be visible — a disable with no corresponding enable elsewhere is
    the finding.
  - >-
    The key and value are matched as two fields in one block, which means they are ANDed across
    the whole attributes ARRAY rather than proven to belong to the same element. A request that
    disables one attribute while setting another to false satisfies both. Deliberate superset;
    triage reads which pair it was, and the KQL expands the array to prove it.
level: high
---
title: Load balancer created or modified without access logging enabled
id: c9270b4e-5183-4fa6-b0d7-268e91c3a750
name: elb_created_without_logging
status: experimental
description: >-
  A load balancer was created and no attribute call enabled access logging. Because logging is off
  by default, a load balancer that was never configured for it looks exactly like one whose logging
  was removed — and neither produces a log entry to be missed. This rule turns the default into an
  event: it fires on creation, and the response is to confirm that a ModifyLoadBalancerAttributes
  enabling logs followed within minutes. It ships at medium because creation is routine; the
  finding is creation with no follow-up, which is a correlation a responder makes rather than a
  match this rule can express.
references:
  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'elasticloadbalancing.amazonaws.com'
    eventName: 'CreateLoadBalancer'
  success:
    errorCode: null
  condition: selection and success
falsepositives:
  - >-
    Every legitimate load balancer creation, until logging is enabled on it. This rule is a
    coverage check rather than a threat detection, and it should be routed accordingly — a queue,
    not a page.
level: medium
---
title: Load balancer access log destination removed or blocked
id: 71ea3c58-90d4-4b27-a6f1-4c0d8b52e937
name: elb_log_destination_tampered
status: experimental
description: >-
  The load balancer still has logging enabled and the bucket it writes to does not accept the
  writes. Deleting the destination bucket, or replacing its policy so the ELB log-delivery
  principal can no longer PutObject, stops delivery while ModifyLoadBalancerAttributes still shows
  access_logs.s3.enabled true — so a configuration check that reads only the attribute is
  satisfied. There is no ELB-side error event when delivery starts failing, which makes this the
  quietest of the three paths and the one that needs a scheduled check rather than an alert.
references:
  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html
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
      - 'PutBucketAcl'
      - 'PutLifecycleConfiguration'
  success:
    errorCode: null
  # ADJUST to the bucket naming used for load balancer log destinations in this estate.
  log_bucket:
    requestParameters.bucketName|contains:
      - 'elb-logs'
      - 'alb-logs'
      - 'lb-access-logs'
  condition: selection and success and log_bucket
falsepositives:
  - >-
    Ordinary lifecycle or policy maintenance on the log bucket. Worth reading every time: a
    lifecycle rule expiring objects after a short period destroys history as effectively as
    disabling logging, and it is the version of this that looks like cost control.
level: medium
```

What this set structurally cannot do: it cannot detect the moment delivery starts failing after a
bucket policy change, because nothing is called then — no event exists. Query 2 and the scheduled
destination check are the only things that find it.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log
> platform for busy windows. Load balancers are regional: run every query in every Region in use.

#### Query 1 — Reconstruct: every logging-attribute change, in order

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in ModifyLoadBalancerAttributes CreateLoadBalancer DeleteLoadBalancer; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       lb: (.requestParameters.loadBalancerArn // .requestParameters.name // "-"),
       logging: [(.requestParameters.attributes // [])[]
                 | select(.key | test("access_logs|connection_logs"))
                 | "\(.key)=\(.value)"],
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'sort_by(.time)'
```

The `logging` array is read from the attributes list rather than from a flat field, which is the
only shape that exists. An empty array on a `ModifyLoadBalancerAttributes` means the call changed
something else. A `CreateLoadBalancer` with no `ModifyLoadBalancerAttributes` following it within
minutes is a load balancer that has never logged — which is the default, and the reason that rule
exists.

#### Query 2 — Sweep: the logging state of every load balancer, which no log carries

```bash
REGION="us-east-1"

for ARN in $(aws elbv2 describe-load-balancers --region "$REGION" --output json | \
             jq -r '.LoadBalancers[].LoadBalancerArn'); do
  NAME="${ARN##*/}"
  aws elbv2 describe-load-balancer-attributes --load-balancer-arn "$ARN" --region "$REGION" \
    --output json | jq -r --arg n "$NAME" '
      (.Attributes | map({(.Key): .Value}) | add) as $a |
      "\(if ($a["access_logs.s3.enabled"] // "false") == "true" then "[OK]  " else "[FAIL]" end) \($n)  enabled=\($a["access_logs.s3.enabled"] // "false")  bucket=\($a["access_logs.s3.bucket"] // "-")  prefix=\($a["access_logs.s3.prefix"] // "-")"'
done
```

`[FAIL]` here covers both cases the log cannot separate — logging turned off, and logging never
turned on. Cross-reference against Query 1: a `[FAIL]` with a matching `access_logs.s3.enabled=false`
event is a disable; a `[FAIL]` with no such event is a load balancer nobody ever configured, which
is the more common finding and the one the absence rule was never going to surface.

#### Query 3 — Inspect: is the destination actually receiving objects

```bash
REGION="us-east-1"
BUCKET="<log-destination-bucket>"
PREFIX="<prefix>"

echo "== most recent objects delivered =="
aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "$PREFIX" --region "$REGION" \
  --query 'reverse(sort_by(Contents,&LastModified))[:5].[Key,LastModified,Size]' \
  --output text 2>/dev/null || echo "[FAIL] cannot list $BUCKET — deleted, or access denied"

echo
echo "== can the ELB log-delivery principal still write =="
aws s3api get-bucket-policy --bucket "$BUCKET" --region "$REGION" --output json 2>/dev/null | \
  jq -r '.Policy | fromjson | .Statement[]
    | select(.Effect == "Allow")
    | select((.Action | if type == "string" then [.] else . end) | any(test("PutObject|s3:\\*")))
    | "allow \(.Action) to \(.Principal | tostring)"' \
  || echo "[FAIL] no bucket policy — ELB log delivery requires one and will be failing"

echo
echo "== does a lifecycle rule expire the history =="
aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET" --region "$REGION" --output json 2>/dev/null | \
  jq -r '.Rules[] | select(.Status == "Enabled") | "rule=\(.ID) expiry=\(.Expiration.Days // "-") days prefix=\(.Filter.Prefix // "*")"' \
  || echo "[i] no lifecycle configuration — objects retained indefinitely"
```

This is the only way to find the quiet path. The attribute can read `true` while the bucket
rejects every write, and **no AWS event marks the moment that starts** — nothing is called. The
most recent object's timestamp is the real answer to "is logging working".

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | jq -s 'sort_by(.time)'
```

Disabling request logging is preparation, not an objective. Its value in an investigation is as a
timestamp that brackets whatever the same principal did next — and what they did before, since the
requests immediately preceding the disable are the last ones on record.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore recording first. Every minute without it is a minute of requests nobody will be able to
reconstruct, and unlike most telemetry there is no partial fallback — the entries simply do not
exist.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being investigated.

#### Step 1 — Re-enable access logging

```bash
REGION="us-east-1"
LB_ARN="<load-balancer-arn>"
BUCKET="<log-destination-bucket>"
PREFIX="<prefix>"

aws elbv2 modify-load-balancer-attributes --load-balancer-arn "$LB_ARN" --region "$REGION" \
  --attributes Key=access_logs.s3.enabled,Value=true \
               Key=access_logs.s3.bucket,Value="$BUCKET" \
               Key=access_logs.s3.prefix,Value="$PREFIX" \
  --output json | jq -r '
    (.Attributes | map({(.Key): .Value}) | add) as $a |
    if ($a["access_logs.s3.enabled"] // "false") == "true"
      then "[OK] access logging enabled -> \($a["access_logs.s3.bucket"])/\($a["access_logs.s3.prefix"] // "")"
      else "[FAIL] attribute did not take — check the bucket policy permits ELB log delivery" end'
```

The bucket and prefix are set explicitly rather than assumed: re-enabling with a stale or empty
bucket value produces a load balancer that reports `enabled=true` and delivers nowhere, which is
the exact state §2 describes as the quiet path.

#### Step 2 — Prove objects are actually landing

```bash
REGION="us-east-1"
BUCKET="<log-destination-bucket>"
PREFIX="<prefix>"

echo "[i] Delivery is every 5 minutes per load balancer node and eventually consistent."
echo "    Wait at least 10 minutes, send some traffic, then confirm a NEW object appears."
LATEST=$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "$PREFIX" --region "$REGION" \
  --query 'reverse(sort_by(Contents,&LastModified))[0].LastModified' --output text 2>/dev/null)
echo "[i] most recent object: ${LATEST:-none}"
echo "[!] 'enabled=true' is not delivery. An object with a timestamp after the re-enable is."
```

#### Step 3 — Size the gap and mark it in the record

The window from the disable in Query 1 to the confirmed delivery in Step 2 has no request-level
record and never will. Write the exact interval into the incident, and mark every conclusion about
that period as unsupported — **including negative ones**. This is the step people skip, and it is
what stops a later reviewer reading an empty query result as an all-clear.

#### Step 4 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')      # user ARN: name = last segment
  aws iam put-user-policy --user-name "$U" --policy-name IR-Deny-All \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')       # role ARN: name = 2nd segment
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$R" --policy-name AWSRevokeOlderSessions \
    --policy-document file:///tmp/revoke.json
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

---

## 4. Eradication

### Remove Attacker Access

#### Enable logging on every load balancer that has never had it

Query 2's `[FAIL]` lines that have no matching disable event in Query 1 are load balancers nobody
ever configured. They are usually the majority, and they are a coverage gap rather than an
incident — but they are the reason the absence rule could never have worked, and closing them is
the durable fix.

#### Repair the destination

If Query 3 showed no recent objects or a missing bucket policy, the delivery path is broken
independently of the attribute. Restore the policy granting the ELB log-delivery principal
`s3:PutObject` on the prefix, and re-check that a new object appears.

#### Right-size who can change load balancer attributes

`elasticloadbalancing:ModifyLoadBalancerAttributes` belongs to an infrastructure role, not to
application deploy credentials. Query 4's principal is the starting point.

#### Remove emergency policies once clean

Delete `IR-Deny-All` and `AWSRevokeOlderSessions` once the principal is rebuilt or cleared.

---

## 5. Recovery

### Restore Clean State

#### Verify every load balancer in every Region is logging

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  for ARN in $(aws elbv2 describe-load-balancers --region "$REGION" --output json 2>/dev/null | \
               jq -r '.LoadBalancers[].LoadBalancerArn'); do
    ON=$(aws elbv2 describe-load-balancer-attributes --load-balancer-arn "$ARN" --region "$REGION" \
      --output json | jq -r '(.Attributes | map({(.Key): .Value}) | add)["access_logs.s3.enabled"] // "false"')
    [ "$ON" = "true" ] || echo "[FAIL] $REGION ${ARN##*/} access logging OFF"
  done
done
echo "[i] no [FAIL] lines above means every load balancer in every Region has logging enabled"
```

#### Verify delivery, not configuration

Re-run Query 3 for each destination bucket. An attribute reading `true` with no object newer than
the re-enable is the failure this playbook exists to catch, and it is invisible to the attribute
check above.

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  eventSource=elasticloadbalancing.amazonaws.com  eventName=ModifyLoadBalancerAttributes"
echo "  requestParameters.attributes[] containing {key: access_logs.s3.enabled, value: false}"
echo "  by an ARN outside known_provisioners"
echo "and MUST fire on the case the source rule cannot represent:"
echo "  eventName=CreateLoadBalancer with no ModifyLoadBalancerAttributes following"
echo "  (logging is OFF by default; nothing was ever recorded, and nothing went missing)"
echo "The rule MUST NOT fire on:"
echo "  ModifyLoadBalancerAttributes setting idle_timeout.timeout_seconds"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| Access logging stopped and the alert did not fire | The rule counted records account-wide, so one load balancer's silence was absorbed by the others |
| Load balancers existed with logging never enabled | Logging is off by default and no provisioning check enforced it |
| A broken delivery path was invisible | The attribute reads `true` while the bucket rejects writes, and no AWS event marks the moment delivery starts failing |
| The gap could not be sized afterwards | No scheduled snapshot of load balancer logging state existed, so "what did we lose" had no baseline |
| Absence was treated as a reliable signal | AWS documents these logs as best-effort and recommends against using them as a complete accounting |

### Recommended Guardrails

**Fence load balancer attributes and the log destination**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["elasticloadbalancing:ModifyLoadBalancerAttributes",
             "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketPolicy"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Enable access logging in the provisioning module, so no load balancer can be created without it.
  The default is off, and a default nobody changes is the most common finding in this service.
- Deliver to a bucket in a separate account whose policy the workload account cannot modify. This
  separates the ability to stop logging from the ability to destroy what was already written.
- Record `AWS::ElasticLoadBalancingV2::LoadBalancer` in AWS Config, so the attribute has a history
  beyond the CloudTrail retention window.
- Set the bucket's lifecycle deliberately. An expiry rule destroys history exactly as effectively
  as disabling logging, and it looks like cost control on review.

**Detection improvements**
- Alert on the control-plane event, not on absence. For this telemetry AWS has said in writing
  that absence is unreliable.
- Alert on `CreateLoadBalancer` as a coverage check. The default-off state produces no absence
  signal because there was never anything to be absent.
- Check the destination, not the attribute, on a schedule. The attribute is a statement of intent;
  the newest object's timestamp is the fact.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log |
| MITRE tactic | Defense Impairment (TA0112) |
| Primary API | `elasticloadbalancing:ModifyLoadBalancerAttributes` with `access_logs.s3.enabled=false`; `s3:DeleteBucketPolicy` on the destination |
| Event source | elasticloadbalancing.amazonaws.com and s3.amazonaws.com — there is no logging-specific event source, because logging is an attribute |
| Key discriminator | The `access_logs.s3.enabled` key carrying `false` inside the `attributes` array of a successful call |
| Ground-truth signal | `describe-load-balancer-attributes` for the state, and the newest object in the destination prefix for whether delivery actually works |
| "Was it used" pivot | The gap between the disable and the restoration, cross-referenced against what the same principal did in that window |
| Blast radius | Every `alb.*` detection, plus any WAF investigation that needs to correlate a blocked request against what the application received |
| Error strings | None on the attribute call itself. A broken delivery path produces **no error event at all** — its only symptom is the absence of new objects |

**MITRE mapping note:** `T1685.002` is the
correct current identifier. Verified live 2026-08-30.

### Residual Risk

The window between the disable and the restoration has no request-level record and never will, so
no conclusion about that period is supportable — including "nothing happened". Because AWS
documents these logs as best-effort and *"not a complete accounting of all requests"*, even the
periods that **are** covered are a sample of unknown completeness, and duplicate delivery means a
count can be high as well as low. Any load balancer found with logging never enabled has no
history at all, not merely a gap. And if the destination bucket was deleted rather than
reconfigured, the objects already written are gone with it — re-enabling logging restores the
future, not the past.
