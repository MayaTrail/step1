# IR Playbook: ECS Service Scaled to a High Desired Count — Compute Hijacking via `ecs:UpdateService`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Resource hijacking (a service's desired task count is raised so ECS runs and continuously replaces a large number of containers, billed to the account that owns the cluster) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, against the source's **P3**. The cost accrues per minute and is unrecoverable once incurred; the compute is durable because ECS replaces every task that stops, so nothing short of resetting `desiredCount` reduces it; and if the same principal also re-pointed the task definition, the multiplied workload is the actor's image rather than yours. The denied variant is **Medium** — an intent signal with no compute behind it, which is where the source rule's missing success filter silently put both |
| MITRE Tactics | Impact (TA0040) |
| MITRE Techniques | T1496.001 (primary), T1496 (parent) — both verified live 2026-08-29 |
| Services in Scope | ECS, ECR (or wherever the image comes from), CloudWatch (`AWS/ECS` metrics, billing alarms), Cost Explorer, EC2 / Fargate capacity and its quotas, IAM, CloudTrail, Organizations (SCP) |

**What the technique does:** the actor calls `UpdateService` with `cluster`, `service` and a large
`desiredCount`. ECS immediately begins placing that many tasks and thereafter maintains the
number, replacing any that stop. Optionally the same call carries a new `taskDefinition`, in
which case the tasks that get multiplied are running an image the actor supplied. Nothing is
created, nothing is deleted, and no configuration is weakened — the account simply starts
running and paying for a great deal more compute. The usual motive is cryptomining.

**Detection thesis.** The discriminator is **the magnitude of the change relative to the
service's own baseline**, not the call: `UpdateService` is the most routine write in ECS and
every deployment is one. The source rule attempts a magnitude test and gets it wrong three ways
— a `.keyword` subfield on a field AWS documents as an integer, an anchored regex that means
"exactly four digits" and so is blind below 1,000, and no success filter at all.

> The opposite direction of the same field — `desiredCount: 0` — is the destructive setting and
> the mandatory precursor to service and cluster deletion. This playbook deliberately does not
> cover it; `../ecs.stealth.service-is-deleted/` and `../ecs.stealth.cluster-is-deleted/` do.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing ECS **management** events — on by default, so
  `lookup-events` returns `UpdateService` and `RegisterTaskDefinition`
- `requestParameters.desiredCount` is **top-level** and an **integer**, and it is **optional**:
  an `UpdateService` that only swaps the task definition omits it entirely. Reading a missing
  value as `0` manufactures scale-to-zero events out of ordinary deployments — test for absence
  before comparing. `.cluster`, `.service` and `.taskDefinition` are all **caller-typed** (short
  name, `family:revision` or ARN). The response is **nested** at `responseElements.service.*`
- **`responseElements.service.runningCount` is the count at the moment of the call**, before any
  new task starts. It is never the answer to "how much actually ran"
- CloudWatch `AWS/ECS` `CPUUtilization` and `MemoryUtilization` on the `ClusterName` +
  `ServiceName` dimensions — sent in 1-minute periods, and ECS states the statistics are
  *"recorded for a period of two weeks"*. This is the only measure of what the extra tasks did,
  and the window closes. Pair it with a **billing anomaly alarm**: capacity, not `desiredCount`,
  decides the outcome, and the bill survives every quota interaction
- The account's **Fargate On-Demand vCPU resource count** quota and its current value — the
  default is 6 per Region and AWS raises it automatically with usage, so what a `desiredCount` of
  1,000 produces differs between two accounts with identical events
- A baseline of the **highest legitimate `desiredCount`** each service reaches. The deployed
  threshold is that number plus headroom; the 50 in §2 is a starting point, not a measurement

**Alerting (must be pre-configured)**
- **`UpdateService` succeeding with `desiredCount` at or above the account's baseline threshold → P0**
- **`RegisterTaskDefinition` then a high-`desiredCount` `UpdateService` by the same principal within 60 minutes → P0**
- **One principal raising `desiredCount` high on three or more distinct services within 30 minutes → P1**
- **`AWS/ECS` `CPUUtilization` sustained near 100% on a service with no corresponding deployment → P1**

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
| P0 | `UpdateService` succeeding with `desiredCount` ≥ the account's baseline threshold (50 as a starting point) | CloudTrail (management) | T1496.001 |
| P0 | `RegisterTaskDefinition` then a high-`desiredCount` `UpdateService` by the same principal within 60 minutes — the multiplied image is the actor's | CloudTrail (management) | T1496.001 |
| P1 | One principal raising `desiredCount` high on three or more distinct services within 30 minutes | CloudTrail (management) | T1496.001 |
| P1 | `AWS/ECS` `CPUUtilization` sustained near 100% on a `ClusterName`+`ServiceName` pair with no matching deployment | CloudWatch `AWS/ECS` | T1496.001 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `UpdateService` with a high `desiredCount` **denied** — intent with no compute behind it, and a map of where the principal's permissions end | CloudTrail (management) | T1496.001 |
| P2 | A day-over-day cost increase on ECS or Fargate with no corresponding change record | Cost Explorer / billing alarm | T1496.001 |
| P3 | `UpdateService` raising `desiredCount` by a large **ratio** but below the absolute floor — a 2 → 40 move on a small service | CloudTrail (management) | T1496.001 |

### Detection Rule Quality Notes

The source rule is the only one of the five that attempts a magnitude test, and it is the only
one with no success filter.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `.keyword` subfield on a field AWS documents as **Type: Integer** | A `.keyword` subfield exists only where the pipeline maps the field as a string. CloudTrail serialises `desiredCount` as a JSON number, so under a numeric mapping the clause matches nothing and the rule never fires | Compare numerically — `requestParameters.desiredCount|gte: <threshold>` |
| Anchored regex `/\d{4}/` means **exactly four digits** | Coverage is `[1000, 5000]` — the upper bound because AWS caps "Tasks per service" at 5,000, not adjustable. A service moved from 2 tasks to 500 is a 250× escalation and does not fire | Threshold at the account's own baseline plus headroom, and add the ratio test |
| **No success filter** — the only rule in the set missing it | A denied `UpdateService` raises the same alert at the same priority as a successful one, so permission probing and a live mining fleet arrive in the same queue | Split: successful at `high`, denied at `medium`, so the denial stays visible without being counted as compute |
| Blind to `desiredCount: 0` | The destructive direction of the same field — and the mandatory precursor to `DeleteService` and `DeleteCluster` — cannot be seen by a rule requiring four digits | Covered by the scale-to-zero base rules in `../ecs.stealth.service-is-deleted/` and `../ecs.stealth.cluster-is-deleted/` |

**Recommended detection — a service scaled to a high desired task count.**

```yaml
# ECS Service Scaled to a High Desired Count (T1496.001 / T1496)
#
# THE DISCRIMINATOR IS THE MAGNITUDE, NOT THE CALL. `UpdateService` is the most routine write
# in ECS: every deployment, every autoscaling action and every rollback is one. What separates
# resource hijacking from operations is how far the number moved, so the rule has to be a
# comparison and the source rule's attempt at one is where it breaks.
#
# WHAT THE SOURCE RULE DOES NOT DO. Its query is
# `requestParameters.desiredCount.keyword:/\d{4}/`, and there are three separate defects.
#
#   1. A `.keyword` subfield exists only where the ingest pipeline maps a field as a string.
#      AWS documents `desiredCount` as Type: Integer, and CloudTrail serialises it as a JSON
#      NUMBER. If the pipeline maps it numerically there is no `.keyword` subfield and the
#      clause matches nothing at all. Whether this rule can fire therefore depends on an
#      ingest-mapping detail rather than on the event - which is a defect regardless of which
#      way the mapping happens to fall.
#   2. A Lucene `regexp` term is ANCHORED - it must match the whole term, not a substring - so
#      `/\d{4}/` means EXACTLY four digits. The rule fires on 1000-9999 and is silent on
#      everything below 1000. A service moved from 2 tasks to 500 is a 250x escalation and
#      does not fire. And because AWS caps "Tasks per service" at 5,000 (not adjustable), the
#      band above 5,000 is unreachable anyway: the rule's real coverage is [1000, 5000], and
#      its blind spot is [baseline+1, 999].
#   3. It has NO SUCCESS FILTER. Alone among the five ECS rules in this set, it omits
#      `NOT _exists_:errorCode`, so a DENIED UpdateService with a high count fires the same
#      alert as a successful one. A principal probing its permissions and an actor who
#      actually scaled a mining fleet arrive in the same queue at the same priority.
#
# It is also blind in the other direction. `desiredCount: 0` is the destructive setting and the
# mandatory precursor to DeleteService and DeleteCluster, and a rule that requires four digits
# cannot see a zero. That gap is covered by ../../ecs.stealth.service-is-deleted/ and
# ../../ecs.stealth.cluster-is-deleted/, both of which ship a scale-to-zero base rule.
#
# THRESHOLD BASIS FOR THE 50 BELOW - stated because a number without a basis is an invented
# number. Three documented figures bound it. AWS caps "Tasks per service" at 5,000 and the
# quota is NOT adjustable, so 5,000 is the hard ceiling and any threshold near it is a ceiling
# test rather than a detection. The Fargate "On-Demand vCPU resource count" quota defaults to
# 6 per Region (adjustable, and AWS raises it automatically with usage), and the smallest
# Fargate task is 0.25 vCPU - so a default-quota account can actually run about 24 tasks, and
# a desiredCount of 1,000 on such an account never materialises. That last point matters more
# than it looks: the CloudTrail event is the detection surface, NOT the resulting task count,
# because the intent is fully expressed by the API call even when the capacity refuses it.
# Fifty sits above what a default-quota Fargate account can materialise and two orders of
# magnitude below the service quota, which puts it inside the band the source rule cannot see.
# It is a STARTING POINT for an account that has never measured. The correct deployed value is
# the highest legitimate desiredCount observed in this account plus headroom, and where the
# baseline is high the ratio test in kql_t1496_001.kql is the better instrument - Sigma cannot
# compare an event against the service's own previous value.
title: ECS service scaled to a high desired task count
id: 781eabd9-3e58-44bd-8326-26c0673e524d
name: ecs_service_scaled_high
status: experimental
description: >-
  A service's desired task count was raised to 50 or more. ECS then keeps that many tasks
  running and replaces any that stop, so the compute is durable and stopping individual tasks
  does not reduce it. The usual motive is cryptomining, billed to the account that owns the
  cluster.
references:
  - https://attack.mitre.org/techniques/T1496/001/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateService.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/general/latest/gr/ecs-service.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1496
  - attack.t1496.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecs.amazonaws.com'
    eventName: 'UpdateService'
  # RE-BASELINE BEFORE DEPLOYING. 50 is a starting point derived from AWS quotas, not from an
  # observed count - see the threshold basis in the header. desiredCount is an INTEGER in the
  # event, so this is a numeric comparison, not a string or regex match.
  magnitude:
    requestParameters.desiredCount|gte: 50
  success:
    errorCode: null
  condition: selection and magnitude and success
falsepositives:
  - >-
    A genuine scale-out event on a large service — a load test, a traffic surge, a regional
    failover. All are traceable to a change record; if they are not, that is the finding.
level: high
---
# The source rule has no success filter, which conflates a denied attempt with a completed one.
# Splitting them keeps the denial VISIBLE rather than discarding it, at a level that says
# corroboration is needed: a burst of these across services is permission probing and belongs
# in triage, but it is not compute that is running and being billed.
title: ECS service scale-out to a high desired count denied
id: 3a1358b2-ab8a-42d5-a451-5c49df6aec75
name: ecs_service_scaled_high_denied
status: experimental
description: >-
  An attempt to raise a service's desired task count to 50 or more was refused. No compute was
  created; the value is as an intent signal and as a map of where the principal's permissions
  end.
references:
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/CommonErrors.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1496.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecs.amazonaws.com'
    eventName: 'UpdateService'
  magnitude:
    requestParameters.desiredCount|gte: 50
  # `errorCode: null` matches when the field is ABSENT, so "denied" is `not success` - never
  # `and not` against a value that is only present on failures.
  success:
    errorCode: null
  condition: selection and magnitude and not success
level: medium
---
# Base rule — sequence component only, not for direct alerting. Scaling a service runs whatever
# its CURRENT task definition says, so an actor who wants their own image scales a service they
# have first re-pointed. This is where the image is.
title: ECS task definition registered
id: 7eda96d8-70f6-429d-84ee-e535418b751e
name: ecs_task_definition_registered_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RegisterTaskDefinition.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1496.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecs.amazonaws.com'
    eventName: 'RegisterTaskDefinition'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
# Register-then-scale is the complete hijack: bring your own image, then multiply it. Scaling
# alone runs more of whatever the service was ALREADY running, which is a different and often
# less alarming event - a load test rather than a mining fleet. The pair is the one that says
# the compute being multiplied is the actor's.
#
# TIMESPAN BASIS. Sixty minutes. UpdateService with a new taskDefinition triggers a deployment
# and the scale-out can be issued in the same breath or after the deployment settles; an hour
# spans a slow rollout without spanning unrelated work.
title: ECS task definition registered and a service then scaled high by the same principal
id: 2bd89bd1-151c-4199-9d40-d75e35ed3865
status: experimental
description: >-
  One principal registered a task definition and then raised a service's desired count to 50 or
  more within the hour. The compute being multiplied is running an image that principal
  supplied, which is resource hijacking rather than a scale-out of existing work.
references:
  - https://attack.mitre.org/techniques/T1496/001/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1496.001
correlation:
  type: temporal_ordered
  rules:
    - ecs_task_definition_registered_bb
    - ecs_service_scaled_high
  group-by:
    - userIdentity.arn
  timespan: 60m
level: high
---
# Fan-out across SERVICES rather than volume of calls, which is why this counts distinct values
# rather than events: one principal issuing five UpdateService calls against a single service
# is a deployment retrying, while the same five spread across three services is someone
# consuming the account. `gte: 3` at the baseline, never `gt`, so a run that touches exactly
# three does not fall through. AWS permits 5,000 services per cluster, so the quota supplies no
# constraint and the threshold has to come from the shape of the work - re-baseline it against
# how many services your own change windows legitimately scale at once.
title: Multiple ECS services scaled high by one principal
id: 06e0e5ff-34a0-4f21-b0ca-e44c0e2b1285
status: experimental
description: >-
  One principal raised the desired task count of three or more distinct services to 50 or more
  inside thirty minutes. Each service maintains its own count independently, so every service
  in the group has to be scaled back separately and stopping tasks achieves nothing.
references:
  - https://docs.aws.amazon.com/general/latest/gr/ecs-service.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1496.001
correlation:
  type: value_count
  rules:
    - ecs_service_scaled_high
  group-by:
    - userIdentity.arn
  field: requestParameters.service
  timespan: 30m
  condition:
    gte: 3
level: high
```

The rule cannot compare an event against the service's **own** previous `desiredCount`, which is
the real discriminator: 50 is an incident on a service that normally runs 2 and routine on one
that normally runs 200. Sigma has no way to reference a prior event's value, so the deployable
rule carries an absolute floor and `detections/kql_t1496_001.kql` carries the ratio, treating a
first-seen service as **unknown** rather than as a baseline of zero.

---

### Key Investigation Queries

> ECS is regional — run these in the service's region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: how far the count moved, and whether the image moved with it

```bash
REGION="us-east-1"
RAW=$(for EV in UpdateService RegisterTaskDefinition; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region,"
  echo "    or missing cloudtrail:LookupEvents. This is NOT 'nothing was scaled'."
else
  # desiredCount is OPTIONAL - an UpdateService that only swaps the task definition omits it.
  # It is emitted as null here rather than defaulted to 0, because a 0 would read as a
  # scale-to-zero that never happened.
  # running_at_call is the count BEFORE the new tasks start; it is not the outcome.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "ecs.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller_arn: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     cluster: ((.requestParameters.cluster // "") | split("/") | last),
     service: ((.requestParameters.service // "") | split("/") | last),
     desired_requested: (if (.requestParameters | has("desiredCount"))
                         then .requestParameters.desiredCount else null end),
     desired_after: (.responseElements.service.desiredCount // null),
     running_at_call: (.responseElements.service.runningCount // null),
     task_family: ((.requestParameters.family //
                    ((.requestParameters.taskDefinition // "") | split("/") | last))
                   | split(":") | first),
     images: [(.requestParameters.containerDefinitions // [])[] | .image],
     forced_deploy: (.requestParameters.forceNewDeployment // null),
     exec_toggled: (.requestParameters.enableExecuteCommand // null),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.service, .time)'
fi
```

Read it per `service`, in time order, and compute the ratio by eye: the previous row's
`desired_after` against this row's `desired_requested` is the escalation, and it is far more
informative than the absolute number. Rows where `desired_requested` is `null` changed something
other than the count — do not read them as zero. A `RegisterTaskDefinition` from the same
`caller_arn` shortly before a scale-out on the same `task_family` is the complete hijack: the
`images` value is what the multiplied tasks are running. `error` values are attempts, not
consumption, and must be counted separately — the source rule conflates them and that is its
third defect. `exec_toggled` = `true` alongside a scale-out means interactive access was added at
the same time (`../ecs.initial-access.command-executed-inside-a-container/`). Record `cluster`,
`service`, `task_family`, `caller_arn` and `access_key` as IOCs.

#### Query 2 — Inspect what the event does not answer: how much compute actually ran

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; SERVICE="<service-from-Query-1>"
SCALED_AT="<iso8601-time-from-Query-1>"

# desiredCount is an INTENT. Capacity decides the outcome: on Fargate the On-Demand vCPU quota
# defaults to 6 per Region - about 24 tasks at the 0.25 vCPU minimum - so a desiredCount of
# 1,000 on a default-quota account never materialises. This is the only measure of what ran.
M=$(aws cloudwatch get-metric-statistics --namespace AWS/ECS --metric-name CPUUtilization \
      --dimensions Name=ClusterName,Value="$CLUSTER" Name=ServiceName,Value="$SERVICE" \
      --period 300 --statistics Average Maximum --region "$REGION" --output json \
      --start-time "$(date -u -d "$SCALED_AT -2 hours" +%Y-%m-%dT%H:%M:%SZ)" \
      --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)")
if [ -z "$M" ]; then
  echo "[!] INCONCLUSIVE - the CloudWatch call failed. How much compute ran is unknown, not zero."
else
  N=$(printf '%s' "$M" | jq '.Datapoints | length')
  if [ "$N" -eq 0 ]; then
    echo "[!] INCONCLUSIVE - no datapoints. Either the tasks never placed (check the Fargate"
    echo "    vCPU quota), or ECS metrics are unavailable for this service, or the two-week"
    echo "    retention has aged out. None of those is proof that nothing ran."
  else
    printf '%s' "$M" | jq -r '.Datapoints | sort_by(.Timestamp) |
      "[i] \(length) datapoints; peak CPUUtilization \(map(.Maximum) | max)%, " +
      "mean \((map(.Average) | add / length) | floor)% from \(first.Timestamp) to \(last.Timestamp)"'
  fi
fi

# What the service is set to RIGHT NOW. describe-services returns HTTP 200 with .services empty
# and a .failures reason of MISSING for a service that does not exist, exit code 0 - so an
# emptiness test comes before any comparison.
D=$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
      --region "$REGION" --output json)
if [ -z "$D" ] || [ "$(printf '%s' "$D" | jq '.services | length')" -eq 0 ]; then
  echo "[!] INCONCLUSIVE - no service description returned (a bad CLUSTER throws"
  echo "    ClusterNotFoundException; a missing SERVICE returns a MISSING failure inside a 200)"
else
  printf '%s' "$D" | jq -r '.services[0] |
    "[i] now: desired=\(.desiredCount) running=\(.runningCount) pending=\(.pendingCount) " +
    "taskDef=\(.taskDefinition) launch=\(.launchType // "capacity-provider")"'
fi
```

The metric block answers "how much did this cost", and its two `INCONCLUSIVE` branches matter as
much as its success branch: no datapoints is ambiguous between *the tasks never placed* and *the
metric is gone*, and neither is "nothing ran". A large `pending` with a small `running` is the
quota refusing the request — the intent was still fully expressed and the event is still the
incident. Compare `taskDef` against Query 1: if it changed alongside the count, treat the image
as hostile until proven otherwise.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="RegisterTaskDefinition UpdateService"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "ecs.amazonaws.com") |
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

**Reset `desiredCount` before stopping any task.** This ordering is not a preference: ECS
maintains the desired count and replaces every task that stops, so `stop-task` against a scaled
service produces a replacement within seconds and a responder who starts there will conclude
containment failed. Set the count back to its documented baseline first, confirm the tasks
drain, and then contain the principal.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Reset the desired count to its baseline and confirm it took

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; SERVICE="<service-from-Query-1>"
BASELINE="<the service's documented desiredCount, from IaC or the change record>"

case "$BASELINE" in
  ''|*[!0-9]*) echo "[FAIL] BASELINE must be a non-negative integer; got '$BASELINE'."
               echo "    Do NOT guess: setting it to 0 is an outage, and guessing high leaves"
               echo "    the hijacked capacity running."; exit 1;;
esac

OUT=$(aws ecs update-service --cluster "$CLUSTER" --service "$SERVICE" \
        --desired-count "$BASELINE" --region "$REGION" --output json)
if [ -z "$OUT" ]; then
  echo "[!] INCONCLUSIVE - update-service returned nothing; the count was NOT reset."
  echo "    Do not stop tasks: the scheduler will replace them."
else
  NEW=$(printf '%s' "$OUT" | jq -r '.service.desiredCount // empty')
  if [ "$NEW" = "$BASELINE" ]; then
    echo "[OK] desiredCount reset to $NEW; tasks will drain asynchronously"
  else
    echo "[FAIL] desiredCount reads '$NEW' after the call, not $BASELINE"
  fi
fi

# If the task definition was ALSO swapped, resetting the count leaves the actor's image
# running at the baseline size. Re-point the service at the known-good revision in the same
# containment window - a smaller mining fleet is still a mining fleet.
KNOWN_GOOD_TD="<family:revision from before the incident, from Query 1 or IaC>"
case "$KNOWN_GOOD_TD" in
  *:*) aws ecs update-service --cluster "$CLUSTER" --service "$SERVICE" \
         --task-definition "$KNOWN_GOOD_TD" --force-new-deployment \
         --region "$REGION" --output json | jq -r '.service.taskDefinition' ;;
  *)   echo "[i] no known-good task definition supplied - skipping the re-point. If Query 1"
       echo "    showed the definition changing alongside the count, this step is NOT optional.";;
esac
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ecs:UpdateService","ecs:CreateService","ecs:RunTask","ecs:StartTask","ecs:RegisterTaskDefinition","iam:PassRole"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyEcsScale" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyEcsScale" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied ECS scaling for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or"
     echo "    a service principal. Contain manually; neither branch above applies.";;
esac
```

`ecs:RunTask` is in the deny list because it is the same outcome by another route — one call
launches up to ten tasks, AWS's documented maximum for the `count` parameter, and a loop over it
reaches any scale without touching a service at all.

---

## 4. Eradication

### Remove Attacker Access

- **Every service the principal scaled is in scope**, not just the one that alerted. The
  `value_count` correlation's group is the work-list, and each service maintains its count
  independently — resetting one does nothing for the others.
- **Deregister the task definition revision** if a new one was registered as part of the
  incident, and confirm the service is not still pointing at it. A service left on the actor's
  revision at the baseline count is a smaller version of the same problem.
- **Check `RunTask` for the same period.** It launches up to ten tasks per call and creates no
  service, so there is no `desiredCount` to reset — and no rule in the source set can see it,
  because a documented maximum of 10 makes a four-digit `count` rule unfireable.
- **Quantify and record the cost.** It is unrecoverable, it is the concrete impact, and it is the
  number that funds the guardrail.
- **Right-size the permission.** `ecs:UpdateService` belongs to the deployment pipeline and to
  autoscaling, and to nothing else. There is **no IAM condition key for a maximum
  `desiredCount`**, so confining the action is the only policy-level control available.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
# A principal that is neither user nor role must reach INCONCLUSIVE, never the clean branch.
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyEcsScale EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyEcsScale"
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

#### Verify the service is back at its baseline, on the right image, and actually there

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; SERVICE="<service-from-Query-1>"
BASELINE="<the service's documented desiredCount>"
KNOWN_GOOD_TD="<family:revision from before the incident>"

# describe-services keeps answering after this remediation - the service still exists, it was
# only scaled - so every branch below stays reachable. The MISSING case is still handled,
# because it arrives as HTTP 200 with exit code 0 and reads as success to any check that only
# tests whether the command ran.
D=$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
      --region "$REGION" --output json)
if [ -z "$D" ]; then
  echo "[!] INCONCLUSIVE - describe-services produced no output. A bad CLUSTER throws"
  echo "    ClusterNotFoundException; a permissions failure looks identical. Unknown, not clean."
  exit 0
fi
NS=$(printf '%s' "$D" | jq '.services | length')
if [ "$NS" -eq 0 ]; then
  echo "[FAIL] $SERVICE is not describable (failure reason:"
  echo "    $(printf '%s' "$D" | jq -r '.failures[0].reason // "none returned"')) - it was"
  echo "    deleted rather than rescaled, which is a different incident:"
  echo "    see ../ecs.stealth.service-is-deleted/"
  exit 0
fi
DESIRED=$(printf '%s' "$D" | jq -r '.services[0].desiredCount // -1')
RUNNING=$(printf '%s' "$D" | jq -r '.services[0].runningCount // -1')
PENDING=$(printf '%s' "$D" | jq -r '.services[0].pendingCount // -1')
TD=$(printf '%s' "$D" | jq -r '.services[0].taskDefinition // empty')
TDSHORT=$(printf '%s' "$TD" | awk -F'/' '{print $NF}')
if   [ "$DESIRED" -lt 0 ] || [ -z "$TD" ]; then
  echo "[!] INCONCLUSIVE - the service was returned without a desired count or task definition"
elif [ "$DESIRED" -gt "$BASELINE" ]; then
  echo "[FAIL] desiredCount is $DESIRED, above the baseline of $BASELINE - still hijacked"
elif [ "$RUNNING" -gt "$BASELINE" ] || [ "$PENDING" -gt 0 ]; then
  echo "[FAIL] desiredCount is correct but running=$RUNNING pending=$PENDING against a baseline"
  echo "    of $BASELINE - the surplus tasks have not finished draining yet"
elif [ -n "$KNOWN_GOOD_TD" ] && [ "$TDSHORT" != "$KNOWN_GOOD_TD" ]; then
  echo "[FAIL] the count is back to $DESIRED but the service runs $TDSHORT, not the known-good"
  echo "    $KNOWN_GOOD_TD - a smaller fleet of the actor's image is still a fleet"
else
  echo "[OK] $SERVICE at desired=$DESIRED running=$RUNNING on $TDSHORT"
fi
```

The two failure branches that matter are the ones a count-only check misses. Drain is
asynchronous, so `desiredCount` reading correctly while `runningCount` is still high means the
compute is still billing. And if the task definition was swapped during the incident, resetting
the count leaves the actor's image running at baseline size — which passes every check that
looks at numbers alone.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     UpdateService / ecs.amazonaws.com / no errorCode with"
echo "  requestParameters.desiredCount at or above the deployed threshold - a NUMERIC"
echo "  comparison on an integer field, not a regex on a .keyword subfield. The value_count"
echo "  correlation must fire at exactly three distinct services in 30 minutes - gte, not gt."
echo "MUST NOT fire on: an UpdateService that omits desiredCount entirely (a task-definition"
echo "  swap or a forced deployment) - a missing field is NOT a zero; a scale-out by the"
echo "  deployment role inside a change window; a DENIED high-count update, which belongs on"
echo "  the separate medium rule and must not be counted as compute that ran."
echo "EXPECTED FP, by design: genuine scale-out - a load test, a traffic surge, a regional"
echo "  failover. All are traceable to a change record; if they are not, that is the finding."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the pipeline could multiply a service's task count | `ecs:UpdateService` granted to an identity that neither deploys nor autoscales; no SCP confining it |
| The scale-out was not distinguished from a deployment | The only rule tested a `.keyword` subfield on an integer field with an anchored four-digit regex, so it was blind below 1,000 and possibly inert entirely |
| Permission probing and real consumption arrived in the same queue | The rule had no success filter — the only one of the five ECS rules missing it |
| The cost was discovered from the bill rather than from the alert | No billing anomaly alarm, and no baseline of each service's legitimate maximum `desiredCount` against which the event could be judged |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the value is wildcarded: Deny + StringNotEquals against
// a wildcarded ARN matches every principal and blocks all scaling - an outage, not a bypass.
// NOTE: there is no IAM condition key for a maximum desiredCount. The action can be confined
// to a principal; the VALUE cannot be constrained by policy at all.
{
  "Effect": "Deny",
  "Action": ["ecs:UpdateService", "ecs:RunTask", "ecs:CreateService"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/ecs-autoscaling", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- All three are real ECS IAM actions, and the autoscaling role must be in the allowlist or
  scaling breaks. Because the value cannot be constrained by policy, the SCP is a
  *who*, not a *how much* — and the backstop for whatever gets through is a billing anomaly
  alarm plus a Fargate vCPU quota kept at the size the workload actually needs rather than raised
  and forgotten.
- Baseline every service's legitimate maximum `desiredCount` and deploy the rule at that number
  plus headroom. The 50 in §2 is derived from AWS quota arithmetic, not from your account.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1496.001 — Resource Hijacking: Compute Hijacking (primary); T1496 — Resource Hijacking (parent) |
| MITRE tactic | Impact (TA0040) |
| Primary API | `ecs:UpdateService` with a raised `desiredCount`; `ecs:RegisterTaskDefinition` when the image is the actor's; `ecs:RunTask` as the serviceless alternative, capped at 10 tasks per call |
| Event source | `ecs.amazonaws.com`, **management** plane, regional — management events are on by default |
| Key discriminator | The **magnitude relative to the service's own baseline**, not the call. `UpdateService` is the most routine write in ECS |
| Field shape | `requestParameters.desiredCount` — **top-level, integer, and OPTIONAL**. A missing value is not a zero. `.cluster`, `.service` and `.taskDefinition` are **caller-typed**. Response **nested** at `responseElements.service.*`, whose `runningCount` is the count *before* the new tasks start |
| Threshold basis | "Tasks per service" = 5,000, not adjustable (the hard ceiling). Fargate "On-Demand vCPU resource count" = 6 per Region by default, adjustable and auto-raised — about 24 tasks at the 0.25 vCPU minimum. 50 sits between them; deploy at your own observed maximum plus headroom |
| "Was it used" pivot | `AWS/ECS` `CPUUtilization` on the `ClusterName`+`ServiceName` dimensions, sent in 1-minute periods and *"recorded for a period of two weeks"*; and the bill. Never `responseElements.service.runningCount` |
| Blast radius | Account spend for as long as the tasks run, the capacity denied to legitimate workloads, and — if the task definition was swapped — an attacker-supplied image running under the service's task role |
| Error strings | `AccessDeniedException`, `ClientException`, `ClusterNotFoundException`, `InvalidParameterException`, `NamespaceNotFoundException`, `PlatformTaskDefinitionIncompatibilityException`, `PlatformUnknownException`, `ServerException`, `ServiceNotActiveException`, `ServiceNotFoundException`, `UnsupportedFeatureException`; plus `NotAuthorized` (401) and `ThrottlingException` from ECS's Common Errors. An over-quota `desiredCount` returns `InvalidParameterException`, **not** a quota-specific code — do not build a rule on a `LimitExceeded` shape here |

**MITRE mapping note.** The source rule labels this **T1496** under **TA0040**, and this is the
one mapping in the ECS set that is correct on the merits. The only refinement is precision:
ATT&CK now carries sub-techniques under T1496, and **T1496.001 (Compute Hijacking)** is the exact
one — using compromised compute for tasks such as mining. Both the parent and the sub-technique
are tagged. The rule's problems here are entirely in its query, not in its mapping.

### Residual Risk

The cost is unrecoverable: it accrued per minute and no remediation refunds it. If the task
definition changed too, the actor's image is registered in the account and remains pullable and
re-deployable after the service is re-pointed. The capacity the surplus tasks consumed may have
starved legitimate workloads, and on a shared cluster that is not confined to the service scaled.
`RunTask` remains a serviceless route to the same outcome — ten tasks per call, no `desiredCount`
to reset, and a source rule whose four-digit `count` requirement the documented maximum of 10
makes unfireable. And if the Fargate vCPU quota was raised before or during the incident, that
raise persists: the same event on the same account will now materialise far more compute.
