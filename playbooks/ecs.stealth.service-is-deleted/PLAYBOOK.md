# IR Playbook: ECS Service Deleted — Workload Stopped or Cleaned Up via `ecs:DeleteService`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Availability / Indicator removal (a service stops serving and is not replaced; or the actor removes the service they themselves created, taking the evidence with it) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, against the source's **P3**. A production service stops and does not come back: its load-balancer wiring, network configuration, task-definition reference and deployment settings survive only in infrastructure code, and once the service reaches `INACTIVE` AWS may purge it entirely, at which point even `DescribeServices` stops answering. Severity does not scale with count — one production service destroyed is already an outage — so the volume correlation raises urgency and the size of the restoration list, not the level |
| MITRE Tactics | Impact (TA0040), Stealth (TA0005) |
| MITRE Techniques | T1489 (primary), T1070 (secondary) — both verified live 2026-08-29 |
| Services in Scope | ECS, CloudTrail, Elastic Load Balancing (target groups the service registered), Route 53 / Cloud Map (service discovery), CloudWatch (`AWS/ECS`, Logs), IAM, Organizations (SCP) |

**What the technique does:** the actor calls `DeleteService` with `cluster`, `service` and optionally
`force`. If the service is still maintaining tasks the call is refused unless `force` is set —
AWS: *"If the service is actively maintaining tasks, you can't delete it, and you must update
the service to a desired task count of zero."* The service moves `ACTIVE` → `DRAINING`, its
tasks transition to `STOPPING`/`STOPPED` and are **not replaced**, and it then moves to
`INACTIVE`. From the moment it is `DRAINING` it stops appearing in `ListServices`, so an
account sweep built on listing will not see it. Its target-group registrations drain, its
service-discovery entries go, and its configuration exists afterwards only in whatever
infrastructure code created it.

**Detection thesis.** The discriminator is **`requestParameters.force` together with the
calling principal**: an orderly teardown emits a scale-to-zero and then a deletion, while
`force: true` is the documented shortcut that removes a service while it is still serving. The
source rule reads neither, and at P3 it triages an outage below a configuration change.

> **This event is also the remediation.** `DeleteService` is how a responder removes an
> attacker's workload — it is step one of `../ecs.stealth.service-is-created/` §4. Before
> escalating, check the caller against the break-glass responder role and the open incident
> record. The alerting path here deliberately allowlists that role, and Query 1 exists partly
> to tell cleanup from destruction.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing ECS **management** events — on by default, so
  `lookup-events` returns `DeleteService`, `UpdateService` and `CreateService`
- `DeleteService` carries exactly three request parameters: `requestParameters.cluster` (short
  name **or** full ARN — caller-typed), `.service` (likewise) and `.force`. The response is
  **nested** at `responseElements.service.*` and is the **last full description of the service
  that will ever exist** — `taskDefinition`, `desiredCount`, `runningCount`, `loadBalancers`,
  `networkConfiguration`, `serviceRegistries`, `deployments[]` and `events[]` are all in it
- `responseElements.service.status` on a normal deletion is **`DRAINING`**, not `INACTIVE`. A
  rule or a check keyed on `INACTIVE` misses almost every real deletion and passes while tasks
  are still running
- **An allowlist that includes the incident-response break-glass role**, not only the deployment
  role — deleting a service is the containment step for another technique in this corpus, and an
  allowlist that omits the responder pages the SOC on its own work — plus service definitions in
  **infrastructure code**, since load-balancer wiring, subnets, security groups,
  `serviceRegistries` and the task-definition reference exist nowhere else afterwards
- CloudWatch `AWS/ECS` `CPUUtilization` / `MemoryUtilization` on the `ClusterName` +
  `ServiceName` dimensions. ECS sends metric data in 1-minute periods and states the statistics
  are *"recorded for a period of two weeks"* — that is how long "what was this service doing
  before it stopped" stays answerable

**Alerting (must be pre-configured)**
- **`DeleteService` succeeding for a principal outside the deployment and response allowlist → P0**
- **`DeleteService` with `force: true` → P0**
- **`UpdateService` with `desiredCount: 0` then `DeleteService`, same principal, within 30 minutes → P1**
- **Three or more `DeleteService` successes by one non-allowlisted principal within 10 minutes → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `DeleteService` succeeding for a principal not on the deployment-and-response allowlist | CloudTrail (management) | T1489 |
| P0 | `DeleteService` with `requestParameters.force: true` — the service was removed while still maintaining tasks | CloudTrail (management) | T1489 |
| P1 | `UpdateService` with `desiredCount: 0` followed by `DeleteService`, same principal, within 30 minutes | CloudTrail (management) | T1489 |
| P1 | Three or more `DeleteService` successes by one non-allowlisted principal within 10 minutes | CloudTrail (management) | T1489 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `DeleteService` on a service the **same principal** created within the previous 24 hours — cleanup after `../ecs.stealth.service-is-created/`, not destruction | CloudTrail (management) | T1070 |
| P2 | A service's `AWS/ECS` `CPUUtilization` stops emitting for a `ClusterName`+`ServiceName` pair with no scheduled teardown | CloudWatch `AWS/ECS` | T1489 |
| P3 | `DeleteService` denied `AccessDeniedException` / `NotAuthorized` / `ServiceNotFoundException` — permission and topology probing | CloudTrail (management) | T1489 |

### Detection Rule Quality Notes

The source rule matches an event name and a success filter, reads neither the caller nor the one
request parameter that carries signal, and cannot tell an outage from its own remediation.

| Issue | Impact | Correction |
|-------|--------|-----------|
| No principal check | Fires on every pipeline teardown **and on the SOC's own containment work**, since `DeleteService` is how a responder removes an attacker's service. An alert that pages on incident response is one people learn to close | Allowlist the deployment role **and** the break-glass responder role |
| `requestParameters.force` unread | An orderly teardown scales to zero first, because ECS refuses otherwise. `force: true` removes a service while it is still serving, and the two are indistinguishable to this rule | Ship the forced-deletion rule, ungated on principal |
| No link to the service's creation | Cleanup — the actor removing the service they created an hour ago — and destruction of a two-year-old production service produce the same event | Join to `CreateService` in the KQL; carry the P2 row for the cleanup case |
| P3, mapped to T1578/TA0005 | An availability incident triaged below a configuration change, and labelled as infrastructure evasion rather than as stopping a service | High; T1489 primary, T1070 for the cleanup reading |

**Recommended detection — a service deleted outside the deployment and response allowlist.**

```yaml
# ECS Service Deleted (T1489 / T1070)
#
# WHAT THE SOURCE RULE DOES NOT DO. It matches `eventName:"DeleteService"` with a success
# filter and nothing else, at P3, mapped to T1578 under TA0005. It never looks at who called,
# and — the sharper omission — it never reads `requestParameters.force`, which is the one field
# in the event that carries real signal.
#
# WHY `force` IS THE DISCRIMINATOR. AWS: "You can delete a service if you have no running tasks
# in it and the desired task count is zero. If the service is actively maintaining tasks, you
# can't delete it, and you must update the service to a desired task count of zero." The
# `force` parameter is documented as: "If true, allows you to delete a service even if it
# wasn't scaled down to zero tasks. It's only necessary to use this if the service uses the
# REPLICA scheduling strategy." So an orderly teardown produces TWO events — an UpdateService
# setting desiredCount to 0, then a DeleteService — while `force: true` is the single-call
# shortcut that removes a service WHILE IT IS STILL SERVING. Rule 2 below reads it, and is
# deliberately not gated on the principal: a pipeline that force-deletes production services
# is a finding about the pipeline.
#
# Note what AWS does NOT say: `force` is nowhere documented as terminating running tasks. It
# waives a precondition. Do not write "force kills the tasks" into a playbook.
#
# THE PROBLEM THIS RULE HAS THAT ITS SIBLINGS DO NOT: DELETION IS ALSO THE REMEDIATION.
# `DeleteService` is exactly the call an incident responder makes to remove an attacker's
# workload — it is step one of ../../ecs.stealth.service-is-created/ §4. A rule that pages on
# every DeleteService will page on its own SOC. The allowlist below therefore has to carry the
# break-glass RESPONDER role as well as the deployment role, and the KQL joins each deletion
# back to the CreateService that produced the service, so an analyst can see whether the thing
# being deleted was ours or the actor's. That distinction is the triage, and no field in the
# DeleteService event supplies it.
#
# FIELD SHAPE. `DeleteService` carries exactly three request parameters — `cluster` (short name
# or full ARN, caller-typed), `service`, and `force`. The response is NESTED at
# `responseElements.service.*` and its `status` is typically `DRAINING`, not `INACTIVE`: AWS
# documents the transition as ACTIVE -> DRAINING -> INACTIVE, with DRAINING lasting until "all
# tasks have transitioned to either STOPPING or STOPPED status". A rule matching
# `responseElements.service.status: INACTIVE` would miss almost every real deletion.
title: ECS service deleted by a principal outside the service-lifecycle pipeline
id: cf459c6f-631b-4bb0-b92d-8780be96e9b5
name: ecs_service_deleted_nonpipeline
status: experimental
description: >-
  A service was deleted by a principal that neither deploys nor responds to incidents. The
  service's tasks stop and are not replaced, and once the service reaches INACTIVE it may be
  purged from ECS record keeping entirely, at which point DescribeServices returns
  ServiceNotFoundException and its configuration survives only in infrastructure code.
references:
  - https://attack.mitre.org/techniques/T1489/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DeleteService.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1489
  - attack.stealth
  - attack.t1070
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecs.amazonaws.com'
    eventName: 'DeleteService'
  # POPULATE BEFORE DEPLOYING, AND INCLUDE THE RESPONDER ROLE. Deleting a service is how an
  # incident responder removes an attacker's workload, so an allowlist holding only the
  # deployment role will page the SOC on its own containment work.
  service_lifecycle_and_response:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace with this account's deployment role
      - ':role/BreakGlassAdmin'     # replace with this account's break-glass responder role
  success:
    errorCode: null
  condition: selection and success and not service_lifecycle_and_response
falsepositives:
  - >-
    An engineer removing a personal or ephemeral service outside the pipeline. Expected in
    development accounts; in production it is the finding.
  - >-
    Incident response on another technique. Deleting a service is the containment step for
    ecs.stealth.service-is-created, so correlate against open incidents before escalating.
level: high
---
# Not gated on the principal: force-deleting a service that is actively maintaining tasks is
# worth a look whoever does it, and a pipeline that does it routinely is the finding.
title: ECS service force-deleted while still maintaining tasks
id: 0a554f6d-44bd-4519-ade1-e56f9de85b8e
name: ecs_service_deleted_forced
status: experimental
description: >-
  A service was deleted with force=true, which AWS documents as waiving the requirement that
  the service first be scaled to zero. An orderly teardown produces a scale-to-zero and then a
  deletion; this is the single-call shortcut that removes a service while it is still serving.
references:
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DeleteService.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1489
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecs.amazonaws.com'
    eventName: 'DeleteService'
  forced:
    requestParameters.force: true
  success:
    errorCode: null
  condition: selection and success and forced
falsepositives:
  - >-
    Automated teardown of ephemeral environments often sets force to avoid a second call.
    Baseline which pipelines do; a force delete from anything else is the signal.
level: high
---
# Base rule — sequence component only, not for direct alerting. The mandatory first half of an
# orderly teardown, and the event the source set's only UpdateService rule cannot see because
# it fires on a HIGH desiredCount.
title: ECS service scaled to zero
id: 26849141-2687-443a-8aa2-3ce33506f560
name: ecs_service_scaled_to_zero_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateService.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1489
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecs.amazonaws.com'
    eventName: 'UpdateService'
  scaled_to_zero:
    requestParameters.desiredCount: 0
  success:
    errorCode: null
  condition: selection and success and scaled_to_zero
level: informational
---
# Scale-to-zero then delete, by one non-pipeline principal, is a DELIBERATE and SEQUENCED
# teardown rather than a stray API call — someone who knew that ECS refuses to delete a service
# maintaining tasks and worked around it the documented way.
#
# TIMESPAN BASIS. Thirty minutes. The gap is however long the tasks take to drain, which is
# bounded by the service's deregistration delay and health-check grace period rather than by
# anything in ECS; half an hour covers a slow drain without spanning unrelated work.
title: ECS service scaled to zero and then deleted by one principal
id: 920802b2-88b3-456e-a1b2-76041c1f032c
status: experimental
description: >-
  One non-pipeline principal set a service's desired count to zero and then deleted it inside
  thirty minutes. That is the documented teardown sequence executed deliberately, not an
  accident, and it destroys the service's configuration along with its tasks.
references:
  - https://attack.mitre.org/techniques/T1489/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1489
correlation:
  type: temporal_ordered
  rules:
    - ecs_service_scaled_to_zero_bb
    - ecs_service_deleted_nonpipeline
  group-by:
    - userIdentity.arn
  timespan: 30m
level: high
---
# Threshold basis. There is no observed baseline, so the reasoning is structural rather than
# numeric-by-assertion: ECS permits 5,000 services per cluster, so the quota constrains nothing
# and cannot supply a threshold. What can is the shape of the work — a human removing a service
# deliberately removes one and confirms it, while three or more inside ten minutes is
# machine-paced, and the two processes that legitimately do that are the deployment pipeline
# and an incident responder, both of which the base rule's allowlist already excludes. `gte` at
# the baseline, never `gt`, so a run that deletes exactly three does not fall through.
# Re-baseline against your own account before deploying.
title: ECS services deleted at volume by one non-pipeline principal
id: 4fb554fe-fdad-43a0-ac18-21a5dbb5b327
status: experimental
description: >-
  One principal outside the deployment and response allowlist deleted three or more services
  inside ten minutes. Each deletion independently destroys a service's configuration and stops
  its tasks, so the restoration work-list is every service in the group.
references:
  - https://docs.aws.amazon.com/general/latest/gr/ecs-service.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1489
correlation:
  type: event_count
  rules:
    - ecs_service_deleted_nonpipeline
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gte: 3
level: high
```

The rule cannot tell you whether the deletion was *authorised in the human sense*: an incident
responder removing an attacker's service and an attacker removing a production service emit the
same event with a different ARN in it. `detections/kql_t1489.kql` supplies the provenance the
event lacks by joining each deletion back to the `CreateService` that produced the service, and
captures `responseElements.service.*` as the last full description that will ever exist.

---

### Key Investigation Queries

> ECS is regional — run these in the service's region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: what was deleted, how, and who created it in the first place

```bash
REGION="us-east-1"
RAW=$(for EV in DeleteService CreateService UpdateService; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region,"
  echo "    or missing cloudtrail:LookupEvents. This is NOT 'no services were deleted'."
else
  # cluster and service are both caller-typed - short name or full ARN - so both are reduced
  # to a bare name. CreateService names the service in serviceName; Delete/UpdateService name
  # it in service. responseElements.service.* is captured because it is the LAST full
  # description of the service that will ever exist.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "ecs.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller_arn: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     cluster: ((.requestParameters.cluster // "") | split("/") | last),
     service: ((.requestParameters.serviceName //
                .requestParameters.service // "") | split("/") | last),
     forced: (.requestParameters.force // null),
     desired_requested: (.requestParameters.desiredCount // null),
     post_status: (.responseElements.service.status // null),
     running_at_call: (.responseElements.service.runningCount // null),
     task_def: (.responseElements.service.taskDefinition // null),
     load_balancers: (.responseElements.service.loadBalancers // null),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.service, .time)'
fi
```

Read it per `service`, in time order. `forced` = `true` means the service was removed while
still maintaining tasks — the documented shortcut around the scale-to-zero requirement, and the
single strongest field-level signal here. `running_at_call` on the `DeleteService` row is how
much was actually serving at the moment it went. `post_status` will read `DRAINING`, not
`INACTIVE`; that is normal and does not mean the deletion failed. Compare the `caller_arn` of
the `DeleteService` row with that of the `CreateService` row for the same `service`: **the same
principal, hours apart, is cleanup after `../ecs.stealth.service-is-created/`, not destruction**
— and in that case the priority is preserving the task definition before it is deregistered, not
restoring the service. `task_def` and `load_balancers` are the rebuild inputs and exist nowhere
else once ECS purges the record. Record `cluster`, `service`, `caller_arn` and `access_key` as
IOCs.

#### Query 2 — Inspect: what state is the service in now, and does its record still exist

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; SERVICE="<service-from-Query-1>"

# describe-services does NOT error for a service that is gone: it returns HTTP 200 with
# .services empty and a .failures reason of MISSING, and the CLI exits 0. A wrong CLUSTER, by
# contrast, throws ClusterNotFoundException - a real error that produces no output here.
D=$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
      --region "$REGION" --output json)
if [ -z "$D" ]; then
  echo "[!] INCONCLUSIVE - describe-services produced no output. Likely ClusterNotFoundException"
  echo "    or a permissions failure. The service's state is unknown, not confirmed deleted."
else
  NS=$(printf '%s' "$D" | jq '.services | length')
  REASON=$(printf '%s' "$D" | jq -r '.failures[0].reason // "none returned"')
  if [ "$NS" -eq 0 ] && [ "$REASON" = "MISSING" ]; then
    echo "[i] $SERVICE is MISSING - already purged from ECS record keeping. AWS warns that"
    echo "    INACTIVE services may be purged and DescribeServices then returns"
    echo "    ServiceNotFoundException, so Query 1's responseElements is now the only record."
  elif [ "$NS" -eq 0 ]; then
    echo "[!] INCONCLUSIVE - no service and failure reason '$REASON' is not MISSING"
  else
    printf '%s' "$D" | jq -r '.services[0] |
      "[i] status=\(.status) desired=\(.desiredCount) running=\(.runningCount) " +
      "pending=\(.pendingCount) taskDef=\(.taskDefinition)"'
  fi
fi
```

The `MISSING` branch is a finding, not a pass: it means the only surviving description of the
service is the `responseElements` captured in Query 1. Note also that a `DRAINING` service is
invisible to `ListServices` — AWS: it is *"no longer visible in the console or in the
`ListServices` API operation"* — so the cluster sweep in §3 Step 1 is framed as a **difference
against your IaC inventory**, not as a list of problems; an empty `list-services` result is
indistinguishable from an empty cluster.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="DeleteService UpdateService"
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

**Confirm this is not your own remediation before doing anything else** — Query 1's
`CreateService` comparison and the incident record answer that in under a minute, and containing
your own responder is worse than the alert. If it is genuinely unauthorised: capture the
service's last full description **before** rebuilding, because a rebuild under the same name is
blocked while the old service is `DRAINING` and the old record is purged once it is `INACTIVE`.
Then contain the principal.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Capture the last description of the service, and of anything else already draining

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; SERVICE="<service-from-Query-1>"
EVID="./ecs-svc-incident-$SERVICE-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || { echo "[FAIL] cannot create evidence directory $EVID"; exit 1; }

# The DeleteService event's own responseElements is the rebuild input: taskDefinition,
# loadBalancers, networkConfiguration and serviceRegistries. Once the service is INACTIVE and
# purged, this CloudTrail record is the only place any of it exists.
aws cloudtrail lookup-events --region "$REGION" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteService \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" --output json |
  jq --arg s "$SERVICE" '[.Events[].CloudTrailEvent | fromjson |
    select(((.requestParameters.service // "") | split("/") | last) == $s) |
    {eventTime, caller: .userIdentity.arn, forced: .requestParameters.force,
     service: .responseElements.service}]' > "$EVID/deleted-service.json"

# Everything still describable in the cluster, DRAINING included - describe-services answers
# for DRAINING and INACTIVE services, which is exactly why it is used here and list-services
# is not.
aws ecs list-services --cluster "$CLUSTER" --region "$REGION" \
  --query 'serviceArns' --output text > "$EVID/active-services.txt"

# -s, not exit status: both calls exit 0 while writing nothing if they were refused.
for F in deleted-service.json active-services.txt; do
  if [ -s "$EVID/$F" ]; then echo "[OK] captured $F ($(wc -c < "$EVID/$F") bytes)"
  else echo "[!] INCONCLUSIVE - $F is empty; that evidence was NOT captured"; fi
done
echo "[i] Do not attempt to recreate $SERVICE until it leaves DRAINING: AWS refuses a"
echo "    CreateService using the name of a service in ACTIVE or DRAINING status."
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ecs:DeleteService","ecs:UpdateService","ecs:DeleteCluster","ecs:StopTask","ecs:DeregisterTaskDefinition"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyEcsDestroy" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyEcsDestroy" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied ECS destruction for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or"
     echo "    a service principal. Contain manually; neither branch above applies.";;
esac
```

`ecs:DeregisterTaskDefinition` is in the deny list because deregistering the definition after
deleting the service is what makes the rebuild impossible — it is the second half of the same
destruction, and the source set alerts on it nowhere.

---

## 4. Eradication

### Remove Attacker Access

- **Rebuild the service from infrastructure code**, and expect the name to be unusable until the
  old one leaves `DRAINING` — AWS refuses a `CreateService` reusing the name of a service in
  `ACTIVE` or `DRAINING` status. Rebuild the load-balancer target-group registration and the
  `serviceRegistries` entries too; deleting the service removed them and nothing else restores
  them.
- **Confirm the task definition still exists.** A `DeleteService` followed by
  `DeregisterTaskDefinition` leaves nothing to rebuild from. A deregistered revision reads
  `INACTIVE`; AWS still allows an existing definition to be described, but a new service cannot
  be created from an `INACTIVE` revision.
- **Every other service in the deletion set is in scope**, not just the one that alerted. The
  volume correlation's group is the work-list, and `list-services` will not show the ones still
  draining.
- **Right-size the permission.** `ecs:DeleteService` belongs to the deployment pipeline and to
  incident response, and to nothing at runtime. The same applies to `ecs:DeleteCluster`
  (`../ecs.stealth.cluster-is-deleted/`).
- **If this was cleanup rather than destruction** — the same principal created the service — then
  eradication is the *other* playbook's: the image, the task definition and the task role are
  still there, and deleting the service removed only the runtime. Follow
  `../ecs.stealth.service-is-created/` §4.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
# A principal that is neither user nor role must reach INCONCLUSIVE, never the clean branch.
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyEcsDestroy EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyEcsDestroy"
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

#### Verify the service is back, ACTIVE, and actually running its tasks

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; SERVICE="<service-from-Query-1>"

# The trap: describe-services returns HTTP 200 with .services empty and a .failures reason of
# MISSING for a service that does not exist, and the CLI exits 0. `if aws ecs describe-services
# ...; then echo "[OK]"` therefore certifies a destroyed service as restored. Five states are
# separated below, and "the call did not run" is one of them.
D=$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
      --region "$REGION" --output json)
if [ -z "$D" ]; then
  echo "[!] INCONCLUSIVE - describe-services produced no output. A bad CLUSTER throws"
  echo "    ClusterNotFoundException; a permissions failure looks identical. Unknown, not clean."
  exit 0
fi
NS=$(printf '%s' "$D" | jq '.services | length')
REASON=$(printf '%s' "$D" | jq -r '.failures[0].reason // "none returned"')
if [ "$NS" -eq 0 ]; then
  echo "[FAIL] $SERVICE is not describable in $CLUSTER (failure reason: $REASON) - it has NOT"
  echo "    been rebuilt"
  exit 0
fi
STATUS=$(printf '%s' "$D" | jq -r '.services[0].status // empty')
DESIRED=$(printf '%s' "$D" | jq -r '.services[0].desiredCount // -1')
RUNNING=$(printf '%s' "$D" | jq -r '.services[0].runningCount // -1')
LBS=$(printf '%s' "$D" | jq '.services[0].loadBalancers // [] | length')
if   [ -z "$STATUS" ] || [ "$RUNNING" -lt 0 ]; then
  echo "[!] INCONCLUSIVE - the service was returned without a status or task counts"
elif [ "$STATUS" = "DRAINING" ]; then
  echo "[FAIL] $SERVICE is still DRAINING - this is the OLD service finishing its deletion,"
  echo "    not the rebuild. The name cannot be reused until it reaches INACTIVE."
elif [ "$STATUS" != "ACTIVE" ]; then
  echo "[FAIL] $SERVICE status is $STATUS, not ACTIVE"
elif [ "$DESIRED" -eq 0 ]; then
  echo "[FAIL] $SERVICE is ACTIVE but desiredCount is 0 - recreated and never scaled up"
elif [ "$RUNNING" -ne "$DESIRED" ]; then
  echo "[FAIL] $SERVICE is ACTIVE with running=$RUNNING of desired=$DESIRED - the rebuild is"
  echo "    incomplete or the tasks are failing to start"
elif [ "$LBS" -eq 0 ]; then
  echo "[!] $SERVICE is ACTIVE and fully running but registers NO load balancer. If it did"
  echo "    before (check Query 1's load_balancers), the rebuild dropped the wiring and the"
  echo "    service is healthy but unreachable. INCONCLUSIVE without that baseline."
else
  echo "[OK] $SERVICE ACTIVE in $CLUSTER, running=$RUNNING/$DESIRED, $LBS load balancer(s)"
fi
```

Every branch is reachable after the remediation, and the two that matter most are the ones a
naive check collapses. `DRAINING` is the *old* service still finishing its deletion, not the new
one — treating it as "the service exists" declares victory on a corpse. And a rebuild that comes
back without its load-balancer registration is healthy by every ECS measure while serving no
traffic, which is why the `loadBalancers` count is asserted and why an unknown baseline lands on
`INCONCLUSIVE` rather than `[OK]`.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     DeleteService / ecs.amazonaws.com / no errorCode, where"
echo "  userIdentity.arn is NOT on the deployment-and-response allowlist; and separately on"
echo "  ANY DeleteService with requestParameters.force true, allowlisted or not. The volume"
echo "  correlation must fire at exactly three deletions in ten minutes - gte, not gt."
echo "MUST NOT fire on: DeleteService by the pipeline role during a stack teardown;"
echo "  DeleteService by the break-glass responder role during containment of"
echo "  ecs.stealth.service-is-created; a DeleteService that returned ServiceNotFoundException."
echo "EXPECTED FP, by design: the forced-deletion rule is NOT gated on the principal, so an"
echo "  ephemeral-environment pipeline that always passes force will fire it. Baseline which"
echo "  pipelines do; a force delete from anything else is the signal."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the pipeline could delete a production service | `ecs:DeleteService` granted to an identity that needs it neither to deploy nor to respond; no SCP confining service lifecycle |
| The service was removed while still serving | `force: true` was available and unmonitored, and no rule read the parameter |
| The rebuild could not reproduce the load-balancer and service-discovery wiring | The service definition lived in the console rather than in infrastructure code, and the only surviving copy was the `responseElements` of the deletion event |
| Triage could not immediately tell destruction from the SOC's own containment | The alert had no allowlist for the responder role and no link back to the service's creation |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the value is wildcarded: Deny + StringNotEquals against
// a wildcarded ARN matches every principal and blocks all teardown - an outage, not a bypass.
{
  "Effect": "Deny",
  "Action": ["ecs:DeleteService", "ecs:DeleteCluster", "ecs:DeregisterTaskDefinition"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- All three are real ECS IAM actions. `ecs:DeregisterTaskDefinition` is included deliberately:
  deregistering the definition after deleting the service is what turns a recoverable outage
  into an unrecoverable one, and no rule in the source set watches it.
- Hold service definitions in infrastructure code, and keep the `AWS/ECS` service metrics —
  ECS emits them in 1-minute periods and states they are *"recorded for a period of two weeks"*,
  which is the window in which "what was this service doing before it stopped" is answerable.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1489 — Service Stop (primary); T1070 — Indicator Removal (secondary, where the actor deletes the service they created) |
| MITRE tactic | Impact (TA0040), Stealth (TA0005) |
| Primary API | `ecs:DeleteService`; `ecs:UpdateService` with `desiredCount: 0` as the mandatory precursor unless `force` is set; `ecs:DeregisterTaskDefinition` as the follow-on that prevents rebuild |
| Event source | `ecs.amazonaws.com`, **management** plane, regional — management events are on by default |
| Key discriminator | `requestParameters.force`, plus the calling principal — and the allowlist must include the incident-response role, because this event is also the remediation |
| Field shape | Three request parameters only: `cluster`, `service` (both **caller-typed**, short name or ARN) and `force`. Response **nested** at `responseElements.service.*`, `status` = **`DRAINING`**, not `INACTIVE`. That response is the last full description of the service that will ever exist |
| "Was it used" pivot | `responseElements.service.runningCount` at the moment of deletion — how much was actually serving; and `AWS/ECS` `CPUUtilization` on the `ClusterName`+`ServiceName` dimensions up to the deletion |
| Blast radius | The service's tasks, its load-balancer target-group registrations, its `serviceRegistries` discovery entries, and its whole definition — network configuration, deployment configuration, task-definition reference — unless held in IaC |
| Error strings | Exactly six documented: `AccessDeniedException`, `ClientException`, `ClusterNotFoundException`, `InvalidParameterException`, `ServerException`, `ServiceNotFoundException`. `ServiceNotActiveException`, `UnsupportedFeatureException` and the `Platform*` codes are documented for `UpdateService`/`CreateService` but **not** for this API. ECS's Common Errors adds `NotAuthorized` (HTTP 401); there is no bare `AccessDenied` |

**MITRE mapping note.** The source rule labels this **T1578** under **TA0005**, and both IDs are
live — so this is imprecision, not staleness, but it is on the wrong axis. Deleting a service
stops a workload, which is **T1489 (Service Stop)** under Impact. **T1070 (Indicator Removal)**
under Stealth is carried as a genuine second mapping for the cleanup reading — the actor removing
the service they themselves created — which is what the directory's `stealth` segment tracks and
what the KQL's `CreateService` join is built to surface. Both readings are real, they call for
opposite responses, and separating them is the first triage decision in §3.

### Residual Risk

If this was destruction, the tasks are gone and were not replaced; anything in their ephemeral
storage is unrecoverable and their logs survive only where the task definition's log driver sent
them. The load-balancer target group and service-discovery entries are deregistered, so callers
fail before reaching anything, and a rebuild that omits them comes back healthy and unreachable.
Once the service reaches `INACTIVE` AWS may purge it — `DescribeServices` then returns
`ServiceNotFoundException`, and the `responseElements` in CloudTrail becomes the only surviving
description, itself bounded by a 90-day Event history window. If it was cleanup, the opposite
holds: the runtime is gone but the task definition, image and task role all remain, and nothing
here removes them — the residual risk is the whole of `../ecs.stealth.service-is-created/`.
