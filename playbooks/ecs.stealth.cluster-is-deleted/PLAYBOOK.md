# IR Playbook: ECS Cluster Deleted — Teardown Cover-Up via `ecs:DeleteCluster`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Indicator removal / Infrastructure destruction (a cluster that was already emptied is deleted, taking its settings, tags, capacity-provider wiring and — once the name is reused — its stopped-task history with it) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, and the source's **P1** is close to right — the only one of the five ECS rules whose priority does not need raising. The reservation is about *placement*, not level: ECS refuses to delete a non-empty cluster, so this fires at the **end** of a sequence whose first steps are unalerted or rated P3. A correct severity on the wrong event; the §2 correlation is what fixes it |
| MITRE Tactics | Stealth (TA0005) |
| MITRE Techniques | T1070 (primary), T1578.003 (secondary) — both verified live 2026-08-29 |
| Services in Scope | ECS, CloudTrail, CloudWatch (`AWS/ECS`, and CloudWatch Logs wherever the task log driver pointed), IAM, EC2 (container instances and their Auto Scaling groups), Organizations (SCP), plus every workload the cluster hosted |

**What the technique does:** the actor scales the cluster's services to zero with `UpdateService`
(`requestParameters.desiredCount: 0`), deletes them with `DeleteService`, deregisters EC2
container instances with `DeregisterContainerInstance`, removes capacity providers, and only
then calls `DeleteCluster` with a single `requestParameters.cluster` value. That ordering is
not a choice: AWS refuses otherwise — *"You must deregister all container instances from this
cluster before you may delete it"* — throwing `ClusterContainsServicesException`,
`ClusterContainsTasksException`, `ClusterContainsContainerInstancesException` or
`ClusterContainsCapacityProviderException` until the cluster is empty, with error text naming
the sequence outright: *"You can't delete a cluster that contains services. First, update the
service to reduce its desired task count to 0, and then delete the service."* The cluster goes
`INACTIVE`, and its settings, tags and capacity-provider associations survive only in
infrastructure code. If the actor then calls `CreateCluster` with the same `clusterName`, the
deleted cluster's tagged stopped-task records stop being retrievable — AWS documents that.

**Detection thesis.** The discriminator is **the calling principal** — `DeleteCluster` is what
every teardown does and the event carries no other separating field — but the useful *signal*
is the precursor chain, because a successful deletion proves the damage is already done. The
source rule reads neither: it matches the event name with a `threshold: > 0` that any count
satisfies, and never looks at `userIdentity.arn`.

> The services destroyed on the way here are `../ecs.stealth.service-is-deleted/`; the
> scale-to-zero that must precede them is the blind side of
> `../ecs.impact.updateservice-with-high-desiredcount/`.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing ECS **management** events. AWS: *"Amazon Elastic
  Container Service logs all Amazon ECS control plane operations as management events"*, and
  management events are logged by default, so `lookup-events` returns them. `DeleteCluster`
  carries exactly one request parameter, `cluster`, documented as *"the short name or full
  Amazon Resource Name (ARN)"* — a **caller-typed** value that arrives in either form and must
  be normalised before any comparison. The response is **nested**:
  `responseElements.cluster.*`, with `status` becoming `INACTIVE`
- The `responseElements.cluster` counts (`runningTasksCount`, `activeServicesCount`,
  `registeredContainerInstancesCount`) are **zero by construction on a successful call** — ECS
  would have refused otherwise — and inform only on a **denied** call, where they record how
  populated the cluster was when the attempt was made
- ECS has **no `AWS::ECS::Task` data event type**; the only documented ECS data events are
  `ecs:Poll`, `ecs:StartTelemetrySession` and `ecs:PutSystemLogEvents` under
  `AWS::ECS::ContainerInstance`, off by default. Nothing in CloudTrail records what ran inside
  a task, so container logs must be retained wherever the task definition's log driver sent
  them. An `awslogs` log group is an independent resource and is not deleted with the cluster —
  AWS does not say so in those words, so verify it rather than assuming it
- **Cluster configuration in infrastructure code** — after a deletion, IaC is the only place the
  settings (including Container Insights), tags, default capacity provider strategy and
  `executeCommandConfiguration` still exist — plus a baseline of which principals own cluster
  lifecycle, in most accounts one deployment role and one break-glass role

**Alerting (must be pre-configured)**
- **`DeleteCluster` succeeding for a principal outside the cluster-lifecycle allowlist → P0**
- **A teardown precursor followed by `DeleteCluster` from the same principal within 60 minutes → P0**
- **`DeleteCluster` followed within 30 minutes by `CreateCluster` from the same principal → P1**
- **`DeleteCluster` denied with any `ClusterContains*` code → P1**

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
| P0 | `DeleteCluster` succeeding for a principal not on the cluster-lifecycle allowlist | CloudTrail (management) | T1070 |
| P0 | A teardown precursor (`UpdateService desiredCount:0`, `DeleteService`, `DeregisterContainerInstance`, `StopTask`, `DeleteCapacityProvider`) then `DeleteCluster`, same principal, within 60 minutes | CloudTrail (management) | T1489 → T1070 |
| P1 | `DeleteCluster` then `CreateCluster` by the same principal within 30 minutes, same normalised cluster name | CloudTrail (management) | T1070 |
| P1 | `DeleteCluster` denied `ClusterContainsServicesException` / `...TasksException` / `...ContainerInstancesException` / `...CapacityProviderException` — an attempt against a **populated** cluster | CloudTrail (management) | T1578.003 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `UpdateService` with `requestParameters.desiredCount: 0` on a production service outside a deploy window — the mandatory first move, and the source set alerts on it nowhere | CloudTrail (management) | T1489 |
| P3 | `DeleteCluster` denied `AccessDeniedException` / `NotAuthorized` — permission probing, not destruction | CloudTrail (management) | T1578.003 |

### Detection Rule Quality Notes

The source rule matches an event name, applies a threshold that cannot fail, and never asks
who called.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `threshold: > 0` over a 10-minute window, grouped by `userIdentity.arn` | Any count above zero satisfies `> 0`, so this is a per-event rule with a ten-minute batching delay bolted on. It is a volume rule expressing no volume, and the delay is pure cost on a P1 | Drop the pseudo-threshold; fire per event on the principal filter |
| No principal check | Fires on every ephemeral test-stack destroy and every Terraform apply that removes a cluster. Where cluster lifecycle belongs to a pipeline, the caller is the entire signal and the rule does not read it | Allowlist the cluster-lifecycle roles; alert on everyone else |
| Alerts on the last link in the chain, and nothing covers the precursors — no rule on `UpdateService desiredCount:0`, `DeregisterContainerInstance`, `StopTask` or `DeleteCapacityProvider`, and `DeleteService` only at **P3** | ECS refuses to delete a non-empty cluster, so this fires only after the services are deleted and the tasks stopped. Triage begins with the damage complete, and the mandatory precursors are invisible or rated two priorities below the cleanup that follows them | Ship the precursor base rule and the `temporal_ordered` correlation, so the alert arrives carrying the sequence; raise the `DeleteService` row (`../ecs.stealth.service-is-deleted/`) |
| Nothing covers delete-then-recreate | Reusing the cluster name makes the deleted cluster's tagged stopped tasks unretrievable — AWS documents this — and produces two ordinary events and no alert | Ship the second `temporal_ordered` correlation; confirm the name match in the KQL |

**Recommended detection — a cluster deleted by a principal outside the lifecycle pipeline.**

```yaml
# ECS Cluster Deleted (T1070 / T1578.003)
#
# WHAT THE SOURCE RULE DOES NOT DO. It matches `eventName:"DeleteCluster"` with a success
# filter, at P1, with `threshold: > 0` inside a ten-minute window grouped by
# `userIdentity.arn`. Any count above zero satisfies "> 0", so the threshold and window buy
# nothing except a ten-minute batching delay on a P1 alert. It never looks at WHO called, so
# every ephemeral test-stack teardown and every Terraform destroy fires it.
#
# THE FACT THAT REFRAMES THIS ENTIRE TECHNIQUE. Amazon ECS REFUSES to delete a non-empty
# cluster. AWS: "You must deregister all container instances from this cluster before you may
# delete it", and the API throws ClusterContainsContainerInstancesException,
# ClusterContainsServicesException, ClusterContainsTasksException and
# ClusterContainsCapacityProviderException. The error text is explicit: "You can't delete a
# cluster that contains services. First, update the service to reduce its desired task count
# to 0, and then delete the service." So a SUCCESSFUL DeleteCluster is proof that the cluster
# was already emptied — the destruction happened in the preceding UpdateService
# (desiredCount 0), DeleteService and DeregisterContainerInstance calls, and the cluster
# deletion is the tidy-up behind them. Alerting on DeleteCluster alone therefore fires on the
# LAST event of the chain, after everything is already gone. Rule 1 below still ships,
# because the deletion is the event that reliably exists; the correlation is what gives a
# responder the chain, and the base rule is what makes the precursors visible at all.
#
# WHY THIS IS INDICATOR REMOVAL AND NOT DATA DESTRUCTION. What the call destroys is a record:
# the cluster's settings (including whether Container Insights was on), its tags, its
# capacity-provider associations, and — through a documented side effect — the ability to
# retrieve stopped tasks later. AWS: "If you have tasks with tags, and then delete the
# cluster, the tagged tasks are returned in the response. If you create a new cluster with
# the same name as the deleted cluster, the tagged tasks are not included in the response."
# Delete-then-recreate under the same name is therefore a supported, documented way to make
# the task history unreachable, and it is the shape the second correlation looks for.
#
# FIELD SHAPE. `DeleteCluster` carries exactly one request parameter, `cluster`, and AWS
# documents it as "The short name or full Amazon Resource Name (ARN) of the cluster to
# delete" — so the value is CALLER-TYPED and may be either form. `CreateCluster` names the
# cluster in `clusterName`. The two events therefore identify the same cluster through
# different fields in different formats, which is why the correlation groups by principal and
# `kql_t1070.kql` does the name join after normalising both to a bare name. Both calls return
# the object NESTED: `responseElements.cluster.*`, with `status` = `INACTIVE` after deletion.
title: ECS cluster deleted by a principal outside the cluster-lifecycle pipeline
id: ab91a150-dbb2-4f3a-ae92-2a26d28fdaae
name: ecs_cluster_deleted_nonpipeline
status: experimental
description: >-
  An ECS cluster was deleted by a principal that does not own cluster lifecycle. Because ECS
  refuses to delete a cluster that still contains services, tasks or registered container
  instances, a successful deletion proves the cluster was emptied first — the destructive
  work is already complete and this event is the end of the chain, not the start of it.
references:
  - https://attack.mitre.org/techniques/T1070/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DeleteCluster.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/logging-using-cloudtrail.html  # retrieved 2026-08-29
tags:
  - attack.stealth
  - attack.t1070
  - attack.t1578.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecs.amazonaws.com'
    eventName: 'DeleteCluster'
  # POPULATE BEFORE DEPLOYING. Unpopulated, this fires on every pipeline teardown. The
  # allowlist IS the discriminator - DeleteCluster carries no field that separates a
  # destructive deletion from a scheduled one.
  cluster_lifecycle_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace with this account's deployment role
      - ':role/BreakGlassAdmin'     # replace with this account's break-glass role
  success:
    errorCode: null
  condition: selection and success and not cluster_lifecycle_pipeline
falsepositives:
  - >-
    An engineer destroying a personal or ephemeral cluster outside the pipeline. Expected in
    development accounts; in a production account it is the finding, because it means cluster
    lifecycle is not owned by the pipeline.
level: high
---
# Base rule — sequence component only, not for direct alerting. These are the calls that MUST
# succeed before a DeleteCluster can succeed, and the source set alerts on none of them
# except DeleteService. `UpdateService` with `desiredCount: 0` is the scale-to-zero AWS names
# explicitly in its own error text, and it is the single most important uncovered precursor:
# the source set's only UpdateService rule fires on a HIGH desiredCount and is structurally
# blind to zero, which is the destructive direction.
#
# eventName and the desiredCount test are deliberately SEPARATE sibling blocks. Keys inside
# one block are ANDed, and `eventName: DeleteService` could never co-occur with
# `desiredCount: 0` on a single event.
title: ECS cluster teardown precursor
id: c2ec0873-1f59-40fd-b3fd-541edb279eb7
name: ecs_cluster_teardown_precursor_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DeleteService.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateService.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1489
logsource:
  product: aws
  service: cloudtrail
detection:
  svc:
    eventSource: 'ecs.amazonaws.com'
  teardown:
    eventName:
      - 'DeleteService'
      - 'DeregisterContainerInstance'
      - 'StopTask'
      - 'DeleteCapacityProvider'
  scale_to_zero_event:
    eventName: 'UpdateService'
  scale_to_zero_value:
    requestParameters.desiredCount: 0
  success:
    errorCode: null
  condition: svc and success and (teardown or (scale_to_zero_event and scale_to_zero_value))
level: informational
---
# Base rule — sequence component only, not for direct alerting. Carries the success filter so
# a denied CreateCluster cannot compose into the high-severity correlation below.
title: ECS cluster created
id: 8dcaafd9-fff2-4a95-934d-5768209dd074
name: ecs_cluster_created_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateCluster.html  # retrieved 2026-08-29
tags:
  - attack.stealth
  - attack.t1070
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecs.amazonaws.com'
    eventName: 'CreateCluster'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
# The full teardown chain by one principal. This is the document that actually carries the
# incident: a DeleteCluster on its own tells you the cluster is gone, while this tells you the
# same principal emptied it first and how.
#
# TIMESPAN BASIS. Sixty minutes, and the basis is service drain rather than an arbitrary
# round number. AWS documents a deleted service moving ACTIVE -> DRAINING -> INACTIVE "after
# all tasks have transitioned to either STOPPING or STOPPED status", and DeleteCluster keeps
# throwing ClusterContainsTasksException until that completes, so the actor is forced to wait
# out the drain between the precursor and the deletion. An hour spans a slow drain on a
# service with a long deregistration delay without spanning unrelated maintenance. Re-baseline
# against your own longest observed drain before deploying.
title: ECS cluster emptied and then deleted by one principal
id: c20a2356-3612-4090-817e-31d6d07eea3a
status: experimental
description: >-
  One principal ran the teardown calls that empty a cluster and then deleted the cluster,
  inside an hour. ECS will not delete a non-empty cluster, so this is the complete
  destruction sequence rather than its final event, and the work-list for recovery is every
  service and task named in the precursor group.
references:
  - https://attack.mitre.org/techniques/T1070/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DeleteCluster.html  # retrieved 2026-08-29
tags:
  - attack.stealth
  - attack.t1070
  - attack.impact
  - attack.t1489
correlation:
  type: temporal_ordered
  rules:
    - ecs_cluster_teardown_precursor_bb
    - ecs_cluster_deleted_nonpipeline
  group-by:
    - userIdentity.arn
  timespan: 60m
level: high
---
# Delete-then-recreate under the same cluster name is ANTI-FORENSICS, and AWS documents the
# mechanism rather than leaving it to inference: "If you have tasks with tags, and then delete
# the cluster, the tagged tasks are returned in the response. If you create a new cluster with
# the same name as the deleted cluster, the tagged tasks are not included in the response."
# So the recreate is what makes the task history unreachable, and it is the step a responder
# can still get in front of.
#
# The correlation groups by principal and NOT by cluster name, because DeleteCluster names the
# cluster in `requestParameters.cluster` (short name OR full ARN, caller's choice) while
# CreateCluster names it in `requestParameters.clusterName`. Sigma cannot join across two
# field names, let alone across two formats. Confirm the name match by hand, or use the KQL,
# which normalises both sides to a bare name and joins on it.
title: ECS cluster deleted and a cluster created by the same principal
id: a48c260f-092c-4012-a151-10aacf0ec2bb
status: experimental
description: >-
  One principal deleted a cluster and created a cluster within thirty minutes. If the names
  match, the stopped-task records that survived the deletion are now unreachable, and the
  cluster's own history has been replaced by an empty resource wearing its name.
references:
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTasks.html  # retrieved 2026-08-29
tags:
  - attack.stealth
  - attack.t1070
correlation:
  type: temporal_ordered
  rules:
    - ecs_cluster_deleted_nonpipeline
    - ecs_cluster_created_bb
  group-by:
    - userIdentity.arn
  timespan: 30m
level: high
```

The rule cannot say what was destroyed — the response counts are zero on every success by
construction, and no ECS data event records what ran inside a task. Nor can it join deletion to
recreation on the cluster name, because `DeleteCluster` uses `requestParameters.cluster` (short
name *or* ARN, caller's choice) and `CreateCluster` uses `requestParameters.clusterName`.
`detections/kql_t1070.kql` normalises both sides, does that join, counts the precursors, and
splits denials into `ClusterContains*` versus access denials.

---

### Key Investigation Queries

> ECS is regional — run these in the cluster's region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: the whole teardown chain, not just the deletion

```bash
REGION="us-east-1"
RAW=$(for EV in DeleteCluster CreateCluster DeleteService UpdateService \
                DeregisterContainerInstance StopTask DeleteCapacityProvider; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region,"
  echo "    or missing cloudtrail:LookupEvents. This is NOT 'no clusters were deleted'."
else
  # DeleteCluster/DeleteService/UpdateService name the cluster in requestParameters.cluster,
  # which AWS documents as "the short name or full ARN" - caller-typed, so it arrives in
  # either form. CreateCluster names it in clusterName. Both are reduced to cluster_name
  # here so the halves of the chain line up.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "ecs.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller_arn: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     cluster_name: ((.requestParameters.clusterName //
                     .requestParameters.cluster // "") | split("/") | last),
     target: (.requestParameters.service // .requestParameters.containerInstance //
              .requestParameters.task // .requestParameters.capacityProvider // null),
     desired_count: (.requestParameters.desiredCount // null),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.time)'
fi
```

Read it as a sequence, per `cluster_name`. A `DeleteCluster` with `error` = `SUCCESS`
guarantees everything above it in that cluster's timeline already succeeded — the `target`
values are the recovery work-list and nothing else records them. `UpdateService` rows with
`desired_count` = `0` are the scale-to-zero; a large `desired_count` is the opposite technique
(`../ecs.impact.updateservice-with-high-desiredcount/`). A `CreateCluster` on the same
`cluster_name` after the deletion is name reuse, and a differing `caller_arn` is worse than
reuse. Any `ClusterContains*` error is an attempt on a cluster that was still populated —
more urgent than a successful deletion of an empty one, not less. Record `cluster_name`,
`caller_arn` and `access_key` as IOCs.

#### Query 2 — Inspect: what state is each named cluster in now

```bash
REGION="us-east-1"; CLUSTER_NAME="<cluster-name-from-Query-1>"

# describe-clusters does NOT error for a deleted cluster. It returns HTTP 200 with the
# cluster absent from .clusters and a .failures entry whose reason is MISSING, and the CLI
# exits 0. Four states must be separated, and "the call did not run" is one of them.
OUT=$(aws ecs describe-clusters --clusters "$CLUSTER_NAME" --region "$REGION" \
        --include SETTINGS TAGS --output json)
if [ -z "$OUT" ]; then
  echo "[!] INCONCLUSIVE - describe-clusters produced no output: failed call, wrong region or"
  echo "    missing ecs:DescribeClusters. This is NOT 'the cluster is fine'."
else
  NCL=$(printf '%s' "$OUT" | jq '.clusters | length')
  STATUS=$(printf '%s' "$OUT" | jq -r '.clusters[0].status // empty')
  REASON=$(printf '%s' "$OUT" | jq -r '.failures[0].reason // "none-returned"')
  if   [ "$NCL" -eq 0 ] && [ "$REASON" = "MISSING" ]; then
    echo "[FAIL] $CLUSTER_NAME is MISSING - deleted and no longer discoverable at all"
  elif [ "$NCL" -eq 0 ]; then
    echo "[!] INCONCLUSIVE - no cluster returned and the failure reason was '$REASON', which"
    echo "    is not MISSING. The call did not answer the question; do not read it as absence."
  elif [ "$STATUS" = "INACTIVE" ]; then
    echo "[FAIL] $CLUSTER_NAME is INACTIVE - deleted, still discoverable for now. AWS warns"
    echo "    against relying on INACTIVE clusters persisting, so capture evidence NOW."
  else
    printf '%s' "$OUT" | jq -r '.clusters[0] |
      "[i] status=\(.status) services=\(.activeServicesCount) tasks=\(.runningTasksCount) " +
      "insights=" + ((.settings // [] | map(select(.name=="containerInsights")) | .[0].value) // "unset")'
  fi
fi

```

This is the block that decides whether you are looking at an incident or a recovered system,
and every branch is reachable — including the ones meaning "I could not tell", which is why
they print `INCONCLUSIVE` rather than folding into the clean path. `MISSING` and `INACTIVE`
are both `[FAIL]`, and they are different failures: `INACTIVE` means the record is still
readable and §3 Step 1 can still capture it, while `MISSING` means it is not.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="DeleteCapacityProvider DeleteService DeregisterContainerInstance StopTask"
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

The deletion cannot be undone, so containment is about the evidence and the next cluster.
**Capture first, contain second, rebuild last** — and do not rebuild under the deleted
cluster's name until the capture is done, because AWS documents that creating a cluster with
that name makes its tagged stopped tasks stop being returned. This ordering is the one thing
here that cannot be repaired if it is got wrong.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Preserve what is about to age out, and freeze the name

```bash
REGION="us-east-1"; CLUSTER_NAME="<cluster-name-from-Query-1>"
EVID="./ecs-incident-$CLUSTER_NAME-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || { echo "[FAIL] cannot create evidence directory $EVID"; exit 1; }

# An INACTIVE cluster still carries its settings and tags, and may not tomorrow. The
# CloudTrail export preserves the chain past the 90-day Event history window.
aws ecs describe-clusters --clusters "$CLUSTER_NAME" --region "$REGION" \
  --include SETTINGS TAGS CONFIGURATIONS ATTACHMENTS --output json > "$EVID/cluster.json"
aws cloudtrail lookup-events --region "$REGION" \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" --output json \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=ecs.amazonaws.com \
  > "$EVID/cloudtrail-ecs.json"
# PERISHABLE, and this is why the step is first. AWS: "stopped tasks appear in the returned
# results for at least one hour" - a floor, not a guarantee - and creating a cluster with the
# deleted cluster's name makes its TAGGED stopped tasks stop being returned. taskDefinitionArn
# and the image list are the only surviving statement of what was running.
TASK_ARNS=$(aws cloudtrail lookup-events --region "$REGION" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopTask \
  --start-time "$(date -u -d '2 days ago' +%Y-%m-%dT%H:%M:%SZ)" --output json |
  jq -r --arg c "$CLUSTER_NAME" '.Events[].CloudTrailEvent | fromjson |
    select(((.requestParameters.cluster // "") | split("/") | last) == $c) |
    .requestParameters.task // empty' | sort -u | head -100 | tr '\n' ' ')
if [ -z "$TASK_ARNS" ]; then
  echo "[!] no StopTask events for $CLUSTER_NAME - the tasks were probably stopped by the"
  echo "    service scale-down, which emits no per-task event. Not an absence of tasks."
else
  aws ecs describe-tasks --cluster "$CLUSTER_NAME" --region "$REGION" --tasks $TASK_ARNS \
    --include TAGS --output json > "$EVID/stopped-tasks.json"
fi

# -s, not exit status: every call above exits 0 while writing nothing if it was refused.
for F in cluster.json cloudtrail-ecs.json stopped-tasks.json; do
  if [ -s "$EVID/$F" ]; then echo "[OK] captured $F ($(wc -c < "$EVID/$F") bytes)"
  else echo "[!] INCONCLUSIVE - $F is empty or absent; that evidence was NOT captured"; fi
done

echo "[i] DO NOT run 'aws ecs create-cluster --cluster-name $CLUSTER_NAME' until the above"
echo "    capture reports [OK]: creating a cluster with the deleted cluster's name makes its"
echo "    tagged tasks stop being returned by DescribeTasks."
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ecs:DeleteCluster","ecs:CreateCluster","ecs:DeleteService","ecs:UpdateService","ecs:DeregisterContainerInstance","ecs:StopTask","ecs:DeleteCapacityProvider"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyEcsTeardown" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyEcsTeardown" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied ECS teardown for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or"
     echo "    a service principal. Contain manually; neither branch above applies.";;
esac
```

The session revocation kills tokens issued before `$CUTOFF` and nothing else — a credential
re-fetched afterwards carries a newer `aws:TokenIssueTime` and is unaffected. The `Deny` is
what stops the next deletion.

---

## 4. Eradication

### Remove Attacker Access

- **Rebuild the cluster from infrastructure code, and only after §3 Step 1's capture has
  completed.** A recreated cluster is bare — no Container Insights setting, no tags, no default
  capacity provider strategy, no `executeCommandConfiguration` — and those exist nowhere but
  IaC, or nowhere at all if the cluster was configured through the console.
- **The precursor targets from Query 1 are the work-list**, not the cluster. Each service has to
  be recreated with its task definition, network configuration and IAM roles; the cluster itself
  is one API call.
- **Re-register the container instances or recreate the capacity provider.** A deregistered
  instance keeps billing while belonging to nothing, and deleting a capacity provider does not
  touch the Auto Scaling group behind it.
- **Right-size the permission.** `ecs:DeleteCluster` is needed by no workload at runtime, and
  neither are `ecs:DeleteService`, `ecs:DeregisterContainerInstance` or
  `ecs:DeleteCapacityProvider`. Only whatever owns cluster lifecycle needs them.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
# A principal that is neither user nor role must reach INCONCLUSIVE, never the clean branch.
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyEcsTeardown EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyEcsTeardown"
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

#### Verify the rebuilt cluster is ACTIVE, in this account, and carries its settings

```bash
REGION="us-east-1"; CLUSTER_NAME="<cluster-name-from-Query-1>"
ACCT=$(aws sts get-caller-identity --query Account --output text)

OUT=$(aws ecs describe-clusters --clusters "$CLUSTER_NAME" --region "$REGION" \
        --include SETTINGS TAGS --output json)
if [ -z "$OUT" ]; then
  echo "[!] INCONCLUSIVE - describe-clusters produced no output; the rebuild is unverified,"
  echo "    not verified-bad. Fix the call before reading anything into this."
  exit 0
fi
NCL=$(printf '%s' "$OUT" | jq '.clusters | length')
REASON=$(printf '%s' "$OUT" | jq -r '.failures[0].reason // "none returned"')
if [ "$NCL" -eq 0 ]; then
  # MISSING is a 200-with-a-failure, not an error - the single easiest false [OK] here.
  echo "[FAIL] $CLUSTER_NAME not describable (failure reason: $REASON) - NOT rebuilt"; exit 0
fi
STATUS=$(printf '%s' "$OUT" | jq -r '.clusters[0].status // empty')
ARN=$(printf '%s' "$OUT" | jq -r '.clusters[0].clusterArn // empty')
INSIGHTS=$(printf '%s' "$OUT" | jq -r '.clusters[0].settings // [] |
             map(select(.name=="containerInsights")) | .[0].value // "unset"')
SVCS=$(printf '%s' "$OUT" | jq -r '.clusters[0].activeServicesCount // -1')
if   [ -z "$ARN" ] || [ -z "$STATUS" ]; then
  echo "[!] INCONCLUSIVE - the cluster was returned without a status or ARN; unreadable"
elif [ "$STATUS" != "ACTIVE" ]; then
  echo "[FAIL] $CLUSTER_NAME status is $STATUS, not ACTIVE"
elif ! printf '%s' "$ARN" | grep -q ":${ACCT}:"; then
  echo "[FAIL] $CLUSTER_NAME belongs to account $(printf '%s' "$ARN" | awk -F: '{print $5}'), not $ACCT"
elif [ "$INSIGHTS" = "unset" ] || [ "$INSIGHTS" = "disabled" ]; then
  echo "[FAIL] $CLUSTER_NAME is back but Container Insights is '$INSIGHTS' - the IaC apply"
  echo "    did not restore the cluster settings, so the rebuild is partial"
elif [ "$SVCS" -eq 0 ]; then
  echo "[FAIL] $CLUSTER_NAME is ACTIVE with 0 services - the cluster was recreated but the"
  echo "    services from Query 1's precursor list were not"
else
  echo "[OK] $CLUSTER_NAME ACTIVE in $ACCT, insights=$INSIGHTS, $SVCS active service(s)"
fi
```

Every branch is reachable *after* the remediation: the cluster exists again, so
`describe-clusters` has something to return, and the two partial rebuilds that actually happen
— back without its settings, back without its services — land on `[FAIL]` rather than being
certified clean. `MISSING` is handled explicitly because it arrives as HTTP 200 with exit code
0 and reads as success to any check that only tests whether the command ran.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     DeleteCluster / ecs.amazonaws.com / no errorCode, where"
echo "  userIdentity.arn is NOT on the cluster-lifecycle allowlist. The precursor correlation"
echo "  must fire when UpdateService(desiredCount=0) or DeleteService by the same principal"
echo "  precedes it within 60 minutes; the reuse correlation on CreateCluster within 30."
echo "MUST NOT fire on: DeleteCluster by the pipeline role during a stack teardown; a"
echo "  DeleteCluster that returned ClusterContainsServicesException or AccessDeniedException"
echo "  (an attempt, not a deletion - those belong on the P1 and P3 rows instead)."
echo "EXPECTED FP, by design: an engineer destroying a personal or ephemeral cluster outside"
echo "  the pipeline. Common in development accounts; if it is common in production, the"
echo "  finding is that cluster lifecycle is not owned by the pipeline."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the pipeline could scale services to zero, delete them and then delete the cluster | `ecs:UpdateService`, `ecs:DeleteService` and `ecs:DeleteCluster` granted to an identity that needs none of them at runtime; no SCP confining cluster lifecycle |
| The alert arrived after the destruction was complete | The only rule in the set fires on `DeleteCluster`, which ECS refuses until the cluster is already empty. The precursors were unalerted, except `DeleteService` at P3 |
| Nobody could say what had been running | The `responseElements.cluster` counts are zero on every successful deletion by construction, and stopped-task records survive only "at least one hour" |
| The rebuilt cluster came back without Container Insights, tags or capacity providers | Cluster configuration lived in the console rather than in infrastructure code, so a recreate produced a bare resource |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the value is wildcarded: Deny + StringNotEquals against
// a wildcarded ARN matches every principal and denies cluster lifecycle outright - an outage,
// not a bypass.
{
  "Effect": "Deny",
  "Action": ["ecs:DeleteCluster", "ecs:DeleteService",
             "ecs:DeregisterContainerInstance", "ecs:DeleteCapacityProvider"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- All four are real ECS IAM actions. The SCP reaches the caller because ECS control-plane
  calls always come from an in-organisation principal in the cluster's own account; an SCP
  would be the wrong instrument only for an external principal, which this technique does not
  involve.
- Hold cluster settings, tags, capacity providers and `executeCommandConfiguration` in IaC, and
  set a CloudWatch Logs retention on the task log groups that outlives your response — the log
  group is the one artifact of a destroyed task that does not live on the cluster.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1070 — Indicator Removal (primary); T1578.003 — Modify Cloud Compute Infrastructure: Delete Cloud Instance (secondary) |
| Primary API | `ecs:DeleteCluster`, preceded necessarily by `ecs:UpdateService` (`desiredCount: 0`), `ecs:DeleteService`, `ecs:DeregisterContainerInstance`; `ecs:CreateCluster` as the second half of a name reuse |
| Event source | `ecs.amazonaws.com`, **management** plane, regional — AWS: *"logs all Amazon ECS control plane operations as management events"*, and management events are on by default |
| Key discriminator | The calling principal. The event carries no field separating destruction from teardown; the *precursor chain* is what carries the incident |
| Field shape | `DeleteCluster`: `requestParameters.cluster` only — **caller-typed**, short name or full ARN. Response **nested** at `responseElements.cluster.*`, `status` → `INACTIVE`. `CreateCluster`: `requestParameters.clusterName`, response also nested |
| "Was it used" pivot | Not applicable — the deletion *is* the outcome. The measurable question is what was destroyed, answered only by the precursor `target` list from Query 1 and by `describe-tasks` on stopped tasks within their "at least one hour" floor |
| Blast radius | The cluster record, its settings (including Container Insights), tags, capacity-provider associations and `executeCommandConfiguration`; and, once the name is reused, the retrievability of its tagged stopped tasks. The tasks and services themselves were destroyed by the precursors |
| Error strings | `AccessDeniedException`, `ClientException`, `ClusterContainsCapacityProviderException`, `ClusterContainsContainerInstancesException`, `ClusterContainsServicesException`, `ClusterContainsTasksException`, `ClusterNotFoundException`, `InvalidParameterException`, `ServerException`, `UpdateInProgressException`. ECS also documents `NotAuthorized` (HTTP 401) in its Common Errors as a second denial form. There is no bare `AccessDenied` in ECS's documented set |

**MITRE mapping note.** The source rule labels this **T1578** under **TA0005**, and both are
live — the parent is defensible and the tactic right, so this is imprecision, not staleness.
The precise sub-technique is **T1578.003 (Delete Cloud Instance)**: deleting infrastructure
after malicious activity to remove evidence. **T1070 (Indicator Removal)** is the primary
because the call destroys a record rather than a workload. **T1485** and **T1489** map to the
*precursors* and are tagged on the precursor base rule rather than here, which keeps the
mapping honest about which event does which thing.

### Residual Risk

The cluster's configuration is unrecoverable unless it was in infrastructure code, and a
rebuild from memory differs in ways nobody notices until an incident needs Container Insights
data that was never re-enabled. What ran inside the destroyed tasks stays unknown: there is no
ECS data event for task execution, stopped-task records survive only "at least one hour" by
AWS's own floor, and if the name was reused before you arrived the tagged ones are already
unretrievable. Deregistered container instances may still be running and billing while
belonging to no cluster. The precursor list is bounded by CloudTrail retention — 90 days in
Event history — so an incident found later than that has no recoverable work-list at all.
