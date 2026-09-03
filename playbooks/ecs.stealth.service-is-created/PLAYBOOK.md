# IR Playbook: ECS Service Created — Self-Restarting Attacker Workload via `ecs:CreateService`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Execution / Persistence (a service is created that keeps a chosen container image running under a chosen IAM role, restarting it whenever it stops) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, against the source's **P3**. A service is durable execution: ECS maintains `desiredCount` tasks and replaces any that stop, so the workload survives every containment action short of scaling or deleting it. It runs under whatever `taskRoleArn` the referenced task definition names, on subnets and security groups the actor chose, and — if `assignPublicIp` is `ENABLED` — with a routable address. P3 is defensible only in a development account where engineers deploy by hand, and the fix there is the principal allowlist, not a lower priority |
| MITRE Tactics | Execution (TA0002), Persistence (TA0003) |
| MITRE Techniques | T1610 (primary), T1053.007 (secondary) — both verified live 2026-08-29 |
| Services in Scope | ECS, ECR (or whatever registry the image came from), IAM (task role, execution role, `iam:PassRole`), CloudTrail, EC2 (subnets, security groups, public addressing), CloudWatch Logs, Organizations (SCP) |

**What the technique does:** the actor calls `RegisterTaskDefinition` with a `family`, a
`containerDefinitions[]` array naming an `image` and optionally a `command`, `entryPoint`,
`environment` and `secrets`, and a top-level `taskRoleArn` — that call is where the payload is.
They then call `CreateService` with `serviceName`, `cluster`, `taskDefinition`, `desiredCount`,
a `launchType` and `networkConfiguration.awsvpcConfiguration.{subnets,securityGroups,assignPublicIp}`.
ECS begins maintaining the invariant immediately: `desiredCount` tasks running, each replaced if
it stops. The tasks assume the task role and can read its temporary credentials from the
container credentials endpoint at `169.254.170.2`, so the service is not just compute — it is
compute holding an AWS identity.

**Detection thesis.** The discriminator is **the calling principal**: `CreateService` carries no
field distinguishing a deployment from an intrusion, because the image, command and role are all
in the referenced task definition. The source rule reads neither the principal nor the
definition — it matches the event name and the absence of an error code, at P3, and fires on
every deployment in the account.

> The scaling of this service afterwards is
> `../ecs.impact.updateservice-with-high-desiredcount/`; a service created with
> `enableExecuteCommand: true` hands the actor the shell in
> `../ecs.initial-access.command-executed-inside-a-container/`.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing ECS **management** events — AWS logs *"all Amazon ECS
  control plane operations as management events"*, on by default, so `lookup-events` returns both
  `CreateService` and `RegisterTaskDefinition`
- `CreateService` request fields, with their real nesting: `requestParameters.serviceName`,
  `.cluster` (short name **or** ARN — caller-typed), `.taskDefinition` (`family`,
  `family:revision` **or** ARN — also caller-typed), `.desiredCount`, `.launchType`,
  `.enableExecuteCommand`, and the three-level
  `.networkConfiguration.awsvpcConfiguration.{subnets,securityGroups,assignPublicIp}` — a flat
  `requestParameters.assignPublicIp` is `null` on every event. Response **nested** at
  `responseElements.service.*`
- `RegisterTaskDefinition` is where the payload is: `requestParameters.containerDefinitions[]`
  carries `image`, `command`, `entryPoint`, `environment`, `secrets`, `privileged`, `user` and
  `linuxParameters`, with `taskRoleArn`, `executionRoleArn`, `networkMode` and `pidMode`
  top-level. **Without this event the blast radius of a created service is unknown**
- ECS has **no `AWS::ECS::Task` data event type**; the only documented ECS data events are
  `ecs:Poll`, `ecs:StartTelemetrySession` and `ecs:PutSystemLogEvents` under
  `AWS::ECS::ContainerInstance`, off by default. Nothing in CloudTrail records what a container
  did, so the task definition's log driver is the only container-level visibility
- A baseline of the task definition **families** that legitimately exist, of which principals
  deploy services, and of the `iam:PassRole` grants on the task roles — an actor who cannot pass
  a role cannot attach a privileged task role to a definition they register

**Alerting (must be pre-configured)**
- **`CreateService` succeeding for a principal outside the service-lifecycle allowlist → P0**
- **`RegisterTaskDefinition` then `CreateService` by the same non-pipeline principal within 30 minutes → P0**
- **Three or more `CreateService` successes by one non-pipeline principal within 10 minutes → P1**
- **`CreateService` with `assignPublicIp: ENABLED` by a non-pipeline principal → P1**

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
| P0 | `CreateService` succeeding for a principal not on the service-lifecycle allowlist | CloudTrail (management) | T1610 |
| P0 | `RegisterTaskDefinition` then `CreateService` by the same non-pipeline principal within 30 minutes — the actor brought their own workload | CloudTrail (management) | T1610 |
| P1 | Three or more `CreateService` successes by one non-pipeline principal within 10 minutes | CloudTrail (management) | T1610 |
| P1 | `CreateService` with `networkConfiguration.awsvpcConfiguration.assignPublicIp: ENABLED` by a non-pipeline principal | CloudTrail (management) | T1610 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `CreateService` with `enableExecuteCommand: true` — interactive shell access built in at creation | CloudTrail (management) | T1609 |
| P3 | `CreateService` denied `AccessDeniedException` / `NotAuthorized` / `ClusterNotFoundException` — permission and topology probing | CloudTrail (management) | T1610 |

### Detection Rule Quality Notes

The source rule matches an event name and a success filter, and reads none of the fields that
make one service creation different from another.

| Issue | Impact | Correction |
|-------|--------|-----------|
| No principal check, and none of the request parameters read | Fires on every deployment of every new service. Where deployment belongs to a pipeline the caller is the entire signal, and `assignPublicIp`, `enableExecuteCommand`, `desiredCount`, `launchType`, the subnets and the security groups are all present in the event and all unused | Allowlist the service-lifecycle roles; add the exposure rule, ungated on principal, on `assignPublicIp: ENABLED` or `enableExecuteCommand: true` |
| Never reaches the task definition | The image, the command and `taskRoleArn` — the entire blast radius — are in a `RegisterTaskDefinition` event the rule set does not correlate to. Triage starts with a service name and no idea what it runs | Ship the `temporal_ordered` register-then-create correlation; resolve the family in the KQL |
| P3, mapped to T1578/TA0005 | The cloud-native equivalent of installing a self-restarting service on a host, triaged below a configuration change and labelled as infrastructure evasion rather than execution | High; T1610 primary with T1053.007 for the restart property |

**Recommended detection — a service created by a principal outside the deployment pipeline.**

```yaml
# ECS Service Created (T1610 / T1053.007)
#
# WHAT THE SOURCE RULE DOES NOT DO. It matches `eventName:"CreateService"` with a success
# filter and nothing else, at P3, mapped to T1578 under TA0005. It fires on every deployment
# of every new service in the account, it never looks at who called, and it reads none of the
# fields that make one CreateService different from another. P3 is also the wrong level for an
# event that is the cloud-native equivalent of installing a service on a host.
#
# CREATE SERVICE IS A POINTER, NOT A PAYLOAD. This is the fact the rule has to be built
# around. `CreateService` names `taskDefinition` — a family:revision string or an ARN — and
# carries NO image, NO command and NO role. The image, the entrypoint, the environment, the
# secrets and `taskRoleArn` all live in the task definition registered by a SEPARATE
# `RegisterTaskDefinition` call. So the blast radius of a created service is not in the event
# that creates it, and any rule that inspects only `CreateService` is inspecting the wrapper.
# The `temporal_ordered` correlation below pairs the two calls, which is the shape of an actor
# deploying their own workload: register a definition pointing at their image, then create a
# service that keeps it running.
#
# WHY A SERVICE AND NOT A TASK. `RunTask` launches tasks that run once and stay dead. A
# SERVICE is a maintained invariant: ECS keeps `desiredCount` tasks running and replaces any
# that stop. Killing the attacker's containers therefore achieves nothing until the service is
# scaled or deleted — which is why this is persistence (T1053.007, Container Orchestration
# Job) as much as it is execution (T1610, Deploy Container), and why the response ordering in
# ../PLAYBOOK.md §3 is scale-then-stop rather than stop-then-scale.
#
# THE TWO FIELDS THAT ARE IN THE EVENT AND WORTH READING.
# `requestParameters.networkConfiguration.awsvpcConfiguration.assignPublicIp` — AWS documents
# the valid values as ENABLED|DISABLED and the default for create-service as DISABLED, so an
# ENABLED value is an explicit choice to give the task a public address. And
# `requestParameters.enableExecuteCommand` — a service created with ECS Exec already on is a
# service built for interactive access (see
# ../../ecs.initial-access.command-executed-inside-a-container/). Rule 2 reads both, and it is
# deliberately NOT gated on the principal allowlist: a pipeline role creating a public,
# exec-enabled service is a finding about the pipeline.
title: ECS service created by a principal outside the service-lifecycle pipeline
id: 6061e915-0afb-474b-a293-70d1d60f96f7
name: ecs_service_created_nonpipeline
status: experimental
description: >-
  A service was created by a principal that does not deploy services. An ECS service is a
  maintained invariant — the scheduler keeps desiredCount tasks running and replaces any that
  stop — so this is durable execution, not a one-off run, and the image and task role it
  carries are in the referenced task definition rather than in this event.
references:
  - https://attack.mitre.org/techniques/T1610/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateService.html  # retrieved 2026-08-29
tags:
  - attack.execution
  - attack.t1610
  - attack.persistence
  - attack.t1053.007
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecs.amazonaws.com'
    eventName: 'CreateService'
  # POPULATE BEFORE DEPLOYING. Unpopulated, this fires on every deployment. The allowlist IS
  # the discriminator - CreateService carries no field that separates a deployment from an
  # attacker's workload, because the image and role are in the task definition, not here.
  service_lifecycle_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace with this account's deployment role
      - ':role/BreakGlassAdmin'     # replace with this account's break-glass role
  success:
    errorCode: null
  condition: selection and success and not service_lifecycle_pipeline
falsepositives:
  - >-
    An engineer deploying a service by hand outside the pipeline. Expected in development
    accounts; in production it is the finding, because it means service deployment is not
    owned by the pipeline.
level: high
---
# Not gated on the principal: a service created with a public IP or with ECS Exec already
# turned on is worth a look whoever created it, and a pipeline that emits either by default is
# itself the finding. The two blocks are SIBLINGS and ORed - they can co-occur, but requiring
# both would miss the single-condition cases, which are the common ones.
title: ECS service created with a public address or with ECS Exec enabled
id: ca06763b-a1a9-4d50-8d3c-a73833748376
name: ecs_service_created_exposed
status: experimental
description: >-
  A service was created whose tasks receive a public IP address, or with execute-command
  functionality enabled on every container in the service. AWS documents assignPublicIp as
  defaulting to DISABLED for create-service, so ENABLED is an explicit choice; enabling ECS
  Exec at creation builds interactive shell access into the service from the start.
references:
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_AwsVpcConfiguration.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html  # retrieved 2026-08-29
tags:
  - attack.execution
  - attack.t1610
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecs.amazonaws.com'
    eventName: 'CreateService'
  public_ip:
    requestParameters.networkConfiguration.awsvpcConfiguration.assignPublicIp: 'ENABLED'
  exec_enabled:
    requestParameters.enableExecuteCommand: true
  success:
    errorCode: null
  condition: selection and success and (public_ip or exec_enabled)
falsepositives:
  - >-
    Public-facing services in a public subnet without a NAT gateway legitimately set
    assignPublicIp ENABLED. Baseline which services do so; the alert is for the ones that
    are new.
level: medium
---
# Base rule — sequence component only, not for direct alerting. This is where the image, the
# command, the environment, the secrets and taskRoleArn actually are. Carries the success
# filter so a rejected registration cannot compose into the correlation below.
title: ECS task definition registered
id: f7b09142-c323-45df-b877-9f7664aec946
name: ecs_task_definition_registered_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RegisterTaskDefinition.html  # retrieved 2026-08-29
tags:
  - attack.execution
  - attack.t1610
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
# Register-then-create is an actor bringing their OWN workload, and it is the shape that
# matters most here. A deployment pipeline does this too — which is exactly why the
# CreateService half is the principal-filtered rule rather than a bare event match.
#
# TIMESPAN BASIS. Thirty minutes. A definition is registered and the service referencing it is
# created in the same operation, usually seconds apart; half an hour absorbs a slow apply and
# a retry without spanning an unrelated deployment later in the day.
title: ECS task definition registered and a service created by the same principal
id: 6510438f-fafb-41f1-a793-b3b900f3676f
status: experimental
description: >-
  One non-pipeline principal registered a task definition and then created a service from it
  inside thirty minutes. The task definition is where the image, entrypoint, environment,
  secrets and task role are; the service is what keeps them running and restarts them.
references:
  - https://attack.mitre.org/techniques/T1610/  # retrieved 2026-08-29
tags:
  - attack.execution
  - attack.t1610
  - attack.persistence
  - attack.t1053.007
correlation:
  type: temporal_ordered
  rules:
    - ecs_task_definition_registered_bb
    - ecs_service_created_nonpipeline
  group-by:
    - userIdentity.arn
  timespan: 30m
level: high
---
# Threshold basis, because a number without one is an invented number. There is no observed
# baseline here, so the reasoning is structural: ECS allows 5,000 services per cluster, so the
# quota is no constraint and cannot supply a threshold. What can is the shape of the work —
# a person deploying by hand outside the pipeline creates one service and then watches it,
# while three or more inside ten minutes is machine-paced, and the one process that
# legitimately does that is the pipeline, which the base rule already excludes. `gte` at the
# baseline, never `gt`, so a run that creates exactly three does not fall through.
# Re-baseline against your own account before deploying.
title: ECS services created at volume by one non-pipeline principal
id: 6ac58c04-5c18-4ae1-8b4c-1189b3dc4309
status: experimental
description: >-
  One principal outside the deployment pipeline created three or more services inside ten
  minutes. Each service independently maintains its own task count, so the eradication
  work-list is every service in the group and stopping tasks accomplishes nothing.
references:
  - https://docs.aws.amazon.com/general/latest/gr/ecs-service.html  # retrieved 2026-08-29
tags:
  - attack.execution
  - attack.t1610
correlation:
  type: event_count
  rules:
    - ecs_service_created_nonpipeline
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gte: 3
level: high
```

The rule cannot say what the service runs: `CreateService` names a task definition and carries no
image, no command and no role, so it fires on the wrapper while the payload sits in an event it
never sees. `detections/kql_t1610.kql` joins the two on the task definition **family** —
normalising the `family:revision` and full-ARN forms first, since a raw string join silently
drops half the events — and surfaces the image, `taskRoleArn`, `privileged` and `pidMode: host`.

---

### Key Investigation Queries

> ECS is regional — run these in the service's region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: what was created, on what network, from which definition

```bash
REGION="us-east-1"
RAW=$(for EV in CreateService RegisterTaskDefinition; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region,"
  echo "    or missing cloudtrail:LookupEvents. This is NOT 'no services were created'."
else
  # taskDefinition is caller-typed - "family", "family:revision" or a full ARN - so it is
  # reduced to the bare FAMILY here, which is the only form the two event types share.
  # assignPublicIp is THREE levels deep; a flat path returns null on every event.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "ecs.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller_arn: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     service: .requestParameters.serviceName,
     cluster: ((.requestParameters.cluster // "") | split("/") | last),
     task_family: ((.requestParameters.family //
                    ((.requestParameters.taskDefinition // "") | split("/") | last))
                   | split(":") | first),
     desired_count: .requestParameters.desiredCount,
     launch_type: .requestParameters.launchType,
     exec_enabled: .requestParameters.enableExecuteCommand,
     public_ip: .requestParameters.networkConfiguration.awsvpcConfiguration.assignPublicIp,
     sgs: .requestParameters.networkConfiguration.awsvpcConfiguration.securityGroups,
     task_role: .requestParameters.taskRoleArn,
     images: [(.requestParameters.containerDefinitions // [])[] | .image],
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.time)'
fi
```

Pair the rows by `task_family`. A `RegisterTaskDefinition` from the same `caller_arn` just
before a `CreateService` on the same family is the bring-your-own-workload shape, and its
`images` and `task_role` are what everything else depends on. `public_ip` = `ENABLED` is an
explicit choice — AWS documents `DISABLED` as the `create-service` default — and with a
permissive `sgs` entry it means the container is internet-reachable. A `CreateService` whose
`task_family` has **no** registration in the window is not clean: the definition predates the
window, and Query 2 resolves it. Record `service`, `cluster`, `task_family`, `caller_arn` and
`access_key` as IOCs.

#### Query 2 — Inspect: resolve the task definition to its image, its role, and that role's reach

```bash
REGION="us-east-1"; TASK_FAMILY="<task-family-from-Query-1>"

# The blast radius is not in the CreateService event. It is here, and it is an IAM lookup
# beyond that. describe-task-definition takes family, family:revision or an ARN.
TD=$(aws ecs describe-task-definition --task-definition "$TASK_FAMILY" --region "$REGION" \
       --output json)
if [ -z "$TD" ]; then
  echo "[!] INCONCLUSIVE - describe-task-definition returned nothing. The definition may have"
  echo "    been deregistered, or the call failed. This is NOT 'the service runs nothing.'"
else
  printf '%s' "$TD" | jq '.taskDefinition |
    {family, revision, status, network_mode: .networkMode, pid_mode: (.pidMode // "unset"),
     task_role: (.taskRoleArn // "none"), execution_role: (.executionRoleArn // "none"),
     containers: [.containerDefinitions[] |
       {name, image, command: (.command // null), entryPoint: (.entryPoint // null),
        privileged: (.privileged // false), user: (.user // null),
        added_caps: (.linuxParameters.capabilities.add // []),
        secrets: [(.secrets // [])[] | .valueFrom],
        log_driver: (.logConfiguration.logDriver // "none")}]}'
fi

# The task role IS the blast radius. A task can read this role's temporary credentials from
# the ECS container credentials endpoint at 169.254.170.2 - the container analogue of
# ../ec2.credential-access.imds-credential-theft/, at a DIFFERENT address.
ROLE_ARN=$(printf '%s' "${TD:-}" | jq -r '.taskDefinition.taskRoleArn // empty')
if [ -z "$ROLE_ARN" ]; then
  echo "[i] no taskRoleArn. On Fargate the containers hold no AWS identity. On EC2 they may:"
  echo "    AWS documents that with no task role configured, the underlying container"
  echo "    instance's role is used instead - so check that instance profile."
else
  ROLE=$(printf '%s' "$ROLE_ARN" | awk -F'/' '{print $NF}')
  INLINE=$(aws iam list-role-policies --role-name "$ROLE" --query 'PolicyNames' --output json)
  ATTACHED=$(aws iam list-attached-role-policies --role-name "$ROLE" \
               --query 'AttachedPolicies[].PolicyArn' --output json)
  if [ -z "$INLINE" ] || [ -z "$ATTACHED" ]; then
    echo "[!] INCONCLUSIVE - could not enumerate policies on $ROLE; blast radius unknown, not empty"
  else
    echo "[i] task role $ROLE  inline=$INLINE  attached=$ATTACHED - read these BEFORE §3:"
    echo "    the role outlives the service, and its reach is what the actor's reach was."
  fi
fi
```

Check `images` against your registry first — an image from outside your own accounts, or a
mutable `:latest` tag, is a finding on its own. `privileged: true`, `pid_mode: host` and any
`added_caps` entry mean the container was built to reach past its own boundary.
`secrets[].valueFrom` names every secret the task was allowed to pull, and those must be treated
as read. The task role's policies answer "what did this have access to", and must be captured
**before** §3 — the role outlives the service, but the question gets harder once the evidence is
torn down.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="CreateService RegisterTaskDefinition"
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

**Scale the service to zero before stopping any task.** This ordering is the whole point: a
service is a maintained invariant, so `stop-task` on a running container simply causes the
scheduler to start a replacement, and a responder who stops tasks first will conclude the
containment failed. Set `desiredCount` to `0`, confirm the tasks drain, and only then contain
the principal — containing first is defensible too, but leaves the workload running while you
work.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Scale to zero, then confirm the tasks are actually gone

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; SERVICE="<service-from-Query-1>"

OUT=$(aws ecs update-service --cluster "$CLUSTER" --service "$SERVICE" \
        --desired-count 0 --region "$REGION" --output json)
if [ -z "$OUT" ]; then
  echo "[!] INCONCLUSIVE - update-service returned nothing; the service was NOT scaled down."
  echo "    Do not proceed to stop tasks: they will be replaced."
else
  echo "[OK] desiredCount set to $(printf '%s' "$OUT" | jq -r '.service.desiredCount')"
fi

# describe-services does NOT error for an absent service: it returns HTTP 200 with .services
# empty and a .failures reason of MISSING, exit code 0. A wrong CLUSTER, by contrast, DOES
# throw ClusterNotFoundException. §5 separates all four states; here we only need the counts.
D=$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
      --region "$REGION" --output json)
if [ -z "$D" ] || [ "$(printf '%s' "$D" | jq '.services | length')" -eq 0 ]; then
  echo "[!] INCONCLUSIVE - no service description returned. Not 'contained' - go to §5."
else
  printf '%s' "$D" | jq -r '.services[0] |
    "[i] status=\(.status) desired=\(.desiredCount) running=\(.runningCount) pending=\(.pendingCount)"'
  echo "    Tasks drain asynchronously - re-run until running and pending are both 0."
fi
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ecs:CreateService","ecs:UpdateService","ecs:RunTask","ecs:StartTask","ecs:RegisterTaskDefinition","ecs:ExecuteCommand","iam:PassRole"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyEcsDeploy" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyEcsDeploy" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied ECS deployment for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or"
     echo "    a service principal. Contain manually; neither branch above applies.";;
esac
```

`iam:PassRole` is in the deny list deliberately: without it the principal cannot attach a task
role to a new definition, which removes the ability to recreate the workload with any identity
worth having.

---

## 4. Eradication

### Remove Attacker Access

- **Delete the service after it is scaled to zero.** AWS: *"You can delete a service if you have
  no running tasks in it and the desired task count is zero."* The `force` parameter waives that
  precondition and is documented as necessary only for `REPLICA` services — it is **not**
  documented as terminating running tasks, so do not rely on it to drain them.
- **Deregister the task definition revision**, or the workload is recreatable in one call.
  Deregistering marks the revision `INACTIVE`; it does not delete the image, which stays in
  whatever registry it came from and remains pullable.
- **Treat every secret in `containerDefinitions[].secrets[].valueFrom` as read.** The tasks ran
  long enough to pull them; rotation is the only remediation, and deleting the service is not.
- **The task role outlives the service.** Its credentials were readable from inside the container
  at `169.254.170.2`, are valid for six hours by AWS's documented default, and self-renew while a
  task runs. Treat its recent activity as suspect — the same reasoning as
  `../ec2.credential-access.imds-credential-theft/`, at a different address.
- **Right-size the permissions.** `ecs:CreateService`, `ecs:RegisterTaskDefinition` and
  `iam:PassRole` on task roles belong to the pipeline and to nothing at runtime.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
# A principal that is neither user nor role must reach INCONCLUSIVE, never the clean branch.
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyEcsDeploy EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyEcsDeploy"
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

#### Verify the service is gone and nothing of it is still running

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; SERVICE="<service-from-Query-1>"

# The trap this check exists to avoid: describe-services returns HTTP 200 for a service that
# does not exist, with .services empty and a .failures entry whose reason is MISSING. The CLI
# exits 0. `if aws ecs describe-services ...; then echo "[OK]"` therefore passes on a deleted
# service AND on a live one, and passes identically when the call is refused.
D=$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
      --region "$REGION" --output json)
if [ -z "$D" ]; then
  echo "[!] INCONCLUSIVE - describe-services produced no output. A bad CLUSTER throws"
  echo "    ClusterNotFoundException (a real error) and a permissions failure looks the same."
  echo "    The service's state is unknown, not clean."
  exit 0
fi
NS=$(printf '%s' "$D" | jq '.services | length')
REASON=$(printf '%s' "$D" | jq -r '.failures[0].reason // "none returned"')
if [ "$NS" -eq 0 ]; then
  if [ "$REASON" = "MISSING" ]; then
    echo "[OK] $SERVICE is MISSING in $CLUSTER - deleted and purged from ECS record keeping"
  else
    echo "[!] INCONCLUSIVE - no service returned, failure reason '$REASON' is not MISSING."
    echo "    The call did not answer the question; do not read it as removal."
  fi
  exit 0
fi
STATUS=$(printf '%s' "$D" | jq -r '.services[0].status // empty')
DESIRED=$(printf '%s' "$D" | jq -r '.services[0].desiredCount // -1')
RUNNING=$(printf '%s' "$D" | jq -r '.services[0].runningCount // -1')
PENDING=$(printf '%s' "$D" | jq -r '.services[0].pendingCount // -1')
if [ -z "$STATUS" ] || [ "$RUNNING" -lt 0 ]; then
  echo "[!] INCONCLUSIVE - the service was returned without a status or task counts"
elif [ "$STATUS" = "ACTIVE" ]; then
  echo "[FAIL] $SERVICE is still ACTIVE (desired=$DESIRED running=$RUNNING pending=$PENDING)"
  echo "    - it was scaled but never deleted, and a desiredCount change restarts it"
elif [ "$RUNNING" -ne 0 ] || [ "$PENDING" -ne 0 ]; then
  echo "[FAIL] $SERVICE is $STATUS but still has running=$RUNNING pending=$PENDING - the"
  echo "    tasks have not finished draining, so the workload is still executing"
else
  echo "[OK] $SERVICE is $STATUS with no running or pending tasks"
fi
```

Every branch stays reachable after the remediation, which is why the check runs against
`describe-services` rather than something the deletion removed: the API keeps answering for
`DRAINING` and `INACTIVE` services, so `[FAIL]` remains reachable for the two outcomes that
actually happen — scaled but never deleted, and deleted but still draining. AWS's note that
`INACTIVE` services *"may be cleaned up and purged from Amazon ECS record keeping"* with
`DescribeServices` then returning `ServiceNotFoundException` is why `MISSING` is a pass.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     CreateService / ecs.amazonaws.com / no errorCode, where"
echo "  userIdentity.arn is NOT on the service-lifecycle allowlist. The register-then-create"
echo "  correlation must fire when the same principal registered the definition first; the"
echo "  volume correlation at exactly three creations in ten minutes - gte, not gt."
echo "MUST NOT fire on: CreateService by the pipeline role during a normal deploy; a"
echo "  CreateService that returned AccessDeniedException or UnsupportedFeatureException."
echo "EXPECTED FP, by design: the exposure rule is NOT gated on the principal, so a pipeline"
echo "  creating a public-facing service in a public subnet fires it. Baseline which services"
echo "  legitimately set assignPublicIp ENABLED; a new one is worth a look whoever made it."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the pipeline could register a task definition and create a service from it | `ecs:RegisterTaskDefinition`, `ecs:CreateService` and `iam:PassRole` granted to an identity that needs none of them at runtime |
| The workload survived the first containment attempt | A service maintains its task count and replaces stopped tasks; stopping containers before scaling to zero has no lasting effect |
| Triage began without knowing what the service ran | The image, command and task role are in `RegisterTaskDefinition`, and no rule correlated the two events |
| The container held an AWS identity | A task role was passed to a definition an untrusted principal registered; its credentials are readable from inside the container at `169.254.170.2` |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the value is wildcarded: Deny + StringNotEquals against
// a wildcarded ARN matches every principal and blocks all deployment - an outage, not a bypass.
{
  "Effect": "Deny",
  "Action": ["ecs:CreateService", "ecs:RegisterTaskDefinition", "ecs:RunTask"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- All three are real ECS IAM actions. Pair the SCP with an `iam:PassRole` deny scoped to the
  task roles — `PassRole` is the control that matters, because a definition registered without a
  role gives the actor compute with no AWS identity.
- Keep task definitions in IaC, pin images by **digest** rather than a mutable tag, and set a log
  driver on every container definition: without one there is no container-level record at all.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1610 — Deploy Container (primary); T1053.007 — Container Orchestration Job (secondary, for the maintained-invariant property) |
| MITRE tactic | Execution (TA0002), Persistence (TA0003) |
| Primary API | `ecs:CreateService`, preceded by `ecs:RegisterTaskDefinition` and gated by `iam:PassRole` |
| Event source | `ecs.amazonaws.com`, **management** plane, regional — management events are on by default |
| Key discriminator | The calling principal, plus `assignPublicIp` and `enableExecuteCommand`. What the service *runs* is not in this event at all |
| Field shape | `requestParameters.networkConfiguration.awsvpcConfiguration.assignPublicIp` — **three levels deep**, `ENABLED`/`DISABLED`, default `DISABLED`. `.cluster` and `.taskDefinition` are **caller-typed** (short name, `family:revision` or ARN). Response **nested** at `responseElements.service.*` |
| "Was it used" pivot | `runningCount` and the `deployments[]` array on `describe-services`; the task role's own activity in CloudTrail, whose role session name is the task ID |
| Blast radius | Whatever the referenced task definition's `taskRoleArn` can reach, every secret in `containerDefinitions[].secrets[].valueFrom`, and the network the chosen subnets and security groups place the tasks on |
| Error strings | `AccessDeniedException`, `ClientException`, `ClusterNotFoundException`, `InvalidParameterException`, `NamespaceNotFoundException`, `PlatformTaskDefinitionIncompatibilityException`, `PlatformUnknownException`, `ServerException`, `UnsupportedFeatureException`; plus `NotAuthorized` (HTTP 401) from ECS's Common Errors. No bare `AccessDenied` exists in ECS's documented set |

**MITRE mapping note.** Both IDs are live, so this is not staleness — but unlike
the cluster-deletion case the mapping is wrong on the merits, not merely coarse. Creating a
service is not an infrastructure modification made to evade detection; it is the deployment of a
workload. **T1610 (Deploy Container)** under Execution is the corrected primary, and
**T1053.007 (Container Orchestration Job)** under Persistence is carried because an ECS service
is a scheduler that restarts what it runs — the property that makes stopping tasks useless and
that the source's mapping does not express at all.

### Residual Risk

The image is still in whatever registry it came from and still pullable, and deregistering a task
definition marks the revision `INACTIVE` without deleting anything. The task role still exists
with the same permissions, and credentials the containers read from `169.254.170.2` stay valid
until they expire — six hours by AWS's documented default, and deleting the service does not
shorten that. Every secret the definition could pull must be assumed read: the tasks ran, and no
ECS data event would show whether they did. If the definition was registered before the
CloudTrail window, whoever created it is unknown; if the containers ran with no log driver there
is no record of their behaviour anywhere. And `CreateService` is only one way to run a container
— `RunTask` and scheduled tasks remain available to a principal whose deny policy did not name
them.
