# IR Playbook: Command Executed Inside an ECS Container — Root Shell and Task-Role Credentials via `ecs:ExecuteCommand`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Execution + Credential access (an interactive session is opened as root inside a running container, from which the task role's temporary AWS credentials are readable) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, P0 once task-role activity is observed after the session. The session runs as the `root` user regardless of the container definition's `user`, and the container holds an AWS identity whose credentials are valid for six hours and self-renew while the task lives. Severity tracks the task role's permissions, so a role with IAM, Secrets Manager or broad data access makes this account-level rather than container-level. The source rates it **P2** — but the priority is the smaller problem, because the rule carrying it **cannot fire at all** (§2) |
| MITRE Tactics | Execution (TA0002), Credential Access (TA0006) |
| MITRE Techniques | T1609 (primary), T1552.005 (secondary), T1613 (enumeration variant) — all verified live 2026-08-29 |
| Services in Scope | ECS, SSM (Session Manager, `ssmmessages`), IAM + STS (task role, execution role, container instance role), CloudTrail, CloudWatch Logs, S3 (session log destination), KMS, EC2 (container instances), Organizations (SCP), plus every service the task role can reach |

**What the technique does:** the actor calls `ecs:ExecuteCommand` with `cluster`, `task`,
`container` and a `command`. ECS Exec is built on SSM Session Manager — AWS: *"This is made
possible by bind-mounting the necessary SSM agent binaries into the container"* — and the
resulting session executes inside the running container as the **`root` user**, which AWS states
happens *"even when you specify a user ID for the container"*. From that shell the actor reads
the task role's temporary credentials from the ECS container credentials endpoint at
`169.254.170.2`, using the relative path the agent injects as
`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`; the response carries `RoleArn`, `AccessKeyId`,
`SecretAccessKey`, `Token` and `Expiration`, and AWS documents those credentials as valid for
**six hours** and rotated automatically. Nothing is installed and nothing is modified. The
container keeps working; the actor now holds an AWS credential and a root shell.

**Why the usual reflexes miss it.** Read the command out of CloudTrail — the field *is* there,
unredacted — and AWS is explicit about the limit: *"if you open an interactive shell section only
the `/bin/bash` command is logged in CloudTrail but not all the others inside the shell."* Go to
the ECS Exec session log, and the default produces none: `logging: DEFAULT` means *"the `awslogs`
configuration in the task definition is used"*, and *"if no `awslogs` log driver is configured in
the task definition, the output won't be logged."* Check IMDS hardening, and IMDSv2 protects
`169.254.169.254` — a different address from the one this technique reads. Stop the task, and you
destroy the only record of what it was: AWS retains stopped tasks *"for at least one hour"*, after
which the task ID no longer resolves to a definition, an image or a role.

**Detection is the task ID, joined to the role session name it becomes.** An ECS task-role
session carries the **task ID as its role session name** — AWS's example ARN ends in a 32-hex
task ID, described as the role name *"followed by the name of the task"* — and that is the same
string `ExecuteCommand` puts in `requestParameters.task`. So every API call made with credentials
stolen from a container names, in its own ARN, the container they came from, and the join between
the Exec event and that session is the whole incident. The source rule reaches none of it: it
requires `userIdentity.accountId` to equal the literal string `anonymous`, which no
IAM-authorised ECS call ever carries, so it has never fired and never will.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail capturing ECS **management** events. AWS logs *"all Amazon ECS
  control plane operations as management events"*, on by default, so `lookup-events` returns
  `ExecuteCommand`, `UpdateService` and `RegisterTaskDefinition`
- `ExecuteCommand` request fields — **exactly five**: `requestParameters.cluster`, `.command`,
  `.container`, `.interactive`, `.task`. The response is **nested**: `responseElements.clusterArn`,
  `.containerArn`, `.containerName`, `.interactive`, `.taskArn`, and
  `.session.{sessionId, streamUrl, tokenValue}`. `tokenValue` is redacted and the redaction string
  differs between AWS's ECS and SSM examples — test for the presence of
  `responseElements.session.sessionId`, never for the placeholder text. **`interactive` is not a
  discriminator**: it is required, and the CLI supports only the interactive form, so
  `interactive: true` is on essentially every event
- **ECS Exec session logging, configured in advance.** The cluster's
  `configuration.executeCommandConfiguration.logging` must be `OVERRIDE` with a `logConfiguration`
  naming `cloudWatchLogGroupName` and/or `s3BucketName`. `DEFAULT` — the value used when nothing
  is specified — records nothing unless the task definition independently carries an `awslogs`
  driver, the write permissions live on the **task role** rather than the execution role, and even
  a correct `OVERRIDE` produces nothing if the image lacks `script` and `cat`
- For calls made **with a task role**, `userIdentity.arn` is
  `arn:aws:sts::<acct>:assumed-role/<TaskRole>/<taskId>` — the session name is the task ID, and it
  is the join key for this entire playbook. CloudTrail also documents `userIdentity.inScopeOf`
  (`sourceArn`, `sourceAccount`, `issuerType`, `credentialsIssuedTo`) for requests *"made in scope
  of an AWS service, such as Lambda or Amazon ECS"*, but publishes no ECS example — confirm its
  shape against a real event before building on it
- SSM data events on `AWS::SSMMessages::ControlChannel` (`CreateControlChannel`,
  `OpenControlChannel`) for the channel-level record — **off by default**. Whether an ECS Exec
  session also emits an `ssm.amazonaws.com` `StartSession` **management** event is **not
  documented and could not be verified**; do not build a correlation on one. ECS itself has **no
  `AWS::ECS::Task` data event type**, so container output exists only where the task definition's
  log driver sent it

**Alerting (must be pre-configured)**
- **`ExecuteCommand` succeeding for a principal outside the debugging allowlist → P0**
- **API activity under a role session name equal to the `task` ID of a preceding `ExecuteCommand` → P0**
- **`enableExecuteCommand: true` then `ExecuteCommand` by the same principal within 60 minutes → P0**
- **`ExecuteCommand` whose `command` invokes a shell binary → P1**
- **One principal running `ExecuteCommand` against three or more distinct tasks within 30 minutes → P1**

**Response Tooling**
- AWS CLI v2 with the **Session Manager plugin** — `aws ecs execute-command` will not run without
  it, and neither will any responder verification that needs to enter a container
- `jq`, and **break-glass credentials that are not any task role and not the principal under
  investigation**: containment revokes sessions on a role, and doing that from a session that role
  issued locks the responder out
- A **holding place for evidence off the cluster** (the stopped-task record ages out in about an
  hour), and the **IAM policy documents of every task role** pulled ahead of time — that is the
  blast radius and it is in no event on this path

**Known IOC Baselines**
- The named **debugging role or roles** that legitimately use ECS Exec, and the ticket each
  session should trace to. In most accounts this is one role and a handful of people, and that set
  is the entire discriminator
- Which clusters have `executeCommandConfiguration.logging` set to `OVERRIDE` and where those logs
  land; and which services carry `enableExecuteCommand: true` in their desired state. Anything
  Exec-enabled and not on that list was enabled by someone
- The **egress addresses** each task set calls AWS from — NAT gateway EIPs or the VPC endpoint. A
  task-role session calling from anything else is off-container use

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ExecuteCommand` succeeding for a principal not on the debugging allowlist | CloudTrail (management) | T1609 |
| P0 | API activity by an assumed-role session whose session name equals the `task` ID of a preceding `ExecuteCommand` — the container's credentials in use | CloudTrail (management) | T1552.005 |
| P0 | `enableExecuteCommand: true` on `UpdateService`/`RunTask`/`CreateService`, then `ExecuteCommand`, same principal, within 60 minutes | CloudTrail (management) | T1609 |
| P1 | `ExecuteCommand` whose `command` contains a shell binary — session contents are not in CloudTrail | CloudTrail (management) | T1609 |
| P1 | One principal running `ExecuteCommand` against three or more distinct `task` values within 30 minutes | CloudTrail (management) | T1609 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `ExecuteCommand` failing `TargetNotConnectedException` across several tasks — a search for one that is Exec-enabled | CloudTrail (management) | T1613 |
| P2 | `CreateCluster` or `UpdateCluster` setting `executeCommandConfiguration.logging` to `NONE`, or removing an `OVERRIDE` destination | CloudTrail (management) | T1685.002 |
| P2 | `ExecuteCommand` denied `AccessDeniedException` — note this also occurs when a *correct* scoped policy's condition key does not match the request | CloudTrail (management) | T1609 |
| P3 | `ssm:StartSession` targeting an ECS task — the path AWS documents as producing no ECS-side log at all | CloudTrail (management, `ssm.amazonaws.com`) | T1609 |

### Detection Rule Quality Notes

The source rule does not fire. Not "fires too often", not "fires imprecisely" — it contains a
conjunct that no event on this path can satisfy.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `userIdentity.accountId:"anonymous"` | CloudTrail documents `accountId` as *"the account that owns the entity that granted permissions for the request"* and enumerates no `anonymous` value. ECS has no unauthenticated API surface — `ExecuteCommand` is SigV4-signed and IAM-authorised — so `accountId` is a twelve-digit account ID on every event. **The rule has never fired and cannot.** It produces no error and no alert, which looks identical to an account where nobody uses ECS Exec | Remove the conjunct entirely; discriminate on the calling principal against a named debugging allowlist |
| No coverage of the shell case | A one-shot `command` is fully recorded; an interactive session records only `/bin/bash`. Those need different handling and the rule distinguishes neither | Ship a separate shell rule, ungated on principal, so an unrecorded session is always surfaced |
| No coverage of the enablement, and no link to the task role | Exec cannot be turned on for existing tasks, so an actor must set `enableExecuteCommand` and force a deployment first — two high-signal events alerted on nowhere. And the event names a task and no role, so the credential the session yields and everything it then does is invisible | Ship the base rule and the `temporal_ordered` correlation; join the `task` ID to the role session name in the KQL and carry the P0 row |
| Denials not separated | With the rule inert this is moot, but the corrected rule must not count `TargetNotConnectedException` sweeps as sessions | Separate `medium` rule for the failure codes |
| P2 | Interactive root access to a running container, triaged below a configuration change | High, P0 once task-role use follows |

**Recommended detection — an ECS Exec session opened by a principal outside the debugging allowlist.**

```yaml
# Command Executed Inside an ECS Container — ECS Exec (T1609 / T1552.005)
#
# THE SOURCE RULE CANNOT FIRE. Its query is
# `eventSource:"ecs.amazonaws.com" AND eventName:"ExecuteCommand" AND
#  userIdentity.accountId:"anonymous" AND NOT _exists_:errorCode`.
# CloudTrail documents `userIdentity.accountId` as "the account that owns the entity that
# granted permissions for the request", and enumerates no `anonymous` value for it. ECS has no
# unauthenticated API surface: ExecuteCommand is a SigV4-signed call authorised by IAM, so
# `accountId` is a twelve-digit account ID on every event this rule could ever see. The
# conjunct is never satisfied. This is a P2 rule providing ZERO coverage of interactive shell
# access to running containers, and it is the most consequential defect in this ECS set.
#
# WHAT ECS EXEC ACTUALLY GRANTS. AWS: "ECS Exec makes use of AWS Systems Manager (SSM) Session
# Manager to establish a connection with the running container... This is made possible by
# bind-mounting the necessary SSM agent binaries into the container." The commands "are run as
# the `root` user" regardless of the container definition's `user`. And the container holds an
# AWS identity: a task with a task role can read that role's temporary credentials from the
# ECS container credentials endpoint at 169.254.170.2 - NOT the EC2 IMDS address, and NOT the
# 169.254.170.23 used by EKS Pod Identity - via the AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
# environment variable the agent injects. So one ExecuteCommand is execution and credential
# access in the same call. See ../../ec2.credential-access.imds-credential-theft/ for the
# EC2 analogue of the second half.
#
# THE COMMAND IS LOGGED, BUT NOT THE ONE THAT MATTERS. `requestParameters.command` is present
# and NOT redacted - AWS's own published CloudTrail extract shows `"command": "ls"` in the
# clear. But AWS is equally explicit about the limit: "if you open an interactive shell section
# only the `/bin/bash` command is logged in CloudTrail but not all the others inside the
# shell." So a one-shot command is fully recorded and an interactive session records only the
# shell binary. Rule 2 below exists because that is the case where CloudTrail stops being
# evidence, and the transcript exists only if ECS Exec session logging was configured - which
# it is NOT by default (see the detection note).
#
# `interactive` IS NOT A DISCRIMINATOR. It is a REQUIRED request parameter and the AWS CLI's
# execute-command only supports the interactive form, so `interactive: true` appears on
# essentially every event. Do not build a rule on it.
#
# FIELD SHAPE. requestParameters: cluster, command, container, interactive, task - those five
# and no others. responseElements is NESTED: clusterArn, containerArn, containerName,
# interactive, taskArn, and session.{sessionId, streamUrl, tokenValue}. The token is redacted;
# the redaction STRING differs between AWS's ECS example and its SSM example, so test for the
# presence of responseElements.session.sessionId rather than matching the placeholder text.
title: ECS Exec session opened on a running container
id: 62227799-79a3-4412-9468-45a1802faae7
name: ecs_exec_session_opened
status: experimental
description: >-
  A principal opened an ECS Exec session into a running container. The command runs as root
  inside the container and can read the task role's temporary credentials from the container
  credentials endpoint, so this is interactive execution and credential access in one call.
references:
  - https://attack.mitre.org/techniques/T1609/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ExecuteCommand.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html  # retrieved 2026-08-29
tags:
  - attack.execution
  - attack.t1609
  - attack.credential-access
  - attack.t1552.005
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecs.amazonaws.com'
    eventName: 'ExecuteCommand'
  # POPULATE BEFORE DEPLOYING. ECS Exec is a debugging tool: in most accounts a small, named
  # set of engineers uses it and everyone else never does. That set IS the discriminator.
  break_glass_debug:
    userIdentity.arn|contains:
      - ':role/OnCallDebug'         # replace with this account's debugging role
      - ':role/BreakGlassAdmin'     # replace with this account's break-glass role
  success:
    errorCode: null
  condition: selection and success and not break_glass_debug
falsepositives:
  - >-
    On-call debugging by an engineer outside the named role. Should be rare and traceable to
    an incident or a ticket; if it is routine, the finding is that production debugging is not
    going through a controlled role.
level: high
---
# NOT gated on the principal, deliberately. This is the case where CloudTrail stops being
# evidence: AWS documents that for an interactive shell "only the /bin/bash command is logged
# in CloudTrail but not all the others inside the shell." Whoever opens a shell, the account
# needs to know a session exists whose contents are unrecorded unless ECS Exec logging was
# configured in advance - and `logging: DEFAULT`, which is the default, records nothing unless
# the task definition independently configures an awslogs driver.
#
# `|contains` is substring matching, so this catches "/bin/bash -c ..." and "sh" inside a
# longer command line. It will also match a legitimate command that merely mentions a shell -
# that over-match is intended, because the cost of missing an unrecorded shell session is
# higher than the cost of reading one extra event.
title: ECS Exec used to open a shell inside a container
id: c9ac6234-2c40-4f1b-98ce-c01a926cade4
name: ecs_exec_shell_invoked
status: experimental
description: >-
  An ECS Exec session invoked a shell rather than a single command. CloudTrail records the
  shell binary and nothing that was typed inside it, so the content of this session exists only
  in ECS Exec session logging, which is not enabled by default.
references:
  - https://aws.amazon.com/blogs/containers/new-using-amazon-ecs-exec-access-your-containers-fargate-ec2/  # retrieved 2026-08-29
tags:
  - attack.execution
  - attack.t1609
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecs.amazonaws.com'
    eventName: 'ExecuteCommand'
  shell:
    requestParameters.command|contains:
      - '/bin/sh'
      - '/bin/bash'
      - '/bin/ash'
      - '/bin/zsh'
      - 'powershell'
      - 'cmd.exe'
  success:
    errorCode: null
  condition: selection and success and shell
falsepositives:
  - >-
    A one-shot command whose arguments mention a shell path. Deliberately tolerated: an
    unrecorded interactive session is the more expensive miss.
level: high
---
# Base rule — sequence component only, not for direct alerting. ECS Exec has a hard
# prerequisite that produces its own event: AWS states "You can't turn on ECS Exec for existing
# tasks. It can only be turned on for new tasks", so an actor facing a task without it must set
# enableExecuteCommand and get new tasks placed. That makes the enablement a reliable, separate
# observable — and the source set alerts on it nowhere.
title: ECS execute-command functionality enabled on a task or service
id: 8503ef66-f988-4626-804c-92e3d546522f
name: ecs_exec_enabled_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateService.html  # retrieved 2026-08-29
tags:
  - attack.execution
  - attack.t1609
logsource:
  product: aws
  service: cloudtrail
detection:
  api:
    eventSource: 'ecs.amazonaws.com'
    eventName:
      - 'UpdateService'
      - 'CreateService'
      - 'RunTask'
      - 'StartTask'
  enabled:
    requestParameters.enableExecuteCommand: true
  success:
    errorCode: null
  condition: api and enabled and success
level: informational
---
# Enable-then-use is the full attacker path, and it is far stronger than either half. A
# legitimate operator debugging a service exec's into a task where the capability was already
# on; an actor who has to turn it on first leaves two events an hour apart with the same ARN
# between them.
#
# TIMESPAN BASIS. Sixty minutes, and the basis is deployment latency rather than a round
# number: enabling execute-command "doesn't trigger a new service deployment", so the actor
# must additionally force one and then wait for tasks to be replaced before Exec works. An hour
# covers a normal rolling replacement with a health-check grace period; shorten it once you
# have measured your own deployment time.
title: ECS Exec enabled and then used by the same principal
id: 9ec9bbaa-4f5a-4710-8247-cf9e4dc76cce
status: experimental
description: >-
  One principal turned on execute-command functionality and then opened a session into a
  container within the hour. Enabling it does not trigger a deployment and does not affect
  existing tasks, so this sequence means the principal also caused new tasks to be placed.
references:
  - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html  # retrieved 2026-08-29
tags:
  - attack.execution
  - attack.t1609
  - attack.credential-access
  - attack.t1552.005
correlation:
  type: temporal_ordered
  rules:
    - ecs_exec_enabled_bb
    - ecs_exec_session_opened
  group-by:
    - userIdentity.arn
  timespan: 60m
level: high
---
# Fan-out across TASKS, not volume of calls, which is why this counts distinct values: an
# engineer debugging one container retries against the same task, while the same number of
# calls spread across three tasks is someone walking the estate. Each task may carry a
# different task role, so every task in the group is a separate credential exposure and a
# separate work-list entry.
#
# THRESHOLD BASIS. No observed baseline exists, so the reasoning is structural: ECS Exec is a
# debugging tool used against the container you are debugging, and a legitimate session
# concerns one task. Three distinct tasks in thirty minutes is not debugging. `gte` at the
# baseline, never `gt`, so a run that touches exactly three does not fall through. Re-baseline
# against your own on-call practice before deploying.
title: ECS Exec used against multiple tasks by one principal
id: 37d1dfdc-499b-4b37-a0b4-569373adff92
status: experimental
description: >-
  One principal opened ECS Exec sessions into three or more distinct tasks inside thirty
  minutes. Each task potentially carries a different task role, so the credential exposure is
  per task and the containment work-list is every task in the group.
references:
  - https://attack.mitre.org/techniques/T1609/  # retrieved 2026-08-29
tags:
  - attack.execution
  - attack.t1609
correlation:
  type: value_count
  rules:
    - ecs_exec_session_opened
  group-by:
    - userIdentity.arn
  field: requestParameters.task
  timespan: 30m
  condition:
    gte: 3
level: high
---
# Failed Exec attempts are a distinct signal and must not be counted as sessions.
# TargetNotConnectedException is the specific one worth watching: AWS documents its causes as
# "Incorrect IAM permissions", "The SSM agent is not installed or is not running", or a VPC
# interface endpoint for ECS without one for Session Manager. A principal sweeping tasks
# collects this error from every task that is NOT exec-enabled, which makes a burst of them the
# signature of someone hunting for a task they can get into.
title: ECS Exec attempts failing across multiple tasks
id: 37ac2476-2355-4d9c-a74f-9b9455af59f2
name: ecs_exec_attempts_failing
status: experimental
description: >-
  ExecuteCommand calls are failing for one principal. TargetNotConnectedException means the
  data path to that container is not established; AccessDeniedException means the principal
  lacks the permission or a policy condition did not match. Either way no session opened, and
  a run of them across tasks is a search for one that will work.
references:
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ExecuteCommand.html  # retrieved 2026-08-29
tags:
  - attack.execution
  - attack.t1609
  - attack.discovery
  - attack.t1613
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecs.amazonaws.com'
    eventName: 'ExecuteCommand'
  failed:
    errorCode:
      - 'TargetNotConnectedException'
      - 'AccessDeniedException'
      - 'ClusterNotFoundException'
      - 'InvalidParameterException'
      - 'ClientException'
  condition: selection and failed
falsepositives:
  - >-
    An operator attempting to exec into a task whose service does not have execute-command
    enabled. Common and benign as a single event; a run of them across distinct tasks is not.
level: medium
```

The rule cannot see inside the session, and neither can anything else unless
`executeCommandConfiguration.logging` was `OVERRIDE` **before** the incident — and even then the
upload fails silently on an image without `script` and `cat`. Nor can it see a session started
through `ssm:StartSession`, which AWS documents as producing no ECS-side log at all.
`detections/kql_t1609.kql` covers what *is* observable: it joins the Exec event's `task` ID to every
subsequent API call by an assumed-role session bearing that ID as its session name, with **no
`eventSource` filter**, because a stolen task-role credential works against every service.

---

### Key Investigation Queries

> ECS is regional — run Queries 1, 2 and 5 in the cluster's region; Query 3 must be run in **every** region, because a stolen task-role credential is global. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: every session, what it ran, and which task it entered

```bash
REGION="us-east-1"
RAW=$(aws cloudtrail lookup-events --region "$REGION" --output json \
        --lookup-attributes AttributeKey=EventName,AttributeValue=ExecuteCommand \
        --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)")
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region,"
  echo "    or missing cloudtrail:LookupEvents. This is NOT 'no sessions were opened'."
else
  # requestParameters.task is a task ID or a full task ARN, caller's choice - reduced to the
  # bare ID because that is the form the role session name uses in Query 3.
  # `command` is NOT redacted, but for an interactive session it is only the shell binary.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "ecs.amazonaws.com") |
    {time: .eventTime, caller_arn: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     cluster: ((.requestParameters.cluster // "") | split("/") | last),
     task_id: ((.requestParameters.task // "") | split("/") | last),
     container: .requestParameters.container,
     command: .requestParameters.command,
     session_id: (.responseElements.session.sessionId // null),
     task_arn: (.responseElements.taskArn // null),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.time)'
fi
```

`task_id` is what everything downstream keys on — the same string that becomes the role session
name of any credential taken from that container. Read `command` carefully: `cat /etc/passwd` is a
complete record of the action, while `/bin/bash`, `/bin/sh` or `powershell` means **the session
contents are not in CloudTrail** and Query 4 is the only remaining source. `session_id` (documented
example form `ecs-execute-command-<hex>`) is the pivot into that log. A run of
`TargetNotConnectedException` across different `task_id` values is a search for a task they can
enter, not a series of failures. Record `task_id`, `cluster`, `caller_arn`, `access_key` and
`session_id` as IOCs.

#### Query 2 — Ground truth: what identity did that container hold, and what could it reach

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; TASK_ID="<task-id-from-Query-1>"

# TIME-CRITICAL. AWS: "stopped tasks appear in the returned results for at least one hour" - a
# floor, not a guarantee. Once the record ages out, the task ID no longer resolves to a task
# definition and the blast radius becomes unrecoverable. Run this BEFORE anything in §3.
T=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ID" --region "$REGION" \
      --include TAGS --output json)
TD_ARN=""
if [ -z "$T" ]; then
  echo "[!] INCONCLUSIVE - describe-tasks produced no output (a bad CLUSTER throws"
  echo "    ClusterNotFoundException; a missing task returns MISSING inside a 200)."
elif [ "$(printf '%s' "$T" | jq '.tasks | length')" -eq 0 ]; then
  echo "[FAIL] task $TASK_ID no longer describable (reason:"
  echo "    $(printf '%s' "$T" | jq -r '.failures[0].reason // "none returned"')) - the record"
  echo "    aged out or the cluster is wrong. Recover the task definition from the"
  echo "    RunTask/CreateService CloudTrail event; it is the only remaining source."
else
  printf '%s' "$T" | jq -r '.tasks[0] |
    "[i] lastStatus=\(.lastStatus) startedAt=\(.startedAt // "n/a") stoppedAt=\(.stoppedAt // "n/a") " +
    "exec=\(.enableExecuteCommand) taskDef=\(.taskDefinitionArn)"'
  TD_ARN=$(printf '%s' "$T" | jq -r '.tasks[0].taskDefinitionArn // empty')
fi

ROLE_ARN=""
if [ -z "$TD_ARN" ]; then
  echo "[!] no task definition resolved - the blast radius is UNKNOWN, not empty. Stop here."
else
  TD=$(aws ecs describe-task-definition --task-definition "$TD_ARN" --region "$REGION" --output json)
  if [ -z "$TD" ]; then
    echo "[!] INCONCLUSIVE - describe-task-definition returned nothing for $TD_ARN"
  else
    printf '%s' "$TD" | jq -r '.taskDefinition |
      {family, revision, task_role: (.taskRoleArn // "NONE"),
       execution_role: (.executionRoleArn // "NONE"),
       network_mode: .networkMode, pid_mode: (.pidMode // "unset"),
       containers: [.containerDefinitions[] |
         {name, image, privileged: (.privileged // false), user: (.user // null),
          secrets: [(.secrets // [])[] | .valueFrom],
          log_driver: (.logConfiguration.logDriver // "NONE")}]}'
    ROLE_ARN=$(printf '%s' "$TD" | jq -r '.taskDefinition.taskRoleArn // empty')
  fi
fi

# The task role IS the blast radius. Note the EC2 trap: AWS documents that "For tasks on Amazon
# EC2, if no task role is configured, the instance role of the underlying Amazon EC2 instance is
# used instead" - so an absent taskRoleArn is NOT a safe negative outside Fargate.
if [ -z "$ROLE_ARN" ]; then
  echo "[!] no taskRoleArn. On Fargate the container held no AWS identity; on EC2 it held the"
  echo "    CONTAINER INSTANCE's role - resolve that instance profile and treat it as the blast"
  echo "    radius. Do not record this as 'no credentials'."
else
  ROLE=$(printf '%s' "$ROLE_ARN" | awk -F'/' '{print $NF}')
  INLINE=$(aws iam list-role-policies --role-name "$ROLE" --query 'PolicyNames' --output json)
  ATTACHED=$(aws iam list-attached-role-policies --role-name "$ROLE" \
               --query 'AttachedPolicies[].PolicyArn' --output json)
  if [ -z "$INLINE" ] || [ -z "$ATTACHED" ]; then
    echo "[!] INCONCLUSIVE - could not enumerate policies on $ROLE; blast radius unknown, not empty"
  else
    echo "[i] task role $ROLE  inline=$INLINE  attached=$ATTACHED"
  fi
fi
```

This is a race against the stopped-task retention floor, which is why it precedes containment. The
task's `exec` value says whether Exec was already available or had to be turned on — cross-check
Query 5. `secrets[].valueFrom` names every secret the container could pull, and a root shell could
pull all of them. The task role's policies answer "what did the attacker get", and `NONE` is the
trap: on EC2 it means the container instance's role, not no role.

#### Query 3 — Session reconstruction: what the container's credentials did, everywhere

```bash
TASK_ID="<task-id-from-Query-1>"
EXEC_TIME="<iso8601-time-from-Query-1>"

# The join that makes this technique detectable: an ECS task-role session carries the TASK ID as
# its role session name. No eventName or eventSource filter - a stolen task-role credential works
# against any service, and constraining this to ECS would hide the point.
# AttributeKey=Username matches the SESSION NAME, which here is the task ID. Keyed on the ROLE
# name it returns zero unconditionally, and that zero would read as clean.
for R in us-east-1 us-west-2 eu-west-1; do
  OUT=$(aws cloudtrail lookup-events --region "$R" --output json \
          --lookup-attributes AttributeKey=Username,AttributeValue="$TASK_ID" \
          --start-time "$(date -u -d "$EXEC_TIME -1 hour" +%Y-%m-%dT%H:%M:%SZ)")
  if [ -z "$OUT" ]; then
    echo "[!] INCONCLUSIVE - $R: lookup-events returned nothing. Failed call or no permission;"
    echo "    NOT 'the credential was unused in $R'."
    continue
  fi
  N=$(printf '%s' "$OUT" | jq '.Events | length')
  echo "== $R: $N event(s) under session name $TASK_ID"
  [ "$N" -eq 0 ] && continue
  printf '%s' "$OUT" | jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, service: .eventSource, event: .eventName,
     role: .userIdentity.sessionContext.sessionIssuer.userName,
     access_key: .userIdentity.accessKeyId, ip: .sourceIPAddress, agent: .userAgent,
     error: (.errorCode // "SUCCESS")}' | jq -s 'sort_by(.time)'
done
```

Zero events in a region is **not** proof the credential was unused there — it is proof this call
found none, which is why the failed-call branch is separated from the empty-result branch. Look for
activity **after** `EXEC_TIME` from an `ip` outside the task set's documented egress addresses, or
against a `service` the workload has no business calling: either is off-container use of the
container's identity and promotes this to P0. Legitimate application traffic uses the same session
name, so the baseline from §1 is what makes the anomaly visible.

#### Query 4 — Inspect what CloudTrail does not log: was there a transcript, and where

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; SESSION_ID="<session-id-from-Query-1>"

C=$(aws ecs describe-clusters --clusters "$CLUSTER" --region "$REGION" \
      --include CONFIGURATIONS --output json)
if [ -z "$C" ] || [ "$(printf '%s' "$C" | jq '.clusters | length')" -eq 0 ]; then
  echo "[!] INCONCLUSIVE - the cluster configuration could not be read. Whether the session was"
  echo "    recorded is UNKNOWN."
  exit 0
fi
LOGGING=$(printf '%s' "$C" | jq -r '.clusters[0].configuration.executeCommandConfiguration.logging // "UNSET"')
LG=$(printf '%s' "$C" | jq -r '.clusters[0].configuration.executeCommandConfiguration.logConfiguration.cloudWatchLogGroupName // ""')
S3=$(printf '%s' "$C" | jq -r '.clusters[0].configuration.executeCommandConfiguration.logConfiguration.s3BucketName // ""')

case "$LOGGING" in
  NONE)         echo "[FAIL] logging is NONE - AWS: 'The execute command session is not logged.'";;
  OVERRIDE)     if [ -z "$LG" ] && [ -z "$S3" ]; then
                  echo "[FAIL] OVERRIDE set but no cloudWatchLogGroupName and no s3BucketName"
                else
                  echo "[i] logging=OVERRIDE cloudWatch='$LG' s3='$S3' - a transcript SHOULD exist,"
                  echo "    but AWS requires 'script' and 'cat' in the image for the upload to"
                  echo "    work. An empty destination is INCONCLUSIVE, not innocence."
                fi;;
  DEFAULT|UNSET) echo "[FAIL] logging is '$LOGGING'. AWS: DEFAULT uses 'the awslogs configuration"
                 echo "    in the task definition', and 'if no awslogs log driver is configured in"
                 echo "    the task definition, the output won't be logged.' Check the log_driver"
                 echo "    from Query 2; if it is NONE, this session was never recorded.";;
  *)            echo "[!] INCONCLUSIVE - unexpected logging value '$LOGGING'";;
esac

# Only worth attempting where a CloudWatch destination exists. The session ID from Query 1 is
# the stream discriminator.
if [ -n "$LG" ]; then
  STREAMS=$(aws logs describe-log-streams --log-group-name "$LG" --region "$REGION" \
              --log-stream-name-prefix "$SESSION_ID" --output json)
  if [ -z "$STREAMS" ]; then
    echo "[!] INCONCLUSIVE - describe-log-streams failed; cannot say whether a transcript exists"
  elif [ "$(printf '%s' "$STREAMS" | jq '.logStreams | length')" -eq 0 ]; then
    echo "[FAIL] no stream matching $SESSION_ID in $LG - configured to record, recorded nothing;"
    echo "    most likely the image lacks 'script' and 'cat'"
  else
    printf '%s' "$STREAMS" | jq -r '.logStreams[] | "[OK] transcript stream: \(.logStreamName)"'
  fi
fi
```

The point is a *defensible* statement about what is knowable. `NONE` and `DEFAULT`-without-`awslogs`
are `[FAIL]` because the session content is permanently gone, not because something is broken now.
`OVERRIDE`-with-no-stream is the misleading one: configuration says recorded, destination is empty,
and the honest reading is a silent upload failure — not that nothing happened.

#### Query 5 — Sweep: every task in the account this would still work against

```bash
REGION="us-east-1"
CLUSTERS=$(aws ecs list-clusters --region "$REGION" --query 'clusterArns[]' --output text)
if [ -z "$CLUSTERS" ]; then
  echo "[!] INCONCLUSIVE - list-clusters returned nothing; the sweep did not run. Not 'no clusters'."
else
  CHECKED=0; ENABLED=0
  for C in $CLUSTERS; do
    SVCS=$(aws ecs list-services --cluster "$C" --region "$REGION" --query 'serviceArns[]' --output text)
    [ -z "$SVCS" ] && { echo "[i] $(basename "$C"): no ACTIVE services, or the call returned none"; continue; }
    for S in $SVCS; do
      # One service per call. describe-services caps at 10 and batching would hide WHICH call
      # failed; stderr is deliberately NOT suppressed, because a refused call must be visible
      # rather than counted as a service verified disabled.
      D=$(aws ecs describe-services --cluster "$C" --services "$S" --region "$REGION" --output json)
      if [ -z "$D" ]; then
        echo "[!] $(basename "$S"): no description returned - NOT verified as Exec-disabled"
        continue
      fi
      CHECKED=$((CHECKED + 1))
      if [ "$(printf '%s' "$D" | jq -r '.services[0].enableExecuteCommand // "absent"')" = "true" ]; then
        ENABLED=$((ENABLED + 1))
        printf '%s' "$D" | jq -r --arg c "$(basename "$C")" '.services[0] |
          "[!] EXEC-ENABLED  \($c)/\(.serviceName)  desired=\(.desiredCount) taskDef=\(.taskDefinition)"'
      fi
    done
  done
  echo "[i] $CHECKED service(s) checked, $ENABLED Exec-enabled. Compare against the desired-state"
  echo "    list from §1. A zero is only meaningful if CHECKED is nonzero - otherwise the sweep"
  echo "    did not run and its silence is not a clean result."
fi
```

This is the "where else does this work" question and the residual-exposure list in one:
`enableExecuteCommand` is inherited by every task a service launches, so an entry here is a standing
capability rather than a past event. The closing caveat is not decoration — an empty result from a
sweep whose inner calls were refused is indistinguishable from a clean account.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**Ordering is the whole difficulty here, and getting it wrong destroys either the evidence or the
containment.** Query 2 must complete first: stopping the task starts a clock AWS documents as *"at
least one hour"*, after which the task ID no longer resolves to a definition. Session revocation
must precede stopping the task, because credentials the actor already read stay valid for up to six
hours whether the task lives or dies — killing the container removes the source but not the
credential, and removes the evidence too. And disabling Exec does **not** affect running tasks: AWS
states it *"can only be turned on for new tasks"*, and the `UpdateService` parameter *"doesn't
trigger a new service deployment"*, so setting `false` without forcing one leaves every container
reachable while the configuration claims otherwise.

Order: **collect (Query 2) → revoke the task role's sessions → replace the tasks → contain the
calling principal.**

> Run under the **break-glass responder credentials** from §1 — and confirm they are not issued
> by the task role you are about to revoke.

#### Step 1 — Revoke the task role's already-issued sessions

```bash
TASK_ROLE_ARN="<task-role-arn-from-Query-2>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)

case "$TASK_ROLE_ARN" in
  arn:aws:iam::*:role/*)
    TR=$(printf '%s' "$TASK_ROLE_ARN" | awk -F'/' '{print $NF}')
    aws iam put-role-policy --role-name "$TR" --policy-name "EmergencyRevokeTaskSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    echo "[OK] denied all pre-$CUTOFF sessions for task role $TR";;
  *)
    echo "[!] INCONCLUSIVE - '$TASK_ROLE_ARN' is not an IAM role ARN. If Query 2 reported NONE"
    echo "    on an EC2 launch type, the identity in play is the CONTAINER INSTANCE ROLE."
    echo "    Revoke that instead - see ../ec2.credential-access.imds-credential-theft/.";;
esac
```

This kills credentials **issued before** `$CUTOFF` and nothing else. A task still running will
have the agent fetch a fresh credential with a newer `aws:TokenIssueTime`, which this policy does
not deny — that is why Step 2 exists and why this step alone is not containment. It is also why
this step comes first: it invalidates the copy the actor already holds, which is the one you
cannot otherwise reach.

#### Step 2 — Replace the running tasks, and disable Exec in the same deployment

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; SERVICE="<service-owning-the-task>"

# Both changes in ONE call. Setting enableExecuteCommand=false alone does nothing to running
# tasks - AWS: ECS Exec "can only be turned on for new tasks", and the parameter "doesn't
# trigger a new service deployment". The forced deployment is what replaces the containers, and
# the new ones come up without the capability.
OUT=$(aws ecs update-service --cluster "$CLUSTER" --service "$SERVICE" \
        --no-enable-execute-command --force-new-deployment \
        --region "$REGION" --output json)
if [ -z "$OUT" ]; then
  echo "[!] INCONCLUSIVE - update-service returned nothing. The tasks were NOT replaced and Exec"
  echo "    was NOT disabled. Do not proceed as if contained."
else
  printf '%s' "$OUT" | jq -r '.service |
    "[OK] update accepted: enableExecuteCommand=\(.enableExecuteCommand) desired=\(.desiredCount)"'
  echo "[i] The deployment is asynchronous. Until the old tasks are replaced they remain"
  echo "    Exec-reachable; §5 asserts that the running tasks are actually new ones."
fi

# A task launched by RunTask rather than by a service has no service to update. Stop it
# directly - but only AFTER Query 2 has captured its definition.
STANDALONE_TASK="<task-id-from-Query-1, only if it belongs to no service>"
case "$STANDALONE_TASK" in
  ''|'<'*)  echo "[i] no standalone task supplied - skipping";;
  *)        aws ecs stop-task --cluster "$CLUSTER" --task "$STANDALONE_TASK" --region "$REGION" \
              --reason "IR: ECS Exec session by unauthorised principal" --output json |
              jq -r '"[OK] stop requested: \(.task.taskArn) lastStatus=\(.task.lastStatus)"';;
esac
```

#### Step 3 — Close the unlogged alternative path

```bash
TASK_ROLE_ARN="<task-role-arn-from-Query-2>"
# AWS: "While starting SSM sessions on your container outside of ECS Exec is possible, this
# could potentially result in the sessions not being logged... We recommend limiting this access
# by denying the ssm:start-session action directly for your Amazon ECS tasks using an IAM
# policy." A session opened that way produces no ecs.amazonaws.com event at all, so this is a
# prevention control with no detection behind it.
case "$TASK_ROLE_ARN" in
  arn:aws:iam::*:role/*)
    TR=$(printf '%s' "$TASK_ROLE_ARN" | awk -F'/' '{print $NF}')
    aws iam put-role-policy --role-name "$TR" --policy-name "DenyDirectSsmSession" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ssm:StartSession","ssm:ResumeSession"],"Resource":"*"}]}'
    case "$(aws iam list-role-policies --role-name "$TR" --query 'PolicyNames[]' --output text)" in
      *DenyDirectSsmSession*) echo "[OK] direct SSM session path denied on $TR";;
      '')                     echo "[!] INCONCLUSIVE - could not list policies on $TR to confirm";;
      *)                      echo "[FAIL] DenyDirectSsmSession is not attached to $TR";;
    esac;;
  *) echo "[!] INCONCLUSIVE - no task role to apply this to; see Step 1's note on EC2";;
esac
```

#### Step 4 — Contain the calling principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ecs:ExecuteCommand","ecs:UpdateService","ecs:RunTask","ecs:StartTask","ecs:RegisterTaskDefinition","ssm:StartSession","iam:PassRole"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyEcsExec" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyEcsExec" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied ECS Exec for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or"
     echo "    a service principal. Contain manually; neither branch above applies.";;
esac
```

`ssm:StartSession` is in the caller's deny list for the same reason it is in the task role's: it
is the route into the container that leaves no ECS-side record.

---

## 4. Eradication

### Remove Attacker Access

#### Every secret the container could read is compromised

The session ran as `root` inside a container that had already resolved its `secrets` at start-up.
Query 2's `secrets[].valueFrom` list names each one, and a root shell could read them from the
process environment or refetch them with the task role. Rotate all of them. Nothing records
whether they were read: the retrieval happened inside the container, and a `GetSecretValue` appears
in CloudTrail only if the actor used the role rather than the already-resolved environment.

#### The task role is the pivot, not the endpoint

Query 3's output is the work-list. Every service the task-role session touched after the Exec event
needs review on its own terms, and any persistence established with that credential belongs to
another playbook — a new service (`../ecs.stealth.service-is-created/`), an IAM change
(`../iam.persistence.role-trust-backdoor/`), a new access key. Then right-size the role: it
should carry only what the workload calls, and the four `ssmmessages:*` actions only where Exec is
genuinely required.

#### Every Exec-enabled service in Query 5 is standing exposure

`enableExecuteCommand` is a service property that every task it launches inherits, so a service on
that list is a capability rather than a past event. Turn it off wherever it is not deliberately
required — each one needs a forced deployment to take effect on already-running tasks.

#### Turn on the logging that was missing

If Query 4 reported `NONE`, `DEFAULT` or `UNSET`, this session's content is gone and so is the next
one's. Set `logging` to `OVERRIDE` with a CloudWatch or S3 destination and a `kmsKeyId`, grant the
task role permission to write there, and confirm the image carries `script` and `cat` — without
them the upload fails silently and the configuration is decorative.

#### Remove the emergency policies once clean, and assert it

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
TASK_ROLE_ARN="<task-role-arn-from-Query-2>"

# The caller. A principal that is neither user nor role must reach INCONCLUSIVE, never clean.
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyEcsExec EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyEcsExec"
    LEFT=$(aws iam list-user-policies --user-name "$N" --query 'PolicyNames[]' --output text);;
  *) N=""; LEFT="UNCHECKED";;
esac
case "$LEFT" in
  UNCHECKED)   echo "[!] INCONCLUSIVE - caller is neither user nor role; check manually";;
  *Emergency*) echo "[FAIL] an emergency policy is still attached to $N: $LEFT";;
  *)           echo "[OK] no emergency policy remains on $N";;
esac

# The task role. EmergencyRevokeTaskSessions is temporary; DenyDirectSsmSession is PERMANENT and
# must SURVIVE this cleanup - it is a guardrail, not an emergency measure, so its absence is a
# failure rather than success.
case "$TASK_ROLE_ARN" in
  arn:aws:iam::*:role/*)
    TR=$(printf '%s' "$TASK_ROLE_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-role-policy --role-name "$TR" --policy-name "EmergencyRevokeTaskSessions"
    TLEFT=$(aws iam list-role-policies --role-name "$TR" --query 'PolicyNames[]' --output text)
    if   [ -z "$TLEFT" ]; then echo "[!] INCONCLUSIVE - could not list policies on $TR"
    elif printf '%s' "$TLEFT" | grep -q "EmergencyRevokeTaskSessions"; then
      echo "[FAIL] the session revocation is still on $TR"
    elif ! printf '%s' "$TLEFT" | grep -q "DenyDirectSsmSession"; then
      echo "[FAIL] DenyDirectSsmSession was removed from $TR - the unlogged SSM path is open again"
    else echo "[OK] $TR: revocation removed, DenyDirectSsmSession retained"; fi;;
  *) echo "[!] INCONCLUSIVE - no task role ARN supplied";;
esac
```

---

## 5. Recovery

### Restore Clean State

#### Verify the running tasks are new ones and none of them is Exec-enabled

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; SERVICE="<service-owning-the-task>"
CONTAIN_TIME="<iso8601-time-when-§3-Step-2-ran>"

# This is the check that catches the containment trap. Disabling ECS Exec does not affect
# already-running tasks, so a service reading enableExecuteCommand=false while still running its
# ORIGINAL tasks is not contained. Both halves are asserted.
D=$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
      --region "$REGION" --output json)
if [ -z "$D" ] || [ "$(printf '%s' "$D" | jq '.services | length')" -eq 0 ]; then
  echo "[!] INCONCLUSIVE - the service could not be described. A bad CLUSTER throws"
  echo "    ClusterNotFoundException; a missing SERVICE returns MISSING inside a 200. Unknown."
  exit 0
fi
SVC_EXEC=$(printf '%s' "$D" | jq -r '.services[0].enableExecuteCommand // "absent"')

TASKS=$(aws ecs list-tasks --cluster "$CLUSTER" --service-name "$SERVICE" \
          --region "$REGION" --query 'taskArns[]' --output text)
T=""
[ -n "$TASKS" ] && T=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks $TASKS \
                         --region "$REGION" --output json)
if [ -z "$T" ]; then
  echo "[!] INCONCLUSIVE - no task descriptions returned. The service may run no tasks, or the"
  echo "    call was refused; those are different and this cannot tell them apart."
  exit 0
fi
STILL_EXEC=$(printf '%s' "$T" | jq '[.tasks[] | select(.enableExecuteCommand == true)] | length')
OLD=$(printf '%s' "$T" | jq --arg t "$CONTAIN_TIME" '[.tasks[] | select(.startedAt < $t)] | length')
TOTAL=$(printf '%s' "$T" | jq '.tasks | length')

if   [ "$SVC_EXEC" = "absent" ]; then
  echo "[!] INCONCLUSIVE - the service description carries no enableExecuteCommand field"
elif [ "$SVC_EXEC" = "true" ]; then
  echo "[FAIL] the SERVICE still has enableExecuteCommand=true - Step 2 did not apply"
elif [ "$STILL_EXEC" -gt 0 ]; then
  echo "[FAIL] $STILL_EXEC of $TOTAL running task(s) are still Exec-enabled. The service says"
  echo "    false but the tasks predate the change: ECS Exec can only be set on NEW tasks."
elif [ "$OLD" -gt 0 ]; then
  echo "[FAIL] $OLD of $TOTAL running task(s) started before $CONTAIN_TIME - the deployment has"
  echo "    not finished replacing them"
else
  echo "[OK] all $TOTAL running task(s) started after containment and none is Exec-enabled"
fi
```

Both `[FAIL]` branches are reachable after the remediation and are the two a naive check misses.
`describe-services` reporting `enableExecuteCommand: false` describes desired state, not the
containers currently running — the per-task assertion closes that gap, and the `startedAt`
comparison catches a deployment still rolling.

#### Verify the task role's credentials are no longer being used off-container

```bash
TASK_ID="<task-id-from-Query-1>"
CUTOFF="<the CUTOFF value used in §3 Step 1>"

# This assertion CAN still emit a signal after the remediation, which is what makes it a real
# check: the aws:TokenIssueTime deny blocks pre-CUTOFF sessions, but a credential re-fetched
# from the container after that carries a newer issue time and is NOT denied. So post-CUTOFF
# activity under this session name is exactly the failure this step exists to detect.
FOUND=0; CHECKED=0
for R in us-east-1 us-west-2 eu-west-1; do
  OUT=$(aws cloudtrail lookup-events --region "$R" --output json \
          --lookup-attributes AttributeKey=Username,AttributeValue="$TASK_ID" \
          --start-time "$CUTOFF")
  [ -z "$OUT" ] && { echo "[!] $R: no output - failed call or no permission, NOT 'clean'"; continue; }
  CHECKED=$((CHECKED + 1)); N=$(printf '%s' "$OUT" | jq '.Events | length')
  [ "$N" -eq 0 ] && continue
  FOUND=$((FOUND + N))
  echo "[FAIL] $R: $N call(s) under session name $TASK_ID after $CUTOFF:"
  printf '%s' "$OUT" | jq -r '.Events[].CloudTrailEvent | fromjson |
    "    \(.eventTime) \(.eventSource) \(.eventName) from \(.sourceIPAddress) -> \(.errorCode // "SUCCESS")"'
done
if   [ "$CHECKED" -eq 0 ]; then echo "[!] INCONCLUSIVE - no region queried; nothing was verified"
elif [ "$FOUND" -eq 0 ]; then   echo "[OK] no activity under $TASK_ID in $CHECKED region(s) since $CUTOFF"
else echo "[FAIL] $FOUND post-cutoff call(s). A re-fetched credential is not covered by the"
     echo "    TokenIssueTime deny - the task still runs, or the role is compromised elsewhere."
fi
```

#### Verify ECS Exec session logging will actually record the next session

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"
C=$(aws ecs describe-clusters --clusters "$CLUSTER" --region "$REGION" \
      --include CONFIGURATIONS --output json)
if [ -z "$C" ] || [ "$(printf '%s' "$C" | jq '.clusters | length')" -eq 0 ]; then
  echo "[!] INCONCLUSIVE - the cluster configuration could not be read"
else
  L=$(printf '%s' "$C" | jq -r '.clusters[0].configuration.executeCommandConfiguration.logging // "UNSET"')
  DEST=$(printf '%s' "$C" | jq -r '.clusters[0].configuration.executeCommandConfiguration.logConfiguration |
           [(.cloudWatchLogGroupName // ""), (.s3BucketName // "")] | map(select(. != "")) | join(",")')
  if   [ "$L" != "OVERRIDE" ]; then
    echo "[FAIL] logging is '$L'. Only OVERRIDE guarantees a destination; DEFAULT records"
    echo "    nothing without an awslogs driver on the task definition."
  elif [ -z "$DEST" ]; then
    echo "[FAIL] OVERRIDE set but no cloudWatchLogGroupName or s3BucketName"
  else
    echo "[OK] logging=OVERRIDE to $DEST. Still verify 'script' and 'cat' are in the image:"
    echo "    without them the upload fails silently and this configuration is decorative."
  fi
fi
```

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     ExecuteCommand / ecs.amazonaws.com / no errorCode, where"
echo "  userIdentity.arn is NOT on the debugging allowlist - with NO condition on"
echo "  userIdentity.accountId, which is a 12-digit account ID on every such event and never"
echo "  the string 'anonymous'. Separately on any ExecuteCommand whose command contains a"
echo "  shell binary, allowlisted or not. The enable-then-use correlation must fire when"
echo "  enableExecuteCommand=true precedes it within 60 minutes by the same principal; the"
echo "  fan-out correlation at exactly three distinct task values in 30 minutes - gte, not gt."
echo "MUST NOT fire on: ExecuteCommand by the named debugging role running a one-shot command;"
echo "  an ExecuteCommand that returned TargetNotConnectedException or AccessDeniedException"
echo "  (no session opened - those belong on the separate medium rule)."
echo "EXPECTED FP, by design: the shell rule is NOT gated on the principal, so on-call"
echo "  debugging with /bin/bash fires it. That is intended: the account needs to know a"
echo "  session exists whose contents CloudTrail did not record, whoever opened it."
echo "CANNOT BE TESTED, and must be stated as a gap: a session opened via ssm:StartSession"
echo "  produces no ecs.amazonaws.com event at all. No rule here can fire on it."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| Interactive root access to a production container went undetected | The only rule covering it required `userIdentity.accountId` to equal `anonymous`, which no IAM-authorised ECS call carries — the rule had never fired and its silence was indistinguishable from absence |
| The session's contents are unrecoverable | `executeCommandConfiguration.logging` was left at its default, which records nothing unless the task definition independently carries an `awslogs` driver |
| The container held credentials worth stealing | A task role broader than the workload needed, readable from inside the container at `169.254.170.2` with no telemetry on the read |
| The first containment attempt left the containers reachable | `enableExecuteCommand: false` does not affect running tasks and does not trigger a deployment; the service reported contained while the original containers were still enterable |
| The blast radius was nearly lost | Stopped-task records survive *"at least one hour"*, and the task ID is the only route from the Exec event to the task definition and the role |

### Recommended Guardrails

**Confine the API, and close the path that bypasses it**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the value is wildcarded: Deny + StringNotEquals against a
// wildcarded ARN matches every principal and denies debugging outright - an outage, not a
// bypass. ssm:StartSession is denied alongside ecs:ExecuteCommand because AWS documents it as
// a route into the same container that produces no ECS-side log.
{
  "Effect": "Deny",
  "Action": ["ecs:ExecuteCommand", "ssm:StartSession"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/OnCallDebug", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

**Structural controls**

- **Scope the debugging role by cluster.** `ecs:ExecuteCommand` supports resource-level permissions
  — `"Resource": "arn:aws:ecs:*:*:cluster/dev-*"` allows it where it is needed and nowhere else.
  AWS documents that a condition-key mismatch surfaces as `AccessDeniedException`, so expect those
  in the logs and do not read them all as attacks.
- **Set `executeCommandConfiguration.logging` to `OVERRIDE`** on every cluster with a CloudWatch or
  S3 destination and a `kmsKeyId`, grant the **task role** permission to write there, then verify a
  real session produces a transcript — the image must contain `script` and `cat`.
- **Right-size every task role.** This is the only control that bounds the damage rather than the
  access, and it is the one that matters when the access control fails.
- **Do not grant the four `ssmmessages:*` actions** to task roles that do not need Exec. Without
  them the channel cannot establish, and the attempt surfaces as `TargetNotConnectedException` — a
  detection you get for free.
- **On EC2 launch types give every task an explicit task role**, even a near-empty one: AWS falls
  back to the container instance's role when none is configured, and that role is usually broader.

**Detection improvements**

- Alert on `enableExecuteCommand: true` on a service not in the desired-state list — a prerequisite
  the actor cannot skip, and cheap to watch.
- Alert on `executeCommandConfiguration.logging` moving to `NONE` or losing its destination
  (`T1685.002`) — the step that makes the next session unrecoverable.
- Baseline each task set's egress addresses, or Query 3's off-container test has nothing to compare
  against and the strongest signal here is unusable.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1609 — Container Administration Command (primary); T1552.005 — Unsecured Credentials: Cloud Instance Metadata API (secondary, the task-role read); T1613 — Container and Resource Discovery (the failed-attempt sweep) |
| MITRE tactic | Execution (TA0002), Credential Access (TA0006) |
| Primary API | `ecs:ExecuteCommand`, preceded where necessary by `ecs:UpdateService` with `enableExecuteCommand: true` plus a forced deployment; `ssm:StartSession` as the unlogged alternative |
| Event source | `ecs.amazonaws.com`, **management** plane, regional — management events are on by default. SSM channel activity is a **data** event on `AWS::SSMMessages::ControlChannel`, off by default |
| Key discriminator | The calling principal against a named debugging allowlist, and whether `command` is a shell binary. **Not** `interactive`, which is required and effectively always `true` |
| Field shape | `requestParameters`: `cluster`, `command`, `container`, `interactive`, `task` — those five only, `command` **not redacted**. `responseElements` **nested**: `clusterArn`, `containerArn`, `containerName`, `interactive`, `taskArn`, `session.{sessionId, streamUrl, tokenValue}`. Test for `session.sessionId`, not for the redaction placeholder |
| Ground-truth signal | The **task ID** in `requestParameters.task` equals the **role session name** of any task-role credential taken from that container — `assumed-role/<TaskRole>/<taskId>`. Documented by AWS as the role name "followed by the name of the task"; the exact format is not guaranteed, so confirm against a real event |
| "Was it used" pivot | CloudTrail activity under that session name after the Exec event, keyed with `AttributeKey=Username` on the **task ID** — a lookup keyed on the role name returns zero unconditionally, and that zero reads as clean |
| Content inspection path | ECS Exec session logging only. `logging: DEFAULT` (the default) records nothing without an `awslogs` driver on the task definition; `OVERRIDE` records to CloudWatch or S3 but fails **silently** if the image lacks `script` and `cat`. There is no other source for what was typed |
| Credential endpoint | `169.254.170.2` + `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` — **not** `169.254.169.254` (EC2 IMDS) and **not** `169.254.170.23` (EKS Pod Identity). Returns `RoleArn`, `AccessKeyId`, `SecretAccessKey`, `Token`, `Expiration`; valid **six hours**, auto-rotated. The read produces no CloudTrail event — AWS does not state this outright, but the endpoint is served locally by the container agent and the documented ECS data-event list does not include it |
| Blast radius | Everything the task role can reach, every secret in the task definition's `secrets[]`, the container's filesystem and process space as root — and on EC2 with no task role, the **container instance role** instead |
| Error strings | Exactly six documented: `AccessDeniedException`, `ClientException`, `ClusterNotFoundException`, `InvalidParameterException`, `ServerException`, `TargetNotConnectedException`. The last means the data path is not established — no `enableExecuteCommand`, no `ssmmessages:*` on the task role, or an ECS VPC endpoint without a Session Manager one. ECS's Common Errors adds `NotAuthorized` (401); there is no bare `AccessDenied`. Note that `AccessDeniedException` also occurs when a **correct** scoped policy's condition key does not match the request |

**MITRE mapping note.** The source rule labels this **T1078** (Valid Accounts) under **TA0001**
(Initial Access). Both IDs are live, so this is not staleness — but the mapping describes a
precondition rather than the technique: every authenticated AWS API call is made with a valid
account, so T1078 carries no information here. **T1609 (Container Administration Command)** is the
corrected primary and describes this API literally: executing commands inside a container through
the container administration service. **T1552.005** is carried for the credential read at
`169.254.170.2`, the same technique `../ec2.credential-access.imds-credential-theft/` maps at
a different address. **T1613** is tagged only on the failed-attempt rule, where the behaviour is
enumeration. The directory's `initial-access` segment preserves the source's tactic label for
continuity; the tactics that actually apply are Execution and Credential Access.

### Residual Risk

**What was typed in an interactive session is unrecoverable** unless `logging: OVERRIDE` was set
beforehand and the image carried `script` and `cat`. This playbook closes that gap for the next
session, not this one: reading the environment, the filesystem and the resolved secrets leaves no
trace anywhere.

The task-role credentials the actor already copied stay valid until they expire — six hours by
AWS's documented default — and the `aws:TokenIssueTime` deny reaches only sessions issued before
the cutoff. If the task was still running when it was applied, the agent's next rotation produces
a credential the policy does not cover, which is why §5's second assertion exists and can genuinely
fail.

`ssm:StartSession` against the same container produces **no `ecs.amazonaws.com` event at all**. The
deny in §3 Step 3 closes it going forward; nothing detects it, and nothing can say retrospectively
whether it was used before. The SSM control-channel data events that would have shown the session
at the transport layer are off by default and cannot be enabled retroactively.

And the exposure is broader than the one task: every service in Query 5's list is Exec-enabled
today, the property is inherited by every task those services launch, and each task carries its own
role. Turning it off on one service contains one service.

