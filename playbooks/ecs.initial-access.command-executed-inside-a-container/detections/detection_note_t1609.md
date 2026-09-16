# Detection Note — T1609 / T1552.005 (Command Executed Inside an ECS Container)

**Signal:** `ExecuteCommand` succeeding on `ecs.amazonaws.com` — an interactive session opened
into a running container, as root, from a principal outside the named debugging role.

## The source rule cannot fire

Its query is:

```
eventSource:"ecs.amazonaws.com" AND eventName:"ExecuteCommand"
  AND userIdentity.accountId:"anonymous" AND NOT _exists_:errorCode
```

CloudTrail documents `userIdentity.accountId` as *"The account that owns the entity that granted
permissions for the request"*, and the `userIdentity` reference enumerates no `anonymous` value
for that field. ECS has no unauthenticated API surface: `ExecuteCommand` is a SigV4-signed call
authorised by IAM, so `accountId` is a twelve-digit account ID on every event this rule could
ever see. **The conjunct is never satisfied.** A P2 rule provides zero coverage of interactive
shell access to running containers, and it does so silently — it produces no errors, no
warnings and no alerts, which is indistinguishable from an account where nobody uses ECS Exec.

This is the most consequential defect in the ECS source set, and it is the reason this use case
was promoted to a full playbook rather than a lean one.

## Why this is Tier 1

Three of `07-TIERS.md`'s five tests apply:

- **Test 1 — account takeover is reachable in one further hop.** The session runs as root inside
  a container that holds an AWS identity. The task role's temporary credentials are readable
  from the ECS container credentials endpoint, and AWS documents them as valid for **six hours**
  and automatically rotated by the agent. If the task role carries IAM, Secrets Manager or broad
  data permissions, one `ExecuteCommand` is the last step before the account.
- **Test 3 — the blast radius is not in the event.** `ExecuteCommand` carries `cluster`,
  `command`, `container`, `interactive` and `task`, and no role. Establishing what the container
  could reach means task → task definition → `taskRoleArn` → attached policies, and the first
  hop is time-bounded: AWS states *"stopped tasks appear in the returned results for at least one
  hour"*. Stop the task before resolving its definition and the blast radius may be
  unrecoverable.
- **Test 5 — the detection has a structural blind spot worth a page of honesty.** For an
  interactive session, CloudTrail records the shell binary and nothing typed inside it, and the
  session transcript is not produced by default. That is the rest of this note.

## The command IS logged — and that is not as useful as it sounds

`requestParameters.command` is present and **not redacted**; AWS's own published CloudTrail
extract shows `"command": "ls"` in the clear alongside `cluster`, `container`, `interactive` and
`task`. Those five are the complete set of request parameters.

But AWS is equally explicit about the limit: *"It is important to understand that only AWS API
calls get logged (along with the command invoked)"*, and *"if you open an interactive shell
section only the `/bin/bash` command is logged in CloudTrail but not all the others inside the
shell."*

So the field's value depends entirely on what it contains. `"command": "cat /etc/passwd"` is a
complete record of the action. `"command": "/bin/bash"` is a record that a session happened and
nothing else. That asymmetry is why `sigma_t1609.yml` ships a separate shell rule, ungated on the
principal: whoever opens it, the account needs to know a session exists whose contents are
unrecorded.

## ECS Exec session logging is not on by default, and that is a two-part failure

The cluster's `configuration.executeCommandConfiguration.logging` takes `NONE`, `DEFAULT` or
`OVERRIDE`. AWS documents `DEFAULT` as the value used when nothing is specified, and defines it
as: *"The `awslogs` configuration in the task definition is used. If no logging parameter is
specified, it defaults to this value. If no `awslogs` log driver is configured in the task
definition, the output won't be logged."*

So the default is not "logging on". It is "inherit from the task definition, and if there is
nothing there, record nothing." A cluster with no `executeCommandConfiguration` at all is not
evidence that sessions were recorded — in the common case it is the opposite.

The second failure is quieter. Even with `logging: OVERRIDE` correctly pointed at
`logConfiguration.cloudWatchLogGroupName` or `s3BucketName`, AWS notes that *"the container image
requires `script` and `cat` to be installed in order to have command logs uploaded correctly to
Amazon S3 or CloudWatch Logs."* A distroless or minimal image therefore produces **no transcript
while the configuration says it should**. Absence of a session log is never evidence of absence
of a session, and a responder who checks the cluster configuration, sees `OVERRIDE`, finds no log
stream and concludes nothing happened has drawn exactly the wrong inference.

Note also that the permissions to write those logs are on the **task role**, not the execution
role.

## The task role is the blast radius, and the endpoint is not the one you think

A container with a task role can read that role's credentials from the **ECS container
credentials endpoint at `169.254.170.2`**, using the relative path the agent injects as
`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`. AWS's own example is `curl
169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, and the response carries `RoleArn`,
`AccessKeyId`, `SecretAccessKey`, `Token` and `Expiration`. Credentials are valid for **six
hours** by default and are rotated automatically by the container agent.

Three addresses get confused here, and getting them wrong sends a responder to the wrong
control:

| Address | Belongs to |
|---|---|
| `169.254.170.2` | **ECS task credentials** — this technique, via `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` |
| `169.254.169.254` | EC2 instance metadata — `../../ec2.credential-access.imds-credential-theft/`. ECS names both in its own `NO_PROXY` guidance, which is how you know they are distinct |
| `169.254.170.23` | **EKS Pod Identity**, via `AWS_CONTAINER_CREDENTIALS_FULL_URI`. Not ECS, not Fargate |

`IMDSv2` is irrelevant here: it hardens `169.254.169.254`, not the ECS credentials endpoint.
Cross-reference the EC2 playbook for the analogous response, but do not reuse its controls.

One EC2-specific trap: AWS states that *"For tasks on Amazon EC2, if no task role is configured,
the instance role of the underlying Amazon EC2 instance is used instead."* So "the task
definition names no `taskRoleArn`" is **not** a safe negative on EC2 — it means the container
reaches the container instance's role instead, which is usually broader.

## The join that makes this detectable

An ECS task role session carries the **task ID as its role session name**. AWS's example ARN is
`arn:aws:sts::123456789012:assumed-role/s3-write-go-bucket-role/7e9894e088ad416eb5cab92afExample`,
described as the role name *"followed by the name of the task"*, and the value is a 32-hex ECS
task ID. AWS also states that *"task credentials have a context of `taskArn` that is attached to
the session, so CloudTrail logs show which task the role credentials were vended for."*

That is the same string `ExecuteCommand` puts in `requestParameters.task`. Joining on it converts
"someone opened a shell" into "someone opened a shell and then these calls were made with the
container's identity" — which is the incident. `kql_t1609.kql` does that join with no
`eventSource` filter, because a stolen task-role credential works against every service.

Caveat honestly: AWS describes the session name as "the name of the task" and shows a task-ID
value, but publishes no format guarantee. Confirm the shape against a real event in your own
account before relying on the regex.

## The enablement prerequisite is its own observable

ECS Exec does not work unless the task was launched with `enableExecuteCommand`. AWS: *"You can't
turn on ECS Exec for existing tasks. It can only be turned on for new tasks."* And on
`UpdateService`, the parameter *"doesn't trigger a new service deployment."* Combining the two:
an actor facing a task without Exec must set `enableExecuteCommand: true` **and** cause new tasks
to be placed — a forced deployment — before anything works. That is two extra CloudTrail events
with the same principal on them, and the source set alerts on neither. The
`ecs_exec_enabled_bb` base rule and the `temporal_ordered` correlation exist for that path.

It also creates a containment trap, documented in `../PLAYBOOK.md` §3: setting
`enableExecuteCommand: false` does **not** affect the tasks already running. Without a new
deployment, the running containers stay reachable while the service configuration says they are
not.

## The unlogged alternative path

AWS warns twice, in the same guide: *"While starting SSM sessions on your container outside of
ECS Exec is possible, this could potentially result in the sessions not being logged. Sessions
started outside of ECS Exec also count against the session quota. We recommend limiting this
access by denying the `ssm:start-session` action directly for your Amazon ECS tasks using an IAM
policy."*

A session started that way produces **no `ecs.amazonaws.com` event at all**. Every rule in this
file is blind to it by construction, and the control is a `ssm:StartSession` deny rather than a
detection.

## What ECS Exec is built on, and what that does log

ECS Exec uses SSM Session Manager, *"made possible by bind-mounting the necessary SSM agent
binaries into the container."* The task role needs exactly four permissions —
`ssmmessages:CreateControlChannel`, `ssmmessages:CreateDataChannel`,
`ssmmessages:OpenControlChannel`, `ssmmessages:OpenDataChannel` — and those generate SSM **data**
events (`CreateControlChannel`, `OpenControlChannel`) under `resources.type`
`AWS::SSMMessages::ControlChannel`, which are **off by default**.

Whether an ECS Exec session also emits an `ssm.amazonaws.com` `StartSession` **management** event
into the customer's trail is **not documented**, and I could not verify it either way. Do not
build a correlation on one existing.

## Other operational facts worth having

Commands *"are run as the `root` user"* regardless of the container definition's `user`.
`readonlyRootFilesystem` is not supported with ECS Exec. The idle timeout is 20 minutes and
cannot be changed. Fargate requires platform version `1.4.0`+ (Linux). Readiness requires both
`enableExecuteCommand: true` **and** the `ExecuteCommandAgent` container's `lastStatus` reading
`RUNNING`.

## Field shape

`requestParameters`: `cluster`, `command`, `container`, `interactive`, `task` — those five and no
others. `responseElements` is **nested**: `clusterArn`, `containerArn`, `containerName`,
`interactive`, `taskArn`, and `session.{sessionId, streamUrl, tokenValue}`. `sessionId`'s
documented example form is `ecs-execute-command-<hex>` and it is the pivot into the session log
and the SSM record. `tokenValue` is redacted, but the redaction **string** differs between AWS's
ECS example and its SSM example — test for the presence of `responseElements.session.sessionId`
rather than matching placeholder text.

**`interactive` is not a discriminator.** It is a required request parameter and the CLI's
`execute-command` supports only the interactive form, so `interactive: true` appears on
essentially every event.

## Response levers

**Error strings:** Exactly six are documented for `ExecuteCommand`: `AccessDeniedException`, `ClientException`,
`ClusterNotFoundException`, `InvalidParameterException`, `ServerException`,
`TargetNotConnectedException`. The last is the operationally interesting one — AWS lists its
causes as *"Incorrect IAM permissions"*, *"The SSM agent is not installed or is not running"*, and
an ECS interface VPC endpoint without a Session Manager one. A principal sweeping for a task it
can enter collects `TargetNotConnectedException` from every task that is not Exec-enabled, which
makes a burst of them a search rather than a failure.

Also documented: *"If you use a condition key in your IAM policy to refine the conditions for the
policy statement, for example limit the actions to a specific cluster, you receive an
`AccessDeniedException` when there is a mismatch between the condition key value and the
corresponding parameter value."* So an `AccessDeniedException` here can mean a scoped policy
working correctly, not only a missing permission.

ECS uses the `Exception` suffix throughout; there is no bare `AccessDenied`, and Common Errors
adds `NotAuthorized` (HTTP 401).

**GuardDuty:** There is **no GuardDuty finding type for ECS Exec or for ECS container command execution.** The
nearest, `Execution:Runtime/SuspiciousShellCreated`, fires when *"a network service or
network-accessible process on an Amazon EC2 instance, or in a container has started an
interactive shell process"* — that is a service spawning a shell, not an operator entering one
through the ECS API, and it will not fire on a legitimate `aws ecs execute-command`. Other
`Execution:Runtime/*` types may fire on what is done *inside* a session. Note that
`PrivilegeEscalation:Runtime/ElevationToRoot` is **expected** during ECS Exec, since AWS runs
those commands as root by design — it is not a signal here. All Runtime Monitoring requires the
agent, and its ECS coverage is Fargate-only.

**MITRE:** The source rule labels this **T1078** (Valid Accounts) under **TA0001** (Initial Access). Both
IDs are live, so this is not staleness, but the mapping describes the *precondition* rather than
the technique: every authenticated AWS API call is made with a valid account, so T1078 carries no
information here.

The corrected primary is **T1609 — Container Administration Command** (Execution, TA0002), whose
description is executing commands inside a container through the container administration
service — literally this API. **T1552.005 — Unsecured Credentials: Cloud Instance Metadata API**
(Credential Access, TA0006) is carried as a genuine second mapping for the task-role credential
read from `169.254.170.2`, the same technique the EC2 sibling playbook maps at a different
address. **T1613 — Container and Resource Discovery** is tagged on the failed-attempts rule,
where the behaviour is enumeration rather than execution. All IDs verified live 2026-08-29.

The directory's `initial-access` segment tracks the source rule's tactic label and is retained for
continuity; the tactics that actually apply are Execution and Credential Access.

**Severity:** **High**, and P0 once task-role activity is observed after the session. The source rates it
**P2** — and the priority is the smaller problem, because the rule that carries it cannot fire at
all.

**Files here:**

- `sigma_t1609.yml` — six documents: the Exec session by a non-debug principal (`high`), the
  shell-invocation case ungated on principal (`high`), an `enableExecuteCommand` base rule
  (`informational`), a `temporal_ordered` correlation firing `high` on enable-then-use within the
  hour, a `value_count` correlation firing `high` at three distinct tasks in thirty minutes, and
  a failed-attempt rule at `medium` for the `TargetNotConnectedException` sweep.
- `kql_t1609.kql` — joins the Exec event's `task` ID to **every subsequent API call made by an
  assumed-role session whose session name is that task ID**, with no `eventSource` filter,
  because a stolen task-role credential works against every service.

Full response procedure is in `../PLAYBOOK.md`.
