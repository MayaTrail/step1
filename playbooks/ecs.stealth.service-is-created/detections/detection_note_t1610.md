# Detection Note — T1610 / T1053.007 (ECS Service Created)

**Signal:** `CreateService` succeeding on `ecs.amazonaws.com` for a principal that does not
deploy services — and, with more precision, that principal having registered the task
definition it points at.

**`CreateService` is a pointer, not a payload.** This is the fact the whole detection has to be
built around, and it is what separates this use case from every other "resource was created"
rule. The event names `taskDefinition` — a `family:revision` string or a full ARN, caller's
choice — and carries **no image, no command, no entrypoint and no role**. All of those live in
the task definition, registered by a separate `RegisterTaskDefinition` call which carries
`containerDefinitions[].image`, `.command`, `.entryPoint`, `.environment`, `.secrets`,
`.privileged`, `.user`, `.linuxParameters`, plus top-level `taskRoleArn`, `executionRoleArn`,
`networkMode` and `pidMode`. A rule that inspects only `CreateService` is inspecting the
wrapper. The `temporal_ordered` correlation in `sigma_t1610.yml` pairs the two calls, and
`kql_t1610.kql` joins them on the task definition **family** so the analyst actually sees the
image.

**A service is a maintained invariant, and that is why this is persistence.** `RunTask`
launches tasks that run once and stay dead. A service keeps `desiredCount` tasks running and
replaces any that stop, which means **stopping the attacker's containers accomplishes nothing**
until the service is scaled to zero or deleted. That is the difference between T1610 (Deploy
Container) and T1053.007 (Container Orchestration Job), and both are carried. It is also why
the containment ordering in `../PLAYBOOK.md` §3 is scale-then-stop and not the reverse.

**What the original rule got wrong** — it matches `eventName:"CreateService"` with a success
filter, at P3, mapped to T1578 under TA0005. Concretely:

| Defect | Consequence |
|---|---|
| No principal check | Fires on every deployment of every new service in the account |
| Reads none of the request parameters | `assignPublicIp`, `enableExecuteCommand`, `desiredCount`, `launchType` and the security groups are all in the event and all unused |
| Does not reach the task definition | The image, the command and the task role — the entire blast radius — are in a different event the rule set does not correlate to |
| P3 | The cloud-native equivalent of installing a persistent service on a host, triaged below a configuration change |

## The two fields that are in the event and worth reading

`requestParameters.networkConfiguration.awsvpcConfiguration.assignPublicIp` — AWS documents the
valid values as `ENABLED | DISABLED` and states *"When you use `create-service` or
`update-service`, the default is `DISABLED`"*. So `ENABLED` is an explicit choice to give the
tasks a routable address. The nesting is three levels deep and must be written out in full; a
flat `requestParameters.assignPublicIp` is `null` on every event.

`requestParameters.enableExecuteCommand` — AWS: *"If `true`, this enables execute command
functionality on all containers in the service tasks."* A service created with ECS Exec already
on is a service built for interactive access; see
`../../ecs.initial-access.command-executed-inside-a-container/` for what that grants, which is
root in the container and the task role's credentials.

Rule 2 in `sigma_t1610.yml` reads both and is deliberately **not** gated on the principal
allowlist: a pipeline that emits public, exec-enabled services by default is itself the
finding. The two conditions are sibling blocks ORed in the condition, not two keys in one
block — requiring both would miss the single-condition cases, which are the common ones.

## Field shape

`CreateService` returns the object **nested**: `responseElements.service.*`, carrying
`serviceArn`, `serviceName`, `clusterArn`, `status`, `desiredCount`, `runningCount`,
`pendingCount`, `taskDefinition`, `roleArn`, `createdBy`, `enableExecuteCommand`,
`networkConfiguration.awsvpcConfiguration.*`, `deployments[]` and `events[]`. The security-group
and subnet lists are arrays and are capped by AWS at 5 and 16 respectively.

`requestParameters.cluster` is documented as the short name **or** the full ARN, and
`requestParameters.taskDefinition` may be `family`, `family:revision` or an ARN. Both are
**caller-typed**: normalise before comparing or the join silently drops half the events.

## Response levers

**Error strings:** The full documented `CreateService` set is nine: `AccessDeniedException`, `ClientException`,
`ClusterNotFoundException`, `InvalidParameterException`, `NamespaceNotFoundException`,
`PlatformTaskDefinitionIncompatibilityException`, `PlatformUnknownException`, `ServerException`,
`UnsupportedFeatureException`. ECS uses the `Exception` suffix throughout — there is no bare
`AccessDenied` in its documented set — and the service's Common Errors page adds a second
denial code, `NotAuthorized` (HTTP 401). Match both. AWS also documents that *"if you attempt
to create a new service with the same name as an existing service in either `ACTIVE` or
`DRAINING` status, you receive an error"*, which is how a re-creation attempt over a service
being deleted surfaces.

## Data plane

ECS logs control-plane operations as **management** events, on by default. The only data events
AWS documents for ECS are `ecs:Poll`, `ecs:StartTelemetrySession` and `ecs:PutSystemLogEvents`
under `resources.type` `AWS::ECS::ContainerInstance`. **There is no `AWS::ECS::Task`
advanced-event-selector resource type.** Nothing in CloudTrail records what the containers did.

**GuardDuty:** There is **no GuardDuty finding type specific to ECS service creation.** GuardDuty Runtime
Monitoring can fire on behaviour *inside* the resulting containers — `Execution:Runtime/*`,
`CryptoCurrency:Runtime/BitcoinTool.B` — but it requires the runtime agent, and its ECS
coverage is Fargate-only. Do not build the response on one existing.

**MITRE:** Both IDs are live, so
this is imprecision rather than staleness, but here the mapping is genuinely wrong rather than
merely coarse: creating a service is not a modification made to evade detection, it is the
deployment of a workload. T1578's closest sub-technique, **T1578.002 (Create Cloud Instance)**,
is about creating a VM to run something outside monitored infrastructure — nearer, but still an
infrastructure-modification reading of what is plainly execution.

The corrected primary is **T1610 — Deploy Container** (Execution, TA0002), whose description is
deploying a container into an environment to execute code. **T1053.007 — Container
Orchestration Job** (Persistence, TA0003) is carried as a genuine second mapping, because an
ECS service is a scheduler that maintains and restarts its tasks — that is the persistence, and
it is the property that dictates the response ordering. All IDs verified live 2026-08-29.

**Severity:** **High** for a creation outside the pipeline, against the source's **P3**. A service is durable
execution under an IAM role, on a network the actor chose, restarting itself indefinitely. The
one case where P3 is defensible is a development account where engineers deploy by hand — and
there the correct fix is the principal allowlist, not a lower priority.

**Files here:**

- `sigma_t1610.yml` — five documents: the non-pipeline service creation (`high`), a
  public-IP-or-Exec-enabled creation not gated on the principal (`medium`), a
  `RegisterTaskDefinition` base rule (`informational`), a `temporal_ordered` correlation firing
  `high` on register-then-create within 30 minutes, and an `event_count` correlation firing
  `high` at three creations in ten minutes by one non-pipeline principal.
- `kql_t1610.kql` — resolves the task definition to its **image**, task role and privileged
  flags, which is the field CreateService does not carry and the whole triage turns on.

Sibling use cases: `../../ecs.stealth.service-is-deleted/` is the opposite event and a
different incident, not a volume variant — the reasoning is in `../_source/PROVENANCE.md`.
`../../ecs.impact.updateservice-with-high-desiredcount/` covers the same service being scaled
after creation.

Full response procedure is in `../PLAYBOOK.md`.
