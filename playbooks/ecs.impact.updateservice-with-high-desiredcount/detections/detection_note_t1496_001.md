# Detection Note — T1496.001 / T1496 (ECS Service Scaled to a High Desired Count)

**Signal:** `UpdateService` raising `requestParameters.desiredCount` far above the service's own
baseline — and, at higher confidence, the same principal having registered the task definition
that the multiplied tasks run.

**The discriminator is the magnitude, not the call.** `UpdateService` is the most routine write
in ECS: every deployment, every autoscaling action and every rollback is one. Nothing about the
event name, the caller alone, or the absence of an error separates resource hijacking from
operations. What separates them is how far the number moved, which makes this the one use case
in this ECS set where the rule has to be a **comparison** — and the source rule's attempt at one
is exactly where it fails.

**What the original rule got wrong.** Its query is
`requestParameters.desiredCount.keyword:/\d{4}/`, and there are three independent defects:

1. **`.keyword` on a numeric field.** A `.keyword` subfield exists only where the ingest
   pipeline maps a field as a string. AWS documents `desiredCount` as **Type: Integer** and
   CloudTrail serialises it as a JSON number. If the pipeline maps it numerically there is no
   `.keyword` subfield and the clause matches nothing at all. Whether the rule can fire
   therefore depends on an ingest-mapping detail rather than on the event — a defect whichever
   way the mapping happens to fall, because the rule's author cannot know.
2. **The regex is anchored, so it means "exactly four digits".** A Lucene `regexp` term must
   match the whole term, not a substring, so `/\d{4}/` covers 1000–9999 and is silent below
   1000. A service moved from 2 tasks to 500 is a 250× escalation and does not fire. And since
   AWS caps *"Tasks per service"* at **5,000** and the quota is **not adjustable**, the band
   above 5,000 is unreachable — the rule's real coverage is `[1000, 5000]` and its blind spot is
   everything from the service's baseline up to 999.
3. **No success filter.** Alone among the five ECS rules in this set, this one omits
   `NOT _exists_:errorCode`. A **denied** `UpdateService` with a high count raises the same
   alert at the same priority as a successful one, so a principal probing its permissions and an
   actor who actually scaled a mining fleet land in the same queue. That is the failure rule B6
   describes: a magnitude rule whose count is not aligned with the work-list.

The rule is also blind in the other direction. `desiredCount: 0` is the destructive setting and
the mandatory precursor to `DeleteService` and `DeleteCluster`, and a rule requiring four digits
cannot see a zero. That gap is covered by `../../ecs.stealth.service-is-deleted/` and
`../../ecs.stealth.cluster-is-deleted/`, each of which ships a scale-to-zero base rule.

## The threshold, and why it is 50

A number without a basis is an invented number, so here is the basis. Three documented figures
bound the problem:

| Figure | Value | Adjustable | What it bounds |
|---|---|---|---|
| Tasks per service | **5,000** | **No** | The hard ceiling on `desiredCount`. Any threshold near it is a ceiling test, not a detection |
| Fargate On-Demand vCPU resource count | **6** per Region by default | Yes — and AWS raises it automatically with usage | What can actually run. At the 0.25 vCPU Fargate minimum that is about 24 tasks |
| Services per cluster | 5,000 | No | Supplies no constraint on fan-out, so the fan-out threshold must come from the shape of the work |

**Fifty** sits above what a default-quota Fargate account can materialise and two orders of
magnitude below the service quota, which places it squarely inside the band the source rule
cannot see. It is a **starting point for an account that has never measured**. The correct
deployed value is the highest legitimate `desiredCount` observed in that account plus headroom,
and where the baseline is already high the **ratio** test in `kql_t1496_001.kql` is the better
instrument — 50 is an incident on a service that normally runs 2 and routine on one that
normally runs 200. Sigma cannot compare an event against a prior event's value, which is
precisely why the KQL carries the ratio and the Sigma carries the floor.

## The event is the detection surface, not the resulting task count

This is worth stating plainly because it inverts the obvious instinct. On a default-quota
Fargate account a `desiredCount` of 1,000 **never materialises**: the vCPU quota refuses it and
the tasks sit unplaceable. The intent is nonetheless fully expressed by the API call, so the
CloudTrail event is the signal and the running task count is not. Two corollaries:

- `responseElements.service.runningCount` is the count **at the moment of the call**, before any
  new task starts. It is never the answer to "how much ran".
- The answer comes from `AWS/ECS` `CPUUtilization` on the `ClusterName` + `ServiceName`
  dimensions — ECS sends metric data in 1-minute periods and states the statistics are
  *"recorded for a period of two weeks"* — and from the bill.

## Field shape and the optional-field trap

`requestParameters.desiredCount` is **top-level** and an integer. It is also **optional**: an
`UpdateService` that only changes the task definition or forces a deployment omits it entirely.
A parser that reads a missing `desiredCount` as `0` will manufacture scale-to-zero events out of
ordinary deployments — the same defect class as `CreateAccessKey`'s omitted `userName`. Test for
absence before comparing.

`requestParameters.cluster`, `.service` and `.taskDefinition` are all **caller-typed**: short
name, `family:revision` or full ARN, at the caller's discretion. Normalise before joining.
`responseElements` is **nested** at `responseElements.service.*`. `UpdateService` can also change
`taskDefinition`, `enableExecuteCommand`, `forceNewDeployment`, `networkConfiguration`,
`capacityProviderStrategy` and `platformVersion` in the same call, so a scale-out paired with a
task-definition swap is one event, not two.

## Response levers

**Error strings:** The full documented `UpdateService` set is eleven: `AccessDeniedException`, `ClientException`,
`ClusterNotFoundException`, `InvalidParameterException`, `NamespaceNotFoundException`,
`PlatformTaskDefinitionIncompatibilityException`, `PlatformUnknownException`, `ServerException`,
`ServiceNotActiveException`, `ServiceNotFoundException`, `UnsupportedFeatureException`. ECS uses
the `Exception` suffix throughout — there is no bare `AccessDenied` — and its Common Errors page
adds `NotAuthorized` (HTTP 401) and `ThrottlingException`. Note that the Common Errors page gives
`AccessDeniedException` as HTTP 403 while every per-API Errors section gives it as 400, so do not
key a rule on the code and the status together.

Exceeding the quota does **not** surface as a distinct code: AWS publishes no maximum for
`desiredCount` on the API itself, so an over-quota request returns `InvalidParameterException`
rather than something quota-specific. Do not build a rule on a `LimitExceeded`-shaped code here.

## Data plane

ECS logs control-plane operations as **management** events, on by default. The only documented
ECS data events are `ecs:Poll`, `ecs:StartTelemetrySession` and `ecs:PutSystemLogEvents` under
`resources.type` `AWS::ECS::ContainerInstance`. **There is no `AWS::ECS::Task` data event type**,
so mining is inferred from CPU and cost and is never observed directly in CloudTrail.

**GuardDuty:** There is **no GuardDuty finding type specific to ECS service scaling.** GuardDuty Runtime
Monitoring can fire on behaviour inside the containers — `CryptoCurrency:Runtime/BitcoinTool.B`
is the relevant family — but it requires the runtime agent and its ECS coverage is Fargate-only.
A `CryptoCurrency:*` finding corroborates the motive; its absence proves nothing.

**MITRE:** The source rule labels this **T1496** under **TA0040** — and this is the one mapping in the ECS
set that is right. T1496 (Resource Hijacking) under Impact is correct; the only refinement is
that ATT&CK now carries sub-techniques, and the precise one is **T1496.001 — Compute Hijacking**,
which covers using compromised compute for tasks such as mining. Both are tagged. All IDs
verified live 2026-08-29.

**Severity:** **High** for a scale-out outside the deployment pipeline, against the source's **P3**. The cost
accrues per minute and is unrecoverable once incurred, the compute is durable because ECS
replaces stopped tasks, and if the actor also re-pointed the task definition then the multiplied
workload is theirs rather than yours. **Medium** for the denied variant, which is where the
source rule's missing success filter silently put both.

**Files here:**

- `sigma_t1496_001.yml` — five documents: the successful scale-out at or above 50 (`high`), the
  denied attempt split out at `medium`, a `RegisterTaskDefinition` base rule
  (`informational`), a `temporal_ordered` correlation firing `high` on register-then-scale within
  the hour, and a `value_count` correlation firing `high` when one principal scales three or more
  distinct services inside thirty minutes.
- `kql_t1496_001.kql` — compares each update against **the service's own previous
  `desiredCount`**, which is the real discriminator and which Sigma cannot express, and treats a
  first-seen service as unknown rather than as a baseline of zero.

Full response procedure is in `../PLAYBOOK.md`.
