# Detection Note — T1489 / T1070 (ECS Service Deleted)

**Signal:** `DeleteService` succeeding on `ecs.amazonaws.com` for a principal that neither
deploys services nor responds to incidents — and, with more precision, `requestParameters.force`
set to `true`.

**This rule has a problem its siblings do not: the deletion is also the remediation.**
`DeleteService` is exactly the call an incident responder makes to remove an attacker's
workload; it is step one of `../../ecs.stealth.service-is-created/` §4. A rule that pages on
every `DeleteService` will page on its own SOC, and a SOC that learns to dismiss the alert has
no coverage of the destructive case. Two things follow, and both are structural rather than
cosmetic. The allowlist in `sigma_t1489.yml` must carry the **break-glass responder role** as
well as the deployment role. And `kql_t1489.kql` joins each deletion back to the `CreateService`
that produced the service, because a service created by the same principal an hour ago and
deleted now is **cleanup**, while a service created by the pipeline two years ago and deleted
now is **destruction** — and no field in the `DeleteService` event distinguishes them.

**`force` is the discriminator, and the source rule does not read it.** AWS: *"You can delete a
service if you have no running tasks in it and the desired task count is zero. If the service
is actively maintaining tasks, you can't delete it, and you must update the service to a desired
task count of zero."* The `force` parameter is documented as *"If `true`, allows you to delete a
service even if it wasn't scaled down to zero tasks. It's only necessary to use this if the
service uses the `REPLICA` scheduling strategy."* So an orderly teardown emits **two** events —
`UpdateService` with `desiredCount: 0`, then `DeleteService` — while `force: true` is the
single-call shortcut that removes a service **while it is still serving**. That is a real
field-level signal, present on every event, and unused.

Note carefully what AWS does *not* say: `force` is nowhere documented as terminating running
tasks. It waives a precondition. Writing "force kills the tasks" into a playbook is an
unverified behavioural claim.

**What the original rule got wrong** — it matches `eventName:"DeleteService"` with a success
filter, at P3, mapped to T1578 under TA0005:

| Defect | Consequence |
|---|---|
| No principal check | Fires on every pipeline teardown **and on the SOC's own containment work** |
| `requestParameters.force` unread | The one field carrying signal is ignored; a forced delete of a live production service is indistinguishable from an orderly one |
| No link to the service's creation | Cleanup and destruction produce the same event, and triage cannot tell them apart |
| P3 | An availability incident on a production workload, triaged below a configuration change |

## The status trap

`DeleteService` returns the object **nested** at `responseElements.service.*`, and its `status`
on a normal deletion is **`DRAINING`**, not `INACTIVE`. AWS: *"the service status moves from
`ACTIVE` to `DRAINING`, and the service is no longer visible in the console or in the
`ListServices` API operation. After all tasks have transitioned to either `STOPPING` or
`STOPPED` status, the service status moves from `DRAINING` to `INACTIVE`."* A rule matching
`responseElements.service.status: INACTIVE` would miss almost every real deletion, and a
recovery check that waits for `INACTIVE` before declaring the workload stopped will pass while
tasks are still running.

Two further consequences of the same transition. A `DRAINING` service is invisible to
`ListServices`, so an account-wide sweep built on `list-services` will not show it — use
`describe-services` with the name. And AWS: *"if you attempt to create a new service with the
same name as an existing service in either `ACTIVE` or `DRAINING` status, you receive an
error"*, which is how a rebuild attempted too early surfaces.

## The verification trap

`describe-services` does **not** error for a service that no longer exists. It returns HTTP 200
with `services` empty and a `failures` entry whose `reason` is `MISSING` — AWS documents that
reason for `DescribeServices` as *"The specified service wasn't found. Verify that the correct
cluster or Region is specified and that the service ARN or name is valid."* The CLI exits 0. So
`if aws ecs describe-services ...; then echo "[OK]"` passes identically for a live service, a
deleted one, and a call that was refused.

The asymmetry is worth internalising: a wrong **service** yields a `MISSING` failure inside a
200, while a wrong **cluster** throws `ClusterNotFoundException`, a real error. Four states have
to be separated — `ACTIVE`, `DRAINING`/`INACTIVE` with tasks still running, `INACTIVE` clean,
and `MISSING` — plus a fifth for the call that did not run.

## Response levers

**Error strings:** The full documented `DeleteService` set is **six**, and it is shorter than the neighbouring
APIs': `AccessDeniedException`, `ClientException`, `ClusterNotFoundException`,
`InvalidParameterException`, `ServerException`, `ServiceNotFoundException`. In particular
`ServiceNotActiveException`, `UnsupportedFeatureException`, `PlatformUnknownException` and
`PlatformTaskDefinitionIncompatibilityException` are **not** documented for this API even though
they are documented for `UpdateService` or `CreateService` — do not key a detection on them
here. ECS uses the `Exception` suffix throughout; there is no bare `AccessDenied` in its
documented set, and its Common Errors page adds `NotAuthorized` (HTTP 401) as a second denial
form.

## Data plane

ECS logs control-plane operations as **management** events, on by default. The only documented
ECS data events are `ecs:Poll`, `ecs:StartTelemetrySession` and `ecs:PutSystemLogEvents` under
`resources.type` `AWS::ECS::ContainerInstance`. **There is no `AWS::ECS::Task` data event type.**

**GuardDuty:** There is **no GuardDuty finding type specific to ECS service deletion.** Identity-side findings
such as `Impact:IAMUser/AnomalousBehavior` may fire on the principal rather than on the service.

**MITRE:** Both IDs are live, so this is imprecision rather than staleness — but it is the
wrong axis. Deleting a service stops a workload; that is **T1489 — Service Stop** under Impact
(TA0040), whose description is stopping or disabling services on a system to render them
unavailable. **T1070 — Indicator Removal** under Stealth is carried as a genuine second mapping
for the cleanup reading, where the actor deletes the service they themselves created — which is
the reading the directory's `stealth` segment tracks, and the one the KQL's `CreateService` join
is built to detect. All IDs verified live 2026-08-29.

**Severity:** **High** for a deletion outside the deployment and response allowlist, against the source's
**P3**. A production service stops serving and does not come back, and its load balancer wiring,
network configuration and task definition reference survive only in infrastructure code. The
severity does not scale with count — one production service destroyed is already an outage — so
the volume correlation raises urgency and the size of the restoration work-list, not the level.

**Files here:**

- `sigma_t1489.yml` — five documents: the non-allowlisted deletion (`high`), a forced deletion
  ungated on principal (`high`), a scale-to-zero base rule (`informational`), a
  `temporal_ordered` correlation firing `high` on scale-then-delete within 30 minutes, and an
  `event_count` correlation firing `high` at three deletions in ten minutes.
- `kql_t1489.kql` — joins each deletion back to the service's **creation**, which is what
  separates cleanup from destruction, and captures `responseElements.service.*` as the last full
  description of the service that will ever exist.

Sibling use cases: `../../ecs.stealth.service-is-created/` is the opposite event and a different
incident, not a volume variant — the reasoning is in `../_source/PROVENANCE.md`.
`../../ecs.stealth.cluster-is-deleted/` is what follows once every service in a cluster has been
deleted.

Full response procedure is in `../PLAYBOOK.md`.
