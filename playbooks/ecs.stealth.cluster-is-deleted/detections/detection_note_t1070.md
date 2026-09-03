# Detection Note — T1070 / T1578.003 (ECS Cluster Deleted)

**Signal:** `DeleteCluster` succeeding on `ecs.amazonaws.com` for a principal that does not own
cluster lifecycle — and, more usefully, the teardown chain that had to run before it could
succeed.

**A successful cluster deletion is the END of a destruction sequence, not the start of one.**
This is the fact that separates this technique from every other "resource was deleted" rule in
the corpus, and it is documented rather than inferred. Amazon ECS refuses to delete a cluster
that still holds anything: *"You must deregister all container instances from this cluster
before you may delete it"*, and the API throws `ClusterContainsContainerInstancesException`,
`ClusterContainsServicesException`, `ClusterContainsTasksException` and
`ClusterContainsCapacityProviderException`. AWS's own error text spells out the required
sequence — *"You can't delete a cluster that contains services. First, update the service to
reduce its desired task count to 0, and then delete the service."*

So by the time this alert fires, the services are already deleted and the tasks are already
stopped. A responder who treats `DeleteCluster` as the incident will contain the wrong event
and miss the calls that did the damage. The correlation in `sigma_t1070.yml` exists for
exactly this reason: it pairs the deletion with its precursors so the alert arrives carrying
the chain.

**What the original rule got wrong** — it matches `eventName:"DeleteCluster"` with a success
filter and nothing else, at P1, wrapped in a `threshold: > 0` over a ten-minute window grouped
by `userIdentity.arn`. Concretely:

- **The threshold is inert.** Any count above zero satisfies `> 0`, so the rule is per-event
  with a ten-minute batching delay bolted on. It is a volume rule that expresses no volume.
- **It never looks at who called.** Every ephemeral test-stack destroy and every Terraform
  apply that removes a cluster fires it. In an account where cluster lifecycle belongs to a
  pipeline, the caller is the entire signal and the rule does not read it.
- **It alerts on the last link.** The source set has no rule on `DeregisterContainerInstance`,
  `StopTask`, `DeleteCapacityProvider`, or on `UpdateService` with `desiredCount: 0` — the
  scale-to-zero AWS names in its own error message. The one precursor it does cover is
  `DeleteService`, at **P3**, two priorities *below* the cleanup step that follows it.

## The uncovered precursor that matters most

`UpdateService` with `desiredCount: 0` is the mandatory first move of the whole sequence, and
the source set's only `UpdateService` rule fires on a **high** desired count. It is
structurally blind to zero. That is a coverage gap in the destructive direction, and it is
carried as a P2 trigger row in `../PLAYBOOK.md` §2 and as a sibling block in the
`ecs_cluster_teardown_precursor_bb` base rule here. See
`../../ecs.impact.updateservice-with-high-desiredcount/` for the other half of that field.

## Delete-then-recreate is documented anti-forensics

AWS: *"If you have tasks with tags, and then delete the cluster, the tagged tasks are returned
in the response. If you create a new cluster with the same name as the deleted cluster, the
tagged tasks are not included in the response."* Recreating the cluster under its old name is
therefore a supported way to make the task history unreachable, and it is a step a responder
can still get in front of if the alert arrives in time. `sigma_t1070.yml` carries a
`temporal_ordered` correlation for the pair; `kql_t1070.kql` does the join properly, on the
cluster name.

The join is not trivial. `DeleteCluster` names the cluster in `requestParameters.cluster`,
which AWS documents as *"the short name or full Amazon Resource Name (ARN)"* — a
**caller-typed** value that arrives in either form. `CreateCluster` names it in
`requestParameters.clusterName`, always short. Sigma cannot join across two field names, still
less across two formats, so the correlation groups by principal and the KQL normalises both
sides to a bare name first. This is the same shape as the queue-name takeover in
`../../sqs.stealth.a-queue-was-deleted/`, and it fails the same way if the normalisation is
skipped.

## The counts in the response are zero by construction

`DeleteCluster` returns the object **nested** — `responseElements.cluster.*` — carrying
`registeredContainerInstancesCount`, `runningTasksCount`, `pendingTasksCount` and
`activeServicesCount`, with `status` becoming `INACTIVE`. On a **successful** call every one
of those counts is zero, because ECS would have refused otherwise. They are informative only
on a **denied** call, where they record how populated the cluster was when the attempt was
made. Reading a zero off a successful deletion as "nothing was running" is a false negative
with the event's own field as its evidence.

AWS also warns against relying on the deleted cluster remaining visible: *"Clusters with an
`INACTIVE` status might remain discoverable in your account for a period of time. However,
this behavior is subject to change in the future. We don't recommend that you rely on
`INACTIVE` clusters persisting."*

## The verification trap

`describe-clusters` on a deleted cluster does **not** error. It returns HTTP 200 with the
cluster absent from `clusters` and a `failures` entry whose `reason` is `MISSING` — AWS
documents that reason for `DescribeClusters` as *"The specified cluster wasn't found."* The
CLI exits 0. Any recovery check shaped as `if aws ecs describe-clusters ...; then echo "[OK]"`
certifies a destroyed cluster as healthy. Three states must be distinguished, plus a fourth
for the call itself: `ACTIVE`, `INACTIVE`, `MISSING`, and *no output at all* — which is a
failed call and must reach `[!] INCONCLUSIVE`, never the pass branch. Note also that a wrong
**cluster** name yields a `MISSING` failure while a wrong cluster on `DescribeServices` throws
`ClusterNotFoundException` — the two APIs report the same mistake differently.

## Response levers

**Error strings:** The full documented `DeleteCluster` set is ten: `AccessDeniedException`, `ClientException`,
`ClusterContainsCapacityProviderException`, `ClusterContainsContainerInstancesException`,
`ClusterContainsServicesException`, `ClusterContainsTasksException`, `ClusterNotFoundException`,
`InvalidParameterException`, `ServerException`, `UpdateInProgressException`. The four
`ClusterContains*` forms are the operationally interesting ones: each is an attempt to delete a
**populated** cluster, which is a more urgent finding than a successful deletion of an empty
one. ECS uses the `Exception` suffix throughout — there is no bare `AccessDenied` in ECS's
documented set — and its Common Errors page carries a second, distinct denial code,
`NotAuthorized` (HTTP 401). Match both. The Common Errors page gives `AccessDeniedException` as
HTTP 403 while every per-API Errors section gives it as 400, so do not key a rule on the code
and the status together.

## Data plane

ECS logs control-plane operations as **management** events, on by default. The only data
events AWS documents for ECS are `ecs:Poll`, `ecs:StartTelemetrySession` and
`ecs:PutSystemLogEvents`, under `resources.type` `AWS::ECS::ContainerInstance`. **There is no
`AWS::ECS::Task` advanced-event-selector resource type** — do not build a detection on one.

**GuardDuty:** There is **no GuardDuty finding type specific to ECS cluster deletion.** Identity-side findings
such as `Impact:IAMUser/AnomalousBehavior` may fire on the principal rather than on the cluster.
Do not build the response on one existing.

**MITRE:** The parent is
defensible and the tactic is right; the mapping is imprecise rather than wrong. The precise
sub-technique is **T1578.003 — Delete Cloud Instance**, whose description is exactly this
behaviour: deleting infrastructure after malicious activity to evade detection and remove
evidence.

The primary carried here is **T1070 — Indicator Removal**, also under Stealth, because what
this call actually destroys is a *record*: the cluster's settings, tags and capacity-provider
associations, and — via the documented same-name recreate — the retrievability of the stopped
tasks. **T1485** (Data Destruction) and **T1489** (Service Stop) belong to the *precursors*, not
to this event, and they are carried on the `ecs_cluster_teardown_precursor_bb` base rule where
they are earned. All IDs verified live against MITRE on 2026-08-29.

**Severity:** **High**, against the source's **P1**, which is close to right — an unusually good call for
this source set, and the only one of the five ECS rules whose priority does not need raising.
The reservation is elsewhere: a P1 on the *last* event of a sequence whose first events are
either unalerted or rated P3 means the pager fires after the damage is complete.

**Files here:**

- `sigma_t1070.yml` — five documents: the non-pipeline cluster deletion (`high`), a teardown
  precursor base rule (`informational`, covering the scale-to-zero the source set does not
  alert on), a `CreateCluster` base rule (`informational`), a `temporal_ordered` correlation
  firing `high` on precursor-then-deletion within 60 minutes, and a `temporal_ordered`
  correlation firing `high` on delete-then-create within 30 minutes.
- `kql_t1070.kql` — joins deletion to recreation **on the normalised cluster name**, counts the
  precursors that had to run first, and splits denials into `ClusterContains*` (an attempt on a
  populated cluster) and access denials (a permission probe).

Full response procedure is in `../PLAYBOOK.md`.
