# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The single service-creation alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| Service Is Created | P3 | per-event | T1578/TA0005 |

## Merge decision — no merge, and the symmetric case was tested rather than assumed

**One source rule, one playbook.** The obvious merge candidate is `Service Is Deleted`: the two
rules are the same shape (bare `eventName` plus a success filter), the same priority (P3), and
the same MITRE label (T1578/TA0005), and they name opposite halves of one resource lifecycle.
That symmetry is exactly why the tests were applied explicitly.

### Test 1 — same observable, same response, differing only in threshold or priority? **No, on both clauses.**

**Not the same observable.** The two events do not share a request shape. `CreateService` carries
`serviceName`, `taskDefinition`, `desiredCount`, `launchType`, `enableExecuteCommand`,
`loadBalancers` and a three-level
`networkConfiguration.awsvpcConfiguration.{subnets,securityGroups,assignPublicIp}` — a full
declaration of what will run and where. `DeleteService` carries exactly three parameters:
`cluster`, `service` and `force`. There is no field they have in common beyond the cluster and
the service name, and every discriminator this playbook uses (`assignPublicIp`,
`enableExecuteCommand`, the task-definition join) is absent from the deletion event. A merged
rule would have nothing to match on.

**Not the same response.** This is what actually decides it, and the two procedures share no
step:

| | Service created | Service deleted |
|---|---|---|
| Containment | Scale to zero **then** delete; the scheduler replaces stopped tasks, so ordering is load-bearing | Capture the deletion event's `responseElements.service` before anything else; it is the only surviving description |
| Eradication | Remove a resource — delete the service, deregister the task definition, rotate the secrets it could read, review the task role's activity | Restore a resource — rebuild from IaC, re-register the load-balancer target group and the service-discovery entries |
| Blast radius | Whatever the task role reaches, every secret in the definition, the network the actor chose | The tasks that stopped, the target-group registration, the discovery entries, the service definition itself |
| Residual risk | The image is still in the registry and the task definition is still registered — both survive deleting the service | The task definition survives, but the runtime and its wiring do not |
| Triage question | "What is this running, and under what identity?" | "Was this ours or the actor's — and was it *us* who deleted it?" |

The last row is not a nicety. `DeleteService` is the containment step **of this playbook**
(§4), so the deletion use case has to allowlist the incident-response role and correlate each
deletion back to the service's creation. Merging would put an alert's own remediation inside the
alert.

### Test 2 — a FLOW/correlation rule that is purely the composition of shipped building blocks? **No.** Neither rule is a correlation; both are per-event matches.

**Verdict: two use cases, two playbooks.** A created service is attacker workload; a deleted one
is destruction or cleanup. They stay separate, and each cross-references the other.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../ecs.stealth.service-is-deleted/` | **Separate** — see above. Cross-referenced in both directions |
| `../../ecs.impact.updateservice-with-high-desiredcount/` | **Separate.** Same resource, different event and a magnitude discriminator this rule does not have. Scaling an existing service is not deploying a new one |
| The source set's `RegisterTaskDefinition with Resource-Intensive Parameters` alert | **Separate, and out of scope for this batch** — but it is the closest thing the source set has to covering the payload half of this technique, and it does not: it matches only `cpu`/`memory` digit counts and never inspects `image`, `command` or `taskRoleArn`. The task definition is where the persistence actually lives, and that gap is recorded in `../PLAYBOOK.md` §2 and §6 |

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project
— including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals
are packaged in a proprietary format whose scaffolding — payload field lists, entity
labels, product-specific field prefixes, internal enums and packaging metadata —
identifies the source on sight while bearing on nothing about whether the rules are
correct. What is retained is the complete detection logic: name, priority, type, MITRE
label, the query verbatim, threshold, window and group-by.

No substitution was needed in this extract.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS
documentation only — a deployed rule travels outside the organisation that wrote it, and
an internal path is not resolvable to whoever receives it.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.
