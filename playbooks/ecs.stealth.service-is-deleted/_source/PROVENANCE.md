# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The single service-deletion alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| Service Is Deleted | P3 | per-event | T1578/TA0005 |

## Merge decision — no merge

**One source rule, one playbook.** The symmetric candidate is `Service Is Created`, and both of
`07-TIERS.md`'s tests were applied against it rather than assumed away. The full comparison is in
`../../ecs.stealth.service-is-created/_source/PROVENANCE.md` and is not duplicated here; the
short form is:

- **Test 1 fails on both clauses.** The events do not share a request shape — `CreateService`
  declares the workload (`taskDefinition`, `desiredCount`, `enableExecuteCommand`,
  `networkConfiguration.awsvpcConfiguration.*`), while `DeleteService` carries only `cluster`,
  `service` and `force`. And the responses share no step: one removes a resource and rotates
  what it could read, the other restores a resource and its load-balancer and service-discovery
  wiring.
- **Test 2 does not apply.** Neither rule is a correlation.

## The reason this use case in particular could not be merged

**Deleting a service is also the remediation.** It is step one of
`../../ecs.stealth.service-is-created/` §4 — the call an incident responder makes to remove an
attacker's workload. That gives this use case a requirement none of its neighbours has: the
alerting path must allowlist the **break-glass responder role** alongside the deployment role,
and triage must be able to distinguish the SOC's own containment from an outage. `kql_t1489.kql`
does that by joining each deletion back to the `CreateService` that produced the service — a
service created by the same principal an hour ago and deleted now is cleanup; a service created
by the pipeline two years ago and deleted now is destruction.

A merged create-and-delete rule would put an alert's own remediation inside the alert, and the
first thing a SOC would do is mute it. That is a response-level difference, which is precisely
what test 1's second clause exists to catch.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../ecs.stealth.service-is-created/` | **Separate** — opposite direction, no shared request field, no shared response step, and this event is the other one's containment action |
| `../../ecs.stealth.cluster-is-deleted/` | **Separate.** `DeleteCluster` is *downstream* of this event: ECS refuses to delete a cluster that still contains services, so a successful cluster deletion proves every service in it was already deleted. Different resource, different reversibility, and the cluster playbook's own scale-to-zero base rule covers the precursor chain |
| `../../ecs.impact.updateservice-with-high-desiredcount/` | **Separate.** Its `UpdateService desiredCount: 0` blind spot is the *precursor* to this event — ECS requires a service be scaled to zero before deletion unless `force` is set — and that precursor is shipped here as the `ecs_service_scaled_to_zero_bb` base rule, not merged into the magnitude playbook where it does not belong |

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

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
