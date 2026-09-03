# Provenance

**Use case:** Flow Alert - Cluster Admin Access Granted After Multiple Unauthorized Operations
**Retrieved:** 2026-08-29
**Extract:** `original_rules.yml` — de-identified, logic-only. It contains **three** entries:
the flow rule and the two building blocks it composes, because a flow whose stages are not
reproduced is not auditable. Name, priority, type, ATT&CK mapping, telemetry plane, referenced
fields, group-by and the flow's stage composition are kept; all platform scaffolding is
stripped. No source, vendor, product or repository is named here or in any shipped file.

## Merge decision — NOT merged. Test 2 was checked and fails on both halves

`07-TIERS.md` merge test 2: *"A FLOW/correlation rule that is purely the composition of building
blocks you are already shipping, adding no new observable. It becomes a correlation document
inside the existing playbook's Sigma, not a playbook of its own."*

**Half one — precondition.** Test 2 relocates a flow *into a sibling playbook*. The two building
blocks here are "user attempts multiple denied actions" and "user assigned cluster-level
administrative permissions". Neither is among the five use cases in scope, so there is no
existing playbook for the correlation to move into. Test 2 relocates; it does not delete a flow
that has no host. The blocks therefore ship as **named base rule documents inside this
playbook's Sigma** (`eks_authz_denied`, `eks_rbac_cluster_admin_granted`), which is the shape
test 2 would have produced anyway had a host existed.

**Half two — merits, and this is the stronger half.** The flow is **not** purely the composition
of its blocks, because **the ordering is the thesis**. Authorization denials are ordinary in any
cluster with working RBAC; administrative grants are ordinary in any cluster with platform
automation. Neither block alone justifies a P1, and neither would survive tuning. What justifies
it is *denials by an identity, then a grant naming that same identity, within the hour* — a
composition that carries information neither component does. That is the definition of a
use case in its own right.

Correcting it also required replacing both stages rather than reusing them, which is further
evidence the flow is not a pure composition:

| Stage | As sourced | As shipped |
|---|---|---|
| Denials | matched an HTTP status that does not correspond to RBAC refusal | `responseStatus.code: 403`, unquoted, with `401` split off as a different incident |
| Grant | Kubernetes audit log only | **two planes** — the Kubernetes binding *and* `eks:AssociateAccessPolicy` on CloudTrail, which creates no Kubernetes object at all |
| Binding | empty group-by, so the two stages were not bound to one identity | `group-by: user.username` |

**Merge test 1** (same observable, same response, differing only in threshold) does not apply:
no sibling in scope shares this observable.

## Tier decision — promoted to Tier 1

Three of `07-TIERS.md`'s five tests apply.

**Test 1 — account takeover is reachable in one further hop.** `cluster-admin` on EKS reads every
Secret and every projected ServiceAccount token in the cluster. A ServiceAccount annotated
`eks.amazonaws.com/role-arn`, or carrying an EKS Pod Identity association, converts a readable
token into AWS credentials for the bound IAM role. The `AmazonEKSClusterAdminPolicy` route is
already an AWS API call: AWS documents it as `apiGroups: *`, `resources: *`, `verbs: *` plus
`nonResourceURLs: *`.

**Test 2 — the response has ordering that can go wrong.** Three ways, and two are irreversible.
Deleting the binding destroys the `roleRef` and usually the ClusterRole it named, so the evidence
query must precede containment. Removing the Kubernetes grant without removing the access-policy
association leaves a live administrator, and removing the association without removing the
binding does the same in the other direction. And deleting the access entry you are yourself
authenticating with, on a cluster whose creator principal is unavailable, is an outage `kubectl`
cannot fix — which is why §3 Step 2 opens with a lockout check that can stop the step.

**Test 3 — the blast radius is not in the event, and getting it after containment is impossible.**
The binding event names a `roleRef`; what that ClusterRole grants is a separate object that the
remediation deletes. The access-policy route is worse: it leaves no cluster-side object at all,
so `kubectl` cannot enumerate the administrators of the cluster it is talking to.

Test 5 (structural blind spot) also holds — escalation via a templated `aws-auth` mapping happens
inside `sts:AssumeRole` and produces no cluster-side event of any kind — but three tests already
exceed the threshold, and that gap is documented in §3 and Residual Risk rather than claimed here.

## Findings about the source rules, not about the technique

1. **Both stages read `sourceIPAddresses`.** The Kubernetes audit `Event` schema names that field
   **`sourceIPs`**, typed `[]string`. There is no `sourceIPAddresses`. Unless the ingestion
   pipeline renames it, any conjunct on that name is unsatisfiable and makes the whole rule inert
   while producing no error — the same failure class as the ECS `accountId:"anonymous"` finding
   in `../../ecs.initial-access.command-executed-inside-a-container/`.
2. **The flow's group-by is empty**, so its two stages are not bound to one identity. Denials by
   one principal and a grant to another satisfy it cluster-wide.
3. **The grant stage cannot see the AWS plane**, which on a cluster in `API` authentication mode
   is the *only* plane a grant happens on.

## Siblings

- `../../eks.lateral-movement.unauthorized-user-trying-to-get-secrets/` — what the grant is used for.
- `../../eks.persistence.flow-alert---suspicious-operation-detected-from-service-ac/` — the same
  escalation performed by a workload identity, where containment is entirely different.
- `../../eks.stealth.user-deleted-log-events/` — the follow-on move against this playbook's telemetry.
- `../../ecs.initial-access.command-executed-inside-a-container/` — container credential theft on the
  ECS endpoint; the shared ground truth is cross-referenced from `../../_ground-truth/eks.md` rather
  than repeated.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
deliberately, for the reason given in the authoring brief. What is retained is the detection
logic that was available: name, priority, type, MITRE label, telemetry plane, referenced fields,
window and group-by. Where the source query text was not available — the two building blocks —
that is stated in the extract rather than reconstructed, and no Quality Notes entry asserts logic
that was not read.

Shipped `references:` cite public MITRE and AWS documentation only.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
