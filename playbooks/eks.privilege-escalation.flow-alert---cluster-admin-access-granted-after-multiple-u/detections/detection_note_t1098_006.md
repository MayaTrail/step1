# Detection Note — T1098.006 / T1613 (Cluster-Admin Granted After Repeated Denials)

**Signal:** authorization denials by one Kubernetes identity, followed within the hour by that
same identity acquiring full control of the cluster — on either of two telemetry planes.

## The telemetry does not exist by default, and that comes first

Every plane-1 rule in `sigma_t1098_006.yml` reads the **Kubernetes audit log**, which on EKS is a
control-plane log type that AWS ships **off**: *"By default, cluster control plane logs aren't
sent to CloudWatch Logs. You must enable each log type individually."* It cannot be enabled
retrospectively, and an account that never enabled it produces the same empty result as an
account where nothing happened.

So before reading any zero from these rules as a finding, confirm the type is on:

```bash
aws eks describe-cluster --name "$CLUSTER" --region "$REGION" \
  --query 'cluster.logging.clusterLogging[?enabled==`true`].types' --output json
```

Destination is fixed — CloudWatch Logs group `/aws/eks/<cluster>/cluster`, stream prefix
`kube-apiserver-audit-` — and AWS states delivery is *"best effort"*, so a gap is a third state
distinct from both "not enabled" and "nothing happened".

## Why this is a flow and stays a flow

`07-TIERS.md` merge test 2 exists to collapse a correlation that adds no observable. It does not
apply here, for two independent reasons set out in `../_source/PROVENANCE.md`. The short form:
**the ordering is the thesis.** Denials are ordinary in any cluster with working RBAC; grants are
ordinary in any cluster with platform automation; and neither block, at the volume a real cluster
produces, survives tuning on its own. The pair, bound to one `user.username` inside an hour, has
no benign form.

## The grant is reachable on two planes and only one of them is Kubernetes

This is the defect that matters most, because it is silent.

| Route | Where the grant lives | Visible in the audit log? |
|---|---|---|
| `ClusterRoleBinding` with `roleRef: cluster-admin` | Kubernetes object | Yes, with full `requestObject` |
| Binding whose `subjects` include group `system:masters` | Kubernetes object | Yes — but contains the string `cluster-admin` nowhere |
| `kube-system/aws-auth` mapping into `system:masters` | Kubernetes object | `update`/`patch`/`delete` yes, with body. **`create` — body absent** |
| `eks:AssociateAccessPolicy` + `AmazonEKSClusterAdminPolicy` | **Nothing in the cluster** | **No. CloudTrail only** |

AWS documents `AmazonEKSClusterAdminPolicy` as `apiGroups: *`, `resources: *`, `verbs: *` plus
`nonResourceURLs: *`. A principal holding it is an administrator of the cluster, and
`kubectl get clusterrolebindings` returns clean over it — there is no Kubernetes object to find.
That is why `eks_access_policy_cluster_admin` carries `logsource: product: aws, service:
cloudtrail` while every other detection rule in the file carries `product: kubernetes, service:
audit`. A file mixing two logsources is not an inconsistency here; it is the shape of the service.

Two adjacent policies matter for the same reason: `AmazonEKSSecretAdminPolicy` grants `secrets`
with verb `*`, and `AmazonEKSAdminViewPolicy` grants `get`/`list`/`watch` on `*`/`*` — AWS notes
outright that it *"includes Kubernetes Secrets"*. Either is a credential-access grant without the
word "admin" doing any work.

## Field-shape traps, all three of which make a rule inert rather than noisy

1. **`sourceIPs`, not `sourceIPAddresses`.** The Kubernetes audit `Event` schema names the field
   `sourceIPs` and types it `[]string`. There is no `sourceIPAddresses`. A conjunct on that name
   is unsatisfiable unless the ingestion pipeline renames it, and an unsatisfiable conjunct makes
   the whole rule match nothing while producing no error. Behind a proxy the client address is
   element **0** and the proxy is last.
2. **`responseStatus.code` is `int32`.** It is `meta/v1.Status.code`. The rules here match it
   unquoted. A backend that ingests it as a string needs the quoted form, and getting this wrong
   is the same silent-inert failure. AWS's own published example query for unauthorized access
   writes `responseStatus.code="401"` — wrong type *and* wrong code.
3. **`403`, not `401`.** RBAC refusal is `403 Forbidden`. `401 Unauthorized` is an authentication
   failure — an unmappable IAM principal, an expired token — and belongs to a different incident.
   A denial stage keyed on `401` does not see RBAC at all.

A fourth, less obvious: `objectRef.name` is **absent on `list` and `watch`**, because those target
a collection. It is populated in this playbook's rules only because every one of them matches a
named write.

## Base rules feeding the correlation carry the success filter

`eks_rbac_cluster_admin_granted` requires `responseStatus.code` in `200`/`201`. Without it, a
**denied** binding attempt satisfies the grant stage, so a probe that failed plus an unrelated
legitimate denial fires a `critical` correlation. `eks_authz_denied` is the mirror: it matches
`403` and nothing else, so a successful request cannot satisfy the first stage.

`eks_rbac_escalate_verb` deliberately carries **no** success filter and no principal gate. The
`escalate` and `bind` verbs exist solely to switch off Kubernetes' own privilege-escalation
prevention; an *attempt* to use them is worth the alert whether or not it succeeded, and gating
on a principal would hide the case the rule is for.

## What none of these rules can see

**Escalation through a templated `aws-auth` mapping.** AWS states that a caller who can assume a
role whose mapping uses `{{SessionName}}` in the **`groups`** field *"can choose their own
Kubernetes group membership by crafting the session name"*. The privilege is selected inside
`sts:AssumeRole`, which names no cluster; nothing is created, nothing is patched, and the
resulting cluster request is an ordinary authenticated call. There is no event to write a rule
against. `../PLAYBOOK.md` §3 Step 1 removes the primitive instead, and Query 3 reports the
equivalent primitive on the access-entry plane.

**The creation of `aws-auth` where none existed.** The EKS default audit policy's first rule
covers that ConfigMap at `RequestResponse` for `update`, `patch` and `delete` — `create` is not in
its verb list, so a create falls through to the generic `configmaps` rule at `Metadata` and
carries no body. `eks_aws_auth_masters_grant` matches `update`/`patch` only, and says so in its
own description rather than appearing to cover a case it cannot.

**The cluster creator.** AWS states the IAM principal that created the cluster is granted
`system:masters` and *"doesn't appear in any visible configuration"*. No rule fires on it, no
sweep enumerates it, and if it is the compromised identity then every containment step in
`../PLAYBOOK.md` has been applied to the wrong principal.

## Response levers

**MITRE:** the source maps this to `T1078 — Valid Accounts` and `T1548 — Abuse Elevation Control Mechanism`. The grant itself is `T1098.006 — Account Manipulation: Additional Container Cluster Roles`, and the repeated denials that precede it are `T1613 — Container and Resource Discovery`. Both verified live 2026-08-30.

**GuardDuty:** EKS Protection covers this area well from EKS audit logs — including `Policy:Kubernetes/AdminAccessToDefaultServiceAccount`, `PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleBindingCreated`, `CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed` and `Policy:Kubernetes/AnonymousAccessGranted`, plus the `AttackSequence:EKS/CompromisedCluster` correlation. Treat these rules as complementary and check for overlap before routing both.

**Files here:**

- `sigma_t1098_006.yml` — the flow's base rules and the ordered correlation over them.
- `kql_t1098_006.kql` — the same sequence expressed against CloudWatch Logs Insights, with both stages in one query.

**Cross-references**

- `../PLAYBOOK.md` §2 reproduces `eks_rbac_cluster_admin_granted` verbatim; Query 1 implements
  both correlation stages against CloudWatch Logs Insights, Query 3 sweeps all four routes.
- `../../_ground-truth/eks.md` §3 carries the full EKS default audit policy and the consequences
  table this note draws on.
- `../../eks.lateral-movement.unauthorized-user-trying-to-get-secrets/` — what the grant is used
  for, and why the audit log cannot say what was read.
- `../../_superseded/aws.defense-evasion.cloudtrail-logging-tampered/` — the reasoning for a detection whose
  own telemetry is the target, which `../../eks.stealth.user-deleted-log-events/` reuses one plane
  down.

Full response procedure is in `../PLAYBOOK.md`.
