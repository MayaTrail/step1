# IR Playbook: Cluster-Admin Access Granted After Repeated Denials — self-escalation in the EKS Kubernetes API via `ClusterRoleBinding` and `AssociateAccessPolicy`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Privilege escalation + Persistence (an identity that was being refused by RBAC acquires full control of the cluster, and keeps it) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, P0 on the correlated pair. Cluster-admin on EKS is not a Kubernetes-scoped privilege: it reads every Secret and every projected ServiceAccount token in the cluster, and a token belonging to a ServiceAccount bound to an IAM role through IRSA or EKS Pod Identity converts directly into AWS credentials. The source rates it **P1**; the disagreement is one step, and the reason to raise it is that the grant is *reachable on a plane the source rule does not watch at all* (§2) |
| MITRE Tactics | Privilege Escalation (TA0004), Persistence (TA0003) |
| MITRE Techniques | T1098.006 (primary), T1613 (the denial phase) — both verified live 2026-08-29 |
| Services in Scope | EKS (control plane, access entries, access policies), CloudWatch Logs (the audit log itself), IAM + STS (the mapped principal), CloudTrail, plus every AWS role reachable through a ServiceAccount the actor could read a token for |

**What the technique does:** an identity that already authenticates to the cluster probes it and
is refused — `responseStatus.code: 403`, repeatedly, across resources it does not hold. It then
takes full control by one of four routes, and only the first is the one people look for: a
`ClusterRoleBinding` whose `roleRef` names `cluster-admin`; a binding whose `subjects` include
the group `system:masters`, which Kubernetes' own default `cluster-admin` ClusterRoleBinding
already binds to that role; an edit to `kube-system/aws-auth` mapping an IAM ARN into
`system:masters`; or — entirely outside Kubernetes — `eks:AssociateAccessPolicy` attaching
`arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy`, which AWS documents as
`apiGroups: *`, `resources: *`, `verbs: *` plus `nonResourceURLs: *`. From there the actor reads
every Secret, every ServiceAccount token, and the `aws-auth` map itself.

**Why the usual reflexes miss it.** Search the cluster and the fourth route leaves nothing to
find: EKS authorizes the principal itself, so `kubectl get clusterrolebindings` returns clean
over a live cluster-admin. Search for the string `cluster-admin` and the `system:masters` route
does not contain it. Read the audit log for the `aws-auth` body and you get it for `update`,
`patch` and `delete` only — the EKS default audit policy's first rule omits `create`, so building
that ConfigMap from nothing is recorded at `Metadata` level with no body. And revoke the IAM
principal without touching Kubernetes, or the Kubernetes binding without touching IAM, and the
grant still stands: they are independent systems that meet only in `user.username`.

**Detection is the ordering, and it has to span two planes.** Denials are ordinary and grants are
ordinary; *denials by an identity, then a grant naming that same identity within the hour* is
self-escalation and has no benign form. The correlation binds them on `user.username`, the only
field carrying the identity on both stages. What the source rule cannot reach is the AWS plane —
the access-policy route emits no Kubernetes audit event at all, so an audit-log-only flow's
second stage never arrives and the rule stays silent while the cluster is owned.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **The `audit` control-plane log type, enabled before the incident.** AWS: *"By default,
  cluster control plane logs aren't sent to CloudWatch Logs. You must enable each log type
  individually."* Without it there is no plane-1 telemetry and every audit query in §2 returns
  nothing. Destination is fixed — CloudWatch Logs group `/aws/eks/<cluster-name>/cluster`, stream
  prefix `kube-apiserver-audit-` — and delivery is *"best effort"*, so a gap is ambiguous between
  "nothing happened", "not enabled" and "not delivered". **`authenticator` alongside it**: an IAM
  principal that fails to map to a Kubernetes identity may produce no plane-1 event naming a real
  user, and that log is where the attempt is visible
- Audit event fields, nesting verified against the Kubernetes audit `Event` reference:
  `user.username` (string), **`user.groups` (array)**, `verb`, `objectRef.{resource, namespace,
  name, apiGroup, subresource}`, `responseStatus.code` (**int32**), `responseStatus.reason`,
  **`sourceIPs` (array — the schema has no `sourceIPAddresses`)**, `userAgent`,
  `annotations["authorization.k8s.io/decision"]`. `requestObject` and `responseObject` exist
  **only where the audit policy says so**
- **What the EKS default audit policy gives you here, and what it withholds.** The
  `rbac.authorization.k8s.io` group is `RequestResponse` for write verbs, so a binding event
  carries its full `roleRef` and `subjects` — this playbook depends on that.
  `kube-system/aws-auth` `update`/`patch`/`delete` is also `RequestResponse` and is the policy's
  *first* rule; **`create` is not in that rule's verb list**. `secrets` and `configmaps` generally
  are capped at `Metadata`; core `events` are `None`. The policy is a `kube-apiserver` flag, so
  on EKS **AWS owns it and you cannot change it**
- CloudTrail management events for `eks.amazonaws.com` — `AssociateAccessPolicy`,
  `CreateAccessEntry`, `UpdateAccessEntry`, `UpdateClusterConfig`. On by default, and the only
  telemetry that exists for the access-policy route
- A **standing export of the audit log out of CloudWatch Logs.** A retention change or a
  `DeleteLogStream` is irreversible and is the obvious follow-on — see
  `../eks.stealth.user-deleted-log-events/`

**Alerting (must be pre-configured)**
- **ClusterRoleBinding or RoleBinding written whose `roleRef` is `cluster-admin`, or a role written with wildcard verbs → P0**
- **Binding written whose `subjects` include the group `system:masters` → P0**
- **`AssociateAccessPolicy` attaching an EKS cluster-admin or secret-admin access policy → P0**
- **Three or more `403` responses for one `user.username` followed within one hour by a successful cluster-admin grant → P0**
- **`kube-system/aws-auth` updated or patched so the new body contains `system:masters` → P1**
- **`escalate` or `bind` verb used against `roles` or `clusterroles` → P1**

**Response Tooling**
- `kubectl` against the cluster with **break-glass credentials that are not the principal under
  investigation and not an access entry you are about to delete**. Removing your own access entry
  while holding no second path in is the commonest way this response self-destructs
- AWS CLI: `eks list-access-entries`, `list-associated-access-policies`,
  `disassociate-access-policy`, `delete-access-entry`, and `logs start-query` /
  `get-query-results`. Insights queries are **asynchronous** — a `Running` status read once and
  treated as an empty result is a false negative
- `jq`, and a **holding place for evidence outside the cluster and outside its log group**

**Known IOC Baselines**
- The **complete list of identities that legitimately hold cluster-admin, on both planes**: every
  ClusterRoleBinding to `cluster-admin`, every subject in `system:masters`, every access entry
  with an admin access policy, every `aws-auth` mapping. This list is the entire discriminator
- The **cluster creator's IAM principal.** AWS: it holds `system:masters` and *"doesn't appear in
  any visible configuration"*, so no sweep will find it and it must be written down separately
- The cluster's `accessConfig.authenticationMode` (`CONFIG_MAP`, `API_AND_CONFIG_MAP`, `API`) —
  it decides which routes are live and therefore which containment steps apply
- The controllers that legitimately hold `escalate` or `bind`. A short, closed list

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | ClusterRoleBinding/RoleBinding written with `roleRef.name: cluster-admin`, or a Role/ClusterRole written with wildcard verbs | Kubernetes audit | T1098.006 |
| P0 | Binding written whose `subjects` include the group `system:masters` — reaches cluster-admin without naming it | Kubernetes audit | T1098.006 |
| P0 | `AssociateAccessPolicy` attaching `AmazonEKSClusterAdminPolicy`, `AmazonEKSAdminPolicy`, `AmazonEKSSecretAdminPolicy` or `AmazonEKSAdminViewPolicy` | CloudTrail (management) | T1098.006 |
| P0 | Three or more `403` responses for one `user.username`, then a successful cluster-admin grant within one hour | Kubernetes audit | T1098.006 |
| P1 | `kube-system/aws-auth` updated or patched and the new body contains `system:masters` | Kubernetes audit | T1098.006 |
| P1 | `escalate` or `bind` verb used against `roles` or `clusterroles` | Kubernetes audit | T1098.006 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `CreateAccessEntry`/`UpdateAccessEntry` supplying a `username` or `kubernetesGroups` containing `SessionName` | CloudTrail (management) | T1098.006 |
| P2 | `create`/`update` on `clusterroles` by an identity that has never written RBAC before | Kubernetes audit | T1098.006 |
| P2 | A burst of `403`s across many distinct `objectRef.resource` values by one identity, with no grant following — the probing half alone | Kubernetes audit | T1613 |

### Detection Rule Quality Notes

The source rule's thesis — denials, then a grant, same identity — is correct, and it is the
reason this stays a flow rather than collapsing into a grant rule. What it gets wrong is the
definition of both stages.

| Issue | Impact | Correction |
|-------|--------|-----------|
| The grant stage watches the Kubernetes audit log only | The EKS access-policy route creates **no Kubernetes object and emits no audit event**. `AssociateAccessPolicy` with `AmazonEKSClusterAdminPolicy` grants `*`/`*`/`*` from the AWS side; the flow's second stage never arrives, so the rule stays silent over a cluster with a live administrator it never saw created | Ship `eks_access_policy_cluster_admin` on the CloudTrail plane and carry it as its own P0 row |
| "Cluster admin" matched by role name | A binding whose `subjects` contain the group `system:masters` reaches the same permissions through Kubernetes' own default `cluster-admin` ClusterRoleBinding and contains the string `cluster-admin` nowhere. So does a freshly written ClusterRole with `verbs: ["*"]`. Both are missed | Three separate selections — `roleRef.name`, `subjects` containing `system:masters`, and wildcard rules — ORed |
| No success filter on either stage | A **denied** binding attempt satisfies a grant stage that matches on the verb, so a probe that failed plus an unrelated legitimate denial fires a high-severity correlation. This is the base-rule defect the kit has caught before | `responseStatus.code` in `200`/`201` on the grant stage; `403` and nothing else on the denial stage |
| Denials matched on `401` | `401` is an **authentication** failure — expired token, unmappable IAM principal. RBAC refusal is **`403`**. A rule keyed on 401 sees no RBAC denial at all, which is the entire first stage. AWS's own published example query for unauthorized access has this defect | Match `403`. Track `401` separately as an authentication incident |
| `responseStatus.code` compared as a quoted string | The audit `Event` types it as **int32** (`meta/v1.Status`). Whether `"403"` matches `403` is a property of the ingestion pipeline, and where it does not the rule matches nothing and reports clean | Match unquoted; confirm the pipeline type once, against a known 403 |
| `sourceIPAddresses` as a field name | The Kubernetes audit schema field is **`sourceIPs`, an array**. There is no `sourceIPAddresses`. Any conjunct on that name is unsatisfiable unless the pipeline renames it — and an unsatisfiable conjunct makes the whole rule inert while producing no error | Use `sourceIPs`, and remember the client IP is the **first** element behind a proxy |
| Empty group-by on the flow | Denials by one identity and a grant by another satisfy the sequence cluster-wide. This is the same defect the SMS flow in this corpus carried | `group-by: user.username` |
| Source priority P1 | The grant reaches every Secret and every ServiceAccount token in the cluster, several of which convert to AWS credentials | High, P0 on the correlated pair |

**Recommended detection — a Kubernetes cluster-admin binding created or modified.**

```yaml
# Cluster-admin granted after repeated authorization denials (T1098.006)
#
# TELEMETRY. These rules read the KUBERNETES AUDIT LOG, not CloudTrail. On EKS that log
# exists only if the `audit` control-plane log type was enabled before the incident — AWS:
# "By default, cluster control plane logs aren't sent to CloudWatch Logs. You must enable
# each log type individually." It lands in CloudWatch Logs group /aws/eks/<cluster>/cluster,
# stream prefix kube-apiserver-audit-. If it was off, every rule below returns zero and the
# zero means "not recorded", never "did not happen".
#
# WHY THE ORIGINAL FLOW IS KEPT AS A FLOW. Its thesis is ORDERING: denials FIRST, admin
# grant SECOND. Either half alone is ordinary — engineers hit RBAC denials all day, and
# platform automation grants roles all day. The pair, bound to one identity inside an hour,
# is self-escalation and nothing else. That is why this ships as its own correlation rather
# than folding into a grant rule.
#
# WHAT THE SOURCE RULE CANNOT DO, AND THESE RULES CAN.
#  * The grant is reachable on TWO planes and the source only watches one. A Kubernetes
#    ClusterRoleBinding is an audit-log event; an EKS access policy association is a
#    CLOUDTRAIL event that creates NO Kubernetes object at all. An account using access
#    entries can be handed
#    arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy — apiGroups *,
#    resources *, verbs *, plus nonResourceURLs * — with nothing appearing in the cluster
#    for a responder to find. eks_access_policy_cluster_admin below covers that plane.
#  * "Cluster admin" is not one string. cluster-admin by roleRef is the obvious form; adding
#    a subject to the system:masters GROUP reaches the same place through the default
#    cluster-admin ClusterRoleBinding, and so does a fresh ClusterRole carrying
#    apiGroups/resources/verbs "*". All three are matched.
#  * Kubernetes RBAC's own escalation guard is bypassable with the `escalate` and `bind`
#    verbs, which exist for no other purpose. Those get their own rule.
#
# FIELD SHAPES — verified against the Kubernetes audit Event API reference, 2026-08-29.
#   user.groups and sourceIPs are ARRAYS ([]string). sourceIPs is the schema name; there is
#   no `sourceIPAddresses` field, and a rule keyed on that name matches nothing unless the
#   ingestion pipeline renames it.
#   responseStatus.code is int32. Comparing it to a quoted string is backend-dependent.
#   objectRef.name is ABSENT on list and watch, because those target a collection.
#   requestObject is populated here only because the EKS default audit policy logs the
#   rbac.authorization.k8s.io group at RequestResponse level for write verbs. It is NOT
#   populated for secrets or configmaps, which that policy caps at Metadata — with one
#   exception, the aws-auth ConfigMap, which is the first rule in the policy and is logged
#   at RequestResponse for update, patch and delete. NOT for create: see the description on
#   eks_aws_auth_masters_grant.
title: Kubernetes cluster-admin binding created or modified
id: 4a4a7b4a-3b02-4a58-9a2c-3a0d3d18a3c4
name: eks_rbac_cluster_admin_granted
status: experimental
description: >-
  A ClusterRoleBinding or RoleBinding was created or changed so that its roleRef names the
  built-in cluster-admin ClusterRole, or a Role or ClusterRole was written granting
  apiGroups, resources and verbs of "*". Either shape hands the subject full control of the
  cluster, which on EKS includes reading every Secret and every projected ServiceAccount
  token in it. Logged with a full requestObject because the EKS default audit policy records
  the rbac.authorization.k8s.io group at RequestResponse level for write verbs.
references:
  - https://kubernetes.io/docs/reference/access-authn-authz/rbac/
  - https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
  - https://attack.mitre.org/techniques/T1098/006/
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.006
logsource:
  category: application
  product: kubernetes
  service: audit
detection:
  write_verb:
    verb:
      - 'create'
      - 'update'
      - 'patch'
  rbac_binding:
    objectRef.resource:
      - 'clusterrolebindings'
      - 'rolebindings'
  admin_roleref:
    requestObject.roleRef.name: 'cluster-admin'
  rbac_role:
    objectRef.resource:
      - 'clusterroles'
      - 'roles'
  wildcard_rule:
    requestObject.rules|contains: '"verbs":["*"]'
  succeeded:
    responseStatus.code:
      - 200
      - 201
  condition: write_verb and succeeded and ((rbac_binding and admin_roleref) or (rbac_role and wildcard_rule))
falsepositives:
  - >-
    Cluster bootstrap and platform automation. A GitOps controller or an installer reconciling
    its own bindings will match. Filter on user.username for the named automation identities
    before deploying, not on the resource — the resource is the whole signal.
level: high
---
title: Kubernetes subject added to the system:masters group
id: 6c1c1c5d-9a6a-4de9-9c62-9b0a5b23ab77
name: eks_masters_group_grant
status: experimental
description: >-
  A binding was written whose subjects include the group system:masters. This is the second
  route to full control and it does not mention cluster-admin anywhere: Kubernetes ships a
  default ClusterRoleBinding named cluster-admin that binds the system:masters group to the
  cluster-admin ClusterRole, so naming the group is equivalent to naming the role. A rule
  matching only roleRef misses it entirely.
references:
  - https://kubernetes.io/docs/reference/access-authn-authz/rbac/
  - https://attack.mitre.org/techniques/T1098/006/
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.006
logsource:
  category: application
  product: kubernetes
  service: audit
detection:
  write_verb:
    verb:
      - 'create'
      - 'update'
      - 'patch'
  binding:
    objectRef.resource:
      - 'clusterrolebindings'
      - 'rolebindings'
  masters_subject:
    requestObject.subjects|contains: 'system:masters'
  succeeded:
    responseStatus.code:
      - 200
      - 201
  condition: write_verb and binding and masters_subject and succeeded
falsepositives:
  - >-
    Almost none. system:masters is not a group any workload should be placed in after cluster
    bootstrap. Treat a match as an incident until an owner is produced.
level: high
---
title: aws-auth ConfigMap changed to add cluster-admin group membership
id: 0e7a2fd6-6e2b-4a52-8b2b-14a1e8c9b2ba
name: eks_aws_auth_masters_grant
status: experimental
description: >-
  The kube-system/aws-auth ConfigMap — the legacy map from IAM principals to Kubernetes
  identities — was changed and the new body contains system:masters. The EKS default audit
  policy's FIRST rule records exactly this object at RequestResponse level for update, patch
  and delete, so the full before-and-after is in the event. Note the gap that rule leaves,
  which this rule inherits and cannot close: `create` is not in its verb list, so building
  the ConfigMap from nothing on a cluster that has none is recorded at Metadata level with no
  body. Cover that case with the EKS-side authentication-mode rule and with a periodic
  configuration read, not with this rule.
references:
  - https://docs.aws.amazon.com/eks/latest/userguide/auth-configmap.html
  - https://attack.mitre.org/techniques/T1098/006/
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.006
logsource:
  category: application
  product: kubernetes
  service: audit
detection:
  target:
    objectRef.resource: 'configmaps'
    objectRef.namespace: 'kube-system'
    objectRef.name: 'aws-auth'
  write_verb:
    verb:
      - 'update'
      - 'patch'
  masters:
    requestObject.data.mapRoles|contains: 'system:masters'
  masters_users:
    requestObject.data.mapUsers|contains: 'system:masters'
  succeeded:
    responseStatus.code: 200
  condition: target and write_verb and succeeded and (masters or masters_users)
falsepositives:
  - >-
    A deliberate, ticketed administrative mapping. It should be rare and it should come from
    the platform automation identity; anything else is worth a phone call.
level: high
---
title: Kubernetes RBAC escalate or bind verb used
id: b3f8e5d1-73a4-4c6f-9b47-2f3d2a5b8c19
name: eks_rbac_escalate_verb
status: experimental
description: >-
  A request used the `escalate` or `bind` verb against roles or clusterroles. Kubernetes
  normally refuses to let a principal create or bind a role carrying permissions it does not
  itself hold; these two verbs exist solely to switch that guard off. Their appearance is
  the deliberate bypass of RBAC's own privilege-escalation prevention and has no routine use
  outside a controller that was explicitly granted them.
references:
  - https://kubernetes.io/docs/reference/access-authn-authz/rbac/
  - https://attack.mitre.org/techniques/T1098/006/
tags:
  - attack.privilege-escalation
  - attack.t1098.006
logsource:
  category: application
  product: kubernetes
  service: audit
detection:
  selection:
    verb:
      - 'escalate'
      - 'bind'
  rbac:
    objectRef.resource:
      - 'roles'
      - 'clusterroles'
  condition: selection and rbac
falsepositives:
  - >-
    A controller holding escalate or bind by design — some ingress and service-mesh
    installers do. Enumerate them once and filter on user.username; there should be a short,
    closed list.
level: high
---
title: Kubernetes authorization denied
id: 2d9b7c04-8f1e-4a3d-b6c8-5e4a1f7d2b30
name: eks_authz_denied
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. A request that authenticated
  and was then refused by RBAC. The discriminator is HTTP 403, not 401: 403 means the
  identity was established and the permission was missing, while 401 means authentication
  itself failed and no Kubernetes identity was resolved. responseStatus.code is an int32 in
  the audit Event schema, so it is matched unquoted here; a backend that ingests it as a
  string needs the quoted form instead, and getting that wrong makes this rule silently
  match nothing.
references:
  - https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
  - https://attack.mitre.org/techniques/T1613/
tags:
  - attack.discovery
  - attack.t1613
logsource:
  category: application
  product: kubernetes
  service: audit
detection:
  denied:
    responseStatus.code: 403
  condition: denied
level: informational
---
title: Repeated authorization denials followed by a cluster-admin grant by the same identity
id: 8f1d4b26-2a97-4e88-9c33-7b6a0e5d4c11
status: experimental
description: >-
  One Kubernetes identity accumulated authorization denials and then successfully granted
  itself, or was granted, full cluster control within the hour. Neither half is remarkable
  alone; the ordering is the finding. group-by is user.username because that is the only
  field that carries the identity on both stages — an IAM principal arrives as the STS
  assumed-role ARN its access entry maps to, a workload as system:serviceaccount:<ns>:<name>.
  Timespan is 1h rather than the source rule's window: probing and escalation happen in one
  working session, and a longer window pairs unrelated activity.
references:
  - https://attack.mitre.org/techniques/T1098/006/
  - https://attack.mitre.org/techniques/T1613/
tags:
  - attack.privilege-escalation
  - attack.persistence
  - attack.t1098.006
correlation:
  type: temporal_ordered
  rules:
    - eks_authz_denied
    - eks_rbac_cluster_admin_granted
  group-by:
    - user.username
  timespan: 1h
level: critical
---
title: EKS cluster-admin access policy associated with an IAM principal
id: 5b0f9a3e-4c71-42d6-8e59-1c8f7a2b6d43
name: eks_access_policy_cluster_admin
status: experimental
description: >-
  AssociateAccessPolicy attached AmazonEKSClusterAdminPolicy — or one of the other
  secret-reaching EKS access policies — to an access entry. This is the plane the Kubernetes
  audit log cannot see: EKS authorizes the principal itself, so no ClusterRoleBinding, no
  Role and no aws-auth entry is created, and a responder searching the cluster for the grant
  finds nothing. It is a CloudTrail management event, logged on a default trail, which is why
  this rule carries a different logsource from the rest of this file.
references:
  - https://docs.aws.amazon.com/eks/latest/userguide/access-policy-permissions.html
  - https://attack.mitre.org/techniques/T1098/006/
tags:
  - attack.privilege-escalation
  - attack.persistence
  - attack.t1098.006
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'eks.amazonaws.com'
    eventName: 'AssociateAccessPolicy'
  admin_policy:
    requestParameters.policyArn|contains:
      - 'AmazonEKSClusterAdminPolicy'
      - 'AmazonEKSAdminPolicy'
      - 'AmazonEKSSecretAdminPolicy'
      - 'AmazonEKSAdminViewPolicy'
  success:
    errorCode: null
  condition: selection and admin_policy and success
falsepositives:
  - >-
    Cluster provisioning, which associates the cluster-admin policy for the operators who
    will run it. Expect a burst at cluster creation and near-silence afterwards; alert on the
    silence being broken.
level: high
---
title: EKS access entry created with a templated username or group
id: c74e1a58-9d20-4e13-bb6f-3a5e8c1d9f27
name: eks_access_entry_templated
status: experimental
description: >-
  CreateAccessEntry or UpdateAccessEntry supplied a username or Kubernetes group containing
  the SessionName template. AWS states plainly that these values are user-controlled when a
  role is assumed, that a caller "can impersonate any Kubernetes username that doesn't match
  a reserved prefix", and that placing the template in groups lets a caller "choose their own
  Kubernetes group membership by crafting the session name". One such mapping is a standing
  escalation primitive that produces no configuration change when it is exercised — the
  escalation happens in the sts:AssumeRole call, which names no cluster.
references:
  - https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html
  - https://docs.aws.amazon.com/eks/latest/userguide/auth-configmap.html
  - https://attack.mitre.org/techniques/T1098/006/
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.006
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'eks.amazonaws.com'
    eventName:
      - 'CreateAccessEntry'
      - 'UpdateAccessEntry'
  templated_group:
    requestParameters.kubernetesGroups|contains: 'SessionName'
  templated_username:
    requestParameters.username|contains: 'SessionName'
  success:
    errorCode: null
  condition: selection and success and (templated_group or templated_username)
falsepositives:
  - >-
    Very few, and the reason is a request-versus-response distinction worth stating. AWS
    recommends letting EKS generate the username, and the generated value DOES contain the
    template — its published CreateAccessEntry response returns
    "arn:aws:sts::012345678910:assumed-role/my-role/{{SessionName}}". But that value appears
    in responseElements.accessEntry.username, not in requestParameters.username, because the
    caller did not send one. This rule reads the REQUEST, so the documented default does not
    match it and only an explicitly supplied template does. Do not "fix" this rule by moving
    it to the response field; that inverts it into an alert on every access entry ever
    created.
level: medium
```

This rule sees the Kubernetes plane and nothing else. It cannot see the access-policy route —
that is `eks_access_policy_cluster_admin` in the same file, on a CloudTrail logsource — and it
cannot see the `aws-auth` **create** case, because the EKS audit policy records that object's
body only for `update`, `patch` and `delete`. It also cannot see an escalation performed by
crafting an STS session name against a templated `aws-auth` mapping: that escalation happens
in `sts:AssumeRole`, which names no cluster, and the resulting cluster access looks like an
ordinary authenticated request. `detections/detection_note_t1098_006.md` covers what closes
each of those gaps.

---

### Key Investigation Queries

> The Kubernetes audit log is **CloudWatch Logs, not CloudTrail** — the extraction pattern is `logs start-query` then `get-query-results`, and it is **asynchronous**. A `Running` status read once and treated as an empty result is a false negative, so every block below polls to a terminal status and routes `Failed`, `Cancelled` and `Timeout` to `[!] INCONCLUSIVE`. Queries 1, 2, 3 and 5 are per cluster; Query 4 must also cover CloudTrail in **every** region the mapped IAM principal can reach.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: the denials, the grant, and whether they are the same identity

```bash
REGION="us-east-1"; CLUSTER="<cluster-name>"
LG="/aws/eks/${CLUSTER}/cluster"
START=$(date -u -d '30 days ago' +%s); END=$(date -u +%s)

# Both stages in one pass. The audit log is one stream family, so denials and grants are
# separated by predicate rather than by query. Note the field names: sourceIPs is an ARRAY, so
# element 0 is addressed explicitly; responseStatus.code is an integer and is compared unquoted.
Q='fields @timestamp, user.username, verb, objectRef.resource, objectRef.namespace, objectRef.name, responseStatus.code, sourceIPs.0, userAgent, requestObject.roleRef.name, annotations.authorization.k8s.io/decision
| filter @logStream like "kube-apiserver-audit"
| filter responseStatus.code = 403
   or (verb in ["create","update","patch"] and objectRef.resource in ["clusterrolebindings","rolebindings","clusterroles","roles"])
   or (objectRef.name = "aws-auth" and objectRef.namespace = "kube-system")
   or verb in ["escalate","bind"]
| sort @timestamp asc
| limit 2000'

QID=$(aws logs start-query --region "$REGION" --log-group-name "$LG" \
        --start-time "$START" --end-time "$END" --query-string "$Q" \
        --output text --query 'queryId')
RES=""; STATUS="Scheduled"
case "${QID:-}" in
  ''|None) STATUS="StartFailed";;
  *) TRIES=0
     while [ "$STATUS" = "Scheduled" ] || [ "$STATUS" = "Running" ]; do
       TRIES=$((TRIES + 1)); [ "$TRIES" -gt 90 ] && { STATUS="PollTimeout"; break; }
       sleep 2
       RES=$(aws logs get-query-results --region "$REGION" --query-id "$QID" --output json)
       [ -z "$RES" ] && { STATUS="CallFailed"; break; }
       STATUS=$(printf '%s' "$RES" | jq -r '.status // "NoStatus"')
     done;;
esac
if [ "$STATUS" != "Complete" ]; then
  echo "[!] INCONCLUSIVE - the query ended '$STATUS'. StartFailed means the log group $LG does"
  echo "not exist (audit logging never enabled), the region is wrong, or logs:StartQuery is"
  echo "    denied. None of these is 'no matching activity'."
else
  echo "[i] $(printf '%s' "$RES" | jq '.results | length') audit record(s) matched"
  printf '%s' "$RES" | jq -r '[.results[] | map({key: .field, value: .value}) | from_entries |
    {time: .["@timestamp"], user: .["user.username"], verb: .verb,
     resource: .["objectRef.resource"], ns: .["objectRef.namespace"],
     name: .["objectRef.name"], code: .["responseStatus.code"],
     src_ip: .["sourceIPs.0"], agent: .userAgent,
     role_ref: .["requestObject.roleRef.name"],
     decision: .["annotations.authorization.k8s.io/decision"]}] | sort_by(.time)'
fi
```

Read it as a sequence, not as a set. A run of `code: 403` from one `user`, then a `create` or
`update` on a binding **by that same `user`** with `code: 200` or `201`, is the incident. Record
`user`, `src_ip`, `agent` and the binding's `name` as IOCs. Two shapes deserve special attention:
a `user` beginning `system:serviceaccount:` means a **workload** escalated, and the response is
the one in `../eks.persistence.flow-alert---suspicious-operation-detected-from-service-ac/`; a
`user` that is an `arn:aws:sts::…:assumed-role/…` string is an **IAM principal** arriving through
an access entry, and its session name is the tail segment. A grant with **no preceding denials**
is not exculpatory — it means the actor already knew what it could do, or escalated on the AWS
plane where the denials would not appear.

#### Query 2 — Ground truth: what the grant actually confers, before anything is deleted

```bash
BINDING="<binding-name-from-Query-1>"

# TIME-CRITICAL, AND THE REASON THIS PRECEDES §3. Deleting the binding deletes the roleRef, and
# a ClusterRole created for the purpose usually goes with it; after that, what was granted is
# knowable only from the audit event, and only if the audit log survives.
B=$(kubectl get clusterrolebinding "$BINDING" -o json)
ROLE=""
if [ -z "$B" ]; then
  echo "[!] INCONCLUSIVE - the ClusterRoleBinding could not be read: it may be a namespaced"
  echo "    RoleBinding, already deleted, or kubectl may lack permission. Fall back to requestObject"
  echo "    in the Query 1 event - it is RequestResponse-level and carries the full roleRef and"
  echo "    subjects."
else
  printf '%s' "$B" | jq -r '{name: .metadata.name, created: .metadata.creationTimestamp,
    role_kind: .roleRef.kind, role_name: .roleRef.name,
    subjects: [.subjects[]? | {kind, name, namespace}]}'
  ROLE=$(printf '%s' "$B" | jq -r '.roleRef.name // empty')
fi

R=""
[ -n "$ROLE" ] && R=$(kubectl get clusterrole "$ROLE" -o json)
if [ -z "$ROLE" ]; then
  echo "[!] no roleRef resolved - what was granted is UNKNOWN, not nothing."
elif [ -z "$R" ]; then
  echo "[!] INCONCLUSIVE - ClusterRole $ROLE could not be read; it may have been deleted after"
  echo "    the binding was made, in which case its permissions are unrecoverable here."
elif [ "$ROLE" = "cluster-admin" ]; then
  echo "[FAIL] roleRef is the built-in cluster-admin - full control of the cluster."
elif [ "$(printf '%s' "$R" | jq '[.rules[]? | select((.verbs // []) | index("*"))] | length')" -gt 0 ]; then
  echo "[FAIL] ClusterRole $ROLE carries wildcard-verb rule(s) - equivalent to admin."
else
  echo "[i] ClusterRole $ROLE has no wildcard-verb rule; read the rules below on their merits."
fi
[ -n "$R" ] && printf '%s' "$R" | jq -r '.rules'
```

`roleRef` and `subjects` are the blast radius and §3 Step 1 destroys both, which is why this runs
first. A role with no wildcard verb is not therefore safe: `secrets` `get`/`list`,
`serviceaccounts/token` `create` and `pods/exec` each reach a credential on their own.

#### Query 3 — Sweep both planes: every path to cluster-admin that exists right now

```bash
CLUSTER="<cluster-name>"; REGION="us-east-1"
FOUND=0; CHECKED=0

# Routes 1 and 2: bindings by roleRef, and bindings by system:masters subject. Both are needed;
# neither implies the other, and only the first contains the string "cluster-admin".
CRB=$(kubectl get clusterrolebindings -o json)
if [ -z "$CRB" ]; then
  echo "[!] INCONCLUSIVE - clusterrolebindings could not be listed; routes 1 and 2 NOT checked"
else
  CHECKED=$((CHECKED + 1))
  ADMIN=$(printf '%s' "$CRB" | jq -r '.items[] |
    select(.roleRef.name == "cluster-admin"
        or ((.subjects // []) | map(select(.kind == "Group" and .name == "system:masters")) | length > 0))
    | "\(.metadata.name)\troleRef=\(.roleRef.name)\tsubjects=\([.subjects[]? | "\(.kind):\(.namespace // "-"):\(.name)"] | join(","))"')
  if [ -n "$ADMIN" ]; then
    echo "$ADMIN" | while IFS= read -r L; do echo "[!] CLUSTER-ADMIN PATH  $L"; done
    FOUND=$((FOUND + 1))
  fi
fi

# Route 3: the legacy map. Absent is legitimate on an API-mode cluster and must not reach the
# same branch as a failed read.
CM=$(kubectl get configmap aws-auth -n kube-system -o json)
if [ -z "$CM" ]; then
  echo "[i] aws-auth absent or unreadable. Expected on an API-mode cluster; on a CONFIG_MAP-mode"
  echo "    cluster it means route 3 was NOT checked."
elif printf '%s' "$CM" | jq -r '.data | to_entries[] | .value' | grep -q "system:masters"; then
  CHECKED=$((CHECKED + 1)); FOUND=$((FOUND + 1))
  echo "[!] CLUSTER-ADMIN PATH  aws-auth maps an IAM principal into system:masters"
  printf '%s' "$CM" | jq -r '.data'
else
  CHECKED=$((CHECKED + 1)); echo "[OK] aws-auth contains no system:masters mapping"
fi

# Route 4: the AWS plane, invisible to every kubectl command above. Also reports the templated
# group primitive, a standing escalation that fires no rule when it is exercised.
AE=$(aws eks list-access-entries --cluster-name "$CLUSTER" --region "$REGION" --output json)
if [ -z "$AE" ]; then
  echo "[!] INCONCLUSIVE - access entries not enumerated; route 4 was NOT checked"
else
  CHECKED=$((CHECKED + 1))
  for P in $(printf '%s' "$AE" | jq -r '.accessEntries[]'); do
    POL=$(aws eks list-associated-access-policies --cluster-name "$CLUSTER" \
            --principal-arn "$P" --region "$REGION" --output json)
    E=$(aws eks describe-access-entry --cluster-name "$CLUSTER" --principal-arn "$P" \
          --region "$REGION" --output json)
    if [ -z "$POL" ] || [ -z "$E" ]; then echo "[!] $P: NOT checked"; continue; fi
    if printf '%s' "$POL" | jq -e '.associatedAccessPolicies[]? |
         select(.policyArn | test("ClusterAdminPolicy|EKSAdminPolicy|SecretAdminPolicy|AdminViewPolicy"))' >/dev/null; then
      echo "[!] CLUSTER-ADMIN PATH  access entry $P carries an admin access policy"
      FOUND=$((FOUND + 1))
    fi
    printf '%s' "$E" | jq -r --arg p "$P" '.accessEntry |
      if ((.kubernetesGroups // []) | join(",") | test("SessionName"))
      then "[!] STANDING ESCALATION  \($p): SessionName template in kubernetesGroups"
      else empty end'
  done
fi

if   [ "$CHECKED" -eq 0 ]; then echo "[!] INCONCLUSIVE - no route enumerated. This is not a clean cluster."
elif [ "$FOUND" -eq 0 ];   then echo "[OK] $CHECKED route(s) enumerated, no cluster-admin path beyond the baseline"
else echo "[FAIL] $FOUND route(s) to cluster-admin present. Compare against the §1 baseline."; fi
echo "[i] The cluster CREATOR holds system:masters and AWS states it does not appear in any"
echo "    visible configuration - it will not show up above, however clean the result looks."
```

Four routes, checked separately, because finding nothing on three says nothing about the fourth.
An entry carrying `AmazonEKSClusterAdminPolicy` is an administrator with no Kubernetes object
behind it, and `AmazonEKSAdminViewPolicy` is nearly as bad because AWS states it *"includes
Kubernetes Secrets"*. Run `aws eks describe-cluster` alongside this: `authenticationMode` decides
which routes are live at all, and the `logging` block decides whether Queries 1 and 4 could
return anything.

#### Query 4 — Session reconstruction: what the identity did with the access, on both planes

```bash
REGION="us-east-1"; CLUSTER="<cluster-name>"
SUBJECT="<user-from-Query-1>"
GRANT_TIME="<iso8601-time-of-the-grant-from-Query-1>"

Q='fields @timestamp, user.username, verb, objectRef.resource, objectRef.namespace, objectRef.name, objectRef.subresource, responseStatus.code, sourceIPs.0
| filter @logStream like "kube-apiserver-audit"
| filter user.username = "SUBJECT_PLACEHOLDER"
| sort @timestamp asc
| limit 2000'
Q=${Q/SUBJECT_PLACEHOLDER/$SUBJECT}

QID=$(aws logs start-query --region "$REGION" --log-group-name "/aws/eks/${CLUSTER}/cluster" \
        --start-time "$(date -u -d "$GRANT_TIME" +%s)" --end-time "$(date -u +%s)" \
        --query-string "$Q" --output text --query 'queryId')
RES=""; STATUS="Scheduled"
case "${QID:-}" in
  ''|None) STATUS="StartFailed";;
  *) TRIES=0
     while [ "$STATUS" = "Scheduled" ] || [ "$STATUS" = "Running" ]; do
       TRIES=$((TRIES + 1)); [ "$TRIES" -gt 90 ] && { STATUS="PollTimeout"; break; }
       sleep 2
       RES=$(aws logs get-query-results --region "$REGION" --query-id "$QID" --output json)
       [ -z "$RES" ] && { STATUS="CallFailed"; break; }
       STATUS=$(printf '%s' "$RES" | jq -r '.status // "NoStatus"')
     done;;
esac
if [ "$STATUS" != "Complete" ]; then
  echo "[!] INCONCLUSIVE - the query ended '$STATUS'. Post-grant activity was NOT established;"
  echo "    do not read this as an empty result."
else
  printf '%s' "$RES" | jq -r '[.results[] | map({key: .field, value: .value}) | from_entries] |
    (map(select(.["objectRef.resource"] == "secrets")) | length) as $sec |
    (map(select(.["objectRef.subresource"] == "token")) | length) as $tok |
    {records: length, secret_requests: $sec, token_mints: $tok,
     resources_touched: (map(.["objectRef.resource"]) | unique),
     namespaces: (map(.["objectRef.namespace"]) | unique)}'
  echo "[i] Any nonzero secret_requests or token_mints means credentials left the cluster."
fi

# Plane 3. If SUBJECT is an STS assumed-role ARN its TAIL segment is the session name, and
# CloudTrail indexes on exactly that. Keyed on the ROLE name the lookup returns zero forever,
# and that zero reads as clean.
case "$SUBJECT" in
  arn:aws:sts::*:assumed-role/*/*)
    SESSION=$(printf '%s' "$SUBJECT" | awk -F'/' '{print $2}')
    for R in us-east-1 us-west-2 eu-west-1; do
      OUT=$(aws cloudtrail lookup-events --region "$R" --output json \
              --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION" \
              --start-time "$GRANT_TIME")
      if [ -z "$OUT" ]; then
        echo "[!] $R: lookup-events returned nothing - failed call or no permission, NOT clean."
        continue
      fi
      echo "== $R: $(printf '%s' "$OUT" | jq '.Events | length') AWS call(s) under $SESSION"
      printf '%s' "$OUT" | jq -r '.Events[].CloudTrailEvent | fromjson |
        "    \(.eventTime) \(.eventSource) \(.eventName) from \(.sourceIPAddress) -> \(.errorCode // "SUCCESS")"'
    done;;
  system:serviceaccount:*)
    echo "[i] the subject is a ServiceAccount and has no STS session of its own. Its AWS reach is"
    echo "    whatever IRSA or Pod Identity binds it to - resolve with 'aws eks list-pod-identity-"
    echo "    associations' and the eks.amazonaws.com/role-arn"
    echo "    annotation, then repeat this lookup against that role.";;
  *)
    echo "[i] '$SUBJECT' is neither an STS ARN nor a ServiceAccount - an aws-auth alias or a"
    echo "    locally-named identity. Map it back through aws-auth before searching CloudTrail.";;
esac
```

`secret_requests` and `token_mints` are the counts that change the incident's nature: a projected
token belonging to an IRSA- or Pod-Identity-bound account converts to AWS credentials, so a
nonzero `token_mints` means the blast radius left the cluster. Zero AWS calls under the session
name is **not** proof the credential was unused — it is proof this call found none, which is why
the failed-call branch is kept separate from the empty one.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**Order matters here in a way it does not on most services, and two of the mistakes are
irreversible.** Query 2 must complete before anything is deleted: removing the binding removes
the `roleRef`, and a ClusterRole created for the purpose usually goes with it, after which what
was granted is knowable only from the audit event. Then both planes must be closed, because
closing one is not containment: removing a ClusterRoleBinding leaves an access-policy
association untouched, and disassociating an access policy leaves a binding untouched. And
**confirm before every AWS-side step that you are not removing your own access** — deleting the
access entry you are authenticating with, on a cluster whose creator principal is unavailable,
is an outage `kubectl` cannot fix.

Order: **collect (Query 2) → revoke on the Kubernetes plane → revoke on the AWS plane →
contain the IAM principal.**

> Run under the **break-glass responder credentials** from §1, and confirm they are not the
> principal you are about to remove.

#### Step 1 — Remove the Kubernetes-plane grant

```bash
BINDING="<binding-name-from-Query-1>"

# Guarded: deleting a binding you did not capture in Query 2 destroys the only record of what
# it granted, and a re-read is the assertion - the delete call succeeding is not.
if kubectl get clusterrolebinding "$BINDING" -o name; then
  kubectl delete clusterrolebinding "$BINDING"
  if kubectl get clusterrolebinding "$BINDING" -o name; then
    echo "[FAIL] $BINDING still present after delete"
  else
    echo "[OK] ClusterRoleBinding $BINDING removed"
  fi
else
  echo "[i] no ClusterRoleBinding named $BINDING - it may be a namespaced RoleBinding, or"
  echo "    already gone. Not success: re-run Query 3 to confirm no path to admin remains."
fi

# The aws-auth route. Edited, never deleted: removing the ConfigMap deletes the node mapping and
# the nodes stop being able to join the cluster.
CM=$(kubectl get configmap aws-auth -n kube-system -o json)
if [ -z "$CM" ]; then
  echo "[i] aws-auth absent or unreadable - nothing to edit on this route"
elif printf '%s' "$CM" | jq -r '.data | to_entries[] | .value' | grep -q "system:masters"; then
  echo "[FAIL] aws-auth still maps a principal into system:masters. Edit it by hand: kubectl edit"
  echo "    -n kube-system configmap/aws-auth Remove ONLY the offending mapRoles/mapUsers entry - the"
  echo "    node mapping (username: system:node:...) must stay, or the nodes deregister."
else
  echo "[OK] aws-auth carries no system:masters mapping"
fi

# Same read, second assertion: a SessionName template in aws-auth is a STANDING escalation. AWS
# states a caller who can assume the mapped role "can choose their own Kubernetes group
# membership by crafting the session name". Exercising it changes no configuration and emits no
# cluster-side event, so it must be removed rather than watched. Query 3 reports the equivalent
# primitive on the access-entry plane.
if [ -n "$CM" ]; then
  HITS=$(printf '%s' "$CM" | jq -r '.data | to_entries[] | .value' | grep -n "SessionName")
  if [ -z "$HITS" ]; then
    echo "[OK] no SessionName template in aws-auth"
  else
    echo "[FAIL] templated mapping(s) in aws-auth - replace with a fixed username or migrate to an"
    echo "    access entry. A template in the GROUPS field has no safe form at all:"
    echo "$HITS"
  fi
fi
```

#### Step 2 — Remove the AWS-plane grant

```bash
CLUSTER="<cluster-name>"; REGION="us-east-1"
PRINCIPAL="<principal-arn-from-Query-3>"

# THE LOCKOUT CHECK. Removing the access entry you are yourself authenticating with, on a
# cluster whose creator principal is unavailable, removes cluster access from everyone with no
# second path in. This must be able to STOP the step, not merely warn.
MY_ARN=$(aws sts get-caller-identity --query 'Arn' --output text)
case "${MY_ARN:-}" in
  ''|None) echo "[!] INCONCLUSIVE - could not resolve your own identity. STOP; do not run the"
           echo "    removal blind."; exit 1;;
esac
if printf '%s' "$MY_ARN" | grep -qF "$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')"; then
  echo "[FAIL] $PRINCIPAL appears to be the identity you are using. Establish a second"
  echo "    administrative path FIRST, then re-run. Refusing to proceed."
  exit 1
fi

POL=$(aws eks list-associated-access-policies --cluster-name "$CLUSTER" \
        --principal-arn "$PRINCIPAL" --region "$REGION" --output json)
if [ -z "$POL" ]; then
  echo "[!] INCONCLUSIVE - could not list associated policies. Nothing was disassociated."
else
  for A in $(printf '%s' "$POL" | jq -r '.associatedAccessPolicies[]?.policyArn'); do
    aws eks disassociate-access-policy --cluster-name "$CLUSTER" \
      --principal-arn "$PRINCIPAL" --policy-arn "$A" --region "$REGION"
    echo "[OK] disassociated $A"
  done
  # Re-read rather than trusting the calls above. The empty list IS the assertion.
  AFTER=$(aws eks list-associated-access-policies --cluster-name "$CLUSTER" \
            --principal-arn "$PRINCIPAL" --region "$REGION" --output json)
  if [ -z "$AFTER" ]; then
    echo "[!] INCONCLUSIVE - could not re-read the associations to confirm"
  elif [ "$(printf '%s' "$AFTER" | jq '.associatedAccessPolicies | length')" -eq 0 ]; then
    echo "[OK] no access policy remains associated with $PRINCIPAL"
  else
    echo "[FAIL] policies still associated:"; printf '%s' "$AFTER" | jq -r '.associatedAccessPolicies[].policyArn'
  fi
fi

# The entry itself carries kubernetesGroups, an independent grant evaluated by Kubernetes RBAC
# that survives disassociating every access policy. Delete the entry only when the principal
# should have no cluster access at all.
aws eks delete-access-entry --cluster-name "$CLUSTER" --principal-arn "$PRINCIPAL" --region "$REGION"
if aws eks describe-access-entry --cluster-name "$CLUSTER" --principal-arn "$PRINCIPAL" \
     --region "$REGION" --output json; then
  echo "[FAIL] the access entry for $PRINCIPAL is still describable"
else
  echo "[OK] access entry removed - the ResourceNotFoundException above is this check succeeding"
fi
```

#### Step 3 — Contain the IAM principal behind the identity

```bash
SUSPECT_ARN="<iam-arn-behind-the-user-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["eks:AssociateAccessPolicy","eks:CreateAccessEntry","eks:UpdateAccessEntry","eks:DeleteAccessEntry","eks:UpdateClusterConfig","eks:DescribeCluster","sts:AssumeRole"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)

case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyEksAdmin" --policy-document "$DENY"
    echo "[OK] denied EKS access-management for user $U";;
  *:assumed-role/*|*:role/*)                      # assumed-role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyEksAdmin" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied EKS access-management for role $R";;
  *)
    echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, a federated"
    echo "identity, or a service principal. Contain manually; neither branch applies. If the"
    echo "    identity was system:serviceaccount:..., there is NO IAM principal to"
    echo "    contain here - see ../eks.persistence.flow-alert---suspicious-operation-detected-from-service-ac/.";;
esac
```

This closes the AWS plane for that principal. It does **not** revoke the Kubernetes access an
already-issued grant confers, and it does not touch a ServiceAccount — those are Steps 1 and 2
and the ServiceAccount playbook respectively. Note also that `aws:TokenIssueTime` reaches only
sessions issued before `$CUTOFF`; a fresh `AssumeRole` after it is not denied by that statement,
which is why `sts:AssumeRole` is in the deny list as well.

## 4. Eradication

### Remove Attacker Access

- **Every Secret in scope of the grant is compromised.** Cluster-admin reads all of them, and
  Query 4's `secret_requests` count says whether it did — but the EKS audit policy caps `secrets`
  at `Metadata`, so it never says what was in them, and a `list` carries no `objectRef.name` at
  all. Rotate on the assumption of full exposure; the detailed reasoning lives in
  `../eks.lateral-movement.unauthorized-user-trying-to-get-secrets/` rather than being repeated.
- **Every ServiceAccount whose token could be minted is compromised.** A token belonging to an
  account annotated `eks.amazonaws.com/role-arn`, or carrying an EKS Pod Identity association,
  converts into AWS credentials. Enumerate both — `kubectl get sa -A -o json` for the annotation,
  `aws eks list-pod-identity-associations` for the other — and treat every bound IAM role as
  compromised, in order of what it can reach.
- **Right-size what was over-granted.** Where the grant went *to* a workload, the finding is
  usually that its ServiceAccount could write RBAC at all. Only a controller should hold `create`
  on `clusterrolebindings`, and nothing outside a short closed list should hold `escalate`/`bind`.
- **Re-enable and widen control-plane logging.** If the audit type was absent, this incident has
  no Kubernetes-side history and the next one will not either.
- **Remove the emergency policies once clean, and assert it** — the block below, not an echo.

```bash
SUSPECT_ARN="<iam-arn-behind-the-user-from-Query-1>"

case "$SUSPECT_ARN" in
  *:assumed-role/*|*:role/*)
    N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyEksAdmin EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*)
    N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyEksAdmin"
    LEFT=$(aws iam list-user-policies --user-name "$N" --query 'PolicyNames[]' --output text);;
  *) N=""; LEFT="UNCHECKED";;
esac
case "$LEFT" in
  UNCHECKED)   echo "[!] INCONCLUSIVE - principal is neither user nor role; check manually";;
  *Emergency*) echo "[FAIL] an emergency policy is still attached to $N: $LEFT";;
  *)           echo "[OK] no emergency policy remains on $N";;
esac
```

---

## 5. Recovery

### Restore Clean State

#### Verify no path to cluster-admin remains outside the baseline

```bash
# Populate ALLOW from §1. An empty allowlist makes every legitimate administrator a finding,
# which is how a check like this gets ignored.
ALLOW="cluster-admin platform-admins cluster-bootstrap"

CRB=$(kubectl get clusterrolebindings -o json)
if [ -z "$CRB" ]; then
  echo "[!] INCONCLUSIVE - clusterrolebindings could not be listed; nothing was verified"
else
  BAD=0
  ADMINS=$(printf '%s' "$CRB" | jq -r '.items[] |
    select(.roleRef.name == "cluster-admin"
        or ((.subjects // []) | map(select(.kind == "Group" and .name == "system:masters")) | length > 0))
    | .metadata.name')
  for B in $ADMINS; do
    case " $ALLOW " in
      *" $B "*) ;;
      *) echo "[FAIL] unexpected cluster-admin binding: $B"; BAD=$((BAD + 1));;
    esac
  done
  if [ "$BAD" -eq 0 ]; then
    echo "[OK] every cluster-admin binding is on the allowlist"
  else
    echo "[FAIL] $BAD binding(s) outside the allowlist remain"
  fi
fi
echo "[i] Re-run Query 3 for the AWS plane. This assertion covers routes 1 and 2 only, and an"
echo "    access-policy association survives every kubectl change made in §3."
```

Both `[FAIL]` branches are reachable after the remediation, which is what makes this a check
rather than a formality: §3 Step 1 deletes one named binding, and an actor who created two is
contained by neither the delete nor a sweep that stops at the first hit.

#### Verify the audit log is enabled and still receiving events

```bash
REGION="us-east-1"; CLUSTER="<cluster-name>"
LG="/aws/eks/${CLUSTER}/cluster"

C=$(aws eks describe-cluster --name "$CLUSTER" --region "$REGION" --output json)
if [ -z "$C" ]; then
  echo "[!] INCONCLUSIVE - describe-cluster returned nothing; logging state UNKNOWN"
elif [ "$(printf '%s' "$C" | jq -r '[.cluster.logging.clusterLogging[]? |
       select(.enabled == true) | .types[]] | index("audit") // "absent"')" = "absent" ]; then
  echo "[FAIL] the audit log type is disabled. There is no Kubernetes-side detection at all."
else
  echo "[OK] audit log type enabled in the cluster configuration"
fi

# Configuration is not delivery. AWS states delivery is "best effort", so "configured" and
# "arriving" are different states and this distinguishes them.
S=$(aws logs describe-log-streams --region "$REGION" --log-group-name "$LG" \
      --log-stream-name-prefix "kube-apiserver-audit" --order-by LastEventTime --descending \
      --max-items 1 --output json)
if [ -z "$S" ]; then
  echo "[!] INCONCLUSIVE - describe-log-streams failed; delivery was NOT verified"
elif [ "$(printf '%s' "$S" | jq '.logStreams | length')" -eq 0 ]; then
  echo "[FAIL] no kube-apiserver-audit stream in $LG - configured but never delivered"
else
  AGE=$(( $(date -u +%s) - $(printf '%s' "$S" | jq -r '.logStreams[0].lastEventTimestamp // 0') / 1000 ))
  if [ "$AGE" -gt 3600 ]; then
    echo "[FAIL] the newest audit event is ${AGE}s old - delivery has stopped, or the log type"
    echo "    was turned off after the first half of this check passed"
  else
    echo "[OK] audit events delivered within the last ${AGE}s"
  fi
fi
```

#### Verify the contained principal can no longer reach the cluster

```bash
SUBJECT="<user-from-Query-1>"
REGION="us-east-1"; CLUSTER="<cluster-name>"
LG="/aws/eks/${CLUSTER}/cluster"
CUTOFF="<the CUTOFF value used in §3 Step 3>"
START=$(date -u -d "$CUTOFF" +%s); END=$(date -u +%s)

# This assertion CAN still emit a signal after the remediation, which is what makes it real: an
# STS session issued after CUTOFF is not covered by the TokenIssueTime deny, and a second
# binding the sweep missed still authorises. Post-cutoff SUCCESS by this identity is the
# failure this exists to catch.
Q='fields @timestamp, user.username, verb, objectRef.resource, responseStatus.code
| filter @logStream like "kube-apiserver-audit"
| filter user.username = "SUBJECT_PLACEHOLDER" and responseStatus.code < 400
| sort @timestamp desc
| limit 200'
Q=${Q/SUBJECT_PLACEHOLDER/$SUBJECT}

QID=$(aws logs start-query --region "$REGION" --log-group-name "$LG" \
        --start-time "$START" --end-time "$END" --query-string "$Q" \
        --output text --query 'queryId')
RES=""; STATUS="Scheduled"
case "${QID:-}" in
  ''|None) STATUS="StartFailed";;
  *) TRIES=0
     while [ "$STATUS" = "Scheduled" ] || [ "$STATUS" = "Running" ]; do
       TRIES=$((TRIES + 1)); [ "$TRIES" -gt 90 ] && { STATUS="PollTimeout"; break; }
       sleep 2
       RES=$(aws logs get-query-results --region "$REGION" --query-id "$QID" --output json)
       [ -z "$RES" ] && { STATUS="CallFailed"; break; }
       STATUS=$(printf '%s' "$RES" | jq -r '.status // "NoStatus"')
     done;;
esac
if [ "$STATUS" != "Complete" ]; then
  echo "[!] INCONCLUSIVE - query ended '$STATUS'; containment was NOT verified."
elif [ "$(printf '%s' "$RES" | jq '.results | length')" -eq 0 ]; then
  echo "[OK] no successful request by $SUBJECT since $CUTOFF"
else
  echo "[FAIL] successful request(s) by $SUBJECT after containment:"
  printf '%s' "$RES" | jq -r '.results[] | map({key: .field, value: .value}) | from_entries |
    "    \(.["@timestamp"]) \(.verb) \(.["objectRef.resource"]) -> \(.["responseStatus.code"])"'
fi
```

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     create/update/patch on clusterrolebindings or rolebindings with"
echo "    requestObject.roleRef.name = cluster-admin and responseStatus.code 200 or 201; a binding"
echo "    whose requestObject.subjects contain the GROUP system:masters, which contains the string"
echo "    cluster-admin nowhere; a Role or ClusterRole with wildcard verbs; AssociateAccessPolicy"
echo "    attaching AmazonEKSClusterAdminPolicy, a CloudTrail event with no Kubernetes counterpart;"
echo "    and the correlation at the THIRD 403 by one user.username followed by any of the above"
echo "    within 1h - gte three, not gt. MUST NOT fire on: a binding attempt that returned 403 (denied"
echo "    - the denial base rule owns it, not the grant stage); a 401, an authentication failure and a"
echo "    different incident; a read of a binding (get/list/watch). EXPECTED FP, by design: the"
echo "    escalate/bind rule is NOT gated on principal, so a controller legitimately holding those"
echo "    verbs fires it. Intended - the account needs to know the RBAC escalation guard was switched"
echo "    off, whoever did it. CANNOT BE TESTED, a stated gap: escalation via a templated aws-auth"
echo "    mapping produces NO cluster-side event - the privilege is chosen in sts:AssumeRole, which"
echo "    names no cluster. Nothing here fires on it; §3 Step 4 removes the primitive instead."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| An identity that had been refused repeatedly was able to grant itself cluster-admin | Write access to `clusterrolebindings` was held by a principal that had no reason to hold it, and RBAC's escalation guard was not the last line because `escalate`/`bind` were reachable |
| The grant was invisible for the period it mattered | The `audit` control-plane log type is off by default and had not been enabled, so plane-1 telemetry did not exist |
| A cluster search for the grant would have come back clean | The access-policy route creates no Kubernetes object; a responder looking only at `kubectl` output cannot see an EKS-authorized administrator |
| Removing the binding did not remove the access | The two identity planes are independent — an access-policy association survives every `kubectl delete`, and a `kubectl` change survives every IAM revocation |
| The blast radius reached AWS | ServiceAccounts bound to IAM roles through IRSA or Pod Identity turn a readable token into AWS credentials, and cluster-admin reads every token in the cluster |

### Recommended Guardrails

**Deny the access-policy route to everyone outside a named break-glass role**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike, not StringNotEquals: the value is wildcarded, and Deny + StringNotEquals
// against a wildcarded ARN matches every principal and denies cluster administration outright
// - an outage, not a bypass. This constrains the AWS plane only; the Kubernetes plane is
// governed by RBAC, which no SCP can reach.
{
  "Effect": "Deny",
  "Action": [
    "eks:AssociateAccessPolicy",
    "eks:CreateAccessEntry",
    "eks:UpdateAccessEntry",
    "eks:UpdateClusterConfig"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/EksBreakGlass", "arn:aws:iam::*:role/PlatformAutomation"] }
  }
}
```

**Structural controls**

- **Enable `audit` and `authenticator` on every cluster and ship the log group off-account.**
  Nothing in this playbook works without them and neither can be enabled retrospectively.
- **Move to `API` authentication mode and retire `aws-auth`.** It removes an entire escalation
  route, replaces an in-cluster object that cluster-admin can edit with an AWS API an SCP can
  constrain, and eliminates the templated-mapping primitive.
- **Never put `{{SessionName}}` or `{{SessionNameRaw}}` in a `groups` field.** AWS states
  outright that a caller *"can choose their own Kubernetes group membership by crafting the
  session name"*, and exercising it produces no event anywhere.
- **Grant `escalate` and `bind` to nothing.** They exist only to bypass RBAC's own escalation
  prevention; a controller that needs them should be granted the target permissions directly.
- **Write down the cluster creator.** AWS states the creating principal holds `system:masters`
  and *"doesn't appear in any visible configuration"* — an administrator no sweep will find.

**Detection improvements**

- Baseline the identities that legitimately write RBAC objects; the set is small and stable, and
  it converts a noisy resource-level rule into a precise principal-level one.
- Alert on `UpdateClusterConfig` changing `accessConfig.authenticationMode` or `logging` — the
  first opens a route, the second closes the telemetry, and both are cheap to watch.
- Baseline the `sourceIPs[0]` values each administrative identity uses. A grant from outside them
  is the strongest single discriminator available, and it is unusable without the baseline.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098.006 — Account Manipulation: Additional Container Cluster Roles (primary); T1613 — Container and Resource Discovery (the denial phase) |
| MITRE tactic | Privilege Escalation (TA0004), Persistence (TA0003) |
| Primary API | Kubernetes: `create`/`update`/`patch` on `clusterrolebindings`, `rolebindings`, `clusterroles`, `roles`; `update`/`patch` on `kube-system/aws-auth`. AWS: `eks:AssociateAccessPolicy`, `eks:CreateAccessEntry`, `eks:UpdateAccessEntry` |
| Event source | **Kubernetes audit log** via CloudWatch Logs `/aws/eks/<cluster>/cluster`, stream prefix `kube-apiserver-audit-` — **off by default**, enabled per log type. Plus `eks.amazonaws.com` **management** events in CloudTrail, on by default |
| Key discriminator | The **ordering**: `responseStatus.code: 403` for one `user.username`, then a successful grant naming that same identity within the hour. Not the grant alone, which platform automation performs routinely |
| Field shape | `user.groups` and `sourceIPs` are **arrays**; there is no `sourceIPAddresses` field. `responseStatus.code` is **int32**. `objectRef.name` is **absent on `list`/`watch`**. `objectRef.apiGroup` is `""` for the core group. `requestObject` is populated for RBAC writes because the EKS default policy sets `RequestResponse` for that group — and is **not** populated for `secrets` or general `configmaps`, which are capped at `Metadata` |
| Audit-policy exceptions that matter | `kube-system/aws-auth` is `RequestResponse` for `update`/`patch`/`delete` **but not `create`**; core `events` are `None`; `serviceaccounts/token` is `Request` with **no `omitStages`**, so it appears at two stages and any count-based rule double-counts |
| "Was it used" pivot | Audit-log activity under the same `user.username` after the grant, counting `objectRef.resource: secrets` and `objectRef.subresource: token`. For an IAM principal, CloudTrail `AttributeKey=Username` keyed on the **session name** — the tail segment of the STS ARN in `user.username`. Keyed on the role name it returns zero unconditionally |
| Identity mapping | Access entries: default `username` is `arn:aws:sts::<acct>:assumed-role/<role>/{{SessionName}}` (AWS's own published response). `aws-auth`: `mapRoles`/`mapUsers` with `rolearn`/`userarn`, `username`, `groups`. ServiceAccount: `system:serviceaccount:<ns>:<name>` |
| Blast radius | Every Secret and every ServiceAccount token in the cluster; through IRSA and Pod Identity, every IAM role those accounts are bound to; the `aws-auth` map itself, which is persistence; and the audit log's own destination, which is the follow-on move |
| Error strings | Kubernetes: `403 Forbidden` (RBAC refusal — the signal), `401 Unauthorized` (authentication failure — a different incident), `404 NotFound`, `409 Conflict`. EKS API: `ResourceNotFoundException`, `InvalidParameterException`, `InvalidRequestException`, `ResourceInUseException`, `ResourceLimitExceededException`, `ServerException` |

**MITRE mapping note.** The source rule labels this **T1078** (Valid Accounts), which is live but
carries no information: every authenticated request to a Kubernetes API server is made with a
valid account, so the label does not distinguish this from any other event in the log.
**T1098.006 — Additional Container Cluster Roles** describes the technique literally, and MITRE's
own description names the mechanism: *"creating RoleBindings or ClusterRoleBindings in Kubernetes
environments"*. **T1613** is carried only on the denial base rule, where the behaviour is
enumeration rather than escalation. The directory's `privilege-escalation` segment matches both
the source's tactic label and the corrected mapping.

### Residual Risk

**Whatever the actor read while it held cluster-admin is gone, and the audit log cannot say what
it was.** The EKS default policy caps `secrets` at `Metadata`, so a `get` names the secret and
never its contents, and a `list` — the efficient form, and the one an actor uses — names nothing
at all, because `objectRef.name` is absent on collection requests. Rotate on the assumption of
full exposure of every Secret in scope of the grant.

**A projected ServiceAccount token already issued to a running pod is not revoked by anything in
§3.** Removing a binding changes authorisation immediately, but a token minted before it stays a
valid credential until it expires or the ServiceAccount object is deleted — and deleting that
breaks the workload. Where Query 4 counted token mints, treat the bound IAM roles as compromised
and revoke on the IAM side.

**If the `audit` log type was off there is no Kubernetes-side history, and enabling it now does
not create one.** Everything reconstructable comes from CloudTrail, which sees the AWS plane
only: it will show an `AssociateAccessPolicy` and never a `ClusterRoleBinding`. Record that,
rather than reporting an absence of evidence as evidence of absence.

**The cluster creator still holds `system:masters` and appears in no sweep.** Query 3 cannot find
it and §5 cannot find it; if that principal is the one that was compromised, every step here has
been applied to the wrong identity.
