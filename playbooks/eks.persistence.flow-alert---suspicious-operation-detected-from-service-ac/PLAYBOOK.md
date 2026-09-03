# IR Playbook: Additional Container Cluster Roles — a ServiceAccount granted standing AWS access via `CreatePodIdentityAssociation`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / privilege escalation (a compromised workload identity administers the cluster it runs in) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High — and critical once RBAC is written. A ServiceAccount that can create a `ClusterRoleBinding` can bind itself to `cluster-admin`, and cluster-admin reaches every node IAM role through one `hostNetwork` pod. The source rule rates this at its middle level, which understates it: the operations in scope have no benign application use, so the rule is not trading precision for recall — it is high-confidence and should be treated as such. |
| MITRE Tactics | Persistence, Privilege Escalation |
| MITRE Techniques | T1098.006 |
| Services in Scope | EKS, EKS Auth, STS, IAM, CloudWatch Logs, CloudTrail |

**What the technique does:** an attacker who reaches code execution inside a pod inherits that
pod's ServiceAccount token, mounted by default at
`/var/run/secrets/kubernetes.io/serviceaccount/token`. From there every step is an ordinary
authenticated Kubernetes API call. They create a `ClusterRoleBinding` naming their own
ServiceAccount as subject and `cluster-admin` as role — one `POST` to
`/apis/rbac.authorization.k8s.io/v1/clusterrolebindings`. They mint a fresh token through the
`serviceaccounts/token` subresource with no `boundObjectRef`, producing a bearer credential
that outlives the pod. They `get` or `list` Secrets in `kube-system`. They create a pod with
`hostNetwork: true`, which AWS documents as always having IMDS access, and read the **node**
IAM role's credentials from `169.254.169.254` — a role that is not the workload's own and that
no RBAC governs.

The reason the usual reflexes miss it is that none of this is in CloudTrail. CloudTrail records
what happens to the cluster — `CreateCluster`, `UpdateClusterConfig`, `CreateAccessEntry`. It
does not record what happens *inside* it. A responder who pulls CloudTrail for the window sees
a quiet account. The Kubernetes audit log holds the entire incident, and on EKS that log is
**off by default**: all five control-plane log types must be enabled individually, before the
fact, or the evidence was never written.

**Detection thesis:** the discriminating fact is the *class* of the identity, not its name. A
request whose `user.username` begins `system:serviceaccount:` was made by a workload, and a
workload's behaviour is fixed by its image — so a workload writing RBAC, minting tokens or
entering pods is anomalous without any baseline. The source rule instead chains opaque stages
over three hours on one plane, and cannot see the IAM role the same ServiceAccount holds.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **EKS control-plane `audit` logs enabled** and shipping to CloudWatch Logs at
  `/aws/eks/<cluster>/cluster`, stream prefix `kube-apiserver-audit-`. This is the single
  prerequisite that cannot be met retroactively — enable it on every cluster now. Fields that
  matter: `user.username`, `user.groups`, `verb`, `objectRef.{resource,subresource,namespace,name}`,
  `responseStatus.code`, `stage`, `sourceIPs` (an array), `requestObject`,
  `annotations["authorization.k8s.io/decision"]` and `["authorization.k8s.io/reason"]`.
- **`authenticator` control-plane logs** — the only record of which IAM principal mapped to
  which Kubernetes identity.
- **CloudTrail management events** for `eks.amazonaws.com` (`CreatePodIdentityAssociation`,
  `UpdatePodIdentityAssociation`, `UpdateClusterConfig`, `CreateAccessEntry`),
  `eks-auth.amazonaws.com` (`AssumeRoleForPodIdentity`) and `sts.amazonaws.com`
  (`AssumeRoleWithWebIdentity`).
- **CloudWatch Logs retention set explicitly** on the cluster log group. The default is Never
  Expire, but a `PutRetentionPolicy` cutting it to one day is a cheap way to destroy this
  evidence — alert on changes to it.

**Alerting (must be pre-configured)**
- **A ServiceAccount successfully created, updated, patched or deleted an RBAC object → P0**
- **A ServiceAccount successfully created a token via the `serviceaccounts/token` subresource → P0**
- **A ServiceAccount read Secrets in `kube-system` → P0**
- **A ServiceAccount used `exec`, `attach` or `portforward` against a pod → P0**
- **The same ServiceAccount was denied a privileged operation and then succeeded at one within an hour → P1**
- **A ServiceAccount created a pod requesting `hostNetwork`, `hostPID` or a privileged container → P1**
- **`CreatePodIdentityAssociation` or `UpdatePodIdentityAssociation` by a principal outside the IaC allowlist → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under
  investigation, holding an EKS access entry mapped to `cluster-admin` **that pre-dates the
  incident** — creating one during the response is itself a `CreateAccessEntry` you will later
  have to distinguish from the attacker's.
- `kubectl` configured against the cluster (`aws eks update-kubeconfig`), and `jq`.
- The workload's own manifests, in version control, to compare a live pod spec against.

**Known IOC Baselines**
- **The controller allowlist.** In-cluster controllers legitimately write RBAC and read
  `kube-system` Secrets. The set is small, closed and stable, and populating it is the entire
  tuning cost of these rules. Enumerate it once per cluster with Query 2 and keep it in version
  control next to the rules.
- Which ServiceAccounts hold an IAM role, via Pod Identity association or the
  `eks.amazonaws.com/role-arn` annotation, and what each of those roles can do. This mapping is
  what turns "a pod was compromised" into a blast-radius statement.
- The cluster's NAT egress addresses. A projected token used from outside them is a token that
  left the cluster.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `user.username` starting `system:serviceaccount:` with a write verb on `clusterrolebindings`, `rolebindings`, `clusterroles` or `roles`, response `200`/`201` | Kubernetes audit | T1098.006 |
| P0 | `objectRef.subresource: token`, `verb: create`, by a ServiceAccount | Kubernetes audit | T1098.006 |
| P0 | `objectRef.resource: secrets` in `objectRef.namespace: kube-system`, read by a ServiceAccount outside `kube-system` | Kubernetes audit | T1552.007 |
| P0 | `objectRef.subresource` of `exec`, `attach` or `portforward` by a ServiceAccount | Kubernetes audit | T1609 |
| P1 | `403` then `200` on privileged targets, same `user.username`, within 1h | Kubernetes audit (correlation) | T1098.006 |
| P1 | `verb: create` on `pods` by a ServiceAccount where `requestObject.spec` sets `hostNetwork`, `hostPID` or a privileged container | Kubernetes audit | T1611 |
| P1 | `CreatePodIdentityAssociation` / `UpdatePodIdentityAssociation` by a principal outside the provisioning allowlist | CloudTrail (management) | T1098.006 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | One ServiceAccount accumulating `403`s across several privileged resource types in an hour | Kubernetes audit | T1613 |
| P2 | `AssumeRoleForPodIdentity` or `AssumeRoleWithWebIdentity` from a source IP outside the cluster's NAT egress | CloudTrail (management) | T1552.007 |
| P3 | `UpdateClusterConfig` disabling the `audit` log type, or `PutRetentionPolicy` shortening the cluster log group | CloudTrail (management) | T1685.002 |

### Detection Rule Quality Notes

The source rule is a flow chaining stages by bare internal ID over three hours, grouped by
`user.username`. Its stages are not in the extract, so the defects below are stated about the
rule's **structure** — which is auditable — and not about logic that cannot be read.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Stages referenced by opaque internal ID | Nobody reviewing the rule can say what it matches. An untunable rule is muted after its first false positive, which is a detection that exists on paper only | Express the thesis in one document: workload identity AND administrative operation. Both halves are visible in the rule text |
| Three-hour ordered window on one identity | In a busy cluster a single ServiceAccount emits enough control-plane traffic that "A then B within 3h" is met by coincidence. The window sets the false-positive rate, not the logic | 1h, and only for the denied→succeeded pair where ordering carries real meaning. The direct operations need no window at all |
| Single-plane | A ServiceAccount's IAM role is invisible to the Kubernetes audit log. The rule cannot see `CreatePodIdentityAssociation`, so the most durable form of this persistence is outside its field of view | Two CloudTrail documents in the same file, and a §3 containment procedure that acts on both planes |
| No `stage` filter | `serviceaccounts/token` is the one rule in the EKS default audit policy without `omitStages: RequestReceived`, so token events are emitted twice and every count on them is doubled | `stage: ResponseComplete` matched explicitly in every count-bearing rule |
| Denials treated as one class | Grouping `401` with `403` pages the on-call every time a kubelet rotates a projected token late | `403` only — identity established, permission missing |

**Recommended detection — a workload identity performing operations that belong to an administrator, on both planes.**

```yaml
# Suspicious operation performed by a Kubernetes ServiceAccount (T1098.006 / T1552.007)
#
# TELEMETRY. The plane-1 rules here read the KUBERNETES AUDIT LOG, not CloudTrail. On EKS that
# log exists only if the `audit` control-plane log type was enabled BEFORE the incident — AWS:
# "By default, cluster control plane logs aren't sent to CloudWatch Logs. You must enable each
# log type individually." It lands in CloudWatch Logs group /aws/eks/<cluster>/cluster, stream
# prefix kube-apiserver-audit-. If it was off, every plane-1 rule returns zero and that zero
# means "not recorded", never "did not happen".
#
# THE DISCRIMINATOR IS THE IDENTITY CLASS, AND IT NEEDS NO BASELINE. Kubernetes renders a
# ServiceAccount as `system:serviceaccount:<namespace>:<name>`, with groups system:authenticated,
# system:serviceaccounts and system:serviceaccounts:<namespace>. That prefix is the one field in
# the audit log that separates a workload from a person without any per-account tuning. A pod
# does a small, fixed set of things forever; a ServiceAccount writing RBAC objects, minting
# tokens, entering other pods or reading kube-system Secrets is a compromised workload or a
# stolen token, whichever way the token got out.
#
# WHY THIS IS NOT A PURE COMPOSITION OF ITS BUILDING BLOCKS. Unlike the ordering-based flow in
# ../../eks.privilege-escalation.flow-alert---cluster-admin-access-granted-after-multiple-u/,
# the thesis here is a CONJUNCTION rather than a sequence: identity class AND operation class.
# Either half alone is worthless — every request in the cluster is made by some identity, and
# privileged operations are performed by humans and controllers constantly. The pair is the
# signal, and no single building block carries it.
#
# FIELD SHAPES — verified against the Kubernetes audit Event API reference, 2026-08-29.
#   sourceIPs is the schema name and it is an ARRAY ([]string); there is no `sourceIPAddresses`,
#   and a rule keyed on that name matches nothing unless the pipeline renames it.
#   responseStatus.code is int32 — matched unquoted below.
#   objectRef.name is ABSENT on list and watch, because those target a collection.
#   objectRef.subresource carries `token`, `exec`, `attach`, `portforward`.
#   requestObject is populated for pods and for the rbac.authorization.k8s.io group because the
#   EKS default audit policy records those at RequestResponse level for write verbs. It is NOT
#   populated for secrets, which that policy caps at Metadata — which is why no rule here claims
#   to know what a Secret contained.
#
# THE STAGE FILTER IS NOT DECORATION. Every rule in the EKS default audit policy carries
# omitStages: ["RequestReceived"] EXCEPT the one covering serviceaccounts/token. So token minting
# — the single most important operation in this file — is emitted at BOTH RequestReceived and
# ResponseComplete, and any count-based rule on it double-counts by exactly two. The success
# filter would exclude the RequestReceived copy implicitly, since no response exists yet, but
# "implicitly" depends on how a pipeline renders an absent responseStatus. `stage` is matched
# explicitly instead.
title: Kubernetes ServiceAccount performed a privileged control-plane operation
id: 9c2f4d17-6b83-4e05-a7d1-52b0e9c3f841
name: eks_sa_privileged_operation
status: experimental
description: >-
  A workload identity — user.username beginning system:serviceaccount: — successfully wrote an
  RBAC object, minted a ServiceAccount token, entered a running pod, or used one of the verbs
  that exist to bypass authorization. None of these belongs to an application. A pod that has
  done its job for months and then writes a ClusterRoleBinding is not doing new work; it is
  running someone else's code, or its projected token is being used from outside the cluster.
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
  workload_identity:
    user.username|startswith: 'system:serviceaccount:'
  completed:
    stage: 'ResponseComplete'
  succeeded:
    responseStatus.code:
      - 200
      - 201
  rbac_write:
    objectRef.resource:
      - 'clusterrolebindings'
      - 'rolebindings'
      - 'clusterroles'
      - 'roles'
    verb:
      - 'create'
      - 'update'
      - 'patch'
      - 'delete'
  token_mint:
    objectRef.subresource: 'token'
    verb: 'create'
  pod_entry:
    objectRef.subresource:
      - 'exec'
      - 'attach'
      - 'portforward'
  bypass_verb:
    verb:
      - 'escalate'
      - 'bind'
      - 'impersonate'
  # POPULATE BEFORE DEPLOYING. In-cluster controllers legitimately perform some of these, and
  # the set is small, closed and stable — it IS the tuning surface for this rule. The names below
  # are the kube-system controllers the EKS default audit policy itself enumerates; add the
  # add-on and GitOps controllers this cluster actually runs. Do not widen it to a namespace
  # prefix: kube-system is exactly where a compromised workload wants to be.
  known_controllers:
    user.username:
      - 'system:serviceaccount:kube-system:endpoint-controller'
      - 'system:serviceaccount:kube-system:namespace-controller'
      - 'system:serviceaccount:kube-system:node-problem-detector'
  condition: workload_identity and completed and succeeded and (rbac_write or token_mint or pod_entry or bypass_verb) and not known_controllers
falsepositives:
  - >-
    A controller missing from known_controllers. Expect a short burst of these on first
    deployment; enumerate them once, add them, and the rule goes quiet. If it does not go quiet,
    the finding is that ordinary workloads hold control-plane write permissions.
  - >-
    An operator or GitOps agent that reconciles RBAC by design. Allowlist the identity, never the
    operation — the operation is the entire signal.
level: high
---
title: Kubernetes ServiceAccount denied a privileged control-plane operation
id: 3e51b8a0-47cc-4f92-b6d3-0a8e17c4d925
name: eks_sa_privileged_operation_denied
status: experimental
description: >-
  Base rule — sequence component, and a signal in its own right at medium. The same operations as
  eks_sa_privileged_operation, refused by RBAC. The discriminator is HTTP 403, not 401: 403 means
  the workload identity was established and the permission was missing, while 401 means the token
  itself failed to authenticate — an expired projected token, which is an availability problem
  rather than an intrusion. A well-built application never probes for permissions it does not
  have, so a workload accumulating 403s is enumerating.
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
  workload_identity:
    user.username|startswith: 'system:serviceaccount:'
  denied:
    responseStatus.code: 403
  privileged_target:
    objectRef.resource:
      - 'clusterrolebindings'
      - 'rolebindings'
      - 'clusterroles'
      - 'roles'
      - 'secrets'
      - 'serviceaccounts'
      - 'pods'
      - 'nodes'
  condition: workload_identity and denied and privileged_target
falsepositives:
  - >-
    A controller whose RBAC was tightened and which still retries the old call. Real, and it
    should be fixed rather than allowlisted — a controller retrying a forbidden call forever is
    a defect either way.
level: medium
---
title: Kubernetes ServiceAccount read Secrets in the kube-system namespace
id: 7f0a6c39-1d54-4b8e-9a02-c63f5b7e2410
name: eks_sa_kube_system_secret_access
status: experimental
description: >-
  A workload identity read Secrets in kube-system. Almost no application has business there, and
  the namespace holds the credentials of the cluster's own components. Note what this rule can
  and cannot tell you: the EKS default audit policy caps `secrets` at Metadata level, so the
  event names WHICH secret only on a `get`. A `list` or `watch` targets a collection and carries
  NO objectRef.name at all — so the highest-impact case, one request returning every Secret in
  the namespace, is the case where the event names nothing. Treat an unnamed list as full
  exposure of the namespace, never as a lesser event than a named get.
references:
  - https://kubernetes.io/docs/concepts/configuration/secret/
  - https://attack.mitre.org/techniques/T1552/007/
tags:
  - attack.credential-access
  - attack.t1552.007
logsource:
  category: application
  product: kubernetes
  service: audit
detection:
  workload_identity:
    user.username|startswith: 'system:serviceaccount:'
  target:
    objectRef.resource: 'secrets'
    objectRef.namespace: 'kube-system'
  read_verb:
    verb:
      - 'get'
      - 'list'
      - 'watch'
  completed:
    stage: 'ResponseComplete'
  # POPULATE BEFORE DEPLOYING — see the note on eks_sa_privileged_operation.
  known_controllers:
    user.username|startswith: 'system:serviceaccount:kube-system:'
  condition: workload_identity and target and read_verb and completed and not known_controllers
falsepositives:
  - >-
    The known_controllers filter here excludes every kube-system ServiceAccount, which is broad
    on purpose — those accounts read their own namespace constantly and the rule is unusable
    without it. The cost is real and must be stated: a compromised kube-system ServiceAccount is
    invisible to this rule. eks_sa_privileged_operation still covers it for writes.
level: high
---
title: Kubernetes ServiceAccount created a pod that escapes container isolation
id: b84d2e70-95a1-4c36-8f2b-71e0d34a9c68
name: eks_sa_privileged_pod_created
status: experimental
description: >-
  A workload identity created a pod requesting host namespaces or privileged containers.
  hostNetwork puts the pod on the node's network stack, which AWS states means it "will always
  have IMDS access" — so such a pod reaches the NODE IAM role at 169.254.169.254 regardless of
  whether EKS Pod Identity or IRSA is configured, and regardless of what the pod's own
  ServiceAccount is allowed. hostPID and privileged reach the node's processes and devices. This
  is the standard route from "I control a workload" to "I control the node". Bodies are available
  here because the EKS default audit policy records core-group writes at RequestResponse level.
references:
  - https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
  - https://attack.mitre.org/techniques/T1611/
tags:
  - attack.privilege-escalation
  - attack.t1611
logsource:
  category: application
  product: kubernetes
  service: audit
detection:
  workload_identity:
    user.username|startswith: 'system:serviceaccount:'
  pod_create:
    objectRef.resource: 'pods'
    verb: 'create'
  succeeded:
    responseStatus.code:
      - 200
      - 201
  host_namespace:
    requestObject.spec.hostNetwork: true
  host_pid:
    requestObject.spec.hostPID: true
  privileged_container:
    requestObject.spec.containers|contains: '"privileged":true'
  condition: workload_identity and pod_create and succeeded and (host_namespace or host_pid or privileged_container)
falsepositives:
  - >-
    CNI, CSI and monitoring DaemonSets legitimately request host namespaces, and they are created
    by controllers rather than by a person. Filter on the creating identity once you have the
    list; the pod spec is not the thing to relax.
level: high
---
title: A workload identity probed for permissions and then exercised them
id: 26bd8f14-c073-4e51-90a7-3f5c1a628db3
status: experimental
description: >-
  One ServiceAccount accumulated authorization denials and then successfully performed a
  privileged control-plane operation. group-by is user.username because it is the only field
  carrying the workload identity on both stages, and it binds them to ONE ServiceAccount — an
  ungrouped version of this correlation is satisfied by unrelated denials anywhere in the cluster.
  Timespan is 1h: a compromised workload is driven interactively and probes and acts in one
  session. Note that this correlation is deliberately INTRA-PLANE. The cross-plane version —
  ServiceAccount acts, then its bound IAM role is assumed — cannot be bound reliably, because the
  ServiceAccount identity is not a documented field of the corresponding CloudTrail event. See
  detection_note_t1098_006.md.
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
    - eks_sa_privileged_operation_denied
    - eks_sa_privileged_operation
  group-by:
    - user.username
  timespan: 1h
level: critical
---
title: EKS Pod Identity association created or changed
id: 4d7c9a52-8e16-4b70-a3f9-6c2b0d51e837
name: eks_pod_identity_association_changed
status: experimental
description: >-
  CreatePodIdentityAssociation or UpdatePodIdentityAssociation bound an IAM role to a Kubernetes
  ServiceAccount. This is the AWS half of a workload identity, and it is invisible to the
  Kubernetes audit log — the association lives in EKS, not in the cluster, so no kubectl command
  enumerates it and no audit event records it. A new association is a new path from a pod to an
  IAM role; whether that path is legitimate depends entirely on whether the namespace and service
  account named in the request are the ones that role was scoped for. Logged as a CloudTrail
  management event on a default trail, which is why this rule carries a different logsource from
  the plane-1 rules in this file.
references:
  - https://docs.aws.amazon.com/eks/latest/userguide/pod-id-how-it-works.html
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
      - 'CreatePodIdentityAssociation'
      - 'UpdatePodIdentityAssociation'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the infrastructure-as-code roles that own these associations.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/PlatformAutomation'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    Ordinary provisioning of a new workload. Expect these in clusters under active development;
    the allowlist is the tuning surface, and an association created by a human outside it is the
    case worth reading.
level: medium
---
title: Workload IAM role assumed for an EKS pod
id: a1e6b473-2f80-49dc-8b15-04d97c3ea562
name: eks_workload_role_assumed
status: experimental
description: >-
  Base rule — inventory and pivot component, not for direct alerting at this level. The two
  documented ways an EKS pod obtains AWS credentials: AssumeRoleForPodIdentity on the EKS Auth
  API (EKS Pod Identity, credentials served to the pod at 169.254.170.23) and
  AssumeRoleWithWebIdentity on STS (IRSA, via the eks.amazonaws.com/role-arn annotation and the
  cluster OIDC provider). It fires constantly in a healthy cluster and is shipped so a responder
  can enumerate which roles a workload actually exercised and from where — not so it can page
  anyone. It is deliberately NOT wired into the correlation above: the ServiceAccount identity
  is not a documented field of either event, and a correlation keyed on a field that may not
  exist is a rule that reports clean forever.
references:
  - https://docs.aws.amazon.com/eks/latest/userguide/pod-id-how-it-works.html
  - https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
  - https://attack.mitre.org/techniques/T1552/007/
tags:
  - attack.credential-access
  - attack.t1552.007
logsource:
  product: aws
  service: cloudtrail
detection:
  pod_identity:
    eventSource: 'eks-auth.amazonaws.com'
    eventName: 'AssumeRoleForPodIdentity'
  irsa:
    eventSource: 'sts.amazonaws.com'
    eventName: 'AssumeRoleWithWebIdentity'
  condition: pod_identity or irsa
level: informational
```

What this set structurally cannot do: it cannot tell you what a Secret contained, because the
managed audit policy caps `secrets` at Metadata and the policy is a `kube-apiserver` flag AWS
owns. It cannot name the object on a `list` or `watch`, because `objectRef.name` is absent for
collection requests — and that unnamed event is the *wider* one. And it cannot bind a
ServiceAccount to the AWS role it assumed, because the ServiceAccount identity is not a
documented field of `AssumeRoleForPodIdentity` or `AssumeRoleWithWebIdentity`; Query 4 joins
those by hand, on namespace and timing, and says so.

---

### Key Investigation Queries

> Queries 1 and 2 read **CloudWatch Logs Insights** against `/aws/eks/<cluster>/cluster` — the
> Kubernetes audit log, which is regional to the cluster. Queries 3 and 4 read CloudTrail, whose
> management events appear in every region. CloudTrail extraction uses
> `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50
> events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: everything this ServiceAccount did

```bash
CLUSTER="<cluster-name>"
REGION="us-east-1"
SA="system:serviceaccount:<namespace>:<name>"   # from the alert's user.username
START=$(date -u -v-24H +%s 2>/dev/null || date -u -d '24 hours ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query \
  --log-group-name "/aws/eks/${CLUSTER}/cluster" \
  --start-time "$START" --end-time "$END" \
  --region "$REGION" --output text --query queryId \
  --query-string "fields @timestamp, verb, objectRef.resource, objectRef.subresource,
                         objectRef.namespace, objectRef.name, responseStatus.code,
                         sourceIPs.0, annotations.\`authorization.k8s.io/decision\`
                  | filter user.username = '${SA}' and stage = 'ResponseComplete'
                  | sort @timestamp asc
                  | limit 1000")

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'
```

Read it as a story in order. The first `403` is where they started probing; the first `200` on
an RBAC resource is where they stopped needing to. If `sourceIPs.0` is a pod address inside the
cluster CIDR, the token is being used from where it was issued; if it is anything else, the
token left the cluster and the pod may be entirely uninvolved.

#### Query 2 — Sweep: every RBAC grant that names this ServiceAccount, and the controller allowlist

```bash
SA_NS="<namespace>"
SA_NAME="<name>"

echo "== bindings naming this ServiceAccount =="
for KIND in clusterrolebindings rolebindings; do
  kubectl get "$KIND" -A -o json | jq -r --arg ns "$SA_NS" --arg n "$SA_NAME" '
    .items[]
    | select(.subjects != null)
    | select(any(.subjects[];
        (.kind == "ServiceAccount" and .name == $n and ((.namespace // $ns) == $ns))))
    | "\(.kind)\t\(.metadata.namespace // "-")/\(.metadata.name)\t-> \(.roleRef.kind)/\(.roleRef.name)"'
done

echo
echo "== what those roles actually permit =="
kubectl get clusterroles -o json | jq -r '
  .items[] | .metadata.name as $r
  | .rules[]? | select((.verbs // []) | any(. == "*" or . == "escalate" or . == "bind" or . == "impersonate"))
  | "\($r)\tverbs=\(.verbs)\tresources=\(.resources // [])"' | sort -u

echo
echo "== every ServiceAccount that wrote RBAC in the last 24h — this IS the allowlist =="
echo "[i] run Query 1's Insights query with the user.username filter removed and"
echo "    'filter objectRef.apiGroup = \"rbac.authorization.k8s.io\" and verb != \"get\"'"
echo "    to enumerate legitimate controllers before deploying the rules."
```

A binding whose `roleRef` is `cluster-admin`, or a role carrying `escalate` or `bind`, ends the
triage question: the ServiceAccount can grant itself anything, and the blast radius is the
cluster.

#### Query 3 — Inspect: the AWS identity the audit log cannot see

```bash
CLUSTER="<cluster-name>"
REGION="us-east-1"
SA_NS="<namespace>"
SA_NAME="<name>"

echo "== EKS Pod Identity associations for this ServiceAccount =="
aws eks list-pod-identity-associations --cluster-name "$CLUSTER" \
  --namespace "$SA_NS" --service-account "$SA_NAME" \
  --region "$REGION" --output json | jq '.associations'

echo
echo "== IRSA annotation, the other binding mechanism =="
kubectl get serviceaccount "$SA_NAME" -n "$SA_NS" -o json | \
  jq -r '.metadata.annotations["eks.amazonaws.com/role-arn"] // "[i] no IRSA annotation"'

echo
echo "== who created or changed an association recently =="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreatePodIdentityAssociation \
  --start-time "$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     ns: .requestParameters.namespace, sa: .requestParameters.serviceAccount,
     role: .requestParameters.roleArn,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | jq -s 'sort_by(.time)'
```

Either mechanism returning a role ARN means the incident has an AWS half. Read that role's
policies before deciding severity — this is where a contained pod turns out to have held
`s3:GetObject` on the production data bucket.

#### Query 4 — Full session reconstruction of the workload's AWS role

```bash
REGION="us-east-1"
ROLE_ARN="<role-arn-from-Query-3>"
ROLE_NAME="${ROLE_ARN##*/}"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$ROLE_NAME" \
  --start-time "$(date -u -v-24H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, src: .eventSource,
     caller: .userIdentity.arn, ip: .sourceIPAddress,
     error: (.errorCode // "SUCCESS")}' | jq -s 'sort_by(.time)'

echo
echo "[i] The ServiceAccount identity is NOT a documented field of AssumeRoleForPodIdentity or"
echo "    AssumeRoleWithWebIdentity. This join is by role, namespace and timing — say so in the"
echo "    incident record rather than asserting the pod made these calls."
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Containment is two-sided and neither side is sufficient. Stripping RBAC leaves the IAM role
reachable; deleting the Pod Identity association leaves cluster-admin in place. Do both, in the
order below, and capture evidence before anything is deleted — the pod spec and the token's
audience are gone the moment the pod is.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being contained.

#### Step 1 — Preserve the evidence that deletion destroys

```bash
SA_NS="<namespace>"
SA_NAME="<name>"
CASE_DIR="./ir-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$CASE_DIR"

kubectl get pods -n "$SA_NS" -o json \
  | jq --arg n "$SA_NAME" '[.items[] | select(.spec.serviceAccountName == $n)]' \
  > "$CASE_DIR/pods.json"
kubectl get serviceaccount "$SA_NAME" -n "$SA_NS" -o json > "$CASE_DIR/sa.json"
kubectl get clusterrolebindings,rolebindings -A -o json > "$CASE_DIR/bindings.json"

UID_BEFORE=$(jq -r '.metadata.uid' "$CASE_DIR/sa.json")
echo "[i] ServiceAccount UID before containment: $UID_BEFORE"
echo "[i] every token issued to this account carries that UID and dies when it changes"
```

#### Step 2 — Stop the workload without losing the node

```bash
OWNER=$(jq -r '.[0].metadata.ownerReferences[0].name // empty' "$CASE_DIR/pods.json")
KIND=$(jq -r '.[0].metadata.ownerReferences[0].kind // empty' "$CASE_DIR/pods.json")

if [ -n "$OWNER" ] && [ "$KIND" = "ReplicaSet" ]; then
  DEPLOY="${OWNER%-*}"
  echo "[i] scaling deployment/$DEPLOY to zero — a bare pod delete just gets recreated"
  kubectl scale deployment "$DEPLOY" -n "$SA_NS" --replicas=0
elif [ -n "$OWNER" ]; then
  echo "[!] pod is owned by $KIND/$OWNER — scale or suspend that object, not the pod"
else
  echo "[!] unmanaged pod; delete it directly once evidence in $CASE_DIR is confirmed complete"
fi
```

#### Step 3 — Cut the in-cluster half

```bash
mapfile -t CRBS < <(jq -r --arg ns "$SA_NS" --arg n "$SA_NAME" '
  .items[] | select(.subjects != null)
  | select(any(.subjects[]; .kind == "ServiceAccount" and .name == $n and ((.namespace // $ns) == $ns)))
  | select(.kind == "ClusterRoleBinding") | .metadata.name' "$CASE_DIR/bindings.json")

for B in "${CRBS[@]}"; do
  [ -z "$B" ] && continue
  if kubectl get clusterrolebinding "$B" >/dev/null 2>&1; then
    kubectl delete clusterrolebinding "$B"
  else
    echo "[i] $B already gone"
  fi
done

# Invalidate every token ever issued to this account. Deleting the ServiceAccount is the only
# operation that does this: tokens carry the account UID, and a recreated account gets a new
# one. Deleting the POD does not — a token minted without a boundObjectRef outlives it.
if kubectl get serviceaccount "$SA_NAME" -n "$SA_NS" >/dev/null 2>&1; then
  kubectl delete serviceaccount "$SA_NAME" -n "$SA_NS"
  kubectl create serviceaccount "$SA_NAME" -n "$SA_NS"
  UID_AFTER=$(kubectl get serviceaccount "$SA_NAME" -n "$SA_NS" -o jsonpath='{.metadata.uid}')
  [ "$UID_AFTER" != "$UID_BEFORE" ] \
    && echo "[OK] UID changed $UID_BEFORE -> $UID_AFTER; prior tokens are dead" \
    || echo "[FAIL] UID unchanged — tokens still valid, investigate before proceeding"
fi
```

#### Step 4 — Cut the AWS half, and contain the calling principal

```bash
CLUSTER="<cluster-name>"
REGION="us-east-1"

ASSOC=$(aws eks list-pod-identity-associations --cluster-name "$CLUSTER" \
  --namespace "$SA_NS" --service-account "$SA_NAME" --region "$REGION" \
  --output json | jq -r '.associations[]?.associationId // empty')

for A in $ASSOC; do
  aws eks delete-pod-identity-association --cluster-name "$CLUSTER" \
    --association-id "$A" --region "$REGION" >/dev/null \
    && echo "[OK] deleted association $A"
done

# IRSA has no association object — the trust lives in the role and the annotation.
kubectl annotate serviceaccount "$SA_NAME" -n "$SA_NS" eks.amazonaws.com/role-arn- 2>/dev/null \
  || echo "[i] no IRSA annotation to remove"

# Kill credentials already issued from the workload role. AWSRevokeOlderSessions denies every
# call made with a session issued before now; it does not touch new, legitimate sessions.
ROLE_NAME="<role-name-from-Query-3>"
if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$ROLE_NAME" \
    --policy-name AWSRevokeOlderSessions --policy-document file:///tmp/revoke.json \
    && echo "[OK] sessions issued before now are revoked on $ROLE_NAME"
fi
```

If Query 1 showed a pod created with `hostNetwork` or `hostPID`, the **node** IAM role must be
treated as compromised as well, and that role is shared by every pod on that node — cordon and
drain the node, then revoke its role's sessions the same way.

---

## 4. Eradication

### Remove Attacker Access

#### Confirm no binding anywhere still names the account

```bash
REMAIN=$(kubectl get clusterrolebindings,rolebindings -A -o json | jq -r --arg n "$SA_NAME" '
  [.items[] | select(.subjects != null)
   | select(any(.subjects[]; .kind == "ServiceAccount" and .name == $n))] | length')
[ "$REMAIN" -eq 0 ] && echo "[OK] no binding names $SA_NAME" \
                    || echo "[FAIL] $REMAIN binding(s) still name it"
```

#### Remove other persistence by the same identity

Query 1's timeline is the checklist. For every `create` it shows, confirm the object is gone:
mutating and validating webhooks (a webhook can re-grant on every admission), `CronJob` objects,
DaemonSets, and any `Secret` of type `kubernetes.io/service-account-token` — the legacy,
non-expiring token form, which is created deliberately and never by accident.

```bash
kubectl get secrets -A --field-selector type=kubernetes.io/service-account-token -o json | \
  jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name)\tfor=\(.metadata.annotations["kubernetes.io/service-account.name"])"'
kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations -o name
```

#### Right-size the permission that made this possible

The finding is rarely "the attacker got in". It is that the workload's ServiceAccount could
write RBAC at all. Applications need almost nothing from the API server; most need no token
mounted. Set `automountServiceAccountToken: false` on the ServiceAccount and on every pod spec
that does not call the API, and the primary credential simply is not there to steal.

#### Remove emergency policies once clean

Delete the `AWSRevokeOlderSessions` policy after the role's legitimate consumers have been
re-issued credentials, and remove any break-glass access entry created during the response.

---

## 5. Recovery

### Restore Clean State

#### Verify the ServiceAccount holds only what the manifest says

```bash
BASELINE_ROLES=$(kubectl apply --dry-run=client -o json -f "<path-to-manifests>" 2>/dev/null \
  | jq -r '[.items[]? | select(.kind|test("RoleBinding$")) | .roleRef.name] | sort | unique | join(",")')
LIVE_ROLES=$(kubectl get clusterrolebindings,rolebindings -A -o json \
  | jq -r --arg n "$SA_NAME" '[.items[] | select(.subjects != null)
      | select(any(.subjects[]; .kind == "ServiceAccount" and .name == $n))
      | .roleRef.name] | sort | unique | join(",")')

[ "$LIVE_ROLES" = "$BASELINE_ROLES" ] && echo "[OK] bindings match the committed manifests" \
                                      || echo "[FAIL] live=[$LIVE_ROLES] baseline=[$BASELINE_ROLES]"
```

#### Confirm the audit log is on and reaching CloudWatch

```bash
ENABLED=$(aws eks describe-cluster --name "$CLUSTER" --region "$REGION" --output json \
  | jq -r '[.cluster.logging.clusterLogging[] | select(.enabled) | .types[]] | join(",")')
case "$ENABLED" in
  *audit*) echo "[OK] audit logging enabled ($ENABLED)" ;;
  *)       echo "[FAIL] audit logging OFF — every rule in this playbook returns zero" ;;
esac
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  user.username=system:serviceaccount:app:web  verb=create"
echo "  objectRef.resource=clusterrolebindings  responseStatus.code=201  stage=ResponseComplete"
echo "The rule MUST NOT fire on:"
echo "  user.username=kubernetes-admin  verb=create  objectRef.resource=clusterrolebindings"
echo "  (a human administrator doing the same thing — the identity class is the whole signal)"
echo "and MUST NOT fire on:"
echo "  user.username=system:serviceaccount:app:web  verb=get  objectRef.resource=configmaps"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A ServiceAccount could write cluster-scoped RBAC | Role granted by convenience — a wildcard verb or an off-the-shelf chart's default binding — and never reviewed against what the application calls |
| The token was mounted in a pod that never uses the API | `automountServiceAccountToken` left at its default of `true` |
| The workload's IAM role was broader than the workload | Pod Identity association pointed at a shared role instead of one scoped to that namespace and account |
| A `hostNetwork` pod could be created at all | No admission policy restricting host namespaces in application namespaces |
| The incident was reconstructable only because audit logging happened to be on | Control-plane logging is off by default and is not enforced at cluster creation |

### Recommended Guardrails

**Keep the AWS half of a workload identity out of reach**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["eks:CreatePodIdentityAssociation", "eks:UpdatePodIdentityAssociation",
             "eks:CreateAccessEntry", "eks:AssociateAccessPolicy"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Prevent the audit log from being turned off**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["eks:UpdateClusterConfig", "logs:DeleteLogGroup", "logs:PutRetentionPolicy"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- `automountServiceAccountToken: false` as the default, opted out of per workload rather than
  into. This removes the credential rather than detecting its misuse.
- A Pod Security Standard at `restricted`, or an admission policy denying `hostNetwork`,
  `hostPID`, `hostIPC`, `privileged` and `hostPath` in every namespace that is not
  infrastructure. This closes the pod-to-node path directly.
- One IAM role per ServiceAccount, with the trust policy's `sub` condition pinned to the exact
  `system:serviceaccount:<ns>:<name>` — a wildcard `sub` lets any pod in the cluster assume it.
- Deny `escalate` and `bind` verbs everywhere outside the platform team's roles; they exist
  precisely to let a subject grant permissions it does not hold.

**Detection improvements**
- Populate `known_controllers` from a week of audit data before deploying, then treat every new
  entrant as a finding rather than as tuning debt.
- Alert on `automountServiceAccountToken` regressing to `true` on a workload previously set to
  `false` — that change is a prerequisite for this whole technique.
- Compare `sourceIPs[0]` against the cluster's pod CIDR. A ServiceAccount token used from
  outside it has left the cluster, and that fact does not need a threshold.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098.006 — Account Manipulation: Additional Container Cluster Roles |
| MITRE tactic | Persistence (TA0003), Privilege Escalation (TA0004) |
| Primary API | `POST /apis/rbac.authorization.k8s.io/v1/clusterrolebindings`, `POST /api/v1/namespaces/<ns>/serviceaccounts/<n>/token` |
| Event source | Kubernetes audit log (`/aws/eks/<cluster>/cluster`); CloudTrail for `eks.amazonaws.com`, `eks-auth.amazonaws.com`, `sts.amazonaws.com` |
| Key discriminator | `user.username` begins `system:serviceaccount:` **and** the operation is administrative — the identity class, which needs no baseline |
| Ground-truth signal | An audit event with `stage: ResponseComplete`, `responseStatus.code` 200/201, and an RBAC `objectRef.resource` |
| "Was it used" pivot | The new binding's `roleRef` resolved and the account then performed an operation it was previously denied — Query 1's 403-then-200 transition |
| Blast radius | The union of every ClusterRole now bound to the account, plus any IAM role reachable through Pod Identity or IRSA, plus the node role if a `hostNetwork` pod was created |
| Error strings | `403` — authenticated, permission missing (enumeration). `401` — token failed to authenticate (expired projected token, not an intrusion signal) |

**MITRE mapping note:** the source rule carries bare `T1098` (Account Manipulation). That is
defensible as a parent but imprecise; `T1098.006 — Additional Container Cluster Roles` names
exactly this behaviour and is what the shipped rules carry. The Secret-read and role-assumption
documents carry `T1552.007`, the host-namespace pod `T1611`, and the denial-accumulation base
rule `T1613`.

### Residual Risk

Anything the account read is already gone. Secret **values** are never in the audit log, so
every Secret in scope of a successful `get` or `list` must be rotated on the assumption it was
taken — and for an unnamed `list`, that means every Secret in the namespace. Tokens minted
before containment are dead once the ServiceAccount UID changes, but AWS credentials already
issued from the workload role remain valid until their expiry unless the revoke policy was
applied, and anything already done with them — an object copied, a key created elsewhere — is
outside this cluster's control entirely. If a `hostNetwork` pod ran, the node role's credentials
were readable by every other pod on that node for as long as it existed, and the containment
boundary is the node, not the workload.
