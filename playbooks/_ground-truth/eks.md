# Ground truth — Amazon EKS

Audited once, 2026-08-29, for the five EKS use cases in this batch. Every playbook in
`techniques/eks.*` is written from this file. Read this instead of re-researching.

**This service does not behave like the rest of the corpus.** Everything below exists
because the primary telemetry is the **Kubernetes audit log**, not CloudTrail, and because
two independent identity systems meet inside one event.

---

## 1. Three telemetry planes, not one

| Plane | Carries | Where it lands | On by default? |
|---|---|---|---|
| **Kubernetes audit log** | Every request to the cluster's API server: `user.username`, `user.groups`, `verb`, `objectRef.*`, `responseStatus.code`, `sourceIPs` | CloudWatch Logs group `/aws/eks/<cluster-name>/cluster`, stream prefix `kube-apiserver-audit-` | **NO** |
| **EKS control-plane API** | `CreateCluster`, `UpdateClusterConfig`, `CreateAccessEntry`, `AssociateAccessPolicy`, `DescribeCluster` — the AWS-side management of the cluster | CloudTrail management events | Yes |
| **Workload AWS API** | What a pod's IAM identity did with AWS: `AssumeRoleWithWebIdentity` (IRSA), `AssumeRoleForPodIdentity` (Pod Identity), then every downstream call | CloudTrail management events | Yes |

All five source rules in this batch read plane 1. **Containment and eradication almost
always cross into planes 2 and 3**, and that crossing is the thing every one of these
playbooks has to get right.

## 2. Control-plane logging — five types, all off

AWS: *"By default, cluster control plane logs aren't sent to CloudWatch Logs. You must
enable each log type individually to send logs for your cluster."*

The five separately-enableable types and their CloudWatch log-stream prefixes:

| Type | Stream prefix | What it is |
|---|---|---|
| `api` | `kube-apiserver-` | API server component log, including the flags it started with |
| `audit` | `kube-apiserver-audit-` | **The Kubernetes audit log. This is the one every rule here reads.** |
| `authenticator` | `authenticator-` | The IAM→Kubernetes authentication component. Unique to EKS |
| `controllerManager` | `kube-controller-manager-` | Core control loops |
| `scheduler` | `kube-scheduler-` | Pod placement |

Enable:

```bash
aws eks update-cluster-config --region "$REGION" --name "$CLUSTER" \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
```

Facts that bear on every playbook:

- **Log group name is fixed**: `/aws/eks/<cluster-name>/cluster`. It is created when the
  first log type is enabled.
- **Delivery is best effort.** AWS: *"Amazon EKS control plane logs are delivered to
  CloudWatch Logs within a few minutes. However, log delivery is best effort."* A gap is
  therefore ambiguous between "nothing happened", "not enabled" and "not delivered".
- **Enabling is retrospectively useless.** Nothing that happened before the type was
  enabled is recoverable. For `api` specifically AWS states that log files rotated before
  enablement *"can't be exported to CloudWatch"*.
- **Log-type changes are a CloudTrail event** — `UpdateClusterConfig` with
  `requestParameters.logging`. That is the only plane on which "someone turned the audit
  log off" is visible, and it is a plane-2 event, not a plane-1 one.
- `audit` and `authenticator` are the two security-relevant types. `authenticator` is where
  an IAM principal that failed to map to a Kubernetes identity shows up; an
  authentication failure may not produce a plane-1 audit event that names a real user.

## 3. The EKS default audit policy — the single most load-bearing fact in this batch

EKS runs a **managed control plane**. The audit policy is a `kube-apiserver` flag
(`--audit-policy-file`), which Kubernetes documents as the responsibility of the
control-plane operator — on EKS that operator is AWS, and **the policy is not
customer-modifiable and is not exposed through any EKS API**. What you get is what AWS
chose. AWS publishes the policy in its EKS guidance (retrieved 2026-08-29, published as
`audit.k8s.io/v1beta1`). Rules are evaluated in order and **first match wins**.

### Consequences, in the order they will bite you

| Request | Effective level | Consequence |
|---|---|---|
| core `events` (any verb, any user) | **`None`** | **Not logged at all.** Deleting Kubernetes Events produces no audit record on an EKS cluster |
| `secrets`, `configmaps`, `tokenreviews` | `Metadata` | You get *who / what verb / which object*. You never get the secret value, and you never get the ConfigMap body |
| `configmaps` named `aws-auth` in `kube-system`, verbs `update`/`patch`/`delete` | **`RequestResponse`** | Full before-and-after of the IAM→Kubernetes identity map. This rule sits **first** in the policy |
| `configmaps` named `aws-auth`, verb **`create`** | `Metadata` | **Gap.** The first rule lists only `update`, `patch`, `delete`. Creating the ConfigMap where none exists is body-less in the log |
| `rbac.authorization.k8s.io` — `create`/`update`/`patch`/`delete` on roles, clusterroles, rolebindings, clusterrolebindings | `RequestResponse` | The binding's `roleRef` and `subjects` are in the event. This is why RBAC grants are reconstructable and secret reads are not |
| `rbac.authorization.k8s.io` — `get`/`list`/`watch` | `Request` | Permission enumeration is logged with its request body |
| `serviceaccounts/token` (any verb) | `Request`, **and this rule has no `omitStages`** | Token minting appears at **both** `RequestReceived` and `ResponseComplete`. Any count-based rule on it double-counts unless it filters `stage` |
| core, `apps`, `batch`, `networking.k8s.io`, `storage.k8s.io` … `create`/`update`/`delete` | `RequestResponse` | Pod specs, deployments, jobs come with full bodies |
| any API group **not** in the policy's group list — `events.k8s.io`, `coordination.k8s.io`, `discovery.k8s.io`, `node.k8s.io`, **and every CRD group** | `Metadata` (final catch-all) | Custom resources are metadata-only. A policy object implemented as a CRD is modified without its body being recorded |
| `/healthz*`, `/version`, `/swagger*` | `None` | Not logged |
| `system:kube-proxy` watches on endpoints/services; `system:nodes` `get` on nodes; controller-manager/scheduler `get`+`update` on kube-system endpoints | `None` | Legitimate control-plane chatter is suppressed — which also means **an actor impersonating one of those identities for one of those exact verb/resource pairs is not logged** |

Every rule except the `serviceaccounts/token` one and the `None` rules carries
`omitStages: ["RequestReceived"]`, so **the normal event you see is
`stage: ResponseComplete`**, plus `ResponseStarted` for long-running `watch` requests.

### The `list` trap — this is a false-negative generator

`objectRef.name` is populated for a request that names one object. A **`list` or `watch`
targets a collection and carries no `objectRef.name`.** So `kubectl get secrets -n prod`
is a *single* audit event, at `Metadata` level, with `objectRef.resource: secrets`,
`objectRef.namespace: prod` and **no name** — and that one event returned every secret in
the namespace. Any query, rule or report that answers "which objects were touched" from
`objectRef.name` returns null on the highest-impact case and non-null on the lowest.

## 4. Audit `Event` field shapes — verified against the Kubernetes API reference

Top level: `kind`, `apiVersion`, `level`, `auditID`, `stage`, `requestURI`, `verb`, `user`,
`impersonatedUser`, `sourceIPs`, `userAgent`, `objectRef`, `responseStatus`,
`requestObject`, `responseObject`, `requestReceivedTimestamp`, `stageTimestamp`,
`annotations`.

| Path | Type | Note |
|---|---|---|
| `user.username` | string | The Kubernetes identity. §5 explains what is in it |
| `user.groups` | **`[]string`** | Array. `system:masters` membership is here, not in a role name |
| `user.uid`, `user.extra` | string, `map[string][]string` | |
| `impersonatedUser` | `UserInfo` | **Present only when the request used impersonation.** Same sub-fields |
| **`sourceIPs`** | **`[]string`** | **The field is `sourceIPs` — an ARRAY.** There is no `sourceIPAddresses` in the schema. On a request through a proxy the client IP is the **first** element and the last is the proxy |
| `objectRef.resource` | string | Plural, lowercase: `secrets`, `pods`, `clusterrolebindings` |
| `objectRef.namespace` | string | Absent on cluster-scoped resources |
| `objectRef.name` | string | **Absent on `list`/`watch`** — see §3 |
| `objectRef.apiGroup` | string | **Empty string for the core group.** `""` ≠ absent |
| `objectRef.subresource` | string | `exec`, `log`, `portforward`, `token` |
| `responseStatus.code` | **int32** | HTTP status. `meta/v1.Status`. A rule comparing it to a **quoted string** is type-dependent and may silently never match |
| `responseStatus.reason` | string | `Forbidden`, `Unauthorized`, `NotFound` |
| `annotations` | `map[string]string` | Carries `authorization.k8s.io/decision` (`allow`/`forbid`) and `authorization.k8s.io/reason` — **the authoritative authorisation outcome, independent of the HTTP code** |

### `responseStatus.code` semantics — the most common rule defect on this service

- **`403` = authenticated, and RBAC refused.** This is what "unauthorized user" means in
  every one of these use cases.
- **`401` = authentication failed** — no valid token, expired token, unmappable IAM
  principal. A different incident with a different response.
- **`200` / `201` = it worked.** For a user who should not have had the permission, this
  is the *worst* outcome and it is the one an "unauthorized" rule keyed on an error code
  cannot see.

A rule that matches only `401` sees no RBAC denial at all. AWS's own published example
query for "unauthorized secret access" uses `responseStatus.code="401"`, and it is wrong
on both counts — wrong code, and quoted against an integer field.

## 5. Two identity systems meet in `user.username`

### 5a. Human / IAM principals

An IAM principal is mapped to a Kubernetes identity by one of two mechanisms. The cluster's
`accessConfig.authenticationMode` selects which are live: `CONFIG_MAP`,
`API_AND_CONFIG_MAP`, or `API`.

**Access entries (current).** `CreateAccessEntry` binds one `principalArn` to a `username`
and optional `kubernetesGroups`. If `username` is omitted AWS generates it; AWS's own
`CreateAccessEntry` response example returns:

```
"username": "arn:aws:sts::012345678910:assumed-role/my-role/{{SessionName}}"
```

So the default `user.username` for an IAM role **is an STS assumed-role ARN with the
session name substituted** — that string is the join key back to CloudTrail. Permissions
attach either as `kubernetesGroups` (Kubernetes RBAC decides) or as an **access policy**
via `AssociateAccessPolicy` (EKS decides, no RBAC object exists).
`arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy` grants
`apiGroups: *`, `resources: *`, `verbs: *` plus `nonResourceURLs: *` — full cluster admin,
granted by an AWS API call, leaving **no Kubernetes object** for a responder to find.
`AmazonEKSSecretAdminPolicy` (`secrets`, `*`) and `AmazonEKSAdminViewPolicy`
(`*`/`*`/`get,list,watch` — AWS notes this *"includes Kubernetes Secrets"*) are the two
other secret-reaching ones. A user cannot create custom access policies.

**`aws-auth` ConfigMap (legacy, deprecated).** `kube-system/aws-auth`, keys `mapRoles`
(`rolearn`, `username`, `groups`) and `mapUsers` (`userarn`, `username`, `groups`).
Two facts that matter:

- The IAM principal that **created the cluster** is granted `system:masters` and *"doesn't
  appear in any visible configuration"* — it is in neither the ConfigMap nor, originally,
  any access entry.
- `username` and `groups` support `{{SessionName}}` / `{{SessionNameRaw}}` templates, and
  AWS warns outright: *"a caller who can assume the mapped role can impersonate any
  Kubernetes username that doesn't match a reserved prefix"*, and if used in `groups`,
  *"a caller can choose their own Kubernetes group membership by crafting the session
  name."* **A single templated mapping is a standing privilege-escalation primitive that
  produces no configuration change when exercised.**

`system:masters` is bound to the `cluster-admin` ClusterRole by the default
`cluster-admin` ClusterRoleBinding. Membership shows up in `user.groups`, never in a
username.

### 5b. Workload / ServiceAccount principals

A pod authenticates as its ServiceAccount. Kubernetes renders that identity as:

```
system:serviceaccount:<namespace>:<name>
```

with groups `system:authenticated`, `system:serviceaccounts`, and
`system:serviceaccounts:<namespace>`. **The `system:serviceaccount:` prefix in
`user.username` is the reliable in-cluster/out-of-cluster discriminator** and the only one
that does not depend on a baseline.

Optionally that ServiceAccount also holds an AWS identity:

| | IRSA | EKS Pod Identity |
|---|---|---|
| Binding | ServiceAccount annotation `eks.amazonaws.com/role-arn`, plus a cluster OIDC provider | `CreatePodIdentityAssociation` (cluster + namespace + service account + role) |
| Trust policy | OIDC federated principal, per cluster | `"Service": "pods.eks.amazonaws.com"`, reusable across clusters |
| Credential fetch | SDK calls `sts:AssumeRoleWithWebIdentity` with a projected token | Agent calls **`AssumeRoleForPodIdentity`** on the EKS Auth API |
| In-pod endpoint | projected token file | `http://169.254.170.23/v1/credentials`, token at `/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token`, audience `pods.eks.amazonaws.com`, 24h |
| CloudTrail | `sts.amazonaws.com` `AssumeRoleWithWebIdentity` | `eks-auth.amazonaws.com` `AssumeRoleForPodIdentity` |

Endpoint discipline: `169.254.170.23` is **EKS Pod Identity**; `169.254.170.2` is the
**ECS** task credentials endpoint (see `techniques/ecs.initial-access.command-executed-inside-a-container/`);
`169.254.169.254` is **EC2 IMDS** (see `techniques/ec2.credential-access.imds-credential-theft/`).
IMDSv2 constrains only the third. AWS notes pods with `hostNetwork: true` *"will always
have IMDS access"*, so a pod on the host network can reach the **node** IAM role
regardless of Pod Identity.

### The containment asymmetry — this is why identity class must be established first

| Principal in `user.username` | To revoke Kubernetes access | To revoke AWS access |
|---|---|---|
| `arn:aws:sts::…:assumed-role/…/…` (access entry) | `aws eks delete-access-entry` / `disassociate-access-policy` — **an AWS call** | Attach a deny / revoke sessions on the IAM role |
| A name mapped by `aws-auth` | `kubectl` edit of `kube-system/aws-auth` — **a Kubernetes call** | Same as above |
| `system:serviceaccount:<ns>:<name>` | Delete the RoleBinding/ClusterRoleBinding, or delete the ServiceAccount — **a Kubernetes call** | `delete-pod-identity-association`, or remove the `eks.amazonaws.com/role-arn` annotation and break the OIDC trust — an AWS call *and* a Kubernetes one |

Doing the AWS half without the Kubernetes half leaves the grant standing; doing the
Kubernetes half without the AWS half leaves the credential live. Neither is containment.

**Bound ServiceAccount tokens survive their binding.** Removing a RoleBinding takes effect
immediately for authorisation, but a projected token already issued to a running pod stays
valid for its lifetime unless the ServiceAccount object itself is deleted (which
invalidates bound tokens because the referenced object is gone). Deleting the
ServiceAccount is the only step that reaches an already-issued token — and it breaks the
workload.

## 6. Sigma logsource

```yaml
logsource:
  category: application
  product: kubernetes
  service: audit
```

This is the published Sigma taxonomy for Kubernetes audit events and it is what every
plane-1 rule in `techniques/eks.*` uses. **Do not force these into
`product: aws, service: cloudtrail`** — the field names would be wrong in every rule.

Plane-2 and plane-3 companion rules — CloudWatch Logs deletion, `UpdateClusterConfig`,
access-entry APIs, `AssumeRoleForPodIdentity` — genuinely *are* CloudTrail events and
correctly carry `product: aws, service: cloudtrail` in the same file. A file mixing both
is not an inconsistency; it is the shape of this service.

## 7. Plane-2 facts used by the containment steps

- EKS API calls are **management** events. The only EKS data-event resource type in
  CloudTrail's data-event table is `AWS::EKS::Dashboard`; nothing else about EKS requires
  a data-event trail.
- **CloudWatch Logs has no CloudTrail data-event resource type at all** — it does not
  appear in that table. `DeleteLogGroup`, `DeleteLogStream` and `PutRetentionPolicy` are
  control-plane operations recorded as management events on a default trail.
- `PutRetentionPolicy` set to a short value destroys history on a timer with no further
  event. `DeleteLogStream` and `DeleteLogGroup` are **irreversible** — CloudWatch Logs has
  no undelete and no versioning.
- Useful CLI verbs, all real: `aws eks describe-cluster`, `update-cluster-config`,
  `list-access-entries`, `describe-access-entry`, `list-associated-access-policies`,
  `disassociate-access-policy`, `delete-access-entry`, `list-pod-identity-associations`,
  `delete-pod-identity-association`, `list-access-policies`;
  `aws logs describe-log-groups`, `describe-log-streams`, `start-query`, `get-query-results`,
  `put-retention-policy`, `create-export-task`.
- CloudWatch Logs Insights: `start-query` is asynchronous — poll `get-query-results` until
  `status` is `Complete`. A `Running` status read once and treated as an empty result is a
  false negative, and `Failed`/`Cancelled` must not reach the same branch as zero rows.

## 8. What could NOT be verified

1. **That the published default audit policy is current for every EKS version and platform
   version.** It is published in AWS's EKS guidance rather than in the EKS API reference,
   as `audit.k8s.io/v1beta1` while the current audit API is `audit.k8s.io/v1`, and EKS
   exposes no API that returns the live policy. Every rule-order claim in §3 is verified
   *against the published policy*, not against a running cluster. Confirm on the cluster by
   generating one known request per class and reading what comes back.
2. **Whether CloudWatch Logs read operations (`GetLogEvents`, `FilterLogEvents`,
   `StartQuery`) are recorded in CloudTrail at all.** The page that would say so returned
   no usable content. Do not assume that an actor reading the audit log leaves a record.
3. **The role session name EKS Pod Identity produces**, and the exact session tags on
   `AssumeRoleForPodIdentity`. AWS documents the mechanism but publishes no example event.
   Confirm against a real CloudTrail record before joining on a session name.
4. **Whether the `authenticator` log emits a distinguishable record for an IAM principal
   with no mapping.** The log type is documented; its record format is not.
5. **The field name any given ingestion pipeline presents for `sourceIPs`.** The upstream
   schema name is `sourceIPs` and it is an array; a rule keyed on `sourceIPAddresses`
   depends on a pipeline rename and matches nothing without one.
6. **Whether `objectRef.apiGroup` is emitted as `""` or omitted for core-group resources**
   by any given pipeline. The schema says empty string; JSON serialisers differ.

## 9. Cross-references

- `techniques/ecs.initial-access.command-executed-inside-a-container/` — container
  credential theft on the ECS endpoint. Established ground truth reused here rather than
  repeated: the container-credentials pattern, the six-hour session validity, the
  session-name-as-join-key technique. The EKS analogue uses a different endpoint and a
  different identity model.
- `techniques/aws.defense-evasion.cloudtrail-logging-tampered/` — the reasoning for a
  detection whose own telemetry is the target. `techniques/eks.stealth.user-deleted-log-events/`
  is the same structural problem one plane down and does not re-derive it.
- `techniques/ec2.credential-access.imds-credential-theft/` — the node IAM role, which
  a `hostNetwork: true` pod reaches regardless of Pod Identity.
