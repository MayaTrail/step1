# Detection Note — T1098.006 (Account Manipulation: Additional Container Cluster Roles)

**Signal:** a Kubernetes ServiceAccount — an identity that exists to run one application —
performed a control-plane operation that only an administrator has any reason to perform:
writing RBAC, minting a token, entering another pod, or reading `kube-system` Secrets.

**The discriminator here is an identity *class*, not an identity, and that is what makes it
cheap.** Most cloud detections need a baseline: this principal normally does X, so Y is
suspicious. This one does not. Kubernetes renders every ServiceAccount as
`system:serviceaccount:<namespace>:<name>`, and that prefix is carried on every audit event.
A workload is not a person; a workload's behaviour is fixed by its image. The pair *(workload
identity, administrative operation)* is anomalous by construction, in any cluster, on day one.

**What the original rule got wrong** — it is a flow that chains stages by bare internal ID
over a three-hour window grouped by `user.username`. Three defects follow from the shape
regardless of what those stages contain. First, the stages are not in the artifact, so nobody
reviewing the rule can say what it matches — a detection whose logic is unreadable cannot be
tuned, and untunable rules get muted. Second, three hours of ordering is a weak binding: in a
busy cluster one ServiceAccount produces enough control-plane traffic that "A then B within
3h" is satisfied by coincidence. Third, and most consequential, the whole rule lives on one
plane. A ServiceAccount has two identities — its RBAC subject inside the cluster and, if
EKS Pod Identity or IRSA is configured, an IAM role outside it. The flow sees only the first.

## The stage filter is not decoration

Every rule in the EKS default audit policy carries `omitStages: ["RequestReceived"]` **except**
the one covering `serviceaccounts/token`. Token minting — the single most important operation
in this file — is therefore emitted twice, at `RequestReceived` and again at `ResponseComplete`.
Any count-based rule on it over-counts by exactly two, and any threshold tuned on observed
volume is silently half of what its author intended. Every rule here pins `stage` explicitly
rather than relying on the success filter to drop the first copy.

## What the audit log will not tell you

`secrets` and `configmaps` are capped at **Metadata** level in AWS's managed audit policy, so
you learn who read what and never what they got. On a managed control plane the audit policy
is a `kube-apiserver` flag AWS owns and does not expose, so this is not tunable.

**`objectRef.name` is absent on `list` and `watch`.** A single `list` of Secrets in a namespace
returns every Secret in it while naming none. The unnamed event is the *wider* event, not the
lesser one, and both the KQL and the Sigma comment say so — this reads backwards to an analyst
scanning for a resource name, which is exactly when it matters.

Custom resources fall to the policy's catch-all at Metadata, so a policy object implemented as
a CRD is modified without its body being recorded.

## Why the correlation stays inside one plane

The obvious cross-plane correlation — ServiceAccount acts in the cluster, then its bound IAM
role is assumed in AWS — is not shipped, because the ServiceAccount identity is **not a
documented field** of `AssumeRoleForPodIdentity` or `AssumeRoleWithWebIdentity`. A correlation
keyed on a field that may not exist is a rule that reports clean forever, which is worse than
no rule: it occupies the slot a real detection would fill. `eks_workload_role_assumed` ships at
`informational` as a pivot instead — a responder joins the two planes by hand, on namespace and
timing, and knows they are doing so.

## Response levers

Containment is **two-sided and asymmetric**, and this is the operational point of the whole
playbook. Removing the RBAC binding does not touch the IAM role. Deleting the Pod Identity
association does not remove the RBAC. Deleting the pod does not invalidate a token minted with
no `boundObjectRef` — that token is bound to nothing and lives to its expiry. Only deleting the
ServiceAccount object itself invalidates every token issued to it, because tokens carry the
account's UID and a recreated account gets a new one.

**Error strings:** HTTP `403` in `responseStatus.code` means the identity authenticated and
the permission was missing — an enumeration signal. `401` means the token failed to
authenticate, which is an expired projected token and an availability problem. The rules
separate them; a rule that treats both as "denied" pages on kubelet rotation.

**MITRE:** T1098.006 — Account Manipulation: Additional Container Cluster Roles, verified live
2026-08-30. The source rule carries bare `T1098`; `.006` is the exact sub-technique. T1552.007
(Container API credentials) covers the Secret-read and role-assumption rules, T1611 the
host-namespace pod, T1613 the denial-accumulation base rule.

**Severity:** high for the direct rules, critical for the correlation. A ServiceAccount that
can write `clusterrolebindings` can bind itself to `cluster-admin`, and cluster-admin on EKS
reaches every node IAM role through a `hostNetwork` pod. There is no higher ceiling inside the
cluster.

**GuardDuty:** the EKS Protection finding families are the closest coverage —
`Persistence:Kubernetes/ContainerWithSensitiveMount`,
`PrivilegeEscalation:Kubernetes/PrivilegedContainer`, and the `Discovery:Kubernetes/*` family
for denial accumulation. They require EKS Audit Log Monitoring to be enabled, which is a
separate switch from control-plane logging and does not populate the CloudWatch log group these
rules read. Treat GuardDuty as corroboration, never as the log source.

**Files here:**
- `sigma_t1098_006.yml` — seven documents. Four Kubernetes-audit rules
  (`eks_sa_privileged_operation` high, `eks_sa_privileged_operation_denied` medium,
  `eks_sa_kube_system_secret_access` high, `eks_sa_privileged_pod_created` high), one
  `temporal_ordered` correlation at critical, and two CloudTrail rules
  (`eks_pod_identity_association_changed` medium, `eks_workload_role_assumed` informational).
- `kql_t1098_006.kql` — the audit-log view, per ServiceAccount, with the AWS-plane query in a
  commented second section because it reads a different table.

Full response procedure is in `../PLAYBOOK.md`.
