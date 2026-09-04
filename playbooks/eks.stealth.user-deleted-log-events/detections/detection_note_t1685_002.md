# Detection Note — T1685.002 (Kubernetes Events Deleted on EKS)

**Signal:** there isn't one, in the audit log, and that is the finding.

## The source rule cannot fire

It matches `verb:"delete" AND objectRef.resource:"events"` against the Kubernetes audit
log. On EKS that combination is never written.

EKS runs a **managed control plane**. The audit policy is a `kube-apiserver` flag
(`--audit-policy-file`), which Kubernetes documents as the control-plane operator's
responsibility — on EKS that operator is AWS, and **the policy is not customer-modifiable
and is not exposed through any EKS API.** In AWS's published policy, core `events` — any
verb, any user — is level **`None`**. Rules are evaluated first-match-wins, and `None` does
not mean "metadata only"; it means the request is not logged.

So deleting Kubernetes Events on an EKS cluster produces **no audit record**. The rule has
matched nothing since deployment, and its silence is indistinguishable from nobody deleting
anything. Anyone reading an empty result as assurance is reading a configuration fact as a
security fact.

There is no fix inside the audit log, and none is offered here.

## What is observable instead

An actor clearing traces on EKS has to touch the AWS plane, and those calls survive:

| What they do | Where it lands | Why it is visible |
|---|---|---|
| `UpdateClusterConfig` disabling log types | CloudTrail, `eks.amazonaws.com` | The cluster keeps running; the streams stop |
| `DeleteLogGroup` on `/aws/eks/<cluster>/cluster` | CloudTrail, `logs.amazonaws.com` | **The cluster's own logging configuration is untouched and still reports enabled** |
| `PutRetentionPolicy` cutting retention to 1 day | CloudTrail, `logs.amazonaws.com` | Records expire before anyone reads them |

The third shipped rule is the nearest **in-cluster** signal: the RBAC grant that permits
event deletion. The audit policy logs `rbac.authorization.k8s.io` create/update/patch at
`RequestResponse`, so the binding's rule body is in `requestObject`. It is a precursor, one
step removed from the act, and is levelled `medium` accordingly.

## Two adjacent gaps from the same policy

Worth knowing because they shape every other EKS playbook:

- **`secrets` and `configmaps` are `Metadata` level.** You learn who read which object, the
  verb, and the namespace. You never learn the secret value or the ConfigMap body.
- **A `list` or `watch` carries no `objectRef.name`.** `kubectl get secrets -n prod` is a
  *single* audit event naming no object — and it returned every secret in the namespace. Any
  query answering "which objects were touched" from `objectRef.name` returns null on the
  highest-impact case and non-null on the lowest.

One narrow exception runs the other way: `configmaps` named `aws-auth` in `kube-system`,
verbs `update`/`patch`/`delete`, are logged at `RequestResponse` — the full before-and-after
of the IAM-to-Kubernetes identity map. But **`create` is absent from that rule's verb list**,
so creating the ConfigMap where none exists is body-less.

## Field shapes that silently return nothing

- **`sourceIPs` is an array**, and the field is `sourceIPs`. There is no `sourceIPAddresses`
  in the schema. Through a proxy the client is the **first** element and the proxy is last.
- **`responseStatus.code` is `int32`.** A rule comparing it to a quoted `"200"` is
  type-dependent and may never match. `200`/`201` both mean the request succeeded.
- **`objectRef.apiGroup` is the empty string for the core group** — `""` is not absent.
- Every policy rule except `serviceaccounts/token` carries `omitStages: ["RequestReceived"]`,
  so the normal event is `stage: ResponseComplete`. Token minting appears at **both** stages,
  so any count on it double-counts unless it filters `stage`.

## Response levers

**MITRE:** Live mapping is
**T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log**, tactic **Defense
Impairment (TA0112)**; TA0005 was renamed *Stealth*. Revoked techniques are served as
redirect stubs and still return HTTP 200 — verify with `tools/attack_currency_check.py`
rather than by loading the page.

**GuardDuty:** EKS Protection covers this area well from EKS audit logs — including `Policy:Kubernetes/AdminAccessToDefaultServiceAccount`, `PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleBindingCreated`, `CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed` and `Policy:Kubernetes/AnonymousAccessGranted`, plus the `AttackSequence:EKS/CompromisedCluster` correlation. Treat these rules as complementary and check for overlap before routing both.

**Files here:**
- `sigma_t1685_002.yml` — three documents: control-plane logging disabled (`high`), audit
  log group deleted or retention shortened (`high`), and the RBAC-grant precursor
  (`medium`). The first two are CloudTrail; the third is Kubernetes audit. **A file mixing
  both logsources is the shape of this service, not an inconsistency.**
- `kql_t1685_002.kql` — the CloudTrail view, with the verdict distinguishing a log-group
  deletion from a log-type disable from a retention cut.

Full response procedure is in `../PLAYBOOK.md`.
