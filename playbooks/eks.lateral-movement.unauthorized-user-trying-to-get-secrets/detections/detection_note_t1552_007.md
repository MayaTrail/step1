# Detection Note — T1552.007 (Unauthorized Secret Access on EKS)

**Signal:** a principal reading, or being refused, Kubernetes secrets — and the refusal is
the less serious half.

## What the original rule got wrong

```
objectRef.resource:"secrets" AND verb:("list" OR "watch" OR "get")
AND NOT user.username:system AND responseStatus.code:"403"
```

**`NOT user.username:system` excludes every workload in the cluster.** A pod authenticates
as `system:serviceaccount:<namespace>:<name>`. That bare substring exclusion was meant to
drop control-plane chatter; what it actually drops is **every ServiceAccount principal** —
so a compromised pod reading secrets is filtered out by the rule that exists to catch it.
Exclude by *exact* ServiceAccount name, never by the substring `system`.

**`responseStatus.code` is `int32` and the rule quotes it.** A quoted comparison against an
integer field is backend-dependent and may silently never match.

**It only matches `403`.** A principal that should not have had the permission but *did*
returns `200`. The rule sees every failure and is blind to every success — and the success
is the incident. `annotations["authorization.k8s.io/decision"]` carries the authoritative
`allow`/`forbid` independent of the HTTP code, and is the better discriminator when the two
disagree.

**What it got right, and this file keeps:** `403` is the correct denial code. AWS's own
published example query for unauthorised secret access uses `401` — wrong on both counts.

| Code | Meaning | Why it matters |
|---|---|---|
| `403` | authenticated, **RBAC refused** | what "unauthorized" means here |
| `401` | **authentication failed** | a different incident — identity mapping, expired token |
| `200`/`201` | **it worked** | the worst outcome, invisible to an error-code rule |

## The list trap — a false-negative generator

`objectRef.name` is populated when a request names one object. **A `list` or `watch` targets
a collection and carries no `objectRef.name`.**

So `kubectl get secrets -n prod` is a **single** audit event, at `Metadata` level, with
`objectRef.resource: secrets`, `objectRef.namespace: prod`, and **no name** — having
returned every secret in the namespace.

Any query, rule or report answering "which secrets were touched" from `objectRef.name`
returns null on the highest-impact case and a name on the lowest. **Treat an absent name as
wider than a present one, never as less.** The shipped KQL carries a `Scope` column that
does exactly this.

## What the audit log will never give you

EKS records `secrets` at **`Metadata`** level. You get who, which verb, which namespace, and
— for a `get` only — which object. **You never get the value**, and no configuration changes
that: on a managed control plane the audit policy is a `kube-apiserver` flag AWS owns and
does not expose through any EKS API.

The consequence for response: you cannot tell from the audit log *what* was read, only that
secrets in a namespace were. Every secret in the blast radius has to be treated as disclosed.

## Identity class decides containment, so establish it first

`user.username` carries two different identity systems:

| Principal | Revoke Kubernetes access | Revoke AWS access |
|---|---|---|
| `arn:aws:sts::…:assumed-role/…` (access entry) | `aws eks delete-access-entry` — an **AWS** call | deny/revoke on the IAM role |
| a name mapped by `aws-auth` | `kubectl` edit of `kube-system/aws-auth` — a **Kubernetes** call | same |
| `system:serviceaccount:<ns>:<name>` | delete the RoleBinding, or the ServiceAccount — a **Kubernetes** call | `delete-pod-identity-association`, or break the OIDC trust — **both** planes |

**Doing the AWS half without the Kubernetes half leaves the grant standing; doing the
Kubernetes half without the AWS half leaves the credential live.** Neither is containment.

**Bound ServiceAccount tokens survive their binding.** Removing a RoleBinding takes effect
immediately for *authorisation*, but a projected token already issued to a running pod stays
valid for its lifetime unless the **ServiceAccount object itself** is deleted — which
invalidates bound tokens because the referenced object is gone, and breaks the workload.
That is the only step that reaches an already-issued token.

## Field shapes

- **`sourceIPs` is an array** — the field is `sourceIPs`; there is no `sourceIPAddresses`.
  Through a proxy the client is the **first** element and the proxy is last.
- `user.groups` is an array; `system:masters` membership is there, not in a role name.
- `objectRef.apiGroup` is the **empty string** for the core group — `""` is not absent.
- Normal stage is `ResponseComplete`; `watch` also emits `ResponseStarted`. Pin the stage or
  long-running requests double-count.

## Response levers

**MITRE:** the source maps this to `T1021 — Remote Services` (Lateral Movement). That is the wrong layer: reading a Kubernetes Secret is not a remote-service session. `T1552.007 — Unsecured Credentials: Container API` names the act exactly. Verified live 2026-08-30.

**GuardDuty:** EKS Protection covers this area well from EKS audit logs — including `Policy:Kubernetes/AdminAccessToDefaultServiceAccount`, `PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleBindingCreated`, `CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed` and `Policy:Kubernetes/AnonymousAccessGranted`, plus the `AttackSequence:EKS/CompromisedCluster` correlation. Treat these rules as complementary and check for overlap before routing both.

**Files here:**
- `sigma_t1552_007.yml` — three documents: secret read denied (`medium`, the base rule),
  secret read **succeeded** by a principal outside the allowlist (`high` — the case the
  source rule cannot see), and a denial-burst correlation (`high`).
- `kql_t1552_007.kql` — all three codes separated, with the `Scope` column marking a
  nameless `list` as whole-namespace.

Full response procedure is in `../PLAYBOOK.md`.
