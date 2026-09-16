# Detection Note — T1609 (Command Execution in a Running Pod)

**Signal:** `objectRef.subresource` of `exec`, `attach` or `portforward` on a pod — set by
the API server from the request path, and not influenceable by the client.

## What the original rule got wrong

```
userAgent: /kubectl-access_matrix/ OR requestURI:/%2Fbin%2Fbash/
OR requestURI:/%2Fbin%2Fsh/ OR requestURI:/%2Fbin%2Fash/
```

Both halves match strings the actor controls or can trivially avoid.

**`userAgent` is set by the client.** `kubectl-access_matrix` names one specific RBAC
enumeration plugin. Renaming the binary, or passing `--user-agent`, defeats the match. A
rule keyed on a tool's self-declared name detects only an actor who did not think about it.

**The shell list is enumerable and incomplete.** `/bin/zsh`, `/bin/dash`, `/busybox`, an
absolute path to any binary — none match. Nor does an `exec` into a **distroless image with
no shell at all**, which is increasingly the norm. And most of what an actor would run is
not a shell.

**The structural field was available and unused.** An exec request carries
`objectRef.subresource: exec` regardless of the command, the client's name, or whether the
target image has a shell. The API server sets it from the request path.

So the shipped rules key on the subresource, and keep the command as **enrichment**: an
interactive shell raises the priority of an already-matched event, and its absence never
suppresses the alert. That inversion is the whole correction.

## The response code is not 200

An exec session is a **WebSocket upgrade** and returns **`101`**. A rule matching only `200`
misses established sessions. `responseStatus.code` is `int32` — do not quote it. `403` is
RBAC refusing the exec, which is a separate and useful signal.

## What the log does not carry, and why it inverts the severity

**The session content is not logged.** `requestURI` holds the command line requested at
session open. Everything typed inside an interactive shell afterwards is invisible.

So an `exec` of `/bin/bash` produces **one event and hides an entire session**, while a
one-shot `exec -- cat /etc/passwd` produces one event that fully describes itself. The
interactive case is the *less* informative record and the *more* dangerous act — which is
why the shipped verdicts rank an interactive shell above a named command, not below it.

## The blast radius is the pod's ServiceAccount, and it is not in this event

The session runs as the pod's identity, not the caller's. Resolving it takes two more steps:

```
pod -> spec.serviceAccountName -> ServiceAccount
ServiceAccount -> eks.amazonaws.com/role-arn annotation (IRSA)
              -> or an EKS Pod Identity association
```

**None of that is in the audit event**, and the pod spec ages out once the pod stops. Capture
it before containment, not after — which is why the playbook's evidence step precedes every
containment step.

Endpoint discipline, since these are routinely confused: `169.254.170.23` is **EKS Pod
Identity**; `169.254.170.2` is the **ECS** task endpoint; `169.254.169.254` is **EC2 IMDS**.
IMDSv2 constrains only the third — and a pod with `hostNetwork: true` reaches the **node**
role through IMDS regardless of Pod Identity.

## Exec by a workload identity is the strongest single signal here

A human operator debugging is plausible. **A `system:serviceaccount:` principal opening an
exec session into another pod is not** — no normal application does it. That is why the KQL
ranks it P0 above an interactive shell by a human.

## Enumeration then execution

The source rule's `userAgent` match was aimed at RBAC enumeration. That is visible
structurally instead: the audit policy records `rbac.authorization.k8s.io` `get`/`list`/`watch`
at `Request` level, and `SelfSubjectAccessReview` / `SelfSubjectRulesReview` are the API for
*"what am I allowed to do?"*. A principal that asks and then execs within the hour is an
actor orienting in a cluster it has just reached — shipped as a `temporal` correlation.

## Response levers

**MITRE:** the source maps this to `T1078 — Valid Accounts`, which describes how the principal got there rather than what it did. `T1609 — Container Administration Command` is the act. Verified live 2026-08-30.

**GuardDuty:** EKS Protection covers this area well from EKS audit logs — including `Policy:Kubernetes/AdminAccessToDefaultServiceAccount`, `PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleBindingCreated`, `CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed` and `Policy:Kubernetes/AnonymousAccessGranted`, plus the `AttackSequence:EKS/CompromisedCluster` correlation. Treat these rules as complementary and check for overlap before routing both.

**Files here:**
- `sigma_t1609.yml` — four documents: pod exec/attach/portforward established (`high`, gated
  on an operator allowlist), the interactive-shell enrichment (`medium`), the
  enumerate-then-exec correlation (`high`), and its self-review base rule (`low`).
- `kql_t1609.kql` — all outcomes separated, with `userAgent` kept as context rather than as
  a match condition.

Full response procedure is in `../PLAYBOOK.md`.
