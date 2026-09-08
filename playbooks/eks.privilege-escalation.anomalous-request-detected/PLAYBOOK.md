# IR Playbook: Command Execution in a Running Pod — `exec` Is the Signal, Not the Command String

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Execution (interactive or one-shot command run inside a running container via the Kubernetes API) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High.** The session runs as the pod's ServiceAccount, so it reaches everything that identity reaches — including, via IRSA or EKS Pod Identity, an AWS role. Session content is not logged, so an interactive shell records one event and conceals everything typed after it. The source rule rates it P2 and matches strings the actor controls |
| MITRE Tactics | Execution |
| MITRE Techniques | T1609 |
| Services in Scope | EKS, Kubernetes RBAC, IAM, STS, EKS Pod Identity / IRSA, and whatever the pod's identity reaches |

**What the technique does:** a principal calls the Kubernetes API for the `exec`, `attach` or
`portforward` subresource on a running pod. The API server upgrades the connection to a
WebSocket (`101`) and the command runs **inside the container, as the pod's ServiceAccount**
— not as the caller. From there the session can read the pod's projected token, reach the
EKS Pod Identity endpoint at `169.254.170.23` for AWS credentials, or — if the pod runs with
`hostNetwork: true` — reach EC2 IMDS at `169.254.169.254` and take the **node** role.

**Detection thesis.** The signal is **`objectRef.subresource`**, which the API server sets
from the request path and the client cannot influence. The source rule matches `userAgent`
(client-declared) and a list of shell paths (enumerable, incomplete, and blind to distroless
images) — so it detects only an actor who did not think about either.

---

## 1. Preparation

**Logging & Visibility**
- **EKS control-plane `audit` logging must be enabled** — all five types are off by default.
  Delivered to CloudWatch Logs at `/aws/eks/<cluster>/cluster`
- Fields this playbook reads: `objectRef.resource`, `.subresource` (`exec`, `attach`,
  `portforward`, `log`, `token`), `.namespace`, `.name`, `user.username`, `sourceIPs`
  (**array** — client first), `requestURI`, `userAgent`, `stage`, and `responseStatus.code`
  (**`int32`** — an exec upgrade returns **`101`**, not `200`)
- **A baseline of which principals legitimately exec.** The shipped rule is an allowlist and
  is worthless without one
- **A way to resolve pod → ServiceAccount → IAM role.** The audit event does not carry it,
  and the pod spec ages out once the pod stops — so either capture pod specs continuously or
  accept that late investigation cannot establish the blast radius
- The cluster's EKS Pod Identity associations and any IRSA annotations

**Alerting (must be pre-configured)**
- **An exec session established by a `system:serviceaccount:` principal → P0**
- **An exec session established by a principal outside the operator allowlist → P1**
- **A principal reviewed its own permissions and opened an exec session within the hour → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- `kubectl` against the cluster (`aws eks update-kubeconfig`), using an access entry that pre-dates the incident — creating one during the response is itself an event you will later have to distinguish from the actor's.
- CloudWatch Logs Insights access for the log group named in **Logging & Visibility**, and the patience for `start-query` to settle before reading results.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- Which principals and automation roles touch this service at all. In most estates the list is short, which makes an unfamiliar caller a finding before any threshold is evaluated.
- The contents of `known_operators` from the shipped rules. Each is populated before deployment and is the whole tuning cost of the detection.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `subresource` exec/attach/portforward established (`101`/`200`) by a `system:serviceaccount:` principal | Kubernetes audit | T1609 |
| P1 | The same by any principal outside the operator allowlist | Kubernetes audit | T1609 |
| P1 | A principal reviewed its own permissions and exec'd within the hour | Kubernetes audit | T1609 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Exec refused by RBAC (`403`) — the actor tried and lacked it | Kubernetes audit | T1609 |
| P3 | `requestURI` naming an interactive shell — enrichment on an already-matched event | Kubernetes audit | T1609 |

### Detection Rule Quality Notes

The source rule matches what the actor controls and misses the field the API server sets.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Matches `userAgent: /kubectl-access_matrix/` | **`userAgent` is set by the client.** Renaming the binary or passing `--user-agent` defeats it. The rule detects only an actor who did not consider it | Key on `objectRef.subresource`, which the API server derives from the request path. Keep `userAgent` as context |
| Matches a fixed list of shell paths in `requestURI` | Enumerable and incomplete — `/bin/zsh`, `/bin/dash`, `/busybox`, an absolute path to any binary, or an exec into a **distroless image with no shell** all evade it. Most of what an actor runs is not a shell | The command becomes **enrichment**: it raises priority on an already-matched event and its absence never suppresses the alert |
| No response-code condition | An exec is a **WebSocket upgrade returning `101`**. A rule that later adds a `200` filter would miss every established session; one with no filter cannot separate an established session from a refused attempt | `101`/`200` for established, `403` for refused, as separate verdicts. `int32`, unquoted |
| No principal allowlist and no identity-class distinction | A human operator debugging is plausible; a **ServiceAccount** exec'ing into another pod is not — no normal application does it. Treating them alike buries the strongest signal | `system:serviceaccount:` prefix ranks P0; everything else is gated on an operator allowlist |
| `group_by: []` | One actor's session sweep across pods produces ungroupable alerts with no principal attached | Grouped by `user.username` |
| Titled "Anomalous Request Detected" | The query implements no anomaly detection — it matches two fixed strings. The title claims a capability the rule does not have, which is how a rule survives review unexamined | Renamed by intent in the playbook; the directory keeps the source slug for traceability |

**Recommended detection — command executed in a running pod.**

```yaml
# Command Execution in a Running Pod (T1609 — Container Administration Command)
#
# Source rule:
#   userAgent: /kubectl-access_matrix/ OR requestURI:/%2Fbin%2Fbash/
#   OR requestURI:/%2Fbin%2Fsh/ OR requestURI:/%2Fbin%2Fash/
#
# It matches two attacker-controllable strings and an enumerable list, and misses the
# structural field that actually identifies the act.
#
# 1. userAgent IS SET BY THE CLIENT. `kubectl-access_matrix` names one specific RBAC
#    enumeration plugin. Renaming the binary, or setting --user-agent, defeats it. A rule
#    keyed on a tool's self-declared name detects only an actor who did not think about it.
# 2. THE SHELL LIST IS ENUMERABLE AND INCOMPLETE. /bin/zsh, /bin/dash, /busybox, an absolute
#    path to any binary, or `exec` into a distroless image with no shell at all — none match.
#    The list also cannot see a command that is not a shell, which is most of what an actor
#    would run.
# 3. THE STRUCTURAL SIGNAL IS objectRef.subresource. An exec request carries
#    subresource `exec` regardless of what command it runs, what the client calls itself, or
#    whether the target image has a shell. It is not attacker-controllable because the API
#    server sets it from the request path.
#
# The rules below key on the subresource and treat the command as ENRICHMENT rather than as
# the match condition — so an unusual command raises the priority but its absence never
# suppresses the alert.
title: Command executed in a running pod
id: 6f2a90e5-84d1-4c37-b95e-0a73c8641bde
name: eks_pod_exec
status: experimental
description: >-
  A principal opened an exec, attach or port-forward session against a running pod. The
  session runs with the pod's ServiceAccount and reaches anything that identity reaches.
references:
  - https://attack.mitre.org/techniques/T1609/                          # retrieved 2026-08-30
  - https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/  # retrieved 2026-08-30
tags:
  - attack.execution
  - attack.t1609
logsource:
  category: application
  product: kubernetes
  service: audit
detection:
  # B4 confirmed: resource and subresource co-occur on every audit Event for these calls.
  selection:
    objectRef.resource: 'pods'
    objectRef.subresource:
      - 'exec'
      - 'attach'
      - 'portforward'
  completed:
    stage: 'ResponseComplete'
  # 101 is the WebSocket upgrade an exec session actually returns; 200 covers the other
  # shapes. responseStatus.code is int32 — do not quote it.
  established:
    responseStatus.code:
      - 101
      - 200
  # DEPLOYMENT PARAMETER — populate before use. Operators and debug tooling that legitimately
  # exec. Allowlist by exact principal, never by a substring like "system", which would drop
  # every system:serviceaccount principal in the cluster.
  known_operators:
    user.username:
      - 'system:serviceaccount:kube-system:cluster-autoscaler'
  condition: selection and completed and established and not known_operators
falsepositives:
  - Break-glass human debugging. It should be rare, attributable and time-boxed; if it is
    routine, the finding is that production debugging happens by exec.
level: high
---
# The command, kept as ENRICHMENT rather than as a match condition. An exec URI carries the
# command in its query string, so these tokens raise the priority of an already-matched
# event. They must never gate the match — the source rule's mistake — because an actor
# running anything not on this list would then be invisible.
title: Pod exec running an interactive shell or a known offensive tool
id: 1d84c60f-3b57-4e92-a70c-9f5182ae37b1
status: experimental
description: >-
  An exec session into a running pod whose request URI names an interactive shell or a
  recognised enumeration tool. Priority enrichment on top of the exec signal itself.
references:
  - https://attack.mitre.org/techniques/T1609/                          # retrieved 2026-08-30
tags:
  - attack.execution
  - attack.t1609
logsource:
  category: application
  product: kubernetes
  service: audit
detection:
  # B4 confirmed: resource and subresource co-occur on every exec audit Event.
  selection:
    objectRef.resource: 'pods'
    objectRef.subresource: 'exec'
  completed:
    stage: 'ResponseComplete'
  # Both encodings: the audit log may carry the URI percent-encoded or decoded depending on
  # the ingestion path, and the corpus has been burned by assuming one form (rule A4).
  interactive:
    requestURI|contains:
      - '%2Fbin%2Fbash'
      - '%2Fbin%2Fsh'
      - '%2Fbin%2Fash'
      - '%2Fbin%2Fzsh'
      - '/bin/bash'
      - '/bin/sh'
      - '/bin/ash'
      - '/bin/zsh'
      - 'busybox'
      - 'nsenter'
  condition: selection and completed and interactive
falsepositives:
  - A debugging session by an allowlisted operator. This rule deliberately does not carry
    the operator allowlist — it is enrichment, and correlating it with the base rule is the
    triage step.
level: medium
---
# Enumeration by an identity that then execs. The source rule's userAgent match was aimed at
# this, but userAgent is client-set. RBAC self-enumeration is visible structurally instead:
# the audit policy records rbac.authorization.k8s.io get/list/watch at Request level, and
# SelfSubjectAccessReview / SelfSubjectRulesReview are the API for "what may I do?".
title: Principal enumerated its own permissions then executed in a pod
id: 9c0e7b34-5f18-4a26-83d7-4e6b21ca058f
status: experimental
description: >-
  One principal reviewed its own permissions and opened a pod exec session within the hour —
  the shape of an actor orienting inside a cluster it has just reached.
references:
  - https://attack.mitre.org/techniques/T1609/                          # retrieved 2026-08-30
tags:
  - attack.execution
  - attack.discovery
  - attack.t1609
correlation:
  type: temporal
  rules:
    - eks_self_permission_review
    - eks_pod_exec
  group-by:
    - user.username
  timespan: 60m
level: high
---
title: Principal reviewed its own permissions
id: 2b47f8a1-6c93-4d05-91be-3a08e7f24c69
name: eks_self_permission_review
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://kubernetes.io/docs/reference/access-authn-authz/authorization/  # retrieved 2026-08-30
tags:
  - attack.discovery
  - attack.t1609
logsource:
  category: application
  product: kubernetes
  service: audit
detection:
  selection:
    objectRef.resource:
      - 'selfsubjectaccessreviews'
      - 'selfsubjectrulesreviews'
  completed:
    stage: 'ResponseComplete'
  condition: selection and completed
level: low
```

Reproduced byte-for-byte from the first rule document of `detections/sigma_t1609.yml`. Three
further documents ship in that file: the interactive-shell enrichment (`medium`), the
enumerate-then-exec correlation (`high`), and its self-review base rule (`low`). **Deploy
the file, not this excerpt** — and populate `known_operators` first, or the base rule fires
on legitimate tooling.

**What these rules structurally cannot do.** They cannot show you what was typed. The audit
log records the command line requested at session open and nothing after it, so an
interactive shell is one event concealing a whole session. And they cannot tell you the
pod's identity — that needs the pod spec, which ages out. Full reasoning in
`detections/detection_note_t1609.md`.

---

### Key Investigation Queries

> These run against the **Kubernetes audit log** at `/aws/eks/<cluster>/cluster`, not CloudTrail. If audit logging was off, none of this exists — see `../eks.stealth.user-deleted-log-events/`.

#### Query 1 — Reconstruct: who exec'd, into what, and did the session establish

```bash
REGION="us-east-1"; CLUSTER="<cluster-name>"
LG="/aws/eks/${CLUSTER}/cluster"
SINCE_MS=$(( ( $(date +%s) - 86400 ) * 1000 ))

aws logs filter-log-events --log-group-name "$LG" --region "$REGION" \
  --start-time "$SINCE_MS" \
  --filter-pattern '{ $.objectRef.subresource = "exec" || $.objectRef.subresource = "attach" || $.objectRef.subresource = "portforward" }' \
  --output json > /tmp/eks-exec.json

# responseStatus.code is int32 — an exec upgrade returns 101, not 200.
# sourceIPs is an ARRAY and the CLIENT is the FIRST element.
jq -r '.events[].message | fromjson |
  select(.stage == "ResponseComplete") |
  {time: .requestReceivedTimestamp,
   user: .user.username,
   kind: (if (.user.username | startswith("system:serviceaccount:")) then "WORKLOAD"
          elif (.user.username | test(":assumed-role/|^arn:aws:")) then "iam"
          else "other" end),
   client: (.sourceIPs // [] | first),
   sub: .objectRef.subresource,
   ns: .objectRef.namespace,
   pod: .objectRef.name,
   uri: .requestURI,
   agent: .userAgent,
   code: .responseStatus.code,
   outcome: (if (.responseStatus.code == 101 or .responseStatus.code == 200) then "ESTABLISHED"
             elif .responseStatus.code == 403 then "rbac-refused"
             else "other" end)}' /tmp/eks-exec.json | jq -s 'sort_by(.time)'
```

`kind: "WORKLOAD"` with `outcome: "ESTABLISHED"` is the strongest row on the page — a pod
opened a session into another pod, and no normal application does that. For human
principals, check `user` against the operator baseline. Read `uri` for the requested command,
but **do not read its absence as reassurance**: an interactive shell records only the shell
itself and hides everything typed afterwards, so a bare `/bin/bash` is *less* informative
and *more* serious than a named one-shot command. `agent` is context only — the client sets
it. Record `user`, `ns`, `pod` and the earliest `time`.

#### Query 2 — Establish the blast radius before containment, because it expires

The session ran as the **pod's** ServiceAccount, not the caller's, and that identity is not
in the audit event. The pod spec is the only source and it ages out when the pod stops.

```bash
REGION="us-east-1"; CLUSTER="<cluster-name>"
NS="<ns-from-Query-1>"; POD="<pod-from-Query-1>"

SA=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{.spec.serviceAccountName}' 2>/dev/null)
if [ -z "$SA" ]; then
  echo "[!] Could not read pod $NS/$POD — it may already have stopped, or kubectl access"
  echo "    is missing. The pod's identity is then UNRECOVERABLE. INCONCLUSIVE, not clean."
else
  echo "[i] Pod $NS/$POD runs as ServiceAccount $SA"
  # IRSA is an annotation on the ServiceAccount.
  ROLE=$(kubectl get sa "$SA" -n "$NS" \
           -o jsonpath='{.metadata.annotations.eks\.amazonaws\.com/role-arn}' 2>/dev/null)
  [ -n "$ROLE" ] && echo "[!] IRSA: $SA -> $ROLE — treat that IAM role as exposed"
  # EKS Pod Identity is an AWS-side association, not an annotation.
  aws eks list-pod-identity-associations --cluster-name "$CLUSTER" --namespace "$NS" \
    --service-account "$SA" --region "$REGION" --output json 2>/dev/null \
    | jq -r '.associations[]? | "[!] Pod Identity: \(.associationArn) — resolve to its IAM role and treat as exposed"'
  # hostNetwork reaches EC2 IMDS regardless of Pod Identity, taking the NODE role.
  HN=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{.spec.hostNetwork}' 2>/dev/null)
  [ "$HN" = "true" ] && echo "[!] hostNetwork=true — this pod could reach EC2 IMDS and take the NODE role. See ../ec2.credential-access.imds-credential-theft/"
fi
```

Every `[!]` line is an identity to treat as compromised. If the pod has already stopped,
say so in the incident record rather than reporting a clean result — the blast radius is
then genuinely unknown.

#### Query 3 — Sweep: the same behaviour anywhere else in the cluster

```bash
CLUSTER="<cluster-name>"
REGION="us-east-1"
START=$(date -u -v-7d +%s 2>/dev/null || date -u -d '7 days ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query \
  --log-group-name "/aws/eks/${CLUSTER}/cluster" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string 'fields user.username, verb, objectRef.resource, objectRef.subresource,
                         objectRef.namespace, responseStatus.code
                  | filter stage = "ResponseComplete"
                  | stats count() as calls,
                          count_distinct(`objectRef.namespace`) as namespaces,
                          count_distinct(`objectRef.name`) as objects
                          by `user.username`, verb, `objectRef.resource`
                  | sort calls desc
                  | limit 200')

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'
```

The alert named one identity and one object; this asks who else does the same thing, and how
widely. Read `namespaces` before `calls` — an identity acting in one namespace is scoped to a
workload, and the same verb across many namespaces is not. A cluster-wide identity that nobody
recognises is a finding before any count is considered.

**`stage = "ResponseComplete"` must stay.** Every rule in the EKS default audit policy carries
`omitStages: ["RequestReceived"]` except the one covering `serviceaccounts/token`, so without
this filter that one operation is counted twice and every threshold on it is silently halved.

#### Query 4 — Full session reconstruction: the identity on both planes

```bash
CLUSTER="<cluster-name>"
REGION="us-east-1"
SUBJECT="<user.username-from-Query-1>"
START=$(date -u -v-7d +%s 2>/dev/null || date -u -d '7 days ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query \
  --log-group-name "/aws/eks/${CLUSTER}/cluster" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string "fields @timestamp, verb, objectRef.resource, objectRef.subresource,
                         objectRef.namespace, objectRef.name, responseStatus.code, sourceIPs.0
                  | filter user.username = '${SUBJECT}' and stage = 'ResponseComplete'
                  | sort @timestamp asc
                  | limit 1000")

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'

echo
echo "[i] The AWS half is NOT in this log. If the subject is a ServiceAccount, its IAM identity"
echo "    is an EKS Pod Identity association or an IRSA annotation, and the calls made with it"
echo "    are in CloudTrail under eks-auth:AssumeRoleForPodIdentity or"
echo "    sts:AssumeRoleWithWebIdentity. Neither event carries the ServiceAccount name, so that"
echo "    join is by namespace and timing — state it as such rather than asserting it."
```

Read it as a sequence. The first `403` is where probing began; the first `200` on a
privileged resource is where it stopped being probing. `sourceIPs.0` inside the cluster's pod
CIDR means the credential is being used where it was issued; anything else means it left.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**Capture the pod's identity before you stop the pod.** Deleting it destroys the spec, and
with it the only link from the session to the AWS role it could reach.

> Run `kubectl` steps under a break-glass kubeconfig whose own access is not what you are
> revoking, and AWS steps under the break-glass credentials from §1.

#### Step 1 — Revoke the exec permission, and treat the pod's identity as compromised

```bash
NS="<ns-from-Query-1>"; POD="<pod-from-Query-1>"; USERNAME="<user-from-Query-1>"

echo "[i] Query 2 must have completed first — the pod spec is the only source of the"
echo "    ServiceAccount and it is destroyed with the pod."
echo "[i] Remove the binding granting pods/exec to $USERNAME:"
echo "    kubectl get clusterrolebindings,rolebindings -A -o json | jq '.items[] | select(.subjects[]? | .name==\"'$USERNAME'\")'"
echo "[!] The pod's ServiceAccount token was readable during the session. Removing a"
echo "    RoleBinding stops AUTHORISATION but does NOT invalidate a token already issued to"
echo "    a running pod — only deleting the ServiceAccount object does, and that breaks the"
echo "    workload. Decide deliberately."
```

#### Step 2 — Revoke the AWS identity the pod carried

```bash
REGION="us-east-1"; CLUSTER="<cluster-name>"
NS="<ns-from-Query-1>"; SA="<serviceaccount-from-Query-2>"
ROLE_NAME="<role-name-from-Query-2>"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Pod Identity: remove the association so no new credentials are minted.
ASSOC=$(aws eks list-pod-identity-associations --cluster-name "$CLUSTER" --namespace "$NS" \
          --service-account "$SA" --region "$REGION" \
          --query 'associations[0].associationId' --output text 2>/dev/null)
if [ -n "$ASSOC" ] && [ "$ASSOC" != "None" ]; then
  aws eks delete-pod-identity-association --cluster-name "$CLUSTER" --association-id "$ASSOC" \
    --region "$REGION" && echo "[OK] Removed Pod Identity association $ASSOC"
else
  echo "[i] No Pod Identity association found — check the IRSA annotation path instead"
fi

# Then revoke sessions already issued from that role.
if [ -n "$ROLE_NAME" ]; then
  aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$NOW"'"}}}]}' \
    && echo "[OK] Revoked pre-existing sessions for role $ROLE_NAME"
fi
```

> Order matters: `aws:TokenIssueTime` denies only tokens issued **before** the cutoff, so
> removing the association must come first. Reversed, the pod re-fetches a credential the
> deny does not cover.

---

## 4. Eradication

### Remove Attacker Access

- **Treat the pod as compromised, not just the session.** Its image, command and mounted
  secrets are all in scope — the session had the container's full filesystem
- **Rotate every secret the pod mounted**, and every credential the ServiceAccount's IAM role
  could read. The session content is not logged, so what was taken is unknowable
- **If `hostNetwork: true`**, treat the **node** IAM role as exposed and work
  `../ec2.credential-access.imds-credential-theft/`
- **Audit who else holds `pods/exec`.** A standing grant is what made this possible and it
  survives replacing the pod
- **Replace the pod from its source image**, do not restart it — a restart of a mutated
  container preserves nothing but proves nothing either
- **Remove the emergency deny policy** once rotation is complete

---

## 5. Recovery

### Restore Clean State

#### Verify the exec permission is gone

```bash
REGION="us-east-1"; CLUSTER="<cluster-name>"; LG="/aws/eks/${CLUSTER}/cluster"
USERNAME="<user-from-Query-1>"
SINCE_MS=$(( ( $(date +%s) - 900 ) * 1000 ))

RAW=$(aws logs filter-log-events --log-group-name "$LG" --region "$REGION" \
        --start-time "$SINCE_MS" \
        --filter-pattern '{ $.objectRef.subresource = "exec" }' --output json 2>/dev/null)

if [ -z "$RAW" ]; then
  echo "[!] filter-log-events returned nothing — API error, missing permission, or audit"
  echo "    logging is off. INCONCLUSIVE, not clean."
else
  N=$(printf '%s' "$RAW" | jq --arg u "$USERNAME" '[.events[].message | fromjson
        | select(.stage == "ResponseComplete")
        | select(.user.username == $u)
        | select(.responseStatus.code == 101 or .responseStatus.code == 200)] | length')
  [ "${N:-1}" -eq 0 ] \
    && echo "[OK] No established exec session by $USERNAME in the last 15 minutes" \
    || echo "[FAIL] $N established exec session(s) by $USERNAME since containment"
fi
```

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     objectRef.resource pods, objectRef.subresource exec, stage"
echo "                  ResponseComplete, responseStatus.code 101 (UNQUOTED int), user not"
echo "                  in known_operators -> eks_pod_exec, level high"
echo "MUST fire on:     the SAME event with NO recognisable shell in requestURI — an exec of"
echo "                  /usr/bin/env, or into a distroless image. The command must never gate"
echo "                  the match; that is the source rule's defect."
echo "MUST fire on:     an exec whose userAgent is anything at all, including a renamed"
echo "                  binary. userAgent is client-set and is context only."
echo "MUST NOT fire on: code 403 — that is RBAC refusing, a separate P2 verdict"
echo "MUST NOT fire on: a principal in known_operators — populate that list first"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal opened a shell inside a running container | `pods/exec` granted more broadly than break-glass debugging requires |
| The deployed rule could be evaded trivially | It matched a client-declared `userAgent` and a fixed list of shell paths rather than the API-server-set subresource |
| What happened inside the session is unknown | Session content is not recorded by the Kubernetes audit log, and no session-recording control was in place |
| The blast radius could not be established after the fact | Pod → ServiceAccount → IAM role is resolvable only from the pod spec, which does not survive the pod |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// The AWS half only — reserve cluster-access grants to the platform pipeline.
{
  "Effect": "Deny",
  "Action": ["eks:CreateAccessEntry", "eks:AssociateAccessPolicy", "eks:CreatePodIdentityAssociation"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/platform-pipeline" }
  }
}
```

> Wildcard value, so `ArnNotLike` — under `StringNotEquals` the wildcard is not expanded, the
> condition matches every request, and the `Deny` denies everything. **And note the ceiling:
> no SCP reaches `pods/exec`, which is RBAC and lives entirely inside the cluster.**

- **Remove `pods/exec` from standing roles.** Make it a break-glass grant with an expiry;
  routine debugging by exec is the underlying finding
- **Run workloads with `automountServiceAccountToken: false`** unless the pod needs the API.
  It removes the token an exec session would otherwise find
- **Never run application pods with `hostNetwork: true`** — it reaches EC2 IMDS and the node
  role regardless of Pod Identity

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1609 — Container Administration Command |
| MITRE tactic | Execution (TA0002) |
| Primary API | Kubernetes `POST` to `pods/exec`, `pods/attach`, `pods/portforward`. No AWS API |
| Event source | Kubernetes audit log via EKS control-plane logging → CloudWatch Logs. **Off by default** |
| Key discriminator | `objectRef.subresource` — set by the API server from the request path, **not client-influenceable**. Not `userAgent`, which the client declares, and not the command string, which is enumerable |
| Response code | An exec is a **WebSocket upgrade returning `101`**, not `200`. `403` is RBAC refusing. `int32` — do not quote |
| Recording limit | **Session content is never logged.** `requestURI` holds the command requested at session open; everything typed afterwards is invisible. An interactive shell is therefore *less* informative and *more* serious than a one-shot command |
| Blast radius | The **pod's** ServiceAccount, not the caller's — plus any IRSA or Pod Identity IAM role behind it, and the node role if `hostNetwork: true`. **Not in the event**; resolvable only from the pod spec, which ages out |
| Endpoints | `169.254.170.23` EKS Pod Identity · `169.254.170.2` ECS · `169.254.169.254` EC2 IMDS. IMDSv2 constrains only the third |
| Strongest signal | An exec by a `system:serviceaccount:` principal. No normal application execs into another pod |

### Residual Risk

**What was done inside the session is unrecoverable.** The audit log records the command
requested at session open and nothing after it. For an interactive shell that means one
event and an unbounded session — and no configuration of EKS audit logging changes it,
because the content never reaches the API server as discrete requests.

**The pod's identity may already be unknowable.** If the pod stopped before Query 2 ran, the
spec is gone and with it the link to the ServiceAccount and any IAM role. The blast radius is
then genuinely indeterminate and should be recorded as such rather than assumed small.

**An issued ServiceAccount token outlives the binding you removed.** Unless the
ServiceAccount object itself was deleted, a token already handed to a running pod stays valid
for its lifetime.

**No AWS-side control prevents a re-grant.** `pods/exec` is RBAC. Anyone able to create
bindings inside the cluster can restore it without touching AWS, and the guardrail above
cannot see it.
