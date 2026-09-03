# IR Playbook: Unauthorized Secret Access on EKS — `get` and `list` on `secrets`, where denials are enumeration and successes are the incident

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential access (Kubernetes secrets read, or read attempts refused by RBAC) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High** on a successful read by a principal outside the baseline: the audit log records that secrets were read but never *which values*, so every secret in the namespace must be treated as disclosed. **Medium** on denials, which are enumeration. The source rule rates the whole thing P2 and can only ever see the denials |
| MITRE Tactics | Credential Access |
| MITRE Techniques | T1552.007 |
| Services in Scope | EKS, Kubernetes RBAC, IAM, STS, EKS Pod Identity / IRSA, and whatever the stored secrets authenticate to |

**What the technique does:** a principal calls the Kubernetes API for `secrets` — `get` for one object,
`list` or `watch` for a whole namespace. RBAC either refuses (`403`) or serves it (`200`).
The audit event records who, which verb, which namespace, and — **only for a `get`** —
which object. It never records the value. The principal is one of two kinds: an IAM identity
mapped in via an access entry or `aws-auth`, or a pod's ServiceAccount rendered as
`system:serviceaccount:<namespace>:<name>`. Which kind it is decides the entire containment
path, and the two paths share no step.

**Detection thesis.** The signal is the **outcome code, unquoted, plus whether the principal
is on a baseline of legitimate readers** — and a `list` with no `objectRef.name` is *wider*
than a named `get`, not narrower. The source rule matches only `403`, quotes an `int32`
field, and excludes `user.username:system`, which drops every workload in the cluster.

---

## 1. Preparation

**Logging & Visibility**
- **EKS control-plane `audit` logging must be enabled** — all five log types are off by
  default. Without it there is no Kubernetes-plane telemetry at all. Delivered to CloudWatch
  Logs at `/aws/eks/<cluster>/cluster`
- **`secrets` are recorded at `Metadata` level**, and that is not changeable: on a managed
  control plane the audit policy is a `kube-apiserver` flag AWS owns and does not expose.
  You get who/verb/namespace, and the object name **only for a `get`**
- Fields this playbook reads: `user.username`, `user.groups` (array), `sourceIPs`
  (**array** — the client is the **first** element; there is no `sourceIPAddresses`),
  `objectRef.resource`, `.namespace`, `.name` (**absent on `list`/`watch`**), `verb`,
  `stage`, `responseStatus.code` (**`int32`**), and
  `annotations["authorization.k8s.io/decision"]`
- **A baseline of which principals legitimately read secrets** — controllers, operators,
  CSI drivers. The `high` rule is an allowlist and is worthless without it
- The cluster's **access entries** and its `kube-system/aws-auth` ConfigMap, so an IAM
  principal in `user.username` can be resolved to how it was granted

**Alerting (must be pre-configured)**
- **A `list`/`watch` of secrets succeeding for a principal outside the reader baseline — whole-namespace scope → P0**
- **A `get` of one secret succeeding for a principal outside the reader baseline → P1**
- **Ten or more secret-read denials for one principal in fifteen minutes → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- `kubectl` against the cluster (`aws eks update-kubeconfig`), using an access entry that pre-dates the incident — creating one during the response is itself an event you will later have to distinguish from the actor's.
- CloudWatch Logs Insights access for the log group named in **Logging & Visibility**, and the patience for `start-query` to settle before reading results.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- The contents of `known_readers` from the shipped rules. Each is populated before deployment and is the whole tuning cost of the detection.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `responseStatus.code` 200/201 on `secrets` for a principal not in the reader allowlist, verb `list`/`watch` (whole namespace) | Kubernetes audit | T1552.007 |
| P1 | The same with verb `get` — one named object | Kubernetes audit | T1552.007 |
| P1 | Ten or more `403` denials on `secrets` for one principal in 15 minutes | Kubernetes audit | T1552.007 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `responseStatus.code` 401 on `secrets` — authentication failed, a different incident | Kubernetes audit | T1552.007 |
| P3 | A single `403` denial — RBAC working | Kubernetes audit | T1552.007 |

### Detection Rule Quality Notes

The source rule sees only failures, filters out every workload, and compares an integer to a
string.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `NOT user.username:system` | A pod authenticates as `system:serviceaccount:<ns>:<name>`, so this bare substring drops **every workload in the cluster** — a compromised pod reading secrets is excluded by the rule meant to catch it. The intent was to drop control-plane chatter | Allowlist by **exact ServiceAccount name**, never by the substring `system`. The shipped rule's `known_readers` block is that allowlist |
| `responseStatus.code:"403"` — quoted | The field is **`int32`**. A quoted comparison is backend-dependent and may silently never match | Unquoted integer comparison |
| Matches only `403` | A principal that should not have had the permission but **did** returns `200`. The rule sees every failure and is blind to every success — and the success is the incident | Separate rules for denied and succeeded, with the succeeded one gated on a reader allowlist |
| No stage filter | Every policy rule except `serviceaccounts/token` omits `RequestReceived`, but a `watch` also emits `ResponseStarted`, so long-running requests double-count in any volume rule | Pin `stage: ResponseComplete` |
| Treats `get`, `list` and `watch` alike | `objectRef.name` is **absent on `list`/`watch`**, and that request returned *every* secret in the namespace. Ranking a named `get` above a nameless `list` inverts the severity | `list`/`watch` scored as whole-namespace and ranked **above** `get` |
| Threshold of 2 in 15 minutes | Two denials is a misconfigured client's first retry. It is a floor for noise, not a signal for enumeration | Ten in fifteen minutes, with the tuning basis stated |

**Recommended detection — secret read denied by RBAC.**

```yaml
# Unauthorized Secret Access Attempt (T1552.007 — Container API Credentials)
#
# Source rule:
#   objectRef.resource:"secrets" AND verb:("list" OR "watch" OR "get")
#   AND NOT user.username:system AND responseStatus.code:"403"
#
# Three defects, and the third is the one that matters most.
#
# 1. responseStatus.code IS int32. The source quotes it. A quoted comparison against an
#    integer field is backend-dependent and may silently never match. Do not quote it.
# 2. `NOT user.username:system` is a bare substring exclusion. It drops every
#    `system:serviceaccount:<ns>:<name>` principal — which is EVERY WORKLOAD IN THE
#    CLUSTER — so a compromised pod reading secrets is excluded by the rule that exists to
#    catch it. The intent was to drop control-plane chatter; the effect is to drop the
#    attacker.
# 3. IT ONLY MATCHES 403. A principal that SHOULD NOT have had the permission but DID gets
#    200, and 200 is the worst outcome. The rule sees the failures and is blind to the
#    successes. `annotations."authorization.k8s.io/decision"` carries the authoritative
#    allow/forbid independent of the HTTP code and is the better discriminator.
#
# One thing the source got right and this file keeps: 403 IS the correct denial code here.
# 403 = authenticated and RBAC refused. 401 = authentication failed, a different incident.
# AWS's own published example query for this uses "401" and is wrong on both counts.
title: Secret read denied by RBAC
id: 3a7f2e94-51cb-4d08-b6e7-9c0a48f31d52
name: eks_secret_read_denied
status: experimental
description: >-
  A principal was refused a read of Kubernetes secrets by RBAC. Denials are enumeration:
  the actor is mapping what its credentials reach.
references:
  - https://attack.mitre.org/techniques/T1552/007/                      # retrieved 2026-08-30
  - https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/  # retrieved 2026-08-30
tags:
  - attack.credential-access
  - attack.t1552.007
logsource:
  category: application
  product: kubernetes
  service: audit
detection:
  # B4 confirmed: resource, verb and stage all co-occur on a single audit Event.
  selection:
    objectRef.resource: 'secrets'
    verb:
      - 'get'
      - 'list'
      - 'watch'
  # Every policy rule except serviceaccounts/token omits RequestReceived, so the normal
  # event is ResponseComplete. Pinning it also stops watch requests double-counting via
  # ResponseStarted.
  completed:
    stage: 'ResponseComplete'
  # int32, unquoted. 403 = authenticated, RBAC refused.
  refused:
    responseStatus.code: 403
  condition: selection and completed and refused
falsepositives:
  - A newly deployed workload whose RoleBinding has not landed yet. It appears as a burst
    from one ServiceAccount and stops; a persistent pattern does not.
level: medium
---
# The case the source rule cannot see, and the more serious one. A read that SUCCEEDED for
# a principal that should not have had the permission returns 200, not 403 — and the
# authoritative record of the authorisation decision is the annotation, not the HTTP code.
title: Secret read succeeded
id: c48d1b60-9e35-4f72-a1d3-7b8e50c2af16
name: eks_secret_read_succeeded
status: experimental
description: >-
  A principal successfully read Kubernetes secrets. Baseline which identities legitimately
  do this; anything outside that set holds credentials it should not.
references:
  - https://attack.mitre.org/techniques/T1552/007/                      # retrieved 2026-08-30
tags:
  - attack.credential-access
  - attack.t1552.007
logsource:
  category: application
  product: kubernetes
  service: audit
detection:
  # B4 confirmed: resource and verb co-occur on every audit Event.
  selection:
    objectRef.resource: 'secrets'
    verb:
      - 'get'
      - 'list'
      - 'watch'
  completed:
    stage: 'ResponseComplete'
  succeeded:
    responseStatus.code:
      - 200
      - 201
  # DEPLOYMENT PARAMETER — populate before use. Exclude the controllers that legitimately
  # read secrets in your cluster, by exact ServiceAccount name. Do NOT exclude on the bare
  # substring "system": that drops every system:serviceaccount principal, i.e. every
  # workload, which is the source rule's defect.
  known_readers:
    user.username:
      - 'system:kube-controller-manager'
      - 'system:serviceaccount:kube-system:generic-garbage-collector'
      - 'system:serviceaccount:kube-system:namespace-controller'
  condition: selection and completed and succeeded and not known_readers
falsepositives:
  - Any operator or controller that reads secrets by design — cert-manager, external-secrets,
    a CSI driver. Enumerate them in `known_readers` by exact name; the allowlist is the rule.
level: high
---
# Enumeration is a rate, not an event. A principal collecting denials across secrets is
# mapping its permission boundary, and that is compromise-adjacent even though nothing
# succeeded.
#
# Threshold basis, stated rather than invented: a workload with a missing RoleBinding
# retries on its client's backoff and converges on one resource. An actor enumerating moves
# across namespaces and resources. Ten denials in fifteen minutes from one principal is
# above a single misconfigured client's retry and below a busy cluster's rollout noise.
# Baseline against your own cluster before deploying.
title: Repeated secret-read denials for one principal
id: 7e51c8d3-2a46-4b9f-8035-e6c179ba4d08
status: experimental
description: >-
  One principal was refused ten or more secret reads in fifteen minutes — permission-boundary
  enumeration rather than a misconfigured client.
references:
  - https://attack.mitre.org/techniques/T1552/007/                      # retrieved 2026-08-30
tags:
  - attack.credential-access
  - attack.discovery
  - attack.t1552.007
correlation:
  type: event_count
  rules:
    - eks_secret_read_denied
  group-by:
    - user.username
  timespan: 15m
  condition:
    gt: 9
level: high
```

Reproduced byte-for-byte from the first rule document of `detections/sigma_t1552_007.yml`.
Two further documents ship in that file: the **succeeded** case gated on a reader allowlist
(`high` — the case the source rule cannot see), and a denial-burst correlation (`high`).
**Deploy the file, not this excerpt** — and populate `known_readers` before deploying, or
the `high` rule fires on every controller in the cluster.

**What these rules structurally cannot do.** They cannot tell you **which** secrets were
read on a `list`, because the event names none — and they can never tell you the values,
because `secrets` are recorded at `Metadata` level and AWS owns the policy. Full reasoning
in `detections/detection_note_t1552_007.md`.

---

### Key Investigation Queries

> These run against the **Kubernetes audit log** in CloudWatch Logs at `/aws/eks/<cluster>/cluster`, not CloudTrail. If audit logging was not enabled, none of this exists — see `../eks.stealth.user-deleted-log-events/`.

#### Query 1 — Reconstruct: who touched secrets, how widely, and with what outcome

```bash
REGION="us-east-1"; CLUSTER="<cluster-name>"
LG="/aws/eks/${CLUSTER}/cluster"
SINCE_MS=$(( ( $(date +%s) - 86400 ) * 1000 ))

aws logs filter-log-events --log-group-name "$LG" --region "$REGION" \
  --start-time "$SINCE_MS" \
  --filter-pattern '{ $.objectRef.resource = "secrets" }' \
  --output json > /tmp/eks-secrets.json

# responseStatus.code is int32 — compare numerically. sourceIPs is an ARRAY and the CLIENT
# is the FIRST element (the last is the proxy). objectRef.name is ABSENT on list/watch.
jq -r '.events[].message | fromjson |
  select(.stage == "ResponseComplete") |
  {time: .requestReceivedTimestamp,
   user: .user.username,
   kind: (if (.user.username | startswith("system:serviceaccount:")) then "workload"
          elif (.user.username | test(":assumed-role/|^arn:aws:")) then "iam"
          else "other" end),
   groups: (.user.groups // []),
   client: (.sourceIPs // [] | first),
   verb: .verb,
   ns: .objectRef.namespace,
   object: (.objectRef.name // null),
   scope: (if .verb == "get" then "one-object" else "WHOLE-NAMESPACE" end),
   code: .responseStatus.code,
   decision: (.annotations["authorization.k8s.io/decision"] // "unrecorded"),
   outcome: (if (.responseStatus.code | tostring | test("^(200|201)$")) then "SUCCEEDED"
             elif .responseStatus.code == 403 then "rbac-denied"
             elif .responseStatus.code == 401 then "auth-failed"
             else "other" end)}' /tmp/eks-secrets.json | jq -s 'sort_by(.time)'
```

Read `outcome` first and `scope` second. **`SUCCEEDED` with `scope: "WHOLE-NAMESPACE"` is
the worst row on the page** — a single `list` returned every secret in that namespace while
naming none of them, so `object: null` there means *wider*, not narrower. `rbac-denied` rows
are enumeration; count them per `user`. `auth-failed` is a different incident — the identity
could not be mapped at all, so look at access entries and `aws-auth` rather than at RBAC.
Where `decision` and `code` disagree, the annotation is authoritative. Record `user`,
`kind`, `ns` and the earliest `time`.

#### Query 2 — Resolve the principal to how it was granted, because containment depends on it

```bash
REGION="us-east-1"; CLUSTER="<cluster-name>"; USERNAME="<user-from-Query-1>"

case "$USERNAME" in
  system:serviceaccount:*)
    NS=$(printf '%s' "$USERNAME" | awk -F: '{print $3}')
    SA=$(printf '%s' "$USERNAME" | awk -F: '{print $4}')
    echo "[i] Workload principal: ServiceAccount $SA in namespace $NS"
    echo "[i] Kubernetes side — find what grants it:"
    echo "    kubectl get rolebindings,clusterrolebindings -A -o json | jq '.items[] | select(.subjects[]? | .kind==\"ServiceAccount\" and .name==\"'$SA'\" and .namespace==\"'$NS'\")'"
    echo "[i] AWS side — does it also hold an AWS identity?"
    aws eks list-pod-identity-associations --cluster-name "$CLUSTER" --namespace "$NS" \
      --service-account "$SA" --region "$REGION" --output json 2>/dev/null \
      | jq -r '.associations[]? | "[!] Pod Identity: \(.associationArn) -> check the IAM role"' \
      || echo "[i] No Pod Identity association (or the call failed — check permissions)"
    echo "[i] IRSA is an annotation, not an API — check it too:"
    echo "    kubectl get sa $SA -n $NS -o jsonpath='{.metadata.annotations.eks\\.amazonaws\\.com/role-arn}'"
    ;;
  arn:aws:*|*assumed-role*)
    echo "[i] IAM principal. Check both grant paths — a cluster may use either or both:"
    aws eks list-access-entries --cluster-name "$CLUSTER" --region "$REGION" --output json 2>/dev/null \
      | jq -r '.accessEntries[]?' || echo "[!] list-access-entries failed — INCONCLUSIVE"
    echo "    kubectl get configmap aws-auth -n kube-system -o yaml"
    ;;
  *)
    echo "[i] $USERNAME is neither a ServiceAccount nor an IAM ARN — an OIDC or"
    echo "    certificate identity. Resolve it manually before containing."
    ;;
esac
```

This is not optional detail. **A workload principal and an IAM principal share no
containment step**, and doing one plane without the other is not containment — the AWS half
alone leaves the Kubernetes grant standing, the Kubernetes half alone leaves the credential
live.

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

Establish the identity class from Query 2 first. Then close **both** planes if the principal
has both.

> Run under the **break-glass responder credentials** from §1. `kubectl` steps need a
> break-glass kubeconfig whose own access entry is not the one being revoked.

#### Step 1 — Revoke the Kubernetes grant

```bash
CLUSTER="<cluster-name>"; REGION="us-east-1"
USERNAME="<user-from-Query-1>"

case "$USERNAME" in
  system:serviceaccount:*)
    NS=$(printf '%s' "$USERNAME" | awk -F: '{print $3}')
    SA=$(printf '%s' "$USERNAME" | awk -F: '{print $4}')
    echo "[i] Delete the RoleBinding/ClusterRoleBinding that grants secret access to $SA in $NS."
    echo "[!] Removing the binding stops AUTHORISATION immediately, but a projected token"
    echo "    already issued to a running pod stays valid for its lifetime. Only deleting the"
    echo "    ServiceAccount object invalidates an issued token — and that breaks the workload."
    echo "    Decide deliberately; do not assume the binding removal was sufficient."
    ;;
  *)
    PRINCIPAL="<principal-arn>"
    aws eks delete-access-entry --cluster-name "$CLUSTER" --principal-arn "$PRINCIPAL" \
      --region "$REGION" && echo "[OK] Deleted access entry for $PRINCIPAL" \
      || echo "[i] No access entry — the grant may be in kube-system/aws-auth; edit that instead"
    ;;
esac
```

#### Step 2 — Revoke the AWS side, if the principal has one

```bash
SUSPECT_ARN="<principal-arn-or-role-behind-the-serviceaccount>"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REVOKE='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$NOW"'"}}}]}'

if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')        # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document "$REVOKE" && echo "[OK] Revoked pre-existing sessions for role $R"
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')       # user ARN: name = LAST segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive \
      && echo "[OK] Disabled key $K for $U"
  done
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — contain manually"
fi
```

> `aws:TokenIssueTime` denies only tokens issued **before** the cutoff. A credential
> re-fetched afterwards is not denied — so this must follow Step 1, not precede it.

---

## 4. Eradication

### Remove Attacker Access

- **Rotate every secret in every namespace the principal could reach.** The audit log records
  that secrets were read, never *which values*, and on a `list` it does not even name the
  objects. There is no way to narrow this from the log — the blast radius is the namespace
- **Follow each secret to what it authenticates.** A Kubernetes secret holding a database
  password, an API token or a cloud credential extends the incident past the cluster
- **Audit the RBAC that permitted it.** If the read succeeded, a binding allowed it; find it
  and decide whether it should exist
- **If the principal was a workload**, treat the pod as compromised, not just the
  ServiceAccount — check its image, its command, and whether it reached the Pod Identity
  endpoint at `169.254.170.23` for AWS credentials
- **Remove the emergency deny policy** once rotation is complete

---

## 5. Recovery

### Restore Clean State

#### Verify the grant is gone and no further reads succeed

```bash
REGION="us-east-1"; CLUSTER="<cluster-name>"; LG="/aws/eks/${CLUSTER}/cluster"
USERNAME="<user-from-Query-1>"
SINCE_MS=$(( ( $(date +%s) - 900 ) * 1000 ))

RAW=$(aws logs filter-log-events --log-group-name "$LG" --region "$REGION" \
        --start-time "$SINCE_MS" \
        --filter-pattern '{ $.objectRef.resource = "secrets" }' --output json 2>/dev/null)

if [ -z "$RAW" ]; then
  echo "[!] filter-log-events returned nothing — API error, missing permission, or audit"
  echo "    logging is off. INCONCLUSIVE, not clean."
else
  N=$(printf '%s' "$RAW" | jq --arg u "$USERNAME" '[.events[].message | fromjson
        | select(.stage == "ResponseComplete")
        | select(.user.username == $u)
        | select(.responseStatus.code == 200 or .responseStatus.code == 201)] | length')
  [ "${N:-1}" -eq 0 ] \
    && echo "[OK] No successful secret read by $USERNAME in the last 15 minutes" \
    || echo "[FAIL] $N successful secret read(s) by $USERNAME since containment"
fi
```

> A zero here proves the grant is gone **only if audit logging is on**. If it is not, this
> block reports `[!] INCONCLUSIVE` rather than clean — an absent log is not an absent attack.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     objectRef.resource secrets, verb list, stage ResponseComplete,"
echo "                  responseStatus.code 200 (UNQUOTED int), user not in known_readers"
echo "                  -> eks_secret_read_succeeded, level high"
echo "MUST fire on:     the same with code 403 -> eks_secret_read_denied, and ten of them"
echo "                  in 15 minutes from one principal -> the correlation, level high"
echo "MUST NOT fire on: a principal listed in known_readers — populate that block first, or"
echo "                  the high rule fires on every controller in the cluster"
echo "MUST NOT fire on: code 401. That is authentication failure, a different incident, and"
echo "                  it is what AWS's own published example query wrongly matches."
echo "CHECK, by design: a system:serviceaccount principal MUST still match. The source rule"
echo "                  excluded them all with NOT user.username:system — verify yours does not."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal read secrets it should not have | RBAC granted `get`/`list` on `secrets` more broadly than the workload required |
| A successful read raised nothing | The deployed rule matched only `403`, so it saw failures and was blind to successes |
| A compromised workload would have been excluded outright | `NOT user.username:system` dropped every `system:serviceaccount:` principal — every pod in the cluster |
| The scope of exposure could not be narrowed | `secrets` are recorded at `Metadata` level and a `list` names no object, so the blast radius is the whole namespace by construction |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Reserve cluster-access grants to the platform pipeline. This is the AWS half only —
// aws-auth and RBAC are Kubernetes objects and no SCP reaches them.
{
  "Effect": "Deny",
  "Action": ["eks:CreateAccessEntry", "eks:AssociateAccessPolicy", "eks:CreatePodIdentityAssociation"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/platform-pipeline" }
  }
}
```

> The condition value carries a wildcard, so it needs `ArnNotLike`. Under `StringNotEquals`
> the wildcard is not expanded, the condition matches every request, and the `Deny` denies
> everything — an outage rather than a bypass. And note the ceiling: **an SCP cannot
> constrain RBAC**, which lives entirely inside the cluster.

- **Prefer external secret storage** — Secrets Manager or SSM Parameter Store via a CSI
  driver — so a Kubernetes secret read yields a reference rather than a credential
- **Enable encryption at rest for Kubernetes secrets with a KMS key**, so etcd access alone
  is insufficient
- **Baseline and review which ServiceAccounts hold `get`/`list` on secrets.** The `high`
  rule is an allowlist; keeping it accurate is the control

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1552.007 — Unsecured Credentials: Container API Credentials |
| MITRE tactic | Credential Access (TA0006) |
| Primary API | Kubernetes `GET`/`LIST`/`WATCH` on `secrets`. No AWS API is involved |
| Event source | Kubernetes audit log via EKS control-plane logging → CloudWatch Logs `/aws/eks/<cluster>/cluster`. **Off by default** |
| Key discriminator | `responseStatus.code` (**`int32`, unquoted**) plus whether the principal is on the reader allowlist. `403` = RBAC refused, `401` = authentication failed, `200`/`201` = it worked |
| Scope trap | `objectRef.name` is **absent on `list`/`watch`** — that request returned every secret in the namespace while naming none. An absent name is **wider**, not narrower |
| Recording limit | `secrets` are `Metadata` level. The **value is never logged** and no customer configuration changes it — AWS owns the audit policy on a managed control plane |
| Field-shape traps | `sourceIPs` is an **array**, client first, proxy last; there is no `sourceIPAddresses`. `user.groups` is an array. `objectRef.apiGroup` is `""` for the core group. Pin `stage: ResponseComplete` or `watch` double-counts |
| Containment | Two planes. IAM principal → `delete-access-entry` (AWS) or `aws-auth` edit (Kubernetes). Workload → delete the RoleBinding (Kubernetes) **and** the Pod Identity association or OIDC trust (AWS). Either half alone is not containment |
| Token persistence | Removing a RoleBinding stops authorisation immediately, but an **already-issued projected token stays valid for its lifetime** unless the ServiceAccount object is deleted |

### Residual Risk

**You cannot know which secrets were read.** The audit log records `secrets` at `Metadata`
level, and a `list` names no object at all. Every secret in the namespace must be treated as
disclosed, and there is no configuration that would have made this narrower.

**Rotation extends past the cluster.** A Kubernetes secret holding a database password or a
cloud credential means the incident continues wherever that credential is honoured, and
nothing in the cluster tells you where that is.

**An already-issued ServiceAccount token outlives the binding you removed.** Unless the
ServiceAccount object itself was deleted, a running pod keeps a valid token for its
lifetime. Removing the RoleBinding stops new authorisations, not the credential.

**An SCP cannot reach RBAC.** The guardrail above constrains the AWS grant paths only.
Anyone with the Kubernetes permission to create bindings can re-grant secret access without
touching AWS at all, and no AWS-side control prevents it.
