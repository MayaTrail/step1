# IR Playbook: Kubernetes Events Deleted on EKS — a rule that cannot fire, and `UpdateClusterConfig` as what is observable instead

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment (cluster audit evidence removed or suppressed) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High.** Nothing is exposed by the act; everything done afterwards is unobservable, and the gap is unrecoverable. The urgency is a function of elapsed time rather than of the call. The deployed rule rates it P1 and has never been able to fire |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | EKS, CloudWatch Logs, CloudTrail, IAM, Kubernetes RBAC |

**What the technique does:** an actor removes evidence of their activity on an EKS cluster. The
source rule assumes they do it by deleting Kubernetes Events — and on EKS that act leaves
no trace to detect. EKS runs a **managed control plane**, so the audit policy is a
`kube-apiserver` flag AWS controls and customers cannot modify or read through any EKS API.
In AWS's published policy, core `events` — any verb, any user — is level **`None`**, and
rules are first-match-wins. Level `None` means the request is not logged at all. What
*does* leave a trace is the AWS-plane work: `UpdateClusterConfig` disabling control-plane
log types, or deleting the `/aws/eks/<cluster>/cluster` CloudWatch log group, or cutting
its retention. Those are CloudTrail management events and they survive.

**Detection thesis.** The signal is the **AWS-plane call**, because the Kubernetes-plane act
is unlogged by policy. The source rule watches for something the platform never writes, and
its silence has always meant "the audit policy suppresses this", not "nobody did it".

---

## 1. Preparation

**Logging & Visibility**
- **All five EKS control-plane log types are off by default** — `api`, `audit`,
  `authenticator`, `controllerManager`, `scheduler`. Enable at minimum `audit` and
  `authenticator`; without them there is no Kubernetes-plane telemetry of any kind
- Control-plane logs land in CloudWatch Logs at **`/aws/eks/<cluster-name>/cluster`**.
  That log group is the single point of failure and is not protected by the cluster's own
  configuration
- CloudTrail management events for `eks.amazonaws.com` `UpdateClusterConfig` and for
  `logs.amazonaws.com` `DeleteLogGroup` / `PutRetentionPolicy` / `DeleteRetentionPolicy`
- **A recorded baseline of each cluster's enabled log types and its log group's retention.**
  `UpdateClusterConfig` reports the new state, not the old one
- **Know what the audit policy does not record**, because it bounds every investigation here:
  core `events` are level `None`; `secrets` and `configmaps` are `Metadata` (never the value
  or body); a `list`/`watch` carries **no `objectRef.name`**

**Alerting (must be pre-configured)**
- **`UpdateClusterConfig` disabling any control-plane log type → P0**
- **`DeleteLogGroup` on a `/aws/eks/` log group → P0**
- **`PutRetentionPolicy` reducing a `/aws/eks/` log group to one day → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- CloudWatch Logs Insights access for the log group named in **Logging & Visibility**, and the patience for `start-query` to settle before reading results.
- A host **outside** the VPC from which to verify reachability. Testing from inside exercises a different path and proves nothing.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- Which principals and automation roles touch this service at all. In most estates the list is short, which makes an unfamiliar caller a finding before any threshold is evaluated.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `UpdateClusterConfig` with `clusterLogging` containing `"enabled":false` | CloudTrail (management) | T1685.002 |
| P0 | `DeleteLogGroup` where `logGroupName` starts `/aws/eks/` | CloudTrail (management) | T1685.002 |
| P1 | `PutRetentionPolicy` cutting a `/aws/eks/` group to ≤1 day | CloudTrail (management) | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A Role or ClusterRole granting `delete` on core `events` created or modified | Kubernetes audit | T1685.002 |
| P3 | No audit records from a cluster in a window — corroborating only | CloudWatch Logs | T1685.002 |

### Detection Rule Quality Notes

The source rule matches a request that EKS's audit policy does not write.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Matches `verb:"delete" AND objectRef.resource:"events"` on the Kubernetes audit log | **It cannot fire on EKS.** AWS's managed audit policy sets core `events` to level `None` for every verb and every user, first-match-wins, and `None` means not logged. The rule has matched nothing since deployment and its silence reads as safety | Detect the **AWS-plane** acts that survive: log types disabled, log group deleted, retention cut. Keep the nearest in-cluster signal — the RBAC grant permitting event deletion — as a `medium` precursor |
| `group_by: []` | No grouping, so one change touching several clusters produces ungroupable alerts with no acting principal attached | Group by the acting principal; the CloudTrail rules carry `userIdentity.arn` |
| Assumes the Kubernetes plane is where evidence removal is visible | On a managed control plane the customer does not own the audit policy. Anything the policy sets to `None` is undetectable by construction, and there is no configuration change that fixes it | Say so explicitly, and move detection to the plane the customer does control |

**Recommended detection — control-plane logging disabled.**

```yaml
# Kubernetes Events Deleted (T1685.002 — Disable or Modify Cloud Log)
#
# THE SOURCE RULE CANNOT FIRE ON EKS. It matches
#   verb:"delete" AND objectRef.resource:"events"
# against the Kubernetes audit log. EKS runs a MANAGED control plane, so the audit policy is
# a kube-apiserver flag AWS controls and customers cannot modify or read through any EKS API.
# In AWS's published policy, core `events` — any verb, any user — is level `None`. Level None
# means the request is NOT LOGGED AT ALL. Deleting Kubernetes Events on an EKS cluster
# produces no audit record, so this rule has matched nothing since the day it was deployed
# and its silence is indistinguishable from nobody deleting anything.
#
# There is no fix inside the audit log. The rules below detect the two things that ARE
# observable and that an actor clearing traces has to touch:
#   1. Deletion of the CloudWatch log group that holds the audit stream — CloudTrail.
#   2. Disabling control-plane log types on the cluster — CloudTrail.
# Both survive, because both are AWS-plane calls rather than Kubernetes-plane ones.
title: EKS control-plane logging disabled
id: 8c1e47b2-06fa-4d59-b3e8-72905c1fa4d6
name: eks_control_plane_logging_disabled
status: experimental
description: >-
  UpdateClusterConfig turned off one or more EKS control-plane log types. The audit and
  authenticator streams stop; the cluster keeps running and the gap is unrecoverable.
references:
  - https://attack.mitre.org/techniques/T1685/002/                            # retrieved 2026-08-30
  - https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html  # retrieved 2026-08-30
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'eks.amazonaws.com'
    eventName: 'UpdateClusterConfig'
  # The five types are api, audit, authenticator, controllerManager, scheduler. A disable
  # sends enabled:false for one or more of them; the event name alone cannot tell a disable
  # from an enable, so the parameter is the discriminator (D-a).
  disabling:
    requestParameters.logging.clusterLogging|contains: '"enabled":false'
  success:
    errorCode: null
  condition: selection and disabling and success
falsepositives:
  - Cost-driven reduction of log types in a non-production cluster. Legitimate and should be
    a named, scheduled change; an ad-hoc disable on a production cluster is the finding.
level: high
---
# The other way the audit trail stops, and it touches no EKS API at all. The audit stream is
# delivered to a CloudWatch log group named /aws/eks/<cluster>/cluster. Deleting that group,
# or shortening its retention, removes the records with the cluster's logging configuration
# still reading as fully enabled.
title: EKS audit log group deleted or retention shortened
id: 4f0b93d5-8e21-4a67-95c3-1d68e0b7fa29
name: eks_audit_log_group_tampered
status: experimental
description: >-
  The CloudWatch log group carrying an EKS cluster's control-plane logs was deleted, or its
  retention reduced. The cluster's own logging configuration is untouched and still reports
  as enabled.
references:
  - https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html  # retrieved 2026-08-30
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'logs.amazonaws.com'
    eventName:
      - 'DeleteLogGroup'
      - 'PutRetentionPolicy'
      - 'DeleteRetentionPolicy'
  # EKS control-plane logs always land under this prefix, which scopes the otherwise very
  # noisy generic CloudWatch Logs calls to this technique.
  eks_log_group:
    requestParameters.logGroupName|startswith: '/aws/eks/'
  success:
    errorCode: null
  condition: selection and eks_log_group and success
falsepositives:
  - Log-group lifecycle managed by IaC when a cluster is decommissioned. Correlate with the
    cluster's own deletion in the same window; a deletion that stands alone is the finding.
level: high
---
# What remains available INSIDE the audit log once the above is understood. Kubernetes
# Events are unlogged, but the RBAC changes an actor needs in order to be able to delete
# them are logged at RequestResponse — the policy's rbac.authorization.k8s.io rules carry
# full request and response bodies. This is the nearest in-cluster signal and it is a
# precursor rather than the act itself. Deliberately `medium`: it is one step removed.
title: RBAC grant covering Kubernetes events
id: b95a2c07-fd34-41e8-8a06-3f7c15e9d842
status: experimental
description: >-
  A Role or ClusterRole granting delete on core events was created or modified. Deleting
  events is itself unlogged on EKS, so the grant that permits it is the closest observable.
references:
  - https://attack.mitre.org/techniques/T1685/002/                            # retrieved 2026-08-30
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  category: application
  product: kubernetes
  service: audit
detection:
  # B4 confirmed: objectRef.apiGroup and verb DO co-occur on a single audit Event — every
  # event carries both. ANDing them here is correct.
  selection:
    objectRef.apiGroup: 'rbac.authorization.k8s.io'
    verb:
      - 'create'
      - 'update'
      - 'patch'
  # These rules are logged at RequestResponse, so the rule body is in requestObject.
  events_rule:
    requestObject|contains: 'events'
  delete_verb:
    requestObject|contains: 'delete'
  # 200 and 201 both mean it worked; responseStatus.code is int32, so do not quote it.
  applied:
    responseStatus.code:
      - 200
      - 201
  condition: selection and events_rule and delete_verb and applied
falsepositives:
  - Any controller or operator legitimately granted event cleanup — several ship with it.
    Baseline the grants that exist before deploying, and alert on additions.
level: medium
```

Reproduced byte-for-byte from the first rule document of `detections/sigma_t1685_002.yml`.
Two further documents ship in that file: audit log group deleted or retention shortened
(`high`, CloudTrail), and the RBAC-grant precursor (`medium`, Kubernetes audit). **A file
carrying both logsources is the shape of this service, not an inconsistency.** Deploy the
file, not this excerpt.

**What these rules structurally cannot do.** They cannot detect the deletion of Kubernetes
Events, because it is not recorded — no rule can, on EKS, and no configuration change
enables it. They detect the AWS-plane acts that accompany trace removal, and the RBAC grant
that permits the in-cluster one. Full reasoning in
`detections/detection_note_t1685_002.md`.

---

### Key Investigation Queries

> These run against **CloudTrail**, deliberately. EKS control-plane logs are regional and land in CloudWatch Logs at `/aws/eks/<cluster>/cluster`; the Kubernetes audit log cannot answer this question at all.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: who changed logging, on which cluster, and to what

```bash
REGION="us-east-1"

for EV in UpdateClusterConfig DeleteLogGroup PutRetentionPolicy DeleteRetentionPolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "eks.amazonaws.com" or .eventSource == "logs.amazonaws.com") |
    (.userIdentity.arn // "") as $arn | ($arn | split("/")) as $p |
    # assumed-role ARN: role name is the 2nd "/" segment, the LAST is the SESSION name.
    {time: .eventTime,
     event: .eventName,
     caller_arn: $arn,
     caller: (if ($arn | test(":assumed-role/")) then $p[1] else $p[-1] end),
     access_key: .userIdentity.accessKeyId,
     cluster: (.requestParameters.name // .requestParameters.clusterName),
     log_group: .requestParameters.logGroupName,
     retention: .requestParameters.retentionInDays,
     logging: (.requestParameters.logging.clusterLogging // []),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time) | map(select(
     (.log_group // "" | startswith("/aws/eks/")) or (.logging | length > 0)))'
```

A `DeleteLogGroup` on a `/aws/eks/` group is the unambiguous case, and note what it does
*not* touch: the cluster's own logging configuration still reports every type as enabled.
On `UpdateClusterConfig`, read the `logging` array — each entry carries `types` and
`enabled`, and an entry with `enabled: false` is the disable. A `retention` of `1` is the
quiet variant: records still arrive and expire before anyone reads them. Record
`caller_arn`, `access_key`, `cluster` and the `time`; the window from that timestamp to now
is the gap.

#### Query 2 — Establish the current state and the size of the gap

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"
LG="/aws/eks/${CLUSTER}/cluster"

CFG=$(aws eks describe-cluster --name "$CLUSTER" --region "$REGION" \
        --query 'cluster.logging.clusterLogging' --output json 2>/dev/null)
if [ -z "$CFG" ]; then
  echo "[!] describe-cluster returned nothing — wrong Region, wrong name, or missing"
  echo "    eks:DescribeCluster. INCONCLUSIVE, not clean."
else
  printf '%s' "$CFG" | jq -r '.[] | select(.enabled == true) | "[i] enabled: \(.types | join(", "))"'
  printf '%s' "$CFG" | jq -e 'any(.[]; .enabled == true and (.types | index("audit")))' >/dev/null 2>&1 \
    && echo "[OK] audit logging is enabled on $CLUSTER" \
    || echo "[FAIL] audit logging is NOT enabled on $CLUSTER"
fi

# The configuration reading as enabled proves nothing if the destination is gone.
DESC=$(aws logs describe-log-groups --log-group-name-prefix "$LG" \
         --region "$REGION" --output json 2>/dev/null)
if [ -z "$DESC" ]; then
  echo "[!] describe-log-groups returned nothing — INCONCLUSIVE, not clean."
else
  N=$(printf '%s' "$DESC" | jq '.logGroups | length')
  if [ "${N:-0}" -eq 0 ]; then
    echo "[FAIL] $LG does not exist — the cluster is configured to log to a group that is gone"
  else
    printf '%s' "$DESC" | jq -r '.logGroups[] | "[i] \(.logGroupName) retention=\(.retentionInDays // "never-expire") stored=\(.storedBytes)B"'
  fi
fi
```

A cluster whose configuration reads as fully enabled while the log group is absent is the
most dangerous state here — every check that asks "is logging on" answers yes. `storedBytes`
against the gap window is the size of what is unrecoverable and belongs in the incident
record.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="DeleteLogGroup DeleteRetentionPolicy PutRetentionPolicy"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "eks.amazonaws.com") |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'group_by(.caller) | map({caller: .[0].caller, calls: length,
                                       events: (map(.event) | unique),
                                       keys: (map(.access_key) | unique),
                                       first: (map(.time) | min), last: (map(.time) | max)})
             | sort_by(-.calls)'
```

The alerting event named one resource; this asks whether the same principal did the same thing
elsewhere, and whether anyone else did it too. Group by caller rather than by resource: the
question the eradication phase needs answered is *how much of this is one actor's work*, and a
per-resource list cannot say. `access_key` is emitted here because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` regardless of whether it happened — see the caveat in the preamble.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-3>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique),
                               errors: (map(.error) | unique),
                               ips: (map(.ip) | unique | .[0:5])})'
```

Keyed on the access key rather than the ARN, because one credential is used across many
sessions and the key is what identifies the credential. The per-service grouping answers the
question this playbook cannot: whether this technique was the objective or one stop on a tour.
A service in that list with no business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID — so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restoring logging is one call and it stops the blindness going forward. It does nothing for
the gap, and it does not tell you what happened during it — CloudTrail does.

> Run under the **break-glass responder credentials** from §1, not under the principal that
> made the change.

#### Step 1 — Restore the log group and the log types

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; LG="/aws/eks/${CLUSTER}/cluster"

# Recreate the destination first. update-cluster-config against a missing log group leaves
# the cluster reporting logging as enabled while delivering nothing.
aws logs create-log-group --log-group-name "$LG" --region "$REGION" 2>/dev/null \
  && echo "[OK] Created $LG" \
  || echo "[i] $LG already exists (or creation failed — check permissions before continuing)"

aws logs put-retention-policy --log-group-name "$LG" --retention-in-days 90 --region "$REGION" \
  && echo "[OK] Retention set to 90 days on $LG"

aws eks update-cluster-config --name "$CLUSTER" --region "$REGION" \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}' \
  && echo "[OK] Requested all five control-plane log types on $CLUSTER (async — verify in §5)"
```

> `update-cluster-config` returns an **update ID** and completes asynchronously. It is a
> request, not a result — do not treat the call's success as proof that logging resumed.
> §5 verifies the applied state.

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller_arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["eks:UpdateClusterConfig","logs:DeleteLogGroup","logs:PutRetentionPolicy","logs:DeleteRetentionPolicy"],"Resource":"*"}]}'

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')       # user ARN: name = LAST segment
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyEksLogging" \
    --policy-document "$DENY" && echo "[OK] Denied further logging changes by user $U"
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')        # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyEksLogging" \
    --policy-document "$DENY" && echo "[OK] Denied further logging changes by role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

> Containing the AWS principal does not touch its **Kubernetes** access. If that principal
> also has an access entry or an `aws-auth` mapping, it can still act inside the cluster —
> see `../eks.privilege-escalation.flow-alert---cluster-admin-access-granted-after-multiple-u/`
> for the two-sided containment this service always needs.

---

## 4. Eradication

### Remove Attacker Access

- **Reconstruct the gap from CloudTrail**, which is unaffected by EKS logging. Use the
  `access_key` from Query 1 to enumerate everything that principal did in the window
- **Check every other cluster** for the same change. An actor disabling logging on one
  rarely stops there
- **Audit RBAC for grants covering `events`** — the third shipped rule's condition. A
  standing grant is what made the in-cluster half possible and it survives the AWS-side fix
- **Right-size the permission.** `eks:UpdateClusterConfig` and `logs:DeleteLogGroup` belong
  to the platform pipeline, not to application teams
- **Remove the emergency deny policy** once the configuration is verified

---

## 5. Recovery

### Restore Clean State

#### Verify logging is applied and delivering

```bash
REGION="us-east-1"; CLUSTER="<cluster-from-Query-1>"; LG="/aws/eks/${CLUSTER}/cluster"

CFG=$(aws eks describe-cluster --name "$CLUSTER" --region "$REGION" \
        --query 'cluster.logging.clusterLogging' --output json 2>/dev/null)
DESC=$(aws logs describe-log-groups --log-group-name-prefix "$LG" --region "$REGION" --output json 2>/dev/null)

if [ -z "$CFG" ] || [ -z "$DESC" ]; then
  echo "[!] Could not read the cluster config or the log group — INCONCLUSIVE, not clean."
else
  AUDIT=$(printf '%s' "$CFG" | jq 'any(.[]; .enabled == true and (.types | index("audit")))')
  GROUPS=$(printf '%s' "$DESC" | jq '.logGroups | length')
  # A configuration reading enabled proves nothing if the destination is missing, so both
  # conditions are required before this reports clean.
  if [ "$AUDIT" = "true" ] && [ "${GROUPS:-0}" -gt 0 ]; then
    echo "[OK] audit logging enabled on $CLUSTER and $LG exists"
  else
    echo "[FAIL] audit_enabled=$AUDIT log_group_present=${GROUPS:-0}"
  fi
fi

# Delivery, not configuration: are records actually arriving since containment?
SINCE_MS=$(( ( $(date +%s) - 900 ) * 1000 ))
EV=$(aws logs filter-log-events --log-group-name "$LG" --start-time "$SINCE_MS" \
       --max-items 1 --region "$REGION" --output json 2>/dev/null)
if [ -z "$EV" ]; then
  echo "[!] filter-log-events returned nothing — API error or no permission. INCONCLUSIVE."
elif [ "$(printf '%s' "$EV" | jq '.events | length')" -gt 0 ]; then
  echo "[OK] Audit records are arriving in $LG within the last 15 minutes"
else
  echo "[FAIL] No records in $LG in the last 15 minutes — configured but not delivering"
fi
```

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     eventSource eks.amazonaws.com, eventName UpdateClusterConfig, no"
echo "                  errorCode, requestParameters.logging.clusterLogging containing"
echo "                  \"enabled\":false  -> eks_control_plane_logging_disabled, level high"
echo "MUST fire on:     DeleteLogGroup where logGroupName starts /aws/eks/ -> level high"
echo "MUST NOT fire on: UpdateClusterConfig that ENABLES log types — the parameter, not the"
echo "                  event name, is the discriminator"
echo "CANNOT fire, by design: any Kubernetes audit event for deleting core events. AWS's"
echo "                  managed audit policy sets that resource to level None. Do not add a"
echo "                  rule for it; it would be the defect this playbook exists to correct."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| Cluster audit evidence was removed or suppressed | `eks:UpdateClusterConfig` and `logs:DeleteLogGroup` available outside the platform pipeline |
| The deployed rule could never have detected it | It watched a Kubernetes resource that AWS's managed audit policy records at level `None`; the policy is not customer-modifiable |
| A deleted log group left the cluster reporting healthy | Nothing reconciled the cluster's logging configuration against the destination's existence |
| The gap is unrecoverable | Control-plane logs have a single destination and no second copy; nothing reconstructs them |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Both planes: the cluster config that stops the stream, and the log group that holds it.
{
  "Effect": "Deny",
  "Action": ["eks:UpdateClusterConfig", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:DeleteRetentionPolicy"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/platform-pipeline" }
  }
}
```

> The condition value carries a wildcard, so it needs `ArnNotLike`. Under `StringNotEquals`
> the wildcard is not expanded, the condition matches every request, and a `Deny` denies
> everything — an outage rather than a bypass.

- **Reconcile each cluster's enabled log types and its log group's existence on a schedule.**
  The two can disagree, and the disagreement is invisible from either side alone
- **Subscribe the audit log group to a second destination** — a subscription filter to a
  security account. A single destination means a single deletion is total
- **Set an explicit retention** and alarm on it changing. A retention cut is quieter than a
  deletion and has the same effect on anyone reading a week later

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log |
| MITRE tactic | Defense Impairment (TA0112). |
| Primary API | `eks:UpdateClusterConfig` · `logs:DeleteLogGroup` · `logs:PutRetentionPolicy` |
| Event source | `eks.amazonaws.com` and `logs.amazonaws.com`, CloudTrail **management** — these survive the Kubernetes audit stream stopping |
| Key discriminator | The **AWS-plane call and its parameters** — `"enabled":false` in `clusterLogging`, a `/aws/eks/` log group deleted, retention cut to 1. Not the Kubernetes act, which is unlogged |
| Structural blind spot | AWS's managed audit policy sets core `events` to level `None` for every verb and user. Deleting Kubernetes Events on EKS produces **no audit record**, and no customer configuration changes that |
| Adjacent policy gaps | `secrets`/`configmaps` are `Metadata` — never the value or body. A `list`/`watch` carries **no `objectRef.name`**, so the highest-impact read names no object. `aws-auth` `create` is body-less while `update`/`patch`/`delete` are `RequestResponse` |
| Field-shape traps | `sourceIPs` is an **array** (no `sourceIPAddresses` exists). `responseStatus.code` is **int32** — do not quote it. `objectRef.apiGroup` is `""` for the core group. Normal stage is `ResponseComplete`; `serviceaccounts/token` appears at **both** stages |
| Blast radius | Nothing exposed by the act. Everything after it unobservable, proportional to elapsed time |

### Residual Risk

**The gap is permanent.** Control-plane logs have one destination and no second copy. For
any window in which logging was off, or the log group absent, there is no record and nothing
reconstructs it.

**The Kubernetes half remains undetectable after every step here.** Restoring logging does
not make event deletion visible — the audit policy still sets that resource to `None`, AWS
owns the policy, and no customer configuration changes it. This playbook detects the AWS-side
work that accompanies trace removal; an actor who only deletes Kubernetes Events, and touches
nothing on the AWS plane, leaves nothing for any rule in this corpus to find.

**A restored configuration is not proof of delivery.** `update-cluster-config` is
asynchronous and returns an update ID, and a cluster can report every log type enabled while
pointing at a log group that no longer exists. Verify records are arriving, not that the
configuration reads correctly.

**Containing the AWS principal leaves its Kubernetes access standing.** If it holds an
access entry or an `aws-auth` mapping, it can still act inside the cluster. Containment here
is two-sided or it is not containment.
