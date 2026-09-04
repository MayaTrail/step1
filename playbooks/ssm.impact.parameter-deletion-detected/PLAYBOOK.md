# IR Playbook: Parameter Deletion Detected — Unrecoverable Destruction via `ssm:DeleteParameter` and `ssm:DeleteParameters`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data destruction (a Parameter Store parameter and every version of it are removed, with no recovery window and no soft delete — the value is gone from AWS permanently) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, and P0 at five or more deletions in five minutes. AWS states plainly that "deleting a parameter removes all versions of it. Once deleted, the parameter and its versions can't be restored" — there is no recovery window, unlike Secrets Manager's 7-to-30-day default. Severity tracks what read the parameter: a feature flag is an inconvenience, a database endpoint or a credential is an outage that surfaces at the next restart rather than immediately. The source rule rates it P3 and fires on every deletion in the account including planned teardowns, which is the combination that gets an unrecoverable-loss alert muted |
| MITRE Tactics | Impact |
| MITRE Techniques | T1485 |
| Services in Scope | Systems Manager (Parameter Store), CloudTrail, IAM, plus every workload that reads the deleted parameters — EC2, ECS, Lambda, launch templates, SSM documents resolving `{{ssm:<name>}}` |

**What the technique does:** the actor calls `DeleteParameter` with one name, or
`DeleteParameters` with up to ten, and Parameter Store removes the parameter along
with its entire version history and any labels attached to it. Nothing is
quarantined, nothing is retained, and `GetParameterHistory` returns nothing
afterwards because the history goes with the parameter. Applications that already
hold the value keep running, so the loss is invisible until something restarts and
fails to resolve its configuration — often hours later, during a deploy that has
nothing to do with the incident. The variant with no principal at all uses
`PutParameter`'s `Expiration` policy instead: Parameter Store performs that
deletion itself at a timestamp the actor chose, and no delete event is produced.

**Detection thesis.** The discriminator is the **principal** and the **count of
names**, not the event: a successful delete by anyone outside the configuration
lifecycle owner, and the size of the `names` array rather than the number of
events, because `DeleteParameters` destroys up to ten parameters per call. The
source rule matches the event name and stops, with no threshold, no success
filter, no principal check and no group-by, so it fires on every planned teardown
and delivers a mass deletion as a page of separate alerts rather than one incident.

---

## 1. Preparation

**Logging & Visibility**

- CloudTrail multi-region trail. AWS states "Systems Manager logs all control
  plane operations to CloudTrail as management events"; the only SSM data events
  are `CreateControlChannel` / `OpenControlChannel` on
  `AWS::SSMMessages::ControlChannel` and `RequestManagedInstanceRoleToken` on
  `AWS::SSM::ManagedNode`. Both delete calls are management events, on by default
- `DeleteParameter` carries `requestParameters.name`; `DeleteParameters` carries
  `requestParameters.names`, an array of up to **10**. Those are different field
  names on different events and never co-occur, so any rule or query covering both
  must read them as alternatives rather than ANDing them
- **`responseElements` presence for `DeleteParameters` is not documented.** The
  API returns `DeletedParameters` and `InvalidParameters`; whether CloudTrail
  records them is unverified. Read them if your trail carries them, and reconcile
  against the live inventory either way
- **A delete aimed at a name that does not exist produces no event.** AWS: "For
  the `DeleteParameter` and `GetParameter` actions, if the specified parameter
  doesn't exist, the `ParameterNotFound` exception is not recorded in AWS
  CloudTrail event logs"
- A **configuration source of truth outside Parameter Store** — the repository,
  the secret's system of record, or a backup. This is the only thing that makes
  recovery possible at all, and it is a prerequisite rather than a nice-to-have
- A **parameter inventory snapshot per path**, taken on a schedule. After a
  deletion, `DescribeParameters` tells you what is there now; only a prior
  snapshot tells you what is missing

**Alerting (must be pre-configured)**

- **A successful `DeleteParameter` or `DeleteParameters` by a principal outside the configuration-lifecycle allowlist → P0**
- **Five or more successful delete calls from one principal within five minutes → P0**
- **A decrypting parameter read followed by a deletion of the same parameter by the same principal within an hour → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | A successful `DeleteParameter` or `DeleteParameters` by a principal outside the configuration-lifecycle allowlist | CloudTrail (management) | T1485 |
| P0 | Five or more successful delete calls from one principal within five minutes — up to fifty parameters | CloudTrail (management) | T1485 |
| P1 | A decrypting parameter read followed by a deletion of the same parameter by the same principal within an hour — collect then destroy | CloudTrail (management) | T1485, T1555.006 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A `PutParameter` carrying an `Expiration` policy — a deletion armed for later that will produce no delete event when it fires | CloudTrail (management) | T1485 |
| P3 | A parameter present in the last inventory snapshot and absent from the current one, with no corresponding delete event | Parameter inventory diff | T1485 |

### Detection Rule Quality Notes

The source rule is an immediate alert on the event name with no threshold, no
group-by, no principal filter and no success filter.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Fires on every deletion in the account | An infrastructure-as-code `destroy` removes an environment's parameters and fires the alert in bulk on planned work, so it is muted inside a week — after which the real deletion is silent | Allowlist the pipeline principal explicitly and alert on everything else |
| No group-by at all | A mass deletion arrives as one alert per event; the responder rebuilds the scope by reading a page of notifications instead of one aggregated finding | Group by `userIdentity.arn` in both the rule and the correlation |
| Counts events, not parameters | `DeleteParameters` takes up to ten names per call, so five events can be fifty destroyed parameters and the alert count understates the loss five-to-one | Expand `requestParameters.names` and count names; set the volume correlation at five **calls** precisely because each is worth ten |
| No success filter | A denied attempt raises the same alert as a completed destruction, and the recovery work-list then names parameters that still exist | `success: {errorCode: null}`, and reconcile against the live inventory rather than trusting the absence of an error |
| Treats "no `errorCode`" as "all names destroyed" | `DeleteParameters`' only documented error is `InternalServerError`; unknown names return in the 200-response `InvalidParameters` array, so a clean event may have destroyed ten, one or none | Reconcile `requestParameters.names` against `DescribeParameters` — absence now is the proof, not the event |
| No read-then-delete correlation | Collect-and-cover — take the value while it is readable, then destroy the parameter and its history — is the pattern with the worst outcome and the rule sees only the second half | `temporal_ordered` correlation from a decrypting read to a deletion by the same principal |

**Recommended detection — an unrecoverable deletion by an unexpected principal.**

```yaml
# Parameter Deletion Detected (T1485)
#
# The original rule is an immediate-type alert on
#   eventSource:"ssm.amazonaws.com" AND (eventName:"deleteparameters" OR eventName:"deleteparameter")
# with no threshold, no window, no group-by and no success filter. It fires on
# every parameter deletion in the account, which means it fires on every
# infrastructure-as-code teardown, and it is muted within a week.
#
# The empty group-by is the second problem: a mass deletion arrives as one alert
# per event rather than one incident, so the responder reconstructs the scope by
# hand from a page of notifications. The rules below group by userIdentity.arn.
#
# Two documented behaviours the rule does not account for:
#
#   * DeleteParameters (plural) takes up to 10 names per call and its ONLY
#     documented error is InternalServerError. Names that do not exist come back
#     in the 200-response InvalidParameters array, so an event with no errorCode
#     may have destroyed anything from ten parameters to none. Counting events
#     is not counting destruction.
#
#   * For DeleteParameter (singular), AWS documents that "if the specified
#     parameter doesn't exist, the ParameterNotFound exception is not recorded in
#     AWS CloudTrail event logs" — so a delete aimed at a name that is not there
#     produces no event at all, and name-probing through the delete API is
#     invisible.
#
# And the deletion this rule can never see: a parameter removed by an Expiration
# parameter policy is deleted by Parameter Store itself, so no principal appears.
# That is armed at PutParameter time — see
# ../../ssm.discovery.excessive-parameter-creation-detected/.
#
# Deletion is terminal. AWS: "Deleting a parameter removes all versions of it.
# Once deleted, the parameter and its versions can't be restored." There is no
# recovery window and no soft delete, unlike Secrets Manager.
title: SSM parameter deleted by a principal outside the owning pipeline
id: 1a383a7e-e82c-47b3-bbbe-5f9d3f833d82
name: ssm_parameter_deleted
status: experimental
description: >-
  A successful DeleteParameter or DeleteParameters by a principal that is not the
  infrastructure pipeline. Deletion removes every version and cannot be undone,
  so this is terminal on one event.
references:
  - https://attack.mitre.org/techniques/T1485/
  - https://docs.aws.amazon.com/systems-manager/latest/userguide/deleting-parameters.html
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DeleteParameters.html
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName:
      - 'DeleteParameter'
      - 'DeleteParameters'
  success:
    errorCode: null
  parameter_owners:                    # tune: principals that own configuration lifecycle
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/ci-cd'
      - ':role/config-admin'
  condition: selection and success and not parameter_owners
falsepositives:
  - An engineer cleaning up their own development path by hand — should be rare, attributable, and confined to non-production prefixes
level: high
---
title: Multiple SSM parameter deletions by one principal in a short window
id: ec482dbf-dffd-4290-a173-982dcce79ac2
status: experimental
description: >-
  Five or more successful delete calls from one principal inside five minutes.
  The threshold is deliberately low: DeleteParameters accepts ten names per call,
  so five events is up to fifty parameters destroyed, and there is no recovery.
references:
  - https://attack.mitre.org/techniques/T1485/
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: event_count
  rules:
    - ssm_parameter_deleted
  group-by:
    - userIdentity.arn
  timespan: 5m
  condition:
    gte: 5
falsepositives:
  - A teardown that the pipeline allowlist did not cover — an environment being decommissioned by hand, which should carry a change record
level: high
---
title: SSM parameter read with decryption then deleted by the same principal
id: 265d3f68-5415-453b-9e66-766db6d0dce8
status: experimental
description: >-
  A decrypting read followed by a deletion from the same principal inside an hour.
  Collect-then-destroy: the value is taken while it is still readable, then the
  parameter and its whole version history are removed so nobody can see what it
  was.
references:
  - https://attack.mitre.org/techniques/T1485/
  - https://attack.mitre.org/techniques/T1555/006/
tags:
  - attack.impact
  - attack.t1485
  - attack.t1555.006
correlation:
  type: temporal_ordered
  rules:
    - ssm_decrypted_read_before_delete
    - ssm_parameter_deleted
  group-by:
    - userIdentity.arn
  timespan: 1h
level: high
---
title: SSM parameter read with decryption
id: e8450df7-f9f9-41a4-9f93-117fcfd6b279
name: ssm_decrypted_read_before_delete
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. A successful
  parameter read that requested decryption. Shipped here so the correlation above
  resolves within this file; the same observable is treated at length in the
  credential-access use case.
references:
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameter.html
tags:
  - attack.credential-access
  - attack.t1555.006
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName:
      - 'GetParameter'
      - 'GetParameters'
      - 'GetParametersByPath'
  decrypt:
    requestParameters.withDecryption: true
  success:
    errorCode: null
  condition: selection and decrypt and success
level: low
```

The rule cannot tell you what was destroyed with certainty, because a successful
`DeleteParameters` may have deleted fewer names than it asked for; Query 2
reconciles the requested list against what still exists, which is the only reliable
scope. It also cannot see two deletions at all: one aimed at a name that does not
exist, which AWS documents as producing no CloudTrail event, and one performed by
Parameter Store itself when an `Expiration` policy fires — that destruction is
armed at `PutParameter` time and is only visible in
`../ssm.discovery.excessive-parameter-creation-detected/`.

---

### Key Investigation Queries

> Parameter Store is **regional** — run these in every Region the account uses.
> Extraction uses `--output json | jq -r '.Events[].CloudTrailEvent | fromjson'`.
> **`lookup-events` returns ≤50 events per page**; paginate on `NextToken` for a
> busy window.

#### Query 1 — Reconstruct: which names were named for deletion, by whom

```bash
REGION="<region>"
START="$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"

for EV in DeleteParameter DeleteParameters; do
  aws cloudtrail lookup-events --region "$REGION" \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$START" --max-results 50 --output json \
  | jq -r '.Events[].CloudTrailEvent | fromjson'
done | jq -s '
  # `name` (singular call) and `names` (plural call) never co-occur — read them
  # as alternatives, and normalise both into one array.
  map({
    time:      .eventTime,
    event:     .eventName,
    caller:    (.userIdentity.arn // "unknown"),
    accessKey: (.userIdentity.accessKeyId // "none"),
    session:   ((.userIdentity.arn // "") | split("/") | last),
    sourceIp:  .sourceIPAddress,
    agent:     .userAgent,
    requestedNames: ([ (.requestParameters.name // .requestParameters.Name // empty) ]
                     + (.requestParameters.names // .requestParameters.Names // [])),
    # Undocumented for DeleteParameters — read if present, never depend on it.
    confirmedDeleted: (.responseElements.deletedParameters // []),
    notDeleted:       (.responseElements.invalidParameters // []),
    error: (.errorCode // "none")
  })
  | group_by(.caller)
  | map({
      caller: .[0].caller,
      calls: length,
      requestedNames: ([.[].requestedNames[]] | unique),
      namesRequested: ([.[].requestedNames[]] | unique | length),
      confirmedDeleted: ([.[].confirmedDeleted[]] | unique),
      accessKey: ([.[].accessKey] | unique),
      sourceIp:  ([.[].sourceIp] | unique),
      errors:    ([.[].error] | unique),
      first: ([.[].time] | min), last: ([.[].time] | max)
    })
  | sort_by(-.namesRequested)'
```

`namesRequested` is the number to escalate on, not `calls` — five calls of the
plural API is up to fifty parameters. `requestedNames` is the reconstruction
work-list and feeds Query 2. `confirmedDeleted` is authoritative when it is
populated and absent otherwise, which is why it is never the only thing read.
`errors` containing only `none` does **not** mean everything named was destroyed;
it means nothing threw. `session` is the last `/` segment of the caller ARN, which
for an EC2 instance-profile session is the instance ID.

#### Query 2 — Reconcile: which of those names are actually gone

```bash
REGION="<region>"
REQUESTED_NAMES="<requested-names-from-Query-1>"    # space-separated
GONE=0; PRESENT=0; UNKNOWN=0

for PNAME in $REQUESTED_NAMES; do
  RAW="$(aws ssm describe-parameters --region "$REGION" --output json \
          --parameter-filters "Key=Name,Values=$PNAME")"
  RC=$?
  if [ "$RC" -ne 0 ] || [ -z "$RAW" ]; then
    UNKNOWN=$((UNKNOWN + 1))
    echo "[!] $PNAME — describe-parameters failed; presence not established"
    continue
  fi
  N="$(printf '%s' "$RAW" | jq '.Parameters | length')"
  if [ "$N" -eq 0 ]; then
    GONE=$((GONE + 1)); echo "[FAIL] $PNAME is GONE — unrecoverable, source the value externally"
  else
    PRESENT=$((PRESENT + 1))
    printf '%s' "$RAW" | jq -r '.Parameters[0]
      | "[OK] \(.Name) still present — version \(.Version), last written by \(.LastModifiedUser)"'
  fi
done

echo "---"
echo "destroyed: $GONE   still present: $PRESENT   unchecked: $UNKNOWN"
if [ "$UNKNOWN" -gt 0 ]; then
  echo "[!] INCONCLUSIVE for $UNKNOWN name(s); the scope is a lower bound, not the answer"
fi
```

This is the only reliable scope. A name that is gone was destroyed and the value
must come from outside AWS. A name still present was **not** destroyed — either it
was returned in `InvalidParameters` because it never existed, or somebody has
recreated it since the deletion, and the `LastModifiedUser` and `Version` in the
output tell you which. A `Version` of 1 on a parameter that was long-lived before
the incident means it was recreated, not spared.

`describe-parameters` returns an empty list as a normal result and a non-zero exit
on failure, so absence is distinguishable from "could not look" — which is exactly
the distinction that decides whether a parameter goes on the recovery list.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="DeleteParameter DeleteParameters GetParameter GetParameters GetParametersByPath"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "ssm.amazonaws.com") |
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

There is nothing to preserve — the data is already gone and no forensic ordering
protects it. Containment is therefore only about stopping the next deletion, and
it comes first, before any recovery work, because recreating parameters while the
principal still holds `ssm:DeleteParameter` simply gives it more to delete.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Stop further deletion

```bash
PRINCIPAL_ARN="<caller-arn-from-Query-1>"
POLICY_NAME="IR-ParamStore-Delete-Freeze"

cat > /tmp/ir-paramstore-delete-freeze.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "FreezeParameterDestruction",
      "Effect": "Deny",
      "Action": ["ssm:DeleteParameter", "ssm:DeleteParameters",
                 "ssm:PutParameter", "ssm:LabelParameterVersion"],
      "Resource": "*" }
  ]
}
JSON

case "$PRINCIPAL_ARN" in
  *:user/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $NF}')"
    aws iam put-user-policy --user-name "$IAM_NAME" \
      --policy-name "$POLICY_NAME" --policy-document file:///tmp/ir-paramstore-delete-freeze.json
    echo "[OK] delete freeze applied to IAM user $IAM_NAME" ;;
  *:assumed-role/*|*:role/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $2}')"
    aws iam put-role-policy --role-name "$IAM_NAME" \
      --policy-name "$POLICY_NAME" --policy-document file:///tmp/ir-paramstore-delete-freeze.json
    echo "[OK] delete freeze applied to role $IAM_NAME"
    echo "[!] PutParameter is denied too, deliberately — an Expiration policy is a delayed"
    echo "    delete, so freezing deletes without freezing writes leaves the path open."
    echo "    If this role is the deployment pipeline, releases now fail; say so in channel." ;;
  *:root)
    echo "[!] root credential — no policy denies root. Rotate the root password, remove"
    echo "    any root access key, confirm root MFA." ;;
  *)
    echo "[!] unrecognised principal shape: $PRINCIPAL_ARN — contain manually." ;;
esac
```

`PutParameter` is in the deny list on purpose. A principal that can still write can
arm an `Expiration` policy on a parameter it cannot delete directly, and Parameter
Store carries out that deletion later with no event attributing it to anyone.

#### Step 2 — Contain the principal

```bash
PRINCIPAL_ARN="<caller-arn-from-Query-1>"
ACCESS_KEY="<access-key-from-Query-1>"

case "$PRINCIPAL_ARN" in
  *:user/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $NF}')"
    # Disable before delete — the key is evidence.
    aws iam update-access-key --user-name "$IAM_NAME" --access-key-id "$ACCESS_KEY" --status Inactive
    echo "[OK] access key $ACCESS_KEY deactivated for user $IAM_NAME" ;;
  *:assumed-role/*|*:role/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $2}')"
    NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    cat > /tmp/ir-revoke-sessions.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Deny", "Action": ["*"], "Resource": ["*"],
      "Condition": { "DateLessThan": { "aws:TokenIssueTime": "$NOW" } } }
  ]
}
JSON
    aws iam put-role-policy --role-name "$IAM_NAME" \
      --policy-name AWSRevokeOlderSessions --policy-document file:///tmp/ir-revoke-sessions.json
    echo "[OK] sessions issued before $NOW revoked for role $IAM_NAME" ;;
  *)
    echo "[!] no containment path for $PRINCIPAL_ARN — contain manually." ;;
esac
```

`aws:TokenIssueTime` denies only tokens issued **before** the cutoff. A host still
holding the underlying compromise re-fetches credentials and gets a newer issue
time, so this kills the credential in hand and does not gate the role.

---

## 4. Eradication

### Remove Attacker Access

- **Recreate from the external source of truth, in dependency order.** The
  configuration repository or the secret's system of record is the only place the
  value survives; `GetParameterHistory` returns nothing, because the history was
  deleted with the parameter. Recreate what applications need to start before what
  they need to run
- **Allow 30 seconds per name.** AWS states "after deleting a parameter, wait for
  at least 30 seconds to create a parameter with the same name" — a restore script
  that deletes and immediately recreates fails intermittently, and the failure
  looks like a permissions problem
- **Treat a deleted `SecureString` as disclosed as well as destroyed.** If the
  actor read it before deleting — the read-then-delete correlation in
  `detections/sigma_t1485.yml` is exactly this shape — recreation is not enough
  and the credential must be rotated at its system of record. Check the decrypting
  reads by the same principal before you recreate
- **Audit every parameter for a lingering `Expiration` policy.** A deletion armed
  before containment still fires;
  `aws ssm describe-parameters --parameter-filters "Key=Path,Option=Recursive,Values=<path>"`
  returns `Policies` per parameter, and any `Expiration` type there is a scheduled
  destruction to clear with an empty `--policies '[]'` write
- **Right-size `ssm:DeleteParameter*`.** Scope it to the pipeline that owns the
  path and remove it from everything else; the permission has no read-only
  equivalent and nothing recoverable behind it
- **Remove the emergency policy once clean, with a real check** — §5 asserts it
  rather than assuming it landed on the right principal

---

## 5. Recovery

### Restore Clean State

#### Verify the parameters are back, current, and not scheduled to expire

```bash
REGION="<region>"
RESTORED_NAMES="<requested-names-from-Query-1>"     # space-separated
RESTORE_AFTER="<utc-timestamp-when-recreation-began>"

CUT="$(date -u -d "$RESTORE_AFTER" +%s)"
OK=0; MISSING=0; STALE=0; ARMED=0; UNKNOWN=0

for PNAME in $RESTORED_NAMES; do
  RAW="$(aws ssm describe-parameters --region "$REGION" --output json \
          --parameter-filters "Key=Name,Values=$PNAME")"
  RC=$?
  if [ "$RC" -ne 0 ] || [ -z "$RAW" ]; then
    UNKNOWN=$((UNKNOWN + 1)); echo "[!] $PNAME — describe-parameters failed"; continue
  fi

  N="$(printf '%s' "$RAW" | jq '.Parameters | length')"
  if [ "$N" -eq 0 ]; then
    MISSING=$((MISSING + 1)); echo "[FAIL] $PNAME still absent — not recreated"; continue
  fi

  LM="$(printf '%s' "$RAW" | jq -r '.Parameters[0].LastModifiedDate // empty')"
  NPOL="$(printf '%s' "$RAW" | jq '[.Parameters[0].Policies // [] | .[]
           | select(.PolicyType == "Expiration")] | length')"
  if [ -z "$LM" ]; then
    UNKNOWN=$((UNKNOWN + 1)); echo "[!] $PNAME — present but no LastModifiedDate returned"; continue
  fi

  # CLI v2 renders timestamps ISO 8601; older configurations emit epoch seconds.
  case "$LM" in
    *[!0-9.]*) LMS="$(date -u -d "$LM" +%s)" ;;
    *)         LMS="${LM%%.*}" ;;
  esac
  if [ -z "$LMS" ]; then
    UNKNOWN=$((UNKNOWN + 1)); echo "[!] $PNAME — unparseable LastModifiedDate: $LM"; continue
  fi

  if [ "$LMS" -lt "$CUT" ]; then
    STALE=$((STALE + 1))
    echo "[FAIL] $PNAME predates the restore window — this is the ORIGINAL, so it was"
    echo "       never deleted; remove it from the loss list and re-scope Query 2"
  elif [ "$NPOL" -gt 0 ]; then
    ARMED=$((ARMED + 1)); echo "[FAIL] $PNAME recreated but carries $NPOL Expiration policy"
  else
    OK=$((OK + 1)); echo "[OK] $PNAME recreated after $RESTORE_AFTER, no expiration armed"
  fi
done

echo "---"
[ "$UNKNOWN" -gt 0 ] && echo "[!] INCONCLUSIVE for $UNKNOWN name(s); do not close on this result"
if [ "$OK" -eq 0 ] && [ "$MISSING" -eq 0 ] && [ "$STALE" -eq 0 ] && [ "$ARMED" -eq 0 ]; then
  echo "[!] INCONCLUSIVE — nothing was checked; RESTORED_NAMES is empty or every lookup failed"
elif [ "$MISSING" -eq 0 ] && [ "$STALE" -eq 0 ] && [ "$ARMED" -eq 0 ]; then
  echo "[OK] all $OK parameters recreated after $RESTORE_AFTER with no expiration policy"
else
  echo "[FAIL] missing: $MISSING   stale: $STALE   expiration armed: $ARMED"
fi
```

The `STALE` branch is the one that earns its place. A parameter whose
`LastModifiedDate` predates the restore window is not a restored parameter — it is
one that was never deleted, which means Query 1's requested-names list overstated
the loss and the scope needs re-cutting. Reporting it as `[OK]` because the name
exists would certify a recovery that never happened.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     eventSource=ssm.amazonaws.com eventName=DeleteParameters"
echo "                  requestParameters.names=[\"/app/prod/db/password\",\"/app/prod/api/key\"]"
echo "                  errorCode absent"
echo "                  userIdentity.arn=arn:aws:iam::111122223333:user/contractor"
echo "MUST fire on:     five or more such successful calls from one userIdentity.arn"
echo "                  inside five minutes — the mass-destruction correlation"
echo "MUST NOT fire on: the same DeleteParameters by userIdentity.arn containing"
echo "                  :role/iac-deploy (the allowlisted pipeline tearing an env down)"
echo "MUST NOT fire on: DeleteParameter carrying errorCode=AccessDenied"
echo "                  (nothing was destroyed; it must not enter the recovery list)"
echo "CANNOT fire at all, by design of the API:"
echo "                  DeleteParameter on a name that does not exist — AWS does not"
echo "                  record ParameterNotFound in CloudTrail, so there is no event"
echo "                  a parameter removed by an Expiration policy — Parameter Store"
echo "                  performs that delete itself and no principal appears"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the configuration lifecycle could destroy parameters permanently | `ssm:DeleteParameter*` granted on `parameter/*`, an action with no reversible form and nothing behind it |
| The loss could not be sized from the alert | Detection counted events; `DeleteParameters` names up to ten parameters per call, and a successful call may delete fewer than it names |
| Recovery depended on a source that may not have existed | No configuration source of truth outside Parameter Store, and the version history — the only in-AWS copy — is deleted with the parameter |
| The alert had been muted before the incident | The rule fired on every planned teardown, with no pipeline allowlist, so the signal was already being ignored when it mattered |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Confine parameter destruction to the pipeline that owns the lifecycle. The Resource
// element is wildcarded, which is fine — wildcards ARE expanded there. The principal
// allowlist is wildcarded too and therefore needs ArnNotLike: Deny + ArnNotEquals
// against a wildcard fails CLOSED and blocks the pipeline along with everyone else.
{
  "Sid": "NoParameterDestructionOutsidePipeline",
  "Effect": "Deny",
  "Action": ["ssm:DeleteParameter", "ssm:DeleteParameters"],
  "Resource": "arn:aws:ssm:*:*:parameter/*",
  "Condition": {
    "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/iac-deploy" }
  }
}
```

- **Keep a configuration source of truth outside Parameter Store.** Parameter
  Store is not a backup of itself: deletion removes every version, so the
  repository or the secret's system of record is the only recovery path that
  exists. Snapshot `DescribeParameters` per path on a schedule as well, so
  "what was there" is answerable after the fact
- **Deny `ssm:Policies` where expiring parameters are not needed**, because an
  `Expiration` policy is a deletion that no delete-focused control or alert will
  ever see. It is an advanced-tier billed feature, so denying it costs almost
  nothing
- **Allowlist the teardown pipeline rather than raising the threshold.** The
  reason this alert was muted is that planned destruction and malicious
  destruction produced identical events; naming the principal is what separates
  them, and it is the one tuning move that does not reduce coverage

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1485 — Data Destruction |
| MITRE tactic | Impact (TA0040) |
| Primary API | `ssm:DeleteParameter` (one name) and `ssm:DeleteParameters` (up to 10 names per call) |
| Event source | `ssm.amazonaws.com` — **management** events, recorded by default. Verified: AWS states "Systems Manager logs all control plane operations to CloudTrail as management events", and the only SSM data-event resource types are `AWS::SSMMessages::ControlChannel` and `AWS::SSM::ManagedNode` |
| Key discriminator | The writing principal, plus the length of `requestParameters.names` — the number of parameters, not the number of events |
| Field shape | `name` on the singular call, `names` (array) on the plural; they never co-occur and must be OR'd, never ANDed |
| "Was it used" pivot | Not applicable — the deletion **is** the impact. The equivalent question is what the parameters fed, answered from the consumers, not from AWS |
| Blast radius | Every workload that reads the parameter, failing at its next restart or refresh rather than immediately |
| Reversibility | **None.** AWS: "Deleting a parameter removes all versions of it. Once deleted, the parameter and its versions can't be restored." No recovery window, no soft delete — contrast Secrets Manager's 7-to-30-day default. Recreating the same name requires waiting at least 30 seconds |
| Error strings | `DeleteParameter`: `ParameterNotFound` — **not recorded in CloudTrail** — and `InternalServerError`. `DeleteParameters`: `InternalServerError` only; unknown names return in the 200-response `InvalidParameters` array. Denials as `AccessDenied` and `AccessDeniedException` — match both |
| Invisible variant | A parameter deleted by an `Expiration` parameter policy is removed by Parameter Store itself: no principal, no delete event. Armed at `PutParameter` time and visible only there |

**MITRE mapping note.** The source rule maps T1485 (*Data Destruction*) under
TA0040, and that is **correct** — the only one of the five Systems Manager alerts
whose mapping needs no correction, which is worth stating rather than passing over.
The disagreement is priority, not mapping: P3 for a loss with no possible restore
puts an irreversible destruction in a queue read the next business day. The
read-then-delete correlation carries T1555.006 alongside T1485, because taking the
value before destroying it is credential access followed by impact and the response
has to cover both.

### Residual Risk

**Nothing recovers the value from AWS.** Recreation restores a name and a value you
sourced elsewhere; it does not restore what was there. If no external source of
truth exists for a given parameter, that configuration is simply gone, and the
honest statement in the incident record is that it was reconstructed by inference.

**A deleted `SecureString` may also have been read.** Deletion destroys the
evidence of what the value was, including the version history that would have shown
it — so an actor that read before deleting leaves you unable to prove what was
disclosed. Where a decrypting read by the same principal precedes the delete,
rotate at the system of record and treat the value as compromised regardless.

**Deletions you cannot see may still be pending.** An `Expiration` policy armed
before containment fires on its own schedule with no principal attached. Until
every parameter under the affected paths has been checked for one, more destruction
is scheduled and no alert in this playbook will announce it.

**Consumers fail later.** A workload holding the value keeps running, so the
outage arrives at the next restart or deploy — possibly days after the incident is
closed, and attributed to whatever change happened to be in flight at the time.
