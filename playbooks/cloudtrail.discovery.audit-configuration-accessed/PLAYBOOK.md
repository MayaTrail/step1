# IR Playbook: CloudTrail Audit Configuration Enumerated — logging state read via `GetTrailStatus` and `DescribeTrails`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Discovery — a principal reads the CloudTrail logging configuration, establishing what is captured, whether it is running, and which Region owns each trail |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Informational for a single read; medium for a sweep or a denied probe; critical when tampering follows from the same principal. On its own this is reconnaissance, not an incident. |
| MITRE Tactics | Discovery |
| MITRE Techniques | T1654 |
| Services in Scope | CloudTrail, CloudWatch Logs, IAM |

**What the technique does:** the actor reads the logging configuration before deciding what to
disable. Two calls carry almost all the value:

- **`GetTrailStatus`** returns `IsLogging` — whether a trail is actually recording.
- **`DescribeTrails`** returns `HomeRegion`, `IsMultiRegionTrail` and `IsOrganizationTrail`.

The `HomeRegion` is a prerequisite rather than a convenience. Both `StopLogging` and `DeleteTrail`
are refused outside it and refused entirely on shadow trails, so an actor either obtains it first or
produces a visible `InvalidHomeRegionException`. `GetEventSelectors` completes the picture by
returning exactly what is and is not being captured.

**Why the usual reflexes miss it.** The first is to scope the rule to `userIdentity.type IAMUser`,
which is what the source rule does — SSO users, federated identities, instance roles and Lambda
roles all arrive as `AssumedRole`, so the rule misses the majority case entirely. The second is to
watch `DescribeTrails` and not `GetTrailStatus`, catching the general half of the prerequisite and
missing the specific one. The third is to alert on every read, which produces a stream that gets
suppressed. The fourth is to treat this as an incident on its own: it is not, and its value is
almost entirely in what follows it.

**Detection thesis:** ship the read at informational across all identity types, alert on the shape —
a sweep, a denied probe, or a read followed by tampering.

**Adjacent playbooks.** What this enumeration precedes:
`../cloudtrail.stealth.trail-logging-stopped/`, `../cloudtrail.impact.trail-deleted/`,
`../cloudtrail.stealth.trail-modified/`. The delivery-path equivalent is
`../cloudtrail.stealth.no-logs-received/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every Region. `DescribeTrails`, `GetTrailStatus` and
`GetEventSelectors` are read-only management events and are recorded by default — this playbook's
own signal needs nothing purchased.

CloudWatch Logs events, if log content reads matter to you. `FilterLogEvents` and `GetLogEvents` are
`logs.amazonaws.com` events and cover a different act from the configuration reads.

**A recorded list of the tools that legitimately enumerate trails.** CSPM platforms, compliance
scanners and inventory jobs sweep every Region on a schedule and look identical to the attacker
sweep. Identifying them is a one-off exercise, and a scanner nobody recognises is a finding in its
own right.

**Alerting (must be pre-configured)**

- **A configuration read followed by a trail being stopped, deleted or reconfigured, by the same principal within 1h → P0**
- **`GetTrailStatus` or `DescribeTrails` across five or more Regions by one principal — the sweep that yields `IsLogging` and `HomeRegion` → P0**

**Response Tooling**

Read access to CloudTrail history for the principal in question. The response here is entirely
analytic: there is nothing to contain unless the reads were followed by something.

The ability to resolve a role session back to the human or workload behind it — an SSO identity
store lookup, or the instance or function the role belongs to. Because the useful identity type here
is `AssumedRole`, the ARN alone rarely names anybody.

**Known IOC Baselines**

The roles used by scanners and inventory tooling, ready to allowlist on the base rule.

Normal read volume per principal. The correlation fires at five reads in ten minutes; knowing
whether that is unusual in your estate is what makes the threshold meaningful rather than arbitrary.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | A logging configuration read followed by `StopLogging`, `DeleteTrail`, `UpdateTrail` or `PutEventSelectors` from the same principal within 1h | Correlation rule | T1654 |
| P0 | `GetTrailStatus` or `DescribeTrails` across five or more Regions by one principal — the sweep that yields `IsLogging` and `HomeRegion` | CloudTrail | T1654 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `GetTrailStatus` and `GetEventSelectors` both read by one principal — whether it is running and what it captures | CloudTrail | T1654 |
| P2 | Configuration reads denied with `AccessDenied` — probing without the permission | CloudTrail | T1654 |
| P2 | `FilterLogEvents` or `GetLogEvents` by a non-service principal — reading log content rather than configuration | CloudWatch Logs | T1654 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `userIdentity.type:"IAMUser"` only | SSO users, federated identities, EC2 instance roles, Lambda execution roles and every cross-account path arrive as `AssumedRole`. A compromised role session reads the whole logging configuration without the rule firing once — this is the majority case, not an edge case | All identity types, with `IdentityTypes` projected in the query so the size of the original gap is visible in real output |
| Watches `DescribeTrails` but not `GetTrailStatus` or `GetEventSelectors` | `GetTrailStatus` returns `IsLogging` and, with `DescribeTrails`, the `HomeRegion` that `StopLogging` and `DeleteTrail` both require. `GetEventSelectors` returns what is captured. The rule catches the general half of the prerequisite and misses the specific one | Both added, and the pairing of status plus selectors rated as its own trigger |
| Mixes `FilterLogEvents` in with CloudTrail calls | That is a CloudWatch Logs call. Reading log content establishes what the defender already has; reading the configuration establishes how to stop them getting more. Different follow-on, same alert | Separated, with distinct verdicts, both still under `T1654` |
| Filters on `sourceIPAddress.keyword` with a regex | `.keyword` is an index-mapping artefact, and the check duplicates the `userIdentity.invokedBy` filter in the same rule — AWS-service-invoked calls set that field. A portability dependency for no coverage | `userIdentity.invokedBy` alone |
| Alerts on every matching read at P3 | A single configuration read is unremarkable, so a per-event alert becomes a stream and is suppressed — taking the sweep and the read-then-tamper cases with it | Informational base rule, with alerting on shape: sweep, denied probe, or tampering that follows |
| Success filter drops denied reads | The successful case has many innocent explanations. A principal probing the logging estate without the permission has few | A dedicated rule on `AccessDenied` and `UnauthorizedOperation` |

**Recommended detection — the reads that matter, and the shapes worth alerting on.**

```yaml
# CloudTrail audit configuration enumerated (T1654)
#
# THE SOURCE RULE MATCHES `userIdentity.type:"IAMUser"` ONLY, which excludes SSO, federation, EC2
# instance roles, Lambda and every cross-account path — all AssumedRole, and the normal shape of a
# cloud intrusion.
#
# It also watches DescribeTrails but not GetTrailStatus or GetEventSelectors, which yield IsLogging
# and the HomeRegion that StopLogging and DeleteTrail both require. This is the one rule in the pack
# whose MITRE mapping is correct and live.
# Full rationale: detections/detection_note_t1654.md.
title: CloudTrail logging configuration enumerated
id: 9f60c3b1-84e2-4d07-a5b9-31c04e7f28da
name: cloudtrail_audit_config_read
status: experimental
description: >-
  Base rule — correlation component and low-value on its own. A read of the CloudTrail logging
  configuration by a human or role principal, covering the calls that matter rather than only
  DescribeTrails: GetTrailStatus returns IsLogging and, with DescribeTrails, the HomeRegion that
  StopLogging and DeleteTrail both require; GetEventSelectors returns what is actually captured. All
  identity types, because AssumedRole is the normal shape of a modern compromise.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html
  - https://attack.mitre.org/techniques/T1654/
tags:
  - attack.discovery
  - attack.t1654
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName:
      - 'DescribeTrails'
      - 'ListTrails'
      - 'GetTrailStatus'
      - 'GetEventSelectors'
      - 'GetInsightSelectors'
      - 'LookupEvents'
  # AWS-service-invoked calls set invokedBy. This one filter replaces the source rule's
  # sourceIPAddress regex, which depended on an index mapping and added no coverage.
  service_invoked:
    userIdentity.invokedBy|exists: true
  condition: selection and not service_invoked
level: informational
---
title: CloudTrail logging configuration swept by one principal
id: 4c18b7de-2035-49a6-b13f-8ea27d60c495
status: experimental
description: >-
  One principal made five or more distinct reads of the CloudTrail logging configuration within ten
  minutes. A single read is unremarkable and is why the base rule is informational; a sweep is
  someone building a picture of what is logged and where, which is the step before deciding what to
  turn off. Ten minutes is short on purpose — this is a scripted pattern, not an exploratory one.
references:
  - https://attack.mitre.org/techniques/T1654/
tags:
  - attack.discovery
  - attack.t1654
correlation:
  type: event_count
  rules:
    - cloudtrail_audit_config_read
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gte: 5
falsepositives:
  - >-
    A compliance scanner or CSPM tool enumerating trails across every Region. It will look exactly
    like this and should be allowlisted by role on the base rule — which is also a useful exercise,
    because an unrecognised scanner is itself worth knowing about.
level: medium
---
title: CloudTrail logging configuration read, then the trail tampered with
id: 7a2e5904-c86d-41b3-90f7-6b5031ade8c2
status: experimental
description: >-
  A principal read the logging configuration and then stopped, deleted or reconfigured a trail. This
  is the sequence the enumeration exists to enable — StopLogging and DeleteTrail are both refused
  outside the trail's home Region, so an actor either finds it first or fails visibly. Catching the
  pair converts a low-value discovery signal into the earliest reliable warning of tampering.
references:
  - https://attack.mitre.org/techniques/T1654/
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.discovery
  - attack.defense-evasion
  - attack.t1654
  - attack.t1685.002
correlation:
  type: temporal_ordered
  rules:
    - cloudtrail_audit_config_read
    - cloudtrail_config_tampered
  group-by:
    - userIdentity.arn
  timespan: 1h
level: critical
---
title: CloudTrail configuration read refused
id: e0c74af6-9b21-4d58-8306-25f19bc0e743
name: cloudtrail_audit_config_read_denied
status: experimental
description: >-
  A read of the CloudTrail logging configuration that was denied. A principal probing for visibility
  into the logging estate without holding the permission is a clearer signal than one that holds it,
  because the successful case has many legitimate explanations and the denied case has few. Dropped
  entirely by any rule filtering on success.
references:
  - https://attack.mitre.org/techniques/T1654/
tags:
  - attack.discovery
  - attack.t1654
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName:
      - 'DescribeTrails'
      - 'ListTrails'
      - 'GetTrailStatus'
      - 'GetEventSelectors'
      - 'GetInsightSelectors'
      - 'LookupEvents'
  denied:
    errorCode|contains:
      - 'AccessDenied'
      - 'UnauthorizedOperation'
  condition: selection and denied
falsepositives:
  - >-
    A least-privilege role that legitimately lacks the permission and whose tooling retries anyway.
    Worth fixing at the source rather than allowlisting, because a retry loop here is
    indistinguishable from probing.
level: medium
---
title: CloudTrail trail configuration tampered with
id: 51b8d02c-6e47-4a93-bf10-c74a26e0938b
name: cloudtrail_config_tampered
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. Any successful call that stops,
  deletes or reconfigures a trail. The rated detections for these acts are in the sibling
  directories ../../cloudtrail.stealth.trail-logging-stopped/,
  ../../cloudtrail.impact.trail-deleted/ and ../../cloudtrail.stealth.trail-modified/.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName:
      - 'StopLogging'
      - 'DeleteTrail'
      - 'UpdateTrail'
      - 'PutEventSelectors'
      - 'PutInsightSelectors'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: it cannot distinguish a legitimate scanner from an actor by
behaviour alone — both sweep every Region and read the same fields. Only the §1 allowlist separates
them, and building it is the substantive preparation for this use case.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

Run Query 1 first; it establishes whether anything followed the reads, which decides everything else.

#### Query 1 — Did the enumeration lead anywhere

```bash
PRINCIPAL="${1:?principal ARN from the alert required}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

# For an assumed role the CloudTrail username is the SESSION name: the second slash-separated
# segment after `assumed-role/`, not the role name and not the last segment.
case "$PRINCIPAL" in
  *:assumed-role/*) LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $2}')" ;;
  *)                LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')" ;;
esac

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$LOOKUP" \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
| jq -r '.Events[].CloudTrailEvent | fromjson
    | (.eventName) as $e
    # GetTrailStatus gives IsLogging; DescribeTrails gives HomeRegion. StopLogging and DeleteTrail
    # are both refused outside the home Region, so these reads are the prerequisite for tampering.
    | (if ($e | test("^(GetTrailStatus|DescribeTrails|ListTrails)$")) then "READ-STATUS"
       elif ($e | test("^Get(Event|Insight)Selectors$")) then "READ-SELECTORS"
       elif ($e | test("^(LookupEvents|FilterLogEvents|GetLogEvents)$")) then "READ-CONTENT"
       elif ($e | test("^(StopLogging|DeleteTrail|UpdateTrail|Put(Event|Insight)Selectors)$")) then "*** TAMPER ***"
       else "other" end) as $class
    | select($class != "other")
    | "\(.eventTime)  \($class)  \($e)  \(.errorCode // "OK")  region=\(.awsRegion)  trail=\(.requestParameters.name // "-")"' \
| sort
```

A `*** TAMPER ***` line after any `READ-` line is the finding, and the reads before it explain why
the tampering succeeded first time rather than producing an `InvalidHomeRegionException`. If nothing
follows the reads, this is reconnaissance and the response is monitoring rather than containment.

#### Query 2 — How wide was the sweep

```bash
PRINCIPAL="${1:?principal ARN required}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"
case "$PRINCIPAL" in
  *:assumed-role/*) LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $2}')" ;;
  *)                LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')" ;;
esac

for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null); do
  N="$(aws cloudtrail lookup-events \
        --lookup-attributes AttributeKey=Username,AttributeValue="$LOOKUP" \
        --start-time "$START" --region "$R" --output json 2>/dev/null \
      | jq -r '[.Events[].CloudTrailEvent | fromjson
                | select(.eventName | test("^(GetTrailStatus|DescribeTrails|ListTrails|Get(Event|Insight)Selectors)$"))]
                | length')"
  [ "${N:-0}" -gt 0 ] && echo "$R: $N configuration read(s)"
done | sort

echo
echo "[!] Five or more Regions is the sweep case. A CSPM tool or compliance scanner produces exactly"
echo "    this shape — check the principal against the §1 allowlist before escalating."
```

#### Query 3 — What the reads would have revealed

```bash
REGION="${AWS_REGION:-us-east-1}"

# Run the same reads the principal ran. Whatever this returns is what they now know, and it is the
# most direct way to assess how much the enumeration was worth to them.
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null); do
  aws cloudtrail describe-trails --include-shadow-trails --region "$R" --output json 2>/dev/null \
  | jq -r --arg r "$R" '.trailList[]
      | "\($r)  \(.Name)  home=\(.HomeRegion)  org=\(.IsOrganizationTrail)  multiregion=\(.IsMultiRegionTrail)"'
done | sort -u

echo
echo "=== And which of them are actually running ==="
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null); do
  aws cloudtrail describe-trails --region "$R" --query 'trailList[].Name' --output text 2>/dev/null \
  | tr '\t' '\n' | while read -r T; do
      [ -z "$T" ] && continue
      S="$(aws cloudtrail get-trail-status --name "$T" --region "$R" --query IsLogging --output text 2>/dev/null)"
      echo "$R/$T logging=$S"
    done
done | sort -u
```

Read the `home=` column as the attacker would. It is the single field that turns a refused
`StopLogging` into a successful one, and an `org=true` line tells them a member-account compromise
cannot silence that trail at all — which is as useful to them as it is reassuring to you.

#### Query 4 — Resolve the role session back to a human or workload

```bash
PRINCIPAL="${1:?principal ARN required}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

# Because the useful identity type here is AssumedRole, the ARN names a role and a session, not a
# person. The AssumeRole event that created the session carries who requested it.
case "$PRINCIPAL" in
  *:assumed-role/*)
    SESSION="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $2}')"
    aws cloudtrail lookup-events \
      --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
      --start-time "$START" --region "$REGION" --output json 2>/dev/null \
    | jq -r --arg s "$SESSION" '.Events[].CloudTrailEvent | fromjson
        | select(.requestParameters.roleSessionName == $s)
        | "\(.eventTime)  assumed by \(.userIdentity.arn)  from \(.sourceIPAddress)  mfa=\((.additionalEventData.MFAUsed) // "unknown")"'
    ;;
  *) echo "not an assumed-role principal — $PRINCIPAL identifies directly" ;;
esac
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**On its own, there is nothing to contain.** Reading a configuration changes nothing, and treating
reconnaissance as an incident produces a response with no actions in it. What Query 1 decides is
which of two very different situations you are in.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 1 shows a
`*** TAMPER ***` line, stop working this playbook and go to the matching sibling:
`../cloudtrail.stealth.trail-logging-stopped/`, `../cloudtrail.impact.trail-deleted/` or
`../cloudtrail.stealth.trail-modified/`. The enumeration is context; the tampering is the incident.

#### Step 1 — Decide which situation this is

```bash
PRINCIPAL="${1:?principal ARN required}"

cat <<NOTE
Work these in order. Only the last one is a containment path.

 1. Is $PRINCIPAL on the §1 scanner allowlist?
      -> yes: close, and confirm the allowlist entry is still accurate.
 2. Did §2 Query 1 show a *** TAMPER *** line?
      -> yes: this is not a discovery incident. Go to the matching sibling playbook now.
 3. Were the reads DENIED?
      -> yes: a principal probed the logging estate without the permission. Fewer innocent
         explanations than a successful read. Continue to Step 2.
 4. Was it a sweep across five or more Regions, or status plus selectors together?
      -> yes: continue to Step 2.
 5. Otherwise: a single read. Record it, monitor the principal, and close.
NOTE
```

#### Step 2 — Establish whether the principal should have been reading this at all

```bash
PRINCIPAL="${1:?principal ARN required}"

case "$PRINCIPAL" in
  *:assumed-role/*)
    R="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $1}')"
    echo "=== Attached managed policies for role $R ==="
    aws iam list-attached-role-policies --role-name "$R" \
      --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null | tr '\t' '\n'
    echo "=== Inline policies ==="
    aws iam list-role-policies --role-name "$R" --query 'PolicyNames' --output text 2>/dev/null | tr '\t' '\n'
    ;;
  *:user/*)
    U="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')"
    aws iam list-attached-user-policies --user-name "$U" \
      --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null | tr '\t' '\n'
    ;;
  *) echo "[!] unrecognised principal shape: $PRINCIPAL" ;;
esac

echo
echo "[!] cloudtrail:DescribeTrails and GetTrailStatus are in ReadOnlyAccess and SecurityAudit, so"
echo "    a principal holding either can do all of this legitimately. The question is not whether"
echo "    they COULD, but whether this workload has any reason to."
```

#### Step 3 — Monitor rather than revoke, unless something followed

```bash
PRINCIPAL="${1:?principal ARN required}"
REGION="${AWS_REGION:-us-east-1}"

# Revoking access for reading a configuration is disproportionate and, if the principal is
# legitimate, disruptive. Watch for the calls that would make it an incident instead.
cat <<NOTE
Watch $PRINCIPAL for the following over the next 24h. Any of them escalates immediately:

  StopLogging / DeleteTrail / UpdateTrail / PutEventSelectors   (trail tampering)
  DisableKey / ScheduleKeyDeletion                              (delivery-path tampering)
  PutBucketPolicy / DeleteBucket on a trail destination         (delivery-path tampering)
  GetTrailStatus in a Region not previously touched             (the sweep continuing)
NOTE

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" --region "$REGION" \
  --query 'Events[].[EventTime,Username]' --output text 2>/dev/null \
  || echo "(no StopLogging yet)"
```

#### Step 4 — Contain the principal, only if Step 1 reached case 3 or 4 and the principal is unexplained

```bash
PRINCIPAL="${1:?principal ARN required}"

case "$PRINCIPAL" in
  *:user/*)
    U="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')"
    aws iam list-access-keys --user-name "$U" --query 'AccessKeyMetadata[].AccessKeyId' \
      --output text 2>/dev/null | tr '\t' '\n' | while read -r K; do
        [ -z "$K" ] && continue
        aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive \
          && echo "[OK] key $K deactivated"
      done
    ;;
  *:assumed-role/*)
    # Role name is the FIRST segment after `assumed-role/`; the second is the session name.
    R="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $1}')"
    echo "[!] assumed role: $R — existing session credentials remain valid until expiry."
    echo "    Save as revoke.json and attach with put-role-policy:"
    cat <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"}}}]}
JSON
    ;;
  *) echo "[!] unrecognised principal shape: $PRINCIPAL — contain manually" ;;
esac
```

This step is deliberately last and deliberately conditional. Reading a configuration is not by
itself grounds for revoking a role that may be running production workloads, and a response that
reaches for it on a discovery signal will be overridden the first time it breaks something.

---

## 4. Eradication

### Remove Attacker Access

#### Treat the enumeration as intelligence about your own estate

Query 3 shows what the principal learned. That output is worth reading on its own terms: a trail
with `org=false` and a `HomeRegion` an attacker now knows is a trail they can stop on the first
attempt. If the sweep revealed an account with only single-Region, non-organization trails, the
finding is the estate rather than the principal.

#### Close the gaps the enumeration would have found

Two changes remove most of the value of this reconnaissance:

- **An organization trail**, which a member account cannot stop, delete or reconfigure regardless of
  its IAM permissions. Knowing its home Region does the attacker no good.
- **An SCP denying the tampering calls** outside a break-glass role, so the home Region stops
  mattering at all.

#### Right-size who can read the logging configuration

`cloudtrail:DescribeTrails` and `cloudtrail:GetTrailStatus` are included in `ReadOnlyAccess` and
`SecurityAudit`, so most read-capable principals have them. That is usually correct — but an
application role, a build role or a data-processing role has no reason to, and those are the
principals a compromise most often lands on. Removing `cloudtrail:*` read permissions from workload
roles costs nothing and removes the reconnaissance step entirely for the most likely entry point.

#### Build the scanner allowlist properly

The dominant false positive here is legitimate tooling, and the only fix is knowing what it is. The
first week of base-rule output is the source: every principal sweeping Regions on a schedule is
either identified and allowlisted, or is a finding.

---

## 5. Recovery

### Restore Clean State

#### Confirm nothing followed the enumeration

```bash
PRINCIPAL="${1:?principal ARN required}"
REGION="${AWS_REGION:-us-east-1}"
SINCE="${2:?timestamp of the first read, from §2 Query 1}"

case "$PRINCIPAL" in
  *:assumed-role/*) LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $2}')" ;;
  *)                LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')" ;;
esac

FOUND="$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$LOOKUP" \
  --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null \
| jq -r '[.Events[].CloudTrailEvent | fromjson
    | select(.eventName | test("^(StopLogging|DeleteTrail|UpdateTrail|Put(Event|Insight)Selectors|DisableKey|ScheduleKeyDeletion)$"))]
    | length')"

if [ "${FOUND:-0}" -eq 0 ]; then
  echo "[OK] no tampering by $PRINCIPAL since $SINCE — this was reconnaissance only"
else
  echo "[FAIL] $FOUND tampering call(s) since $SINCE — this is not a discovery incident"
fi
```

#### Confirm the logging estate is in the state the enumeration should have found boring

```bash
aws cloudtrail describe-trails --include-shadow-trails --output json 2>/dev/null \
| jq -r 'if ([.trailList[] | select(.IsOrganizationTrail == true)] | length) > 0
         then "[OK] organization trail present — knowing the home Region gains an attacker nothing"
         else "[FAIL] no organization trail — the sweep produced actionable information" end'

aws cloudtrail describe-trails --include-shadow-trails --output json 2>/dev/null \
| jq -r 'if ([.trailList[] | select(.IsMultiRegionTrail == true and .IncludeGlobalServiceEvents == true)] | length) > 0
         then "[OK] multi-Region trail with global events — IAM and STS are covered"
         else "[FAIL] no multi-Region trail with global events — IAM and STS activity is invisible" end'
```

The framing matters. Recovery from a discovery incident is not restoring something that broke — it
is making the information the attacker gathered worthless, and these two checks are what determine
whether it was.

#### Confirm the corrected detection fires

```bash
REGION="${AWS_REGION:-us-east-1}"

# Exercise GetTrailStatus specifically — the call the source rule did not watch — from a role
# session rather than an IAM user, which is the identity type it also excluded. This is entirely
# read-only and changes nothing.
for R in us-east-1 eu-west-1 ap-southeast-1 us-west-2 eu-central-1; do
  aws cloudtrail describe-trails --region "$R" --query 'trailList[0].Name' --output text 2>/dev/null \
  | while read -r T; do
      [ -z "$T" ] || [ "$T" = "None" ] && continue
      aws cloudtrail get-trail-status --name "$T" --region "$R" >/dev/null 2>&1 \
        && echo "[OK] read $R/$T"
    done
done
echo "[!] Five Regions swept — expect the sweep correlation within 15 min, from an AssumedRole"
echo "    principal. If nothing fires, either the identity-type filter or the event list is wrong."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Did anything follow the reads? | It is the only question that decides whether this is an incident. Everything else is context. |
| Was the principal an `AssumedRole`? | If so, the source rule would have missed it entirely, and the identity-type filter is the finding rather than the reads. |
| Was `GetTrailStatus` among the calls? | It returns `IsLogging` and pairs with `DescribeTrails` for the `HomeRegion` — the specific prerequisite for tampering, and the call the source rule did not watch. |
| Was the principal on the scanner allowlist? | If the allowlist does not exist, this alert will be closed as a scanner every time, including when it is not one. |
| What did the sweep reveal? | A single-Region, non-organization trail estate is actionable intelligence. An organization trail is not. |
| Does this workload have any reason to read CloudTrail? | Application and build roles usually do not, and removing the permission removes the reconnaissance step at the most likely entry point. |

### Recommended Guardrails

**Cover all identity types.** Filtering to `IAMUser` excludes SSO, federation, instance roles and
Lambda — in most estates that is nearly all traffic, and the exclusion is invisible because the rule
still fires occasionally on the legacy identities that remain.

**Watch `GetTrailStatus` and `GetEventSelectors`, not just `DescribeTrails`.** Those are the calls
that turn a refused tampering attempt into a successful one.

**Ship the read at informational and alert on shape.** A per-event alert on a common read becomes a
stream and gets suppressed, taking the sweep and read-then-tamper cases with it.

**Create an organization trail.** It is the recommendation in every playbook in this directory set,
and here it has a specific effect: it makes the information gathered by the enumeration worthless,
because knowing the home Region of a trail you cannot alter gains nothing.

**Remove `cloudtrail:` read permissions from workload roles.** Application, build and data roles
have no reason to enumerate trails, and those are the principals a compromise most often lands on.

### Technique Reference

**T1654 — Log Enumeration.** Verified live at https://attack.mitre.org/techniques/T1654/ on
2026-08-30. This is the mapping the source rule already had, and it is correct — the only one of the
five CloudTrail rules in that pack that is.

**T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log** is tagged on the
read-then-tamper correlation, since the second half of that pair is the tampering itself. Verified
live 2026-08-30.

AWS references relied on throughout, all verified 2026-08-30:

- `GetTrailStatus` API reference — the fields the enumeration returns:
  https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html
- `StopLogging` API reference — the home-Region constraint that makes these reads a prerequisite:
  https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html

Service-wide verified behaviour shared by every `cloudtrail.*` playbook is in
`../_ground-truth/cloudtrail.md`.

### Residual Risk

**Legitimate scanners are behaviourally identical.** A CSPM platform sweeping every Region reads the
same fields in the same pattern. No amount of rule refinement separates them; only the allowlist
does, and an estate without one will close every instance of this alert as a scanner.

**The console reads differently from the CLI.** A human browsing the CloudTrail console generates
`DescribeTrails` and `GetTrailStatus` as a side effect of loading a page, without intending to
enumerate anything. That inflates the base rule's volume and is one more reason it ships at
informational rather than alerting.

**Reading is not the only way to learn the home Region.** A trail's ARN contains its Region, and
ARNs appear in bucket policies, IAM policies, tags and IaC repositories. An actor who has read any of
those does not need `DescribeTrails`, and nothing here will see them.

**This use case has no containment of its own.** Everything the playbook can do is either analytic
or belongs to a sibling directory. That is the correct shape for a discovery technique, and it means
the value here depends entirely on the correlations being deployed alongside the tampering rules
rather than on their own.
