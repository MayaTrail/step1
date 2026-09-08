# IR Playbook: CloudTrail Logging Stopped — recording suspended via `StopLogging`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defence evasion — API recording and log delivery are suspended for a trail, ending the account's primary audit record for as long as the stop stands |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical. AWS states a trail can be updated without stopping it and that `StopLogging` is the only way to stop recording, so there is no benign reconfiguration reading. The source rule rates it P2 — one level below its own downstream symptom. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | CloudTrail, IAM, AWS Organizations, S3 |

**What the technique does:** the actor calls `StopLogging` on a trail. AWS: *"Suspends the recording
of AWS API calls and log file delivery for the specified trail... This action is the only way to
stop recording."* Nothing about the trail's configuration changes — it still exists, still has its
selectors, still points at its bucket. It simply stops recording, and every API call made from that
moment leaves no trace in that trail.

**Why the usual reflexes miss it.** The first is to filter on success, which is what the source rule
does — AWS refuses this call outside the trail's home Region, so an actor who is guessing fails
first, and that failure is both higher fidelity and earlier than the success. The second is to treat
this as reconfiguration: AWS states plainly that a trail can be updated while running, so there is
no such reading. The third is to conclude the account went dark: where a management-account
organization trail covers it, a member account cannot alter that trail at all and coverage
continues. The fourth is to restart logging and consider it handled — nothing recorded during the
gap is recoverable, which is the entire point of the technique.

**Detection thesis:** alert on the attempt as well as the act, rate the act above its own symptom,
and resolve "did we actually go dark" against the trail inventory rather than against the event.

**Adjacent playbooks.** The trail removed rather than paused is `../cloudtrail.impact.trail-deleted/`.
Selectors narrowed while logging continues is `../cloudtrail.stealth.trail-modified/`. The
downstream symptom is `../cloudtrail.stealth.no-logs-received/`, and reading the configuration
beforehand is `../cloudtrail.discovery.audit-configuration-accessed/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

An **organization trail owned by the management account**. This is the single control that makes the
technique fail rather than succeed: AWS states that member-account users *"will not have sufficient
permissions to delete organization trails, turn logging on or off, change what types of events are
logged, or otherwise alter organization trails in any way."* With one in place, a compromised member
account produces a refused attempt instead of a gap.

A recorded trail inventory — name, `HomeRegion`, `IsMultiRegionTrail`, `IsOrganizationTrail`,
destination bucket — because none of that is in the `StopLogging` event and all of it decides the
blast radius.

**Independent logs that survive a CloudTrail gap.** VPC flow logs, S3 server access logs, ALB access
logs, GuardDuty findings and CloudWatch metrics all continue while a trail is stopped, and they are
the only way to reconstruct the window. Knowing in advance which of them you have is the difference
between a partial reconstruction and none.

Awareness that a **single-Region trail outside `us-east-1` never received IAM or STS events**. AWS
records global service events in `us-east-1` and delivers them only to single-Region trails there.
That gap predates any incident and a coverage review that only confirms a trail exists will miss it.

**Alerting (must be pre-configured)**

- **`StopLogging` succeeds → P0**
- **`StopLogging` refused with `InvalidHomeRegionException` — the caller was guessing which Region owns the trail → P0**
- **`StopLogging` succeeds and `StartLogging` follows from the same principal within 24h → P0**

**Response Tooling**

An IAM principal that can call `cloudtrail start-logging`, `describe-trails` and `get-trail-status`
outside the change pipeline, **in every Region** — the home Region of the affected trail may not be
the one the responder is working in.

CloudTrail log file integrity validation enabled, so that the digest files can establish whether the
delivered log files for the surrounding period are complete and unmodified.

**Known IOC Baselines**

The roles that legitimately manage CloudTrail, if any. In most estates the correct list is empty
outside the deployment pipeline, and an empty list is a strong baseline.

The set of independent log sources per workload, mapped to what they can and cannot reconstruct.
Assembling that during an incident wastes the window.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `StopLogging` succeeds on any trail | CloudTrail | T1685.002 |
| P0 | `StopLogging` refused with `InvalidHomeRegionException` — AWS accepts this call only in the trail's home Region and never on a shadow trail, so the caller was guessing | CloudTrail | T1685.002 |
| P0 | `StopLogging` succeeds and `StartLogging` follows from the same principal within 24h — the end state is correct and only the history holds the gap | Correlation rule | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `StopLogging` refused with `NotOrganizationMasterAccountException` — a member-account principal tried to silence a trail it cannot alter | CloudTrail | T1685.002 |
| P2 | `StopLogging` refused with `TrailNotFoundException` — the caller was enumerating trail names | CloudTrail | T1654 |
| P2 | `StopLogging` on a trail that was already stopped — no change, but the intent is identical | CloudTrail | T1685.002 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `NOT _exists_:errorCode` drops every failed attempt | AWS refuses `StopLogging` outside the trail's home Region and on shadow trails entirely, so an actor who is guessing fails first. That failure is higher fidelity than the success, and it arrives while visibility is still intact | A second rule on the diagnostic error codes, at high — `InvalidHomeRegionException`, `NotOrganizationMasterAccountException`, `TrailNotFoundException`, `AccessDenied` |
| Rated P2, below its own symptom | The same pack rates "No Logs From AWS CloudTrail" at P1. That is the consequence of this event, it arrives later, and it is not actionable in the way the cause is | Critical. AWS: *"there is no need to use this action. You can update a trail without stopping it first"* — there is no benign reading to hedge against |
| No organization-trail context | Whether the account actually went dark depends on whether a management-account organization trail also covers it, which member accounts cannot alter. The event is identical either way | Resolved in §2 Query 2 against `describe-trails`, and stated in the rule rather than assumed |
| No pairing with `StartLogging` | A stop followed by a start restores the expected configuration, so every state-based check passes afterwards and only the event history holds the gap | A `temporal_ordered` correlation over 24h, grouped by principal, with the gap length computed |
| No principal dimension | In most estates nothing outside the deployment pipeline should call this at all, which makes an allowlist unusually cheap and unusually effective | Left to deployment: the correct baseline is usually an empty list, and any hit is then a finding |

**Recommended detection — the act, the refused attempt, and the pair that hides the gap.**

```yaml
# CloudTrail logging stopped (T1685.002)
#
# THE SOURCE RULE FILTERS ON SUCCESS AND THROWS AWAY THE BETTER SIGNAL. AWS refuses StopLogging
# outside the trail's home Region and refuses it on shadow trails entirely, so an actor who does not
# already know the home Region fails first — higher fidelity than the success, and earlier.
#
# AWS also states "there is no need to use this action. You can update a trail without stopping it
# first", so there is no benign reconfiguration reading. And whether the account actually went dark
# is not in the event: member accounts cannot alter an organization trail at all.
# Full rationale: detections/detection_note_t1685_002.md.
title: CloudTrail logging stopped
id: 6d4a08f9-15c3-4e72-b806-2f95a7c1e34b
name: cloudtrail_stop_logging
status: experimental
description: >-
  A successful StopLogging. AWS states this is the only way to stop recording and that there is
  normally no reason to use it, since a trail can be updated while running — so there is no
  benign-reconfiguration reading. Whether the account actually went dark depends on whether an
  organization trail also covers it, which this event does not carry.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName: 'StopLogging'
  success:
    errorCode: null
  condition: selection and success
falsepositives:
  - >-
    A trail being decommissioned, where the DeleteTrail that follows within minutes is the
    corroborating evidence. Its absence is what makes a lone stop worth waking someone for.
level: critical
---
title: CloudTrail StopLogging attempted and refused
id: 3f70b621-9c8e-4d45-a1f2-570e8ba3d69c
name: cloudtrail_stop_logging_refused
status: experimental
description: >-
  A StopLogging that failed. The error code says what the caller did not know. InvalidHomeRegion
  means they were guessing which Region owns the trail — AWS refuses the call anywhere but the home
  Region and refuses it on shadow trails entirely. NotOrganizationMasterAccount means a member
  account tried to silence an organization trail it cannot touch. TrailNotFound means they were
  enumerating names. All three are an actor working out how to go dark, before they manage it, and
  all three are dropped by any rule filtering on success.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName: 'StopLogging'
  diagnostic_errors:
    errorCode:
      - 'InvalidHomeRegionException'
      - 'NotOrganizationMasterAccountException'
      - 'TrailNotFoundException'
      - 'AccessDenied'
      - 'InsufficientDependencyServiceAccessPermissionException'
  condition: selection and diagnostic_errors
falsepositives:
  - >-
    A cross-Region automation loop that calls StopLogging in every Region and expects most calls to
    fail. That is a real pattern and a bad one; allowlist the role rather than dropping the rule,
    because it is also exactly what an actor probing for the home Region looks like.
level: high
---
title: CloudTrail logging stopped and restarted by the same principal
id: b8e51de0-247a-4c96-83b7-e0d4f1a62c58
status: experimental
description: >-
  A principal stopped logging and started it again. The end state is correct, which is the problem —
  every state-based check passes and only the event history holds the gap. The interval between the
  two events is the window in which nothing was recorded, and reconstructing what happened inside it
  is not possible from CloudTrail by definition.
references:
  - https://attack.mitre.org/techniques/T1685/002/
  - https://attack.mitre.org/techniques/T1070/
tags:
  - attack.defense-evasion
  - attack.t1685.002
  - attack.t1070
correlation:
  type: temporal_ordered
  rules:
    - cloudtrail_stop_logging
    - cloudtrail_start_logging
  group-by:
    - userIdentity.arn
  timespan: 24h
falsepositives:
  - >-
    A maintenance window that legitimately stops and restarts a trail. AWS states a trail can be
    updated without stopping it, so this should be rare enough to allowlist by role rather than to
    tune away by shortening the timespan.
level: critical
---
title: CloudTrail logging started
id: 92c7f38a-b046-4e51-9d38-7ab150ce62f4
name: cloudtrail_start_logging
status: experimental
description: >-
  Base rule — correlation component and change accounting, never for direct alerting. A successful
  StartLogging. On its own this is a trail being turned on, which is a good thing happening.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StartLogging.html
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName: 'StartLogging'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: it cannot recover anything that happened while logging was
stopped. That is not a limitation of the rules, it is the definition of the technique, and the
reconstruction in §4 works from log sources outside CloudTrail for exactly that reason.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

Run Query 1 first; it establishes the gap that the rest of the playbook is scoped to.

#### Query 1 — Reconstruct: the stop, the attempts, and whether it was restarted

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in StopLogging StartLogging DeleteTrail UpdateTrail PutEventSelectors; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      # Failures are NOT filtered out. AWS refuses StopLogging outside the trail'"'"'s home Region and
      # on shadow trails, so a refusal means the caller was guessing — earlier and higher fidelity
      # than the success a success-only rule waits for.
      | (.errorCode // "none") as $err
      | (if $err == "InvalidHomeRegionException" then "REFUSED(wrong region — caller was guessing)"
         elif $err == "NotOrganizationMasterAccountException" then "REFUSED(org trail — member account)"
         elif $err == "TrailNotFoundException" then "REFUSED(enumerating trail names)"
         elif $err != "none" then "REFUSED(\($err))"
         else "OK" end) as $outcome
      | "\(.eventTime)  \(.eventName)  \($outcome)  \(.userIdentity.arn)  " +
        "trail=\(.requestParameters.name // "-")  region=\(.awsRegion)  ip=\(.sourceIPAddress)"'
done | sort
```

Read this as a sequence. A run of `REFUSED(wrong region...)` followed by an `OK StopLogging` is an
actor working out the home Region and then succeeding — and the refusals are timestamped before the
gap opens, which is the only period in which the response has full visibility. A `StartLogging`
after the stop bounds the gap; its absence means the gap is still open.

#### Query 2 — Establish what coverage actually remained

```bash
echo "=== Every trail visible from this account, including shadows ==="
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null); do
  aws cloudtrail describe-trails --include-shadow-trails --region "$R" --output json 2>/dev/null \
  | jq -r --arg r "$R" '.trailList[]
      | "\($r)  \(.Name)  org=\(.IsOrganizationTrail)  multiregion=\(.IsMultiRegionTrail)  " +
        "home=\(.HomeRegion)  globalevents=\(.IncludeGlobalServiceEvents)  bucket=\(.S3BucketName)"'
done | sort -u

echo
echo "=== Which of them are actually logging right now ==="
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null); do
  aws cloudtrail describe-trails --region "$R" --query 'trailList[].TrailARN' --output text 2>/dev/null \
  | tr '\t' '\n' | while read -r T; do
      [ -z "$T" ] && continue
      S="$(aws cloudtrail get-trail-status --name "$T" --region "$R" \
             --query 'IsLogging' --output text 2>/dev/null)"
      [ "$S" = "True" ] && echo "[OK] $T logging" || echo "[FAIL] $T NOT logging"
    done
done | sort -u
```

This is the query that decides how bad the incident is, and it is not answerable from the event.
An `org=True` trail still logging means the account was never dark — a member account cannot alter
an organization trail, so the stop hit an account-level trail and the organization's copy carried
on. If every remaining trail is `multiregion=False` with a `home` outside `us-east-1`, then **IAM
and STS activity was never being delivered anywhere**, before this incident and independently of it.

#### Query 3 — Reconstruct the gap from sources CloudTrail does not control

```bash
GAP_START="${1:?gap start timestamp from Query 1 required}"
GAP_END="${2:?gap end timestamp, or now}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== GuardDuty findings inside the gap (independent of CloudTrail delivery) ==="
DET="$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text 2>/dev/null)"
if [ -n "$DET" ] && [ "$DET" != "None" ]; then
  aws guardduty list-findings --detector-id "$DET" --region "$REGION" \
    --finding-criteria "{\"Criterion\":{\"updatedAt\":{\"GreaterThanOrEqual\":$(date -u -d "$GAP_START" +%s000 2>/dev/null || echo 0)}}}" \
    --query 'FindingIds' --output text 2>/dev/null | head -20
else
  echo "[!] no GuardDuty detector in $REGION — one fewer independent source"
fi

echo
echo "=== Other sources that keep running while a trail is stopped ==="
echo "  VPC flow logs        — network movement, but not API calls"
echo "  S3 server access logs— object access on buckets that had it enabled"
echo "  ALB / CloudFront logs— inbound request history"
echo "  Config configuration items — resource STATE changes, which is often enough to infer the call"
echo "  CloudWatch metrics   — invocation counts, error rates, unusual volume"
aws configservice describe-configuration-recorder-status --region "$REGION" \
  --query 'ConfigurationRecordersStatus[].[name,recording]' --output text 2>/dev/null \
  || echo "[!] AWS Config not recording in $REGION"
```

AWS Config is the most useful of these and the most often forgotten. It records resource *state*
rather than API calls, so a change made during the gap still shows up as a configuration item with a
timestamp — which frequently identifies what was done even though the call itself was never logged.

#### Query 4 — Full session reconstruction of the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 1 required}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

# For an assumed role the CloudTrail username is the SESSION name: the second slash-separated
# segment after `assumed-role/`, not the role name and not the last segment.
case "$PRINCIPAL" in
  *:assumed-role/*) LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $2}')" ;;
  *)                LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')" ;;
esac

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$LOOKUP" \
  --start-time "$START" --region "$REGION" --max-results 200 \
  --query 'Events[].[EventTime,EventName,EventSource]' --output text 2>/dev/null | sort
```

Look for `DescribeTrails`, `GetTrailStatus` and `GetEventSelectors` **before** the stop. Reading the
logging configuration is how an actor finds the home Region, and it is covered by its own use case
in `../cloudtrail.discovery.audit-configuration-accessed/`.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restart logging first. It is one call, it is not destructive, and every minute it is deferred is
another minute with no audit record — including of the response itself.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 2 shows no trail
logging anywhere, the account is fully dark and the response is being conducted without an audit
trail. Restart logging before investigating, accept that the first minutes of the response will be
unrecorded, and note that in the timeline.

#### Step 1 — Restart logging, in the trail's home Region

```bash
TRAIL="${1:?trail name or ARN from Query 1 required}"
HOME_REGION="${2:?the HomeRegion of the trail, from Query 2, required}"

# StopLogging and StartLogging both require the trail's HOME Region for a multi-Region trail, and
# neither can be called on a shadow trail. Running this in the wrong Region fails with
# InvalidHomeRegionException — the same error the actor hit.
aws cloudtrail start-logging --name "$TRAIL" --region "$HOME_REGION" \
  && echo "[OK] logging restarted on $TRAIL in $HOME_REGION" \
  || echo "[FAIL] check that $HOME_REGION is the trail's home Region and that this is not a shadow trail"

aws cloudtrail get-trail-status --name "$TRAIL" --region "$HOME_REGION" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json 2>/dev/null
```

`LatestDeliveryError` is worth reading here even when `IsLogging` is true. A trail can be logging and
failing to deliver — a bucket policy change, a KMS key change — and that failure produces the same
downstream silence as a stop while looking healthy in every summary view.

#### Step 2 — Contain the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 1 required}"

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

Containing the principal is unusually clear-cut here. Unlike a bucket policy or a security group,
there is no operational workflow that legitimately calls `StopLogging`, so the risk of halting
something important by revoking this principal's access is lower than in most playbooks.

#### Step 3 — Preserve the delivered logs and validate their integrity

```bash
TRAIL="${1:?trail name required}"
HOME_REGION="${2:?home Region required}"
BUCKET="$(aws cloudtrail describe-trails --trail-name-list "$TRAIL" --region "$HOME_REGION" \
           --query 'trailList[0].S3BucketName' --output text 2>/dev/null)"

echo "Trail delivers to: ${BUCKET:-unknown}"

# If log file validation was enabled, the digest files establish whether the delivered files around
# the gap are complete and unmodified — which is a different question from whether they exist.
VALID="$(aws cloudtrail describe-trails --trail-name-list "$TRAIL" --region "$HOME_REGION" \
          --query 'trailList[0].LogFileValidationEnabled' --output text 2>/dev/null)"
if [ "$VALID" = "True" ]; then
  echo "[OK] log file validation is enabled — validate the surrounding period:"
  echo "    aws cloudtrail validate-logs --trail-arn <arn> --start-time <gap-start> --region $HOME_REGION"
else
  echo "[!] log file validation is NOT enabled — you cannot prove the delivered files are complete"
  echo "    or unmodified, only that they are present. Enable it in §4."
fi
```

#### Step 4 — Check whether the trail was the only one

```bash
# A stop on one trail matters far less if another still covers the same events. Query 2 listed
# them; this reduces that to the single question the report needs to answer.
COVERED=0
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null); do
  aws cloudtrail describe-trails --include-shadow-trails --region "$R" --output json 2>/dev/null \
  | jq -r '.trailList[] | select(.IsOrganizationTrail == true) | .TrailARN' 2>/dev/null
done | sort -u | while read -r T; do
    [ -n "$T" ] && { echo "[OK] organization trail present: $T"; COVERED=1; }
  done
[ "$COVERED" -eq 0 ] && echo "[!] no organization trail found — account-level trails are the only coverage"
```

---

## 4. Eradication

### Remove Attacker Access

#### Establish the gap and state it as a gap

The window runs from the successful `StopLogging` to the `StartLogging` that ended it, or to Step 1
if none did. Nothing that happened inside it is in CloudTrail, and nothing will put it there. The
report should give the interval explicitly and say what was reconstructed from where — Config
items, GuardDuty findings, flow logs — rather than presenting a partial reconstruction as complete.

Where Query 2 found an organization trail still logging, say that too: the gap may be much smaller
than the event suggests, and that is worth as much as the reverse finding.

#### Create the organization trail if there is not one

This is the eradication step that generalises, because it turns the technique from a success into a
refused attempt. A management-account organization trail cannot be stopped, deleted or narrowed from
a member account by anyone, regardless of their IAM permissions in that account.

#### Deny the operation outside a break-glass path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyCloudTrailTampering",
  "Effect": "Deny",
  "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
             "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors"],
  "Resource": "*",
  "Condition": {"ArnNotLike": {"aws:PrincipalARN": "arn:aws:iam::*:role/YourBreakGlassRole"}}
}
```

Attach it to an OU, not the management account, where SCPs do not apply. `YourBreakGlassRole` must
be a role that genuinely exists — an `ArnNotLike` against a non-existent role denies the action to
everyone including you. Test in a non-production OU first.

#### Enable log file validation and multi-Region coverage

Two configuration changes close the gaps this incident exposed. **Log file validation** lets you
prove the delivered files are complete and unmodified rather than merely present. **Multi-Region**
on at least one trail is what makes IAM and STS events visible at all: AWS records those in
`us-east-1` and delivers them only to single-Region trails there, so a single-Region trail elsewhere
was blind to them before anyone stopped anything.

---

## 5. Recovery

### Restore Clean State

#### Verify every trail is logging and delivering

```bash
FAIL=0
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null); do
  aws cloudtrail describe-trails --region "$R" --query 'trailList[].TrailARN' --output text 2>/dev/null \
  | tr '\t' '\n' | while read -r T; do
      [ -z "$T" ] && continue
      aws cloudtrail get-trail-status --name "$T" --region "$R" --output json 2>/dev/null \
      | jq -r --arg t "$T" '
          if .IsLogging != true then "[FAIL] \($t) is not logging"
          elif (.LatestDeliveryError // "") != "" then "[FAIL] \($t) logging but delivery failing: \(.LatestDeliveryError)"
          else "[OK] \($t) logging, last delivery \(.LatestDeliveryTime // "unknown")" end'
    done
done | sort -u
```

`IsLogging` alone is not recovery. A trail can be logging and failing to deliver — a bucket policy
change or a KMS key change produces exactly the same downstream silence as a stop, while every
summary view shows the trail as healthy.

#### Verify the guardrails that make this fail next time

```bash
echo "=== Is there an organization trail? ==="
aws cloudtrail describe-trails --include-shadow-trails --output json 2>/dev/null \
| jq -r 'if ([.trailList[] | select(.IsOrganizationTrail == true)] | length) > 0
         then "[OK] organization trail present — member accounts cannot stop, delete or narrow it"
         else "[FAIL] no organization trail — this technique will succeed again" end'

echo "=== Is at least one trail multi-Region with global events? ==="
aws cloudtrail describe-trails --include-shadow-trails --output json 2>/dev/null \
| jq -r 'if ([.trailList[] | select(.IsMultiRegionTrail == true and .IncludeGlobalServiceEvents == true)] | length) > 0
         then "[OK] IAM and STS events are being delivered"
         else "[FAIL] no multi-Region trail with global events — IAM and STS activity is invisible" end'

echo "=== Is log file validation enabled? ==="
aws cloudtrail describe-trails --output json 2>/dev/null \
| jq -r '.trailList[] | if .LogFileValidationEnabled == true
         then "[OK] \(.Name) validated" else "[FAIL] \(.Name) has no log file validation" end'
```

#### Confirm the corrected detection fires

```bash
TRAIL="${1:?a NON-PRODUCTION trail name required}"
WRONG_REGION="${2:-eu-west-1}"

# Exercise the REFUSED path, not the successful one: it is the half the source rule could not see,
# and it proves the detection without stopping any logging at all. AWS refuses StopLogging outside
# the trail's home Region, so this is safe by construction.
aws cloudtrail stop-logging --name "$TRAIL" --region "$WRONG_REGION" 2>&1 \
  | grep -qi 'InvalidHomeRegion' \
  && echo "[OK] refused with InvalidHomeRegionException — expect the high-severity refused-attempt rule within 15 min" \
  || echo "[!] did not get InvalidHomeRegionException — check that $WRONG_REGION is not the home Region"
```

That test is the reason the refused-attempt rule is worth having: it can be exercised safely on any
schedule, in any account, without ever suspending a trail.

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Were there refused attempts before the successful one? | They are timestamped before the gap opened, and they are the earliest point at which this was detectable. If they exist and nothing fired, the success-only filter is the finding. |
| Was an organization trail in force? | If yes, the account was never dark and the incident is an attempt. If no, that is the recommendation that matters most. |
| Was the affected trail multi-Region with global events? | If not, IAM and STS were already invisible before the stop, and the pre-existing gap is larger than the one this created. |
| How long was the gap, and what independently logged sources covered it? | This is the whole content of the report. A gap with Config recording is very different from one without. |
| Was log file validation enabled? | Decides whether the surrounding logs can be shown to be complete, or only to be present. |
| Did the principal read the logging configuration first? | `DescribeTrails` and `GetTrailStatus` are how the home Region is found, and they are an earlier signal still. |

### Recommended Guardrails

**Create a management-account organization trail.** It is the only control that makes this technique
fail rather than succeed, because member accounts cannot alter one regardless of their IAM
permissions. Everything else here is detection; this is prevention.

**Alert on refused attempts, not only on successes.** The wrong-Region refusal is high fidelity, it
is free, and it arrives before visibility is lost. A rule that filters on `errorCode` absent is
choosing the later, weaker signal.

**Rate the cause above the symptom.** "No logs received" at P1 with "logging stopped" at P2 inverts
the order in which a responder can still act. By the time the absence is noticed the gap is already
open; the stop is the moment intervention is cheap.

**Make at least one trail multi-Region with `IncludeGlobalServiceEvents`.** Without it, IAM and STS
activity is not delivered to any trail outside `us-east-1`, which silently undermines every
identity-focused detection in the estate.

**Enable log file validation everywhere.** It costs nothing and it converts "the logs are present"
into "the logs are complete and unmodified", which is the claim an incident report actually needs.

### Technique Reference

**T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log.** Verified live at
https://attack.mitre.org/techniques/T1685/002/ on 2026-08-30.

**T1070 — Indicator Removal** is tagged on the stop-then-start correlation: restoring the trail to
its expected state is what makes a configuration review show nothing wrong. Verified live 2026-08-30.

AWS references relied on throughout, all verified 2026-08-30:

- `StopLogging` API reference — the home-Region constraint, the shadow-trail restriction, the
  "no need to use this action" statement, and the full error list:
  https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html
- CloudTrail concepts — organization trails and member-account permissions, global service event
  handling, and the four event types:
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html

Service-wide verified behaviour shared by every `cloudtrail.*` playbook is in
`../_ground-truth/cloudtrail.md`.

### Residual Risk

**The gap is unrecoverable, permanently.** Nothing recorded during a stop can be retrieved, and no
amount of preparation changes that. What preparation changes is how much can be reconstructed from
elsewhere, which is why §1's inventory of independent log sources is the substantive control.

**Delivery can fail while the trail reports as logging.** A bucket policy change, a KMS key
disabled, or an S3 lifecycle rule produces the same downstream silence as a stop with none of the
events. `LatestDeliveryError` is the only field that distinguishes them, and no rule here watches
it — that belongs to `../cloudtrail.stealth.no-logs-received/`.

**An account-level trail can be stopped even where an organization trail exists.** The organization
trail keeps delivering, so coverage continues, but any downstream tooling keyed to the account
trail's bucket goes quiet. The incident is smaller than it looks and the operational disruption may
not be.

**Log file validation proves integrity, not completeness of intent.** A digest confirms the
delivered files are unmodified. It cannot show that a trail was configured to capture the events you
assumed it was capturing — that is a selector question, and it belongs to
`../cloudtrail.stealth.trail-modified/`.
