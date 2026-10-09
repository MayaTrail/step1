# IR Playbook: CloudTrail Trail Deleted — `cloudtrail:DeleteTrail` Removes the Audit Trail and Its Configuration

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment (a trail is permanently removed; from that moment nothing is delivered by it, and its configuration can only be recovered from earlier events) |
| Threat Actor | N/A — single technique, not actor-attributed (Stratus Red Team `aws.defense-evasion.cloudtrail-delete`) |
| Platform | aws |
| Severity | High. Raise to Critical when the deleted trail was the account's only multi-Region trail, when it carried data events, or when the same principal acts on IAM, KMS or data stores after the delete |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | CloudTrail, S3 (log bucket), IAM, STS, GuardDuty, AWS Config, Security Hub, Organizations (SCP) |

**What the technique does:** the actor calls `cloudtrail:DeleteTrail`. Delivery stops at once and,
unlike `StopLogging`, there is nothing to switch back on: the trail's event selectors, destination
bucket and prefix, KMS key, CloudWatch Logs integration and Region scope are gone. Log files already
delivered stay in the bucket — the delete does not touch S3 — so history up to the delete survives
and the record from that moment on does not.

**How this emulation runs it.** The tenant's connected role assumes the lab role
`stratus-red-team-ct-delete-attacker-role` (session `atomic-t1685002-ct-delete`), whose inline
policy allows only `cloudtrail:GetTrail` and `cloudtrail:DeleteTrail` on the ARN of
`stratus-red-team-ct-delete-trail`, a single-Region management-event trail the stack created with
its own bucket. The role reads the trail with `GetTrail` (target confirmation — it learns the
bucket the logs go to) and deletes it. There is no revert; the stack's destroy removes the leftover
bucket. Events produced: `AssumeRole`, `GetTrail`, `DeleteTrail`.

**Why the usual reflexes miss it.** Deletion is louder than a stop, and it is caught more often —
but three things still go wrong. The GuardDuty finding AWS documents for it,
`Stealth:IAMUser/CloudTrailLoggingDisabled`, is default severity **Low**, so it is triaged with the
other Lows. Posture checks (AWS Config, Security Hub CloudTrail.1/CloudTrail.3) evaluate on a
schedule and fail only if the deleted trail was the one that satisfied them; an account with two
trails stays compliant while the one carrying data events disappears. And recovery from IaC
restores the trail without anyone writing down what the window lost.

**Detection thesis:** alert on `DeleteTrail` itself, with no `errorCode` filter — a refused delete
is an attacker discovering that the trail is protected. Use the trail's last
`CreateTrail`/`UpdateTrail` event to reconstruct what was lost (data events or not, which Regions,
which bucket), and CloudTrail Event history — which AWS describes as separate from any trails —
to recover the management events of the gap.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **An organization trail** owned by the management account. Member accounts can see it but
  cannot delete it; a `DeleteTrail` against it from a member account fails with
  `NotOrganizationMasterAccountException`.
- **Event history** keeps 90 days of management events per Region independently of any trail. It
  is the fallback for the gap; it does not contain data events.
- **CloudTrail retention long enough to keep the trail's `CreateTrail`/`UpdateTrail` events.**
  After a delete, `GetTrail` and `DescribeTrails` return nothing; those events are the only record
  of what the trail covered.
- **Log bucket protection.** The delete does not touch the bucket, but an actor who deletes the
  trail often goes after the files next. S3 Object Lock or replication to a log-archive account
  keeps them.

**Alerting (must be pre-configured)**
- **`DeleteTrail`, any outcome → P1**, raised to **P0** for the only multi-Region trail or any
  trail with data event selectors.
- **`UpdateTrail` turning a trail single-Region, dropping global service events or disabling log
  file validation → P2** (shipped as the second Sigma document).

**Response Tooling**
- Break-glass credentials with `cloudtrail:CreateTrail`, `cloudtrail:StartLogging`,
  `cloudtrail:PutEventSelectors`, `cloudtrail:LookupEvents`, `iam:PutRolePolicy`.
- The trail definition in IaC, so recreation is a deploy rather than a reconstruction.

**Known IOC Baselines**
- Principals that have ever called `DeleteTrail` (normally only the IaC role during teardown).
- The trail inventory: name, home Region, multi-Region flag, data event selectors, bucket.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `DeleteTrail` succeeding on the only multi-Region trail or a data-event trail | CloudTrail (management) / Event history | T1685.002 |
| P1 | `DeleteTrail`, any outcome, from a principal not on the trail-admin list | CloudTrail (management) | T1685.002 |
| P1 | `DeleteTrail` refused with `NotOrganizationMasterAccountException` or an access-denied code | CloudTrail (management) | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `UpdateTrail` with `isMultiRegionTrail: false`, `includeGlobalServiceEvents: false` or `enableLogFileValidation: false` | CloudTrail (management) | T1685.002 |
| P2 | `GetTrail` / `DescribeTrails` from a principal that does not administer logging, shortly before any trail change | CloudTrail (management) | T1685.002 |
| P2 | GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled` (default severity Low) | GuardDuty | T1685.002 |
| P3 | Security Hub CloudTrail.1 / CloudTrail.3 failing | Security Hub / Config | T1685.002 |

### Detection Rule Quality Notes

| Issue | Impact | Correction |
|-------|--------|-----------|
| The generated rule covered only `DeleteTrail` | Weakening a trail in place (single-Region, no global events, no validation) leaves `IsLogging: true` and no delete event | Second document on `UpdateTrail` with the three weakening flags, at medium so the package's display rule stays the delete |
| No record of what was lost | Responders recreate "a trail" rather than *the* trail | The KQL recovers the last bucket, Region scope and KMS key from the latest `CreateTrail`/`UpdateTrail`, and reports whether a trail of the same name came back |
| Success filtering considered | A refused delete would be hidden | Deliberately no `errorCode` filter on the primary rule |

### Key Investigation Queries

> Run in the trail's **home Region** — `DeleteTrail` is only accepted there.

#### Query 1 — Is the trail gone?

```bash
TRAIL="<trail_name>"
aws cloudtrail get-trail-status --name "$TRAIL"
```

`TrailNotFoundException` means deleted (or never existed under that name in this Region).
Confirm with Query 4 before concluding.

#### Query 2 — Who deleted it, when, and was it refused

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteTrail \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,Username,CloudTrailEvent]' --output json
```

From `CloudTrailEvent` record `userIdentity.arn`, `userIdentity.accessKeyId`, `sourceIPAddress`,
`userAgent`, `requestParameters.name` and `errorCode`. A populated `errorCode` is a refused attempt
— the trail is intact, but the principal is hostile. An empty result is not proof of absence:
check the Region and the `cloudtrail:LookupEvents` permission.

#### Query 3 — What the trail was (its last configuration)

```bash
TRAIL="<trail_name>"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$TRAIL" \
  --start-time "$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,EventName,CloudTrailEvent]' --output json
```

The latest `CreateTrail` / `UpdateTrail` / `PutEventSelectors` events carry the configuration that
the delete erased: `s3BucketName`, `isMultiRegionTrail`, `kmsKeyId`, `cloudWatchLogsLogGroupArn`,
and the event selectors. If the trail is older than 90 days and your SIEM does not hold these
events, the IaC definition is the only source. If `ResourceName` returns nothing, filter Query 2's
window by `EventSource` instead — not every CloudTrail event populates the resource name.

#### Query 4 — What still records this account

```bash
aws cloudtrail describe-trails --include-shadow-trails \
  --query 'trailList[].[Name,HomeRegion,IsMultiRegionTrail,IsOrganizationTrail,S3BucketName]' --output table
```

If another multi-Region trail (or an organization trail) is listed and logging, it covered the gap,
data events excepted unless it also selects them. If nothing is listed, the account has no trail at
all and Event history is the only record from the delete onward.

#### Query 5 — What the principal did after the delete

```bash
SESSION="<session-name-or-user-from-Query-2>"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION" \
  --start-time "$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,EventSource,EventName]' --output table
```

For an assumed role `Username` is the session name (`atomic-t1685002-ct-delete` for this
emulation). A `GetTrail` immediately before the delete is the target confirmation this emulation
performs. Activity after the delete is the reason for it.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Contain the principal first

```bash
ROLE="<role-name-from-Query-2>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyDenyTrailTampering \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["cloudtrail:DeleteTrail","cloudtrail:StopLogging","cloudtrail:UpdateTrail","cloudtrail:PutEventSelectors","s3:PutLifecycleConfiguration","s3:DeleteObject"],"Resource":"*"}]}'
```

Containment precedes recreation here: recreating a trail the principal can delete again buys
nothing. For an IAM user, deactivate the access keys and attach the same deny as a user policy.

#### Step 2 — Recreate the trail from its recorded configuration

```bash
TRAIL="<trail_name>"; BUCKET="<bucket_name>"
aws cloudtrail create-trail --name "$TRAIL" --s3-bucket-name "$BUCKET" --is-multi-region-trail --enable-log-file-validation
aws cloudtrail start-logging --name "$TRAIL"
```

`CreateTrail` does not start logging; `StartLogging` does. Re-apply the event selectors and KMS
key recovered in Query 3 (`put-event-selectors`, `update-trail --kms-key-id`) — a recreated trail
with default selectors silently drops the data events the old one carried. Prefer an IaC deploy
when one exists.

#### Step 3 — Preserve the gap from Event history

```bash
GAP_START="<delete-time-from-Query-2>"; GAP_END="<recreate-time>"
aws cloudtrail lookup-events --start-time "$GAP_START" --end-time "$GAP_END" --output json > gap-events.json
```

Paginate on `NextToken` until it is empty. Event history keeps 90 days.

#### Step 4 — Protect the existing log files

Run `aws s3api get-bucket-lifecycle-configuration --bucket <bucket_name>` and
`aws s3api get-bucket-policy --bucket <bucket_name>`. A new expiration rule or a policy change on
the log bucket after the delete is the next step of the same intrusion — see the CloudTrail
lifecycle-rule playbook.

---

## 4. Eradication

### Remove Attacker Access

- Trace the session back to its source identity (`AssumeRole` events for the role ARN) and contain
  that identity as well.
- Remove `cloudtrail:DeleteTrail` from every principal that does not own trail lifecycle.

### Prevent recurrence

- Attach the **`Protect-security-services-from-tampering`** SCP from the guardrail catalogue. It
  denies `cloudtrail:DeleteTrail`, `StopLogging`, `UpdateTrail`, `PutEventSelectors` and
  `CreateTrail` except for named administrative roles; replace its sample exception list with your
  own roles before attaching it.
- Move logging to an organization trail and a log-archive account bucket.

### Remove the emergency policies once clean

```bash
ROLE="<role-name-from-Query-2>"
aws iam delete-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions
aws iam delete-role-policy --role-name "$ROLE" --policy-name EmergencyDenyTrailTampering
aws iam list-role-policies --role-name "$ROLE"
```

---

## 5. Recovery

### Restore Clean State

#### Confirm the recreated trail is logging and complete

```bash
TRAIL="<trail_name>"
aws cloudtrail get-trail-status --name "$TRAIL"
```

`IsLogging: true` and a `LatestDeliveryTime` advancing within 15 minutes. Then
`aws cloudtrail get-event-selectors --trail-name <trail_name>` must match the selectors recovered
in Query 3.

#### Backfill and record the loss

Load `gap-events.json` into the SIEM, tagged as recovered from Event history. Record in the
incident that data events for the gap are not recoverable.

#### Confirm the corrected detection fires

```text
MUST fire on:     DeleteTrail / cloudtrail.amazonaws.com, with or without errorCode -> high.
                  UpdateTrail with isMultiRegionTrail, includeGlobalServiceEvents or
                  enableLogFileValidation set to false -> medium.
MUST NOT fire on: GetTrail / DescribeTrails / GetTrailStatus reads; an UpdateTrail that only
                  changes the KMS key or bucket prefix.
EXPECTED FP:      the IaC role tearing down a trail it owns - allowlist the role ARN.
```

Running this emulation is the test: `GetTrail` then `DeleteTrail` from session
`atomic-t1685002-ct-delete`.

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| One call removed the trail | `cloudtrail:DeleteTrail` held by a principal that does not own logging; no SCP |
| The loss went unmeasured | No inventory of what each trail covered; the configuration died with the trail |
| The GuardDuty finding did not page | Default severity Low |

### Recommended Guardrails

- **Catalogue match:** `Protect-security-services-from-tampering` (SCP, conditional on
  `aws:PrincipalARN` exceptions) denies `cloudtrail:DeleteTrail`.
- **Structural:** an organization trail plus a log-archive bucket with Object Lock, so no single
  member-account principal can remove the record or its history.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log |
| Primary API | `cloudtrail:DeleteTrail` (`requestParameters.name` = trail name or ARN) |
| Preceding API in this emulation | `cloudtrail:GetTrail` (same parameter) |
| Event source | `cloudtrail.amazonaws.com`, management event, trail home Region |
| Errors worth reading | `NotOrganizationMasterAccountException`, `InvalidHomeRegionException`, `TrailNotFoundException`, access-denied codes from an SCP or IAM deny |
| Surviving evidence | Log files already in the bucket, Event history (90 days, management events), earlier `CreateTrail`/`UpdateTrail` events |
| Lab identity | Role `stratus-red-team-ct-delete-attacker-role`, session `atomic-t1685002-ct-delete`, trail `stratus-red-team-ct-delete-trail` |

### Residual Risk

Data events between the delete and the recreation are permanently lost, and a recreated trail is
only as complete as the configuration you could recover for it. If the trail's
`CreateTrail`/`UpdateTrail` events have aged out of retention and no IaC definition exists, the
event selectors it carried are unknown and the recreated trail may cover less than the original
without anyone noticing.
