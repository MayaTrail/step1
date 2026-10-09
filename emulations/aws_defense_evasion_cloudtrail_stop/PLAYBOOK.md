# IR Playbook: CloudTrail Trail Stopped — `cloudtrail:StopLogging`, a Gap in the Audit Log, and a Trail That Reports Healthy Again

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment (API audit logging for a trail is paused; every call made during the pause is missing from that trail's log files) |
| Threat Actor | N/A — single technique, not actor-attributed (Stratus Red Team `aws.defense-evasion.cloudtrail-stop`) |
| Platform | aws |
| Severity | High. Nothing is read, changed or destroyed by the call itself, but it removes the evidence for whatever happens next. Raise to Critical when the stopped trail is the account's only multi-Region trail, or when the stop is followed by IAM, KMS or data-plane activity from the same principal inside the gap |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | CloudTrail, S3 (log bucket), IAM, STS, GuardDuty, AWS Config, Security Hub, Organizations (SCP) |

**What the technique does:** the actor calls `cloudtrail:StopLogging` on a trail. The trail
configuration, its bucket and every log file already delivered remain; only delivery stops. Every
API call made while the trail is stopped is absent from **that trail's** log files and from every
downstream consumer that reads them — the SIEM, CloudWatch Logs metric filters, and any detection
pipeline fed from the bucket. The evasive form, which this emulation reproduces, restarts the trail
with `StartLogging` once the noisy work is done, so a later `GetTrailStatus` returns
`IsLogging: true` and every periodic posture check evaluates a healthy trail.

**How this emulation runs it.** The tenant's connected role assumes a lab role,
`stratus-red-team-ct-stop-attacker-role` (session name `atomic-t1685002-ct-stop`), whose only
permissions are `cloudtrail:GetTrailStatus`, `cloudtrail:StopLogging` and `cloudtrail:StartLogging`
on **one** ARN: the lab trail `stratus-red-team-ct-stop-trail`, a single-Region management-event
trail created by the stack with its own log bucket. The role then calls `GetTrailStatus`,
`StopLogging`, waits 30 seconds, and calls `StartLogging` from a `finally` block, so the trail is
restarted even if the run fails. The tenant's own trails are outside the role's reach. The
CloudTrail events produced are `AssumeRole`, `GetTrailStatus`, `StopLogging` and `StartLogging`.

**Why the usual reflexes miss it.** Three reasons.

1. **Posture checks look at state, and the state is restored.** AWS Config and Security Hub
   control CloudTrail.1 evaluate whether a trail is logging. Thirty seconds, or thirty minutes,
   later it is. Nothing in the trail's *current* configuration records that it was ever off.
2. **The GuardDuty finding people expect is not a paging signal.**
   `Stealth:IAMUser/CloudTrailLoggingDisabled` has a default severity of **Low**, and AWS documents
   it as triggered by "a successful deletion or update of a trail" or the deletion of the trail's
   bucket. Treat it as corroboration if it appears, never as the alert.
3. **An absence alert on log volume cannot localise the gap.** Log delivery is batched, roughly
   every five minutes, so a 30-second stop does not produce a measurable dip. Only the control-plane
   event dates the gap.

**Detection thesis:** alert on the `StopLogging` event itself, with **no** `errorCode` filter —
a refused stop is the same intent against a better-defended trail — and correlate it with a
`StartLogging` on the same trail by the same principal to identify the evasive stop-and-restart.
Then use the two facts that survive a restart to size the gap: the trail's own `StopLoggingTime`
in `GetTrailStatus`, and **CloudTrail Event history**, which AWS states "is separate from any
trails or event data stores that you create", so management events from inside the gap are still
there for 90 days.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **At least one multi-Region trail you do not depend on the attacker leaving alone**, ideally an
  **organization trail** created from the management account. Member accounts can see an
  organization trail but cannot stop or delete it: `StopLogging` on it from a member account fails
  with `NotOrganizationMasterAccountException`. A second trail turns a gap into a cross-check.
- **Event history is your recovery source for the gap.** It records 90 days of management events
  per Region regardless of trail state. It does **not** contain data events (S3 object calls,
  Lambda invocations) or Insights events; anything in those categories during the gap is gone.
- **Know the trail's home Region.** `StopLogging` must be called in the trail's home Region (any
  other Region returns `InvalidHomeRegionException`), so the event is always there. For a
  multi-Region trail, one call stops delivery for every Region.
- `GetTrailStatus` exposes `IsLogging`, `StartLoggingTime`, `StopLoggingTime`,
  `LatestDeliveryTime` and `LatestDeliveryError`. Keep a baseline of `StopLoggingTime` per trail;
  a change in it is a stop that a restart did not hide.

**Alerting (must be pre-configured)**
- **`StopLogging` on any trail, any `errorCode` → P1**, raised to **P0** when the trail is the
  account's only multi-Region trail or an organization trail.
- **`StopLogging` followed by `StartLogging` on the same trail by the same principal within 1 hour → P1**
  (the evasive pattern; shipped as a `temporal_ordered` correlation).
- **`StopLogging` refused (`AccessDenied*`, `NotOrganizationMasterAccountException`) → P1.** The
  control held; the principal is still attempting defence impairment.

**Response Tooling**
- Break-glass credentials with `cloudtrail:StartLogging`, `cloudtrail:GetTrailStatus`,
  `cloudtrail:DescribeTrails`, `cloudtrail:LookupEvents`, `iam:PutRolePolicy`,
  `iam:UpdateAccessKey`, held outside the account's normal identity provider.
- The list of roles that legitimately manage trails (usually one IaC deployment role).

**Known IOC Baselines**
- Which principals have ever called `StopLogging`. In most accounts the honest answer is none.
- The set of trails, their home Regions, whether they are multi-Region or organization trails.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `StopLogging` succeeding on the only multi-Region trail, or on an organization trail from the management account | CloudTrail (management) / Event history | T1685.002 |
| P1 | `StopLogging`, any outcome, from a principal not on the trail-admin list | CloudTrail (management) | T1685.002 |
| P1 | `StopLogging` then `StartLogging` on the same trail by the same principal within 1h | CloudTrail (management), correlation | T1685.002 |
| P1 | `GetTrailStatus` shows `StopLoggingTime` later than the recorded baseline | CloudTrail API | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `GetTrailStatus` / `DescribeTrails` / `GetEventSelectors` burst from a principal that does not administer trails — reconnaissance before tampering | CloudTrail (management) | T1685.002 |
| P2 | GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled` (default severity Low) | GuardDuty | T1685.002 |
| P3 | Security Hub CloudTrail.1 / CloudTrail.3 failing, AWS Config trail rule NON_COMPLIANT | Security Hub / Config | T1685.002 |

### Detection Rule Quality Notes

The rule this package was generated with matched `StopLogging` with no outcome filter — correct,
and kept. The improvements are about what it could not express.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Single-event rule only | The evasive stop-and-restart reads like a maintenance blip and is closed as such | Add `cloudtrail_start_logging_bb` (successful `StartLogging`) and a `temporal_ordered` correlation grouped on `userIdentity.arn` + `requestParameters.name`, 1h |
| No gap measurement | The responder cannot tell a 30-second blip from a six-hour blind spot | `kql_t1685_002.kql` pairs each stop with the next successful start on the same trail and reports `GapMinutes`; an empty restart time means it may still be stopped |
| Trail identified by name **or** ARN | A stop by ARN and a start by name do not join on the raw value | The KQL normalises both to the trail name (last path segment of the ARN) |
| Success filters written as `errorCode: null` elsewhere in the corpus | The in-process evaluator never matches `field: null`, so such rules are dead in validation runs | Base rule uses the `exists: false` modifier on `errorCode` |

The shipped Sigma is in `detections/sigma_t1685_002.yml` (three documents). The correlation is not
evaluable by the single-event evaluator by design; its two component rules are.

### Key Investigation Queries

> CloudTrail is regional and `StopLogging` is recorded in the trail's **home Region**. Run these
> there. `lookup-events` returns at most 50 events per page — paginate on `NextToken` for a busy
> window.

#### Query 1 — Current status of the trail, including the time of the last stop

```bash
TRAIL="<trail_name>"
aws cloudtrail get-trail-status --name "$TRAIL"
```

Read `IsLogging`, then `StopLoggingTime` and `StartLoggingTime`. `IsLogging: true` with a
`StopLoggingTime` inside your incident window is a stop that was restarted — the evasive case.
`IsLogging: false` means the trail is still stopped: go to §3 now. `LatestDeliveryError` populated
means delivery is failing for another reason (bucket policy, KMS), which is a different incident
with the same blind spot.

#### Query 2 — Every stop in the last 7 days, with outcome and principal

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,Username,CloudTrailEvent]' --output json
```

Run it again with `AttributeValue=StartLogging` to pair each stop with its restart. For each
`StopLogging`, record `userIdentity.arn`, `userIdentity.accessKeyId`,
`sourceIPAddress`, `userAgent`, `requestParameters.name` and `errorCode`. An empty result is **not**
proof of no stop — it can be the wrong Region (run in the trail's home Region) or a missing
`cloudtrail:LookupEvents` permission.

#### Query 3 — What happened inside the gap (Event history, not the trail)

```bash
GAP_START="<StopLoggingTime-from-Query-1>"; GAP_END="<StartLoggingTime-from-Query-1>"
aws cloudtrail lookup-events --start-time "$GAP_START" --end-time "$GAP_END" \
  --query 'Events[].[EventTime,EventSource,EventName,Username]' --output table
```

This works because Event history is independent of the trail. It returns **management events
only**: if the trail also carried S3 or Lambda data events, those are lost for the gap and the
only alternatives are S3 server access logs and service-native logs. Treat any `iam:*`, `kms:*`,
`sts:AssumeRole`, `secretsmanager:GetSecretValue` or `s3:PutBucketPolicy` in this window as the
reason the trail was stopped.

#### Query 4 — The principal's session, before and after

```bash
SESSION="<session-name-or-user-from-Query-2>"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION" \
  --start-time "$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,EventSource,EventName]' --output table
```

For an assumed-role session `Username` is the **session name** (for this emulation,
`atomic-t1685002-ct-stop`), not the role name. Look for `GetTrailStatus`/`DescribeTrails` just
before the stop (target selection) and for `DeleteTrail`, `PutEventSelectors`, `UpdateTrail` or
`PutBucketLifecycle` on the log bucket — the other ways to blind the same trail, each with its own
playbook in this catalogue.

#### Query 5 — Every trail in the account and whether it is logging

```bash
aws cloudtrail describe-trails --include-shadow-trails \
  --query 'trailList[].[Name,HomeRegion,IsMultiRegionTrail,IsOrganizationTrail,S3BucketName]' --output table
```

Then run Query 1 for each trail in its home Region. Answer two questions: was the stopped trail the
only multi-Region trail, and did any other trail keep logging through the gap (if so, its log files
are the authoritative record of the window, data events included).

---

## 3. Containment

### Immediate Actions (first 15 minutes)

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Restart the trail if it is still stopped

```bash
TRAIL="<trail_name>"
aws cloudtrail start-logging --name "$TRAIL"
aws cloudtrail get-trail-status --name "$TRAIL" --query '[IsLogging,StartLoggingTime,LatestDeliveryTime,LatestDeliveryError]'
```

`IsLogging` must be `true`. `LatestDeliveryTime` advancing over the next 5–15 minutes is the proof
that files are landing again; `IsLogging` alone only proves the flag is set.

#### Step 2 — Preserve the evidence of the gap before it ages out

```bash
GAP_START="<StopLoggingTime>"; GAP_END="<StartLoggingTime>"
aws cloudtrail lookup-events --start-time "$GAP_START" --end-time "$GAP_END" --output json > gap-events.json
```

Event history keeps 90 days. Export the window now — for a long gap, paginate on `NextToken` until
it is empty — and store it with the incident record. This file is the only copy of the gap that
the attacker could not suppress.

#### Step 3 — Contain the principal

```bash
ROLE="<role-name-from-Query-2>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyDenyTrailTampering \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["cloudtrail:StopLogging","cloudtrail:DeleteTrail","cloudtrail:UpdateTrail","cloudtrail:PutEventSelectors"],"Resource":"*"}]}'
```

The `aws:TokenIssueTime` deny kills sessions issued before the cutoff; a credential fetched after
it is not denied, which is why the second, action-specific deny is attached as well. For an IAM
user, deactivate its access keys (`aws iam update-access-key --status Inactive`) and attach the
same deny as a user policy.

#### Step 4 — Check the other blinding routes

Run Query 4's follow-ups: `GetEventSelectors` on the trail (management events still included,
`ReadWriteType: All`), `get-bucket-lifecycle-configuration` on its bucket (no short expiration) and
`describe-trails` (the trail still exists). An actor who stopped a trail once and found it alerted
on is likely to try a quieter route next.

---

## 4. Eradication

### Remove Attacker Access

- Rotate or delete every credential the principal held; if it was an assumed role, find the
  identity that assumed it (`lookup-events` for `AssumeRole` with the role ARN) and contain that too.
- Remove `cloudtrail:StopLogging` from every policy that does not administer trails. It is rarely
  granted deliberately; it usually arrives with `cloudtrail:*` or `AdministratorAccess`.

### Prevent recurrence

- Deploy the **`Protect-security-services-from-tampering`** SCP from the guardrail catalogue, which
  denies `cloudtrail:StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` and
  `CreateTrail` to everyone except named administrative roles. Edit its exception list to your
  real break-glass and IaC roles before attaching it.
- Move the account under an **organization trail**, which member accounts cannot stop.

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

#### Confirm the trail is logging and delivering

```bash
TRAIL="<trail_name>"
aws cloudtrail get-trail-status --name "$TRAIL"
```

`IsLogging: true`, `LatestDeliveryTime` within the last 15 minutes, `LatestDeliveryError` absent.
Record the final `StopLoggingTime` / `StartLoggingTime` pair as the bounds of the gap.

#### Backfill the gap in your SIEM

Load `gap-events.json` from §3 Step 2 into the SIEM, tagged as recovered from Event history, so
detections that run over the trail's data can be re-run across the window. State in the incident
record that data events for the window are unrecoverable.

#### Confirm the corrected detection fires

```text
MUST fire on:     StopLogging / cloudtrail.amazonaws.com, with or without errorCode -> high.
                  StopLogging then successful StartLogging on the same trail by the same
                  principal within 1h -> high (correlation).
MUST NOT fire on: StartLogging alone; GetTrailStatus / DescribeTrails reads.
EXPECTED FP:      a change-managed trail rebuild by the IaC role - allowlist the role ARN.
```

Running this emulation is the test: one `StopLogging` and one `StartLogging` from session
`atomic-t1685002-ct-stop`, 30 seconds apart.

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| One call blinded the account's audit trail | `cloudtrail:StopLogging` held by a principal that does not administer logging; no SCP protecting trails |
| The gap went unnoticed after the restart | Posture checks evaluate current state; GuardDuty's finding is Low and documented for delete/update, not stop |
| The window could not be fully reconstructed | Data events exist only in trails; Event history covers management events only |

### Recommended Guardrails

- **Catalogue match:** `Protect-security-services-from-tampering` (SCP, conditional on
  `aws:PrincipalARN` exceptions) denies `cloudtrail:StopLogging`. It would have refused this
  emulation's call if the lab role were not on its exception list.
- **Structural:** an organization trail, owned by the management account, that member accounts
  cannot stop; and a second destination (CloudTrail Lake or a log-archive account bucket) so one
  trail is never the only record.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log |
| Primary API | `cloudtrail:StopLogging` (`requestParameters.name` = trail name or ARN) |
| Revert API | `cloudtrail:StartLogging` (same parameter) |
| Event source | `cloudtrail.amazonaws.com`, management event, trail home Region |
| Errors worth reading | `NotOrganizationMasterAccountException` (member account tried an org trail), `InvalidHomeRegionException`, `TrailNotFoundException`, access-denied codes from an SCP or IAM deny |
| Surviving evidence | Event history (90 days, management events), `GetTrailStatus.StopLoggingTime`, any other trail that kept logging |
| Lab identity | Role `stratus-red-team-ct-stop-attacker-role`, session `atomic-t1685002-ct-stop`, trail `stratus-red-team-ct-stop-trail` |

### Residual Risk

Data events made during the gap are permanently absent: there is no AWS source that reconstructs S3
object reads or Lambda invocations for a window in which the only trail logging them was stopped.
If the stopped trail was the only one, the incident's scope for that window is bounded by
management events in Event history and by service-native logs (S3 server access logs, VPC flow
logs, application logs) — and an actor who stopped the trail had reason to believe those were the
only ones that mattered.
