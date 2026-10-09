# IR Playbook: CloudTrail Event Selectors Rewritten — `PutEventSelectors` Leaves a Trail "Logging" Nothing

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment (a trail's event selectors are replaced so it records no management events, or only reads, while still reporting that it is logging) |
| Threat Actor | N/A — single technique, not actor-attributed (Stratus Red Team `aws.defense-evasion.cloudtrail-event-selectors`) |
| Platform | aws |
| Severity | High. It is quieter than `StopLogging` or `DeleteTrail` and defeats the trail health checks those are caught by. Raise to Critical when the impaired trail is the only one recording management events, or when activity by the same principal follows inside the blind window |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | CloudTrail, IAM, STS, AWS Config, Security Hub, Organizations (SCP) |

**What the technique does:** `cloudtrail:PutEventSelectors` **replaces** every selector on a trail.
The actor submits one basic selector with `ReadWriteType: ReadOnly`,
`IncludeManagementEvents: false` and no data resources. From then on the trail matches nothing:
no management events, read or write, and no data events. `GetTrailStatus` still returns
`IsLogging: true`, the bucket still exists, `LatestDeliveryTime` may even keep moving for digest
files — every signal a health check reads says the trail is fine.

**How this emulation runs it.** The connected role assumes `stratus-red-team-ct-selectors-attacker-role`
(session `atomic-t1685002-ct-selectors`), whose only permissions are
`cloudtrail:GetEventSelectors` and `cloudtrail:PutEventSelectors` on the lab trail
`stratus-red-team-ct-selectors-trail`. It reads the current selectors, replaces them with the
empty-coverage selector above, waits 30 seconds, and restores the original selectors from a
`finally` block. Events produced: `AssumeRole`, `GetEventSelectors`, `PutEventSelectors` (impair),
`PutEventSelectors` (restore). The tenant's own trails are out of the role's reach.

**Why the usual reflexes miss it.** The standard tamper detections key on `StopLogging` and
`DeleteTrail`; neither occurs. Trail health checks key on `IsLogging`; it stays `true`. And
`PutEventSelectors` is a routine call — teams use it to add S3 or Lambda data events — so an
eventName-only rule is noisy enough to be tuned away. The discriminator is the **content** of the
new selectors, and it has to be read as a whole: a trail commonly carries one management selector
and a second, data-only selector with `includeManagementEvents: false`, and that second selector
on its own is not impairment.

**Detection thesis:** because the call replaces everything, the request alone states the trail's
new coverage. Alert when **no** selector in the request keeps management events, when every
selector is read-only, or (advanced selectors) when no selector names the `Management` event
category. Measure the blind window by pairing the change with the next `PutEventSelectors` that
restores full coverage, and recover the management events of that window from Event history.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **A baseline of every trail's selectors** (`get-event-selectors`), kept as data. The question
  "what did this trail record before?" cannot be answered from the trail after the change.
- **Event history** records 90 days of management events per Region independently of trail
  selectors; it is the recovery source for the blind window. Data events have no equivalent.
- **Two management-event trails, or an organization trail.** Member accounts cannot change an
  organization trail's selectors, and a second trail turns the blind window into a cross-check.
- Basic selectors appear in `requestParameters.eventSelectors[]` (`readWriteType`,
  `includeManagementEvents`, `dataResources[]`, `excludeManagementEventSources[]`); advanced
  selectors in `requestParameters.advancedEventSelectors[]` (`name`, `fieldSelectors[]` with
  `field` / `equals`). A trail uses one or the other.

**Alerting (must be pre-configured)**
- **`PutEventSelectors` leaving no management selector, or only read-only selectors → P1** (P0 for
  the account's only management trail).
- **Advanced selectors with no `Management` category → P1.**
- **`excludeManagementEventSources` set (KMS, RDS Data API) → P2.**

**Response Tooling**
- Break-glass credentials with `cloudtrail:PutEventSelectors`, `GetEventSelectors`,
  `LookupEvents`, `iam:PutRolePolicy`; the selectors in IaC.

**Known IOC Baselines**
- Who changes selectors (normally only the IaC role) and how often (rarely).

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `PutEventSelectors` on the only management-event trail leaving no management selector | CloudTrail (management) / Event history | T1685.002 |
| P1 | `PutEventSelectors` (basic) with no selector keeping management events, or only `ReadOnly` selectors | CloudTrail (management) | T1685.002 |
| P1 | `PutEventSelectors` (advanced) with no `Management` event category | CloudTrail (management) | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `excludeManagementEventSources` naming `kms.amazonaws.com` or `rdsdata.amazonaws.com` | CloudTrail (management) | T1685.002 |
| P2 | `GetEventSelectors` / `DescribeTrails` from a principal that does not administer logging | CloudTrail (management) | T1685.002 |
| P3 | Security Hub CloudTrail.1 failing (no multi-Region trail with read and write management events) | Security Hub | T1685.002 |

### Detection Rule Quality Notes

| Issue | Impact | Correction |
|-------|--------|-----------|
| The generated rule matched literal substrings such as `"includeManagementEvents":false` on the flattened request | Whether a nested object serialises with or without a space after the colon is the backend's choice; in the in-process evaluator the rule never fired | Regular expressions with optional whitespace on `requestParameters.eventSelectors` |
| It fired on any selector with `includeManagementEvents: false` | The common management + data-only two-selector layout alerted on every data-event change | Require that **no** selector in the request keeps management events (the call replaces all of them, so the request is the whole state) |
| Advanced selectors were not covered | The same impairment written as advanced selectors was invisible | Second document: advanced selectors with no `Management` category |
| The restore and the impairment looked alike | — | The restore keeps `includeManagementEvents: true` / `ReadWriteType: All` and does not match; the KQL uses it to close the blind window |

### Key Investigation Queries

> Run in the trail's **home Region**.

#### Query 1 — What the trail records right now

```bash
TRAIL="<trail_name>"
aws cloudtrail get-event-selectors --trail-name "$TRAIL"
```

Healthy: at least one `EventSelectors[]` entry with `IncludeManagementEvents: true` and
`ReadWriteType: All`, or an `AdvancedEventSelectors[]` entry whose `FieldSelectors` include
`eventCategory` equals `Management`. Compare against your baseline. If this already looks healthy,
the change may have been reverted — Query 2 tells you.

#### Query 2 — Every selector change in the last 7 days

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutEventSelectors \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,Username,CloudTrailEvent]' --output json
```

For each event read `requestParameters.trailName`, the full `requestParameters.eventSelectors` (or
`advancedEventSelectors`), `userIdentity.arn`, `sourceIPAddress` and `errorCode`. Order them by
time: the impairing change opens the blind window, the next change that restores management
events closes it. This emulation produces exactly that pair 30 seconds apart.

#### Query 3 — Is the trail still "logging"?

```bash
TRAIL="<trail_name>"
aws cloudtrail get-trail-status --name "$TRAIL"
```

`IsLogging: true` during the blind window is the point of the technique — record it in the incident
so nobody closes it on the strength of a status check.

#### Query 4 — The management events the trail did not record

```bash
GAP_START="<impairing-change-time>"; GAP_END="<restoring-change-time>"
aws cloudtrail lookup-events --start-time "$GAP_START" --end-time "$GAP_END" \
  --query 'Events[].[EventTime,EventSource,EventName,Username]' --output table
```

Event history does not depend on trail selectors, so this lists the window's management events.
Data events (S3 objects, Lambda invocations) in the window are not recoverable from AWS.

#### Query 5 — The principal's session

```bash
SESSION="<session-name-or-user-from-Query-2>"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION" \
  --start-time "$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,EventSource,EventName]' --output table
```

`GetEventSelectors` before the change is the actor capturing the original configuration to put it
back — the same thing this emulation does. Anything between the two `PutEventSelectors` calls is
what the change was for.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Restore management-event coverage

```bash
TRAIL="<trail_name>"
aws cloudtrail put-event-selectors --trail-name "$TRAIL" \
  --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true}]'
```

This replaces every selector, including any data-event selectors the trail had. If the baseline
carried data events, put back the full baseline (from IaC) instead, or the trail stays impaired
for data events. Confirm with Query 1.

#### Step 2 — Preserve the blind window

```bash
GAP_START="<impairing-change-time>"; GAP_END="<restore-time>"
aws cloudtrail lookup-events --start-time "$GAP_START" --end-time "$GAP_END" --output json > gap-events.json
```

Paginate on `NextToken` until it is empty.

#### Step 3 — Contain the principal

```bash
ROLE="<role-name-from-Query-2>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyDenyTrailTampering \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["cloudtrail:PutEventSelectors","cloudtrail:StopLogging","cloudtrail:DeleteTrail","cloudtrail:UpdateTrail"],"Resource":"*"}]}'
```

For an IAM user, deactivate its access keys and attach the same deny as a user policy.

---

## 4. Eradication

### Remove Attacker Access

- Trace the session to its source identity and contain it; remove `cloudtrail:PutEventSelectors`
  from every principal that does not own trail configuration.

### Prevent recurrence

- Attach the **`Protect-security-services-from-tampering`** SCP from the guardrail catalogue; it
  denies `cloudtrail:PutEventSelectors` (with `StopLogging`, `DeleteTrail`, `UpdateTrail`,
  `CreateTrail`) outside named admin roles. Replace its sample exception list with your own roles.
- Run a scheduled selector drift check against the baseline — the one control that catches a
  change made before your alerting existed.

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

#### Confirm coverage matches the baseline

```bash
TRAIL="<trail_name>"
aws cloudtrail get-event-selectors --trail-name "$TRAIL"
```

Every selector in the baseline present, and at least one recording read and write management
events. Then backfill `gap-events.json` into the SIEM, tagged as recovered from Event history.

#### Confirm the corrected detection fires

```text
MUST fire on:     PutEventSelectors whose basic selectors keep no management events, or are all
                  ReadOnly -> high. Advanced selectors with no Management category -> high.
                  excludeManagementEventSources non-empty -> medium.
MUST NOT fire on: the restore (ReadWriteType All, IncludeManagementEvents true); a request with a
                  management selector plus a data-only selector; GetEventSelectors reads.
EXPECTED FP:      a data-events-only secondary trail being configured - allowlist its name.
```

Running this emulation is the test: the first `PutEventSelectors` from session
`atomic-t1685002-ct-selectors` must fire; the second (restore) must not.

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A trail recorded nothing while reporting healthy | Health checks read `IsLogging`, not coverage; no selector baseline |
| The change was not alerted | The rule keyed on eventName only, or on serialisation-dependent substrings |
| `PutEventSelectors` was available to the principal | Granted with `cloudtrail:*`; no SCP |

### Recommended Guardrails

- **Catalogue match:** `Protect-security-services-from-tampering` (SCP, conditional on
  `aws:PrincipalARN` exceptions) denies `cloudtrail:PutEventSelectors`.
- **Structural:** an organization trail whose selectors member accounts cannot change.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log |
| Primary API | `cloudtrail:PutEventSelectors` (replaces all selectors) |
| Emulation payload | One basic selector: `ReadWriteType=ReadOnly`, `IncludeManagementEvents=false`, `DataResources=[]` |
| Event source | `cloudtrail.amazonaws.com`, management event, trail home Region |
| Key fields | `requestParameters.trailName`, `requestParameters.eventSelectors[]`, `requestParameters.advancedEventSelectors[]` |
| What does not change | `GetTrailStatus.IsLogging` (stays `true`), the bucket, the trail ARN |
| Lab identity | Role `stratus-red-team-ct-selectors-attacker-role`, session `atomic-t1685002-ct-selectors`, trail `stratus-red-team-ct-selectors-trail` |

### Residual Risk

Data events during the blind window are unrecoverable, and if the impaired trail was the only one
carrying them nothing else covers the window. Without a stored selector baseline, a responder
cannot prove the restored trail records what it did before; an attacker who removed one data-event
selector among several would survive a restore that only checks for management events.
