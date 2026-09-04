# Detection Note — T1685.002 (CloudTrail Logging Tampered)

**Signal:** a CloudTrail configuration change that **reduces recorded scope** — logging
stopped, a trail deleted, Region coverage narrowed, event selectors rewritten to record
less, the destination bucket repointed, or delivery broken S3-side — made by a principal
that is not the logging pipeline. Not the event name.

**This is the one technique in the set whose detection depends on the telemetry it
disables.** Every other playbook here can assume the trail is intact while it reasons
about what the trail recorded. This one cannot, and pretending otherwise produces a
detection strategy that is sound right up to the moment it is needed. The whole design
below follows from taking that seriously rather than writing around it.

**What the original rules got wrong** — `UpdateTrail` is matched by event name alone, so
the rule cannot distinguish a narrowing from a widening and fires identically on an
operator turning multi-Region logging *on*. `PutEventSelectors` and `PutInsightSelectors`
are not matched at all, so the quiet forms of the technique produce no alert. `StopLogging`
and `DeleteTrail` are rated P2 and `UpdateTrail` P3, which routes an account going dark to
a queue nobody reads overnight.

## Absence is the evidence, and absence is not something a threshold fires on

`StopLogging` is itself recorded — the call happens while the trail is still logging, and
CloudTrail records its own configuration changes as management events. What is not
recorded is everything the actor does *next*. So the ground truth of this technique is a
gap, and a gap has no event to match.

There are exactly two ways to make a gap detectable, and both must be built before the
incident:

1. **A second, independent recorder**, so the gap in one is a presence in the other. This
   is the load-bearing §1 prerequisite of the playbook, and it is the only control that
   still works when the principal degrading the trail is legitimately allowed to
   administer CloudTrail.
2. **An absence detector** — a rule that fires when the expected rows stop arriving.
   `AWSCloudTrail | summarize count() by AwsRegion, bin(...) | where count < N`. It has no
   event to key on and therefore no natural threshold; the threshold has to come from a
   measured baseline of your own quietest hour per Region, and a Region with no workload
   has to be excluded by name rather than by lowering the bar for every Region.

Companion 1 in `kql_t1685_002.kql` is that absence detector. It is the only rule in this
directory that fires *after* the technique has succeeded.

## What survives the tampering — verified, because the intuition is wrong

The intuition is that stopping the trail blinds the account. It does not, and getting this
right changes the response.

| Path | Survives a stopped/deleted/narrowed trail? | Why |
|------|--------------------------------------------|-----|
| CloudTrail **Event history** | **Yes**, 90 days, management events, per Region | AWS: *"The event history is separate from any trails or event data stores that you create for your account. Changes you make to your event data stores or trails do not affect the event history."* `aws cloudtrail lookup-events` reads it |
| **GuardDuty** | **Yes** | AWS: GuardDuty consumes CloudTrail management events *"directly from CloudTrail through an independent and duplicated stream of events"*, and *"your CloudTrail configurations don't affect how GuardDuty consumes and processes the event logs"* |
| A **second trail** the actor cannot reach | Yes, by construction | An organization trail, or a trail in a separate logging account |
| **AWS Config** | Partly | `AWS::CloudTrail::Trail` is a recorded resource type, so trail *configuration* changes produce configuration items. But the managed rule that checks whether a trail is enabled, `CLOUD_TRAIL_ENABLED`, has trigger type **Periodic** — it evaluates on a schedule, not at the moment of the stop |
| **EventBridge** on CloudTrail events | **No** | AWS: *"To record events with one of the CloudTrail `detail-type` values, you must enable a CloudTrail trail with logging."* An EventBridge rule on `AWS API Call via CloudTrail` is downstream of the thing being disabled, not independent of it |
| **CloudTrail Lake** event data stores | Yes, where you have them | Ingest independently of trails. But **Lake closed to new customers on 31 May 2026**, so for most accounts reading this it is not an option to adopt now |
| The **S3 archive** and the SIEM feed | No | This is what the technique actually destroys |

So the honest statement of impact is narrower and sharper than "the account went dark":
the technique destroys **real-time detection**, the **durable archive beyond 90 days**,
**every event category Event history never held** (data events, Insights events, network
activity events), **organization-level aggregation**, and the **log file integrity digest
chain**. It does not destroy incident-time management-event reconstruction inside 90 days
in the Region where the calls landed. A responder who believes it does will not run the
one query that still works.

## Narrowing versus widening — the difference the source rule cannot see

`UpdateTrail` is a **partial** update: an omitted optional parameter leaves the setting
unchanged. So `isMultiRegionTrail: false` in `requestParameters` was explicitly sent, and
`true` is a different value. Narrowing and widening are separable on the event, which is
what makes a rule on this call possible at all:

```
isMultiRegionTrail: false          shadow trails in every other Region are DELETED
includeGlobalServiceEvents: false  CloudFront, IAM and STS events stop arriving — those
                                   three are what AWS's sentence names, Route 53 is not —
                                   but only for a SINGLE-Region trail whose home Region is
                                   us-east-1; AWS requires the value to be true on a
                                   multi-Region trail, and since 22 Nov 2021 global service
                                   events are recorded in us-east-1 only, so elsewhere this
                                   flag removes nothing that was arriving anyway
enableLogFileValidation: false     digest chain breaks after ONE HOUR, and no digest
                                   files are created for the whole period it stays off
s3BucketName: <not the approved one>   delivery continues, to somewhere you do not read
```

Two separate pieces of evidence sit behind that paragraph, and they are worth keeping
apart because only one of them is a quote.

**The casing is documented.** AWS publishes a success-path `StartLogging` record reading
`"requestParameters": { "name": "myTrail" }` and an `UpdateTrail` record reading:

```
"requestParameters": { "name": "myTrail2", "isMultiRegionTrail": true }
```

Initial-lowercase keys in both. That is why the field paths in the shipped rules are
asserted rather than hedged. Note where the second one sits, though: it is the
*"Error code and message log example"* and carries `"errorCode": "TrailNotFoundException"`.
Cite it for the casing; it says nothing about what a **successful** call does.

**The partial-update behaviour is demonstrated, not stated.** No AWS sentence says an
omitted `UpdateTrail` parameter is left unchanged — the API description says only that it
*"updates trail settings that control what events you are logging"*. What AWS does publish
is a CLI example: `aws cloudtrail update-trail --name my-trail --is-multi-region-trail`
passes that one flag, and the returned trail still carries `S3BucketName`,
`IncludeGlobalServiceEvents`, `LogFileValidationEnabled` and `IsOrganizationTrail`
unchanged. That is the whole basis for treating a `false` as deliberately sent, so confirm
it against one real `UpdateTrail` event from your own IaC pipeline before you tune anything
on the *absence* of a flag — an older provider that writes every parameter on every apply
breaks the inference, which is why it also appears in the rule's false positives.

`PutEventSelectors` is different: the call submits the selector set whole, so the event
carries the **resulting configuration** rather than the delta. AWS states the cross-type
case outright — *"If you apply `AdvancedEventSelectors` to a trail, any existing
`EventSelectors` are overwritten"*, and the converse — and demonstrates the same-type case
rather than stating it, the API having no patch or delete verb and the user guide's
instruction for reversing a KMS exclusion being to *"remove the `eventSource` selector, and
run the command again"*. Either way the responder sees an end state, never a change. Some
end states are narrowings on their face and are matched by the shipped rules:

```
IncludeManagementEvents: false          no control-plane activity recorded at all
ReadWriteType: "ReadOnly"               every MUTATING call disappears, and the trail
                                        still reports management events as enabled
                                        (valid values are ReadOnly | WriteOnly | All)
ExcludeManagementEventSources: [...]    one service's control plane removed — but the
                                        value set is CLOSED: AWS documents it as empty,
                                        or kms.amazonaws.com, or rdsdata.amazonaws.com,
                                        and nothing else. There is no "actor excludes
                                        some other service" case to detect, because the
                                        API will not accept one
advanced FieldSelector Field:
   "userIdentity.arn"                   filtered by WHO called it — data events on a
                                        trail, management events on an event data store.
                                        See the paragraph below; the distinction matters
```

That last one deserves naming, and it deserves getting right — the obvious reading of it
is wrong in a way that changes the response. An advanced event selector on
`userIdentity.arn` is a precise self-exclusion primitive: the resource keeps running,
`IsLogging` stays true, every other principal is logged normally, and one ARN is
invisible. But **what it can hide depends on what you apply it to.** AWS's field table:

> For CloudTrail management events, supported fields include `eventCategory` (required),
> `eventSource`, and `readOnly`. The following additional fields are available **for event
> data stores**: `eventName`, `eventType`, `sessionCredentialFromConsole`, and
> `userIdentity.arn`.

and, on the field itself: *"For event data stores, this is an optional field used to
filter management and data events for actions taken by specific IAM identities. **For
trails, this is an optional field used to filter data events and network activity
events.**"*

So `PutEventSelectors` on a **trail** cannot exclude a principal from **management**
logging — that combination is not an accepted configuration, and a rule that describes it
that way sends a responder looking for a control-plane gap that is not there. What a trail
selector on `userIdentity.arn` does hide is that principal's **data events** and network
activity events, which for an actor working in S3 or KMS is still exactly the hole they
want. The management-event version of this move exists, but it lives on an **event data
store** and arrives as `CreateEventDataStore` / `UpdateEventDataStore` — a different event
name, which is why those two are now matched alongside `PutEventSelectors` in both the
Sigma and the KQL, and why the KQL verdicts name the two cases separately.

**The general case is not decidable from the event.** A selector set that drops one data
resource or tightens one `StartsWith` prefix looks structurally identical to the widening
that added it. That case needs a diff against a stored baseline of `get-event-selectors`
output, on a schedule — the same shape as the code-hash drift detector in the
`lambda_updatecode_nondeploy` note, and the same reason: it is the only check that still
works when the acting principal is on every allowlist.

## `IsLogging: true` is not a health check

The S3-side break is the quietest form of all. A bucket policy that no longer permits
`cloudtrail.amazonaws.com` to `s3:PutObject`, a deleted bucket, or a KMS key CloudTrail
can no longer use, all stop log files arriving — while the trail reports `IsLogging: true`
and CloudTrail emits **no event of its own**, because nothing about the trail changed. The
signal is on `GetTrailStatus`, and only there. Its exact response fields:

```
IsLogging                          bool   whether the trail is currently logging
LatestDeliveryError                str    the S3 error on the last log-file delivery
LatestDeliveryTime                 ts
LatestDigestDeliveryError          str    the S3 error on the last DIGEST delivery
LatestDigestDeliveryTime           ts
LatestCloudWatchLogsDeliveryError  str    the CloudWatch Logs delivery path
LatestCloudWatchLogsDeliveryTime   ts
LatestNotificationError            str    the SNS path
LatestNotificationTime             ts
StartLoggingTime                   ts     when logging was last started
StopLoggingTime                    ts     when logging was last stopped
```

**Six** further fields are documented as *"no longer in use"*:
`LatestDeliveryAttemptTime`, `LatestDeliveryAttemptSucceeded`,
`LatestNotificationAttemptTime`, `LatestNotificationAttemptSucceeded`, `TimeLoggingStarted`
and `TimeLoggingStopped`. Do not build a check on them; they read as empty and an emptiness
test on a dead field is a permanent `[OK]`. Note the two live near-homonyms in the list
above — the fields that carry the logging-state timestamps are `StartLoggingTime` and
`StopLoggingTime`, **not** `TimeLoggingStarted` / `TimeLoggingStopped`, and the pairs
differ only in word order.

**A recovery check that asserts only `IsLogging == true` prints a false `[OK]` on a trail
delivering nothing.** That is the worst failure mode available on a containment assertion,
and the playbook's Recovery section asserts on `LatestDeliveryError` as well for exactly
this reason.

The mitigating fact, and it is a large one: **CloudTrail retries delivery for 30 days**
after a misconfiguration. Fixing the bucket policy inside that window recovers the files
that could not be written. This is the only form of this technique that is genuinely
reversible.

## Response levers

**A second recorder is the only structural control.** AWS states that users in member
accounts *"do not have sufficient permissions to delete organization trails, turn logging
on or off, change what types of events are logged, or otherwise change an organization
trail in any way"* — a member-account compromise cannot degrade it. Member accounts *can*
still read it: AWS documents that a member account with CloudTrail permissions can see
validation failures for an organization trail by running `get-trail-status`, which is what
makes the delivery-error check runnable from the affected account. One shape trap on that
path — *"If the trail is an organization trail and you are a member account in the
organization … you must provide the full ARN of that trail, and not just the name."* A
member-account check that passes the bare name errors instead of answering, and an error
routed into the pass branch is a `[OK]` on a trail nobody looked at.

**Restore logging before anything else.** Every containment step you take after the trail
is down is itself unrecorded by that trail, so a responder who disables the attacker's keys
first has performed the most consequential actions of the incident off the record.
`StartLogging` comes first. Note that `DeleteTrail` is irreversible — the trail must be
recreated — but that **the S3 log files survive it**: AWS states that *"while deleting a
CloudTrail trail is an irreversible action, CloudTrail does not delete log files in the
Amazon S3 bucket for that trail, the Amazon S3 bucket itself, or the CloudWatch log group
to which the trail delivers events."*

**The gap boundary is fuzzy at the start and sharp at the end, and that asymmetry is
useful.** AWS documents that *"after you turn off logging for a trail, the trail can still
receive events that occurred before logging was turned off"* — CloudTrail decides using
*"the most recent time that logging was turned off"*, not the trail state at the moment the
event occurred. Two consequences. First, the `StopLogging` call itself, and other events
from just before it, normally do land in the trail, which is why the loud form of this
technique is self-recording. Second, *"event selectors and advanced event selectors are not
evaluated for delayed events delivered to a trail after logging is turned off"*, so
post-restart deliveries can include categories the trail is not configured for — do not
read those as a selector change. What never arrives is anything that happened **during** the
off period. That is the gap, and nothing recovers it from this trail.

**Error strings:** denials are `AccessDenied` (IAM-evaluated) and `AccessDeniedException`
(service-evaluated) — no EC2-style `Client.` prefix. The complete non-denial set for these
calls is enumerated in the trailing comments of `kql_t1685_002.kql`; the operationally
useful one is **`InvalidHomeRegionException`**, documented on all five write calls —
`StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` and `PutInsightSelectors`
— and thrown when any of them is called from a Region other than the trail's home Region.
An actor guessing wrong leaves a failed call in the Region it guessed, which is a free
early warning — and a responder must run every write in the trail's home Region or it
returns zero. `GetTrailStatus` is the exception and does **not** list that error: AWS
documents it as returning *"trail status from a single Region"*, so a responder polls it
Region by Region rather than being told it guessed wrong.

**MITRE:** Both halves are now stale, and stale in a way that
survives a casual check. And the same restructure **renamed TA0005 from "Defense Evasion"
to "Stealth"** and moved this behaviour to **Defense Impairment (TA0112)** — so a rule
carrying TA0005 now claims a tactic that still exists but is no longer this one.
**T1685.002 (*Disable or Modify Tools: Disable or Modify Cloud Log*), tactic Defense
Impairment (TA0112)**, is the precise mapping and is what this directory carries. The
lifecycle-rule and object-deletion variants — expiring the delivered log objects rather
than stopping their creation — are better described by **T1070 (*Indicator Removal*,
tactic Stealth TA0005)**, because those logs were recorded and then destroyed; the
scope-narrowing variants are squarely T1685.002. A mapping-precision note, not an
operational defect: the source rules do fire on the right event names.

**Severity:** the source rates `StopLogging` and `DeleteTrail` P2 and `UpdateTrail` P3. IR
view **High**, P0 for every successful scope reduction. This is a technique whose entire
purpose is to buy the actor an unobserved window, so the time between the alert and the
response *is* the payload — a P2 that pages nobody overnight hands over the night.

**GuardDuty:** `Stealth:IAMUser/CloudTrailLoggingDisabled` — *"AWS CloudTrail logging was
disabled"*. AWS states it *"can be triggered by a successful deletion or update of a
trail"* and *"can also be triggered by a successful deletion of an S3 bucket that stores
the logs from a trail that is associated with GuardDuty"*. Read that list literally:
**`StopLogging` is not named in it**, and neither is `PutEventSelectors`. Its **default
severity is Low**, which is the wrong disposition for an account going dark and needs
raising in your severity mapping. `DefenseEvasion:IAMUser/AnomalousBehavior`
(**default severity Medium**) *does* name `StopLogging` explicitly among the APIs it
models, but it is behavioural — it fires on an anomalous call, so it will not fire when
the acting principal routinely administers CloudTrail. Between them the two findings cover
the technique unevenly and neither is the control; both are corroboration.

**Files here:**

- `sigma_t1685_002.yml` — seven documents: trail stopped/deleted/narrowed (`high`),
  destination repointed to an unapproved bucket (`high`, ships with a placeholder
  allowlist that must be filled in), selectors narrowed or Insights disabled (`high`,
  covering `PutEventSelectors`, `PutInsightSelectors` and the event-data-store
  self-exclusion route on `Create`/`UpdateEventDataStore`), a logging-configuration read
  base rule (`informational`) with the survey-then-degrade temporal correlation (`high`),
  and a denied-write base rule (`low`) with its volume correlation (`medium`).
- `kql_t1685_002.kql` — the parsed, statement-level version, including the array-absence
  test the Sigma cannot express, plus two companions to deploy alongside it: the
  **absence detector** and the denied-write probe.

Cross-references: the shape-guard discipline here (array-or-absent, pad before `mv-apply`)
is the same trap documented in `detection_note_t1098_003.md` for IAM policy documents —
`Statement` as object-or-array — and it fails the same way, by silently evaluating
nothing. The baseline-diff pattern is the one in the `lambda_updatecode_nondeploy` note.
The sibling `../../aws.initial-access.sg-remote-management-open/detections/detection_note_t1686_001.md`
covers the other Defense Impairment (TA0112) technique in this corpus — note the file name,
which is `t1686_001`, not the pre-restructure `t1562_007`.

Full response procedure is in `../PLAYBOOK.md`.
