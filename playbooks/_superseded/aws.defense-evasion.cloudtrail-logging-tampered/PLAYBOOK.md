# IR Playbook: CloudTrail Logging Tampered — Audit Blinding via `cloudtrail:StopLogging` and `cloudtrail:PutEventSelectors`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment / audit-trail degradation (a trail is stopped, deleted, repointed or narrowed so that what the actor does next is never recorded) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | **High**, P0 for every successful scope reduction. The technique has no payload of its own — it produces an unobserved window, and everything of value happens inside that window. So the interval between the change and the response *is* the impact, which makes the disposition, not the rule logic, the first thing worth fixing: the source alerts rate `StopLogging` and `DeleteTrail` **P2** and `UpdateTrail` **P3**, routing an account going dark to a queue nobody reads overnight. Severity does not fall when the change looks small. A single `UpdateTrail --no-is-multi-region-trail` deletes the shadow trails in every other Region while the home-Region trail still reports `IsLogging: true`, and a single advanced event selector removes one principal from the record while every other principal is logged normally |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | CloudTrail, S3, KMS, IAM, STS, Organizations, GuardDuty, CloudWatch Logs, EventBridge, AWS Config |

**What the technique does:** the actor degrades CloudTrail so that its own subsequent
activity is not recorded. The loud form is one call — `cloudtrail:StopLogging` (parameter
`Name`, empty response body) or `cloudtrail:DeleteTrail` (same shape, irreversible). The
quiet forms leave the trail running and reporting healthy: `cloudtrail:UpdateTrail` with
`IsMultiRegionTrail` false, which **deletes the shadow trails in every other Region**; with a
new `S3BucketName`, which keeps delivery alive but sends it somewhere the detection pipeline
does not read; with `EnableLogFileValidation` false, which breaks the digest chain an hour
later and creates no digests at all for the period it stays off;
`cloudtrail:PutEventSelectors` rewriting the selector set so that management events, or every
mutating call, or one service's control plane stops matching; and
`cloudtrail:PutInsightSelectors` with an **empty** list, the documented way to turn Insights
off. Quietest of all is not a CloudTrail call at all: a bucket-policy edit, a lifecycle rule,
a bucket deletion or an unusable SSE-KMS key on the destination stops log files arriving
while the trail keeps reporting `IsLogging: true` and emits **no CloudTrail event of its
own**, because nothing about the trail changed.

**Why this is potent, and why the usual reflexes miss it.** The reflex is to check whether
the trail is on, and `DescribeTrails` and `GetTrailStatus`'s `IsLogging` both answer *yes*
for four of the six forms above — the repointed bucket, the narrowed selectors, the disabled
validation and the broken S3 delivery all leave a trail reporting itself healthy. The second
reflex is to look for the event, and here the technique inverts the usual model: `StopLogging`
**is** recorded, because CloudTrail records its own configuration changes as management
events and the call happens while the trail is still logging — but nothing the actor does
*afterwards* is. The evidence is an **absence**, and a threshold rule has no event to fire on.
Any playbook implying otherwise claims coverage it does not have. Absence becomes detectable
in exactly two ways, both of which must exist before the incident: a **second, independent
recorder**, and an **absence detector** whose threshold comes from a measured per-Region
baseline rather than from the API.

**Detection is the direction of the change and the delivery status, not the event name.**
`UpdateTrail` is the same call an operator makes to turn multi-Region logging *on*, so the
discriminator is that the change **reduces** recorded scope — a flag explicitly sent `false`,
a selector set that no longer asks for management events, a destination off the approved list
— plus, for the S3-side break that produces no event at all, `GetTrailStatus`'s
`LatestDeliveryError` on a trail still claiming to log. The source alerts match `UpdateTrail`
by event name with a bare success filter, which cannot separate a narrowing from a widening,
and match `PutEventSelectors` and `PutInsightSelectors` not at all (§2).

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **A second recorder the account under attack cannot reach.** An **organization trail**
  owned by the management account is the structural answer: AWS states that users in member
  accounts *"do not have sufficient permissions to delete organization trails, turn logging
  on or off, change what types of events are logged, or otherwise change an organization
  trail in any way"*. A member account can still *read* it — `get-trail-status` returns
  validation failures — but must pass the **full trail ARN, not the name**, or the call
  errors instead of answering. The alternative is a second trail in a separate logging
  account delivering to a bucket in a third account with Object Lock
- **CloudTrail Event history** is independent of every trail and is the single most
  important fact in this playbook: *"Changes you make to your event data stores or trails do
  not affect the event history"*, and *"settings that you apply to a trail or event data
  store do not apply to event history"*. **90 days, per Region, management events only**;
  `aws cloudtrail lookup-events` reads it
- CloudTrail's own configuration changes are **management** events under
  `cloudtrail.amazonaws.com` (`managementEvent: true`, `readOnly: false`), and
  `requestParameters` uses the **initial-lowercase** form of the wire parameter names —
  `name`, `s3BucketName`, `isMultiRegionTrail`. `StopLogging` and `DeleteTrail` carry only
  `requestParameters.name` and return an **empty body**: no `responseElements` to pivot from
- A **stored baseline** of `describe-trails` and `get-event-selectors` per trail per Region,
  plus the approved destination bucket names and KMS key ARNs. A `PutEventSelectors` event
  carries the resulting configuration and never the delta, so without a baseline "what
  changed" has no answer after the fact
- A **polled** `get-trail-status` per trail per Region asserting on `IsLogging` **and**
  `LatestDeliveryError`, `LatestDigestDeliveryError`, `LatestCloudWatchLogsDeliveryError`,
  `StartLoggingTime`, `StopLoggingTime`. Six response fields — the four `*Attempt*` ones plus
  `TimeLoggingStarted` and `TimeLoggingStopped` — are documented *"no longer in use"*; a check
  built on one is a permanent `[OK]`, and the last two are word-order homonyms of the live
  `StartLoggingTime` / `StopLoggingTime`
- **GuardDuty enabled** — it consumes CloudTrail management events *"directly from CloudTrail
  through an independent and duplicated stream of events"*, and *"your CloudTrail
  configurations don't affect how GuardDuty consumes and processes the event logs"*. And **log
  file integrity validation on**, with digests delivered to an Object-Locked bucket in a
  separate account: disabling it breaks the chain after one hour and creates no digests at all
  for the period it stays off
- **Do not count on EventBridge.** AWS: *"To record events with one of the CloudTrail
  `detail-type` values, you must enable a CloudTrail trail with logging."* A rule on
  `AWS API Call via CloudTrail` is downstream of the thing being disabled — and a default
  `ENABLED` rule matches only **write** management events, read-only ones needing the state
  `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`. **AWS Config is corroboration, not a
  tripwire** for the same reason in a different shape: `AWS::CloudTrail::Trail` is a recorded
  resource type, but `CLOUD_TRAIL_ENABLED`, `MULTI_REGION_CLOUD_TRAIL_ENABLED` and
  `CLOUDTRAIL_S3_DATAEVENTS_ENABLED` are all **Periodic**, reporting on a schedule rather
  than at the moment of the stop

**Alerting (must be pre-configured)**
- **`StopLogging` or `DeleteTrail` succeeding on any trail → P0**
- **`UpdateTrail` sending `isMultiRegionTrail`, `includeGlobalServiceEvents` or `enableLogFileValidation` as `false` → P0**
- **`PutEventSelectors` resulting in `includeManagementEvents: false`, `readWriteType: ReadOnly`, or advanced selectors that no longer request `eventCategory Equals Management` → P0**
- **`CreateEventDataStore` / `UpdateEventDataStore` with a field selector on `userIdentity.arn` — one identity excluded from management-event logging → P0**
- **`GetTrailStatus` returning `IsLogging: true` with a non-empty `LatestDeliveryError` or `LatestDigestDeliveryError` → P0**
- **`UpdateTrail` repointing `s3BucketName` to a bucket not on the approved-destination list → P1**
- **CloudTrail rows stop arriving from a Region with known workload for longer than its measured quiet window → P1**
- **A logging-configuration read followed within 15 minutes by a scope reduction, same principal → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under
  investigation — and ideally issued from a different account, since the principal that can
  degrade a trail can usually also degrade the record of the response
- `jq`; the stored `describe-trails` and `get-event-selectors` baselines; the approved
  destination bucket and KMS key list; the per-Region workload map the absence detector uses
- A second trail already provisioned and delivering **before** the incident. Standing one up
  mid-incident is worth doing, but it records only from the moment it exists

**Known IOC Baselines**
- Which principals may call `cloudtrail:StopLogging`, `DeleteTrail`, `UpdateTrail`,
  `PutEventSelectors` or `PutInsightSelectors` at all — in most accounts one IaC role and
  one break-glass role, everything else an incident
- Each trail's **home Region**. Every write to a trail must be issued there or it throws
  `InvalidHomeRegionException`, and a responder who guesses wrong gets zero rows
- The approved destination bucket names, their bucket-policy statement IDs, and the SSE-KMS
  key ARNs CloudTrail is permitted to use
- Which trails legitimately run **read-only** as one half of a read/write split, and which
  legitimately carry `excludeManagementEventSources`. Both are documented, supported
  configurations and neither is distinguishable from the attack without this list

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `StopLogging` or `DeleteTrail` succeeds on any trail | CloudTrail (management) | T1685.002 |
| P0 | `UpdateTrail` sending `isMultiRegionTrail`, `includeGlobalServiceEvents` or `enableLogFileValidation` as `false` | CloudTrail (management) | T1685.002 |
| P0 | `PutEventSelectors` resulting in `includeManagementEvents: false`, `readWriteType: ReadOnly`, or advanced selectors with no `eventCategory Equals Management` | CloudTrail (management) | T1685.002 |
| P0 | `CreateEventDataStore` / `UpdateEventDataStore` with a field selector on `userIdentity.arn` — an identity excluded from management-event logging | CloudTrail (management) | T1685.002 |
| P0 | `GetTrailStatus` returning `IsLogging: true` with a non-empty `LatestDeliveryError` or `LatestDigestDeliveryError` | CloudTrail trail status (polled) | T1685.002 |
| P1 | `UpdateTrail` repointing `s3BucketName` to a bucket not on the approved-destination list | CloudTrail (management) | T1685.002 |
| P1 | CloudTrail rows stop arriving from a Region with known workload for longer than its measured quiet window | SIEM ingest volume | T1685.002 |
| P1 | A logging-configuration read followed within 15 minutes by a scope reduction, same principal | CloudTrail (management) | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `PutEventSelectors` setting a non-empty `excludeManagementEventSources` on a trail not baselined for it | CloudTrail (management) | T1685.002 |
| P2 | `PutEventSelectors` on a **trail** with a field selector on `userIdentity.arn` — that principal's **data** events stop being recorded | CloudTrail (management) | T1685.002 |
| P2 | Three or more denied CloudTrail configuration writes by one principal in 15 minutes | CloudTrail (management) | T1685.002 |
| P2 | `PutInsightSelectors` with an empty selector list — Insights collection turned off | CloudTrail (management) | T1685.002 |
| P3 | `StopEventDataStoreIngestion` or `DeleteEventDataStore` on an event data store used as a second recorder | CloudTrail (management) | T1685.002 |
| P3 | `PutBucketPolicy`, `PutBucketLifecycleConfiguration` or `DeleteBucket` on a CloudTrail log-destination bucket | CloudTrail (management), `s3.amazonaws.com` | T1685.002, T1070 |

### Detection Rule Quality Notes

Two of the five source alerts are adequate because their API has exactly one effect. The
third matches an event name whose entire meaning sits in parameters it never reads; the
fourth detects an absence but groups it by the wrong key; the fifth is scoped to a principal
type most access no longer uses.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `Trail Modified` matches `eventName:"UpdateTrail"` with no content check | `UpdateTrail` is the call an operator makes to turn multi-Region logging **on**, attach a CloudWatch Logs group, or migrate the destination bucket. The rule fires identically on the widening and the narrowing, so it is either paged on constantly or muted — and it is muted long before an actor uses it | Match the parameters, not the name. `UpdateTrail` behaves as a partial update and `requestParameters` carries only what was sent, so `isMultiRegionTrail: false` was explicitly requested and `true` does not match. Same for `includeGlobalServiceEvents` and `enableLogFileValidation`; the destination change needs an approved-bucket allowlist and ships as its own rule |
| Nothing in the set matches `PutEventSelectors` or `PutInsightSelectors` | The quiet forms produce no alert at all — management events switched off, `readWriteType` restricted to `ReadOnly`, Insights emptied. The trail keeps running, `IsLogging` stays `true` and `DescribeTrails` is unchanged, so nothing else catches them either | New rule on both calls keyed on the resulting configuration. Insights-off is the **absence** of an `insightType`, because AWS turns Insights off by accepting an empty list |
| Nothing matches the event-data-store calls | Filtering **management** events by `userIdentity.arn` is possible only on an event data store, so the sharpest self-exclusion in the whole technique arrives on an event name the source set does not look at | `Create`/`UpdateEventDataStore` matched alongside `PutEventSelectors` in the same rule; the two cases are separated in the KQL verdict text because they hide different event categories |
| `Trail Logging Stopped` and `Trail Deleted` at P2, `Trail Modified` at P3 | The technique's whole value is elapsed unobserved time, so deferring triage to business hours is not a tuning choice — it is a decision to grant the window. This is the highest-value change in the set and it needs no rule logic at all | P0 for every successful scope reduction; P1 for the signals that need a baseline to interpret |
| `No Logs From AWS CloudTrail` groups by the ingest pipeline's log-stream identifier | Fires once for the whole account and names none of the four causes — trail stopped, delivery broken, selectors narrowed, or the shipper itself down. A responder cannot act on it, and because a shipper outage produces the identical alert it trains people to dismiss the one rule that fires *after* the technique succeeds | Group by **Region** so the alert says where to point `get-trail-status`, and state the four candidate causes in the verdict text |
| The same alert uses a 2h window with threshold `1.0`, and the extract does not record the comparison direction | Two hours is longer than the exposure most of these incidents need, and a below-threshold test that cannot be read as below-threshold from the definition is not auditable. A Region with no workload legitimately produces zero rows and fires forever | Bin no shorter than ingestion lag and no longer than the window you are willing to lose; derive the floor from your own measured quietest hour per Region, and exclude idle Regions **by name** rather than lowering the bar for every Region at once |
| `Audit Logging Configuration Accessed` filters `userIdentity.type:"IAMUser"` | Blind to every assumed-role principal — federated console sessions, instance profiles, CI/CD roles, cross-account access. In an account using SSO or IaC this sees a small and unrepresentative slice of the reads it exists to find | Drop the principal-type filter. Keep `NOT _exists_:userIdentity.invokedBy` and the `*.amazonaws.com` source-IP exclusion, which correctly remove AWS-service-initiated calls |
| The same alert has no `eventSource` filter and ORs `FilterLogEvents` in | `FilterLogEvents` is `logs.amazonaws.com`, not CloudTrail, so one rule spans two services and a P3 on ordinary log reading buries the CloudTrail-configuration reads it was written for | Filter `eventSource: cloudtrail.amazonaws.com`, and demote reading to what it is — a sequence component. It becomes signal only as read→degrade by one principal, shipped as a `temporal_ordered` correlation over an `informational` base rule |
| No alert separates denied CloudTrail writes from successful ones | A principal collecting `AccessDenied` across CloudTrail writes is establishing whether it can blind the account. Folded into the success path it either raises a false "trail is down" — sending a responder to restore a trail that never went down — or is lost in the volume | Success path filtered `errorCode: null`; denials split into their own base rule at `low` with an `event_count` correlation at `medium`. The success path carries **no** threshold, because degrading a trail takes one call and a threshold there gates out the technique's entire footprint |

**Recommended detection — a trail stopped, deleted, or explicitly narrowed in scope.**

```yaml
# CloudTrail Logging Tampered (T1685.002)
#
# The source rules match `StopLogging`, `DeleteTrail` and `UpdateTrail` by event name with
# a bare success filter and no content inspection. Two of the three are adequate because
# the API itself is unambiguous — `StopLogging` has exactly one effect. The third is not:
# `UpdateTrail` is the same call an operator makes to turn multi-Region logging ON, to
# point a trail at a new bucket during a migration, or to attach a CloudWatch Logs group.
# Matching the event name cannot distinguish a narrowing from a widening, so the rule
# either pages on every legitimate trail change or gets muted. Nothing in the set matches
# `PutEventSelectors` or `PutInsightSelectors` at all — the quiet forms of this technique
# leave no event the deployed rules look at.
#
# The discriminator is that the change REDUCES recorded scope. `UpdateTrail` leaves
# unspecified parameters unchanged, so a narrowing flag appears in requestParameters only
# when it was explicitly sent: `isMultiRegionTrail: false` is a narrowing and
# `isMultiRegionTrail: true` is a widening, and they are separable on the event. The same
# is true of `includeGlobalServiceEvents` and `enableLogFileValidation`.
#
# `PutEventSelectors` carries the RESULTING configuration, not the delta. What AWS states
# in a sentence is the cross-type overwrite — "If you apply `AdvancedEventSelectors` to a
# trail, any existing `EventSelectors` are overwritten", and the converse. Same-type
# wholesale replacement is demonstrated rather than stated: the API has no patch or delete
# verb, and the user guide's instruction for reversing a KMS exclusion is to "remove the
# `eventSource` selector, and run the command again" — i.e. resubmit the complete desired
# set. Either way the event shows the end state and never the change. Some end states are
# narrowings on their face — management events off, ReadWriteType restricted to ReadOnly,
# a non-empty ExcludeManagementEventSources, an advanced selector keyed on
# `userIdentity.arn`. The general case is not, and needs a diff against a known-good
# selector baseline. That baseline check is the load-bearing complement to these rules and
# it is not expressible in Sigma. See `detection_note_t1685_002.md`.
#
# FIELD SHAPE — the casing is DOCUMENTED, the array addressing is not.
# The API Reference names the wire parameters `Name`, `S3BucketName`, `IsMultiRegionTrail`,
# `EventSelectors[].ReadWriteType`, `AdvancedEventSelectors[].FieldSelectors[].Field`. What
# CloudTrail writes into `requestParameters` is the INITIAL-LOWERCASE form, and AWS
# publishes two records that show it outright. The success-path one is `StartLogging`:
# `"requestParameters": {"name": "myTrail"}` (CloudTrail concepts, retrieved 2026-08-29).
# The `UpdateTrail` one reads
# `"requestParameters": {"name": "myTrail2", "isMultiRegionTrail": true}` — but read where
# it sits: it is the "Error code and message log example", and carries
# `"errorCode": "TrailNotFoundException"`. It fixes the CASING, which is all the field
# paths below need. It does NOT establish the partial-update semantics claimed above,
# because that call failed and changed nothing; the evidence for that is the CLI example
# cited on `narrow_region`. So the scalar paths are not a guess and do not need confirming.
# What DOES vary is how your backend addresses an element of a selector ARRAY. The dotted
# form used below is what Elastic-family and Sentinel backends produce; a backend that
# requires an explicit index needs `[0]` inserted. AWS publishes no `PutEventSelectors`
# log record, so confirm the selector-array paths — not the scalar ones — against a real
# event before deploying. An unmatched field path fails silently, and this rule set is the
# one where a silent failure is least survivable.
title: CloudTrail trail stopped, deleted, or narrowed in scope
id: 6aa02757-a52b-4125-9029-d4aebc05e3b6
name: cloudtrail_scope_reduced
status: experimental
description: >-
  A CloudTrail trail stopped logging, was deleted, or had its recorded scope reduced —
  multi-Region coverage turned off, global service events dropped, or log file integrity
  validation disabled. Every subsequent action by the caller is unrecorded by that trail
  for as long as the change stands.
references:
  - https://attack.mitre.org/techniques/T1685/002/                                     # retrieved 2026-08-29
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DeleteTrail.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html  # retrieved 2026-08-29 — the UpdateTrail record that fixes the requestParameters casing
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  service:
    eventSource: 'cloudtrail.amazonaws.com'
  # StopLogging and DeleteTrail have exactly one effect each. No content check is possible
  # and none is needed — the API name IS the discriminator for these two. Both carry
  # `requestParameters: {"name": "<trail>"}` and return an empty body, so there is no
  # responseElements object to pivot from either.
  stop_or_delete:
    eventName:
      - 'StopLogging'
      - 'DeleteTrail'
  update_call:
    eventName: 'UpdateTrail'
  # UpdateTrail behaves as a partial update: an omitted optional parameter leaves the
  # setting alone, and requestParameters carries only what was actually sent. AWS never
  # states this in a sentence — the API description says only that UpdateTrail "updates
  # trail settings" — so it is asserted here on a DEMONSTRATION, not a quote: the user
  # guide's `aws cloudtrail update-trail --name my-trail --is-multi-region-trail` example
  # passes that one flag and the returned trail still carries S3BucketName,
  # IncludeGlobalServiceEvents, LogFileValidationEnabled and IsOrganizationTrail unchanged.
  # So a `false` here was explicitly sent, and the widening (`true`) does not match. This
  # is what separates a narrowing from a routine trail edit; the source rule's bare
  # `eventName:"UpdateTrail"` cannot. Confirm it against one real UpdateTrail event from
  # your own IaC pipeline before tuning anything on the absence of a flag.
  narrow_region:
    requestParameters.isMultiRegionTrail: false
  # Narrow, but check the shape before you tune on volume: AWS requires
  # IncludeGlobalServiceEvents to be `true` on a multi-Region trail, and since 22 Nov 2021
  # the events AWS names — CloudFront, IAM and STS; NOT Route 53, which that sentence does
  # not list — are recorded in us-east-1 only. So a successful `false` here means a
  # SINGLE-Region trail, and it only removes anything real when that trail's home Region is
  # us-east-1. Rare, which is why it stays at this level.
  narrow_global_events:
    requestParameters.includeGlobalServiceEvents: false
  # Disabling validation breaks the digest chain one hour later and CloudTrail creates no
  # digest files for the period it stays off — so it destroys the ability to prove the
  # remaining logs are complete, without stopping logging.
  narrow_validation:
    requestParameters.enableLogFileValidation: false
  success:
    errorCode: null
  condition: service and success and (stop_or_delete or (update_call and (narrow_region or narrow_global_events or narrow_validation)))
falsepositives:
  - 'A migration that legitimately consolidates several single-Region trails into one
    multi-Region trail will emit `isMultiRegionTrail: false` on the trails being wound
    down. Correlate against a change record; the winding-down trails should also be
    deleted shortly afterwards by the same pipeline principal.'
  - Infrastructure-as-code drift reconciliation re-applying a stored trail definition.
    Filter on the pipeline role ARN once baselined — not on the event name.
  - '`enableLogFileValidation: false` is occasionally sent by an older IaC provider that
    writes every parameter on every apply rather than only the changed ones. Confirm
    whether your provider does this before tuning it out; if it does, the narrowing flags
    are not trustworthy from that principal and the selector baseline in the playbook
    becomes the primary control for it.'
level: high
---
# Repointing the destination bucket is a scope reduction that leaves every other trail
# setting intact, so it matches none of the flags above. It is separated from Rule 1
# because it needs an allowlist of legitimate destination buckets to be meaningful, and an
# allowlist is a deployment-time input rather than a property of the event.
title: CloudTrail trail destination repointed to an unapproved bucket
id: 6b249eab-0e57-4e34-9ed3-d32ca982a216
name: cloudtrail_destination_repointed
status: experimental
description: >-
  A trail's S3 destination bucket was changed to a bucket that is not on the approved
  log-destination list. Delivery continues and the trail still reports IsLogging true,
  but the logs land somewhere the detection pipeline does not read and the retention,
  object-lock and access controls of the approved bucket no longer apply.
references:
  - https://attack.mitre.org/techniques/T1685/002/                                     # retrieved 2026-08-28
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html  # retrieved 2026-08-28
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName: 'UpdateTrail'
  # Non-empty test. UpdateTrail is a partial update, so an edit that did not touch the
  # bucket carries no s3BucketName at all — and an absent field does not match the
  # allowlist below, which would make `not approved_destination` true on every unrelated
  # trail edit. `|re: '\S'` matches any non-empty value; `|exists: true` is the
  # spec-native equivalent if your backend supports it.
  repoint:
    requestParameters.s3BucketName|re: '\S'
  # REPLACE THESE with your own approved log-destination bucket names before deploying.
  # Left as placeholders deliberately: a shipped allowlist of somebody else's bucket names
  # is an allowlist of nothing, and this rule fires on every trail edit until it is filled
  # in — which is the correct failure mode for a rule whose whole content is an allowlist.
  approved_destination:
    requestParameters.s3BucketName:
      - '<approved-log-archive-bucket>'
      - '<approved-log-archive-bucket-secondary>'
  success:
    errorCode: null
  condition: selection and success and repoint and not approved_destination
falsepositives:
  - A genuine log-archive migration. It should appear in change control and should be
    followed by the new bucket being added to this allowlist.
level: high
---
# None of the source rules match this call at all. It is the quiet form of the technique:
# the trail keeps running, `IsLogging` stays true, `DescribeTrails` looks unchanged, and
# the events the actor is about to generate simply stop matching any selector.
title: CloudTrail event selectors narrowed or Insights disabled
id: a2fefb16-3c15-4529-90cd-6fa8673c9fac
name: cloudtrail_selectors_narrowed
status: experimental
description: >-
  A trail's event selectors, or an event data store's advanced event selectors, were
  rewritten into a configuration that records less — management events excluded, write
  events dropped by restricting ReadWriteType to ReadOnly, a management event source
  excluded, a selector filtering by the caller's own identity, or Insights event
  collection turned off. The trail continues to report that it is logging.
references:
  - https://attack.mitre.org/techniques/T1685/002/                                            # retrieved 2026-08-29
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_PutEventSelectors.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AdvancedFieldSelector.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_EventSelector.html     # retrieved 2026-08-29
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html  # retrieved 2026-08-29
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selectors_call:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName: 'PutEventSelectors'
  # A trail configured NOT to include management events records no control-plane activity
  # at all. There is no prior state in which this is a widening.
  mgmt_off:
    requestParameters.eventSelectors.includeManagementEvents: false
  # ReadOnly means every mutating call disappears while the trail still reports management
  # events as enabled. The sharpest quiet form available on this API.
  read_only:
    requestParameters.eventSelectors.readWriteType: 'ReadOnly'
  # A non-empty ExcludeManagementEventSources removes one service's control plane from the
  # trail. The value set is CLOSED: AWS documents it as empty, or containing
  # `kms.amazonaws.com` or `rdsdata.amazonaws.com`, and nothing else — so this block cannot
  # fire on "an actor excluding some other service", because the API will not accept one.
  # It fires on the documented cost-control configuration, which is both a real reduction
  # in what is recorded and common. Baseline it per trail and filter the trails that
  # legitimately carry it; do not delete the block, because the same value on the trail
  # that is your KMS audit source is the attack.
  excluded_source:
    requestParameters.eventSelectors.excludeManagementEventSources|contains: 'amazonaws.com'
  # Self-exclusion by caller identity — but read the scope carefully, because it is not
  # what it first looks like. On a TRAIL, AWS documents `userIdentity.arn` as available to
  # filter DATA events and network activity events only; the management-event field set for
  # a trail is `eventCategory`, `eventSource` and `readOnly`. `eventName`, `eventType`,
  # `sessionCredentialFromConsole` and `userIdentity.arn` become available for management
  # events only on an EVENT DATA STORE. So:
  #   PutEventSelectors  + userIdentity.arn -> one principal's DATA-event activity vanishes
  #   Update/CreateEventDataStore + same    -> one principal's MANAGEMENT activity vanishes
  # Both are self-exclusion and both are matched, via the two branches in `condition:`.
  # Neither has a benign form: there is no operational reason to stop recording one
  # principal while recording every other. The management-event branch is the sharper one.
  self_exclusion:
    requestParameters.advancedEventSelectors.fieldSelectors.field: 'userIdentity.arn'
  # Event data stores take the same advancedEventSelectors structure at the top level of
  # requestParameters, which is why `self_exclusion` resolves against them unchanged. The
  # eventSelectors-shaped blocks above do not apply here and simply never match — they are
  # ORed, so that costs nothing.
  eds_call:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName:
      - 'CreateEventDataStore'
      - 'UpdateEventDataStore'
  insights_call:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName: 'PutInsightSelectors'
  # Insights is turned off by passing an EMPTY selector list, so the discriminator is the
  # ABSENCE of an insightType under insightSelectors. `field: null` matches when the field
  # is absent, which is exactly the empty-array case after flattening. Verify this renders
  # as an absent field on your backend rather than an empty array before relying on it.
  insights_emptied:
    requestParameters.insightSelectors.insightType: null
  success:
    errorCode: null
  condition: success and ((selectors_call and (mgmt_off or read_only or excluded_source or self_exclusion)) or (eds_call and self_exclusion) or (insights_call and insights_emptied))
falsepositives:
  - '`excludeManagementEventSources` is the dominant false positive here and the one to
    tune first. Its documented value set is exactly `kms.amazonaws.com` and
    `rdsdata.amazonaws.com`, both of which are the standard cost-control configuration, so
    this block fires on a common benign change. Filter by TRAIL NAME once you have
    baselined which trails legitimately carry it — never by value, which would disable the
    block outright on the trail that is your KMS audit source.'
  - A trail deliberately dedicated to read-only events as one half of a read/write split
    across two buckets. That configuration is documented by AWS and is legitimate; it must
    be baselined per trail, since the same value on the trail that carries your write
    events is the attack.
  - Insights being disabled during a cost review. Rare, traceable, and worth confirming.
level: high
---
title: CloudTrail logging configuration read
id: 30df39a0-e436-4206-b4b6-1403634acffa
name: cloudtrail_config_read
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html  # retrieved 2026-08-28
tags:
  - attack.discovery
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  # justified: base rule for the temporal correlation below. These are ordinary read calls
  # that every console visit to the CloudTrail page emits; they carry no signal alone and
  # this rule is deployed at informational level solely so the sequence can resolve it.
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName:
      - 'DescribeTrails'
      - 'ListTrails'
      - 'GetTrailStatus'
      - 'GetEventSelectors'
      - 'GetInsightSelectors'
  # The success filter is on the BASE rule, not only on the correlation. A denied read
  # followed by a successful tamper is a different story from a successful survey followed
  # by a tamper, and folding them together would let a failed probe raise a `high`.
  success:
    errorCode: null
  condition: selection and success
level: informational
---
# The survey-then-degrade fingerprint. An actor who does not already know the trail
# topology has to ask, and CloudTrail answers with the trail names, their home Regions,
# their buckets and their selectors — everything needed to choose which trail to degrade
# and how. An operator who edits a trail through the console also reads first, so this is
# a sequence, not a signature: it is worth `high` only because the second half is already
# `high` on its own and the ordering raises confidence, not because reading is suspicious.
title: CloudTrail configuration surveyed then trail scope reduced by the same principal
id: 3ea80b9a-e628-4ebc-b716-5aa230861c83
status: experimental
description: >-
  One principal read the account's CloudTrail configuration and then, within fifteen
  minutes, stopped, deleted or narrowed a trail. The read tells the actor which trail
  covers the Region it intends to work in; the write removes it.
references:
  - https://attack.mitre.org/techniques/T1685/002/   # retrieved 2026-08-28
tags:
  - attack.defense-impairment
  - attack.t1685.002
correlation:
  type: temporal_ordered
  rules:
    - cloudtrail_config_read
    - cloudtrail_scope_reduced
  group-by:
    - userIdentity.arn
  timespan: 15m
level: high
---
title: CloudTrail configuration write denied
id: 046aa464-575d-491b-a104-6b8f96a6377a
name: cloudtrail_tamper_denied
status: experimental
description: Base rule — volume component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html  # retrieved 2026-08-28
tags:
  - attack.defense-impairment
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
      - 'CreateEventDataStore'
      - 'DeleteEventDataStore'
      - 'UpdateEventDataStore'
      - 'StopEventDataStoreIngestion'
  # AccessDenied is the IAM-evaluated denial. AccessDeniedException is the
  # service-evaluated form. Match both prefix-tolerantly, and confirm which one your
  # account actually produces against a real denied event before tuning anything on it.
  denied:
    errorCode|contains: 'AccessDenied'
  condition: selection and denied
level: low
---
# Kept strictly separate from the success-path rules. A principal collecting AccessDenied
# across CloudTrail writes is finding out whether it can blind the account before it tries
# anything else, and it must not share an alert with a trail that is actually down.
#
# Threshold basis: derived from the API surface, not from an observed baseline. Degrading
# a single trail takes ONE call, so the success path carries no threshold at all — putting
# one there would gate the technique's own footprint out of existence. The denial path is
# different: an operator who lacks CloudTrail permissions discovers it on the first or
# second call and stops. Three or more distinct denied CloudTrail writes in fifteen
# minutes is an actor working through the API surface. Baseline against your own account
# before deploying; this is a starting point, not a measurement.
title: CloudTrail configuration writes denied repeatedly for one principal
id: e7ce3531-afb7-4cfb-8c73-fe898212bc92
status: experimental
description: >-
  One principal was denied three or more CloudTrail configuration writes within fifteen
  minutes — an actor establishing whether it can degrade logging before acting.
references:
  - https://attack.mitre.org/techniques/T1685/002/   # retrieved 2026-08-28
tags:
  - attack.defense-impairment
  - attack.t1685.002
correlation:
  type: event_count
  rules:
    - cloudtrail_tamper_denied
  group-by:
    - userIdentity.arn
  timespan: 15m
  condition:
    gt: 2
level: medium
```

Reproduced byte-for-byte from the first rule document of
`detections/sigma_t1685_002.yml`; the file's leading comment block, which records what the
source alerts got wrong and carries the field-shape evidence, is not repeated here. Six
further documents ship in that file: the destination-repointed rule (`high`, with a
placeholder allowlist that **must** be filled in before deployment), the selectors-narrowed
rule (`high`, covering `PutEventSelectors`, `PutInsightSelectors` and the event-data-store
route), a logging-configuration-read base rule (`informational`) with the survey-then-degrade
`temporal_ordered` correlation (`high`), and a denied-write base rule (`low`) with its
`event_count` correlation (`medium`). **Deploy the file, not this excerpt.**

**What these rules structurally cannot do — and here that list is the point, not a
footnote.** Three gaps.

**The absence.** Every rule above needs an event to exist, and after a successful stop the
events that would fire them are never generated: the rule set goes quiet, and quiet is
indistinguishable from a calm Tuesday. No threshold fires on nothing happening. Only two
things answer it, both architecture rather than detection — a **second recorder**, so the gap
in one is a presence in the other, and an **absence detector** on per-Region ingest volume,
which has no event to key on, therefore no natural threshold, and must be calibrated from
your own measured floor. Companion 1 in `detections/kql_t1685_002.kql` is that detector, and
the only rule here that fires after the technique has already worked.

**The general narrowing.** `PutEventSelectors` carries the resulting configuration rather
than the delta — AWS states the cross-type case outright (*"If you apply
`AdvancedEventSelectors` to a trail, any existing `EventSelectors` are overwritten"*) and the
same-type case follows from there being no patch verb. A set that drops one data-resource ARN
or tightens one `StartsWith` prefix is structurally identical to the widening that added it,
and only a diff against the stored baseline separates them — Query 2, which is also the only
check that survives a compromised logging pipeline whose ARN is on every allowlist here.

**Delivery**, which generates no CloudTrail event at all because nothing about the trail
changed. Visible only on `GetTrailStatus`, in `LatestDeliveryError` /
`LatestDigestDeliveryError` / `LatestCloudWatchLogsDeliveryError` — never in `IsLogging`.

**On error strings:** denials are `AccessDenied` (IAM-evaluated) and `AccessDeniedException`
(service-evaluated), no EC2-style `Client.` prefix; match both prefix-tolerantly and confirm
against a real denied event. The full non-denial set per call is in the KQL file's trailing
comments and in §6, and is **not** uniform — `PutInsightSelectors` omits `ConflictException`
and `InsufficientDependencyServiceAccessPermissionException` that the other four carry. The
operationally useful one is `InvalidHomeRegionException`: these calls must be issued from the
trail's home Region, so an actor guessing wrong leaves a failed call in the Region it
guessed. Full reasoning is in `detections/detection_note_t1685_002.md`.

---

### Key Investigation Queries

> **Resolve the home Region before anything else — Query 1 does it for you.** `DeleteTrail`, `UpdateTrail` and `PutEventSelectors` must be issued from the trail's home Region, and management events land in the Region where the call was made, so a query run against the wrong Region returns zero and reads as clean. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows. An Event history lookup accepts **one** attribute filter plus a time range, which is why these iterate event names rather than combining filters.

#### Query 1 — Reconstruct: which trail was degraded, by whom, and in which direction

`lookup-events` reads **Event history**, which is not affected by trail configuration — so
this query still works when the trail it is describing is switched off. That is the single
most important operational fact in this playbook.

```bash
WINDOW="24 hours ago"
# Enumerate the Regions actually enabled for the account rather than assuming a list.
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

for R in $REGIONS; do
  for EV in StopLogging DeleteTrail UpdateTrail PutEventSelectors PutInsightSelectors \
            CreateEventDataStore UpdateEventDataStore StopEventDataStoreIngestion \
            DeleteEventDataStore StartLogging; do
    aws cloudtrail lookup-events \
      --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
      --start-time "$(date -u -d "$WINDOW" +%Y-%m-%dT%H:%M:%SZ)" \
      --region "$R" --output json 2>/dev/null
  done
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "cloudtrail.amazonaws.com") |
    (.userIdentity.arn // "") as $arn | ($arn | split("/")) as $p |
    # assumed-role ARN: role name is the 2nd "/" segment; the LAST segment is the SESSION
    # name. IAM-user ARN: the name IS the last segment. One idiom does not serve both.
    ((if ($arn | test(":assumed-role/")) then $p[1] else $p[-1] end)) as $caller |
    (.requestParameters // {}) as $rp |
    {time: .eventTime, event: .eventName, region: .awsRegion,
     trail: ($rp.name // $rp.trailName // $rp.eventDataStore // "<none>"),
     caller_arn: $arn, caller_name: $caller,
     access_key: .userIdentity.accessKeyId,        # feeds ACCESS_KEY_ID in Query 4
     invoked_by: (.userIdentity.invokedBy // "-"),
     # Direction of travel. A flag is present only when it was explicitly sent — that
     # asymmetry is the entire signal, and it is why the source rule cannot work.
     narrowing: ([ (if $rp.isMultiRegionTrail        == false then "multi-region-off"   else empty end),
                   (if $rp.includeGlobalServiceEvents == false then "global-events-off" else empty end),
                   (if $rp.enableLogFileValidation    == false then "validation-off"    else empty end),
                   (if ($rp.s3BucketName // "") != ""          then "bucket-repointed"  else empty end),
                   (if (.eventName | test("^(StopLogging|DeleteTrail)$")) then "logging-stopped" else empty end)
                 ]),
     new_bucket: ($rp.s3BucketName // "-"),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Read it as a direction, not a list of events. A row whose `narrowing` array is non-empty
with `error: "SUCCESS"` is the incident; a row carrying `isMultiRegionTrail: true` with an
empty `narrowing` is an operator widening coverage — exactly the near-miss the source rule
cannot distinguish. `invoked_by` other than `-` means a service made the call on a
principal's behalf, usually CloudFormation drift reconciliation: contain the principal
without disabling the stack update path and the next apply re-applies the change. Rows with
an `error` are the probing path — count them per `caller_arn`, never score them as changes,
because a failed `StopLogging` read as a stop sends a responder to restore a trail that
never went down. Record `trail`, `region`, `caller_arn`, `access_key` and the `time` of the
**first** successful narrowing: that timestamp starts the gap and every later section
depends on it. A `StartLogging` row following a `StopLogging` row by the same principal is
the actor closing the window behind itself — the trail looks healthy by the time anyone
looks.

#### Query 2 — Sweep: live posture of every trail in every Region, against the baseline

The account-wide ground truth, and the only check that catches a narrowing too subtle to
read off the event. It asserts three independent things per trail — is it logging, is it
*delivering*, do its selectors match the baseline — because each fails without the others
changing.

```bash
BASELINE_DIR="<path-to-stored-selector-baseline>"   # one <trail-name>.json per trail
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

for R in $REGIONS; do
  # DescribeTrails' response key is lowercase `trailList`. --no-include-shadow-trails
  # keeps each multi-Region trail to its home Region so it is assessed exactly once.
  aws cloudtrail describe-trails --no-include-shadow-trails --region "$R" \
      --output json 2>/dev/null \
    | jq -r --arg r "$R" '.trailList[]? |
        [$r, .Name, .HomeRegion, .TrailARN, (.IsMultiRegionTrail|tostring),
         (.LogFileValidationEnabled|tostring), (.IsOrganizationTrail|tostring),
         .S3BucketName] | @tsv'
done | sort -u | while IFS=$'\t' read -r R NAME HOME ARN MULTI VALID ORG BUCKET; do
  [ -z "$NAME" ] && continue
  # Pass the ARN, not the name: an organization trail read from a member account requires
  # the full ARN, and the ARN is unambiguous everywhere else too.
  ST=$(aws cloudtrail get-trail-status --name "$ARN" --region "$HOME" --output json 2>&1)
  if ! printf '%s' "$ST" | jq -e '.IsLogging != null' >/dev/null 2>&1; then
    echo "[!] $HOME/$NAME INCONCLUSIVE — get-trail-status returned no status: $(printf '%s' "$ST" | head -c 160)"
    continue
  fi
  LOGGING=$(printf '%s' "$ST" | jq -r '.IsLogging')
  DERR=$(printf   '%s' "$ST" | jq -r '.LatestDeliveryError       // ""')
  DGERR=$(printf  '%s' "$ST" | jq -r '.LatestDigestDeliveryError // ""')
  [ "$LOGGING" = "true" ] || echo "[!] $HOME/$NAME IsLogging=false — trail is STOPPED"
  [ -z "$DERR" ]  || echo "[!] $HOME/$NAME LatestDeliveryError: $DERR"
  [ -z "$DGERR" ] || echo "[!] $HOME/$NAME LatestDigestDeliveryError: $DGERR"
  [ "$VALID" = "true" ] || echo "[!] $HOME/$NAME log file validation is OFF — no digest chain"
  # Emit the ARN: every later block keys on it, and get-trail-status on an organization
  # trail from a member account requires the full ARN rather than the name.
  echo "[i] $HOME/$NAME arn=$ARN multiRegion=$MULTI org=$ORG bucket=$BUCKET"

  # Selector diff. PutEventSelectors carries the RESULT, not the delta, so only a diff
  # against a stored baseline sees a narrowing that is not narrow on its face.
  LIVE=$(aws cloudtrail get-event-selectors --trail-name "$ARN" --region "$HOME" \
           --output json 2>/dev/null | jq -S 'del(.TrailARN)')
  WANT_FILE="$BASELINE_DIR/$NAME.json"
  if [ -z "$LIVE" ]; then
    echo "[!] $HOME/$NAME INCONCLUSIVE — get-event-selectors returned nothing"
  elif [ ! -f "$WANT_FILE" ]; then
    echo "[!] $HOME/$NAME has NO stored selector baseline — cannot assess; record one now"
  elif [ "$LIVE" = "$(jq -S 'del(.TrailARN)' "$WANT_FILE")" ]; then
    echo "[OK] $HOME/$NAME selectors match baseline"
  else
    echo "[!] $HOME/$NAME SELECTOR DRIFT"
    diff <(printf '%s\n' "$LIVE") <(jq -S 'del(.TrailARN)' "$WANT_FILE") | sed 's/^/      /'
  fi
done
echo "[i] Sweep complete — every [!] is unremediated, and every INCONCLUSIVE is UNASSESSED, not clean"
```

`IsLogging=false` is the loud form. A non-empty `LatestDeliveryError` **with**
`IsLogging=true` is the S3-side break — the trail reports healthy and delivers nothing —
which is why this asserts on the error fields separately rather than trusting the logging
flag. `SELECTOR DRIFT` is the narrowing the events could not describe: read the diff for
`IncludeManagementEvents` flipping to `false`, `ReadWriteType` moving to `ReadOnly`, a
`FieldSelector` on `userIdentity.arn` appearing, or an `eventCategory Equals Management`
selector disappearing. A trail with **no stored baseline** prints `[!]`, not `[OK]` — it has
not been assessed, and on this technique that difference is the whole game.

#### Query 3 — Bound the gap, and prove it with the digest chain

The impact is a period of time. This bounds it, then uses log file integrity validation to
state on evidence that nothing was delivered inside it — the difference between "we think
logging was off for two hours" and a finding that survives review.

```bash
TRAIL_ARN="<trail-arn-from-Query-2>"
HOME_REGION="<region-from-Query-1>"
GAP_START="<time-from-Query-1>"                      # first successful narrowing
GAP_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"             # or the StartLogging time from Query 1

ST=$(aws cloudtrail get-trail-status --name "$TRAIL_ARN" --region "$HOME_REGION" --output json 2>&1)
if printf '%s' "$ST" | jq -e '.IsLogging != null' >/dev/null 2>&1; then
  printf '%s' "$ST" | jq '{IsLogging, StopLoggingTime, StartLoggingTime,
                           LatestDeliveryTime, LatestDeliveryError,
                           LatestDigestDeliveryTime, LatestDigestDeliveryError}'
  echo "[i] StopLoggingTime / StartLoggingTime are the authoritative boundaries. Do NOT read"
  echo "    TimeLoggingStopped / TimeLoggingStarted — those two are documented 'no longer in"
  echo "    use', are permanently empty, and differ only in word order."
else
  echo "[!] INCONCLUSIVE — could not read trail status: $(printf '%s' "$ST" | head -c 200)"
fi

# The digest chain is what turns "we think" into evidence. It covers only periods in which
# validation was ENABLED — if the actor disabled it, this reports the break, which is
# itself the finding rather than a failure of the check.
# --trail-arn, --start-time AND --region are all required ("The validate-logs command is
# Region specific"), and an ORGANIZATION trail additionally requires --account-id. Omit it
# and the command errors — which a responder can easily misread as evidence of a gap.
aws cloudtrail validate-logs --trail-arn "$TRAIL_ARN" --region "$HOME_REGION" \
  --start-time "$GAP_START" --end-time "$GAP_END" --verbose 2>&1 | tail -40
# Organization trail: add --account-id "<this-account-id>" to the call above.
```

`StopLoggingTime` and `StartLoggingTime` bound the window; anything done between them was
never written to this trail and never will be. The start boundary is fuzzy and the end is
sharp. AWS documents that after logging is turned off *"the trail can still receive events
that occurred before logging was turned off"*, decided from the most recent stop time —
which is why the `StopLogging` call itself normally does appear in the trail it stopped, and
why the loud form is self-recording. The same mechanism means delayed events delivered after
a restart *"are not evaluated"* against event selectors, so a post-recovery log file
carrying a category the trail is not configured for is expected, not a second narrowing.
`validate-logs` reporting a broken or absent chain across the window is positive evidence
that files are missing; a chain that validates cleanly either side bounds the gap.

#### Query 4 — Session reconstruction: everything the principal did, inside and outside the gap

```bash
ACCESS_KEY_ID="<access-key-from-Query-1>"
GAP_START="<time-from-Query-1>"
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

for R in $REGIONS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
    --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$R" --output json 2>/dev/null
done | \
  jq -r --arg t "$GAP_START" '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource, region: .awsRegion,
     phase: (if .eventTime >= $t then "IN-OR-AFTER-GAP" else "before" end),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

**This runs against Event history, so it sees management events regardless of what happened
to the trail** — 90 days, in the Region where each call landed. That makes it the most
valuable query here, and the one a responder who believes "the account went dark" will not
think to run. Read `before` rows for the survey that preceded the change, and
`IN-OR-AFTER-GAP` rows for what the window was bought for — `CreateAccessKey`,
`PutUserPolicy`, `UpdateAssumeRolePolicy`, `CreateUser`, `AssumeRole` into a new role — each
outliving everything in §3 and routing to its own playbook. Two limits to report rather than
work around: Event history holds **no data, Insights or network activity events**, so S3
object reads and Lambda invocations in the window are unknowable from here; and a credential
minted inside the gap has its own `accessKeyId`, so re-run per key until it converges.

**Corroborate against the two recorders the tamper did not touch.** Where they disagree with
the picture above, they are right. **GuardDuty** (`aws guardduty list-findings` per Region)
consumes its own duplicated CloudTrail stream — but read the finding scope literally:
`Stealth:IAMUser/CloudTrailLoggingDisabled` is documented as triggered by *"a successful
deletion or update of a trail"* or by deletion of the log bucket, so **`StopLogging` is not
named**, nor is `PutEventSelectors`, and its default severity is **Low**, meaning it paged
nobody. `DefenseEvasion:IAMUser/AnomalousBehavior` (Medium) does model `StopLogging`, but
fires only when the call is anomalous *for that principal* — silent when the actor uses a
role that routinely administers CloudTrail. And any **organization trail** visible to
`describe-trails --include-shadow-trails` means the gap here is a *presence* in the
management account's bucket: that is where the window's events actually are, so request them.
Empty output from either is a finding about your coverage, not an all-clear.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**Capture, then restore recording — before touching the attacker.** Every containment action
taken while the trail is down is itself unrecorded, so a responder who disables the
attacker's keys first performs the most consequential actions of the incident off the
record. Capture precedes restore because `put-event-selectors` in Step 3 overwrites the
attacker's configuration with no version history.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being contained. Confirm first that the responder role is exempt from any
> existing `cloudtrail:` deny guardrail — one that catches the responder turns Step 1 into
> an `AccessDenied` at the worst possible moment.

#### Step 1 — Capture the tampered configuration, then restart logging

```bash
TRAIL="<trail-from-Query-1>"
HOME_REGION="<region-from-Query-1>"
EVIDENCE="/tmp/ir-cloudtrail-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$EVIDENCE"

for CMD in "describe-trails --trail-name-list $TRAIL" "get-event-selectors --trail-name $TRAIL" \
           "get-insight-selectors --trail-name $TRAIL" "get-trail-status --name $TRAIL"; do
  OUT=$(aws cloudtrail $CMD --region "$HOME_REGION" --output json 2>&1)
  F="$EVIDENCE/$(echo "$CMD" | awk '{print $1}')-tampered.json"
  if echo "$OUT" | jq -e . >/dev/null 2>&1; then printf '%s\n' "$OUT" > "$F"; echo "[OK] captured $F"
  else echo "[!] could not capture '$CMD': $(printf '%s' "$OUT" | head -c 120)"; fi
done

# StopLogging is the only API that suspends recording; StartLogging is its inverse. Both
# must be issued from the trail's HOME Region or they throw InvalidHomeRegionException, and
# neither works against a shadow trail.
if aws cloudtrail get-trail-status --name "$TRAIL" --region "$HOME_REGION" >/dev/null 2>&1; then
  aws cloudtrail start-logging --name "$TRAIL" --region "$HOME_REGION" && \
    echo "[OK] Logging restarted on $TRAIL at $(date -u +%Y-%m-%dT%H:%M:%SZ) — record this as the gap END"
else
  echo "[!] $TRAIL not found in $HOME_REGION — DeleteTrail is irreversible, or the home Region is wrong."
  echo "    Recreate from IaC with the SAME name, bucket and prefix. A trail ARN is"
  echo "    arn:aws:cloudtrail:<region>:<account>:trail/<name>, so an identical recreation"
  echo "    keeps the destination bucket policy's aws:SourceArn condition valid; a renamed"
  echo "    one does not, and also breaks KMS key policy and SIEM ingestion references."
  echo "    aws cloudtrail create-trail --name \"$TRAIL\" --s3-bucket-name <approved-bucket> \\"
  echo "      --is-multi-region-trail --enable-log-file-validation --region \"$HOME_REGION\""
fi
```

> `StartLogging` restores recording from this moment and recovers nothing from the gap.
> `DeleteTrail` destroys the trail but **not** the delivered evidence: AWS states that
> *"while deleting a CloudTrail trail is an irreversible action, CloudTrail does not delete
> log files in the Amazon S3 bucket for that trail, the Amazon S3 bucket itself, or the
> CloudWatch log group to which the trail delivers events."* Do not let anyone tidy the
> bucket while recreating the trail.

#### Step 2 — Repair delivery, which restarting logging does not fix

```bash
TRAIL_ARN="<trail-arn-from-Query-2>"
HOME_REGION="<region-from-Query-1>"
LOG_BUCKET="<approved-log-archive-bucket>"
EVIDENCE="<evidence-dir-from-Step-1>"

ST=$(aws cloudtrail get-trail-status --name "$TRAIL_ARN" --region "$HOME_REGION" --output json 2>&1)
# D-0: a failed get-trail-status leaves DERR empty for the same reason a healthy trail does.
# Test that the call actually returned status BEFORE reading the error field, or "could not
# check" lands in the "delivery is fine" branch.
if ! printf '%s' "$ST" | jq -e '.IsLogging != null' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — get-trail-status returned no status for $TRAIL_ARN in $HOME_REGION:"
  echo "    $(printf '%s' "$ST" | head -c 200)"
  echo "    Delivery health is UNASSESSED. Resolve this before treating the trail as repaired."
  DERR=""
else
  DERR=$(printf '%s' "$ST" | jq -r '.LatestDeliveryError // ""')
fi
if [ -n "$DERR" ]; then
  echo "[!] Delivery broken S3-side: $DERR — restarting logging did NOT fix this"
  aws s3api get-bucket-policy --bucket "$LOG_BUCKET" --output json \
    > "$EVIDENCE/bucket-policy-as-found.json" 2>/dev/null
  aws s3api get-bucket-lifecycle-configuration --bucket "$LOG_BUCKET" --output json \
    > "$EVIDENCE/bucket-lifecycle-as-found.json" 2>/dev/null
  echo "[i] Restore the two required statements: AWSCloudTrailAclCheck20150319 allowing"
  echo "    cloudtrail.amazonaws.com s3:GetBucketAcl on the bucket ARN, and"
  echo "    AWSCloudTrailWrite20150319 allowing s3:PutObject on"
  echo "    arn:aws:s3:::$LOG_BUCKET/[prefix/]AWSLogs/<account-id>/* with s3:x-amz-acl ="
  echo "    bucket-owner-full-control and aws:SourceArn = $TRAIL_ARN. An organization trail"
  echo "    needs a third, AWSCloudTrailOrganizationWrite20150319, on AWSLogs/<o-orgid>/*."
  echo "[i] CloudTrail retries delivery for 30 DAYS after a misconfiguration, so fixing the"
  echo "    policy inside that window RECOVERS the files that could not be written. This is"
  echo "    the only genuinely reversible variant of this technique — do not delete the trail"
  echo "    to stop the retry charges until you have decided against recovery."
elif printf '%s' "$ST" | jq -e '.IsLogging != null' >/dev/null 2>&1; then
  echo "[OK] No LatestDeliveryError on $TRAIL_ARN"
fi
```

#### Step 3 — Restore selectors, coverage and validation to the known-good baseline

```bash
TRAIL_ARN="<trail-arn-from-Query-2>"
HOME_REGION="<region-from-Query-1>"
TRAIL="<trail-from-Query-1>"
BASELINE_DIR="<path-to-stored-selector-baseline>"

# PutEventSelectors carries the RESULTING set, which is why the baseline file is a complete
# configuration rather than a patch — and why re-applying it is a full restore.
BF="$BASELINE_DIR/$TRAIL.json"
if [ -f "$BF" ]; then
  if jq -e '.AdvancedEventSelectors[]?' "$BF" >/dev/null 2>&1; then
    aws cloudtrail put-event-selectors --trail-name "$TRAIL_ARN" --region "$HOME_REGION" \
      --advanced-event-selectors "$(jq -c '.AdvancedEventSelectors' "$BF")" && \
      echo "[OK] Restored advanced event selectors on $TRAIL from baseline"
  else
    aws cloudtrail put-event-selectors --trail-name "$TRAIL_ARN" --region "$HOME_REGION" \
      --event-selectors "$(jq -c '.EventSelectors' "$BF")" && \
      echo "[OK] Restored basic event selectors on $TRAIL from baseline"
  fi
else
  echo "[!] No baseline at $BF — do NOT guess. Logging all read and write management events"
  echo "    is the AWS default and the safe interim state:"
  echo "    aws cloudtrail put-event-selectors --trail-name \"$TRAIL_ARN\" --region \"$HOME_REGION\" \\"
  echo "      --event-selectors '[{\"ReadWriteType\":\"All\",\"IncludeManagementEvents\":true}]'"
fi

aws cloudtrail update-trail --name "$TRAIL_ARN" --region "$HOME_REGION" \
  --is-multi-region-trail --enable-log-file-validation && \
  echo "[OK] Multi-Region coverage and log file validation re-enabled on $TRAIL"
echo "[i] The digest chain does not heal: no digest files exist for any period in which"
echo "    validation was off or logging was stopped, so that span stays unprovable"
echo "    permanently. Re-enabling starts a new chain from now."
```

#### Step 4 — Revoke sessions and contain the acting principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REVOKE_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$NOW"'"}}}]}'
DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["cloudtrail:StopLogging","cloudtrail:DeleteTrail","cloudtrail:UpdateTrail","cloudtrail:PutEventSelectors","cloudtrail:PutInsightSelectors","cloudtrail:CreateEventDataStore","cloudtrail:UpdateEventDataStore","cloudtrail:DeleteEventDataStore","cloudtrail:StopEventDataStoreIngestion","s3:PutBucketPolicy","s3:DeleteBucketPolicy","s3:PutLifecycleConfiguration"],"Resource":"*"}]}'

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')        # user ARN: name = LAST segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] Disabled key $K for user $U"
  done
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyLoggingChange" \
    --policy-document "$DENY_DOC" && echo "[OK] Denied further logging changes by user $U"
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')         # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document "$REVOKE_DOC" && echo "[OK] Revoked pre-existing sessions for role $R"
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyLoggingChange" \
    --policy-document "$DENY_DOC" && echo "[OK] Denied further logging changes by role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

> Disable, do not delete: an inactive key stays enumerable and keeps its creation metadata.
> `aws:TokenIssueTime` denies only tokens issued **before** the cutoff, so a credential
> re-fetched afterwards from IMDS or a fresh `AssumeRole` is not denied — it kills leaked
> session tokens, it does not gate the role. **Apply this deny only after Steps 1–3.**
> `cloudtrail:UpdateTrail` and `PutEventSelectors` are on the list because the attacker used
> them, and they are also exactly what the restore needed; running Step 4 first against a
> role the responder shares is the ordering mistake this technique invites.

---

## 4. Eradication

### Remove Attacker Access

#### Confirm every trail in every Region is back to known-good

Work Query 2's full output, not the one trail that raised the alert. An actor who found one
writable trail usually assessed the others, and a multi-Region trail turned single-Region
leaves silently deleted shadow trails in every other Region — those Regions are now unlogged
and nothing in them will alert. Re-run Query 2 until every trail prints `[OK] selectors match
baseline` or an explained, change-controlled difference, and until no trail lacks a baseline.

#### Remove the persistence the window was bought for

From Query 4's `IN-OR-AFTER-GAP` rows. The logging change is the enabler, not the objective,
and none of this is undone by restoring the trail:

- **Access keys and login profiles** created in the window — disable, delete once documented,
  and re-run Query 4 under each new key until it converges
- **IAM grants** — `Put*Policy` / `Attach*Policy` route to
  `../../iam.privilege-escalation.inline-policy-grant/` and
  `../aws.privilege-escalation.iam-managed-policy-escalation/`
- **Role trust changes** — `UpdateAssumeRolePolicy`, or a role created with an external
  principal, is a re-entry path that survives everything here:
  `../../iam.persistence.role-trust-backdoor/`
- **Other logging surfaces** — the same permission usually reaches `DeleteFlowLogs`, GuardDuty
  detector deletion and S3 server access logging; Query 4 is not filtered to CloudTrail, so
  those calls are already in its output
- **The log bucket** — a lifecycle rule added in the window expires already-delivered objects
  on a timer, destroying evidence *after* the incident looks closed. That variant is T1070;
  `s3api get-bucket-lifecycle-configuration` plus object versioning are the checks

#### Right-size who can degrade logging

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table 2>/dev/null
aws iam list-role-policies          --role-name "$SUSPECT_ROLE" --output table 2>/dev/null
echo "[i] Look for cloudtrail:* or a bare Action:*. Most principals that legitimately READ"
echo "    trail configuration have no reason to hold StopLogging, DeleteTrail, UpdateTrail,"
echo "    PutEventSelectors or the event-data-store writes — splitting read from write costs"
echo "    nothing operationally and removes the technique from most of the account."
```

#### Remove the emergency policies once clean

```bash
ACTING_ROLE="<acting-role-name>"     # leave empty if the acting principal was an IAM user
ACTING_USER="<acting-user-name>"     # leave empty if it was a role
LEFT=0; UNK=0

# Step 4 uses put-user-policy when the acting principal was an IAM USER — that path needs
# the user-side removal, which delete-role-policy does not cover.
[ -n "$ACTING_ROLE" ] && for PN in EmergencyRevokeSessions EmergencyDenyLoggingChange; do
  aws iam delete-role-policy --role-name "$ACTING_ROLE" --policy-name "$PN" 2>/dev/null
done
[ -n "$ACTING_USER" ] && \
  aws iam delete-user-policy --user-name "$ACTING_USER" --policy-name "EmergencyDenyLoggingChange" 2>/dev/null

# delete-*-policy exits 0 whether or not anything was there, so the delete is not evidence —
# the re-list is. A listing that FAILS is inconclusive and must not reach the [OK] branch.
for SPEC in "role:$ACTING_ROLE" "user:$ACTING_USER"; do
  KIND="${SPEC%%:*}"; NAME="${SPEC#*:}"; [ -z "$NAME" ] && continue
  if L=$(aws iam list-${KIND}-policies --${KIND}-name "$NAME" --query 'PolicyNames[]' --output text 2>/dev/null); then
    printf '%s' "$L" | tr '\t' '\n' | grep -qE '^Emergency' && \
      { echo "[FAIL] $KIND $NAME still carries an Emergency* policy"; LEFT=$((LEFT+1)); }
  else
    echo "[!] could not list inline policies on $KIND $NAME — UNASSESSED"; UNK=$((UNK+1))
  fi
done
[ "$UNK" -gt 0 ] && echo "[!] $UNK principal(s) inconclusive — not clean"
{ [ "$LEFT" -eq 0 ] && [ "$UNK" -eq 0 ]; } && echo "[OK] No Emergency* policy remains on the contained principal"
```

---

## 5. Recovery

### Restore Clean State

> Every check below can fail, and "could not check" reaches `[!] INCONCLUSIVE`, never `[OK]`.
> That matters more here than anywhere else in the corpus because **the obvious verification
> is guaranteed to pass**: re-running Query 1 against a trail you have just restarted returns
> a clean result whether or not the account is clean, since the gap contains no events by
> construction. A check whose subject is the telemetry the incident destroyed cannot certify
> anything — writing one produces exactly the false `[OK]` this section exists to prevent.

#### Verify the trail is logging *and* delivering

```bash
TRAIL_ARN="<trail-arn-from-Query-2>"
HOME_REGION="<region-from-Query-1>"

ST=$(aws cloudtrail get-trail-status --name "$TRAIL_ARN" --region "$HOME_REGION" --output json 2>&1)
if ! printf '%s' "$ST" | jq -e '.IsLogging != null' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — get-trail-status returned no status: $(printf '%s' "$ST" | head -c 200)"
else
  LOGGING=$(printf '%s' "$ST" | jq -r '.IsLogging')
  DERR=$(printf   '%s' "$ST" | jq -r '.LatestDeliveryError // ""')
  DTIME=$(printf  '%s' "$ST" | jq -r '.LatestDeliveryTime  // ""')
  # IsLogging alone is not a health check, and an empty LatestDeliveryError is not one
  # either: right after a restart there may have been no delivery ATTEMPT yet, so the error
  # field is empty for the same reason a healthy trail's is. FRESHNESS separates them.
  # AWS: CloudTrail "typically delivers logs within an average of about 5 minutes of an API
  # call. This time is not guaranteed." Because it is not guaranteed, a stale reading is a
  # PROMPT TO LOOK, not a verdict — a hard FAIL on an unguaranteed SLA is a gate people
  # learn to skip. 30 minutes is six typical cycles; tune it to your own observed spread.
  if [ "$LOGGING" != "true" ]; then
    echo "[FAIL] $TRAIL_ARN IsLogging=$LOGGING — still stopped"
  elif [ -n "$DERR" ]; then
    echo "[FAIL] $TRAIL_ARN is logging but NOT delivering: $DERR"
  elif [ -z "$DTIME" ]; then
    echo "[!] INCONCLUSIVE — no LatestDeliveryTime yet. Wait one delivery cycle and re-run;"
    echo "    an empty delivery error on a trail that has never delivered proves nothing."
  else
    AGE=$(( $(date -u +%s) - $(date -u -d "$DTIME" +%s) ))
    [ "$AGE" -lt 1800 ] \
      && echo "[OK] $TRAIL_ARN logging, delivered ${AGE}s ago, no delivery error" \
      || echo "[!] $TRAIL_ARN reports healthy but last delivery was ${AGE}s ago — stale. Not
    proof of a fault (delivery time is not guaranteed), but do not close on it: re-check
    after one more cycle, and treat a second stale reading as a delivery failure."
  fi
fi
```

#### Verify recorded scope is back to the baseline

```bash
TRAIL_ARN="<trail-arn-from-Query-2>"
HOME_REGION="<region-from-Query-1>"

CFG=$(aws cloudtrail describe-trails --trail-name-list "$TRAIL_ARN" --region "$HOME_REGION" \
        --output json 2>/dev/null \
      | jq -r '.trailList[0] | "\(.IsMultiRegionTrail) \(.LogFileValidationEnabled)"' 2>/dev/null)
case "$CFG" in
  "true true")    echo "[OK] multi-Region coverage and log file validation both restored" ;;
  ""|"null null") echo "[!] INCONCLUSIVE — describe-trails returned no record for $TRAIL_ARN" ;;
  *)              echo "[FAIL] multiRegion/validation = $CFG (want: true true)" ;;
esac
echo "[i] Now re-run the Query-2 sweep across every Region. Expect zero [!] lines. Any"
echo "    remaining SELECTOR DRIFT is unremediated; any INCONCLUSIVE is unassessed, and a"
echo "    trail with no stored baseline stays [!] until one is recorded — it has not passed."
```

#### Verify a second recorder exists that this account cannot degrade

The check that decides whether the next occurrence is detectable at all, and the one most
likely to be skipped because it is about architecture rather than this incident.

```bash
ORG_TRAILS=$(for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
    aws cloudtrail describe-trails --include-shadow-trails --region "$R" --output json 2>/dev/null \
      | jq -r '.trailList[]? | select(.IsOrganizationTrail == true) | .TrailARN'
  done | sort -u)

if [ -n "$ORG_TRAILS" ]; then
  echo "[OK] Organization trail(s) in scope — a principal in this account cannot delete one,"
  echo "     turn its logging on or off, or change what it records:"
  printf '     %s\n' $ORG_TRAILS
else
  echo "[FAIL] No organization trail is in scope. Every trail here is modifiable from inside"
  echo "       this account, so the technique you just responded to has no independent"
  echo "       witness and will not be detectable next time. A §6 finding, not a note."
fi
```

#### Verify the gap is documented rather than assumed

```bash
TRAIL_ARN="<trail-arn-from-Query-2>"
HOME_REGION="<region-from-Query-1>"
GAP_START="<time-from-Query-1>"
CASE_NOTE="<path-to-incident-record>"

# The finding is the gap's BOUNDARIES and the evidence for them — never its absence, which
# cannot be established. Assert the record exists and names them; fail if it does not.
if [ -f "$CASE_NOTE" ] && grep -q "$GAP_START" "$CASE_NOTE"; then
  echo "[OK] Incident record names the gap start $GAP_START"
else
  echo "[FAIL] $CASE_NOTE does not record the gap start — the window IS the finding"
fi
aws cloudtrail validate-logs --trail-arn "$TRAIL_ARN" --region "$HOME_REGION" \
  --start-time "$GAP_START" 2>&1 | tail -20
echo "[i] Read validate-logs output as evidence OF the gap, not a failure to fix it: a broken"
echo "    or absent digest chain across the window proves files are missing, a clean chain"
echo "    either side bounds it. Neither outcome recovers anything."
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rules MUST fire on these, all eventSource cloudtrail.amazonaws.com,"
echo "errorCode ABSENT:"
echo '  StopLogging          {"name":"prod-trail"}                                -> cloudtrail_scope_reduced, high'
echo '  DeleteTrail          {"name":"prod-trail"}                                -> cloudtrail_scope_reduced, high'
echo '  UpdateTrail          {"name":"prod-trail","isMultiRegionTrail":false}     -> high'
echo '  UpdateTrail          {"name":"prod-trail","enableLogFileValidation":false}-> high'
echo '  UpdateTrail          {"name":"prod-trail","s3BucketName":"attacker-logs"} -> cloudtrail_destination_repointed, high'
echo '  PutEventSelectors    {"trailName":"prod-trail","eventSelectors":[{"readWriteType":"ReadOnly","includeManagementEvents":true}]} -> cloudtrail_selectors_narrowed, high'
echo '  PutInsightSelectors  {"trailName":"prod-trail","insightSelectors":[]}     -> cloudtrail_selectors_narrowed, high'
echo '  UpdateEventDataStore {"eventDataStore":"arn:...","advancedEventSelectors":[{"fieldSelectors":[{"field":"userIdentity.arn","notEquals":["arn:aws:sts::111122223333:assumed-role/x/y"]}]}]} -> high'
echo
echo "MUST NOT fire on the near-misses — this is the whole point of the rewrite:"
echo '  1. UpdateTrail {"name":"prod-trail","isMultiRegionTrail":true} — an operator WIDENING'
echo "     coverage. An event-name match cannot tell this from the narrowing above; that is"
echo "     defect one in the source set, and this is the test for it."
echo '  2. UpdateTrail {"name":"prod-trail","cloudWatchLogsLogGroupArn":"arn:aws:logs:..."} —'
echo "     attaching a log group. No narrowing flag present, so no match."
echo "  3. Any fire case with errorCode=AccessDenied — the denied-write correlation at medium,"
echo "     never the high rule. A failed StopLogging read as a stop sends a responder to"
echo "     restore a trail that never went down."
echo "  4. DescribeTrails or GetTrailStatus alone — informational base rule; it reaches high"
echo "     only as the ordered read-then-degrade correlation."
echo
echo "Test the absence detector SEPARATELY — no synthetic EVENT can exercise it. Stop ingest"
echo "from one active Region for longer than the configured bin and confirm Companion 1 fires;"
echo "a rule set that only fires on events cannot detect an outcome that IS the absence of them."
```

---
## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal in the account could stop, delete or narrow the trail that records it | CloudTrail write permissions held outside a break-glass path, and no organization or cross-account trail placing the authoritative recorder beyond the reach of the account being recorded |
| The change was not caught while it was happening | The deployed alert matched `UpdateTrail` by event name with no parameter check, so it could not separate a narrowing from a widening; `PutEventSelectors`, `PutInsightSelectors` and the event-data-store calls were not matched at all |
| It would not have been paged even if it had been caught | `StopLogging` and `DeleteTrail` rated P2, `UpdateTrail` P3 — a disposition that grants the unobserved window the technique exists to buy |
| The absence went unnoticed for the length of the gap | The one absence alert grouped by the ingest pipeline's log-stream identifier over a 2-hour window, so it fired for the account rather than a Region, named none of the four possible causes, and was indistinguishable from the shipper being down |
| The narrowing could not be assessed against anything | No stored `get-event-selectors` baseline existed, and the event carries the resulting configuration rather than the delta, so "what did this replace" had no answer after the fact |
| Delivery health was never monitored | `IsLogging` was treated as the health signal. It stays `true` through a broken bucket policy, a deleted bucket and an unusable KMS key — `LatestDeliveryError` was the field that would have shown it |

### Recommended Guardrails

**Restrict CloudTrail configuration writes to a break-glass path**

An SCP is the right instrument: the principal degrading the trail is inside your
organisation, which is precisely the population SCPs govern. Two limits to write down rather
than discover mid-incident. SCPs *"have no effect on users or roles in the management
account"*, so this protects member-account trails and **not** the organization trail, which
lives in the management account and is protected instead by controlling who can assume roles
there. And SCPs *"do not affect any service-linked role"*, so `AWSServiceRoleForCloudTrail`
is out of scope by construction and needs no exemption.

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": [
    "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
    "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors",
    "cloudtrail:DeleteEventDataStore", "cloudtrail:UpdateEventDataStore",
    "cloudtrail:StopEventDataStoreIngestion"
  ],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {
      "aws:PrincipalArn": ["arn:aws:iam::*:role/BreakGlassAdmin", "arn:aws:iam::*:role/iac-deploy"]
    }
  }
}
```

> **The operator choice is load-bearing and fails silently in one of two directions.** `*` is
> expanded only in the `Resource` element and in the `*Like` operators, so a wildcarded
> `aws:PrincipalArn` needs `ArnNotLike` (or `StringNotLike`). `ArnNotEquals` against
> `arn:aws:iam::*:role/BreakGlassAdmin` matches **every** principal including the break-glass
> role, and a `Deny` matching everything **fails closed** — nobody can administer CloudTrail,
> including the responder in §3 Step 1. The mirror error is worse because it is quiet: `Deny`
> with `ArnEquals` against the same wildcard matches **nothing**, so the guardrail permits
> everything it was written to deny and reads as protection in every review after. Test it
> with a non-exempt principal before relying on it.

**Structural controls**
- **An organization trail, or a trail in a separate logging account, is the only control that
  survives a legitimate administrator.** Every allowlist above necessarily exempts the
  principal permitted to administer CloudTrail; a recorder in an account the compromised
  principal cannot reach does not have that hole. AWS is explicit that member accounts cannot
  delete an organization trail, turn its logging on or off, or change what it records — and
  can still read its status, which is what makes it usable during response
- **Deny log-object and log-bucket-policy changes on the destination bucket**, with the same
  `ArnNotLike` break-glass exemption, in a bucket policy rather than an SCP:
  `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:PutLifecycleConfiguration`,
  `s3:PutBucketPolicy`, `s3:DeleteBucketPolicy`, `s3:DeleteBucket`. None of these is a
  `cloudtrail:` action, so none is reachable by the SCP above, and all of them break delivery
  or destroy the archive without touching the trail. **Do not extend that list to
  `s3:PutObject` or `s3:GetBucketAcl` without adding
  `"BoolIfExists": {"aws:PrincipalIsAWSService": "false"}` to the same condition block** —
  those two are the actions `cloudtrail.amazonaws.com` itself performs, and AWS documents
  that condition as the way to exempt a service principal from a `Deny` (you cannot use
  `NotPrincipal` with one). Do not instead reason about whether `aws:PrincipalArn` is
  populated for a service caller: AWS documents that key as present "in the request context
  for all signed requests" and says nothing about service principals either way, so the
  behaviour is unsourced. Use the documented guard
- **S3 Object Lock in compliance mode** on that bucket, in a third account, so the archive
  survives both the trail and the bucket policy
- **Log file integrity validation on everywhere, and left on.** It is the only mechanism that
  lets you prove after the fact that files are missing rather than assert it
- **Store the selector baseline in version control** and diff it on a schedule — the same
  shape as the code-hash drift detector in the Lambda playbook and for the same reason: it is
  the only check that still works when the acting principal is on every allowlist
- **Split read from write on CloudTrail permissions.** Most principals needing
  `DescribeTrails` and `GetTrailStatus` have no reason to hold `StopLogging` or
  `PutEventSelectors`

**Detection improvements**
- Deploy the parameter-aware rules; never an event-name match on `UpdateTrail`
- Deploy the **absence detector** per Region, with a floor measured from your own quietest
  hour over at least four weeks including a weekend, and idle Regions excluded by name. It is
  the only rule that fires after the technique has already worked
- Poll `GetTrailStatus` per trail per Region and alert on the three delivery-error fields;
  `IsLogging` is not a health check
- Raise `Stealth:IAMUser/CloudTrailLoggingDisabled` above its **Low** default without treating
  it as coverage — its documented triggers are trail deletion or update and log-bucket
  deletion, leaving `StopLogging` and `PutEventSelectors` to the rules above
- Run the selector-baseline diff continuously rather than as an incident-time query

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log |
| MITRE tactic | Defense Impairment (TA0112) |
| Primary API | `cloudtrail:StopLogging` / `DeleteTrail` / `UpdateTrail` / `PutEventSelectors` / `PutInsightSelectors`, plus `Create`/`Update`/`DeleteEventDataStore` and `StopEventDataStoreIngestion` |
| Event source | `cloudtrail.amazonaws.com` — **regional; every write must be issued from the trail's home Region**, so a query in the wrong Region returns zero and reads as clean |
| Key discriminator | Whether the resulting configuration records **less**. `UpdateTrail` behaves as a partial update and `requestParameters` carries only what was sent, so `isMultiRegionTrail: false` is a narrowing and `true` a widening — separable on the event. Not the event name |
| Field shape | `requestParameters` keys are **initial-lowercase** (`name`, `isMultiRegionTrail`, `s3BucketName`), shown in AWS's own published records. `StopLogging` and `DeleteTrail` return an **empty body** — no `responseElements` to pivot from. `UpdateTrail`'s response renames the flag to `LogFileValidationEnabled` |
| Ground-truth signal | `GetTrailStatus`: `IsLogging`, `LatestDeliveryError`, `LatestDigestDeliveryError`, `LatestCloudWatchLogsDeliveryError`, `LatestDeliveryTime`, `StartLoggingTime`, `StopLoggingTime`. Six further fields are documented "no longer in use", are permanently empty, and two are word-order homonyms of the live pair — a check built on one is a permanent `[OK]` |
| Survives the tampering | **Event history** (90 days, management events, per Region, explicitly unaffected by trail and selector changes); **GuardDuty** (independent duplicated CloudTrail stream); a **second or organization trail**; **CloudTrail Lake** event data stores where they already exist — Lake closed to new customers on 31 May 2026 |
| Does NOT survive | **EventBridge** on `AWS API Call via CloudTrail` — documented as requiring a trail with logging, so it is downstream of the thing being disabled. **AWS Config** records the trail resource, but `CLOUD_TRAIL_ENABLED`, `MULTI_REGION_CLOUD_TRAIL_ENABLED` and `CLOUDTRAIL_S3_DATAEVENTS_ENABLED` are all **Periodic**, so they lag |
| "Was it used" pivot | Session reconstruction by `accessKeyId` against Event history (Query 4) — it works with the trail down. Management events only: data, Insights and network activity events in the gap are unrecoverable |
| Selector scope trap | On a **trail**, `userIdentity.arn` filters **data** and network activity events only; the management-event field set is `eventCategory`, `eventSource`, `readOnly`. Excluding one identity from **management** logging requires an **event data store**. `ExcludeManagementEventSources` accepts only `kms.amazonaws.com` and `rdsdata.amazonaws.com`, so there is no "excludes some other service" case to detect |
| Blast radius | Everything that happens in the account while the change stands, in whatever scope was removed — up to every management event in every Region. Proportional to elapsed time, not to the call |
| Reversibility | `StartLogging` restores recording but recovers nothing from the gap. `DeleteTrail` is irreversible (recreate) but leaves log files, bucket and log group intact. The digest chain does not heal. **The one genuinely reversible variant** is a delivery break: CloudTrail retries for **30 days**, so fixing the bucket policy inside that window recovers the missed files |
| Error strings | `AccessDenied` / `AccessDeniedException` on denial — no EC2-style `Client.` prefix. Eleven non-denial exceptions are common to `StopLogging`, `DeleteTrail`, `UpdateTrail` and `PutEventSelectors` (`TrailNotFoundException`, `InvalidTrailNameException`, `CloudTrailARNInvalidException`, `InvalidHomeRegionException`, `OperationNotPermittedException`, `UnsupportedOperationException`, `ConflictException`, `ThrottlingException`, `NotOrganizationMasterAccountException`, `NoManagementAccountSLRExistsException`, `InsufficientDependencyServiceAccessPermissionException`). The set is **not** uniform: `PutInsightSelectors` carries nine of the eleven, omitting `ConflictException` and `InsufficientDependencyServiceAccessPermissionException`. Per-call additions (`InvalidEventSelectorsException`, `InvalidInsightSelectorsException`, and `UpdateTrail`'s S3/SNS/KMS/CloudWatch-Logs set) are enumerated in `detections/kql_t1685_002.kql` |
| Sibling technique | `../aws.initial-access.sg-remote-management-open/` — T1686.001, the other Defense Impairment technique in this set |

**MITRE mapping note:** Both halves are stale in a way that
survives a casual check. The same restructure renamed `TA0005`
from "Defense Evasion" to **Stealth** and moved this behaviour to **Defense Impairment
(TA0112)**, so an alert carrying `TA0005` now names a tactic that still exists but is no
longer this one. **T1685.002 under TA0112** is the precise mapping and is what this directory
carries. The lifecycle-rule and object-deletion variants — expiring already-delivered log
objects rather than stopping their creation — are better described by **T1070** (*Indicator
Removal*, tactic Stealth TA0005), because those logs were recorded and then destroyed. A
mapping-precision note, not an operational defect: the source alerts do fire on the right
event names.

### Residual Risk

**The gap is permanent, and its size is the incident.** Everything done between
`StopLoggingTime` and `StartLoggingTime` — or between the selector narrowing and its
restoration — was never written to that trail and never will be. `start-logging` resumes
recording from now; it does not backfill. Report the window as a duration with both
boundaries and the evidence for them, not as "logging was restored". If nobody can say when
the change happened, the gap extends back to the limit of your other telemetry, usually far
further than the actual compromise — which is why the timestamp of the first successful
narrowing is the single most valuable field in Query 1.

**How much is genuinely unknowable is narrower and sharper than "the account went dark", and
getting it right changes what you do next.** Management events in the gap are **still
reconstructable** from Event history for 90 days, in the Region where each call landed —
Query 4 does it, and a responder who assumes otherwise will skip the one query that still
works and blanket-rotate instead of enumerating. What is genuinely gone is everything Event
history never held: **data events** (S3 object reads and writes, Lambda invocations, DynamoDB
item operations), **Insights events**, and **network activity events**. If the actor's
objective was data and you had no second trail carrying data events, what they read in the
window is unknowable and those objects must be treated as disclosed. Also gone:
organization-level aggregation, anything older than 90 days once retention passes, and the
durable S3 archive for the window.

**The integrity guarantee does not come back.** CloudTrail creates no digest files for any
period in which validation was off or logging was stopped, so that span can never be proven
complete — not for this incident, and not for any audit or legal process that later asks.
Re-enabling validation starts a new chain from the moment it is turned on. A trail stopped
for twenty minutes carries a permanent, documented hole in its evidentiary chain, and that
stays true even if the actor turns out to have done nothing in the window.

**The archive may still be being destroyed on a timer.** A lifecycle rule added during the
window expires already-delivered objects days or weeks later, long after the incident looks
closed; so does an unnoticed `DeleteObject` sweep on an unversioned bucket. Neither is a
CloudTrail call, neither fires any rule in this directory, and both are T1070 rather than
T1685.002. Check `get-bucket-lifecycle-configuration` and object versioning on the log bucket
before closing, and again a week later.

**And the enabling permission usually survives the response.** The principal was contained,
but the technique needed only `cloudtrail:StopLogging` or `UpdateTrail`, and unless §4's
right-sizing was actually applied, every other principal holding the same permission can
repeat this tomorrow. Until an organization trail or a cross-account logging trail exists,
there is no recorder in this account that a principal in this account cannot reach — which
means the control you are relying on to detect the next occurrence is the same one that just
failed.
