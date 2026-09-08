# Detection Note — T1685.002 (Disable or Modify Tools: Disable or Modify Cloud Log)

**Signal:** a trail reconfigured so that it keeps logging and captures less.

## The stealthiest of the three, rated lowest

Stopping a trail sets `IsLogging` false. Deleting one removes it from `describe-trails`. Modifying
one leaves it **present, logging, and healthy in every summary view** — `IsLogging` true,
`LatestDeliveryTime` still moving, the trail still listed. Any dashboard built on those fields shows
green throughout.

The source pack rates stopping and deleting at P2 and this at P3. That is backwards: the one no
health check can corroborate is the one that most needs an alert.

## `UpdateTrail` is not how coverage is narrowed

Event selectors are set by a **separate call** — `PutEventSelectors`, or `PutInsightSelectors` for
Insights. A rule scoped to `UpdateTrail` never sees them. And selectors are **replaced wholesale
rather than merged**, so a single call can remove every data-event and network-activity selector.

That matters more than it used to: CloudTrail now logs four event types — management, data, network
activity and Insights — and only management events are on by default. Everything above the default
is selector-configured and therefore removable by one call this rule does not match.

## Four distinct abuses, reported identically

| Change | Effect |
|---|---|
| `isMultiRegionTrail` → false | Every Region but the home Region stops being covered |
| `includeGlobalServiceEvents` → false | IAM, STS and CloudFront become invisible |
| `s3BucketName` changed | Still logging, to a bucket nobody queries |
| `kmsKeyId` changed | Logs delivered intact and undecryptable |

The KMS variant is the worst of the four and the least likely to be noticed: objects keep arriving,
correctly sized and on schedule, so a volume-based or freshness-based health check sees nothing at
all. Only an attempt to read them fails, and that usually happens during the next incident.

Turning off global service events is the sharpest. IAM and STS events are recorded in `us-east-1`
and delivered only to trails that include them, so one flag makes all identity activity invisible
while every identity-focused detection in the estate keeps reporting clean.

## Response levers

**Compare, do not check.** There is no status field that shows this. The only method is to compare
the current configuration and selectors against the last `UpdateTrail` / `PutEventSelectors` event
in the history, field by field. Anything that asks "is the trail logging" answers yes.

**Read the selector history before restoring.** Because selectors are replaced rather than merged,
the previous set exists only in the previous `PutEventSelectors` event. Restoring from memory
reproduces management-events-only coverage and looks correct.

**Absence in an `UpdateTrail` request is not a change.** The API accepts a partial document, so a
flag that is not present was not modified. Reading absence as "turned off" invents findings, and the
rules and query here read only what is present.

**Check whether the destination is still readable.** A redirected bucket and a changed KMS key both
leave the trail logging. `get-trail-status` will not tell you; attempting to read a recent object
will.

**MITRE:** `T1685.002` is the live
mapping, verified live 2026-08-30.

**GuardDuty:** no finding type covers trail reconfiguration.
`Stealth:IAMUser/CloudTrailLoggingDisabled` covers a stop only, so a narrowed or redirected trail
produces no GuardDuty signal at all — this directory is the only coverage.

**Files here:**
- `sigma_t1685_002.yml` — five documents: `cloudtrail_trail_coverage_reduced` (critical),
  `cloudtrail_trail_destination_changed` (high), `cloudtrail_event_selectors_changed` (high, the
  call the source rule could not see), `cloudtrail_config_changed` (informational base rule), and an
  `event_count` correlation for three or more configuration changes by one principal in an hour
  (critical).
- `kql_t1685_002.kql` — separates the four abuses of `UpdateTrail`, surfaces selector edits
  alongside them, and states inline why every health check still passes.

Full response procedure is in `../PLAYBOOK.md`.
