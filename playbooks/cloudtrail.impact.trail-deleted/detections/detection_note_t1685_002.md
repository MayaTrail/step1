# Detection Note — T1685.002 (Disable or Modify Tools: Disable or Modify Cloud Log)

**Signal:** `DeleteTrail` — and the two facts about it that a responder will otherwise get backwards.

## The log files are not gone

> *"While deleting a CloudTrail trail is an irreversible action, CloudTrail does not delete log
> files in the Amazon S3 bucket for that trail, the Amazon S3 bucket itself, or the CloudWatch log
> group to which the trail delivers events."*

Everything delivered before the deletion is still there and still searchable. What was destroyed is
**future coverage**, not the historical record.

This is worth leading with because the natural assumption is the opposite, and acting on it is
expensive: a response that opens with "our logs are gone" skips the reconstruction that is entirely
possible during the hour when it is most useful. The source rule reports "Trail Deleted" at P2 and
offers nothing that would correct the assumption.

## What is irreversible is the configuration, and it expires in 90 days

The `DeleteTrail` request carries only the trail name. The selectors, destination bucket, KMS key,
`isMultiRegionTrail`, `includeGlobalServiceEvents` and `enableLogFileValidation` settings exist only
in the last `CreateTrail` or `UpdateTrail` event for that trail, and `lookup-events` serves 90 days.

That is the actual deadline in this incident. Recovering the configuration is the first action, not
a later one, and the KQL surfaces `Recoverable` precisely so a responder knows whether the clock has
already run out.

## Blast radius is not in the event either

> *"Deleting a multi-Region trail will stop logging of events in all AWS Regions enabled in your AWS
> account. Deleting a single-Region trail will stop logging of events in that Region only. It will
> not stop logging of events in other Regions even if the trails in those other Regions have
> identical names to the deleted trail."*

One event name, two very different incidents, and the distinguishing field lives in the trail's
history rather than in the deletion. The KQL joins them for that reason.

## Response levers

**Recover the configuration before containing anything.** `lookup-events` on `CreateTrail` and
`UpdateTrail` for that trail name is the only source. Everything else in the response can wait an
hour; this cannot wait ninety days.

**Read the refused attempts.** AWS accepts `DeleteTrail` only in the trail's home Region and never
on a shadow trail, so an actor guessing produces `InvalidHomeRegionException` first — before
coverage is lost, and invisible to any rule filtering on success.

**Check whether a replacement was created.** Delete-and-replace leaves `describe-trails` returning a
trail with the same name, so every check that asks "is there a trail" passes. Comparing the new
trail's selectors against the recovered configuration is the only thing that shows what changed.

**An organization trail makes this fail.** Member accounts cannot delete one regardless of their IAM
permissions, so the same technique produces `NotOrganizationMasterAccountException` instead of a
gap.

**MITRE:** `T1685.002` is the live
mapping; `T1070 — Indicator Removal` is tagged on the delete-and-replace correlation. Both verified
live 2026-08-30.

**GuardDuty:** no finding type covers trail deletion specifically.
`Stealth:IAMUser/CloudTrailLoggingDisabled` covers a stop, not a delete, so this is additional
coverage rather than duplicated.

**Files here:**
- `sigma_t1685_002.yml` — four documents: `cloudtrail_trail_deleted` (critical),
  `cloudtrail_trail_delete_refused` (high, on the diagnostic error codes),
  `cloudtrail_trail_created` (informational base rule), and a `temporal_ordered` correlation for
  deleted-then-replaced by one principal (critical).
- `kql_t1685_002.kql` — joins each deletion to the trail's last create or update event to recover
  the configuration and establish the blast radius, and reports whether the 90-day recovery window
  has already passed.

Full response procedure is in `../PLAYBOOK.md`.
