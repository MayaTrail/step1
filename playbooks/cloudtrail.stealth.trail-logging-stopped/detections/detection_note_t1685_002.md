# Detection Note — T1685.002 (Disable or Modify Tools: Disable or Modify Cloud Log)

**Signal:** `StopLogging` — and, more usefully, `StopLogging` that was refused.

## The failure is the better signal, and the source rule drops it

AWS refuses this call outside the trail's home Region:

> *"For a trail enabled in all Regions, this operation must be called from the Region in which the
> trail was created, or an `InvalidHomeRegionException` will occur. This operation cannot be called
> on the shadow trails (replicated trails in other Regions) of a trail enabled in all Regions."*

So an actor who does not already know which Region owns the trail fails on the first attempt. That
failure is higher fidelity than the success — no automation calls `StopLogging` in the wrong Region
— and it arrives *before* logging stops, which is the only point at which the response still has
full visibility. `NOT _exists_:errorCode` throws all of it away.

The error codes worth reading rather than filtering:

| Error | What it says about the caller |
|---|---|
| `InvalidHomeRegionException` | They were guessing the home Region |
| `NotOrganizationMasterAccountException` | A member account tried to silence an organization trail |
| `TrailNotFoundException` | They were enumerating trail names |
| `AccessDenied` | They lacked the permission and now know it |

## There is no benign reconfiguration story

> *"Under most circumstances, there is no need to use this action. You can update a trail without
> stopping it first. This action is the only way to stop recording."*

AWS's own position is that a running trail can be updated. So the usual triage question — "was
someone reconfiguring it?" — has an answer already, and it is no. This ships at critical, where the
source rated it P2, one level *below* the "No Logs From CloudTrail" rule in the same pack. That
inverts cause and symptom: the stop arrives first and is actionable; the absence of logs arrives
later and is not.

## Response levers

**Establish what coverage remained before anything else.** Where a management-account organization
trail covers this account, a member-account `StopLogging` cannot alter it and the account is still
being logged. Where one does not, the account went silent at that timestamp. The event is identical
in both cases. `describe-trails --include-shadow-trails` with `IsOrganizationTrail`,
`IsMultiRegionTrail` and `HomeRegion` is the resolution, and "a trail exists" is not.

**Check whether the trail was ever seeing IAM.** Global service events for IAM, STS and CloudFront
are recorded in `us-east-1`, and CloudTrail delivers them *only* to single-Region trails in
`us-east-1`. A single-Region trail elsewhere was blind to every IAM and STS call before anyone
touched it, so the gap this incident opened may be smaller than the gap that already existed.

**Restarting logging does not recover the window.** Nothing recorded during the gap is retrievable
— that is what the technique achieves. Reconstruct from services that log independently: VPC flow
logs, S3 server access logs, ALB access logs, GuardDuty findings, and the resource state itself.

**A stop followed by a start leaves a clean end state.** Every configuration check passes afterwards,
which is why the correlation exists and why the event history is the only evidence. Keep it longer
than the longest window you would want to be able to reconstruct.

**MITRE:** `T1685.002` is the live
mapping; `T1070 — Indicator Removal` is tagged on the stop-then-start correlation. Both verified
live 2026-08-30.

**GuardDuty:** `Stealth:IAMUser/CloudTrailLoggingDisabled` covers the successful stop. It does not
cover the refused attempt, which is the earlier and more useful half.

**Files here:**
- `sigma_t1685_002.yml` — four documents: `cloudtrail_stop_logging` (critical),
  `cloudtrail_stop_logging_refused` (high, on the diagnostic error codes),
  `cloudtrail_start_logging` (informational base rule), and a `temporal_ordered` correlation for
  stopped-then-restarted by one principal (critical).
- `kql_t1685_002.kql` — computes the dark window between stop and start, separates a wrong-Region
  refusal from an organization-trail refusal, and states inline why the event does not establish
  whether the account actually went dark.

Full response procedure is in `../PLAYBOOK.md`.
