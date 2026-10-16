# Detection Note: T1685.002 (Stop CloudTrail Trail)

**Signal:** `cloudtrail:StopLogging` (`eventSource: cloudtrail.amazonaws.com`, management event, trail home region) on any trail, **with or without** an `errorCode`. `requestParameters.name` carries the trail name or ARN. The emulation calls `StartLogging` about 30 seconds later from the same session, which is the evasive stop-dwell-restart shape the correlation rule targets.

## What ships

| Rule | Level | Fires on the emulation |
|------|-------|------------------------|
| `cloudtrail_stop_logging` - any StopLogging | high | yes |
| `cloudtrail_start_logging_bb` - successful StartLogging (base rule) | informational | yes (sequence component only) |
| Stop then restart by one principal on one trail within 1h (`temporal_ordered`) | high | yes |

The KQL pairs every stop with the next successful start on the same trail and reports the gap in minutes; an empty restart time means the trail may still be stopped.

## Coverage beyond the rule

- **CloudTrail Event history is separate from trails.** Stopping a trail does not stop Event history, so the management events of the gap can be recovered with `lookup-events` for 90 days. Data events and Insights events in the gap are not recoverable.
- **`GetTrailStatus` keeps `StopLoggingTime`** after a restart. A trail that reads `IsLogging=true` with a recent `StopLoggingTime` was stopped and restarted.
- **GuardDuty** `Stealth:IAMUser/CloudTrailLoggingDisabled` is default severity **Low** and is documented for deletion or update of a trail; do not rely on it for StopLogging.
- **AWS Config / Security Hub CloudTrail.1** evaluate periodically and see a healthy trail once it has been restarted.
- **Organization trails** cannot be stopped from member accounts (`NotOrganizationMasterAccountException`). The `Protect-security-services-from-tampering` SCP in the guardrail catalogue denies `cloudtrail:StopLogging` outside named admin roles.

## Response

1. `StartLogging` on the trail if it is still stopped; confirm with `GetTrailStatus` (`IsLogging`, `LatestDeliveryTime`).
2. Reconstruct the gap from Event history (`lookup-events` between `StopLoggingTime` and `StartLoggingTime`).
3. Revoke the acting principal's sessions and review everything it did in the gap.

**MITRE:** T1685.002 (*Disable or Modify Tools: Disable or Modify Cloud Log*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** session name `atomic-t1685002-ct-stop` on the lab role `stratus-red-team-ct-stop-attacker-role`, trail `stratus-red-team-ct-stop-trail`, restart about 30 s after the stop. A real attacker may never restart; the pairing is not a reason to downgrade the alert.
