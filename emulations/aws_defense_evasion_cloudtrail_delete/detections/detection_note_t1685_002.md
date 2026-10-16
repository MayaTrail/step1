# Detection Note: T1685.002 (Delete CloudTrail Trail)

**Signal:** `cloudtrail:DeleteTrail` (`eventSource: cloudtrail.amazonaws.com`, management event, trail home Region) on any trail, **with or without** an `errorCode`. `requestParameters.name` carries the trail name or ARN. Unlike `StopLogging` there is no revert: the trail configuration is gone and has to be recreated.

## What ships

| Rule | Level | Fires on the emulation |
|------|-------|------------------------|
| `cloudtrail_delete_trail` - any DeleteTrail | high | yes |
| UpdateTrail making a trail single-Region, dropping global service events or disabling log file validation | medium | no (variant, not exercised) |

The KQL recovers the deleted trail's last known bucket, Region scope and KMS key from the most recent `CreateTrail`/`UpdateTrail`, and reports whether a trail of the same name was created again.

## Coverage beyond the rule

- **GuardDuty** `Stealth:IAMUser/CloudTrailLoggingDisabled` is documented for a successful deletion of a trail, at default severity **Low**. Corroboration, not the alert.
- **CloudTrail Event history** is separate from trails: management events after the delete remain queryable for 90 days. Data events have no such fallback.
- **AWS Config / Security Hub CloudTrail.1 and CloudTrail.3** flag a missing trail at their next evaluation.
- **Organization trails** cannot be deleted from member accounts. The `Protect-security-services-from-tampering` SCP in the guardrail catalogue denies `cloudtrail:DeleteTrail` outside named admin roles.

## Response

1. Recreate the trail from IaC (or from the configuration recovered by the KQL) and confirm `GetTrailStatus` shows `IsLogging: true` and an advancing `LatestDeliveryTime`.
2. Export Event history from the delete time to the recreate time; that window is unlogged by the trail.
3. Revoke the acting principal's sessions; check for `StopLogging`, `PutEventSelectors` or lifecycle changes on the log bucket by the same principal.

**MITRE:** T1685.002 (*Disable or Modify Tools: Disable or Modify Cloud Log*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** session `atomic-t1685002-ct-delete` on the lab role `stratus-red-team-ct-delete-attacker-role`, a `GetTrail` immediately before the `DeleteTrail` of `stratus-red-team-ct-delete-trail`. The emulation does not recreate the trail; the stack's destroy removes the leftover bucket.
