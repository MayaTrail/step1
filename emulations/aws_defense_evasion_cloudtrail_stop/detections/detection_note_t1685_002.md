# Detection Note: T1685.002 (Stop CloudTrail Trail)

**Signal:** `cloudtrail:StopLogging` on any trail. The emulation also calls `StartLogging` about 30 seconds later; a real attacker may or may not restart it.

## Coverage beyond the rule

- **GuardDuty:** `Stealth:IAMUser/CloudTrailLoggingDisabled`.
- **AWS Config** rule `cloudtrail-enabled` and Security Hub control **CloudTrail.1** flag a stopped trail on their next evaluation.
- Organization trails can only be stopped from the management account. Prefer them for tamper resistance.

## Response

1. `StartLogging` on the trail immediately.
2. Treat the stop-to-start window as a blind spot: reconstruct it from other trails, Config and service logs.
3. Revoke the acting principal's sessions and review its other recent activity.

**MITRE:** T1685.002 (*Disable or Modify Tools: Disable or Modify Cloud Log*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** the run assumes the lab role `stratus-red-team-ct-stop-attacker-role` (session name `atomic-*`) and, where the technique is reversible, reverts it seconds later. A real attacker leaves the change in place; the pairing is not a reason to downgrade the alert.
