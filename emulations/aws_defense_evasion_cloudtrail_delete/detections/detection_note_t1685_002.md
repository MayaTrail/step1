# Detection Note: T1685.002 (Delete CloudTrail Trail)

**Signal:** `cloudtrail:DeleteTrail` on any trail. `requestParameters.name` carries the trail name or ARN.

## Coverage beyond the rule

- **AWS Config** `cloudtrail-enabled` / Security Hub **CloudTrail.1** flag the missing trail on their next evaluation.
- An SCP denying `cloudtrail:DeleteTrail` and `cloudtrail:StopLogging` outside a break-glass role prevents this outright.

## Response

1. Recreate the trail (from IaC) and confirm delivery resumes.
2. Treat everything after the delete as unlogged by that trail; use other trails, Config and service logs.
3. Revoke the acting principal's sessions.

**MITRE:** T1685.002 (*Disable or Modify Tools: Disable or Modify Cloud Log*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** the run assumes the lab role `stratus-red-team-ct-delete-attacker-role` (session name `atomic-*`) and, where the technique is reversible, reverts it seconds later. A real attacker leaves the change in place; the pairing is not a reason to downgrade the alert.
