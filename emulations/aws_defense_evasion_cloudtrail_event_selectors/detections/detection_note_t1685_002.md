# Detection Note: T1685.002 (Disable CloudTrail Logging Through Event Selectors)

**Signal:** `cloudtrail:PutEventSelectors` where `requestParameters.eventSelectors[].includeManagementEvents` is `false` or `readWriteType` is `ReadOnly`. Advanced selectors (`advancedEventSelectors`) can achieve the same; extend the rule if you use them.

## Coverage beyond the rule

- A trail health check on `IsLogging` alone **misses this**. Also compare `GetEventSelectors` against your baseline.
- AWS Config rule `cloudtrail-enabled` does not inspect selectors; use a custom rule or Security Hub **CloudTrail.1** (requires management read+write events).

## Response

1. Restore the selectors from IaC.
2. Treat the window as unlogged for write events on that trail.
3. Revoke the acting principal's sessions.

**MITRE:** T1685.002 (*Disable or Modify Tools: Disable or Modify Cloud Log*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** the run assumes the lab role `stratus-red-team-ct-selectors-attacker-role` (session name `atomic-*`) and, where the technique is reversible, reverts it seconds later. A real attacker leaves the change in place; the pairing is not a reason to downgrade the alert.
