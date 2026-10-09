# Detection Note: T1685.002 (Disable CloudTrail Logging Through Event Selectors)

**Signal:** `cloudtrail:PutEventSelectors` (`eventSource: cloudtrail.amazonaws.com`, management event, trail home Region) whose new selectors record no management events, or only read events. The call **replaces** every selector on the trail, so the request alone describes the trail's new coverage. `GetTrailStatus` keeps reporting `IsLogging: true` throughout.

The emulation sets one basic selector `ReadWriteType=ReadOnly, IncludeManagementEvents=false, DataResources=[]` — a trail that delivers nothing — waits 30 seconds, and restores the original selectors.

## What ships

| Rule | Level | Fires on the emulation |
|------|-------|------------------------|
| Basic selectors: no selector keeps management events, or only read-only selectors | high | yes (not on the restore) |
| Advanced selectors with no `Management` event category | high | no (variant) |
| `excludeManagementEventSources` non-empty (KMS / RDS Data API excluded) | medium | no (variant) |

The generated rule matched literal JSON substrings (`"includeManagementEvents":false`), which depends on how a backend serialises nested objects and never matched in the in-process evaluator; the rules now use regular expressions with optional whitespace. It also fired on the common two-selector layout (management + data-only); the basic rule now requires that **no** selector keeps management events. The KQL classifies each change and measures the blind window until coverage is restored.

## Coverage beyond the rule

- A trail health check on `IsLogging` alone **misses this**. Compare `GetEventSelectors` against a baseline.
- Security Hub **CloudTrail.1** requires a multi-Region trail recording read and write management events, and fails when the only such trail is impaired — at its next periodic evaluation.
- **CloudTrail Event history** is independent of trail selectors: management events of the blind window remain queryable for 90 days.
- The `Protect-security-services-from-tampering` SCP in the guardrail catalogue denies `cloudtrail:PutEventSelectors` outside named admin roles.

## Response

1. Restore the selectors from IaC; confirm with `get-event-selectors`.
2. Export Event history for the blind window; data events in it are not recoverable.
3. Revoke the acting principal's sessions.

**MITRE:** T1685.002 (*Disable or Modify Tools: Disable or Modify Cloud Log*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** session `atomic-t1685002-ct-selectors` on the lab role `stratus-red-team-ct-selectors-attacker-role`; `GetEventSelectors`, then two `PutEventSelectors` 30 s apart on `stratus-red-team-ct-selectors-trail`. A real attacker leaves the selectors in place; the restore is not a reason to downgrade the alert.
