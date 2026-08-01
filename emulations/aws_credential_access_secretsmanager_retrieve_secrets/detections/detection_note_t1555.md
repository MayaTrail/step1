# Detection Note — T1555 (Retrieve a High Number of Secrets Manager Secrets)

**Signal:** a high volume of **distinct secrets** read by one principal in a
short window.

**Why the event alone is not the signal:** `GetSecretValue` is among the most
frequent calls in any account that uses Secrets Manager — every application
fetches its config secret on startup and on cache expiry. A rule that alerts
1:1 on this event fires constantly and is muted within days. The deployable
detection is the volume correlation.

**Count distinct secrets, not events.** `value_count` over
`requestParameters.secretId` measures what actually determines severity: how
much of the vault was disclosed. It also absorbs the batch-API variant for
free — `BatchGetSecretValue` emits a per-secret `GetSecretValue` entry, so
those are counted once each with no double-counting.

**Denial filtering is load-bearing:** the base rule filters `errorCode: null`.
Without it, a principal hitting `AccessDenied` on 15 secrets fires the same P0
as a real exfiltration, and the correlation's count no longer matches the
eradication work-list of secrets that actually need rotating.

**`ListSecrets` is context, not a trigger.** Plenty of tooling lists secrets.
Use `ListSecrets` → `GetSecretValue` as a *sequence* signal; never alert on
enumeration alone.

**Error strings:** Secrets Manager errors are *not* `Client.`-prefixed the way
EC2 errors are. A denial surfaces as `AccessDenied` (IAM-policy denial) or
`AccessDeniedException` (service/resource-policy denial) — match both, plus
`ResourceNotFoundException` and `DecryptionFailure`. Confirm the exact strings
against a real denied event in your account.

**Recovery note:** this emulation's infrastructure sets
`recovery_window_in_days = 0`, so tearing it down hard-deletes the secrets
immediately rather than scheduling them for deletion.

**Severity:** the manifest rates this MEDIUM; the IR view is **High** — the
technique discloses live secret plaintext.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1555.yml` — two documents: the base rule (`low`, not for direct
  alerting) and the `value_count` correlation that is the actual detection.
- `kql_t1555.kql` — same logic for backends without Sigma correlation support.

Full response procedure is in `../PLAYBOOK.md`.
