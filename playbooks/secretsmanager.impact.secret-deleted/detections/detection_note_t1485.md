# Detection Note — T1485 (Data Destruction)

**Signal:** `DeleteSecret` — and, specifically, the one request parameter that decides whether it is
reversible.

## The rule cannot fire

It matches `eventName:"deletesecret"`. CloudTrail emits `DeleteSecret`, so on a case-sensitive field
it matches nothing. Tenth instance of this defect class across the source set.

## Two incidents, one alert

| Call | Outcome |
|---|---|
| `DeleteSecret` (default) | 30-day recovery window, `RestoreSecret` undoes it |
| `DeleteSecret --recovery-window-in-days 7` | The shortest window Secrets Manager permits |
| `DeleteSecret --force-delete-without-recovery` | No window, no restore, gone |

The source rule reads none of the request body, so all three arrive identically. One is a ticket; one
is permanent destruction of credential material.

## Beware the absent parameter

`forceDeleteWithoutRecovery` and `recoveryWindowInDays` are optional. When the caller omits them they
are **missing from `requestParameters` entirely** — not present-and-false. A rule written as
`NOT forceDeleteWithoutRecovery:"false"` would therefore match every ordinary deletion. The documents
here match on the value `true` being present, never on the absence of `false`.

## The recovery window is not an outage window

AWS: *"When a secret is scheduled for deletion, you cannot retrieve the secret value."*

Consumers start failing the moment the call succeeds. The thirty days are for recovering the
**value**, not for keeping the service running — a responder who reads "30-day window" as "we have
time" has the urgency exactly backwards. Replicas have no window at all: *"When you delete a replica,
it is deleted immediately."*

## Response levers

**`RestoreSecret` is one call and it is the whole containment step.** It clears the `DeletionDate`
and consumers recover immediately. Do it before investigating; the investigation does not expire and
the window does.

**Check whether the value was read first.** A principal that called `GetSecretValue` and then
`DeleteSecret` disclosed the credential and then destroyed the evidence of what it was. That is a
larger incident than either half, and the disclosure side is owned by
`../../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/`.

**Deletion takes the rotation configuration and the resource policy with it.** Restoring the secret
restores those too, which is another reason to restore before rebuilding by hand.

**MITRE:** the source maps `T1528 — Steal Application Access Token` under Credential Access. Deleting
a secret steals nothing. `T1485 — Data Destruction` (verified live 2026-08-30) with `T1489 — Service
Stop` for the immediate consumer outage.

**GuardDuty:** no finding type covers Secrets Manager deletion.

**Files here:**
- `sigma_t1485.yml` — four documents: force-deletion without recovery (critical),
  `secretsmanager_secret_deleted` as the base rule (low), the seven-day minimum window (medium), and
  a `value_count` correlation at three distinct secrets in thirty minutes (high).
- `kql_t1485.kql` — separates forced from windowed deletion, flags a restore that self-corrected, and
  surfaces whether the value was read before the deletion.

Full response procedure is in `../PLAYBOOK.md`.
