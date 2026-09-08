# Detection Note — T1098 (Account Manipulation)

**Signal:** `CancelRotateSecret` — the call that makes a stolen credential permanent.

## Why this is persistence and not evasion

Nothing about the defender's visibility changes when rotation is cancelled, and the call is fully
logged. What changes is that a credential the actor already holds stops expiring.
`T1098 — Account Manipulation` covers "any action that **preserves** or modifies adversary access",
which is exactly this. Verified live 2026-08-31.

## It is quiet by construction

No error, no outage, no missing telemetry. The only observable difference is that
`LastRotatedDate` stops advancing — which nothing watches by default. That is why the source's P3
understates it, and why the durable control here is a **state** check (is rotation still enabled
where it should be) rather than an event rule.

## Undoing it is three calls, not one

AWS warns that cancelling mid-rotation "can leave the `VersionStage` labels in an unexpected state",
leaving an orphaned `AWSPENDING` version, and that "**failing to clean up a cancelled rotation can
block you from starting future rotations**."

So the response is: `ListSecretVersionIds` to find the orphan, clear `AWSPENDING` with
`UpdateSecretVersionStage`, then `RotateSecret`. A responder who runs only the last one gets a
rotation that silently refuses to start and reads like a permissions problem.

## Response levers

**Cancel-then-rotate inside the same window is usually a Lambda swap.** It is the dominant false
positive and it is visible in one field.

**A refused cancellation deserves an alert.** The source rule excludes errors, so an actor the
permissions caught leaves no trace in it — and that is the one clean signal this technique offers.

**Check whether the value was read first.** Read-then-cancel is a stolen credential being made
permanent, which is a different incident from an operator turning rotation off.

**MITRE:** `T1098 — Account Manipulation` (verified live 2026-08-31), which covers any action
that preserves adversary access.

**Scope carries the severity.** Rotation cancelled on one secret is a finding; on three it is a
sweep across the account's credentials, which is why the correlation ships at critical while the
single event ships at high.

**GuardDuty:** no finding type covers Secrets Manager rotation.

**Adjacent:** the value-replacement half of this technique — an actor writing their own value in —
is `../../secretsmanager.persistence.secret-value-replaced/`.

**Files here:**
- `sigma_t1098.yml` — four documents: rotation cancelled (high), cancellation refused (medium),
  `secretsmanager_rotation_cancelled` as the informational base rule, and a three-secrets-in-thirty-
  minutes correlation (critical).
- `kql_t1098.kql` — separates cancelled from refused, flags the Lambda-swap shape, and rates a
  read-then-cancel sequence above a bare cancellation.

Full response procedure is in `../PLAYBOOK.md`.
