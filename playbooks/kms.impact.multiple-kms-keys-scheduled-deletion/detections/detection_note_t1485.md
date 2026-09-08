# Detection Note — T1485 (Data Destruction)

**Signal:** a KMS key scheduled for deletion — one is enough — and, as an escalation, several by
one principal in a short window.

**This is the rare destructive AWS action that comes with an undo button, and the whole response
is shaped by that.** `ScheduleKeyDeletion` enforces a waiting period of **7 to 30 days**, during
which the key sits in `PendingDeletion` and `CancelKeyDeletion` reverses it completely. Nothing is
lost until the window expires. After it expires, every ciphertext under that key is permanently
undecryptable — there is no support path, no backup of the key material, and no recovery of any
kind.

So the number that matters in triage is **hours remaining**, and the correct first action is to
cancel, then investigate. That inversion — act before you understand — is unusual and it is
correct here, because cancelling is free and reversible while expiry is not.

**What the original rule got wrong** — its threshold describes a script rather than the technique.

Five keys in ten minutes is scripted destruction, which is real. But **one** key scheduled by a
principal that does not own key lifecycle is already an incident: a single customer-managed key can
be the only thing standing between an attacker and every object encrypted under it. The corrected
set ships the single-key case at high and keeps volume as an escalation rather than as the
entry condition.

*It also discards the refusals.* `ScheduleKeyDeletion` denied repeatedly across keys is a principal
mapping which keys it can destroy. It changes no state, so nothing else in the estate notices — and
it is the earliest warning this technique produces.

## Two shorter paths to the same outcome

**`DisableKey` takes effect immediately.** No waiting period, no pending state. Every decrypt call
under that key starts failing at once with `KMSInvalidStateException`. Its practical effect while
it lasts is identical to deletion, and it is instantly reversible — which makes it the quieter
choice and the one a volume rule on `ScheduleKeyDeletion` cannot see at all.

**A key policy rewrite can strip decrypt access** without touching the key's state. The key is
healthy, its rotation is on, and nothing can use it. `PutKeyPolicy` is shipped as a companion for
that reason.

**The minimum window is itself a signal.** AWS permits 7 to 30 days and defaults to 30. Choosing 7
shortens the response window by three quarters, and routine decommissioning has no reason to.

## Response levers

**Cancel first.** `CancelKeyDeletion` returns the key to `Disabled` — note, **not** to `Enabled`.
The key must be re-enabled separately, and a responder who cancels and stops has left every
consumer still failing.

**The blast radius is not in KMS.** KMS records that a key exists and was used; what it protects
is assembled from the consuming services — S3 bucket encryption configuration, EBS volume
attributes, RDS storage encryption, Secrets Manager secrets — each asked separately. A key with no
apparent consumer is not necessarily unused; it may protect data in an account you are not looking
at, via a key policy grant.

**Multi-Region keys resist deletion.** A primary with live replicas cannot be deleted until the
replicas are, so a schedule against one may simply be blocked. That is a genuine control and it is
visible in `describe-key`, not in the trail.

**Error strings:** `KMSInvalidStateException` on a decrypt against a disabled or pending key —
this is what a consuming service reports, and it is where the outage surfaces first.
`NotFoundException`, `KMSInvalidStateException` and `InvalidArnException` on the KMS calls
themselves; denials as `AccessDenied` / `AccessDeniedException`, both forms.

**MITRE:** the source carries `T1486 — Data Encrypted for Impact`, which describes an adversary
encrypting data to deny access. This is the inverse — the data is already encrypted and the key is
being removed — so `T1485 — Data Destruction` is correct. Verified live 2026-08-30. `T1486` is
defensible only in that the outcome resembles ransomware without the ransom demand.

**Severity:** high for a single scheduled deletion, critical for volume or for a window under 48
hours remaining, high for repeated refusals. The severity is driven by time remaining more than by
count, which is why the KQL sorts on it.

**GuardDuty:** no coverage. There is no finding type whose resource is a KMS key.

**Files here:**
- `sigma_t1485.yml` — the volume correlation at critical, a per-event component at informational,
  a denial rule, and a refusal correlation.
- `kql_t1485.kql` — sorted by **hours remaining** rather than by count, with the minimum pending
  window surfaced because choosing 7 days is itself a signal.

Full response procedure is in `../PLAYBOOK.md`.
