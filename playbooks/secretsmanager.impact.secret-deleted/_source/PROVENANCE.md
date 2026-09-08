# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One rule: Secret Deletion Attempted |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

**The rule cannot fire.** It matches `eventName:"deletesecret"`. CloudTrail emits `DeleteSecret`, and
on a case-sensitive field the lowercase form matches nothing. Tenth instance of this defect class
across the source set — see `../../_ground-truth/secretsmanager.md` §7.

**It has no content check on the one parameter that decides the incident.** `DeleteSecret` has two
completely different outcomes and they arrive as the same alert:

- **Default.** A recovery window of 7 days minimum, 30 by default. Secrets Manager stamps a
  `DeletionDate` and `RestoreSecret` undoes it at any point before that.
- **`ForceDeleteWithoutRecovery: true`.** No window, no `RestoreSecret`, gone. It cannot be combined
  with `RecoveryWindowInDays` in the same call.

One is reversible with a single command; the other is permanent destruction of credential material.
A rule that does not read the request body cannot tell an operator which one just happened.

**And the recovery window is not an outage window.** AWS: "When a secret is scheduled for deletion,
you cannot retrieve the secret value." Every consumer calling `GetSecretValue` starts failing the
moment the call succeeds. The thirty days are for recovering the **value**, not for keeping the
service up — a responder who reads "30-day window" as "we have time" has the urgency exactly
backwards. Replicas have no window at all: "When you delete a replica, it is deleted immediately."

**MITRE:** the source maps `T1528 — Steal Application Access Token` under Credential Access. Deleting
a secret steals nothing; it destroys. `T1485 — Data Destruction` is used here, with `T1489 — Service
Stop` for the immediate consumer outage. Both verified live 2026-08-30. Where the same principal read
the value before deleting it, the disclosure is the larger incident and is owned by
`../../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/`.

**What it gets right:** the query has no `NOT _exists_:errorCode`, so denied attempts match as well
as successes — which is what the name promises. It then rates them identically, which is the part
corrected here.

**Merge test:** not applicable — one source rule, one use case. Enumeration that precedes a deletion
belongs to `../../secretsmanager.discovery.secrets-enumerated/`; this playbook cross-references rather
than reproducing it.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `secretsmanager.*` playbook is in `../../_ground-truth/secretsmanager.md`,
audited 2026-08-30. §4 covers the deletion semantics.
