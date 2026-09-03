# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Multiple KMS Keys Scheduled Deletion |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

The source rule is `eventSource:"kms.amazonaws.com" AND eventName:"schedulekeydeletion"` at a
threshold of five in ten minutes, so every row of the `Issue | Impact | Correction` table in
`../PLAYBOOK.md` §2 is auditable against the artifact.

**The threshold is the defect, and it is the wrong shape for this technique.** Five keys in ten
minutes describes a script. One key scheduled for deletion by a principal that does not own key
lifecycle is already an incident, because a single customer-managed key can be the only thing
standing between an attacker and every object encrypted under it. The volume rule is worth having
and it must not be the only rule — the corrected set ships the single-key case at high and keeps
volume as an escalation.

**And it discards the refusals, which are the earlier signal.** `ScheduleKeyDeletion` denied
repeatedly across keys is a principal mapping which keys it can destroy, and it produces no state
change at all — so nothing else in the estate will notice it. That is shipped as its own rule.

**MITRE:** the source carries `T1486 — Data Encrypted for Impact`, which describes an adversary
encrypting data to deny access to it. Scheduling a key for deletion is the inverse: the data is
already encrypted and the key that decrypts it is being removed. Mapped to
`T1485 — Data Destruction`, verified live 2026-08-30, with `T1486` noted as defensible only in the
sense that the outcome resembles ransomware without the ransom.

**Merge test:** not applicable — one source rule, one use case. `../../kms.impact.kms-key-disabled/`
and `../../kms.impact.kms-key-scheduled-deletion/` are the adjacent use cases and are cross-referenced
rather than folded in.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth is inline in the shipped files.
