# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Immediate rule and threshold rule over the same query string |
| Scope captured | Two rules, one use case: New Key Created, and Multiple Keys Created |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

**Merge test:** the two rules share one query and differ only in threshold — an immediate rule and a
five-in-ten-minutes rule over `CreateKey`. That is already a base rule plus a correlation, which is
the structure the kit asks for, so they stay together as one use case rather than being split into
two directories that would reproduce the same response twice.

**Neither rule can fire.** Both match `eventName:"createkey"`. CloudTrail emits `CreateKey`, and on a
case-sensitive field the lowercase form matches nothing. Twelfth instance of this defect class across
the source set — see `../../_ground-truth/kms.md` §7.

**Creating a key encrypts nothing.** Both rules map to `T1486 — Data Encrypted for Impact`, which is
the technique the creation *serves* rather than the one it performs. A new key on its own is a
one-dollar-a-month resource with no data under it. This playbook rates plain creation as
informational and reserves the severity for the request parameters that matter.

**And the request body is where this use case actually lives.** `CreateKey` carries four parameters
that change what the key is for, and the source rules read none of them:

- **`Origin: EXTERNAL`.** The key holds no AWS-generated material; the creator imports their own. AWS
  never has it. `DeleteImportedKeyMaterial` then makes every ciphertext under that key unreadable
  **immediately** — no 7-to-30-day window like `ScheduleKeyDeletion` — and recovery requires
  re-importing the same material, which only the importer holds. This is the in-account ransomware
  primitive and it is one API call away from a key this rule reports at P4.
- **`Policy`.** A key created with a policy that admits an external account is cross-account staging.
- **`BypassPolicyLockoutSafetyCheck: true`.** A key that is unmanageable from birth.
- **`MultiRegion: true`.** Replicable to other regions, so the blast radius is not one region's.

**Five keys in ten minutes is a deployment.** An infrastructure apply that stands up an environment
creates keys in a burst; a person does not. The threshold selects for the pipeline. Kept at five, but
with a provisioning allowlist doing the discrimination, because the volume signal is genuinely weak
here — key creation is cheap and legitimate.

**The classic AWS ransomware pattern is not visible to this rule at all.** Re-encrypting data with a
key held in the **attacker's** account creates nothing in yours. The detectable artifact is on the
data side — objects whose `KMSKeyId` names an account that is not yours — and it is named in §4 of
the playbook rather than pretended to be covered here.

**Boundary with the neighbouring playbooks:** `DisableKey` is `../../kms.impact.kms-key-disabled/`;
`ScheduleKeyDeletion` is `../../kms.impact.kms-key-scheduled-deletion/` and
`../../kms.impact.multiple-kms-keys-scheduled-deletion/`; key-policy access removal is
`../../kms.impact.key-policy-access-removed/`. This playbook owns creation only.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for the `kms.*` playbooks authored against it is in `../../_ground-truth/kms.md`,
audited 2026-08-30. §1 compares the four ways to make ciphertext unreadable; §2 covers external
origin.
