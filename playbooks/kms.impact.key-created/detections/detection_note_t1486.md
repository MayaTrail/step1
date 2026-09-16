# Detection Note — T1486 (Data Encrypted for Impact)

**Signal:** `CreateKey`, and specifically the four request parameters that decide what the key is for.

## Neither source rule can fire

Both match `eventName:"createkey"`. CloudTrail emits `CreateKey`, so on a case-sensitive field
neither matches anything. Twelfth instance of this defect class across the source set.

The two rules are otherwise well shaped: an immediate rule and a five-in-ten-minutes rule over the
same query is a base rule plus a correlation, which is the structure the kit asks for. They are kept
together.

## Creating a key encrypts nothing

A new KMS key is a one-dollar-a-month resource with no data under it. `T1486` is the technique the
key later *serves*, not the one creation performs, so plain creation is informational here.

## The request body is where this use case lives

| Parameter | Why it matters |
|---|---|
| `Origin: EXTERNAL` | The key holds no AWS-generated material; the creator imports their own and AWS never has it |
| `Policy` | A policy admitting an external account is cross-account staging, and it is a raw JSON string on the request side |
| `BypassPolicyLockoutSafetyCheck: true` | A key that is unmanageable from birth |
| `MultiRegion: true` | Replicable, so a later change is not confined to one region |

**`Origin: EXTERNAL` is the one that matters most.** `DeleteImportedKeyMaterial` makes every
ciphertext under such a key unreadable **immediately** — no 7-to-30-day window like
`ScheduleKeyDeletion`, and AWS's recovery instruction is to "reimport the same key material", which
only the importer holds. That is the in-account ransomware primitive, and it is one API call away
from a key the source rules report at P4.

## Beware the absent parameter

`bypassPolicyLockoutSafetyCheck` is optional, so it is **missing** from `requestParameters` on an
ordinary call rather than present-and-false. The rule here tests for the value `true` being present.
The inverse form — `NOT bypassPolicyLockoutSafetyCheck:"false"` — matches every ordinary call, and it
is exactly the bug carried by the neighbouring `PutKeyPolicy` rule in
`../../kms.impact.key-policy-access-removed/`.

## Response levers

**Five in ten minutes is a deployment.** The threshold is kept but the discrimination moved to a
provisioning allowlist on the base rule, because the volume signal is genuinely weak — key creation is
cheap and legitimate.

**The classic AWS ransomware pattern is invisible here.** Re-encrypting data with a key in the
**attacker's** account creates nothing in yours. The detectable artifact is on the data side: objects
or volumes whose `KMSKeyId` names another account.

**MITRE:** `T1486 — Data Encrypted for Impact`, verified live 2026-08-30, as the technique the key
serves. Creation alone is staging and is rated accordingly.

**GuardDuty:** no finding type covers KMS key creation.

**Files here:**
- `sigma_t1486.yml` — four documents: external key material (high), lockout check bypassed (high),
  `kms_key_created` as the informational base rule carrying the provisioning allowlist, and a
  five-in-ten-minutes correlation (medium).
- `kql_t1486.kql` — reads all four parameters, tests the creation-time policy for an external
  account, and rates material deletion above everything else.

Full response procedure is in `../PLAYBOOK.md`.
