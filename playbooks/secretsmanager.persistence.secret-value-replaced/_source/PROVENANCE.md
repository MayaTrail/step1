# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One rule: A Secret Was Updated |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

**Merge test: not merged.** `07-TIERS.md` permits exactly two merges — the same
observable differing only in threshold or priority, and a correlation composed purely of shipped
building blocks — and this is neither. `UpdateSecret` and `CancelRotateSecret` are different APIs
producing different events with different responses, and the doctrine is explicit that sharing a
service or a MITRE technique is not grounds. Rotation lives in
`../../secretsmanager.persistence.rotation-disabled/` and is cross-referenced rather than restated.

**The rule cannot fire.** It matches `eventName:"updatesecret"`. CloudTrail emits `UpdateSecret`, so
on a case-sensitive field it matches nothing. Eleventh instance of this defect class across the
source set — see `../../_ground-truth/secretsmanager.md` §7.

**And `UpdateSecret` is one of three write paths, and not the one the SDKs use.**

- **`PutSecretValue`** writes a new version and moves `AWSCURRENT` to it. It is what the AWS SDKs and
  rotation Lambdas call.
- **`UpdateSecretVersionStage`** writes **nothing at all**. It moves `AWSCURRENT` to a version that
  already exists, so an actor who once had a value staged can make it operative again without any
  permission to write the secret and without producing a write event.

The rule watches one of the three, and it is the least used. See
`../../_ground-truth/secretsmanager.md` §6.

**It excludes errors,** so a denied write — an actor the permissions caught — produces no alert.

**MITRE:** the source maps `T1098` under TA0005. The technique is defensible but the tactic is not:
nothing about the defender's visibility changes. `T1556 — Modify Authentication Process` is used here
as the primary, because replacing a secret's value replaces the material an application authenticates
with; `T1565.001 — Stored Data Manipulation` covers the purely destructive shape. Both verified live
2026-08-31.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `secretsmanager.*` playbook is in `../../_ground-truth/secretsmanager.md`,
audited 2026-08-30. §6 covers the three write paths and version retention.
