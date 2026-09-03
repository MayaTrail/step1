# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One rule: Multiple Failed Access Attempts |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

**Merge test: not merged.** `07-TIERS.md` permits exactly two merges — the same observable differing only in threshold or priority, and a correlation
composed purely of shipped building blocks — and this is neither. A successful `ListSecrets` and any
Secrets Manager call returning `AccessDenied` are different observables with different responses, and
the doctrine is explicit that sharing a service is not grounds. Listing now lives in
`../../secretsmanager.discovery.secrets-enumerated/` and is cross-referenced rather than restated.

## What the rule gets wrong

**`T1110 — Brute Force` under Initial Access.** Brute force is guessing credentials. An
`AccessDenied` from Secrets Manager is returned to a principal whose credential **authenticated
successfully** and whose authorization failed — so the technique does not apply, and Initial Access
is wrong in the same way: the actor is already inside. This is discovery. `T1526 — Cloud Service
Discovery`, verified live 2026-08-31.

**Grouped by `sessionIssuer.userName`, which is the role name.** Every concurrent session of a role
shares it, so twenty sessions with one denial each are indistinguishable from one session with
twenty — and the alert names the role rather than the actor. The listing rule in the neighbouring
playbook groups by `userIdentity.arn`, which does carry the session. Two rules, same service,
different keys, no stated reason. Regrouped on the session here. See
`../../_ground-truth/secretsmanager.md` §8.

**Twenty denials in five minutes.** Four a minute sustained. That is a workload retrying in a loop,
not a person walking an inventory. Ten in fifteen minutes is used here, which still catches the loop
and also catches a patient actor.

**`AccessDenied` only.** A call blocked by an SCP or a permissions boundary can surface with a
different error code, so an exact-match filter under-counts in any account that uses them. Widened
here, with the widening stated.

**No dimension separating a loop from a walk.** One secret id repeated is a workload missing a
grant; many distinct ids is an inventory being probed. That single distinction dismisses the dominant
false positive and the rule cannot express it.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.

Service ground truth for every `secretsmanager.*` playbook is in `../../_ground-truth/secretsmanager.md`,
audited 2026-08-30. §8 covers the group-by field.
