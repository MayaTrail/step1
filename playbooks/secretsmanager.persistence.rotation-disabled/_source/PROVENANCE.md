# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One rule: Automatic Secrets Rotation Turned Off |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

**Merge test: not merged.** `07-TIERS.md` permits exactly two merges — the same
observable differing only in threshold or priority, and a correlation composed purely of shipped
building blocks — and this is neither. `CancelRotateSecret` and `UpdateSecret` are different APIs
producing different events with different responses, and the doctrine is explicit that sharing a
service or a MITRE technique is not grounds. The value-replacement half lives in
`../../secretsmanager.persistence.secret-value-replaced/` and is cross-referenced rather than
restated.

**Cancelling rotation is quiet by construction.** Nothing errors, nothing breaks, and no
visibility is lost. The credential simply stops changing, so a value the actor already holds
remains the live one indefinitely. That is why the source's P3 understates it and why a
state-based check — is rotation still enabled where it should be — catches this when an
event-based rule does not.

**Undoing it is three calls, not one.** AWS warns that cancelling mid-rotation "can leave the
`VersionStage` labels in an unexpected state", leaving an orphaned `AWSPENDING` version, and that
"failing to clean up a cancelled rotation can block you from starting future rotations". A
responder who runs only `RotateSecret` gets a rotation that silently refuses to start.

**The rule excludes errors,** so a *denied* `CancelRotateSecret` — an actor the permissions caught
— produces no alert at all. That is the one clean signal this technique offers and it is filtered
out.

**MITRE:** Its redirect target, `T1685 — Disable or Modify Tools`, is about
defensive tooling; cancelling rotation changes no defensive visibility and is fully logged.
`T1098 — Account Manipulation` is used here: it covers any action that **preserves** adversary
access, which is precisely what stopping a credential from changing does. Verified live 2026-08-31.

**What the rule gets right:** the event name is correctly cased, and it groups by
`userIdentity.arn`, which carries the session — unlike the denial rule in
`../../secretsmanager.discovery.access-repeatedly-denied/`, which groups by role name. Both kept.

**Tier:** 1, on criterion 2 of `07-TIERS.md` — *the response has ordering that can go wrong*.

Service ground truth for every `secretsmanager.*` playbook is in `../../_ground-truth/secretsmanager.md`,
audited 2026-08-30. §5 covers the rotation-restart trap.
