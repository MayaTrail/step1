# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: High Severity Alert Detected |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule is one threshold query and is fully readable, so every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**One thing the source pack gets right and is worth recording as such:** Suricata severity is
inverted — 1 is the most severe — and the pack maps 1 to high, 2 to medium and 3/4 to low. That is
correct. It is noted explicitly because a reviewer's instinct is to "fix" the inversion, and doing
so would silently invert the entire alert hierarchy.

**The defect is the action filter.** `(action:"allowed" OR NOT action:"blocked")` keeps only
traffic the firewall did not block. That is a reasonable paging decision and a poor detection
decision: it removes the ability to distinguish "nobody is attacking us" from "everything is being
blocked", and it discards the probing run-up in which an actor is refused repeatedly before finding
a path that passes. The corrected set keeps both streams and separates them by **rule level** —
unblocked at high to a person, blocked at low to a dashboard — rather than by filter.

Two smaller ones. The construct is also redundant: with `alert.action` taking `allowed` or
`blocked`, `allowed OR NOT blocked` is `allowed` plus records where the field is absent. And the
companion medium-severity rule in the same pack has an empty `group_by` with a threshold of zero,
so every individual alert pages with no aggregation and no actor.

**MITRE:** the source pack maps this rule to nothing at all. Mapped here to
`T1071 — Application Layer Protocol` for the command-and-control shape most severity-1 signatures
carry, with `T1190 — Exploit Public-Facing Application` on the signature-breadth correlation, which
observes an actor working through an estate. Both verified live 2026-08-30. A severity-based rule
does not map cleanly to one technique — the signatures underneath it span many — so these are the
tactic-level anchors rather than a claim about any particular alert.

**Merge test:** the blocked and unblocked rules are two halves of one observation, and the
correlation reads across them. No separate source rule covers either half, so nothing has been
aggregated.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `netfw.*` playbook is in `../../_ground-truth/netfw.md`, audited on
2026-08-30. The stateless-engine limitation is §1; which actions produce alert logs is §2; the
record shape and the two action fields are §3; the severity inversion is §4.
