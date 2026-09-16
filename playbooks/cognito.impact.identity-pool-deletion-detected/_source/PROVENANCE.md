# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | One alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| Identity Pool Deletion Detected | P3 | per-event (threshold 0 in 10m), grouped by `userIdentity.arn` | T1485/TA0040 |

## Merge assessment — **no merge**

One source rule, one use case, one playbook. `07-TIERS.md`'s two merge tests were applied
against every neighbouring Cognito rule and none passes.

| Considered | Verdict |
|------------|---------|
| the user-pool deletion use case (not in this set) | **Separate.** Different event source — `cognito-identity.amazonaws.com` here, `cognito-idp.amazonaws.com` there. Different resource, different blast radius (an identity pool holds no credentials of its own; a user pool holds every user account), and a different recovery path. Sharing the tactic and the technique is explicitly **not** grounds to merge |
| `../../cognito.impact.user-pool-deletion-protection-disabled-followed-by-user-po/` | **Separate.** Identity pools have no deletion-protection concept at all, so there is no preceding disable to correlate on and the entire sequence thesis of that playbook is inapplicable here |
| `../../cognito.persistence.identity-pool-configured-to-allow-unauthenticated-access/` | **Separate, and the opposite direction.** Same resource and the same API family, but that use case is about a pool that has been made *more* reachable and remains live and abusable; this one is about a pool that no longer exists. Different observable (`UpdateIdentityPool`/`CreateIdentityPool` with a flag value, versus `DeleteIdentityPool`), opposite response — that one revokes and re-scopes a live role, this one rebuilds a destroyed resource — and no shared containment step. They **are** cross-referenced, because a deletion that follows an unauthenticated-access change in the same pool is anti-forensic cleanup rather than destruction, and the responder needs to check for that ordering |

Test 1 (same observable, same response, differing only in threshold or priority) fails on the
observable for every candidate: no other rule in the set fires on `DeleteIdentityPool`. Test 2
does not apply — this is not a flow rule and no correlation composes it.

## Threshold, as inherited

The alert is `logs_threshold` with a threshold of `0.0` over a 10-minute window. In the source
format that is how a per-event rule is expressed — "more than zero matches in the window" —
not a volume condition. The extract records the `0.0` verbatim rather than normalising it,
because a reader auditing `../PLAYBOOK.md`'s claim that this rule has *no* volume logic needs
to see the number the source actually carried. The 10-minute window is a notification-grouping
interval, not a detection threshold; the shipped rule is per-event and carries no correlation
of its own for the same reason.

## What the extract does not carry, and where it went instead

The source rule's group-by is `userIdentity.arn` and nothing else — it does not group by, and
does not surface, the identity pool being deleted. `DeleteIdentityPool` carries the pool ID in
`requestParameters`, so the field exists and is simply unused. That is a defect rather than a
provenance note, and it is recorded as a row in `../PLAYBOOK.md` §2's
`Detection Rule Quality Notes` table with its correction.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals are
packaged in a proprietary format whose scaffolding — payload field lists, entity labels,
product-specific field prefixes, internal enums and packaging metadata — identifies the source
on sight while bearing on nothing about whether the rules are correct. What is retained is the
complete detection logic: name, priority, type, MITRE label, the query verbatim, threshold,
window and group-by.

No MITRE substitution was needed for this rule: its structured label is `T1485/TA0040`, and
T1485 is live. `../PLAYBOOK.md` §6 accepts it as the primary mapping and adds a second one the
source does not carry; the reasoning is there, not here.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation
only — a deployed rule travels outside the organisation that wrote it, and an internal path is
not resolvable to whoever receives it.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.
