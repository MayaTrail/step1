# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, threshold, window, unique-count key, group-by keys and MITRE labels |
| Scope captured | One alert — `Multiple DNS Zones Deleted by a Single User` |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract, with the query and volume parameters reconstructed** (see the notice in that file) |

## Alerts captured

| Alert | Priority | Type | Threshold | Window | Unique-count key | Source MITRE label |
|-------|----------|------|-----------|--------|------------------|--------------------|
| Multiple DNS Zones Deleted by a Single User | P2 | unique count | 5 | 10m | `requestParameters.id` | — |

**What could not be verified.** The source alert package was not reachable from the authoring
session, so the query string and the volume parameters are a reconstruction rather than a
transcription. `../PLAYBOOK.md` §2's quality table is written so that every entry holds for any
rule of this title: it criticises the absence of a success filter, the absence of a principal
filter, counting only the deletions rather than the purges that must precede them, and
presenting a threshold count as a scope. None of that depends on the exact field path or the
exact threshold figure the source used.

## Merge decision — merge test 1 was APPLIED AND FAILED

This rule and `../../route53.stealth.dns-zone-deleted/` match the **identical observable** — a
successful `DeleteHostedZone` — so they pass the *same observable* half of `07-TIERS.md` merge
test 1. They fail the other half, which the test states as an explicit exclusion: *"If the
response differs at all — different containment, different eradication — they are two use
cases."*

The three differences are mechanical, not a matter of urgency or of running the same command in
a loop:

1. **The work-list cannot come from the event.** With one zone, the event carries the ID and one
   backward correlation resolves the name. At volume the alert's count is a **floor** — it fires
   at the threshold while the actor continues — `lookup-events` pages at 50, and, decisively,
   **a deleted zone is absent from `list-hosted-zones`, so no live-state call can enumerate what
   is missing.** The first step here is a reconciliation of an AWS Config inventory against the
   surviving zones, and nothing can be restored until it completes. There is no such step in the
   single-zone playbook.
2. **The containment order inverts, for a reason specific to this API.** With one zone the zone
   is recreated first, to reclaim the name, and the principal is contained after. At volume the
   principal must be severed **first**, because a newly created hosted zone contains only its
   default SOA and NS records — exactly the state `DeleteHostedZone` requires — so a recreate
   loop racing a live delete loop hands back zones that are immediately re-deletable.
3. **Restoration is a queue, not a loop, and ordering it is a containment decision.** AWS
   assigns four **different** name servers to every hosted zone, so each recreated zone needs a
   registrar-side delegation change — at whatever registrar holds that domain, which may not be
   AWS — with *"up to 48 hours to take effect"*. One zone is one registrar action. Fifty zones is
   a prioritised queue against a fixed per-item cost, and because AWS states that a deleted zone
   leaves a name where *"someone could hijack the domain"*, the order is a race rather than a
   backlog. There is nothing to prioritise when there is one zone.

Merge test 2 does not apply: this is not a FLOW rule composing building blocks shipped elsewhere.

**The contrast that shows the test was applied rather than assumed.** Merging *would* have been
correct had the deletion been reversible — where cardinality really is the only difference,
containment is the same command run once or fifty times and the second row belongs in §2's
trigger table. `DeleteHostedZone` is irreversible, recovery needs a second party per zone, and
the recreated resource is immediately re-destroyable. None of that is true of a reversible
operation, and it is why these two split where a reversible pair would not.

## Tier decision — TIER 2

The catalogue proposes Tier 2 and the five tests were applied.

- **Test 1** — no. Losing hosted zones costs resolution, not credentials.
- **Test 2** (ordering that can go wrong) — **the closest call.** The recreate-before-sever
  inversion is a real ordering hazard and it is the reason for the split above. But it is one
  sentence of strategy plus the ordering of two containment steps, which is exactly what the
  Tier 2 template provides ("*two sentences on strategy — including anything that must happen
  BEFORE something else*"). It does not need five containment steps.
- **Test 3** (blast radius not in the event) — partially: the zone names are not in the events
  and some are not in CloudTrail at all. But AWS Config holds them, and containment does not
  make them harder to get. One investigation query covers it.
- **Test 4** — no. The evidence is destroyed by the attack, before the alert; nothing in §3–§5
  destroys anything further.
- **Test 5** — no. The blind spots (no query data, the 100 KB omission, zones outside the
  lookback) are three paragraphs, not a page.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../route53.stealth.dns-zone-deleted/` | **Separate** — merge test 1 applied and failed on the response half; see above. Cross-referenced in both directions, and the field shape, region trap and error sets are documented once there rather than duplicated here |
| The source set's per-record-type deletion rules (`A Record Deleted`, `NS Record Deleted` and siblings) | **Separate, and they are the precursor.** They match `ChangeResourceRecordSets` with a different request shape and fire before this rule does. They appear here as the base rule of this playbook's purge-sweep correlation — a component, not a merge |
| The source set's `DNS Zone Created` rule | **Separate, and the opposite direction.** It is also the event an attacker generates when re-creating a zone they just deleted, so it appears here as a P2 trigger row |

## MITRE label dispute — yes

Its replacement
`T1685` (*Disable or Modify Tools*, Defense Impairment TA0112) is wrong on the merits: destroying
hosted zones impairs no defence. This playbook maps **`T1485` — Data Destruction (Impact,
TA0040)**, verified live 2026-08-29. Reasoning in `../PLAYBOOK.md` §6 and
`techniques/_ground-truth/route53.md` §10.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief, and additionally
because the source package was not reachable from the authoring session. That second departure is
stated in the file itself.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation only.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
