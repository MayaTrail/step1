# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, threshold, window, group-by keys and MITRE labels |
| Scope captured | One alert — `DNS Zone Deleted` |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract, with the query line reconstructed** (see the notice in that file) |

## Alerts captured

| Alert | Priority | Type | Window | Group-by | Source MITRE label |
|-------|----------|------|--------|----------|--------------------|
| DNS Zone Deleted | P2 | threshold, `> 0` | 10m | `userIdentity.arn` | — |

A `logs_threshold` alert with a threshold of `0` is a per-event alert wearing a volume shape: it
fires on the first matching document in the window, and the window only adds a batching delay.

**What could not be verified.** The source alert package was not reachable from the authoring
session, so the query string is a reconstruction rather than a transcription. Every entry in
`../PLAYBOOK.md` §2's quality table is written to hold for any rule of this title — it criticises
the absence of a principal filter, the absence of the precursor chain, and the reliance on an
event that names only a zone ID, none of which depend on the exact field path the source used.

## Merge decision — NOT merged with the volume variant, and this was the close call

The volume variant, `Multiple DNS Zones Deleted by a Single User`, ships as its own playbook at
`../../route53.stealth.multiple-dns-zones-deleted-by-a-single-user/`. It matches the identical
observable — successful `DeleteHostedZone` — so it passes the *same observable* half of
`07-TIERS.md` merge test 1. **It fails the other half**, which the test states as an explicit
exclusion: *"If the response differs at all — different containment, different eradication —
they are two use cases."*

Three differences in the response, each mechanical rather than a matter of urgency or of
looping the same command:

1. **The work-list comes from a different place, and at volume it cannot come from the event.**
   Here the event carries the zone ID and one backward correlation resolves the name. At volume
   the alert fires at its threshold while the actor's set is unbounded, `lookup-events` pages at
   50, and — decisively — **deleted zones are absent from `list-hosted-zones`, so live state
   cannot enumerate what is missing.** The mass playbook's first step is therefore a
   reconciliation of an AWS Config inventory against the surviving zones, and no restoration can
   begin until it completes. That step does not exist here.
2. **The containment order inverts, for a reason specific to this API.** Here the zone is
   recreated first and the principal contained after. At volume the principal must be severed
   **first**, because a freshly created hosted zone contains only the default SOA and NS records
   — which is exactly the state `DeleteHostedZone` requires — so a recreate loop racing a live
   delete loop hands back zones that are immediately re-deletable and loses ones it has already
   restored.
3. **Restoration does not parallelise, so it has to be ordered, and ordering it is a containment
   decision.** A recreated zone is assigned four **different** name servers, so each restored
   zone needs a registrar-side delegation change with up to 48 hours of propagation, at whatever
   registrar holds that domain. One zone is one registrar action. Fifty zones is a queue against
   a fixed per-item cost, worked in the order of which names an attacker can most profitably
   claim — and AWS states plainly that *"if you delete a hosted zone, someone could hijack the
   domain"*, which makes the ordering a race rather than a backlog. There is nothing to triage
   when there is one zone.

Merge test 2 does not apply: this is not a correlation rule.

## Tier decision — TIER 2

The catalogue proposes Tier 2 and the five promotion tests were applied rather than assumed.

- **Test 1** (account takeover one hop away) — no. Losing a hosted zone costs resolution, not
  credentials.
- **Test 2** (ordering that can go wrong) — the ordering constraint that exists here is AWS's
  own teardown rule for a child zone (delete the parent NS record first, wait out its TTL), and
  it is one sentence in §3 plus one containment step. It does not carry a Tier 1 response.
- **Test 3** (blast radius not in the event) — **partially, and it is the strongest argument.**
  The event carries only a zone ID; the name and the records are not in it. But they *are*
  retrievable, from AWS Config and from the `DELETE` changes that had to precede the delete, and
  retrieving them is not made impossible by containment. That is a breadth problem handled by
  two investigation queries, which is exactly what Tier 2 provides.
- **Test 4** (evidence destroyed by the remediation) — no. The evidence is destroyed by the
  *attack*, before the alert fires. Nothing in §3 or §4 destroys anything further.
- **Test 5** (structural blind spot worth a page) — no. The blind spots here (no query data, an
  omitted `requestParameters` above 100 KB) are two paragraphs, not a page.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../route53.stealth.multiple-dns-zones-deleted-by-a-single-user/` | **Separate** — see the merge decision above. Cross-referenced in both directions |
| The `ChangeResourceRecordSets` record-deletion rules in the source set (`A Record Deleted`, `NS Record Deleted`, and their siblings) | **Separate, and they are the precursor.** They match a different event with a different request shape, and they fire *before* this rule does. They appear here as trigger rows and as the base rule of this playbook's `temporal_ordered` correlation, which is the relationship `07-TIERS.md` test 2 prescribes — a component, not a merge |
| `../../route53.stealth.ns-record-created-or-updated/` | **Separate, and adjacent.** That covers delegation being *handed away* while the zone survives; this covers the zone being *destroyed*. §3 here hands off to it when the parent zone still delegates to the deleted child |
| The source set's `Query Logging Disabled` alert | **Separate.** Different observable (`DeleteQueryLoggingConfig`), and it is a visibility technique rather than a destructive one. It is out of this batch's scope and is noted as a coverage dependency in §1 |

## MITRE label dispute — yes

Its mechanical replacement `T1685` (*Disable or Modify Tools*, Defense
Impairment, TA0112) is **also wrong on the merits**: deleting a hosted zone impairs no defence
and clears no log.

This playbook maps **`T1485` — Data Destruction (Impact, TA0040)**, verified live 2026-08-29,
which lists IaaS and covers cloud-resource deletion in its own words. The reasoning and the
rejected candidates are in `../PLAYBOOK.md` §6 and in `techniques/_ground-truth/route53.md` §10.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief, and additionally —
uniquely to this batch — because the source package was not reachable from the authoring
session. That second departure is stated in the file itself rather than left to be discovered.

The shipped `references:` blocks in `../detections/` cite public MITRE, AWS and IETF
documentation only — a deployed rule travels outside the organisation that wrote it, and an
internal path is not resolvable to whoever receives it.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
