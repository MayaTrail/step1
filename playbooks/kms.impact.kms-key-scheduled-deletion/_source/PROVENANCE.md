# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The single per-event key-deletion alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| KMS Key Scheduled Deletion | P3 | per-event | T1486/TA0040 |

## Merge decision — NOT merged, and this was the closest call in the service

The volume variant of this rule (`Multiple KMS Keys Scheduled Deletion`, P2, threshold 5 in
10m) ships as its **own playbook** at `../../kms.impact.multiple-kms-keys-scheduled-deletion/`.
It carries the byte-identical query, so it passes the *same observable* half of
`07-TIERS.md` merge test 1 — and it fails the other half, which the test states as an explicit
exclusion: *"If the response differs at all — different containment, different eradication —
they are two use cases."*

Three differences in the response, each mechanical rather than a matter of urgency:

1. **The containment work-list comes from a different source.** Here it comes from the event:
   one alert, one key ARN, cancel it. At volume it cannot, because the alert fires at its
   threshold while the actor's set is unbounded and `lookup-events` pages at 50 — so the mass
   playbook's first containment step is a live `list-keys`/`describe-key` state sweep, and
   containment cannot begin until that sweep completes. That step does not exist here.
2. **Step order inverts.** Here the cancel comes first and the principal is contained after.
   At volume the principal must be severed first, because `ScheduleKeyDeletion` succeeds on a
   key in the `Disabled` state — which is exactly the state `CancelKeyDeletion` leaves behind —
   so a cancel loop racing a live scheduling loop can lose keys it has already saved.
3. **The deadlines are a queue, not a deadline.** Each key carries its own `PendingWindowInDays`
   between 7 and 30, so a mass event produces a staggered set of expiry dates that has to be
   worked in ascending `DeletionDate` order. One key has one deadline.

The reversible sibling `../../kms.impact.kms-key-disabled/` **was** merged with its own volume
variant, and the contrast is the argument: re-enabling a disabled key costs nothing, has no
clock and no irreversible step, so cardinality really is the only difference there. Here it is
not. Merging is not applied reflexively across a service because the source rules happen to
share a query string.

## Tier decision — promoted to Tier 1

This use case is authored at **Tier 1** (`07-TIERS.md` §Tier 1), promoted on:

- **Test 4 — the evidence is destroyed by the remediation window.** When the waiting period
  expires AWS deletes the key, its key material, *all* of its metadata, its aliases and its
  grants together. The usage history that establishes what the key protected is destroyed at the
  same instant as the ability to decrypt it, so the blast radius must be collected before the
  deadline or it becomes permanently uncollectable. Every other use case in this service leaves
  the evidence behind.
- **Test 2 — the response has ordering that can go wrong.** `CancelKeyDeletion` succeeds only in
  `PendingDeletion` and returns the key to `Disabled`, not `Enabled`; `EnableKey` fails in
  `PendingDeletion`. And `PutKeyPolicy` is permitted on a key pending deletion, so the attacker
  can sever the cancel path after scheduling — which is why the first containment step is a
  key-policy check rather than the cancel itself.
- **Test 3 — the blast radius is not in the event.** Nothing on the event names a ciphertext and
  AWS does not store one; the answer must be assembled from `GetKeyLastUsage`, CloudTrail
  encryption contexts and the grant list, all of which expire with the key.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals are
packaged in a proprietary format whose scaffolding — payload field lists, entity labels,
product-specific field prefixes, internal enums and packaging metadata — identifies the source
on sight while bearing on nothing about whether the rule is correct. What is retained is the
complete detection logic: name, priority, type, MITRE label, the query verbatim, threshold,
window and group-by.

No substitution was applied. The extract labels itself `T1486/TA0040`; both IDs are live as of
the currency check on 2026-08-29, so both are written verbatim. The mapping is disputed on the
merits in `../PLAYBOOK.md` §6 and in `../detections/detection_note_t1485.md`.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation
only — a deployed rule travels outside the organisation that wrote it, and an internal path is
not resolvable to whoever receives it.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
