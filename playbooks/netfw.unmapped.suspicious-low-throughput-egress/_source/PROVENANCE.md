# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Suspicious Low-Throughput Egress |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule is one threshold query and is fully readable, so every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**The rule's name and its logic describe different things.** It matches `age >= 3600` **and**
`bytes >= 5,000,000` — a session lasting at least an hour and carrying at least 5 MB, roughly
1.4 KB/s. That is low *rate* and substantial *volume*: slow exfiltration over a persistent
connection, which is a real and worthwhile detection.

Command-and-control **beaconing**, which "low-throughput egress" names, is the opposite shape: many
short flows at regular intervals, each a few hundred bytes. Every one of those has an age near zero
and a byte count orders of magnitude below the threshold, so the rule cannot see beaconing at all.
Both shapes are shipped here because both are real and the pack has a rule for only one.

**`netflow` is uni-directional and that breaks the volume test quietly.** AWS: *"The log type
`netflow` logs uni-directional flows, so each event represents traffic going in a single
direction."* So `bytes` is one leg — a large download and a large upload produce matching records
and only one is exfiltration. The corrected rules read `event.direction`, where `to_server` is the
outbound leg, rather than inferring intent from volume.

**And the alert is structurally late.** Netflow records are emitted when a flow ends or times out,
so a flow matching `age >= 3600` produces its record at least an hour after it began. The
10-minute window is a window on record *arrival*, not on traffic. No window setting changes this;
it is a property of the format, and it is stated in the shipped files rather than tuned away — the
value of the detection is scoping the loss, not preventing it.

Two smaller ones: geo-enrichment stands in for "external" where the destination address answers
directly, and a threshold of zero grouped only by source means every matching flow alerts
individually rather than per source-destination pair.

**MITRE:** the source carries bare `T1071`. `T1041 — Exfiltration Over C2 Channel` is added for the
slow-transfer rule, which observes data leaving rather than a channel existing;
`T1071 — Application Layer Protocol` is kept for the beaconing correlation. Both verified live
2026-08-30.

**Merge test:** the beaconing correlation ships here rather than as a separate use case because it
is the shape this rule is *named* for — separating them would leave the pack's naming and its
detection permanently mismatched. No separate source rule covers beaconing.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `netfw.*` playbook is in `../../_ground-truth/netfw.md`, audited on
2026-08-30. The uni-directional netflow property and the emission timing are §5; the
stateless-engine limitation is §1.
