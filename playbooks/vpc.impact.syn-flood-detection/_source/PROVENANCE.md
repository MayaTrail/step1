# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: SYN Flood Detection |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule is one threshold query and is fully readable, so every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**Two independent defects, either of which alone would make the rule miss a real flood.**

`tcp\-flags:"2"` is an exact match on a value AWS documents as **OR-ed across the aggregation
interval**: *"For short connections, the flags might be set on the same line in the flow log
record, for example, 19 for SYN-ACK and FIN, and 3 for SYN and FIN."* A SYN flood consists of
nothing but short connections, so its records overwhelmingly carry SYN OR-ed with something else.
The rule matches the tidy minority and misses the flood.

`threshold: 999` counts **records**, and a flow log record is an aggregate carrying `packets`. One
record can represent a hundred thousand packets, so the threshold measures how many distinct
5-tuples appeared rather than how much traffic arrived — a single-source flood can saturate a
target without ever reaching it. The corrected detections sum packets and count distinct sources,
and ship as two correlations because the distributed and concentrated forms of the attack have
opposite shapes.

Two smaller ones: the 5-minute window is shorter than the default 10-minute aggregation interval,
so it measures bucket alignment rather than traffic; and `action:REJECT` restricts the rule to
floods the security group already absorbed, which is the less damaging case.

**MITRE:** `T1498 — Network Denial of Service`, the source's own mapping, kept and verified live
2026-08-30.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `vpc.*` playbook is in `../../_ground-truth/vpc.md`, audited on
2026-08-30. The `tcp-flags` bitmask and its OR-ing are §4; field versions are §2; timing is §6;
`log-status` is §5.
