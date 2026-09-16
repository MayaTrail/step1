# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a regular expression |
| Scope captured | One alerting rule: Suspicious Query with Base64 Encoded String |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS, IETF and MITRE documentation only.

The source rule is one regular expression over `query_name` and is fully readable, so every row of
the `Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**The rule searches for a character DNS does not carry.** It matches base64 **padding** — a
`query_name` ending in one or two `=` signs, or containing them before a dot. But `=` is not part
of the DNS preferred syntax (RFC 1035: letters, digits and hyphens), which is precisely why every
tool that stuffs base64 into DNS strips the padding first. The rule matches essentially nothing a
working tunnel produces; what it does match is malformed queries. The regex is not the wrong
technique — the character class is.

**And it has no `group_by` at all**, with a threshold of zero. Every individual match is an alert,
with no aggregation, no actor and no domain to act on.

The corrected set measures **subdomain cardinality under a registered domain**, which is
encoding-agnostic: base64, base32, hex and custom alphabets all produce the same shape, because the
payload *is* the subdomain. Label length, `TXT`/`NULL` query types, `NXDOMAIN` ratio and TCP
transport are shipped as components around it.

**One property of this log source makes the corrected rule unusually reliable.** AWS logs only
unique queries, not cache hits — which makes volume reasoning about ordinary domains meaningless.
Tunnelling generates a distinct name per query by construction, so every query is a cache miss and
every one is logged. The cardinality measure is exactly the one the cache cannot suppress.

**MITRE:** `T1048.003 — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted
Non-C2 Protocol` for the exfiltration direction, refining the source's bare `T1048`, with
`T1071.004 — Application Layer Protocol: DNS` for the command-and-control direction and
`T1568.001 — Dynamic Resolution: Fast Flux DNS` on the NXDOMAIN component. All verified live
2026-08-30. Both directions are cited because a DNS tunnel carries traffic both ways and the log
cannot distinguish which mattered.

**Merge test:** the label-length, query-type and NXDOMAIN rules ship here as components of one
detection rather than as separate use cases — none has a source rule of its own, and none is usable
alone. Nothing has been aggregated.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `route53dns.*` playbook is in `../../_ground-truth/route53dns.md`,
audited on 2026-08-30. The caching rule is §1; DNS label limits are §4; field semantics are §3.
