# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Suspicious AWS Metadata Query |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule is one threshold query and is fully readable, so every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**The rule is a free-text search, and the field the string lands in is the entire meaning.**
`"169.254.169.254"` matched anywhere in the record covers two unrelated events. In `rdata` it means
a name resolved to the metadata address — DNS rebinding, where a fetcher that validated the
hostname connects somewhere else entirely. In `query_name` it means somebody looked up the literal
address as a name, which is malformed and rarely interesting. The corrected rules read `rdata`.

**`AND _exists_:query_name` is a check that cannot fail.** Every Resolver query log record carries
a `query_name` — it is the name that was asked for. The clause narrows nothing.

**The address set is wider than one address.** `169.254.170.2` serves ECS task metadata and
task-role credentials and `169.254.170.23` serves EKS Pod Identity credentials. Naming only
`169.254.169.254` misses two credential endpoints reached by the identical primitive. The corrected
rule matches the `169.254.0.0/16` prefix.

**MITRE:** the source carries bare `T1552`. Mapped to `T1552.005 — Unsecured Credentials: Cloud
Instance Metadata API`, which names this exactly and carries the IaaS platform, verified live
2026-08-30. `T1590.002` is carried by the private-address rule, which is reconnaissance of internal
naming rather than credential access.

**Merge test:** the private-address and DNS Firewall rules ship in this file rather than as
separate use cases because they are the same observation read at different severities — an answer
pointing somewhere it should not, and whether the firewall saw it. No separate source rule covers
either, so nothing has been aggregated.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `route53dns.*` playbook is in `../../_ground-truth/route53dns.md`,
audited on 2026-08-30. The caching rule is §1; field semantics are §3; the control plane is §5.
