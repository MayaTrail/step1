# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule, `less_than` condition, no query body |
| Scope captured | One alerting rule: No Logs From Amazon Route53 DNS Query |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project. The
extract's `group_by` referenced the ingesting platform's own metadata namespace; it is rendered
`log_source.*` by `tools/deid_extract.py`, which learned that shape from this rule.

The source rule counts records, fewer than one in four hours, grouped by the log pipeline's
application and subsystem labels — so every row of the `Issue | Impact | Correction` table in
`../PLAYBOOK.md` §2 is auditable against the artifact.

**The grouping key is the defect.** It groups by the ingestion pipeline's labels, which can tell
you that a shipper stopped and never which **VPC** stopped being logged. Resolver query logging is
configured and associated per VPC, so the VPC is the only useful unit, and it is precisely the one
the rule cannot name.

**Three documented properties make absence weak evidence here.** Logging is **opt-in per VPC**, and
association is a separate step from creation — so a VPC never associated produces nothing and looks
identical to one just silenced. AWS logs **only unique queries, not cache hits**, so a VPC with a
small stable set of destinations legitimately produces very few records once warm. And
`additional_properties.is_delayed` is a documented delivery-delay flag with no published maximum,
so a gap is never conclusive.

**The common case is disassociation, not deletion.** `DisassociateResolverQueryLogConfig` stops one
VPC while the configuration survives and every other VPC keeps logging — the surgical form, which
an account-wide count is structurally blind to. A rule watching only deletion misses it.

**DNS Firewall is shipped alongside** because removing it is worse in one specific way: the
firewall fields are the only place AWS states a verdict in this log source, so removing the rule
group both stops the blocking and empties the field that would have recorded it. An empty
`firewall_rule_action` afterwards means "no match" — true, and easily read as "allowed".

**MITRE:** Mapped to
`T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log`, verified live 2026-08-30.

**Merge test:** the DNS Firewall rules ship here rather than as a separate use case because they
are the same act against the same telemetry — no separate source rule covers them, so nothing has
been aggregated.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `route53dns.*` playbook is in `../../_ground-truth/route53dns.md`,
audited on 2026-08-30. The caching rule is §1; opt-in association is §2; `is_delayed` is §3; the
control plane is §5.
