# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule, `less_than` condition |
| Scope captured | One alerting rule: No Logs From AWS ALB |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule is one threshold query — `_exists_:"elb"`, fewer than one record in two hours,
grouped by nothing — so every row of the `Issue | Impact | Correction` table in `../PLAYBOOK.md`
§2 is auditable against the artifact.

**Four properties of this telemetry, each documented by AWS, make an absence rule unusable here —
more so than for any other log source in this project.** The `group_by` is empty, so one load
balancer going dark among several never moves the total. AWS states the logs are best-effort and
explicitly recommends against using them *"as a complete accounting of all requests"*. Access
logging is **disabled by default**, so a load balancer that never logged looks identical to one
just silenced. And an idle ALB writes nothing at all — there is no equivalent of the VPC flow log
`NODATA` record — so silence is the ordinary state of an unused load balancer.

The corrected set moves the detection to `ModifyLoadBalancerAttributes`, adds a coverage rule on
`CreateLoadBalancer` because the default is off, and covers the destination-tampering path where
the attribute still reads enabled and nothing lands.

**MITRE:** Mapped to `T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log`, verified live
2026-08-30.

**Merge test:** not applicable — one source rule, one use case. Same shape as
`../../waf.stealth.no-logs-from-aws-waf/` and `../../vpc.stealth.no-logs-from-amazon-vpc-flow-logs/`,
deliberately, because the argument is the same and the three should not diverge.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `alb.*` playbook is in `../../_ground-truth/alb.md`, audited on
2026-08-30. The best-effort statement is §1; default-off and delivery are §2; the control plane is
§9.
