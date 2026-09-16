# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule, `less_than` condition, no query body |
| Scope captured | One alerting rule: No Logs From AWS Network Firewall in 4 Hours |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule counts records, fewer than one in four hours, grouped by nothing — so every row of
the `Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**This service has a legitimate, permanent reason to produce no logs, and the source rule cannot
tell it from an incident.** AWS: *"Firewall logging is only available for traffic that you forward
to the stateful rules engine."* A policy whose stateless default action is `aws:drop` or `aws:pass`
rather than `aws:forward_to_sfe` produces no alert log and no flow log — correctly, and forever. An
absence rule fires on that configuration continuously, which is how a team arrives at ignoring it.
That is a stronger objection than the usual "absence is ambiguous": here the false positive is a
property of a valid configuration rather than a transient condition.

**And the API records what survives, not what was removed.** Logging is a configuration *on* the
firewall, not a separate resource, so there is no delete verb. `UpdateLoggingConfiguration`
**replaces** the whole configuration: removing one log type and removing all of them are the same
call, and the request carries the **remaining** destinations. A rule matching "the alert type was
removed" matches nothing, because the removed type is exactly what the event does not contain. The
shipped rules match on the configuration becoming empty, and route the partial case to a state
comparison instead — which is a read, not a log match.

**The `group_by` is empty**, so one firewall going dark among several barely moves an account-wide
count. Firewalls are per-endpoint resources; the firewall is the unit and it is the one the rule
cannot name.

**A third path is covered that the source rule does not consider at all:** changing the firewall
policy so stateless defaults no longer forward to the stateful engine. It achieves the same result
as disabling logging, leaves every dashboard showing logging enabled, and removes the inspection as
well as the record.

**MITRE:** Mapped to
`T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log`, verified live 2026-08-30.

**Merge test:** the firewall-policy rule ships here rather than as a separate use case because it is
the same act — removing the record — by another route. No separate source rule covers it, so
nothing has been aggregated.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `netfw.*` playbook is in `../../_ground-truth/netfw.md`, audited on
2026-08-30. The stateless-engine limitation is §1; which actions produce logs is §2; the control
plane and the replace-not-delete semantics are §7.
