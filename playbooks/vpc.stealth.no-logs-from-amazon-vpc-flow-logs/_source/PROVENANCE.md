# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule, `less_than` condition, no query body |
| Scope captured | One alerting rule: No Logs From Amazon VPC Flow Logs |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule carries no query body — it is a count of all records from the integration, fewer
than one in two hours, grouped by nothing. That is fully readable, and every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against it.

**The defect that matters most is the empty `group_by`.** The rule counts every flow record in the
account, so deleting one VPC's subscription in an account with several changes the total by a
fraction and the rule never fires. The blind spot is proportional to how much else is still
logging, which makes the rule weakest in exactly the estates with the most to lose.

Three more follow from the platform rather than from the rule's author: `NODATA` is itself a
record, so record presence is not evidence of observation; `SKIPDATA` means AWS dropped records it
had, so partial loss looks perfectly healthy to a count; and delivery is *"on a best effort
basis"* with published typicals but no maximum, so a gap is never conclusive in either direction.

**The quiet case the rule cannot reach at all** is a format downgrade. A subscription's format
cannot be edited — AWS: *"you can't change its configuration or the flow log record format...
Instead, you can delete the flow log and create a new one"* — so delete-then-recreate is both
ordinary maintenance and the way a custom format silently becomes the version 2 default. Records
keep arriving at the same rate, the absence rule stays quiet, and every detection reading
`tcp-flags`, `pkt-srcaddr`, `pkt-dstaddr` or `flow-direction` goes blind at once. That is why the
shipped set reads the *format* in `CreateFlowLogs` rather than counting anything.

**MITRE:** Mapped to **`T1685.002` — Disable or Modify Tools: Disable or Modify Cloud Log** (Defense
Impairment, TA0112), verified live 2026-08-30, which is the correct replacement and describes this
exactly.

**Merge test:** not applicable — one source rule, one use case. This follows the same shape as
`../../waf.stealth.no-logs-from-aws-waf/` — the control-plane cause in Sigma, the absence view as a
corroborator — because the argument is identical and the two should not diverge.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `vpc.*` playbook is in `../../_ground-truth/vpc.md`, audited on
2026-08-30. `log-status` values are §5; timing and delivery are §6; field versions and the
immutable format are §2; where the control plane lives is §11.
