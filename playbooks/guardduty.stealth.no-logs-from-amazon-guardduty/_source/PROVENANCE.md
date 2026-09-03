# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule, `less_than` condition |
| Scope captured | One alerting rule: No Logs From Amazon GuardDuty |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule is `detail.service.serviceName:guardduty` counted over 36 hours with a `less_than`
condition, so every row of the `Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is
auditable against the artifact.

**The rule alerts when the account is secure.** GuardDuty emits a finding when it *detects*
something; an account with nothing wrong emits none, for days, correctly. AWS defines even the
lowest band as *"attempted suspicious activity that did not compromise your environment"* — which
happens to internet-facing estates and not to quiet internal ones.

This is a stronger objection than the usual "absence is ambiguous" that applies to the other
no-logs rules in this project. Those detect a real gap and cannot attribute it. This one's firing
condition **is the desired state**, and no window length fixes it — lengthening the window makes the
rule slower without making it right. A team running it learns the GuardDuty alert means nothing,
which is the state they are in on the day the detector is actually turned off.

**So no absence view is shipped here at all**, which is a deliberate departure from every other
`*.stealth.no-logs-*` playbook in this corpus. The signal is the act, in CloudTrail, plus a state
read of the detector.

**Three ways to go blind, and the quietest is a documented feature.** Deleting or disabling the
detector is loud. A suppression rule auto-archives matching findings, so the console shows a healthy
detector while the suppressed class reaches nobody. And a **trusted IP list** stops findings for
those addresses being **generated at all** — not archived, never created — which no finding-stream
monitoring can reveal. All three are shipped at high.

A fourth path is not a GuardDuty action at all: its DNS findings depend on Route 53 Resolver query
logging and its EKS findings on audit log monitoring, so disabling those blinds GuardDuty without
touching it. Covered in the corresponding playbooks and cross-referenced rather than duplicated.

**MITRE:** Mapped to
`T1685 — Disable or Modify Tools`, verified live
2026-08-30. Note the sub-technique choice: `.001` is for disabling a security **tool** and `.002`
for a **log**. GuardDuty is a tool, so the other `*.stealth.no-logs-*` playbooks in this corpus use
`.002` and this one does not.

**Merge test:** the suppression-rule and trusted-IP-list rules ship here rather than separately
because they are the same act — removing detection — by quieter routes. No separate source rule
covers either.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `guardduty.*` playbook is in `../../_ground-truth/guardduty.md`, audited
on 2026-08-30. The severity bands and what a Low finding means are §1; the control plane and the
trusted-IP-list behaviour are §6; the upstream dependencies are §5.
