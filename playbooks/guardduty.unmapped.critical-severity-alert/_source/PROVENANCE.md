# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Critical Severity Alert |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule is one threshold query and is fully readable, so every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**What the pack gets right, recorded as such:** the severity bands. AWS defines Critical as
9.0–10.0, High 7.0–8.9, Medium 4.0–6.9 and Low 1.0–3.9, and all four source rules encode them
exactly. The bands are easy to get wrong and a reviewer should not "fix" them.

**The defect is `NOT _exists_:detail.service.userFeedback`, and it is inverted.** That field records
whether a user marked a finding **useful or not useful** — feedback on GuardDuty's accuracy, not a
decision to stop alerting. So marking a finding **useful**, which means confirming it is a true
positive, removes it from the detection. The real suppression mechanism is a suppression rule with
auto-archive, whose effect is `service.archived`. The corrected rules exclude archived findings,
exclude `[SAMPLE]` findings, and ignore `userFeedback` entirely — projecting it rather than
filtering on it.

**Two fields carrying most of the value are unused by the whole pack.**
`service.resourceRole` distinguishes `TARGET` — something attacked you — from `ACTOR` — something
of yours attacked somebody, which is a compromised host by definition. And `service.count` is the
number of occurrences aggregated into the finding, which is the only measure of how much activity
it represents. Both are shipped as rules here.

**Severity-band rules are one use case in four costumes.** The pack contains Critical, High, Medium
and Low variants of the same query differing only in the numeric range and the window. This
playbook covers the Critical case and the two structural rules above; writing four near-identical
playbooks would be padding rather than coverage, and the differences between the bands are a
routing decision rather than a different response.

**MITRE:** the source maps this rule to nothing. `T1078 — Valid Accounts` is the anchor for the
critical band, whose findings overwhelmingly involve credentials in use, with
`T1526 — Cloud Service Discovery` on the occurrence-count rule. Both verified live 2026-08-30. A
severity-based rule spans many techniques by construction — the finding **type** identifies the
technique for any particular alert, and these are anchors rather than claims about it.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `guardduty.*` playbook is in `../../_ground-truth/guardduty.md`, audited
on 2026-08-30. The severity bands are §1; aggregation and the destruction of older detail are §2;
`userFeedback` versus suppression is §3; the finding shape is §4.
