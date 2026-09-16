# Detection Note — T1078 (Valid Accounts) / T1526 (Cloud Service Discovery)

**Signal:** a GuardDuty finding in the 9.0–10.0 band, a finding naming one of your own resources as
the **actor**, or a finding whose aggregated occurrence count is large.

**A finding is an index entry, not evidence, and AWS says so in the same paragraph that explains
why.** Repeat activity is aggregated into the existing finding rather than creating new ones:

> When a finding is aggregated, it is updated with information from the latest occurrence of that
> activity... **the finding details will be updated to reflect the remote IP of the most recent
> source and older information will be replaced.** Complete information about individual activity
> attempts will still be available in your CloudTrail logs or VPC Flow Logs.

So a brute-force campaign from fifty addresses produces **one** finding naming **one** address —
the most recent. A responder who builds a blocklist from the finding blocks one attacker in fifty
and has no indication the list is short. Everything in this playbook follows from treating the
finding as a pointer and CloudTrail or flow logs as the record.

**What the original rule got wrong** — one filter, and it is backwards.

`NOT _exists_:detail.service.userFeedback` excludes any finding carrying user feedback. That field
records whether someone marked the finding **useful or not useful** — it is feedback on GuardDuty's
accuracy, not a decision to stop alerting. **Marking a finding useful — confirming it is a true
positive — removes it from the detection.** The suppression mechanism is a suppression rule with
auto-archive, and its effect is `service.archived`. The corrected rules exclude archived findings,
exclude `[SAMPLE]` findings, and project `userFeedback` without filtering on it.

**What the pack gets right:** the severity bands. Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9,
Low 1.0–3.9, all encoded exactly. Recorded because they are easy to get wrong and a reviewer should
not reverse them.

## Two fields carry most of the value and the whole pack ignores both

**`service.resourceRole`** is `TARGET` or `ACTOR`. `TARGET` means something attacked your resource.
**`ACTOR` means your resource was the one attacking** — which is a compromised host by definition,
and a materially different incident. An `ACTOR` finding at medium severity outranks a `TARGET`
finding at high, and no severity-based rule can express that.

**`service.count`** is the number of occurrences folded into the finding. It is the only field that
says how much activity a finding represents, and it means that **counting findings measures
distinct security issues per resource** rather than volume of activity. A count in the thousands on
a medium-severity finding is a sustained campaign wearing a moderate label, invisible to every rule
in the source pack.

## Severity-band rules are one use case in four costumes

The pack ships Critical, High, Medium and Low variants of the same query, differing only in the
numeric range and the window. The band is a **routing** decision — who gets paged, how fast — not a
different response, and the response for any particular finding is determined by its **type**. This
playbook covers the critical band plus the two structural rules above; four near-identical
playbooks would be padding rather than coverage, and the honest way to say that is to say it.

One thing the bands do change: AWS defines Low as *"attempted suspicious activity that did not
compromise your environment, for example, a port scan or a failed intrusion attempt"*. That is why
the pack's 24-hour window on the Low rule is defensible where a 5-minute window would not be.

## Response levers

**Go to CloudTrail and flow logs immediately.** That is not a fallback, it is AWS's own
instruction — the finding named the most recent source and discarded the rest, and the complete
record is in the sources GuardDuty read.

**Check whether findings were suppressed at source, not just archived.** A trusted IP list
(`CreateIPSet`) stops findings being **generated** — not archived afterwards, never created. It is
a legitimate feature and an excellent place to hide, and nothing in the finding stream shows it.

**GuardDuty's silence may not be information.** Its DNS findings depend on Route 53 Resolver query
logging for the VPC, and its EKS findings on audit log monitoring being enabled. Where those were
turned off — see `../../route53dns.stealth.no-logs-from-amazon-route53-dns-query/` and
`../../vpc.stealth.no-logs-from-amazon-vpc-flow-logs/` — GuardDuty went quiet for the same reason,
and that quiet is not evidence of anything.

**MITRE:** the source maps this rule to nothing at all. `T1078 — Valid Accounts` anchors the
critical band, whose findings overwhelmingly involve credentials in use, and `T1526 — Cloud Service
Discovery` the occurrence-count rule. Both verified live 2026-08-30. These are anchors: a
severity-based rule spans many techniques, and the finding **type** is what identifies the technique
for any given alert.

**Severity:** critical for the 9.0+ band, high for an `ACTOR` finding above the Low band and for a
large occurrence count. The last two deliberately outrank their own severity bands.

**GuardDuty:** no finding type covers GuardDuty itself being disabled, suspended or having its detector deleted. The service does not report on its own availability, which is the reason a CloudTrail-based rule for it is necessary rather than redundant.

**Files here:**
- `sigma_t1078.yml` — three documents: `guardduty_critical_finding` (critical),
  `guardduty_resource_is_actor` (high — the field the pack never reads), and
  `guardduty_high_occurrence_finding` (high — the field that says how much activity a finding hides).
- `kql_t1078.kql` — findings ranked with the band, the actor role and the aggregated count, with
  `userFeedback` projected rather than filtered and `[SAMPLE]` excluded.

Full response procedure is in `../PLAYBOOK.md`.
