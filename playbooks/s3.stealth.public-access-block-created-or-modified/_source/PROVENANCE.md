# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Public Access Block Has Been Created/Modified |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously one of seven folded into
`aws.exfiltration.s3-bucket-public-exposure`.

**The rule cannot fire.** It matches `eventName:"PutPublicAccessBlock"`, which is the SDK operation
name. CloudTrail emits `PutBucketPublicAccessBlock` for a bucket and `PutAccountPublicAccessBlock`
for the account, and AWS documents that *"in some cases, the CloudTrail event name differs from the
API action name"*. What makes this worth recording rather than quietly fixing: a **different rule in
the same source pack** matches `PutBucketPublicAccessBlock` correctly (see
`../../s3.exfiltration.public-access-block-removed/`), while a third matches `DeletePublicAccessBlock`
and also cannot fire. The pack names the same operation two ways across three rules. Neither the
correct nor the incorrect form generalises — every event name has to be checked against AWS's own
list, one at a time.

**`NOT (flag:false)` is not `all four true`.** All four flags are `Required: No`, so a request
carrying only `BlockPublicPolicy: true` satisfies the condition while saying nothing about the other
three, and AWS does not document whether an omitted flag is cleared or preserved. The rule therefore
reports a partial hardening as a hardening, and the resulting configuration is not derivable from
the event. `s3_pab_partial_hardening` is that case, shipped at low.

**And the rule detects a good thing happening.** Enabling a guardrail is not an incident. Rated P4
and routed somewhere, it is change accounting rather than security, and it belongs at informational.
Its one genuine security use is as the **second half of a pair**: a principal who lowered the block,
acted, and then put it back has closed the window behind them, and the restored configuration is
exactly what makes a state-based review show nothing wrong. That correlation is the only document
here above informational, and it is the reason this use case survives decomposition at all rather
than being dropped.

**MITRE:** the source maps this rule to **nothing**. `T1070 — Indicator Removal` for restoring the
expected configuration to conceal that it changed; `T1530` on the weakening half of the pair. Both
verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `s3.*` playbook is in `../../_ground-truth/s3.md`, audited 2026-08-30.
