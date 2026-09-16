# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Public Access Block Has Been Removed |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously one of seven folded into
`aws.exfiltration.s3-bucket-public-exposure`. Each is now its own directory with its own source
rule. The closest sibling is `../../s3.exfiltration.public-access-block-deleted/`, which covers the
delete-side event — and which is where the two rules diverge sharply in quality.

**This rule's event name is correct, and that is worth recording.** It matches
`PutBucketPublicAccessBlock`, which **is** the CloudTrail event name — the API operation is
`PutPublicAccessBlock`. The delete-side rule in the same pack matches the API name and therefore
cannot fire. The divergence is per-operation, so getting one right implies nothing about the other,
and a reviewer should check each against AWS's own event list rather than generalising from either.

**The defect is that it ORs four flags that are not equivalent.** AWS defines each separately:

- `RestrictPublicBuckets: false` and `IgnorePublicAcls: false` change how an **existing**
  configuration is evaluated — data can be exposed immediately, with no second call.
- `BlockPublicPolicy: false` and `BlockPublicAcls: false` are prospective. AWS states that enabling
  them "doesn't affect existing policies or ACLs", and the inverse holds: disabling them exposes
  nothing on its own, it removes the refusal on the next write.

A single rule reporting all four identically leaves the responder unable to tell whether data is
public now or whether there is still a window. The corrected set splits them by effect and rates
them accordingly.

**Two smaller points.** All four flags are `Required: No`, so a request may carry any subset — a
rule requiring a flag to be present and false misses one that omits it, and the resulting state is
not derivable from a partial event. And the account-level setting is the floor: AWS applies "the
most restrictive combination", so a bucket-level flag set false has no effect while the account
block holds it true, which makes every finding here conditional on the account state.

**MITRE:** the source maps this rule to **nothing**. `T1530 — Data from Cloud Storage`, verified
live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `s3.*` playbook is in `../../_ground-truth/s3.md`, audited on
2026-08-30. The event-name divergence is §1; scope interaction is §2; per-flag semantics are §3.
