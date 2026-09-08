# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Public Access Block Has Been Deleted |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** This use case was previously one of seven folded into a
single `aws.exfiltration.s3-bucket-public-exposure` playbook. Each of the seven is now its own
directory with its own source rule, per the one-source-rule-one-use-case standard. The other six are
`../../s3.stealth.public-access-block-created-or-modified/`,
`../../s3.stealth.access-logging-disabled/`, `../../s3.exfiltration.public-access-block-removed/`,
`../../s3.exfiltration.bucket-policy-made-public/`, `../../s3.exfiltration.bucket-acl-configured/` and
`../../s3.impact.bucket-policy-deleted/`.

**The defect is that the rule cannot fire.** It matches `eventName: "DeletePublicAccessBlock"`,
which is the **SDK operation name**. AWS states that "in some cases, the CloudTrail event name
differs from the API action name" and lists the bucket-level event as
**`DeleteBucketPublicAccessBlock`**. The string the rule matches never appears in a CloudTrail
record for a bucket, so it reports clean in every account, permanently. Verified against the S3
CloudTrail events page on 2026-08-30.

**Two gaps beyond the event name.** Account-level Block Public Access emits
`DeleteAccountPublicAccessBlock` and is not covered by any rule in the pack — yet AWS applies "the
most restrictive combination of the bucket-level and account-level settings", so removing the
account block weakens every bucket at once. And the deletion alone exposes nothing: the block gates
what a policy or ACL may do, so the exposure requires a second act, and the correlation over the
pair is the incident.

**MITRE:** the source maps this rule to **nothing**. `T1530 — Data from Cloud Storage` is the
objective, with `T1098 — Account Manipulation` on the correlation where a grant follows. Both
verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `s3.*` playbook is in `../../_ground-truth/s3.md`, audited on
2026-08-30. The event-name divergence is §1; account versus bucket scope is §2; what each flag does
and does not do is §3; management versus data events is §4.
