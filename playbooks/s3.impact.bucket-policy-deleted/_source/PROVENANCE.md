# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Bucket Policy Has Been Deleted |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously one of seven folded into
`aws.exfiltration.s3-bucket-public-exposure` — a grouping this rule never fitted, because deleting a
policy cannot make a bucket public.

**The event is directionally ambiguous and the rule ignores that.** `DeleteBucketPolicy` records
that a policy was removed, not what it said. A bucket policy may contain `Allow` statements, `Deny`
statements or both, so removing it can widen access, narrow it, or do both at once. The source rule
reports all three identically at P4. Nothing in the event resolves the direction — only the **last
`PutBucketPolicy` for that bucket** does, and CloudTrail's copy of that event is frequently the only
surviving record of the policy's contents. The shipped KQL joins the two for exactly this reason.

**It does not make a bucket public, and treating it as exposure sends the response the wrong way.**
Public access requires a wildcard `Allow`; deleting a policy removes statements and adds none. A
responder who runs the public-bucket procedure here will find nothing and close the ticket, while
the removed `Deny` statements — transport enforcement, encryption enforcement, VPC-endpoint
restriction, delete protection, all frequently implemented nowhere else — stay removed.

**And unlike its sibling, the success carries no guardrail inference.** A successful public
`PutBucketPolicy` proves `BlockPublicPolicy` was false at that instant, because S3 rejects the call
when the flag is set. `DeleteBucketPolicy` has no such interlock: Block Public Access does not gate
it. The two events sit next to each other in every log and reason completely differently, and a rule
set that treats them as a pair will draw a false conclusion from one of them.

**A self-protecting policy cannot resist this.** Where the policy itself denied `s3:PutBucketPolicy`
to non-administrators, that protection is part of what gets deleted. The KQL flags it, because it
changes who could have made the next change.

**Severity is split on scale rather than content.** One deletion is genuinely ambiguous and ships at
medium. One principal deleting policies across three or more buckets within an hour is not
ambiguous, and that `value_count` correlation is the shape that actually justifies the source use
case's "impact" framing — which its single-event P4 rule did not.

**MITRE:** the source maps this rule to **nothing**. `T1530 — Data from Cloud Storage` for the
widen-access outcome, verified live 2026-08-30. `T1531 — Account Access Removal` is tagged on the
multi-bucket correlation for the availability outcome; it is written for identity accounts rather
than resource policies and is the closest available fit rather than an exact one. `T1685 — Disable
or Modify Tools` was considered and **rejected**: its description scopes it to security tools,
logging agents and telemetry, and a bucket policy is none of those.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `s3.*` playbook is in `../../_ground-truth/s3.md`, audited 2026-08-30.
