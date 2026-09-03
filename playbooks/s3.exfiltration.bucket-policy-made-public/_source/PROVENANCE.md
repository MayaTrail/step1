# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Bucket Policy Has Been Made Public |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously one of seven folded into
`aws.exfiltration.s3-bucket-public-exposure`.

**The rule's only predicate is a field AWS does not emit.** It matches
`requestParameters.bucketPolicy.bucket_made_public:true`. That path appears in no AWS documentation,
and its shape gives it away — every documented CloudTrail `requestParameters` field for S3 is
camelCase and this one is snake_case. It is platform enrichment. Wherever the enrichment is absent —
raw CloudTrail, a different pipeline, a re-ingest — the rule matches nothing and reports clean. This
is a different failure from a wrong event name: the rule may well work where it was written, and
stop working when moved, with no error either way.

**A boolean also cannot carry AWS's evaluation, which runs backwards from the intuitive one.**
Verbatim: *"When evaluating a bucket policy, Amazon S3 begins by assuming that the policy is public.
It then evaluates the policy to determine whether it qualifies as non-public."* Non-public requires
that access is granted only to **fixed** values of an enumerated set of keys — an AWS principal,
`aws:SourceIp`, `aws:SourceArn`, `aws:SourceVpc`, `aws:SourceVpce`, `aws:SourceOwner`,
`aws:SourceAccount`, `aws:userid`, `s3:DataAccessPointArn`, `s3:DataAccessPointAccount` — and
nothing outside that list counts. So `"Principal": "*"` with a fixed `aws:SourceVpce` is not public,
while the same statement with `"vpc-*"` is.

**The shipped rules are therefore deliberately approximate, and the direction of error is stated.**
`s3_bucket_policy_public_principal` over-matches: it fires on conditioned statements AWS would call
non-public. That is the right direction for a rare control-plane write, and the playbook resolves
every hit with `GetBucketPolicyStatus` — AWS's own evaluator — rather than by reading the policy by
eye. A second rule covers the case a human reviewer is most likely to wave through: a scoping
condition whose value carries a wildcard, which is AWS's own worked public example.

**The most useful thing here is an inference, not a rule.** `BlockPublicPolicy: true` *"causes
Amazon S3 to reject calls to `PutBucketPolicy` if the specified bucket policy allows public
access."* So a public policy write that returned **no error** is evidence that the gate was false at
that instant. The guardrail state at write time is recoverable from the write itself, without the
Block Public Access event history.

**MITRE:** the source maps this rule to **nothing**. `T1530 — Data from Cloud Storage`, verified
live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `s3.*` playbook is in `../../_ground-truth/s3.md`, audited 2026-08-30;
§6 covers the meaning of "public" and is the basis for every claim above.
