# Detection Note — T1530 (Data from Cloud Storage)

**Signal:** a `PutBucketPolicy` that grants to a wildcard principal — and the fact that it
succeeded, which is itself evidence about the guardrail.

## The source rule's only predicate is a field AWS does not emit

It matches `requestParameters.bucketPolicy.bucket_made_public:true`. That path appears in no AWS
documentation, and its shape gives it away — every documented CloudTrail `requestParameters` field
for S3 is camelCase, this one is snake_case. It is platform enrichment.

This fails differently from a wrong event name. A wrong event name never works anywhere. This rule
may work perfectly where it was authored and silently stop working when the pipeline changes, with
no error and no gap in the dashboard. A rule whose only predicate is a field its own data source
does not produce is not portable and is not auditable.

## AWS's evaluation runs backwards from the intuitive one

> *"When evaluating a bucket policy, Amazon S3 begins by assuming that the policy is public. It then
> evaluates the policy to determine whether it qualifies as non-public."*

Non-public requires granting access only to **fixed** values of an enumerated set of keys: an AWS
principal, `aws:SourceIp`, `aws:SourceArn`, `aws:SourceVpc`, `aws:SourceVpce`, `aws:SourceOwner`,
`aws:SourceAccount`, `aws:userid` (outside `AROLEID:*`), `s3:DataAccessPointArn`,
`s3:DataAccessPointAccount`. Nothing outside that list counts — a condition on
`aws:PrincipalTag/team`, for instance, leaves a wildcard-principal policy public.

Two consequences the rules encode:

- Matching `"Principal": "*"` **over-matches**, because a fixed scoping condition makes it
  non-public. The rule accepts that and the playbook resolves each hit with
  `GetBucketPolicyStatus`.
- A scoping condition whose value carries a wildcard **re-publicises** the statement. AWS's own
  example: `"StringLike": {"aws:SourceVpc": "vpc-*"}` is public;
  `"StringEquals": {"aws:SourceVpc": "vpc-91237329"}` is not. This is the shape that survives human
  review, because the reviewer sees a condition and stops reading. It ships as its own rule.

## Response levers

**`GetBucketPolicyStatus` is the arbiter, not the statement text.** It is AWS's own evaluator and
it is the only thing that reproduces the rules above correctly. Reading the policy by eye is how
conditioned-but-public statements get closed as false positives.

**The successful write proves the gate was down.** `BlockPublicPolicy: true` *"causes Amazon S3 to
reject calls to `PutBucketPolicy` if the specified bucket policy allows public access."* A public
write with no `errorCode` therefore establishes that the flag was false at that instant, with no
need for the Block Public Access history. If no corresponding gate-lowering event exists in the
window, the gate was already down before it — a longer-standing problem than the alert implies.

**Expect containment to break a partner, and expect it to be reported as unrelated.** AWS: one
public statement *"renders the entire policy public, so `RestrictPublicBuckets` applies. As a
result, Amazon S3 disables cross-account access, even though the policy delegates access to a
specific account."* Restoring the guardrail on a policy that also delegates to a partner account
stops that partner working. Removing the public statement — not just restoring the flag — is what
brings them back.

**Restoring Block Public Access does not remove the statement.** It suppresses the effect. The
policy still carries the public grant, it survives every audit that reads only the guardrail, and it
becomes live again the moment the flag moves.

**MITRE:** the source maps this rule to **nothing**. `T1530 — Data from Cloud Storage`, verified
live 2026-08-30.

**GuardDuty:** `Policy:S3/BucketAnonymousAccessGranted` covers the outcome. Complementary rather
than redundant — GuardDuty reports that the bucket became anonymously accessible; these rules catch
the write, the conditioned variant GuardDuty may evaluate differently, and the pairing with the gate.

**Files here:**
- `sigma_t1530.yml` — four documents: `s3_bucket_policy_public_principal` (high),
  `s3_bucket_policy_wildcard_condition` (medium), `s3_pab_gate_lowered` (informational base rule),
  and a `temporal_ordered` correlation pairing the lowered gate with the write it would have
  refused (critical).
- `kql_t1530.kql` — separates a genuinely public write from a scoped one and from one re-publicised
  by a `StringLike`, and infers the guardrail state at write time from the write's success.

Full response procedure is in `../PLAYBOOK.md`.
