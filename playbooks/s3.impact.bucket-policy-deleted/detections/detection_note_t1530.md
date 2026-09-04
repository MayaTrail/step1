# Detection Note — T1530 (Data from Cloud Storage)

**Signal:** a bucket policy removed — with the direction of the change not recoverable from the
event that reports it.

## The event says a policy went away, not what it said

A bucket policy may contain `Allow` statements, `Deny` statements or both. So `DeleteBucketPolicy`
can widen access, narrow it, or do both at once, and the source rule reports all three identically
at P4.

The only thing that resolves the direction is the **last `PutBucketPolicy` for that bucket**, whose
CloudTrail record carries the full document — and which is frequently the only surviving copy of the
policy at all. The shipped KQL joins deletions to the most recent preceding write for exactly this
reason, and reports `UNKNOWN` rather than `clean` when no such write exists inside the lookback.

## It does not make a bucket public

Public access requires a wildcard `Allow`. Deleting a policy removes statements and adds none.

This matters because the wrong reflex is expensive: a responder who reads "bucket policy deleted" as
an exposure runs the public-bucket procedure, finds the bucket is not public, and closes the ticket
— while the removed `Deny` statements stay removed. Those are usually the transport enforcement,
encryption enforcement, VPC-endpoint restriction and delete protection, and they are usually
implemented nowhere else.

The exposure case here is the **pair**: a deletion followed by a public write. That ships as its own
correlation rather than being implied by the deletion.

## Unlike its sibling, the success proves nothing about the guardrail

A successful public `PutBucketPolicy` establishes that `BlockPublicPolicy` was false at that instant,
because S3 rejects the call when the flag is set. `DeleteBucketPolicy` has no such interlock — Block
Public Access does not gate it, because removing a policy cannot make a bucket public.

The two events sit next to each other in every log and reason in opposite directions. A rule set
that treats them as a matched pair will draw a false conclusion from one of them.

## Response levers

**Recover the policy text before anything else.** `aws cloudtrail lookup-events` on
`PutBucketPolicy` for that bucket is the recovery path, and it is time-limited: `lookup-events`
serves 90 days, after which the trail's S3 objects are the only source, subject to their own
lifecycle. Restoring the bucket's controls is not possible without it.

**Check what the removed policy protected, not who it granted.** The `Deny` statements are the part
nobody has a copy of. An `Allow` is usually reproducible from the IaC definition; a `Deny` added by
hand after an audit finding often is not.

**Expect an availability report, and connect it.** If the removed policy was the only grant a
partner account held, that partner is now failing. It will arrive as an unrelated ticket.

**A self-protecting policy could not resist this.** Where the policy denied `s3:PutBucketPolicy` to
non-administrators, that protection was deleted along with it — so the set of principals who could
have made the *next* change is larger than it was before, and larger than an IAM review will show.

**Scale is the reliable signal.** One deletion is ambiguous. Three across different buckets by one
principal in an hour is not, and that is the case worth waking someone for.

**MITRE:** the source maps this rule to **nothing**. `T1530 — Data from Cloud Storage` for the
widen-access outcome, verified live 2026-08-30. `T1531 — Account Access Removal` is tagged on the
multi-bucket correlation for the availability outcome, as the closest available fit rather than an
exact one — it is written for identity accounts, not resource policies. `T1685 — Disable or Modify
Tools` was considered and rejected: its description scopes it to security tools, logging agents and
telemetry, and a bucket policy is none of those.

**GuardDuty:** no finding type covers bucket policy deletion. `Impact:S3/AnomalousBehavior.Permission` is adjacent but is driven by S3 **data** events, which are off by default, so it does not fire on a management-plane policy delete.

**Files here:**
- `sigma_t1530.yml` — four documents: `s3_bucket_policy_deleted` (medium, deliberately not higher
  because a lone deletion is ambiguous), a `value_count` correlation for three or more buckets by
  one principal in an hour (critical), a `temporal_ordered` correlation for deletion followed by a
  public write (high), and `s3_bucket_public_write` as the informational base rule.
- `kql_t1530.kql` — joins each deletion to the last preceding `PutBucketPolicy` to recover the
  direction of the change, and reports `UNKNOWN` rather than clean when the policy predates the
  lookback.

Full response procedure is in `../PLAYBOOK.md`.
