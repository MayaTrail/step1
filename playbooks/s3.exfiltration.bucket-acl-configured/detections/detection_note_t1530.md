# Detection Note — T1530 (Data from Cloud Storage)

**Signal:** a `PutBucketAcl` that grants to one of the two predefined groups AWS treats as public —
and the two cases where the event alone cannot tell you.

## The source rule reports the call, not what the call did

`eventName:"PutBucketAcl" AND NOT _exists_:errorCode`, at P3. It fires identically on an ACL set to
`private` and on one granting the world read access. In any estate that manages ACLs this is a
continuous stream, and a continuous P3 is a suppressed P3 — which takes the one call that mattered
with it.

There was no need for it to be content-blind. AWS's definition is two URIs:

> *"Amazon S3 considers a bucket or object ACL public if it grants any permissions to members of the
> predefined `AllUsers` or `AuthenticatedUsers` groups."*

Nothing else in an ACL makes it public, so the check costs one `contains`.

## `AuthenticatedUsers` means any AWS account, not yours

This is the single most common misreading in triage. `AuthenticatedUsers` grants to any principal in
**any** AWS account — anyone who can create an account qualifies. AWS evaluates it as public and it
is public in practice. The shipped rule rates it identically to `AllUsers`, and the KQL gives it its
own verdict line so that a responder reading the alert does not have to remember this.

## Neither the event nor a live read is individually authoritative

**The event may be redacted.** Where another account sets the ACL, AWS removes the grantee detail
from the bucket owner's copy — the record says an ACL was written, not what it granted.
`s3_bucket_acl_opaque_write` covers that shape at low, because the correct verdict is *cannot be
determined from this event*, which is neither clean nor public.

**And the live read may be masked.** AWS: *"suppose that a bucket has an ACL that grants public
access, but the bucket also has the `IgnorePublicAcls` setting enabled. In this case,
`GetBucketAcl` returns an ACL that reflects the access permissions that Amazon S3 is enforcing,
rather than the actual ACL that is associated with the bucket."* A stored public grant can be
invisible to `GetBucketAcl`, and it becomes live the moment the flag moves.

The consequence is that an ACL read must always be paired with a guardrail read. Neither answers the
question alone.

## Response levers

**The successful write proves the gate was down.** `BlockPublicAcls: true` makes S3 reject a
`PutBucketAcl` carrying a public ACL, so a public grant with no `errorCode` establishes the flag was
false at that instant — recoverable from the write itself, with no need for the Block Public Access
history.

**Confirm ACLs are even in use before trusting a clean result.** Object Ownership set to
bucket-owner-enforced disables ACLs entirely and makes `PutBucketAcl` fail.
`get-bucket-ownership-controls` tells you which regime the bucket is in; a clean result on a
bucket-owner-enforced bucket means the feature is off, not that the control is working.

**Resetting the ACL to `private` is the fix, and it is separate from the guardrail.** ACL grants
survive every Block Public Access change — the flags suppress their effect and do not remove them.
`put-bucket-acl --acl private` is what removes the grant.

**Moving the bucket to bucket-owner-enforced removes the technique.** It is the durable fix rather
than a detection: with ACLs disabled, no `PutBucketAcl` can grant anything, and this entire class of
exposure stops being possible on that bucket.

**MITRE:** the source maps this rule to **nothing**. `T1530 — Data from Cloud Storage`, verified
live 2026-08-30.

**GuardDuty:** `Policy:S3/BucketAnonymousAccessGranted` covers an `AllUsers` grant and `Policy:S3/BucketPublicAccessGranted` the broader public-access outcome. `AuthenticatedUsers` and the redacted cross-account shape are where these rules add coverage rather than duplicate it.

**Files here:**
- `sigma_t1530.yml` — four documents: `s3_bucket_acl_public_grant` (high, covering both predefined
  groups and the canned-ACL header form), `s3_bucket_acl_opaque_write` (low, for the redacted
  cross-account shape), `s3_pab_acl_gate_lowered` (informational base rule), and a
  `temporal_ordered` correlation pairing the lowered ACL gate with the grant it would have refused
  (critical).
- `kql_t1530.kql` — separates a public grant from an `AuthenticatedUsers` grant from an undeterminable
  one, and states inline why neither the event nor a live read settles the question alone.

Full response procedure is in `../PLAYBOOK.md`.
