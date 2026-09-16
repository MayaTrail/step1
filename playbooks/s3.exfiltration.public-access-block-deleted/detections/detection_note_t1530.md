# Detection Note — T1530 (Data from Cloud Storage)

**Signal:** `DeleteBucketPublicAccessBlock` — the guardrail that refuses a public policy or a public
ACL removed from a bucket.

**The rule this replaces cannot fire.** It matches `DeletePublicAccessBlock`, which is the **SDK
operation name**. AWS states that "in some cases, the CloudTrail event name differs from the API
action name" and lists the bucket-level event as `DeleteBucketPublicAccessBlock`. The string the
rule looks for never appears in a CloudTrail record for a bucket — so it reports clean in every
account, permanently. This is not casing and not tuning; the value does not occur.

It is worth stating the inverse too, because the same pack gets it right elsewhere: a sibling rule
matching `PutBucketPublicAccessBlock` **is** correct. The divergence is per-operation and has to be
checked per-operation, not assumed either way.

**What else the original rule missed**

*Account scope is a different event with a larger blast radius.* Account-level Block Public Access
emits `DeleteAccountPublicAccessBlock`, and AWS evaluates the two scopes together: *"If the
`PublicAccessBlock` configurations are different between the bucket and the account, Amazon S3 uses
the most restrictive combination."* So the account block is what holds the line for every bucket
whose own configuration is weaker or absent, and removing it weakens all of them at once. No
bucket-scoped rule sees it. It ships here at critical.

*Removing the block exposes nothing on its own.* Block Public Access is a gate on what a policy or
ACL is **allowed** to say — it is not itself an access control. The exposure needs a second act, so
the deletion is the precondition and the ordered correlation over it is the incident. Shipping only
the deletion produces an alert with no blast radius; shipping only the exposure misses the window
in between.

## Re-enabling the block is not remediation

Three of the four flags are prospective only, and AWS says so for each:

- `BlockPublicAcls` — *"Enabling this setting doesn't affect existing policies or ACLs."*
- `BlockPublicPolicy` — *"Enabling this setting doesn't affect existing bucket policies."*
- `IgnorePublicAcls` — *"doesn't affect the persistence of any existing ACLs and doesn't prevent new
  public ACLs from being set."*

Only `IgnorePublicAcls` and `RestrictPublicBuckets` change how an **existing** configuration is
evaluated. A responder who re-enables the block and stops may have left a public policy in force and
believe the bucket is closed. The containment in the playbook therefore reads the policy and the ACL
after re-enabling, not instead of it.

All four flags are `Required: No`, so a request may carry any subset — a rule requiring all four to
be present matches fewer events than it should.

## Response levers

**The read is invisible without preparation.** Object-level operations are **data events, off by
default and billable**. `lookup-events` returns zero for them regardless of whether they happened,
so "was the exposed data actually accessed" is unanswerable unless a data-event trail existed
beforehand. Treat the exposure window as full disclosure rather than looking for evidence that
cannot exist.

**A cross-account ACL is redacted in the owner's trail.** AWS: the bucket owner *"doesn't get the ACL
configuration information, specifically the grantee email address and the grant"*. So for the case
that matters most — somebody else granting themselves access — the owner's trail records that a
call happened and not what it did. `get-bucket-acl` on the live bucket is the answer.

**AWS Config records `AWS::S3::Bucket`** including policy and public-access-block state, and is the
only source of what the configuration looked like before the trail window.

**MITRE:** the source maps this rule to **nothing**. `T1530 — Data from Cloud Storage` names the
objective; `T1098 — Account Manipulation` is carried on the correlation, where a grant follows the
guardrail removal. Both verified live 2026-08-30.

**Severity:** high for a bucket-level deletion, critical for account-level and for the ordered pair.
The account case outranks the bucket case deliberately — it is one event affecting everything.

**GuardDuty:** `Policy:S3/BucketBlockPublicAccessDisabled` covers this act at bucket scope and `Policy:S3/AccountBlockPublicAccessDisabled` at account scope. Neither pairs the removal with the policy or ACL write that follows, which is what the correlation here adds.

**Files here:**
- `sigma_t1530.yml` — four documents: `s3_bucket_pab_deleted` (high), `s3_account_pab_deleted`
  (critical), `s3_bucket_exposure_write` (informational base rule) and a `temporal_ordered`
  correlation pairing removal with exposure (critical).
- `kql_t1530.kql` — per principal per hour, with bucket and account scope separated and the
  Block Public Access flags projected as submitted.

Full response procedure is in `../PLAYBOOK.md`.
