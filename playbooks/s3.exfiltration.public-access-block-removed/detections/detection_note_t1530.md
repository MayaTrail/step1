# Detection Note — T1530 (Data from Cloud Storage)

**Signal:** `PutBucketPublicAccessBlock` submitting a flag set to `false` — and which flag decides
whether data is exposed now or whether a window remains.

**The four flags are not interchangeable, and the source rule ORs them as if they were.** AWS
defines each one separately, and the split that matters is immediate versus prospective:

| Flag set to `false` | Effect |
|---|---|
| `RestrictPublicBuckets` | An existing public policy becomes **effective again**. Immediate. |
| `IgnorePublicAcls` | Existing public ACLs **take effect again**. Immediate. |
| `BlockPublicPolicy` | S3 will now **accept** a public policy on the next write. Prospective. |
| `BlockPublicAcls` | S3 will now **accept** a public ACL on the next write. Prospective. |

So two of them can expose data with no further call, and two only remove a refusal. A rule that
reports all four identically leaves a responder unable to tell which situation they are in — and
those situations have different urgency and different first actions.

**What the original rule got right, and it is worth saying:** the event name.
`PutBucketPublicAccessBlock` **is** the CloudTrail event; the API operation is
`PutPublicAccessBlock`. Its delete-side sibling in the same pack matches the API name and cannot
fire — see `../../s3.exfiltration.public-access-block-deleted/`. The divergence is per-operation,
so a reviewer must check each against AWS's list rather than generalising from either.

## Two things that make an event here non-authoritative

**A partial request does not describe the resulting state.** All four flags are `Required: No`, so a
request may carry any subset, and AWS does not document whether omitted flags are cleared or
preserved. The KQL surfaces `MinFlags` for that reason: below four means the resulting configuration
is not derivable from the event, and only `get-public-access-block` gives it.

**The account setting is the floor.** AWS: *"If the `PublicAccessBlock` configurations are different
between the bucket and the account, Amazon S3 uses the most restrictive combination."* A bucket-level
flag set false has **no effect at all** while the account block holds that flag true. Every finding
here is therefore conditional on the account state, which is why the playbook's sweep reads the
account before the buckets. The corollary is the account-scope rule, at critical: lowering the floor
lets every bucket fall to its own configuration in one call, under an event name no bucket rule
matches.

## Response levers

**`get-bucket-policy-status` is AWS's own verdict** on whether a bucket policy is public, and it is
more reliable than reading statements by eye. Nothing in the event carries it — the immediate-effect
flags matter only if a public configuration already exists, and this is how you find out.

**Restoring the flag is not the whole fix.** If `RestrictPublicBuckets` was lowered and a public
policy was already attached, setting the flag back to true suppresses the policy's effect but leaves
the policy in place — one call away from being effective again. The playbook's containment reads and
rewrites the policy rather than relying on the gate.

**The read is invisible without preparation.** Object operations are data events, off by default and
billable, and cannot be enabled retroactively. Treat the exposure window as full disclosure rather
than searching for read records that do not exist.

**MITRE:** the source maps this rule to **nothing**. `T1530 — Data from Cloud Storage` names the
objective. Verified live 2026-08-30.

**Severity:** high for an immediate-effect flag, medium for a prospective one, critical for
account scope and for a lowered gate followed by a write. The gap between high and medium is
precisely the distinction the source rule collapses.

**GuardDuty:** `Policy:S3/BucketBlockPublicAccessDisabled` covers the bucket-scope act and `Policy:S3/AccountBlockPublicAccessDisabled` the account-scope one; `Policy:S3/BucketAnonymousAccessGranted` and `Policy:S3/BucketPublicAccessGranted` cover the outcome. Complementary rather than redundant — GuardDuty reports that a block was disabled; these rules say which flag, and therefore whether data is exposed now or a window remains.

**Files here:**
- `sigma_t1530.yml` — five documents: `s3_pab_weakened_immediate` (high),
  `s3_pab_weakened_prospective` (medium), `s3_account_pab_weakened` (critical),
  `s3_bucket_open_write` (informational base rule) and a `temporal_ordered` correlation pairing a
  lowered gate with the write it would have refused (critical).
- `kql_t1530.kql` — flags separated by effect, with `MinFlags` marking a partial request and the
  account-floor caveat stated inline.

Full response procedure is in `../PLAYBOOK.md`.
