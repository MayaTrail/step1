# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Bucket ACL Has Been Configured |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously one of seven folded into
`aws.exfiltration.s3-bucket-public-exposure`.

**The rule has no content check at all.** `eventName:"PutBucketAcl" AND NOT _exists_:errorCode`,
rated P3. It fires identically on an ACL set to `private` and on one granting the world read
access. This is not a subtle defect: it is a rule that reports the *occurrence* of a call and says
nothing about what the call did, in a stream that in any ACL-managing estate is continuous. A
continuous P3 is a suppressed P3, and it takes the one call that mattered with it.

**AWS's definition of a public ACL is narrow and exact, so the check is cheap.** Verbatim: *"Amazon
S3 considers a bucket or object ACL public if it grants any permissions to members of the predefined
`AllUsers` or `AuthenticatedUsers` groups."* Two URIs. Nothing else in an ACL makes it public, which
is why the shipped rule can be specific rather than heuristic — there is no reason for the original
to have been content-blind.

**`AuthenticatedUsers` is not what its name suggests.** It means any principal in **any** AWS
account, not any principal in yours. AWS evaluates a grant to it as public, and it is public in
practice, because anyone who can create an AWS account qualifies. It ships at the same severity as
`AllUsers` and is called out separately in the detection note, because the name invites exactly the
wrong conclusion during triage.

**The event is not always readable, and that is a third verdict.** Where the ACL is set by another
account, AWS redacts the grantee detail from the bucket owner's copy of the event: the record says
an ACL was written, not what it granted. `s3_bucket_acl_opaque_write` ships at low for that shape,
because the honest answer is *cannot be determined from this event* — which is neither "clean" nor
"public", and which a rule matching every `PutBucketAcl` collapses into the same P3 as everything
else.

**And reading the ACL back does not settle it either.** Verbatim: *"suppose that a bucket has an ACL
that grants public access, but the bucket also has the `IgnorePublicAcls` setting enabled. In this
case, `GetBucketAcl` returns an ACL that reflects the access permissions that Amazon S3 is
enforcing, rather than the actual ACL that is associated with the bucket."* A public grant can be
stored and invisible to a live read, and it becomes live the moment `IgnorePublicAcls` is turned
off. Every ACL read in the playbook is paired with a guardrail read for that reason.

**MITRE:** the source maps this rule to **nothing**. `T1530 — Data from Cloud Storage`, verified
live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 2 of `07-TIERS.md` — *the response has ordering that can go wrong*.

Service ground truth for every `s3.*` playbook is in `../../_ground-truth/s3.md`, audited 2026-08-30;
§6 covers the meaning of "public" and the `GetBucketAcl` effective-permissions behaviour.
