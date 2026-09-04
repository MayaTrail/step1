# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority; all seven are of the platform's *immediate* type — a query with no threshold, no window and no group-by |
| Scope captured | The seven S3 alerts covering public access block, bucket policy, bucket ACL and access logging |
| Retrieved | 2026-08-27 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | MITRE | Fires on |
|-------|----------|-------|----------|
| Public Access Block Has Been Deleted | P3 | none | `eventName:"DeletePublicAccessBlock"` — an event name CloudTrail does not emit |
| Public Access Block Has Been Created/Modified | P4 | none | `eventName:"PutPublicAccessBlock"` — also not emitted — AND **none** of the four settings false, i.e. the hardening direction |
| Access Logging Has Been Disabled | P2 | none | `eventName:"putbucketlogging"` (lowercased) with no `BucketLoggingStatus.LoggingEnabled` |
| Public Access Block Has Been Removed | P2 | none | `PutBucketPublicAccessBlock` with any of the four settings false. No `eventSource`, no `errorCode` filter |
| Bucket Policy Has Been Made Public | P2 | none | `requestParameters.bucketPolicy.bucket_made_public:true` — not a field CloudTrail writes. No `eventSource`, no `errorCode` filter |
| Bucket ACL Has Been Configured | P3 | none | Every successful `PutBucketAcl`, with no grantee inspection |
| Bucket Policy Has Been Deleted | P4 | none | Every successful `DeleteBucketPolicy` |

All seven carry **no ATT&CK mapping at all** — not an imprecise one, none. The `mitre:`
line in the extract records that as a fact rather than leaving it to be inferred from the
extractor's silence.

The three public-access-block alerts are the exposure signal this technique corrects, and
they are the reason the technique is scoped to all three mechanisms rather than to
`PutBucketPolicy` alone: Block Public Access overrides both a public policy and a public
ACL, so its removal is the event that converts a latent misconfiguration into a live
exposure — with no policy or ACL event in that window. The set rates that event P3 and P4.

`Bucket Policy Has Been Deleted` is retained although deleting a bucket policy usually
*reduces* access: a policy carrying an explicit `Deny` is the control keeping a bucket
private, and its deletion is unrecoverable because bucket policies are not versioned. It
is analysed, and kept at `medium` rather than promoted, in `../PLAYBOOK.md` §2.

`Access Logging Has Been Disabled` is in scope because server access logs are one of only
three places a read of a public object can be recorded, and the only one that records
anonymous reads with their source IP. Disabling it before opening a bucket is what makes
"was it used" permanently unanswerable.

## Extraction

`original_rules.yml` is produced by the kit's shared extractor, not by hand:

```bash
SOURCE_PACKS=<path-to-source-packages> \
  python3 tools/deid_extract.py <PackDir> "Public Access Block" "Bucket Policy" "Bucket ACL" "Access Logging" \
  > techniques/aws.exfiltration.s3-bucket-public-exposure/_source/original_rules.yml
```

The extractor emitted name, priority, type, query, threshold, window and group-by, but not
the ATT&CK mapping. For this technique the mapping's **absence** is itself a finding
reported in §6 of the playbook, and a claim about a field the extract does not carry is
not auditable — a reader could not tell "the source rule has no mapping" from "the
extractor dropped it". The extractor was corrected to emit a `mitre:` line for every
alert, `none` where the source carries no mapping. The change is additive: every other
field is unchanged, and previously shipped extracts differ only by the gained line.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project
— including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately. The originals are packaged in a proprietary format whose
scaffolding — payload field lists, entity labels, product-specific field prefixes,
internal enums and packaging metadata — identifies the source on sight while bearing on
nothing about whether the rules are correct. What is retained is the complete detection
logic: name, priority, type, the Lucene query verbatim, threshold, window, group-by and
the ATT&CK mapping. Every claim in the "Detection Rule Quality Notes" table in
`../PLAYBOOK.md` §2 is checkable against it — including the whitespace defect in the
second alert's query, which is preserved as submitted.

The shipped `references:` blocks in `detections/` cite public MITRE and AWS documentation
only — a deployed rule travels outside the organisation that wrote it, and an internal
path is not resolvable to whoever receives it.
