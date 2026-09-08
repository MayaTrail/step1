# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Access Logging Has Been Disabled |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously one of seven folded into
`aws.exfiltration.s3-bucket-public-exposure`, where it did not belong — this is a defence-evasion
use case with a different tactic, a different technique and a different response, and it was carried
along only because the source rules shared a service.

**The rule's logic is right and its event name is not quite.** It tests
`NOT _exists_ requestParameters.BucketLoggingStatus.LoggingEnabled`, which is exactly AWS's
documented disable: *"To enable logging, you use `LoggingEnabled` and its children request elements.
To disable logging, you use an empty `BucketLoggingStatus` request element."* But it matches
`putbucketlogging` where CloudTrail emits `PutBucketLogging`. Whether that fires depends on the
index mapping rather than on the rule — an exact-match keyword field never matches it, a
lowercase-analysed text field does. A detection whose correctness is a property of someone else's
analyser configuration is not one, so the shipped rule uses the documented casing.

**The larger gap is that disabling is the loud half.** A `PutBucketLogging` that keeps
`LoggingEnabled` and changes `TargetBucket` or `TargetPrefix` ends the flow of records into whatever
anyone queries, while logging still reads as enabled and the source rule sees nothing. AWS constrains
the destination to the same account and Region, so this is not an exfiltration path — it is a way to
make the logs land where nobody is looking. A second rule covers it.

**And there is a delivery path this call does not touch.** Server access logs can now be delivered to
CloudWatch Logs, configured through the CloudWatch Logs APIs rather than through `PutBucketLogging`.
Any rule scoped to this event is blind to a change made there. That gap is stated rather than closed;
it is not closable from S3 CloudTrail events.

**Severity was lowered deliberately, on AWS's own statement.** The source rates this P2 as though an
audit record were lost. AWS: *"Server access log records are delivered on a best-effort basis... The
completeness and timeliness of server logging is not guaranteed... it might not be delivered at
all... server logging is not meant to be a complete accounting of all requests."* CloudTrail data
events are the authoritative record of object access and are unaffected by this call. So the shipped
disable rule is medium, and the sequence — visibility reduced, then the bucket changed — is what
carries a high.

**MITRE:** the source maps this rule to **nothing**. `T1685.002 — Disable or Modify Tools: Disable or
Modify Cloud Log`, verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `s3.*` playbook is in `../../_ground-truth/s3.md`, audited 2026-08-30.
