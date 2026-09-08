# Detection Note — T1685.002 (Disable or Modify Tools: Disable or Modify Cloud Log)

**Signal:** `PutBucketLogging` that ends the flow of server access log records — either by turning
logging off, or by pointing it somewhere nobody reads.

## The rule's logic is right; its casing and its scope are not

The source tests `NOT _exists_ requestParameters.BucketLoggingStatus.LoggingEnabled`, which is
precisely AWS's documented disable: *"To enable logging, you use `LoggingEnabled` and its children
request elements. To disable logging, you use an empty `BucketLoggingStatus` request element."*

Two problems sit on top of correct logic:

**It matches `putbucketlogging`.** CloudTrail emits `PutBucketLogging`. Whether the rule fires is
then a property of the index mapping — a keyword field never matches, a lowercase-analysed text
field does. A detection whose correctness depends on someone else's analyser is not a detection.

**Disabling is the loud half.** A `PutBucketLogging` that keeps `LoggingEnabled` and changes
`TargetBucket` or `TargetPrefix` silences the pipeline just as completely, still reads as enabled,
and is invisible to a rule testing only for absence. AWS constrains the destination to the same
account and Region, so this is not exfiltration — it is making the logs land where nobody looks.
The redirect rule covers it, and needs the account's real log destinations populated to work.

## Why this ships at medium, not high

AWS is explicit that these logs are not an audit record:

> *"Server access log records are delivered on a best-effort basis... The completeness and
> timeliness of server logging is not guaranteed. The log record for a particular request might be
> delivered long after the request was actually processed, or it might not be delivered at all...
> server logging is not meant to be a complete accounting of all requests."*

CloudTrail data events are the authoritative record of object access, and `PutBucketLogging` does
not touch them. So this is a visibility reduction, not the destruction of evidence. What makes it
matter is the **order**: a principal that reduces visibility on a bucket and then rewrites its
policy is doing something the two events separately do not show. That sequence is the high, and it
is why the correlation exists rather than a higher base severity.

## Response levers

**Log arrival proves nothing, in either direction.** AWS: *"Changes to the logging status of a
bucket take time to actually affect the delivery of log files... if you enable logging for a
bucket, some requests made in the following hour might be logged, and others might not."* Records
keep arriving for roughly an hour after a disable and resume slowly after a re-enable. Confirm both
the incident and the recovery from `get-bucket-logging`, never from whether logs are showing up.

**The CloudWatch Logs delivery path is invisible here.** Server access logs can be delivered to
CloudWatch Logs, configured through the CloudWatch Logs APIs rather than through
`PutBucketLogging`. A change made there produces no S3 event and no rule in this directory will see
it. Stated rather than closed — it is not closable from S3 CloudTrail events.

**Restore from configuration, and preserve the old destination first.** If this was a redirect, the
records it produced exist — in the attacker's chosen bucket, in the same account, and they are the
only copy of what the source bucket served during the window. Copy them before overwriting the
configuration; `PutBucketLogging` does not merge, and the previous destination is not recoverable
from the new configuration.

**Fall back to CloudTrail data events, not to the access logs.** They are unaffected by this call
and they are authoritative. Whether they cover the bucket decides whether the dark window is
genuinely dark, and that is the first thing to establish.

**Restricting `s3:PutBucketLogging` is cheap.** It belongs to infrastructure automation and nothing
else, so an SCP denying it outside the provisioning path costs nothing operationally and removes the
technique from every compromised application role at once.

**MITRE:** the source maps this rule to **nothing**. `T1685.002 — Disable or Modify Tools: Disable
or Modify Cloud Log`, verified live 2026-08-30.

**GuardDuty:** `Stealth:S3/ServerAccessLoggingDisabled` covers the disable case directly, from CloudTrail management events. It does **not** cover the redirect — a `PutBucketLogging` that keeps `LoggingEnabled` and changes the target reads as logging still enabled — so that half is this directory's own contribution rather than a duplicate.

**Files here:**
- `sigma_t1685_002.yml` — four documents: `s3_access_logging_disabled` (medium),
  `s3_access_logging_redirected` (medium), `s3_bucket_open_write` (informational base rule), and a
  `temporal_ordered` correlation for visibility-reduced-then-bucket-changed (high).
- `kql_t1685_002.kql` — separates the disable from the redirect, and rates on whether the logging
  change came *before* the bucket change rather than on the logging change alone.

Full response procedure is in `../PLAYBOOK.md`.
