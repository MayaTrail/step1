# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Trail Modified |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously one of five folded into
`aws.defense-evasion.cloudtrail-logging-tampered`.

**This is the stealthiest of the three tampering techniques and the pack rates it lowest.** Stopping
a trail sets `IsLogging` false. Deleting one removes it from `describe-trails`. Modifying one leaves
it present, logging, and reporting healthy in every summary view — while capturing less, delivering
somewhere else, or delivering under a key nobody can read. The pack rates Stop and Delete P2, and
this P3.

**It only matches `UpdateTrail`, which is not how coverage is narrowed.** Event selectors are set by
a separate call — `PutEventSelectors`, or `PutInsightSelectors` for Insights. An actor who removes
every data-event selector reduces coverage substantially without ever calling `UpdateTrail`, and
this rule never fires. Selectors are also **replaced wholesale rather than merged**, so one call
does it.

**And `UpdateTrail` itself has four distinct abuses that the rule does not separate:**

| Change | Effect |
|---|---|
| `isMultiRegionTrail` → false | Every Region but the home Region stops being covered, in one call |
| `includeGlobalServiceEvents` → false | IAM, STS and CloudFront become invisible — they are recorded in `us-east-1` and delivered only to trails that include them |
| `s3BucketName` changed | The trail keeps logging, to a bucket nobody queries |
| `kmsKeyId` changed | Logs are delivered intact and are undecryptable without the new key |

An `UpdateTrail` that *enables* log file validation is reported identically to one that turns global
service events off. A rule with no content check on a call this configurable is an occurrence
counter rather than a detection.

**The rule also matches `eventSource.keyword`.** That suffix is an index-mapping artefact, not part
of the CloudTrail record. Its sibling rules in the same pack match plain `eventSource`, so the pack
writes the same field two ways across five rules and this one only works against one particular
mapping — the same portability failure as an enrichment-only field, in a different disguise.

**MITRE:** `T1685.002 — Disable or
Modify Tools: Disable or Modify Cloud Log`, verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case. It is kept separate from the stop
and delete atoms because the response differs entirely: there is nothing to restart or recreate, and
the work is a field-by-field comparison against the previous configuration.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `cloudtrail.*` playbook is in `../../_ground-truth/cloudtrail.md`,
audited 2026-08-30. §4 covers global service event delivery and §5 the four event types.
