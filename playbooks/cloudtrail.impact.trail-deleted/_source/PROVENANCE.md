# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Trail Deleted |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously one of five folded into
`aws.defense-evasion.cloudtrail-logging-tampered`, where it was rated identically to `StopLogging`
despite differing from it in both directions.

**The delivered log files survive, and the source rule gives no reason to think so.** AWS: *"While
deleting a CloudTrail trail is an irreversible action, CloudTrail does not delete log files in the
Amazon S3 bucket for that trail, the Amazon S3 bucket itself, or the CloudWatch log group to which
the trail delivers events."* The historical record is intact and fully searchable. A responder whose
only input is "Trail Deleted, P2" will reasonably assume the history is gone and skip the
reconstruction that is still entirely possible — which is a worse outcome than the deletion itself.

**What is irreversible is the configuration, and it is not in the event.** The `DeleteTrail` request
carries only the trail name. Selectors, destination bucket, KMS key, `isMultiRegionTrail`,
`includeGlobalServiceEvents` and `enableLogFileValidation` exist only in the last `CreateTrail` or
`UpdateTrail` event for that trail — which `lookup-events` serves for 90 days. That window is the
real deadline in this incident, and nothing in the source rule surfaces it.

**Blast radius is `IsMultiRegionTrail`, also not in the event.** *"Deleting a multi-Region trail will
stop logging of events in all AWS Regions enabled in your AWS account. Deleting a single-Region
trail will stop logging of events in that Region only. It will not stop logging of events in other
Regions even if the trails in those other Regions have identical names to the deleted trail."* One
event name, two very different incidents.

**The refused attempt is again the earlier signal, and again discarded.** *"This operation must be
called from the Region in which the trail was created. `DeleteTrail` cannot be called on the shadow
trails."* `NOT _exists_:errorCode` drops the `InvalidHomeRegionException` that an actor guessing the
home Region produces first, and the `NotOrganizationMasterAccountException` that a member account
probing an organization trail produces.

**And the delete-and-replace shape passes every review.** Delete the real trail, create one with the
same name and minimal selectors, and `describe-trails` still returns a trail called what it was
called. A `temporal_ordered` correlation covers it, because no state-based check will.

**MITRE:** `T1685.002 — Disable or
Modify Tools: Disable or Modify Cloud Log` is the live mapping, with `T1070 — Indicator Removal` on
the delete-and-replace correlation. Both verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case. It is kept separate from
`../../cloudtrail.stealth.trail-logging-stopped/` because the response differs materially: a stop is
undone with one call, a deletion requires rebuilding a configuration that only the event history
holds.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `cloudtrail.*` playbook is in `../../_ground-truth/cloudtrail.md`,
audited 2026-08-30.
