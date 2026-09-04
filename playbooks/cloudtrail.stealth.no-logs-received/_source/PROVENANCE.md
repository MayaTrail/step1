# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule (`threshold: 1.0`, `window: 2h`) grouped by a platform metadata field |
| Scope captured | One alerting rule: No Logs From AWS CloudTrail |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project. The
`group_by` value in the extract is a platform metadata field and has been replaced with a
placeholder; the original identified the ingestion product.

**Decomposed from an aggregated playbook.** Previously one of five folded into
`aws.defense-evasion.cloudtrail-logging-tampered`.

**It detects the symptom and rates it above every cause.** P1 here, against P2 for the trail being
stopped, P2 for deleted and P3 for modified. The causes arrive first and are actionable; the silence
arrives up to two hours later and says only that something happened somewhere. A responder paged by
this has less information than one paged by any of the other four rules in the same pack.

**It is also not a detection rule, and cannot be.** Sigma — and every event-driven rule engine —
evaluates when an event arrives. When no event arrives, nothing evaluates. A heartbeat has to be a
**scheduled** check, and this directory ships one as a specification in `../PLAYBOOK.md` §1 rather
than pretending a rule can do it. That distinction matters because an absence rule authored inside a
rule engine reports clean forever, which is indistinguishable from working.

**Its `group_by` is the ingestion pipeline's own stream identifier, not a trail.** So it detects
"this stream went quiet", which conflates a stopped trail with a broken collector, an expired
credential, a network fault and a genuinely dormant account. Those have entirely different responses
and the benign ones are far more common — which is how a P1 becomes an ignored P1.

**What this directory adds instead: the silent causes no CloudTrail rule covers.** Stopping,
deleting and modifying a trail are CloudTrail API calls, covered by the three sibling atoms. But
delivery also fails, with `IsLogging` still true, when something changes **outside** CloudTrail —
the destination bucket's policy stops allowing `cloudtrail.amazonaws.com` to write, the bucket is
deleted, a lifecycle rule expires the objects, or the KMS key is disabled or scheduled for deletion.
Each is an ordinary S3 or KMS event, each produces exactly the silence this rule waits two hours to
notice, and no CloudTrail-scoped rule set sees any of them.

Note that the bucket-deletion case is the **only** one in this whole set that destroys the
historical record: AWS is explicit that deleting a trail leaves the bucket and its log files intact.

**MITRE:** `T1685.002 — Disable or
Modify Tools: Disable or Modify Cloud Log`, verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case. It is kept separate from the three
tampering atoms because its causes are in different services entirely.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `cloudtrail.*` playbook is in `../../_ground-truth/cloudtrail.md`,
audited 2026-08-30.
