# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Audit Logging Configuration Accessed |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously one of five folded into
`aws.defense-evasion.cloudtrail-logging-tampered`. It never belonged there: the tactic is Discovery,
not Defense Evasion, and the response is to look at what happened next rather than to restore
anything.

**This is the one rule in the pack with a correct, live MITRE mapping.** `T1654 — Log Enumeration`,
Discovery. Its four siblings all map to a revoked parent.

**Its filter on `userIdentity.type:"IAMUser"` excludes almost every modern principal.** SSO users,
federated identities, EC2 instance roles, Lambda execution roles and every cross-account access path
arrive as `AssumedRole`. A compromised role session — the normal shape of a cloud intrusion — reads
the entire logging configuration without this rule firing once. This is the majority case, not an
edge case.

**And it watches the least informative of the read calls.** `DescribeTrails` returns the trail list.
The calls an actor actually needs before tampering are `GetTrailStatus`, which returns `IsLogging`
and, with `DescribeTrails`, the trail's `HomeRegion` — and both `StopLogging` and `DeleteTrail` are
refused outside the home Region and refused entirely on shadow trails, so obtaining it is a
prerequisite. Then `GetEventSelectors`, which returns precisely what is and is not captured. Neither
is matched.

**`FilterLogEvents` is a CloudWatch Logs call, not a CloudTrail one.** Reading log *content* and
reading the logging *configuration* are different acts with different follow-ons — one establishes
what the defender already has, the other establishes how to stop them getting more. Both are `T1654`
and both are covered here, separated so the response can differ.

**The `sourceIPAddress.keyword` regex is a redundant portability dependency.** `.keyword` is an
index-mapping artefact, and the check duplicates the `userIdentity.invokedBy` filter immediately
above it in the same rule — AWS-service-invoked calls set that field. One mapping dependency for no
additional coverage.

**What this directory adds beyond fixing those: the pair.** A read of the logging configuration
followed by tampering, by the same principal, converts a low-value discovery signal into the
earliest reliable warning that a trail is about to be stopped. That correlation is the reason this
use case is worth keeping rather than dropping as noise.

**MITRE:** `T1654 — Log Enumeration` (Discovery), verified live 2026-08-30, with `T1685.002` on the
read-then-tamper correlation.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `cloudtrail.*` playbook is in `../../_ground-truth/cloudtrail.md`,
audited 2026-08-30. §2 covers the home-Region prerequisite that makes these reads worth watching.
