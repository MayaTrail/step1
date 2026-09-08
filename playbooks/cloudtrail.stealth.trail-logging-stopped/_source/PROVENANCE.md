# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Trail Logging Stopped |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously one of five folded into
`aws.defense-evasion.cloudtrail-logging-tampered`. The five were genuinely five use cases: stopping
a trail, deleting one, narrowing one's selectors, the absence of delivered logs, and *reading* the
logging configuration. They share a service and nothing else — the last has a different tactic
entirely, and the fourth is a deadman's switch rather than an event rule.

**The rule filters on success and throws away the better signal.** `NOT _exists_:errorCode` drops
every failed `StopLogging`. AWS: *"For a trail enabled in all Regions, this operation must be called
from the Region in which the trail was created, or an `InvalidHomeRegionException` will occur. This
operation cannot be called on the shadow trails."* An actor who does not already know the home
Region therefore fails first, and that failure is higher fidelity than the success (no automation
calls `StopLogging` in the wrong Region), earlier than the success (it happens before logging
stops), and entirely invisible to the shipped source rule. `NotOrganizationMasterAccountException`
is the same story for a member account probing an organization trail.

**And it is rated P2, one level below its own downstream symptom.** The same pack rates "No Logs From
AWS CloudTrail" at P1. That is the consequence; this is the cause, and it arrives first. AWS on the
operation: *"Under most circumstances, there is no need to use this action. You can update a trail
without stopping it first. This action is the only way to stop recording."* There is no benign
reconfiguration reading, because AWS says a trail can be updated while running. Shipped at critical.

**Whether logging actually stopped is not in the event.** *"Users in member accounts will not have
sufficient permissions to delete organization trails, turn logging on or off, change what types of
events are logged, or otherwise alter organization trails in any way."* Where a management-account
organization trail covers this account, a member-account `StopLogging` cannot succeed against it.
Where one does not, the account may have gone dark. The playbook resolves this against the trail
inventory rather than assuming either.

**MITRE:** `T1685.002 — Disable or
Modify Tools: Disable or Modify Cloud Log` is the live mapping, with `T1070 — Indicator Removal` on
the stop-then-start correlation. Both verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `cloudtrail.*` playbook is in `../../_ground-truth/cloudtrail.md`,
audited 2026-08-30. §1 and §2 cover this operation's semantics and its error codes.
