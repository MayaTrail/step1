# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The CloudTrail logging-integrity alerts — three trail-mutation alerts, one absence-of-telemetry alert, one logging-configuration-read alert |
| Retrieved | 2026-08-28 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Source MITRE label |
|-------|----------|--------------------|
| Trail Modified | P3 | — |
| Trail Logging Stopped | P2 | — |
| Trail Deleted | P2 | — |
| No Logs From AWS CloudTrail | P1 | — |
| Audit Logging Configuration Accessed | P3 | T1654/TA0007 |

Writing it verbatim here would ship a stale citation into a corpus
whose currency gate (`tools/attack_currency_check.py`) exists specifically to catch that.
What the substitution costs is four digits; what it preserves is everything a reviewer
needs — the label was the *parent* technique with no sub-technique, it redirects to
**T1685** (*Disable or Modify Tools*), and the precise mapping for all four is
**T1685.002** (*Disable or Modify Tools: Disable or Modify Cloud Log*).

The tactic IDs are verbatim because they still resolve. Note that the same restructure
**renamed TA0005 from "Defense Evasion" to "Stealth"**, and moved this behaviour to
**Defense Impairment (TA0112)** — so the source label is wrong on the tactic as well as
stale on the technique, and in a way that is invisible if you only check that the ID
loads. TA0007 (Discovery) on the fifth alert is unaffected.

The first extraction pass ran against a broader name filter and matched 60 alerts in the
same pack. Fifty-five were dropped. The five retained are the ones whose subject is the
integrity of CloudTrail itself.

## What was excluded, and why

| Excluded | Count | Reason |
|----------|-------|--------|
| Alerts about *other* logging surfaces — VPC flow-log deletion, GuardDuty detector disable/delete, WAF ACL and rule deletion | 4 | Same MITRE parent, different service, different containment and different recovery path. Each belongs with the service it degrades, not here. They are genuinely T1685-family and worth a playbook; they are not this playbook |
| Identity and credential alerts — root usage, console login without MFA, access-key creation, federation-token volume, key-compromise quarantine, Identity Center IdP change | 11 | Different tactic entirely. Present in the extract only because the pack name contains the string the filter matched |
| Enumeration / volume building blocks — multi-service enumeration, error-rate anomalies, distinct-API counts, region-count anomalies, CLI-agent fingerprinting | 14 | Discovery-tactic behavioural rules with no CloudTrail-configuration subject |
| Service-specific alerts carried in the same pack — SSM parameter and document rules, ECS/EKS rules, S3 browser user-agent, EIP transfer, internet-gateway operations, SCP modification, AMI made public, `LeaveOrganization` | 26 | Unrelated subjects |

`errorMessage` is optional on a
CloudTrail error record while `errorCode` is not, so that filter admits denied calls as
successes. Neither alert is in scope here; both are reported upward.

## De-identification

**No source, vendor, product, repository or package is named in any file in this project
— including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the
originals are packaged in a proprietary format whose scaffolding identifies the source on
sight while bearing on nothing about whether the rules are correct. What is retained is
the complete detection logic — name, priority, type, MITRE label, the query verbatim,
threshold, window and group-by. Every claim in the "Detection Rule Quality Notes" table
in `../PLAYBOOK.md` §2 is checkable against it.

One further substitution was applied after extraction. The `No Logs From AWS CloudTrail`
alert groups by a **platform metadata field** — the identifier of the log stream the
platform ingests into, not an AWS field. The shared extractor strips one product field
prefix by shape but not this one, so the field name was replaced with
`<log-stream-identifier>`. Nothing about the rule's logic changed: it groups by log
stream, and that is what the placeholder says. The substitution is recorded here so a
reviewer diffing the extract against the original can account for the one line that
differs.

`bash ../../tools/scrub_check.sh .` passes on this directory.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS
documentation only — a deployed rule travels outside the organisation that wrote it, and
an internal path is not resolvable to whoever receives it.

## One structural note on the source set

`No Logs From AWS CloudTrail` is the only alert in the entire pack that detects an
**absence**, and for this technique absence is the evidence. It is the right idea and
this playbook keeps it. The extract records its threshold (`1.0`) and window (`2h`) but
**not the comparison operator**, because the extractor emits the threshold value without
the direction of the test. The alert is a below-threshold test by construction — an
above-threshold reading of "1 log in 2 hours" would fire constantly — but the operator is
not recoverable from the extract, and that limitation is stated rather than assumed. The
defects that matter for this alert are its window and its grouping key, both of which are
auditable from the extract as it stands.
