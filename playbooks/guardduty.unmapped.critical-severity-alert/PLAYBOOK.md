# IR Playbook: GuardDuty Critical Finding — what a `severity` 8.0+ finding is, and what it is not

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Detection triage (a managed threat detection service reported a resource may already be compromised) |
| Threat Actor | N/A — finding-driven, not actor-attributed |
| Platform | aws |
| Severity | Critical for the 9.0–10.0 band. AWS: *"a critical severity level indicates that an attack sequence may be in progress or had recently happened. One or more AWS resources... are potentially being compromised or may have already been compromised."* |
| MITRE Tactics | Persistence, Privilege Escalation |
| MITRE Techniques | T1078 |
| Services in Scope | GuardDuty, CloudTrail, VPC (flow logs), Route 53 Resolver, IAM, EC2, S3, EKS |

**What the technique does:** this playbook is a triage frame rather than one attack. A critical
finding covers credential compromise, ransomware-adjacent behaviour, cryptomining and attack
sequences — the finding **type** identifies the technique, and the response follows from that. What
is common to all of them is a misunderstanding worth correcting once: **a GuardDuty finding is an
index entry, and the evidence is somewhere else.**

**Why the usual reflexes miss it.** The first reflex is to read the finding as the record of what
happened. It is not — GuardDuty aggregates repeat activity into the existing finding and *"the
finding details will be updated to reflect the remote IP of the most recent source and older
information will be replaced"*. A campaign from fifty addresses shows one. The second reflex is to
count findings, which measures distinct security issues per resource and not activity;
`service.count` is the field carrying the latter. The third is to treat GuardDuty's silence as
reassurance, which fails whenever one of its upstream data sources was disabled.

**Detection thesis:** alert on the band, but route on two fields the source pack never reads —
`service.resourceRole`, which says whether your resource was the attacker, and `service.count`,
which says how much activity a single finding is hiding.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **GuardDuty enabled in every Region, with all protection plans the estate warrants**, and
  delegated administration configured so member accounts cannot silently disable it.
- **GuardDuty findings delivered to EventBridge and retained**, because the console shows current
  state and this playbook needs history — aggregation overwrites the finding in place.
- **CloudTrail and VPC Flow Logs retained for at least as long as GuardDuty findings.** AWS names
  them as where the complete record lives, and a finding pointing at a window you no longer have is
  a pointer to nothing.
- **An inventory of suppression rules and trusted IP lists**, reviewed. A trusted IP list stops
  findings being generated at all, which no finding-stream monitoring can reveal.

**Alerting (must be pre-configured)**
- **A finding with `severity` ≥ 9.0, not archived, not `[SAMPLE]` → P0**
- **A finding with `service.resourceRole: ACTOR` above the Low band → P0**
- **A finding with `service.count` ≥ 500 → P1**
- **`CreateIPSet` / `UpdateIPSet`, or `CreateFilter` with an archive action → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- The remediation runbook per finding **family** — credential compromise, instance compromise, S3
  exposure, cryptomining. The band tells you how fast; the type tells you what to do.

**Known IOC Baselines**
- Your own scanners and penetration testers, by resource and address, so an `ACTOR` finding that is
  yours is recognisable in seconds.
- Which upstream sources GuardDuty depends on in this estate, so its silence can be interpreted.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `detail.severity` ≥ 9.0, `service.archived` false, type not `[SAMPLE]` | GuardDuty via EventBridge | T1078 |
| P0 | `service.resourceRole: ACTOR` with `severity` ≥ 4.0 — your resource is the one attacking | GuardDuty via EventBridge | T1078 |
| P1 | `service.count` ≥ 500 on a single finding | GuardDuty via EventBridge | T1526 |
| P1 | `CreateIPSet` / `UpdateIPSet`, or `CreateFilter` / `UpdateFilter` with an archive action | CloudTrail (`guardduty`) | T1685 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A finding whose `updatedAt` is more than seven days after its `createdAt` — the activity has not stopped | GuardDuty via EventBridge | T1078 |
| P2 | `UpdateDetector` disabling the detector or one of its features | CloudTrail (`guardduty`) | T1685 |
| P3 | A finding carrying `userFeedback` — projected for context, never used to suppress | GuardDuty via EventBridge | — |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `NOT _exists_:detail.service.userFeedback` | The field records whether a user marked the finding **useful or not useful**. So marking a finding **useful** — confirming it is a true positive — removes it from the detection. Feedback is not suppression | Exclude `service.archived`, which is what a suppression rule actually sets. Project `userFeedback` and never filter on it |
| No exclusion of sample findings | AWS prefixes generated samples with `[SAMPLE]` and fills them with fictitious detail. A console demonstration produces a P1 critical alert | Exclude `detail.type` beginning `[SAMPLE]` |
| `service.resourceRole` never read | `TARGET` means something attacked you; `ACTOR` means your resource attacked somebody, which is a compromised host by definition. An ACTOR finding at medium severity outranks a TARGET finding at high, and no severity rule can express that | A dedicated rule at high on `ACTOR` above the Low band |
| `service.count` never read | GuardDuty aggregates repeats into one finding, so counting findings measures distinct issues per resource and not activity. A count in the thousands on a medium finding is a sustained campaign wearing a moderate label | A dedicated rule on the occurrence count, independent of severity |
| Four near-identical rules for four bands | The band is a routing decision, not a different response — the response is determined by the finding **type**. Maintaining four copies of one query multiplies the cost of every correction, including this one | One playbook covering the critical band and the two structural rules. The band belongs in the routing configuration |
| Severity ranges | **Correct.** AWS defines Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 1.0–3.9 and the pack encodes them exactly | No change. Documented so a reviewer does not "fix" them |

**Recommended detection — the band, plus the two fields that outrank it.**

```yaml
# Critical-severity GuardDuty finding (T1078 / T1526)
#
# A GUARDDUTY FINDING IS AN INDEX ENTRY, NOT EVIDENCE, AND AWS SAYS SO. Findings are aggregated:
# "If GuardDuty detects a new activity related to the same security issue, then instead of creating
# a new finding, GuardDuty will update the original finding with the latest details."
#
# And the sentence that decides how every one of these must be read:
#   "the finding details will be updated to reflect the remote IP of the most recent source and
#    OLDER INFORMATION WILL BE REPLACED. Complete information about individual activity attempts
#    will still be available in your CloudTrail logs or VPC Flow Logs."
#
# So a brute-force campaign from fifty addresses produces ONE finding naming ONE address — the last
# one. A responder who builds a blocklist from the finding blocks one attacker in fifty and believes
# the list is complete. detail.service.count carries how many occurrences were folded in; the
# finding count does not. Every rule here treats the finding as a pointer and CloudTrail or VPC Flow
# Logs as the record, which is AWS's own instruction.
#
# THE userFeedback EXCLUSION IS INVERTED AND IT IS THE DEFECT WORTH FIXING. The source rules filter
# out findings carrying detail.service.userFeedback. That field records whether a user marked the
# finding USEFUL or NOT USEFUL — it is feedback on GuardDuty's accuracy, not a decision to stop
# alerting. So marking a finding USEFUL, which means confirming it is a true positive, silences it.
# The suppression mechanism is a suppression rule with auto-archive, whose effect is
# service.archived. The rules below exclude archived findings and ignore userFeedback entirely.
#
# SEVERITY BANDS ARE CORRECT IN THE SOURCE PACK AND ARE PRESERVED. AWS: Critical 9.0-10.0,
# High 7.0-8.9, Medium 4.0-6.9, Low 1.0-3.9. Recorded because they are easy to get wrong and a
# reviewer should not "fix" them.
#
# SAMPLE FINDINGS ARE PREFIXED [SAMPLE] and carry fictitious detail. A rule that does not exclude
# them fires on a console demonstration.
title: GuardDuty critical-severity finding
id: 7d15a03e-64c2-4b98-a70f-53e816bc9204
name: guardduty_critical_finding
status: experimental
description: >-
  A finding in the 9.0-10.0 band. AWS: "a critical severity level indicates that an attack sequence
  may be in progress or had recently happened. One or more AWS resources... are potentially being
  compromised or may have already been compromised." Archived findings are excluded because
  archiving is the deliberate suppression mechanism; userFeedback is NOT used as an exclusion,
  because marking a finding useful would otherwise silence it. Sample findings are excluded by the
  [SAMPLE] prefix AWS applies to their type.
references:
  - https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html
  - https://docs.aws.amazon.com/guardduty/latest/ug/finding-aggregation.html
  - https://attack.mitre.org/techniques/T1078/
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1078
logsource:
  product: aws
  service: guardduty
detection:
  finding:
    detail.service.serviceName: 'guardduty'
  critical:
    detail.severity|gte: 9.0
  archived:
    detail.service.archived: true
  sample:
    detail.type|startswith: '[SAMPLE]'
  condition: finding and critical and not archived and not sample
falsepositives:
  - >-
    Authorised penetration testing, which produces genuine findings from genuine activity. The
    correct handling is a suppression rule scoped to the tester's addresses and the engagement
    window, not a permanently muted detection.
level: critical
---
title: GuardDuty finding naming one of your own resources as the actor
id: 2a90c847-3fb1-4e56-9d02-71c4805ea3b6
name: guardduty_resource_is_actor
status: experimental
description: >-
  A finding whose service.resourceRole is ACTOR — meaning the resource in your account was the one
  performing the activity, not the one it was aimed at. This is the single most useful field in a
  GuardDuty finding and no rule in the source pack reads it. TARGET means something attacked you;
  ACTOR means something of yours attacked someone, which is a compromised host by definition and a
  materially different incident. Shipped at high across all severities above Low, because an ACTOR
  finding at medium severity outranks a TARGET finding at high.
references:
  - https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-summary.html
  - https://attack.mitre.org/techniques/T1078/
tags:
  - attack.persistence
  - attack.t1078
logsource:
  product: aws
  service: guardduty
detection:
  finding:
    detail.service.serviceName: 'guardduty'
  actor:
    detail.service.resourceRole: 'ACTOR'
  above_low:
    detail.severity|gte: 4.0
  archived:
    detail.service.archived: true
  sample:
    detail.type|startswith: '[SAMPLE]'
  condition: finding and actor and above_low and not archived and not sample
falsepositives:
  - >-
    Security scanning tools you run yourself, which are genuinely the actor. Nameable by resource
    and worth an explicit suppression rule rather than a filter in the detection.
level: high
---
title: GuardDuty finding representing a large number of aggregated occurrences
id: c463e781-05da-42bf-8916-b0e7259cf34d
name: guardduty_high_occurrence_finding
status: experimental
description: >-
  A finding whose service.count is large. Because GuardDuty aggregates repeat activity into one
  finding rather than creating new ones, the count is the only field that says how much activity
  the finding represents — and a rule that counts FINDINGS undercounts activity by whatever this
  number is. A count in the thousands on a medium-severity finding is a sustained campaign wearing
  a moderate label, and it is invisible to any severity-based rule. Shipped at high for that reason:
  the volume is the signal, not the severity.
references:
  - https://docs.aws.amazon.com/guardduty/latest/ug/finding-aggregation.html
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: guardduty
detection:
  finding:
    detail.service.serviceName: 'guardduty'
  many_occurrences:
    detail.service.count|gte: 500
  archived:
    detail.service.archived: true
  sample:
    detail.type|startswith: '[SAMPLE]'
  condition: finding and many_occurrences and not archived and not sample
falsepositives:
  - >-
    Internet background scanning against a public endpoint, which accumulates a large count on a
    low-severity finding legitimately. Pair the count with a severity floor when tuning, and note
    that the count keeps rising on the same finding ID rather than producing new ones.
level: high
```

What this set structurally cannot do: it cannot tell you who all the attackers were, because
aggregation replaced the earlier ones. It cannot tell you how much activity occurred beyond
`service.count`. And it cannot show findings that were never generated — a trusted IP list
suppresses at source, and Query 2 is the only place that surfaces.

---

### Key Investigation Queries

> Queries 1 and 2 read the GuardDuty API. Query 3 reads CloudTrail — which is where AWS says the
> complete record lives. Extraction uses `--output json | jq`. GuardDuty is regional: run the state
> queries in every Region.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: the finding, and how much it is hiding

```bash
REGION="us-east-1"
FINDING_ID="<finding-id>"
DETECTOR=$(aws guardduty list-detectors --region "$REGION" --output text --query 'DetectorIds[0]')

aws guardduty get-findings --detector-id "$DETECTOR" --finding-ids "$FINDING_ID" \
  --region "$REGION" --output json | jq -r '.Findings[] | {
    id: .Id, type: .Type, severity: .Severity,
    created: .CreatedAt, updated: .UpdatedAt,
    occurrences: .Service.Count,
    resourceRole: .Service.ResourceRole,
    actionType: .Service.Action.ActionType,
    archived: .Service.Archived,
    userFeedback: (.Service.UserFeedback // "none"),
    resourceType: .Resource.ResourceType,
    resource: (.Resource.InstanceDetails.InstanceId
               // .Resource.AccessKeyDetails.UserName
               // .Resource.S3BucketDetails[0].Name
               // "see full record"),
    mostRecentRemoteIp: (.Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4
                         // .Service.Action.AwsApiCallAction.RemoteIpDetails.IpAddressV4
                         // "n/a")
  }'
```

`occurrences` is the number of events folded into this one finding. `mostRecentRemoteIp` is named
that deliberately: AWS replaces the earlier ones, so it is **one address out of however many
`occurrences` implies**. If `occurrences` is 4,000 and you have one IP, you have one IP.
`resourceRole` of `ACTOR` changes the incident from "we were attacked" to "we are attacking", and
should change who is woken.

#### Query 2 — Sweep: is GuardDuty seeing everything it should

```bash
REGION="us-east-1"
DETECTOR=$(aws guardduty list-detectors --region "$REGION" --output text --query 'DetectorIds[0]')

if [ -z "$DETECTOR" ] || [ "$DETECTOR" = "None" ]; then
  echo "[FAIL] no GuardDuty detector in $REGION — nothing is being detected here at all"
else
  aws guardduty get-detector --detector-id "$DETECTOR" --region "$REGION" --output json | \
    jq -r '"[i] status=\(.Status)  findingPublishingFrequency=\(.FindingPublishingFrequency)"'

  echo
  echo "== suppression rules: findings archived automatically =="
  for F in $(aws guardduty list-filters --detector-id "$DETECTOR" --region "$REGION" \
             --output json | jq -r '.FilterNames[]'); do
    aws guardduty get-filter --detector-id "$DETECTOR" --filter-name "$F" --region "$REGION" \
      --output json | jq -r '"\(.Name)\taction=\(.Action)\trank=\(.Rank)\tcriteria=\(.FindingCriteria | tostring | .[0:200])"'
  done

  echo
  echo "== trusted IP lists: findings NEVER GENERATED for these addresses =="
  aws guardduty list-ip-sets --detector-id "$DETECTOR" --region "$REGION" --output json | \
    jq -r '.IpSetIds[]' | while read -r S; do
      aws guardduty get-ip-set --detector-id "$DETECTOR" --ip-set-id "$S" --region "$REGION" \
        --output json | jq -r '"\(.Name)\tstatus=\(.Status)\tlocation=\(.Location)"'
    done
  echo "[!] A trusted IP list suppresses findings AT SOURCE — they are never created, never"
  echo "    archived, and never appear in any finding-stream monitoring. It is a legitimate"
  echo "    feature and the best available place to hide. Read the list contents, not just its name."
fi
```

#### Query 3 — Inspect: the record AWS says the finding does not contain

```bash
REGION="us-east-1"
PRINCIPAL="<access-key-or-user-from-Query-1>"
SINCE="<createdAt-from-Query-1>"

echo "== the complete activity, which the finding aggregated away =="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$PRINCIPAL" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     arn: .userIdentity.arn, ip: .sourceIPAddress,
     error: (.errorCode // "SUCCESS")}' | \
  jq -s 'group_by(.ip) | map({ip: .[0].ip, calls: length,
                              first: (map(.time) | min), last: (map(.time) | max),
                              events: (map(.event) | unique)})'
```

This is the step the finding exists to send you to. AWS: *"Complete information about individual
activity attempts will still be available in your CloudTrail logs or VPC Flow Logs."* The grouping
by source address is the point — it produces the **full** list the finding reduced to one entry, and
it is the list a blocklist should be built from.

For network-based findings the equivalent is a VPC flow log query over the same window and the same
resource, which `../vpc.lateral-movement.incoming-requests-over-remote-service-ports-accepted-from/`
covers in detail.

#### Query 4 — Full session reconstruction, and whether detection was tampered with

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in UpdateDetector DeleteDetector CreateFilter UpdateFilter CreateIPSet UpdateIPSet \
          ArchiveFindings UpdateMemberDetectors DisassociateFromMasterAccount; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress,
       params: (.requestParameters | tostring | .[0:300])}'
done | jq -s 'sort_by(.time)'
```

Any of these shortly before the finding's `createdAt` is a different and more serious incident: the
detection was being shaped before the activity. `CreateIPSet` and `CreateFilter` with an archive
action are the two that silently reduce what you will ever see.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**The response is determined by the finding type, not by this playbook.** What is standardised here
is the frame: establish which side you are on, size what the finding is hiding, and go to the real
evidence before acting on the finding's own details.

> Run every command under the **break-glass responder credentials** from §1.

#### Step 1 — Establish which side of the finding you are on

```bash
ROLE="<resourceRole-from-Query-1>"
TYPE="<type-from-Query-1>"
COUNT="<occurrences-from-Query-1>"

case "$ROLE" in
  ACTOR)
    echo "[FAIL] Your resource is the ACTOR — something in this account is attacking."
    echo "       This is a compromised host or credential by definition. Contain the RESOURCE,"
    echo "       not the remote address, and treat the severity band as a floor." ;;
  TARGET)
    echo "[i] Your resource is the TARGET. Containment is about the resource's exposure and the"
    echo "    attacker's access, and the remote address in the finding is ONE of possibly many." ;;
  *)
    echo "[!] resourceRole is '$ROLE' — read the full finding record before acting." ;;
esac
echo "[i] type=$TYPE  occurrences=$COUNT"
[ "${COUNT:-0}" -gt 100 ] && echo "[!] $COUNT occurrences aggregated into this ONE finding. The remote address shown is the MOST RECENT only — Query 3 has the full list."
```

#### Step 2 — Build the actor list from CloudTrail, not from the finding

Run Query 3. Its output grouped by source address is what a blocklist, a WAF rule or a network ACL
should be built from. Using the finding's own `RemoteIpDetails` gives you the last attacker and
none of the others, and nothing in the finding indicates how many are missing — `service.count` is
the only hint, and it counts occurrences rather than sources.

#### Step 3 — Contain per the finding family

For a credential finding — the `UnauthorizedAccess:IAMUser/*` family — revoke sessions and disable
keys as in `../ec2.credential-access.imds-credential-theft/` §3, which covers the case where
there is no IAM object behind the credential. For an instance finding, isolate with a quarantine
security group as in `../vpc.initial-access.possible-ssrf-attempt-hit-to-169254169254/` §3. For an
S3 finding, see `../_superseded/aws.exfiltration.s3-bucket-public-exposure/`. Those procedures are not restated
here; this playbook's job is to get you to the right one with the right scope.

#### Step 4 — Do not archive the finding as part of containment

Archiving is how findings are suppressed, and a finding archived during an incident stops being
re-notified when the activity resumes. Leave it open until the incident is closed, and record the
suppression decision separately from the containment decision.

---

## 4. Eradication

### Remove Attacker Access

#### Work the full actor list

Everything in Query 3's grouped output, not the one address the finding named. This is the single
most common gap in a GuardDuty-driven response and it is a direct consequence of documented
aggregation behaviour.

#### Audit the suppression surface

Query 2's filters and trusted IP lists are a standing control that reduces what GuardDuty will ever
report. Confirm every entry has an owner and a reason. A trusted IP list added shortly before an
incident is not a tuning decision.

#### Confirm GuardDuty's inputs are intact

Its DNS findings depend on Route 53 Resolver query logging for the VPC and its EKS findings on
audit log monitoring. If either was disabled during the incident window, GuardDuty's silence about
that class of activity means nothing, and the corresponding playbook —
`../route53dns.stealth.no-logs-from-amazon-route53-dns-query/` or
`../eks.stealth.user-deleted-log-events/` — applies.

#### Right-size who can change GuardDuty

`guardduty:UpdateDetector`, `CreateFilter`, `CreateIPSet` and `ArchiveFindings` belong to the
security function, not to application teams or to a general administrator role.

---

## 5. Recovery

### Restore Clean State

#### Verify GuardDuty is enabled everywhere with nothing suppressed unexpectedly

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  D=$(aws guardduty list-detectors --region "$REGION" --output text --query 'DetectorIds[0]' 2>/dev/null)
  if [ -z "$D" ] || [ "$D" = "None" ]; then
    echo "[FAIL] $REGION has no detector"
  else
    S=$(aws guardduty get-detector --detector-id "$D" --region "$REGION" --output text --query 'Status')
    [ "$S" = "ENABLED" ] || echo "[FAIL] $REGION detector status=$S"
    N=$(aws guardduty list-ip-sets --detector-id "$D" --region "$REGION" --output json | jq '.IpSetIds | length')
    F=$(aws guardduty list-filters --detector-id "$D" --region "$REGION" --output json | jq '.FilterNames | length')
    [ "$N" -eq 0 ] || echo "[!] $REGION has $N trusted IP set(s) — findings are never generated for those addresses"
    [ "$F" -eq 0 ] || echo "[!] $REGION has $F filter(s) — check which auto-archive"
  fi
done
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  detail.severity=9.4  service.archived=false  type not starting [SAMPLE]"
echo "and MUST fire at high on the case the source pack cannot express:"
echo "  detail.severity=5.0 with service.resourceRole=ACTOR"
echo "  (a medium-severity finding where YOUR resource is the attacker)"
echo "The rule MUST NOT fire on:"
echo "  type='[SAMPLE] UnauthorizedAccess:EC2/SSHBruteForce'  (a console demonstration)"
echo "  the same finding with service.archived=true          (deliberately suppressed)"
echo "and MUST STILL fire on:"
echo "  a finding carrying service.userFeedback='USEFUL'"
echo "  (the source rule excludes this — confirming a true positive silenced it)"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A confirmed finding stopped alerting | The rule excluded findings carrying `userFeedback`, so marking one useful suppressed it |
| A blocklist built from the finding was incomplete | Aggregation replaces earlier source details; the finding names only the most recent |
| A sustained campaign was rated medium | Severity is per finding type; `service.count` carried the volume and no rule read it |
| A compromised host attacking outward was triaged as an inbound attack | `service.resourceRole` was never read |
| GuardDuty's silence was read as reassurance | Its DNS and EKS findings depend on upstream logs that had been disabled |

### Recommended Guardrails

**Keep GuardDuty's configuration in security hands**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["guardduty:DeleteDetector", "guardduty:UpdateDetector",
             "guardduty:CreateFilter", "guardduty:UpdateFilter",
             "guardduty:CreateIPSet", "guardduty:UpdateIPSet",
             "guardduty:ArchiveFindings", "guardduty:UpdateMemberDetectors",
             "guardduty:DisassociateFromMasterAccount"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/SecurityOperations"] } }
}
```

**Structural controls**
- Use delegated administration so member accounts cannot disable their own detectors, and alert on
  `UpdateMemberDetectors` and `DisassociateFromMasterAccount`.
- Review trusted IP lists on a schedule and treat every entry as an exception with an owner. They
  suppress findings **at source**, which no finding-stream monitoring can reveal.
- Retain CloudTrail and flow logs for at least as long as findings. A finding pointing at a window
  you no longer have is a pointer to nothing, and the finding is explicitly not the record.
- Route by band rather than duplicating the rule per band. One rule with a severity field in the
  routing configuration is one thing to correct when something like the `userFeedback` filter turns
  out to be wrong.

**Detection improvements**
- Alert on `service.resourceRole: ACTOR` independently of severity. It is the difference between
  being attacked and attacking, and no band expresses it.
- Alert on `service.count` independently of severity. It is the only measure of how much activity a
  finding represents, and severity does not scale with it.
- Exclude `service.archived` and `[SAMPLE]`, never `userFeedback`. Feedback is accuracy reporting;
  archiving is suppression.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1078 — Valid Accounts |
| MITRE tactic | Persistence (TA0003), Privilege Escalation (TA0004) |
| Primary API | None — GuardDuty findings are produced by AWS. The relevant control-plane calls are `guardduty:UpdateDetector`, `CreateFilter` and `CreateIPSet` |
| Event source | GuardDuty findings via EventBridge; CloudTrail for the configuration |
| Key discriminator | `detail.severity` ≥ 9.0 for the band; `service.resourceRole: ACTOR` and `service.count` for the two structural rules |
| Ground-truth signal | **CloudTrail and VPC Flow Logs.** AWS names them explicitly as where the complete record lives, because the finding replaces older detail on aggregation |
| "Was it used" pivot | Query 3 — the full source-address list from CloudTrail, which the finding reduced to its most recent entry |
| Blast radius | Determined by the finding type and the resource named. `ACTOR` findings mean the blast radius is what your own resource could reach |
| Error strings | Not applicable. Severity bands: Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 1.0–3.9 |

**MITRE mapping note:** the source pack maps this rule to **nothing at all**. `T1078 — Valid
Accounts` anchors the critical band, whose findings overwhelmingly involve credentials already in
use, and `T1526 — Cloud Service Discovery` the occurrence-count rule. `T1685 — Disable or
Modify Tools` covers the suppression triggers in §2, and is the correct current ID for disabling a
security **tool** as distinct from `.002` for a **log**. Note there is no cloud-security-tool
sub-technique — `.001` is Windows Event Log — so the parent is the mapping. All verified live
2026-08-30. A severity-based rule spans many techniques by construction — the finding **type** is
what identifies the technique for any given alert.

### Residual Risk

The finding named the most recent source and discarded the earlier ones, so any actor list not
rebuilt from CloudTrail or flow logs is incomplete by an amount nothing reports. If those sources
have aged out, the earlier attackers are unrecoverable. Findings suppressed by a trusted IP list
were never generated, so no review of the finding stream will ever reveal what they would have
said. And GuardDuty's DNS and EKS findings depend on upstream logs that this corpus documents as
disableable — where they were off, GuardDuty was quiet for that reason, and its quiet over that
period is not evidence of anything.
