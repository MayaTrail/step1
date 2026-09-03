# IR Playbook: GuardDuty Disabled or Suppressed — `DeleteDetector`, `UpdateDetector`, a filter, or a trusted IP list

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment (managed threat detection is turned off, or narrowed so that a chosen class of activity is never reported) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. GuardDuty is frequently the only behavioural detection an account has, and two of the three paths leave every dashboard showing a healthy detector. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685 |
| Services in Scope | GuardDuty, CloudTrail, S3 (trusted IP list objects), Route 53 Resolver, EKS |

**What the technique does:** three routes to not being detected. Delete or disable the detector —
loud, and regional, so the other Regions keep reporting and an account-wide view looks fine. Create
a **suppression rule**, which auto-archives matching findings: the detector stays healthy, the
volume looks normal, and the chosen class reaches nobody. Or add a **trusted IP list**, after which
findings for those addresses are never generated at all — not archived, never created, and
invisible to anything watching the finding stream.

**Why the usual reflexes miss it.** The reflex is to alert when findings stop arriving, and that
rule fires when the account is secure. GuardDuty emits findings when it detects something, so
silence is the normal state of a healthy quiet account — the alert becomes background noise, and
the team is trained to ignore it before the day it matters. The second reflex is to check the
console, where two of the three paths show a perfectly healthy detector.

**Detection thesis:** detect the act in CloudTrail, where it is attributed and timestamped, and
corroborate with a **state read** of the detector rather than a query over findings. This playbook
deliberately ships no absence rule.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail management events for `guardduty.amazonaws.com`**, in every Region. GuardDuty is
  regional and so is disabling it.
- **A scheduled `get-detector` / `list-filters` / `list-ip-sets` snapshot per Region**, stored with
  history. This is the corroborator that replaces the absence rule, and it is the only thing that
  finds a suppression rule created before monitoring existed.
- **Monitoring on the S3 objects backing any trusted IP list.** The `CreateIPSet` event carries a
  `Location`, not the addresses — so the trusted set can be changed by writing to that object with
  no GuardDuty API call at all.
- **Delegated administration**, so member accounts cannot disable their own detectors, with
  `UpdateMemberDetectors` and `DisassociateFromMasterAccount` alerted on.

**Alerting (must be pre-configured)**
- **`DeleteDetector`, or `UpdateDetector` disabling the detector or a feature → P0**
- **`CreateFilter` / `UpdateFilter` with an `ARCHIVE` action → P0**
- **`CreateIPSet` / `UpdateIPSet` — findings for those addresses are never generated → P0**
- **`UpdateMemberDetectors`, `DeleteMembers` or `DisassociateFromMasterAccount` → P0**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- The standard detector configuration — which protection plans should be enabled — written down, so
  a partially disabled detector is a diff rather than a judgement.

**Known IOC Baselines**
- The security function's role ARNs. This should be a very short allowlist and it is the only tuning
  surface for all three rules.
- The legitimate trusted IP ranges and suppression rules, by name and owner, with a reason. Anything
  outside that list is the finding.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `DeleteDetector`, or `UpdateDetector` with `enable: false` or a feature set to `DISABLED` | CloudTrail (`guardduty`) | T1685 |
| P0 | `CreateFilter` / `UpdateFilter` with `action: ARCHIVE` by a principal outside the security function | CloudTrail (`guardduty`) | T1685 |
| P0 | `CreateIPSet` / `UpdateIPSet` — findings for the listed addresses are never generated | CloudTrail (`guardduty`) | T1685 |
| P0 | `UpdateMemberDetectors`, `DeleteMembers` or `DisassociateFromMasterAccount` | CloudTrail (`guardduty`) | T1685 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A write to an S3 object backing a trusted IP list, with no accompanying GuardDuty API call | CloudTrail (`s3` data events) | T1685 |
| P2 | A detector whose enabled features differ from the standard, in the scheduled state sweep | `get-detector` state sweep | T1685 |
| P3 | `ArchiveFindings` called manually during an open incident | CloudTrail (`guardduty`) | T1685 |

### Detection Rule Quality Notes

The source rule counts findings over 36 hours with a `less_than` condition, so every row below is
auditable against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| The rule fires when the account is secure | GuardDuty emits a finding only when it detects something, so an account with nothing wrong emits none for days. The firing condition **is** the desired state — this is inversion, not ambiguity, and no window length fixes it | Detect the act in CloudTrail. **No absence rule is shipped**, which is a deliberate departure from every other no-logs playbook in this corpus |
| No coverage of suppression rules | A filter with an `ARCHIVE` action auto-archives matching findings. The detector is healthy, the volume is normal, and the suppressed class reaches nobody. An absence rule sees nothing because findings are still being generated | `guardduty_suppression_filter_created` at high, with the criteria in the event for triage |
| No coverage of trusted IP lists | Findings for listed addresses are **never generated** — not archived, never created. No finding-stream monitoring can reveal it, and the console shows an unbroken history | `guardduty_trusted_ip_set_changed` at high, rated equal to deleting the detector because it is quieter and more selective |
| No account of regionality | GuardDuty is regional. Disabling it in one Region leaves every other Region reporting normally, so an account-wide finding count barely moves | Every rule is per-Region by construction, and the state sweep in Query 2 iterates Regions |
| Treats findings as the health signal | The detector's status is exposed through the API, not through the finding stream. A healthy detector producing no findings and a deleted detector look identical to a finding count | A scheduled state read, which is the corroborator this playbook uses instead of an absence rule |

**Recommended detection — three paths, two of which leave the dashboards green.**

```yaml
# GuardDuty disabled or suppressed (T1685)
#
# THE SOURCE RULE ALERTS WHEN THE ACCOUNT IS SECURE. It fires when fewer than one GuardDuty finding
# arrives in 36 hours. But GuardDuty produces a finding only when it detects something — and an
# account with nothing wrong produces none, for days at a time, correctly. AWS defines even the
# lowest band as "attempted suspicious activity that did not compromise your environment", which is
# something that happens to internet-facing estates and not to quiet internal ones.
#
# So the rule's firing condition is the desired state. This is not "absence is ambiguous", which is
# the usual objection to a no-logs rule; it is that the rule is inverted. A team running it learns
# that the GuardDuty alert means nothing, which is exactly the state they are in on the day the
# detector is actually turned off.
#
# THE DETECTOR'S STATUS IS THE SIGNAL, AND IT IS A STATE READ. GuardDuty exposes whether it is
# enabled through the API, not through the finding stream. Everything below detects the ACT of
# disabling or suppressing, in CloudTrail, and §2 of ../PLAYBOOK.md carries the state sweep.
#
# THERE ARE THREE WAYS TO GO BLIND AND ONLY ONE IS LOUD:
#   DeleteDetector / UpdateDetector(enable=false)  -> the whole service, obvious
#   CreateFilter with action ARCHIVE               -> findings are created and auto-archived, so the
#                                                     console shows a detector working while the
#                                                     matching findings never reach anyone
#   CreateIPSet (trusted IP list)                  -> findings for those addresses are NEVER
#                                                     GENERATED. Not archived, not suppressed after
#                                                     the fact — never created. Nothing in the
#                                                     finding stream can reveal this, and it is a
#                                                     legitimate documented feature.
# The third is the quietest and the rules below treat it at the same level as the first.
#
# AND A FOURTH THAT IS NOT A GUARDDUTY ACTION AT ALL. GuardDuty's DNS findings depend on Route 53
# Resolver query logging for the VPC, and its EKS findings on EKS audit log monitoring. Disabling
# those degrades GuardDuty without touching it — covered in
# ../../route53dns.stealth.no-logs-from-amazon-route53-dns-query/ and ../../eks.stealth.user-deleted-log-events/,
# and noted here so the dependency is not rediscovered during an incident.
title: GuardDuty detector deleted or disabled
id: 9e4b7a12-0c85-4d36-bf70-28a15c93e604
name: guardduty_detector_disabled
status: experimental
description: >-
  DeleteDetector removed the detector, or UpdateDetector turned it off. The loudest of the three
  paths and the one an absence rule would eventually catch — after up to 36 hours, and only if the
  account was otherwise producing findings. Detected here at the moment it happens, attributed to a
  principal, and naming the Region: GuardDuty is regional, so disabling it in one Region leaves
  every other Region reporting normally.
references:
  - https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html
  - https://attack.mitre.org/techniques/T1685/001/
tags:
  - attack.defense-impairment
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'guardduty.amazonaws.com'
    eventName:
      - 'DeleteDetector'
      - 'UpdateDetector'
      - 'UpdateMemberDetectors'
      - 'DisassociateFromMasterAccount'
      - 'DeleteMembers'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the security function's roles. This should be a very short list,
  # and an empty one is a defensible start.
  known_security_roles:
    userIdentity.arn|contains:
      - ':role/SecurityOperations'
      - ':role/PlatformAutomation'
  condition: selection and success and not known_security_roles
falsepositives:
  - >-
    Enabling a feature through UpdateDetector, which uses the same event name as disabling one.
    Read the request parameters: the finding is enable=false or a features list with a feature set
    to DISABLED, and the rule is deliberately broad because both arrive as the same call.
level: high
---
title: GuardDuty suppression rule created
id: 46c0f983-71ea-4b25-90d8-5e73b1a4c82f
name: guardduty_suppression_filter_created
status: experimental
description: >-
  A filter was created or updated with an ARCHIVE action — a suppression rule. Matching findings are
  still generated and then archived automatically, so the detector looks healthy, the finding count
  in the console looks normal, and the suppressed class never reaches anyone. This is a legitimate
  and necessary feature for tuning out known-benign activity, which is exactly why it is worth
  alerting on: the same mechanism tunes out an attacker. Read the FindingCriteria in the request,
  not just the fact of the call.
references:
  - https://docs.aws.amazon.com/guardduty/latest/ug/findings_suppression-rule.html
  - https://attack.mitre.org/techniques/T1685/001/
tags:
  - attack.defense-impairment
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'guardduty.amazonaws.com'
    eventName:
      - 'CreateFilter'
      - 'UpdateFilter'
  success:
    errorCode: null
  archiving:
    requestParameters.action: 'ARCHIVE'
  known_security_roles:
    userIdentity.arn|contains:
      - ':role/SecurityOperations'
      - ':role/PlatformAutomation'
  condition: selection and success and archiving and not known_security_roles
falsepositives:
  - >-
    Ordinary tuning, which is what suppression rules exist for. The alert is not that a rule was
    created but that one was created outside the security function — and the criteria are in the
    same event for triage.
level: high
---
title: GuardDuty trusted IP list created or updated
id: d78e2504-3a91-46cb-b0f7-16295de3c840
name: guardduty_trusted_ip_set_changed
status: experimental
description: >-
  A trusted IP set was created or updated. This is the quietest way to blind GuardDuty and it
  deserves the same level as deleting the detector: findings for addresses on the list are NEVER
  GENERATED — not created and archived, never created at all. No finding-stream monitoring can
  reveal it, no finding count changes, and the console shows a healthy detector with a normal
  history. The list contents live in an S3 object referenced by Location, so the event names the
  list and not its members; reading the object is part of triage rather than optional.
references:
  - https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_upload-lists.html
  - https://attack.mitre.org/techniques/T1685/001/
tags:
  - attack.defense-impairment
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'guardduty.amazonaws.com'
    eventName:
      - 'CreateIPSet'
      - 'UpdateIPSet'
  success:
    errorCode: null
  known_security_roles:
    userIdentity.arn|contains:
      - ':role/SecurityOperations'
      - ':role/PlatformAutomation'
  condition: selection and success and not known_security_roles
falsepositives:
  - >-
    Adding the corporate egress range, which is the normal use. Legitimate and still worth reading
    every time — the difference between a corporate range and an attacker's range is which one you
    can name, and the event does not contain the addresses.
level: high
```

What this set structurally cannot do: it cannot tell you which addresses a trusted IP list contains,
because the event carries an S3 location and not the members — and it cannot see a change made by
writing to that object directly. It also cannot see GuardDuty being blinded through its upstream
data sources, which is a different playbook.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log
> platform for busy windows. GuardDuty is regional: run every query in every Region.

#### Query 1 — Reconstruct: every GuardDuty configuration change

```bash
REGION="us-east-1"
SINCE=$(date -u -v-90d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in DeleteDetector UpdateDetector CreateDetector CreateFilter UpdateFilter DeleteFilter \
          CreateIPSet UpdateIPSet DeleteIPSet ArchiveFindings UpdateMemberDetectors \
          DeleteMembers DisassociateFromMasterAccount; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       name: (.requestParameters.name // "-"),
       action: (.requestParameters.action // "-"),
       location: (.requestParameters.location // "-"),
       enable: (.requestParameters.enable // "-"),
       criteria: ((.requestParameters.findingCriteria // {}) | tostring | .[0:200]),
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'sort_by(.time)'
```

Ninety days, because suppression rules are usually old — they are created quietly and left. Read
`action: ARCHIVE` and any `CreateIPSet` as findings in their own right regardless of age.
`enable: "false"` on `UpdateDetector` is the disable case; the same event name is used to enable, so
the parameter is what separates them.

#### Query 2 — Sweep: the state, which replaces the absence rule

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  D=$(aws guardduty list-detectors --region "$REGION" --output text --query 'DetectorIds[0]' 2>/dev/null)
  if [ -z "$D" ] || [ "$D" = "None" ]; then
    echo "[FAIL] $REGION  no detector"
    continue
  fi
  S=$(aws guardduty get-detector --detector-id "$D" --region "$REGION" --output text --query 'Status')
  [ "$S" = "ENABLED" ] && echo "[OK]   $REGION  detector $D enabled" \
                       || echo "[FAIL] $REGION  detector $D status=$S"

  aws guardduty list-filters --detector-id "$D" --region "$REGION" --output json | \
    jq -r '.FilterNames[]' | while read -r F; do
      aws guardduty get-filter --detector-id "$D" --filter-name "$F" --region "$REGION" \
        --output json | jq -r --arg r "$REGION" \
        'if .Action == "ARCHIVE"
           then "       [!] \($r) SUPPRESSION RULE \(.Name): \(.FindingCriteria | tostring | .[0:180])"
           else "       [i] \($r) filter \(.Name) action=\(.Action)" end'
    done

  aws guardduty list-ip-sets --detector-id "$D" --region "$REGION" --output json | \
    jq -r '.IpSetIds[]' | while read -r I; do
      aws guardduty get-ip-set --detector-id "$D" --ip-set-id "$I" --region "$REGION" \
        --output json | jq -r --arg r "$REGION" \
        '"       [!] \($r) TRUSTED IP LIST \(.Name) status=\(.Status) location=\(.Location) — findings for these addresses are NEVER GENERATED"'
    done
done
```

This is the corroborator that replaces the absence rule, and it answers a question no finding count
can: is the detector on, and what has been narrowed. Every `[!]` line is something reducing what
GuardDuty will ever report, and each needs an owner and a reason.

#### Query 3 — Inspect: what the trusted list actually contains

```bash
REGION="us-east-1"
LOCATION="<location-from-Query-2>"

echo "[i] The CreateIPSet event carries a LOCATION, not the addresses. Fetch the object:"
BUCKET=$(printf '%s' "$LOCATION" | sed -e 's|^https://||' -e 's|^s3://||' | cut -d/ -f1 | sed 's|\..*||')
KEY=$(printf '%s' "$LOCATION" | sed -e 's|^https://[^/]*/||' -e 's|^s3://[^/]*/||')
if [ -n "$BUCKET" ] && [ -n "$KEY" ]; then
  aws s3api head-object --bucket "$BUCKET" --key "$KEY" --region "$REGION" --output json 2>/dev/null | \
    jq -r '"[i] object last modified: \(.LastModified)  size: \(.ContentLength)"' \
    || echo "[!] could not stat the object — check the location format and permissions"
  echo "[i] Retrieve and review the contents before concluding anything:"
  echo "    aws s3 cp s3://$BUCKET/$KEY - | head -50"
fi
echo
echo "[!] Anyone who can write to that object changes the trusted set with NO GuardDuty API call."
echo "    Check the object's own access history in CloudTrail S3 data events, not just Query 1."
```

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | jq -s 'sort_by(.time)'
```

Narrowing detection is preparation. What the same principal did **after** the change is the
incident, and what they did before it usually explains how they got the permission.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore detection first, then work out what was hidden while it was narrowed.

> Run every command under the **break-glass responder credentials** from §1.

#### Step 1 — Re-enable the detector, per Region

```bash
REGION="us-east-1"
D=$(aws guardduty list-detectors --region "$REGION" --output text --query 'DetectorIds[0]')

if [ -z "$D" ] || [ "$D" = "None" ]; then
  echo "[!] no detector in $REGION — creating one loses all prior findings, which are not recoverable."
  echo "    Create it, and record in the incident that the finding history for this Region is gone:"
  echo "    aws guardduty create-detector --enable --region $REGION"
else
  aws guardduty update-detector --detector-id "$D" --enable --region "$REGION" \
    && aws guardduty get-detector --detector-id "$D" --region "$REGION" --output text --query 'Status' \
    | xargs -I{} echo "[OK] $REGION detector status: {}"
fi
```

#### Step 2 — Remove the suppression, after reading it

```bash
REGION="us-east-1"
D="<detector-id>"
FILTER="<filter-name-from-Query-2>"

aws guardduty get-filter --detector-id "$D" --filter-name "$FILTER" --region "$REGION" \
  --output json | jq '{Name, Action, Rank, FindingCriteria}'
echo
echo "[i] Read the criteria above and record them in the incident BEFORE deleting — they say what"
echo "    the attacker expected to generate, which is a lead in itself."
echo "[i] Then: aws guardduty delete-filter --detector-id $D --filter-name $FILTER --region $REGION"
```

The criteria are evidence. A suppression rule scoped to one finding type and one resource tells you
what the actor expected GuardDuty to notice, and deleting it before reading it throws that away.

#### Step 3 — Remove the trusted IP list, and check who wrote the object

```bash
REGION="us-east-1"
D="<detector-id>"
IPSET="<ip-set-id-from-Query-2>"

aws guardduty get-ip-set --detector-id "$D" --ip-set-id "$IPSET" --region "$REGION" \
  --output json | jq '{Name, Format, Location, Status}'
echo
echo "[i] Retrieve the object contents (Query 3) and record the addresses — they are the actor's"
echo "    infrastructure if this was not a legitimate list."
echo "[i] Then: aws guardduty delete-ip-set --detector-id $D --ip-set-id $IPSET --region $REGION"
echo "[!] Also check S3 data events for writes to that object. The list can be changed without any"
echo "    GuardDuty API call, so Query 1 may show only the original creation."
```

#### Step 4 — Establish what was not reported

The window from the change to its removal is a period in which the suppressed class of activity was
not reported. GuardDuty does not retroactively generate findings for it. The underlying data —
CloudTrail, VPC Flow Logs, DNS query logs — still exists if retained, and re-examining it for the
suppressed criteria over that window is the only way to recover what was hidden. Scope that
explicitly rather than assuming the restored detector fills the gap.

---

## 4. Eradication

### Remove Attacker Access

#### Audit every filter and IP set in every Region

Query 2's `[!]` lines across all Regions are the backlog. Each needs an owner and a reason.
Suppression rules accumulate legitimately during tuning, which is what makes an extra one easy to
miss — the review is the control, not the alert.

#### Monitor the trusted-list objects themselves

A trusted IP list can be changed by writing to its S3 object. Enable S3 data events on that prefix
and alert on writes; otherwise the GuardDuty rules here see only the original `CreateIPSet`.

#### Right-size who can configure GuardDuty

`guardduty:UpdateDetector`, `CreateFilter`, `CreateIPSet` and `ArchiveFindings` belong to the
security function. Query 4's principal is the starting point.

#### Confirm the upstream sources are intact

GuardDuty's DNS findings need Route 53 Resolver query logging and its EKS findings need audit log
monitoring. If either was disabled during the window, the corresponding playbook applies and
GuardDuty's silence about that class of activity was never meaningful.

---

## 5. Recovery

### Restore Clean State

#### Verify detectors and their features across every Region

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  D=$(aws guardduty list-detectors --region "$REGION" --output text --query 'DetectorIds[0]' 2>/dev/null)
  if [ -z "$D" ] || [ "$D" = "None" ]; then echo "[FAIL] $REGION no detector"; continue; fi
  S=$(aws guardduty get-detector --detector-id "$D" --region "$REGION" --output text --query 'Status')
  [ "$S" = "ENABLED" ] || echo "[FAIL] $REGION status=$S"
done
echo "[i] no [FAIL] lines means every Region has an enabled detector"
```

#### Verify nothing unaccounted-for is suppressing findings

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  D=$(aws guardduty list-detectors --region "$REGION" --output text --query 'DetectorIds[0]' 2>/dev/null)
  [ -z "$D" ] || [ "$D" = "None" ] && continue
  N=$(aws guardduty list-ip-sets --detector-id "$D" --region "$REGION" --output json | jq '.IpSetIds | length')
  F=$(aws guardduty list-filters --detector-id "$D" --region "$REGION" --output json | jq '.FilterNames | length')
  [ "$N" -eq 0 ] && [ "$F" -eq 0 ] || echo "[!] $REGION: $N trusted IP set(s), $F filter(s) — each needs an owner in the register"
done
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  eventSource=guardduty.amazonaws.com  eventName=CreateIPSet  no errorCode"
echo "  by an ARN outside known_security_roles"
echo "  (findings for those addresses are NEVER GENERATED — the quietest path, and the one no"
echo "   absence rule can see because findings keep arriving normally for everything else)"
echo "and MUST fire on:"
echo "  eventName=CreateFilter with action=ARCHIVE"
echo "The rule MUST NOT fire on:"
echo "  eventName=CreateFilter with action=NOOP  (a saved view, not a suppression)"
echo "and note there is NO absence test here at all: an account with no findings is a secure"
echo "  account, which is why the source rule alerts on health."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| The no-logs alert was ignored | It fired whenever the account was quiet, which is the desired state — the alert was noise by construction |
| A suppression rule went unnoticed | Findings kept arriving normally, so nothing about the finding stream changed |
| A trusted IP list was invisible | Findings for those addresses were never generated, so no count, dashboard or absence rule could reveal it |
| Disabling one Region was not noticed | GuardDuty is regional and monitoring was account-wide |
| The trusted list could be changed without a GuardDuty call | The list lives in an S3 object and that object was not monitored |

### Recommended Guardrails

**Keep GuardDuty configuration in security hands**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["guardduty:DeleteDetector", "guardduty:UpdateDetector",
             "guardduty:CreateFilter", "guardduty:UpdateFilter",
             "guardduty:CreateIPSet", "guardduty:UpdateIPSet",
             "guardduty:ArchiveFindings", "guardduty:UpdateMemberDetectors",
             "guardduty:DeleteMembers", "guardduty:DisassociateFromMasterAccount"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/SecurityOperations"] } }
}
```

**Structural controls**
- Use delegated administration, so a member account cannot disable its own detector, and alert on
  the member-management events.
- Keep a register of every suppression rule and trusted IP list with an owner, a reason and a review
  date. These accumulate legitimately, which is what makes one extra easy to hide.
- Store trusted IP list objects in a bucket the workload accounts cannot write to, and enable S3
  data events on the prefix. The list is changeable without any GuardDuty API call.
- Snapshot detector state per Region on a schedule. It is the corroborator that replaces the absence
  rule, and it is the only thing that finds a suppression created before monitoring existed.

**Detection improvements**
- Do not alert on the absence of findings. In this service that is an alert on being secure, and it
  trains the team to ignore the channel that matters.
- Rate a trusted IP list change the same as deleting the detector. It is quieter, more selective,
  and invisible to every finding-based check.
- Alert per Region. An account-wide view of a regional service hides the single-Region case
  entirely.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685 — Disable or Modify Tools |
| MITRE tactic | Defense Impairment (TA0112) |
| Primary API | `guardduty:DeleteDetector`, `UpdateDetector`, `CreateFilter` with `ARCHIVE`, `CreateIPSet` |
| Event source | guardduty.amazonaws.com — and S3 data events for the trusted-list objects |
| Key discriminator | The control-plane call itself. `UpdateDetector` uses one event name for enabling and disabling, so `enable: false` or a `DISABLED` feature is the discriminator |
| Ground-truth signal | `get-detector`, `list-filters` and `list-ip-sets` per Region — live state, and the corroborator this playbook uses instead of an absence rule |
| "Was it used" pivot | Re-examine CloudTrail, VPC Flow Logs and DNS query logs for the suppression criteria over the affected window. GuardDuty does not retroactively generate findings |
| Blast radius | Every detection GuardDuty would have produced in the affected Region, for the affected class, for the duration |
| Error strings | None on the calls themselves. A trusted IP list's `Status` reflects activation; the addresses are in the S3 object at `Location` and not in any event |

**MITRE mapping note:** The sub-technique choice matters and differs from the rest of this corpus: `T1685` covers
disabling a security **tool**, while `T1685.002` covers disabling a **log**. GuardDuty is a tool, so
this playbook uses `.001` where every other `*.stealth.no-logs-*` playbook here uses `.002`.
Verified live 2026-08-30.

### Residual Risk

GuardDuty does not retroactively generate findings, so whatever the suppressed class would have
reported during the window is simply absent — restoring the detector restores the future and not the
past. Recovering it means re-examining CloudTrail, flow logs and DNS query logs for the suppression
criteria, which is only possible if those were retained for the period. If the detector was deleted
rather than disabled, the prior finding history went with it and is not recoverable at all. A
trusted IP list can be changed by writing to its S3 object with no GuardDuty API call, so the
control-plane trail may show only the original creation and nothing since. And GuardDuty's own
upstream dependencies mean it can be blinded without any of these events occurring — where the DNS
or EKS log sources were disabled, its silence over that period was never meaningful in the first
place.
