# IR Playbook: Network Firewall Logging Stopped — `UpdateLoggingConfiguration`, or a policy that stops forwarding to the stateful engine

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment (the record of inspected network traffic stops — and on one of the two paths, the inspection stops with it) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. Every `netfw.*` detection reads from this source. On the firewall-policy path the loss is larger than the logging: traffic that no longer reaches the stateful engine is neither inspected nor recorded, while every console view continues to show logging enabled. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | AWS Network Firewall, VPC, CloudWatch Logs, S3, Firehose, CloudTrail |

**What the technique does:** two paths. `UpdateLoggingConfiguration` submitted with an empty
destination list turns off every log type in one call — there is no delete verb, because logging is
an attribute of the firewall rather than a separate resource. Or `UpdateFirewallPolicy` changes the
stateless default actions so they no longer include `aws:forward_to_sfe`, and traffic stops reaching
the engine that logs. The second is quieter and worse: the logging configuration is untouched, every
dashboard shows it enabled, and the traffic is no longer inspected either.

**Why the usual reflexes miss it.** An absence rule is the reflex, and this is the worst service in
the corpus for one — because a valid configuration produces no logs permanently. AWS: *"Firewall
logging is only available for traffic that you forward to the stateful rules engine."* A policy
that handles a traffic class statelessly is silent by design. The rule fires on it forever, and a
team that has learned to ignore it is in exactly that state when logging is genuinely disabled.

**Detection thesis:** detect on the control-plane calls, which name the firewall and the principal.
Treat the partial-removal case as a state comparison rather than a log match, because the API
records what survives and never what was removed.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail management events for `network-firewall.amazonaws.com`.**
- **A scheduled `describe-logging-configuration` snapshot per firewall, stored with history.** This
  is not optional here: `UpdateLoggingConfiguration` replaces the configuration and its request
  carries the **surviving** log types, so a partial removal can only be identified by comparing
  against a previous value. Without stored history the comparison has nothing to compare against.
- **A scheduled `describe-firewall-policy` snapshot**, capturing `StatelessDefaultActions`. This is
  what decides whether the firewall logs anything at all.
- **Log destinations in a separate account** where the workload account cannot modify the bucket
  policy or log group.

**Alerting (must be pre-configured)**
- **`UpdateLoggingConfiguration` with an empty destination list → P0**
- **`UpdateFirewallPolicy` or `CreateFirewallPolicy` whose stateless defaults omit `aws:forward_to_sfe` → P0**
- **Any other `UpdateLoggingConfiguration` by a principal outside the provisioning allowlist → P1**
- **`DeleteFirewall`, or `UpdateFirewallDeleteProtection` disabling protection → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- The intended logging configuration for each firewall — log types and destination ARNs — written
  down. Restoring from memory is how a firewall ends up logging to the wrong bucket.

**Known IOC Baselines**
- Which roles legitimately manage firewall configuration — one infrastructure role.
- **Which policies deliberately handle traffic statelessly**, recorded as decisions. This is the
  permanent false-positive set for any absence monitoring, and writing it down is what makes the
  rest of this playbook's reasoning possible.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `UpdateLoggingConfiguration` succeeding with an empty `logDestinationConfigs` | CloudTrail (`network-firewall`) | T1685.002 |
| P0 | `UpdateFirewallPolicy` / `CreateFirewallPolicy` whose `statelessDefaultActions` omit `aws:forward_to_sfe` | CloudTrail (`network-firewall`) | T1685.002 |
| P1 | Any other `UpdateLoggingConfiguration` by a principal outside the provisioning allowlist | CloudTrail (`network-firewall`) | T1685.002 |
| P1 | `DeleteFirewall`, or `UpdateFirewallDeleteProtection` turning protection off | CloudTrail (`network-firewall`) | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A firewall whose live log types differ from the stored snapshot — the partial removal, resolvable only by comparison | `describe-logging-configuration` state sweep | T1685.002 |
| P2 | A firewall in service with no logging configuration at all | State sweep | T1685.002 |
| P3 | No records from a specific `firewall_name` for four hours — corroborating only, and see §2's five explanations | Network Firewall logs | T1685.002 |

### Detection Rule Quality Notes

The source rule counts records over four hours with an empty `group_by`, so every row below is
auditable against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Absence used as the control on a service with a permanently-silent valid configuration | AWS logs only traffic forwarded to the stateful engine, so a policy whose stateless default is `aws:drop` or `aws:pass` produces nothing — correctly and forever. The rule fires on that configuration continuously, and a team that has learned to ignore it is in that state when logging is genuinely disabled | Detect on the control-plane calls. Absence demoted to a P3 corroborator with its five explanations enumerated so nobody re-derives them mid-incident |
| `group_by` is empty | An account-wide count barely moves when one firewall goes dark. Firewalls are per-endpoint resources, so the firewall is the unit and it is what the rule cannot name | The control-plane events name the firewall; the absence view groups by `firewall_name` |
| Assumes a deletion event exists | Logging is an attribute of the firewall, not a separate resource. There is no delete verb — `UpdateLoggingConfiguration` replaces the whole configuration | Match the empty-configuration case, which is what the removal actually looks like on the wire |
| Cannot see a partial removal | The call's request carries the **surviving** log types, so removing alert logging while keeping flow logging looks identical to a routine destination change. The removed type is exactly what the event does not contain | A deliberately broad medium rule that triggers a **state comparison**, plus a §1 requirement for stored snapshots so the comparison has a baseline |
| No coverage of the firewall-policy path | Changing stateless defaults so they omit `aws:forward_to_sfe` stops the logging and the inspection, while every dashboard still shows logging enabled. It is the quieter path and the more damaging one | `netfw_stateless_forward_removed` at high — the same level as outright removal, because it is strictly worse |
| Four-hour window | Reasonable in itself, and it does not address any of the above. The window is not the problem; the signal is | Window kept only for the corroborating view and explicitly not treated as conclusive |

**Recommended detection — both control-plane paths, including the one that leaves the dashboards green.**

```yaml
# Network Firewall logging stopped (T1685.002)
#
# THIS SERVICE HAS A LEGITIMATE, PERMANENT REASON TO PRODUCE NO LOGS, AND THE SOURCE RULE CANNOT
# TELL IT FROM AN INCIDENT. AWS: "Firewall logging is only available for traffic that you forward
# to the stateful rules engine. You forward traffic to the stateful engine through stateless rule
# actions and stateless default actions in the firewall policy."
#
# So a policy whose stateless default action is aws:drop or aws:pass rather than aws:forward_to_sfe
# produces NO alert log and NO flow log, correctly and forever. An absence rule fires on that
# configuration continuously, and the team learns to ignore it — which is the state they are in
# when logging is actually disabled.
#
# UpdateLoggingConfiguration RECORDS WHAT REMAINS, NOT WHAT WAS REMOVED. Logging is a configuration
# ON the firewall rather than a separate resource, so there is no delete verb to watch. The call
# REPLACES the whole configuration: removing the alert log type and removing every log type are the
# same API call, and the request carries the SURVIVING log destinations. A rule matching "the alert
# type was removed" therefore matches nothing — the removed type is exactly what the event does not
# contain. The rules below match on the configuration becoming EMPTY or SHRINKING, which is what
# the event can actually express, and §2 of ../PLAYBOOK.md carries the state comparison that
# resolves the partial case.
#
# THE group_by IS EMPTY. The source rule counts records account-wide, so one firewall going dark
# among several barely moves the total. Firewalls are per-VPC-endpoint resources; the firewall is
# the unit and it is the one the rule cannot name.
title: Network Firewall logging configuration replaced with an empty one
id: 5f2c7940-8b31-4ea6-93d0-16c4a87e2b5f
name: netfw_logging_removed
status: experimental
description: >-
  UpdateLoggingConfiguration submitted with no log destinations at all. This is the unambiguous
  case — every log type off, one call, attributed to a principal, naming the firewall. Note the
  shape: logging is an attribute of the firewall and the call replaces the entire configuration, so
  an empty LogDestinationConfigs list IS the removal. There is no delete event and no per-type
  removal event to watch for.
references:
  - https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-update-logging-configuration.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'network-firewall.amazonaws.com'
    eventName: 'UpdateLoggingConfiguration'
  success:
    errorCode: null
  has_destinations:
    requestParameters.loggingConfiguration.logDestinationConfigs.logType|exists: true
  # POPULATE BEFORE DEPLOYING with the infrastructure-as-code roles that own firewall configuration.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not has_destinations and not known_provisioners
falsepositives:
  - >-
    A firewall being decommissioned, which should be followed by DeleteFirewall within minutes. An
    empty logging configuration with the firewall still in service is the finding.
level: high
---
title: Network Firewall logging configuration changed
id: b3806e15-4c72-49fd-a058-2e91d7346cb0
name: netfw_logging_configuration_changed
status: experimental
description: >-
  Any successful UpdateLoggingConfiguration that still carries destinations. Shipped at medium and
  deliberately broad, because the API cannot express the interesting case any other way: the call
  replaces the whole configuration and the request contains the log types that SURVIVE, so a
  partial removal — dropping alert logging while keeping flow logging — is indistinguishable from a
  routine destination change without comparing against the previous state. That comparison is a
  state read, not a log match, and it is Query 2 of ../PLAYBOOK.md. This rule exists so the
  comparison is triggered.
references:
  - https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-update-logging-configuration.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'network-firewall.amazonaws.com'
    eventName: 'UpdateLoggingConfiguration'
  success:
    errorCode: null
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    Changing a log destination, adding a log type, or migrating buckets — all ordinary and all
    indistinguishable from a partial removal in the event alone. That is the point of the rule:
    it triggers the state comparison rather than deciding on its own.
level: medium
---
title: Firewall policy changed to stop forwarding traffic to the stateful engine
id: a71d5e38-06b9-4c24-8f57-3ba90c62e7d1
name: netfw_stateless_forward_removed
status: experimental
description: >-
  UpdateFirewallPolicy or CreateFirewallPolicy submitted with stateless default actions that do not
  include aws:forward_to_sfe. This achieves the same result as disabling logging, without touching
  the logging configuration at all: AWS logs only traffic forwarded to the stateful engine, so a
  policy that drops or passes statelessly produces no alert log and no flow log for that traffic.
  It is quieter than turning logging off — every dashboard still shows logging enabled — and it
  removes the inspection as well as the record.
references:
  - https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-policy-settings.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'network-firewall.amazonaws.com'
    eventName:
      - 'UpdateFirewallPolicy'
      - 'CreateFirewallPolicy'
  success:
    errorCode: null
  forwards_to_stateful:
    requestParameters.firewallPolicy.statelessDefaultActions|contains: 'aws:forward_to_sfe'
  condition: selection and success and not forwards_to_stateful
falsepositives:
  - >-
    A policy that genuinely handles a traffic class statelessly for throughput reasons. Legitimate,
    and it should be a recorded decision — the cost of that decision is that the traffic is neither
    inspected by the stateful engine nor logged anywhere.
level: high
```

What this set structurally cannot do: it cannot identify which log type was removed in a partial
change, because the event carries the survivors. That is a state comparison and it needs a stored
baseline, which is a preparation item rather than an incident query.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log
> platform for busy windows. Firewalls are regional: run every query in every Region in use.

#### Query 1 — Reconstruct: every firewall configuration change

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in UpdateLoggingConfiguration UpdateFirewallPolicy CreateFirewallPolicy \
          DeleteFirewall UpdateFirewallDeleteProtection AssociateFirewallPolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       firewall: (.requestParameters.firewallName // .requestParameters.firewallArn // "-"),
       surviving_log_types: [((.requestParameters.loggingConfiguration.logDestinationConfigs) // [])[].logType],
       stateless_defaults: ((.requestParameters.firewallPolicy.statelessDefaultActions) // []),
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'sort_by(.time)'
```

The field is named `surviving_log_types` deliberately. It is **what remains**, not what was
removed — an `UpdateLoggingConfiguration` showing `["FLOW"]` means alert logging is now off, and the
event contains no trace of the word ALERT. An empty array means all logging is off.
`stateless_defaults` without `aws:forward_to_sfe` is the other path, and it will appear on a
`UpdateFirewallPolicy` with a perfectly healthy logging configuration.

#### Query 2 — Sweep: live logging state against what it should be

```bash
REGION="us-east-1"

for FW in $(aws network-firewall list-firewalls --region "$REGION" --output json | \
            jq -r '.Firewalls[].FirewallName'); do
  TYPES=$(aws network-firewall describe-logging-configuration --firewall-name "$FW" \
    --region "$REGION" --output json 2>/dev/null | \
    jq -r '[.LoggingConfiguration.LogDestinationConfigs[]?.LogType] | sort | join(",")')
  if [ -z "$TYPES" ]; then
    echo "[FAIL] $FW  NO logging configuration at all"
  else
    case "$TYPES" in
      *ALERT*FLOW*|*FLOW*ALERT*) echo "[OK]   $FW  logging: $TYPES" ;;
      *)                          echo "[!]    $FW  logging: $TYPES  — partial. Compare against the stored snapshot" ;;
    esac
  fi

  POLICY=$(aws network-firewall describe-firewall --firewall-name "$FW" --region "$REGION" \
    --output text --query 'Firewall.FirewallPolicyArn' 2>/dev/null)
  DEFAULTS=$(aws network-firewall describe-firewall-policy --firewall-policy-arn "$POLICY" \
    --region "$REGION" --output json 2>/dev/null | \
    jq -r '.FirewallPolicy.StatelessDefaultActions | join(",")')
  case "$DEFAULTS" in
    *forward_to_sfe*) echo "       stateless defaults: $DEFAULTS  (traffic reaches the stateful engine and is logged)" ;;
    *)                echo "       [FAIL] stateless defaults: $DEFAULTS  — this traffic NEVER reaches the stateful engine and produces NO log" ;;
  esac
done
```

This is the query that resolves the case CloudTrail cannot. `[!]` on the log types is a partial
configuration, and whether it is a removal depends entirely on the stored snapshot from §1 — the
event stream cannot tell you, because the removed type is the one thing it does not record.

#### Query 3 — Inspect: is the destination actually receiving

```bash
REGION="us-east-1"
FW="<firewall-name>"

aws network-firewall describe-logging-configuration --firewall-name "$FW" --region "$REGION" \
  --output json | jq -r '.LoggingConfiguration.LogDestinationConfigs[]? |
    "\(.LogType)\t\(.LogDestinationType)\t\(.LogDestination | tostring)"'

echo
echo "[i] A configuration is not delivery. For a CloudWatch Logs destination, confirm a recent"
echo "    stream; for S3, confirm a recent object; for Firehose, check the stream's error metrics."
echo "    There is no Network Firewall event that fires when delivery starts failing."
DEST=$(aws network-firewall describe-logging-configuration --firewall-name "$FW" --region "$REGION" \
  --output json | jq -r '.LoggingConfiguration.LogDestinationConfigs[0].LogDestination.logGroup // empty')
if [ -n "$DEST" ]; then
  aws logs describe-log-streams --log-group-name "$DEST" --order-by LastEventTime --descending \
    --max-items 3 --region "$REGION" --output json 2>/dev/null | \
    jq -r '.logStreams[] | "\(.logStreamName)\tlast=\(.lastEventTimestamp)"' \
    || echo "[FAIL] cannot read $DEST — deleted, or permissions changed"
fi
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

Disabling network logging is preparation. Read what the same principal did in the surrounding hours
— and read the alert log for the period immediately **before** the change, since those are the last
records that exist.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore recording, then restore inspection if the policy path was used — and check which path it
was first, because the two have different fixes and only one of them shows up on a dashboard.

> Run every command under the **break-glass responder credentials** from §1.

#### Step 1 — Establish which path was taken

```bash
REGION="us-east-1"
FW="<firewall-name>"

TYPES=$(aws network-firewall describe-logging-configuration --firewall-name "$FW" --region "$REGION" \
  --output json 2>/dev/null | jq -r '[.LoggingConfiguration.LogDestinationConfigs[]?.LogType] | join(",")')
POLICY=$(aws network-firewall describe-firewall --firewall-name "$FW" --region "$REGION" \
  --output text --query 'Firewall.FirewallPolicyArn')
DEFAULTS=$(aws network-firewall describe-firewall-policy --firewall-policy-arn "$POLICY" \
  --region "$REGION" --output json | jq -r '.FirewallPolicy.StatelessDefaultActions | join(",")')

echo "[i] logging types: ${TYPES:-<none>}"
echo "[i] stateless defaults: $DEFAULTS"
case "$DEFAULTS" in
  *forward_to_sfe*) echo "[i] Traffic reaches the stateful engine. If logs stopped, the LOGGING path was used — Step 2." ;;
  *)                echo "[FAIL] Stateless defaults do not forward to the stateful engine. The POLICY path was used:"
                    echo "       inspection is off as well as logging, and the dashboards look healthy. Step 3." ;;
esac
```

#### Step 2 — Restore the logging configuration

```bash
REGION="us-east-1"
FW="<firewall-name>"
LOG_GROUP_ALERT="/aws/network-firewall/alert"
LOG_GROUP_FLOW="/aws/network-firewall/flow"

aws network-firewall update-logging-configuration --firewall-name "$FW" --region "$REGION" \
  --logging-configuration "LogDestinationConfigs=[
    {LogType=ALERT,LogDestinationType=CloudWatchLogs,LogDestination={logGroup=$LOG_GROUP_ALERT}},
    {LogType=FLOW,LogDestinationType=CloudWatchLogs,LogDestination={logGroup=$LOG_GROUP_FLOW}}]" \
  --output json | jq -r '[.LoggingConfiguration.LogDestinationConfigs[].LogType] | "[OK] logging restored: " + join(",")'
```

The call replaces the whole configuration, so **every** log type must be listed — submitting only
the missing one removes the others. That is the same property that makes a partial removal
invisible, working against you during the fix.

#### Step 3 — Restore stateful forwarding, if the policy path was used

```bash
REGION="us-east-1"
POLICY="<firewall-policy-arn>"

echo "[i] Review the current policy before changing it — this call also replaces the whole object:"
aws network-firewall describe-firewall-policy --firewall-policy-arn "$POLICY" --region "$REGION" \
  --output json | jq '.FirewallPolicy'
echo
echo "[!] Restoring aws:forward_to_sfe sends traffic back through the stateful engine, which will"
echo "    begin DROPPING whatever the stateful rules drop. That is the correct state and it may be"
echo "    a visible change in behaviour — confirm with the service owner rather than discovering it."
```

Emitted for review rather than executed. Re-enabling inspection is a functional change as well as a
security one, and doing it blind during an incident risks trading a logging gap for an outage.

#### Step 4 — Size the gap and contain the principal

The window from the change in Query 1 to confirmed delivery is unrecorded — and on the policy path
it is also uninspected, which is the larger loss. Record the interval, mark conclusions about it as
unsupported, and contain the principal using the standard procedure in §3 Step 4 of
`../vpc.stealth.no-logs-from-amazon-vpc-flow-logs/`, which is identical and not restated here.

---

## 4. Eradication

### Remove Attacker Access

#### Bring every firewall to the standard configuration

Query 2's `[FAIL]` and `[!]` lines are the backlog. A firewall with no logging configuration at all
is more common than one that was tampered with, and it is the same gap.

#### Record the deliberate stateless decisions

Any policy that genuinely handles traffic statelessly should appear in the §1 baseline as a
decision with an owner. Undocumented, it is indistinguishable from this technique — and it is the
permanent false positive that makes absence monitoring unusable here.

#### Right-size who can change firewall configuration

`network-firewall:UpdateLoggingConfiguration` and `UpdateFirewallPolicy` belong to an
infrastructure role. Query 4's principal is the starting point.

#### Confirm delete protection is on

`UpdateFirewallDeleteProtection` disabling protection frequently precedes a deletion. Turning it
back on is one call and removes the fastest path to losing the firewall entirely.

---

## 5. Recovery

### Restore Clean State

#### Verify every firewall logs and inspects

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  for FW in $(aws network-firewall list-firewalls --region "$REGION" --output json 2>/dev/null | \
              jq -r '.Firewalls[].FirewallName'); do
    T=$(aws network-firewall describe-logging-configuration --firewall-name "$FW" --region "$REGION" \
        --output json 2>/dev/null | jq -r '[.LoggingConfiguration.LogDestinationConfigs[]?.LogType] | length')
    P=$(aws network-firewall describe-firewall --firewall-name "$FW" --region "$REGION" \
        --output text --query 'Firewall.FirewallPolicyArn' 2>/dev/null)
    D=$(aws network-firewall describe-firewall-policy --firewall-policy-arn "$P" --region "$REGION" \
        --output json 2>/dev/null | jq -r '.FirewallPolicy.StatelessDefaultActions | join(",")')
    [ "${T:-0}" -ge 2 ] || echo "[FAIL] $REGION $FW has ${T:-0} log type(s)"
    case "$D" in *forward_to_sfe*) ;; *) echo "[FAIL] $REGION $FW stateless defaults: $D" ;; esac
  done
done
echo "[i] no [FAIL] lines above means every firewall logs both types and forwards to the stateful engine"
```

#### Verify delivery, not configuration

Re-run Query 3 for each firewall. A configuration with no recent stream or object is the failure
mode with no event behind it.

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire at high on:"
echo "  eventName=UpdateLoggingConfiguration with logDestinationConfigs = []"
echo "  (an empty list IS the removal — there is no delete verb for this)"
echo "and MUST fire at high on the path the source rule does not consider:"
echo "  eventName=UpdateFirewallPolicy with statelessDefaultActions=['aws:drop']"
echo "  (logging configuration untouched, dashboards green, nothing inspected or recorded)"
echo "The rule MUST NOT fire at high on:"
echo "  UpdateLoggingConfiguration carrying both ALERT and FLOW destinations by the provisioning role"
echo "and note there is NO synthetic test for a partial removal — the event carries the surviving"
echo "  types, so that case is a state comparison and needs the stored snapshot from §1."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| Logging stopped and the alert did not fire, or was ignored | An account-wide absence rule that also fires permanently on any policy handling traffic statelessly |
| Nobody could say which log type was removed | `UpdateLoggingConfiguration` records the surviving types, and no snapshot history existed to compare against |
| The policy path was not covered at all | The rule watched the logging configuration; changing stateless defaults achieves the same thing and leaves the dashboards green |
| A firewall was in service with no logging | No provisioning check required a logging configuration at creation |
| Delivery failure would have been invisible | There is no Network Firewall event for delivery starting to fail, and no scheduled destination check existed |

### Recommended Guardrails

**Fence firewall logging and policy configuration**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["network-firewall:UpdateLoggingConfiguration",
             "network-firewall:UpdateFirewallPolicy",
             "network-firewall:DeleteFirewall",
             "network-firewall:UpdateFirewallDeleteProtection"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Configure both log types in the provisioning module, so a firewall cannot enter service without
  them. Logging is enabled after creation, so the default is off.
- Snapshot `describe-logging-configuration` and `describe-firewall-policy` on a schedule and keep
  the history. It is the only way to identify a partial removal, because the event stream
  structurally cannot.
- Record every deliberate stateless-handling decision with an owner. Undocumented, it is
  indistinguishable from this technique and it is what makes absence monitoring unusable here.
- Keep log destinations in a separate account. Stopping the logging and destroying it should
  require different access.

**Detection improvements**
- Alert on the control-plane calls, not on absence. In this service a valid configuration is
  permanently silent, so absence is not merely ambiguous — it has a standing false positive.
- Cover the firewall-policy path alongside the logging path. It is quieter, strictly worse, and
  leaves every dashboard reporting healthy.
- Alert on a firewall with no logging configuration as a standing coverage check, independent of
  any event. That finds the firewall nobody configured, which the event stream never will.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log |
| MITRE tactic | Defense Impairment (TA0112) |
| Primary API | `network-firewall:UpdateLoggingConfiguration` with an empty destination list; `UpdateFirewallPolicy` removing `aws:forward_to_sfe` |
| Event source | network-firewall.amazonaws.com |
| Key discriminator | An empty `logDestinationConfigs` in the request, or `statelessDefaultActions` without `aws:forward_to_sfe` |
| Ground-truth signal | `describe-logging-configuration` and `describe-firewall-policy` — live state, and the only way to resolve a partial removal |
| "Was it used" pivot | The gap between the change and the restoration, and the alert records immediately preceding it — those are the last that exist |
| Blast radius | Every `netfw.*` detection. On the policy path, also the inspection itself: that traffic is neither examined nor recorded |
| Error strings | None on the calls themselves. A failing delivery produces **no event at all** — its only symptom is the absence of new streams or objects |

**MITRE mapping note:** `T1685.002` is the correct current identifier. Verified live 2026-08-30.

### Residual Risk

The window between the change and the restoration is unrecorded, and on the firewall-policy path it
is also **uninspected** — the traffic was neither examined nor logged, so there is no basis for any
statement about it in either direction. If the removal was partial, its start date is knowable only
if a snapshot existed beforehand; the event stream records what survived and never what went. A
firewall found with no logging configuration at all has no history rather than a gap. And unlike the
VPC and DNS cases, GuardDuty is unaffected here — it does not consume these logs — which means its
silence over the period is genuinely uninformative rather than misleadingly reassuring.
