# IR Playbook: High-Severity Firewall Alert Not Blocked — a severity-1 stateful signature in the `alert` log that the policy let through

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Detection triage (a top-severity network signature fired and the traffic proceeded) |
| Threat Actor | N/A — signature-driven, not actor-attributed |
| Platform | aws |
| Severity | High when the traffic was not blocked. Severity 1 in Suricata's inverted scale is the most severe level, and a rule at that level firing without a drop means either the rule is in alert-only mode or a pass is ordered ahead of it — both of which are configuration findings as much as traffic findings. |
| MITRE Tactics | Command and Control |
| MITRE Techniques | T1071 |
| Services in Scope | AWS Network Firewall, VPC, CloudWatch, CloudTrail |

**What the technique does:** this playbook is triage structure rather than one attack. A severity-1
signature covers exploitation attempts, command-and-control protocols, known-malicious
infrastructure and credential theft in transit — the signature name in the record is what
identifies the technique, and the response follows from that. What is common to all of them is the
question this playbook answers first: **did the firewall stop it, and if not, why not.**

**Why the usual reflexes miss it.** The reflex is to alert only on traffic that was not blocked,
which is what the source rule does. That discards the blocked stream entirely — and with it the
ability to tell "nobody is attacking us" from "everything is being blocked", and the probing run-up
in which an actor is refused repeatedly before finding a path that passes. The second reflex is to
read the alert log as a record of what the firewall saw, and it is not: only `DROP`, `ALERT` and
`REJECT` produce entries, and traffic the *stateless* engine handled produces nothing at all.

**Detection thesis:** keep both streams and separate them by severity of routing rather than by
filter. The unblocked severity-1 alert goes to a person; the blocked stream goes to a dashboard
where its volume — and its sudden absence — remain visible.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **Alert logging enabled on every firewall**, and flow logging alongside it. Logging is configured
  after the firewall is created and per log type, so a firewall existing implies nothing.
  `../netfw.stealth.no-logs-from-aws-network-firewall-in-4-hours/` covers its absence.
- **The policy's stateless rules documented**, because traffic they handle is invisible in every
  log this playbook reads. The set of traffic forwarded to the stateful engine is the set this
  detection can see, and that is a policy decision made in advance.
- **TLS inspection where the workload permits it.** Without it, an alert on an encrypted flow
  matched the envelope only, and `tls_inspected` is absent rather than false.
- **CloudTrail management events for `network-firewall.amazonaws.com`**, particularly
  `UpdateFirewallPolicy` and `UpdateRuleGroup` — a rule moving from `DROP` to `ALERT` is how a
  severity-1 signature starts passing traffic.

**Alerting (must be pre-configured)**
- **A severity-1 alert with `alert.action: allowed` → P0**
- **`alert.action: allowed` while `verdict.action: drop` — the two fields disagreeing → P1**
- **One source matching five or more distinct severity-1 signature IDs in an hour → P1**
- **A rule group changing a severity-1 rule's action from `DROP` to `ALERT` → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- The rule group inventory with which groups are in alert-only evaluation mode and until when. The
  most common cause of this alert is an evaluation that nobody ended.

**Known IOC Baselines**
- Your own vulnerability scanners' source addresses and schedules. They are the single most likely
  cause of the signature-breadth correlation firing.
- Which rule groups are managed and which are custom, since the response differs — a managed group
  in alert mode is a policy decision, a custom one may be a mistake.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `event.alert.severity: 1` with `event.alert.action: allowed` | Network Firewall alert logs | T1071 |
| P0 | Severity-1 alerts from one source across ≥ 5 distinct `signature_id` values, unblocked | Network Firewall alert logs | T1190 |
| P1 | `alert.action: allowed` while `verdict.action: drop` on the same record | Network Firewall alert logs | T1071 |
| P1 | `UpdateRuleGroup` or `UpdateFirewallPolicy` changing a severity-1 rule's action away from `DROP` | CloudTrail (`network-firewall`) | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | One source matching ≥ 5 distinct severity-1 signatures, all blocked | Network Firewall alert logs (correlation) | T1190 |
| P2 | A severity-1 alert on a flow where `tls_inspected` is absent — the envelope was matched, not the payload | Network Firewall alert logs | T1573 |
| P3 | Sustained blocked severity-1 volume, and any sudden stop in it | Network Firewall alert logs | T1190 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Filters out everything the firewall blocked | Removes the ability to distinguish "nobody is attacking us" from "everything is being blocked", and discards the run-up in which an actor is refused repeatedly before finding a path that passes | Both streams kept, separated by **rule level** — unblocked at high to a person, blocked at low to a dashboard — so routing is explicit and the second stream survives |
| `action:"allowed" OR NOT action:"blocked"` is redundant | The field takes `allowed` or `blocked`, so the expression reduces to `allowed` plus records where the field is absent. It reads as a considered condition and is not one | Match `allowed` positively; handle absence deliberately rather than by accident |
| Reads only `alert.action`, never `verdict.action` | AWS's examples carry both, and where they disagree the **verdict** is the packet's fate. A rule reading only the alert's report can be confidently wrong about what happened | Both projected in the KQL with an explicit `Disagree` counter, and the disagreement given its own trigger |
| Companion medium rule has empty `group_by` and threshold zero | Every individual alert pages, with no aggregation and no actor. The rule that fires most is muted first | Group by source address; the correlation counts distinct signatures, which is what separates an actor from one noisy rule |
| Nothing accounts for the stateless engine | AWS: *"Firewall logging is only available for traffic that you forward to the stateful rules engine."* Traffic a stateless rule dropped produces **no log of any kind**, so absence of an alert is not evidence of absence of traffic | Stated in the rules and the note, and §1 asks for the stateless policy to be documented — it defines what this detection can see at all |
| Treats the alert log as complete coverage | Only `DROP`, `ALERT` and `REJECT` produce alert entries. A `PASS` rule produces none, so traffic matching an explicit pass is in the flow log and nowhere here | Stated wherever a count appears; the flow log is named as the other half |
| Severity mapping | **Correct** — the pack maps Suricata's inverted scale properly (1 = most severe). Recorded as a row because a reviewer's instinct is to reverse it, and doing so would invert the whole hierarchy silently | No change. Documented in the rule header so the next person does not "fix" it |

**Recommended detection — both streams, separated by routing rather than by filter.**

```yaml
# High-severity stateful firewall alert on traffic that was not blocked (T1071 / T1190)
#
# SURICATA SEVERITY IS INVERTED AND THE SOURCE PACK GETS THIS RIGHT. severity 1 is the MOST severe,
# ascending to less severe. The source rules map 1 to high, 2 to medium and 3/4 to low, which is
# correct — stated here explicitly because a reviewer's instinct is to "fix" it in the wrong
# direction, and doing so would silently invert the entire alert hierarchy.
#
# THE ACTION FILTER DISCARDS HALF THE PICTURE. The source rule keeps only
# `action:"allowed" OR NOT action:"blocked"` — so a high-severity signature that the firewall
# BLOCKED never fires. That is defensible for paging and wrong for situational awareness: it
# removes the ability to distinguish "nobody is attacking us" from "everything is being blocked",
# and it hides the run-up in which an attacker probes and is refused before finding something that
# passes. The corrected set keeps both and separates them by rule level rather than by filter, so
# the blocked stream goes to a dashboard and the unblocked stream to a person.
#
# `verdict.action` IS THE PACKET'S FATE; `alert.action` IS THE RULE'S REPORT. AWS's own examples
# carry `"action":"allowed"` on one record and `"action":"blocked"` with `"verdict":{"action":"drop"}`
# on another. Where both are present and disagree, the verdict is what happened. The rules below
# read alert.action because it is the field the source rule uses and the one always present, and
# the KQL projects both so a responder can see a disagreement rather than inherit one.
#
# ONLY DROP, ALERT AND REJECT PRODUCE ALERT LOGS. AWS: "A stateful rule sends alerts for the rule
# actions DROP, ALERT, and REJECT." A `PASS` rule produces no alert entry at all, so the alert log
# is a filtered view by design and never a record of everything the firewall saw. Anything reading
# it as complete coverage is reading a subset.
#
# AND THE STATELESS ENGINE IS INVISIBLE HERE. AWS: "Firewall logging is only available for traffic
# that you forward to the stateful rules engine." Traffic a stateless rule dropped produces no log
# of any kind. The absence of an alert is therefore not evidence the traffic did not arrive — it
# may have been handled before the stateful engine ever saw it.
#
# `group_by: []` ON THE SOURCE MEDIUM RULE WITH A THRESHOLD OF ZERO means every single alert pages,
# with no aggregation and no actor. The correlation below groups by source address and signature,
# which is the pair that distinguishes one noisy signature from one determined host.
title: High-severity stateful rule alert, not blocked
id: 6b3d2f81-95a4-4c07-b6e2-71095fa3d84c
name: netfw_high_severity_unblocked
status: experimental
description: >-
  A stateful rule with Suricata severity 1 — the most severe level — alerted on traffic the firewall
  did not block. This is the case that needs a person: the signature fired and the packet
  proceeded, either because the rule's action was ALERT rather than DROP or because the policy
  ordered a pass ahead of it. Read aws_metadata.resource_arn to identify which rule group produced
  it; that is the fastest route to whether the pass was intended.
references:
  - https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-logging-contents.html
  - https://attack.mitre.org/techniques/T1071/
tags:
  - attack.command-and-control
  - attack.t1071
logsource:
  product: aws
  service: networkfirewall
detection:
  alert_event:
    event.event_type: 'alert'
  most_severe:
    event.alert.severity: 1
  not_blocked:
    event.alert.action: 'allowed'
  condition: alert_event and most_severe and not_blocked
falsepositives:
  - >-
    A managed rule group running in alert-only mode during evaluation, which is the normal way to
    introduce one. Expect volume for as long as that lasts; the finding is a severity-1 signature
    still in alert mode after the evaluation period ended.
level: high
---
title: High-severity stateful rule alert, blocked
id: e0715a3c-4826-4d9f-83b1-2c690847ef52
name: netfw_high_severity_blocked
status: experimental
description: >-
  The same signature and severity, blocked. Shipped at low and deliberately kept rather than
  filtered away: the source rule discards these entirely, which removes the ability to distinguish
  "nobody is attacking" from "everything is being blocked", and hides the probing run-up in which an
  attacker is refused repeatedly before finding a path that passes. Route to a dashboard, not to a
  person — and note that a sudden stop in this stream is itself worth reading, because it means
  either the attacker left or the blocking did.
references:
  - https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-logging-contents.html
  - https://attack.mitre.org/techniques/T1071/
tags:
  - attack.command-and-control
  - attack.t1071
logsource:
  product: aws
  service: networkfirewall
detection:
  alert_event:
    event.event_type: 'alert'
  most_severe:
    event.alert.severity: 1
  blocked:
    event.alert.action: 'blocked'
  condition: alert_event and most_severe and blocked
falsepositives:
  - >-
    Background internet scanning against a public endpoint, continuously. That is what this stream
    mostly is, which is why it is at low and why its VOLUME rather than its presence is the signal.
level: low
---
title: One source triggering many distinct high-severity signatures
id: 9c48b607-13ae-4520-9f7d-58e2c130ba69
status: experimental
description: >-
  A single source address matched an unusual number of DISTINCT severity-1 signatures. Signature
  breadth separates a determined actor from a noisy rule: an ordinary scanner trips the same
  signature repeatedly, while an actor working through an estate trips different ones as they move
  through reconnaissance, exploitation and command-and-control. group-by is the source address
  because that is the actor; the signatures are read off the matched records and tell you what they
  were trying.
references:
  - https://attack.mitre.org/techniques/T1190/
tags:
  - attack.initial-access
  - attack.t1190
correlation:
  type: value_count
  rules:
    - netfw_high_severity_blocked
  group-by:
    - event.src_ip
  timespan: 1h
  condition:
    field: event.alert.signature_id
    gte: 5
falsepositives:
  - >-
    A vulnerability scanner you own, which trips many signatures by design and is the single most
    likely cause of this firing. Exclude by source address, and confirm the schedule matches.
level: medium
```

What this set structurally cannot do: it cannot see traffic the stateless engine handled, it cannot
see traffic that matched a `PASS` rule, and where `tls_inspected` is absent it matched the envelope
rather than the payload. All three mean the same thing — the alert log is a view of what the policy
chose to inspect, and never a record of what arrived.

---

### Key Investigation Queries

> Queries 1 and 2 read the alert logs, most often through CloudWatch Logs Insights over the
> configured log group. Field names follow `../_ground-truth/netfw.md` §3. Queries 3 and 4 read the
> Network Firewall and CloudTrail APIs.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: what fired, from where, and was it stopped

```bash
REGION="us-east-1"
LOG_GROUP="/aws/network-firewall/alert"
SRC="<src-ip-from-the-alert>"
START=$(date -u -v-24H +%s 2>/dev/null || date -u -d '24 hours ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string "fields @timestamp, event.alert.severity, event.alert.signature,
                         event.alert.signature_id, event.alert.action, event.verdict.action,
                         event.src_ip, event.dest_ip, event.dest_port, event.app_proto,
                         event.tls.sni, event.http.hostname, event.aws_metadata.resource_arn
                  | filter event.src_ip = '${SRC}' and event.event_type = 'alert'
                  | sort @timestamp asc
                  | limit 500")

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'
```

Read it in order. A run of `blocked` records followed by an `allowed` one is the shape that
matters — the actor probed, was refused, and found a path. That sequence is exactly what the source
rule's filter discards, since it keeps only the last record and drops the story leading to it.
`aws_metadata.resource_arn` on the `allowed` record names the rule group that let it through.

#### Query 2 — Sweep: which signatures are passing traffic, estate-wide

```bash
REGION="us-east-1"
LOG_GROUP="/aws/network-firewall/alert"
START=$(date -u -v-24H +%s 2>/dev/null || date -u -d '24 hours ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string 'fields event.alert.severity, event.alert.signature_id, event.alert.signature,
                         event.alert.action, event.aws_metadata.resource_arn, event.src_ip
                  | filter event.event_type = "alert" and event.alert.severity <= 2
                  | stats count() as alerts,
                          count_distinct(event.src_ip) as sources
                          by `event.alert.signature_id`, `event.alert.signature`,
                             `event.alert.action`, `event.aws_metadata.resource_arn`
                  | sort alerts desc
                  | limit 100')

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'
```

Any row with `action = allowed` and `severity = 1` is a signature that is not stopping anything.
Group them by `resource_arn`: if they all come from one rule group, that group is in alert-only
mode and this is one configuration finding rather than many traffic findings.

#### Query 3 — Inspect: what the policy actually does with this traffic

```bash
REGION="us-east-1"
FIREWALL_NAME="<firewall-name>"

POLICY=$(aws network-firewall describe-firewall --firewall-name "$FIREWALL_NAME" --region "$REGION" \
  --output text --query 'Firewall.FirewallPolicyArn')
echo "[i] policy: $POLICY"

echo
echo "== stateless actions decide what the stateful engine — and therefore the log — ever sees =="
aws network-firewall describe-firewall-policy --firewall-policy-arn "$POLICY" --region "$REGION" \
  --output json | jq -r '.FirewallPolicy |
    "stateless default:          \(.StatelessDefaultActions | join(","))
stateless fragment default: \(.StatelessFragmentDefaultActions | join(","))
stateful default:           \((.StatefulDefaultActions // []) | join(",") )
stateful rule order:        \(.StatefulEngineOptions.RuleOrder // "DEFAULT_ACTION_ORDER")"'

echo
echo "[!] Any stateless action that is not aws:forward_to_sfe means that traffic NEVER reaches the"
echo "    stateful engine and produces NO log entry at all — not an alert, not a flow record."

echo
echo "== rule groups, and their order =="
aws network-firewall describe-firewall-policy --firewall-policy-arn "$POLICY" --region "$REGION" \
  --output json | jq -r '.FirewallPolicy.StatefulRuleGroupReferences[]? |
    "priority=\(.Priority // "-")  override=\(.Override.Action // "none")  \(.ResourceArn)"'
echo "[!] An Override action of DROP_TO_ALERT converts every DROP in a managed group to ALERT."
echo "    That is the single most common reason a severity-1 signature passes traffic."
```

#### Query 4 — Full session reconstruction of who changed the policy

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in UpdateFirewallPolicy UpdateRuleGroup AssociateFirewallPolicy UpdateLoggingConfiguration; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       target: (.requestParameters.firewallPolicyName // .requestParameters.ruleGroupName // .requestParameters.firewallName // "-"),
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'sort_by(.time)'
```

A signature that used to block and now alerts is a policy change, and this finds it. The most
common benign explanation is a managed rule group added with a `DROP_TO_ALERT` override for
evaluation — which is correct practice and becomes a finding when the evaluation never ends.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**The response depends on the signature**, so the first step is to read it rather than to act. What
this playbook standardises is the decision: was the traffic stopped, and if not, was that intended.

> Run every command under the **break-glass responder credentials** from §1.

#### Step 1 — Establish whether the traffic was actually stopped

```bash
ALERT_ACTION="<event.alert.action-from-Query-1>"
VERDICT="<event.verdict.action-from-Query-1>"

if [ "$VERDICT" = "drop" ]; then
  echo "[OK] verdict=drop — the packet was dropped whatever alert.action reported."
  echo "     This is a blocked attempt. Record it, and read the run-up in Query 1 for what came next."
elif [ "$ALERT_ACTION" = "allowed" ]; then
  echo "[FAIL] the traffic PROCEEDED. Steps 2 and 3 apply."
  echo "       Establish whether the rule is in alert mode by design (Query 3's Override) or"
  echo "       whether a pass rule is ordered ahead of it."
else
  echo "[!] alert.action=$ALERT_ACTION verdict=$VERDICT — read the raw record before acting."
fi
```

The two fields answer different questions and AWS populates both. Acting on `alert.action` alone is
how a responder concludes traffic passed when the verdict says it was dropped.

#### Step 2 — If it passed: find out why, before changing anything

Query 3's output answers this in one read. A rule group reference carrying an `Override` action of
`DROP_TO_ALERT` converts every `DROP` in that group to `ALERT` — which is the correct way to
evaluate a managed rule group, and a finding when the evaluation was never ended. If there is no
override, the rule's own action is `ALERT`, or a pass rule sits ahead of it in the policy's order.

Changing the policy before knowing which is a good way to cause an outage while responding to an
alert.

#### Step 3 — Block the specific traffic without rewriting the policy

```bash
REGION="us-east-1"
RULE_GROUP_ARN="<ir-block-rule-group-arn>"
SRC="<src-ip-from-Query-1>"

if ! aws network-firewall describe-rule-group --rule-group-arn "$RULE_GROUP_ARN" --region "$REGION" >/dev/null 2>&1; then
  echo "[FAIL] IR rule group $RULE_GROUP_ARN not found — a small, high-priority, initially-empty"
  echo "       stateful group is the §1 prerequisite that makes this step one call instead of a"
  echo "       policy rewrite. Create it before the next incident."
else
  echo "[i] Add a drop rule for $SRC to the IR rule group and confirm its priority is ahead of"
  echo "    any pass rule. Review the rule text before applying — a malformed Suricata rule is"
  echo "    rejected at update time, which is a safe failure, but a too-broad one is not."
  aws network-firewall describe-rule-group --rule-group-arn "$RULE_GROUP_ARN" --region "$REGION" \
    --output json | jq -r '.RuleGroup.RulesSource.RulesString // "<no rules string — stateful rules are defined elsewhere in this group>"'
fi
```

A narrow drop in a dedicated incident rule group is reversible and auditable. Editing the managed
policy under time pressure is neither.

#### Step 4 — Treat the destination as reached

If the traffic passed, whatever it was aimed at received it. Move to the host or service at
`event.dest_ip` — the firewall's job is finished and the incident is now wherever the packet
landed. `event.http.url`, `event.http.hostname` and `event.tls.sni` in the record tell you what was
requested.

---

## 4. Eradication

### Remove Attacker Access

#### End the evaluations that never ended

Query 2's `severity = 1, action = allowed` rows grouped by `resource_arn` are the backlog. Each is a
rule group whose drops are being converted to alerts. Remove the override, or record a decision with
a date — an indefinite evaluation is a permanent gap wearing a temporary label.

#### Close the stateless blind spot deliberately

Query 3's stateless default actions determine what the stateful engine — and therefore every rule
in this service — ever sees. `aws:forward_to_sfe` is what makes traffic inspectable. Anything else
is a decision to handle traffic without logging it, and it should be a recorded decision rather than
an inherited default.

#### Enable TLS inspection where the workload permits

Without it, every alert on an encrypted flow matched the envelope. That is a real limit on this
entire log source and closing it changes what all the other `netfw.*` rules can see.

#### Remove the emergency rule once clean

The IR rule group entry should be removed or promoted to the permanent policy with a note. A
forgotten drop rule becomes an unexplained connectivity failure later.

---

## 5. Recovery

### Restore Clean State

#### Verify no severity-1 rule group is passing traffic by configuration

```bash
REGION="us-east-1"
FIREWALL_NAME="<firewall-name>"
POLICY=$(aws network-firewall describe-firewall --firewall-name "$FIREWALL_NAME" --region "$REGION" \
  --output text --query 'Firewall.FirewallPolicyArn')

OVERRIDES=$(aws network-firewall describe-firewall-policy --firewall-policy-arn "$POLICY" \
  --region "$REGION" --output json | \
  jq '[.FirewallPolicy.StatefulRuleGroupReferences[]? | select(.Override.Action != null)] | length')
[ "$OVERRIDES" -eq 0 ] && echo "[OK] no rule group is overridden to alert-only" \
                       || echo "[FAIL] $OVERRIDES rule group(s) still overridden — every DROP in them is an ALERT"
```

#### Verify the stateless policy forwards what you think it forwards

```bash
REGION="us-east-1"
POLICY="<firewall-policy-arn>"
DEFAULTS=$(aws network-firewall describe-firewall-policy --firewall-policy-arn "$POLICY" \
  --region "$REGION" --output json | jq -r '.FirewallPolicy.StatelessDefaultActions | join(",")')
case "$DEFAULTS" in
  *forward_to_sfe*) echo "[OK] stateless default forwards to the stateful engine — traffic is inspectable and logged" ;;
  *)                echo "[FAIL] stateless default is '$DEFAULTS' — that traffic never reaches the stateful engine and produces NO log" ;;
esac
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire at high on:"
echo "  event.event_type=alert  event.alert.severity=1  event.alert.action=allowed"
echo "and MUST also produce a record at low on:"
echo "  the same alert with event.alert.action=blocked"
echo "  (the source rule discards this entirely, losing the probing run-up)"
echo "The rule MUST NOT fire at high on:"
echo "  event.alert.severity=3  (Suricata severity is INVERTED — 3 is LOW, and treating it as"
echo "  high is the error a reviewer introduces while 'fixing' the mapping)"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A severity-1 signature alerted and the traffic proceeded | A rule group override converted its `DROP` to `ALERT`, and the evaluation period was never ended |
| The probing run-up was invisible | The rule filtered out blocked alerts, so only the successful attempt was recorded |
| A responder concluded traffic passed when it was dropped | Only `alert.action` was read; `verdict.action` is the packet's actual fate |
| Some traffic produced no log at all | Stateless rules handled it, and AWS only logs traffic forwarded to the stateful engine |
| Alerts on encrypted flows carried no payload evidence | TLS inspection was not configured, and `tls_inspected` is omitted rather than false |

### Recommended Guardrails

**Keep the firewall policy out of general deploy credentials**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["network-firewall:UpdateFirewallPolicy", "network-firewall:UpdateRuleGroup",
             "network-firewall:UpdateLoggingConfiguration", "network-firewall:DeleteFirewall"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Give every rule group override an explicit end date and review them on that date. An evaluation
  with no end is a permanent gap labelled temporary, and it is the most common cause of this alert.
- Set stateless default actions to `aws:forward_to_sfe` unless there is a recorded reason not to.
  Anything else handles traffic without producing any log at all.
- Keep a small, high-priority, empty stateful rule group for incident use. It turns containment into
  one call rather than a policy rewrite under time pressure.
- Enable TLS inspection where the workload allows. It is the difference between matching the
  envelope and matching the payload, across every rule in this service.

**Detection improvements**
- Keep the blocked stream. Filtering it out removes the ability to distinguish quiet from
  successfully-defended, and discards the sequence that precedes a successful attempt.
- Read `verdict.action` as well as `alert.action`, and alert on the two disagreeing. They answer
  different questions and AWS populates both.
- Count distinct signatures per source, not alerts. Breadth separates an actor from a noisy rule;
  volume does not.
- Document the severity inversion next to the rule. It is correct in this pack and it is exactly the
  kind of thing a later reviewer silently reverses.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1071 — Application Layer Protocol |
| MITRE tactic | Command and Control (TA0011); the breadth correlation is Initial Access (TA0001) |
| Primary API | None — the technique is network traffic. The relevant control-plane calls are `network-firewall:UpdateFirewallPolicy` and `UpdateRuleGroup` |
| Event source | AWS Network Firewall alert logs (Suricata EVE JSON) |
| Key discriminator | `event.alert.severity: 1` with `event.alert.action: allowed` — a top-severity signature whose traffic proceeded |
| Ground-truth signal | `event.verdict.action` for the packet's fate, and `describe-firewall-policy` for whether the pass was configured |
| "Was it used" pivot | The destination. If the traffic passed, the incident is at `event.dest_ip`, and `event.http.url` or `event.tls.sni` says what was requested |
| Blast radius | Whatever the destination host or service exposes. The firewall's role ends where the packet lands |
| Error strings | Not applicable. `alert.action` takes `allowed` or `blocked`; `verdict.action` takes `drop`. Suricata severity is 1 (most severe) ascending |

**MITRE mapping note:** the source pack maps this rule to **nothing at all**. `T1071 — Application
Layer Protocol` is the tactic-level anchor for the command-and-control shape most severity-1
signatures carry, with `T1190` on the breadth correlation, which observes an actor working through
an estate rather than one signature firing. A severity-based rule spans many techniques by
construction — the signature name in the record is what identifies the technique for any particular
alert, and these mappings are anchors rather than claims about it. Both verified live 2026-08-30.

### Residual Risk

The alert log describes the traffic the policy chose to inspect and never the traffic that arrived.
Anything the stateless engine handled produced no record of any kind, so the absence of an alert for
a given flow is not evidence the flow did not happen. Anything matching a `PASS` rule produced no
alert entry either. And where `tls_inspected` is absent, the signature matched the envelope of an
encrypted session — a clean result there means the envelope looked clean and nothing more. If the
traffic passed, the destination received it, and no action taken at the firewall afterwards changes
what already arrived.
