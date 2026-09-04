# IR Playbook: SYN Flood — sustained `protocol: 6` connection attempts consuming a target's capacity

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Impact / availability (a target's connection table or upstream capacity is exhausted by connection attempts that are never completed) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. Availability rather than confidentiality or integrity, but a saturated connection table takes a service down as completely as anything in this corpus, and the response window is minutes. The source rule's P1 rating is right; three of its four parameters are not. |
| MITRE Tactics | Impact |
| MITRE Techniques | T1498 |
| Services in Scope | VPC (flow logs, network ACLs, security groups), EC2, Elastic Load Balancing, AWS Shield, CloudWatch |

**What the technique does:** the attacker sends TCP SYN packets and never completes the handshake.
Each one costs the target a half-open connection slot held until timeout, and costs the attacker
almost nothing. Two shapes, and they are operationally different incidents. **Distributed**: many
thousands of sources, a few packets each, addresses usually spoofed — the aggregate is what hurts.
**Concentrated**: a handful of sources sending enormous volume — one link or one instance is
saturated. The first cannot be blocked by address; the second can, and quickly.

**Why the usual reflexes miss it.** The reflex is to count events, and a flow log record is not an
event — it is an *aggregate* over an interval carrying a `packets` field. One record can represent
a hundred thousand packets. A rule thresholding on record count measures how many distinct
5-tuples appeared, so it fires readily on a spoofed-source flood and can miss a single-source
flood that saturates the target entirely. The second reflex is to look for "SYN without ACK", and
AWS does not record ACK at all.

**Detection thesis:** sum packets, count distinct sources, and test *the SYN bit is set* rather
than a specific bitmask value — because AWS OR-s the flags across the aggregation interval and a
flood consists entirely of the short connections that produce OR-ed values.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **A flow-log subscription whose custom format includes `tcp-flags`, `pkt-srcaddr`,
  `pkt-dstaddr` and `flow-direction`.** `tcp-flags` is a version 3 field and the default format
  is version 2, so on a default subscription every flag-based rule here matches nothing. AWS:
  *"After you create a flow log, you can't change its configuration or the flow log record
  format... Instead, you can delete the flow log and create a new one."* This cannot be fixed
  during an incident.
- **A 1-minute maximum aggregation interval on internet-facing subnets.** The default is 10
  minutes, which puts the floor on detection latency at roughly 15 minutes and makes a
  fast-moving flood visible only after it has done its damage.
- **CloudWatch metrics for the target**: `ActiveConnectionCount`, `TargetResponseTime`,
  `HTTPCode_ELB_5XX_Count` and target health. Flow logs say what arrived; only these say whether
  the service degraded.
- **AWS Shield Advanced** where the workload justifies it. Its detection is independent of flow
  logs and it engages before an alert reaches a person.

**Alerting (must be pre-configured)**
- **500 or more distinct source addresses sending SYN-bit traffic to one target within 15 minutes → P0**
- **More than one million SYN-bit packets from five or fewer sources to one target within 15 minutes → P0**
- **A flow-log subscription without `tcp-flags` in its format — the flag-based detections cannot fire → P1**
- **Target health checks failing or load balancer 5xx rising while SYN volume is elevated → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- A **pre-authorised network ACL change procedure**. A NACL is stateless and evaluates before
  security groups, which makes it the right containment for a concentrated flood — and a change
  nobody is authorised to make at 03:00 is not a control.
- The Shield response team engagement path, if Advanced is subscribed, written down.

**Known IOC Baselines**
- The target's normal source-address set and its normal connection rate, from a quiet week. Source
  *familiarity* is what separates a flood from a launch, and it cannot be computed during one.
- Which endpoints are meant to be internet-facing at all. A flood against something that should
  never have been public is two findings, not one.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | ≥ 500 distinct `pkt-srcaddr` with the SYN bit set to one `pkt-dstaddr` in 15 minutes | VPC flow logs (correlation) | T1498 |
| P0 | > 1,000,000 summed `packets` with the SYN bit set from ≤ 5 sources to one target in 15 minutes | VPC flow logs | T1498 |
| P1 | A flow-log subscription whose format omits `tcp-flags` — every flag-based detection is silent | `describe-flow-logs` | T1498 |
| P1 | Target health checks failing, or load balancer 5xx rising, concurrent with elevated SYN volume | CloudWatch / ELB | T1498 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `log-status: SKIPDATA` present during the window — AWS dropped records, so every count is a floor | VPC flow logs | T1498 |
| P2 | Elevated SYN volume whose source set is familiar from the baseline — a surge rather than an attack | VPC flow logs | T1498 |
| P3 | Sustained outbound SYN volume from a VPC instance — your host participating in someone else's flood | VPC flow logs | T1498 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `tcp-flags: "2"` matched exactly | AWS OR-s the flags across the aggregation interval — *"19 for SYN-ACK and FIN, and 3 for SYN and FIN"*. A flood is nothing but short connections, so its records overwhelmingly carry OR-ed values. The rule matches the tidy minority and misses the flood it is named for | Test that the SYN bit is set: `binary_and(flags, 2) != 0`, or the enumerated set {2, 3, 6, 7, 18, 19, 22, 23} where a backend has no bitwise operator |
| Threshold of 999 on record count | A flow log record is an aggregate carrying `packets`; one record can represent a hundred thousand. The threshold measures distinct 5-tuples, so a spoofed-source flood clears it trivially and a single-source flood saturating a link may never reach it | Sum `packets` and count distinct sources. Two correlations, because the distributed and concentrated shapes have opposite signatures and one threshold cannot serve both |
| 5-minute window | The default maximum aggregation interval is 10 minutes and delivery is *"about 5 minutes"* to CloudWatch Logs, best effort. A 5-minute window sees zero buckets or one, so the count measures bucket alignment rather than traffic | 15 minutes, stated relative to the aggregation interval, shortenable only on a 1-minute subscription |
| `action: REJECT` only | Restricts the rule to floods the security group already absorbed. A flood that *reaches* the target and consumes its connection table is the incident, and it is ACCEPTed | Both actions matched; the accept-to-refuse ratio read as an indicator rather than used as a filter |
| `group_by: destination_ip` | Behind a Network Load Balancer, AWS shows *"the primary private IPv4 address"* of the interface rather than the target, so every destination collapses to the balancer and the alert names the wrong host — which during an availability incident routes the response to the wrong team | Group by `pkt-dstaddr`, a version 3 field, which is why §1 specifies the format |
| No handling of the field being absent | On a default-format subscription `tcp-flags` does not exist, and a rule reading it returns nothing. "No SYN traffic" and "this subscription cannot answer" are indistinguishable, and the second reads as an all-clear | The KQL carries a `FieldMissing` column with its own verdict line, and §1 makes the format a prerequisite rather than an assumption |

**Recommended detection — both shapes of the attack, measured in packets and in sources.**

```yaml
# SYN flood against a VPC endpoint (T1498)
#
# `tcp-flags` IS A VERSION 3 FIELD. The default flow-log format is version 2 and does not contain
# it, and AWS states the format is fixed for the life of the subscription: "After you create a
# flow log, you can't change its configuration or the flow log record format... Instead, you can
# delete the flow log and create a new one with the required configuration." Against a
# default-format subscription every rule in this file that reads tcp-flags matches nothing — not
# noisily, silently. The required custom format is in §1 of ../PLAYBOOK.md.
#
# THE BITMASK IS OR-ED ACROSS THE AGGREGATION INTERVAL, AND THIS BREAKS AN EXACT MATCH.
# AWS: "TCP flags can be OR-ed during the aggregation interval. For short connections, the flags
# might be set on the same line in the flow log record, for example, 19 for SYN-ACK and FIN, and
# 3 for SYN and FIN." A SYN flood is nothing but short connections, so its records carry SYN
# OR-ed with whatever else the flow saw. The source rule matches tcp-flags exactly 2 and therefore
# misses the majority of a real flood while matching the tidy minority. The correct test is THE
# SYN BIT IS SET, and with bit values FIN=1, SYN=2, RST=4, SYN-ACK=18 the reachable set is
# enumerated below rather than expressed as an arithmetic AND, because not every Sigma backend
# implements a bitwise operator.
#
# ACK IS NOT RECORDED AT ALL. AWS: "since tcp-flags does not support logging ACK or PSH flags,
# records for traffic with these unsupported flags will result in tcp-flags value 0." So
# "SYN without ACK" — the textbook half-open definition — describes a field that does not exist,
# and any rule phrased that way is matching on an absence that means nothing. The half-open
# character of a flood has to be inferred from packet counts and source fan-out instead, which is
# what the correlations below do.
#
# COUNTING RECORDS UNDER-MEASURES A FLOOD BY ORDERS OF MAGNITUDE. A flow log record is an
# AGGREGATE over an interval, carrying `packets` and `bytes`. One record can represent a hundred
# thousand packets. The source rule thresholds on 999 records in five minutes, which is a
# threshold on how many distinct 5-tuples appeared — a spoofed-source flood clears it trivially
# and a single-source flood may never reach it while saturating the target. Sum `packets`, and
# count distinct sources; do not count rows.
#
# THE WINDOW IS SHORTER THAN THE AGGREGATION INTERVAL. The default maximum aggregation interval is
# 10 minutes and delivery is "about 5 minutes" to CloudWatch Logs, best effort. A five-minute
# window sees zero buckets or one, so a count tuned against it is measuring bucket alignment
# rather than traffic. 15m is used below, with the note that it may be shortened only on a
# 1-minute (Nitro) subscription.
#
# `protocol` IS AN IANA NUMBER — 6 is TCP. `action` is uppercase ACCEPT or REJECT.
title: High-volume TCP SYN traffic to one destination
id: 5a2e91c7-6b40-4d18-93f5-8c07a1e2fb64
name: vpc_syn_volume
status: experimental
description: >-
  Base rule — correlation component. A TCP flow whose OR-ed flags carry the SYN bit. It fires on
  every connection attempt in the VPC, so it must never be routed anywhere on its own; it exists
  so the correlations below can sum packets and count sources over it. The enumerated flag set is
  every value in which bit 2 is set, given AWS's documented bit assignments and OR-ing behaviour.
references:
  - https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
  - https://attack.mitre.org/techniques/T1498/
tags:
  - attack.impact
  - attack.t1498
logsource:
  product: aws
  service: vpcflowlogs
detection:
  tcp_ingress:
    flow-direction: 'ingress'
    protocol: 6
  syn_bit_set:
    tcp-flags:
      - 2       # SYN
      - 3       # SYN + FIN
      - 6       # SYN + RST
      - 7       # SYN + FIN + RST
      - 18      # SYN-ACK
      - 19      # SYN-ACK + FIN
      - 22      # SYN-ACK + RST
      - 23      # SYN-ACK + FIN + RST
  condition: tcp_ingress and syn_bit_set
level: informational
---
title: SYN flood — sustained connection attempts from many sources to one target
id: e93b0f47-52ad-4c61-b8d0-71fa6e35c298
status: experimental
description: >-
  Many distinct sources sent SYN traffic to one destination inside the aggregation window. Source
  fan-out is the discriminator that separates a flood from a busy service: a popular endpoint has
  many clients but a stable set of them, while a flood's sources are drawn from a spoofed or
  botnet range and are mostly seen once. group-by is pkt-dstaddr rather than dstaddr because AWS
  states that for traffic to an interface whose destination is not one of that interface's
  addresses, the log shows "the primary private IPv4 address" — behind a Network Load Balancer
  every target collapses to the balancer's interface and the alert names the wrong host.
references:
  - https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
  - https://attack.mitre.org/techniques/T1498/
tags:
  - attack.impact
  - attack.t1498
correlation:
  type: value_count
  rules:
    - vpc_syn_volume
  group-by:
    - pkt-dstaddr
  timespan: 15m
  condition:
    field: pkt-srcaddr
    gte: 500
falsepositives:
  - >-
    A genuine traffic surge on a public endpoint — a launch, a campaign, a cache expiring across a
    large client base. Distinguished by whether the sources are ones you have seen before, which
    is a question for the investigation queries rather than for the rule.
level: high
---
title: SYN flood — a single source saturating one target
id: 1c74d8e0-3f92-40ab-95c6-2e08b47da531
status: experimental
description: >-
  The other shape of the same attack, and the one a source-fan-out rule cannot see. A single
  address, or a small set, sending enormous packet volume to one destination. This counts PACKETS
  rather than records, because a flow log record is an aggregate — one record can represent a
  hundred thousand packets, so a threshold on record count measures how many distinct 5-tuples
  appeared and not how much traffic arrived. The two correlations together cover both the
  distributed and the concentrated form; either alone leaves half the technique undetected.
references:
  - https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
  - https://attack.mitre.org/techniques/T1498/
tags:
  - attack.impact
  - attack.t1498
correlation:
  type: event_count
  rules:
    - vpc_syn_volume
  group-by:
    - pkt-dstaddr
    - pkt-srcaddr
  timespan: 15m
  condition:
    gte: 2000
falsepositives:
  - >-
    A load generator or a synthetic monitoring service running against your own endpoint. Named,
    scheduled and allowlistable by source address; the schedule is the giveaway.
  - >-
    This counts flow RECORDS per source-destination pair, which is a proxy for volume rather than
    volume itself. The packet-level view is in kql_t1498.kql, which sums `packets` directly —
    Sigma correlations have no summation operator, and the difference is stated rather than
    papered over.
level: high
```

What this set structurally cannot do: it cannot tell you whether the handshake completed, because
ACK is not a recorded flag — the half-open character is inferred from packets-per-source and
labelled as an inference. It cannot tell you whether the source addresses are real, because a SYN
flood spoofs them by design. And it cannot tell you the service degraded; that is CloudWatch, and
Query 3 goes there.

---

### Key Investigation Queries

> Query 1 reads **CloudWatch Logs Insights**, which auto-discovers flow log fields in
> **camelCase** (`pktSrcAddr`, `pktDstAddr`, `tcpFlags`, `action`, `logStatus`, `flowDirection`)
> while the record format uses hyphens. Queries 2–4 read the EC2, ELB and CloudWatch APIs.

#### Query 1 — Reconstruct: the shape of the traffic against this target

```bash
REGION="us-east-1"
LOG_GROUP="/aws/vpc/flowlogs"
TARGET="<target-private-ip>"
START=$(date -u -v-6H +%s 2>/dev/null || date -u -d '6 hours ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string "fields @timestamp, pktSrcAddr, dstPort, tcpFlags, action, packets, bytes
                  | filter pktDstAddr = '${TARGET}' and protocol = 6
                  | filter flowDirection = 'ingress' and logStatus = 'OK'
                  | filter tcpFlags in [2,3,6,7,18,19,22,23]
                  | stats sum(packets) as pkts, count() as records,
                          count_distinct(pktSrcAddr) as sources
                          by bin(5m)
                  | sort @timestamp desc
                  | limit 200")

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'
```

The enumerated flag list is every value in which the SYN bit is set, given AWS's bit assignments
and OR-ing. Read `pkts` against `sources`: thousands of sources with tens of packets each is
distributed; a handful of sources with millions is concentrated. That single ratio decides §3, and
nothing else in this playbook matters until it is answered.

#### Query 2 — Sweep: can this subscription answer the question at all

```bash
REGION="us-east-1"

aws ec2 describe-flow-logs --region "$REGION" --output json | jq -r '
  .FlowLogs[] |
  ((.LogFormat // "") | contains("tcp-flags")) as $flags |
  "\(if $flags then "[OK]  " else "[FAIL]" end) \(.FlowLogId) on \(.ResourceId)  interval=\(.MaxAggregationInterval)s  tcp-flags=\($flags)"'

echo
echo "[i] A [FAIL] line means every flag-based detection in this playbook is SILENT on that"
echo "    resource — not noisy, silent. The format cannot be changed; the subscription must be"
echo "    deleted and recreated. Do that after the incident, and record it as a finding now."
echo "[i] interval=600 means the earliest sound alerting window is roughly 15-20 minutes."
```

#### Query 3 — Inspect: did the service actually degrade

```bash
REGION="us-east-1"
LB_ARN="<load-balancer-arn>"
TG_ARN="<target-group-arn>"
START=$(date -u -v-6H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ)
END=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "== target health right now =="
aws elbv2 describe-target-health --target-group-arn "$TG_ARN" --region "$REGION" --output json 2>/dev/null | \
  jq -r '.TargetHealthDescriptions[] | "\(.Target.Id):\(.Target.Port)\t\(.TargetHealth.State)\t\(.TargetHealth.Reason // "-")"'

echo
echo "== connection and error counts over the window =="
LB_DIM=$(printf '%s' "$LB_ARN" | sed 's|.*:loadbalancer/||')
for M in ActiveConnectionCount NewConnectionCount RejectedConnectionCount HTTPCode_ELB_5XX_Count TargetResponseTime; do
  echo "-- $M"
  aws cloudwatch get-metric-statistics --namespace AWS/ApplicationELB --metric-name "$M" \
    --dimensions Name=LoadBalancer,Value="$LB_DIM" \
    --start-time "$START" --end-time "$END" --period 300 --statistics Sum Maximum \
    --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Datapoints | sort_by(.Timestamp) | .[] | "\(.Timestamp)\tsum=\(.Sum // "-")\tmax=\(.Maximum // "-")"' | tail -8
done
```

`RejectedConnectionCount` rising is the load balancer hitting its own connection limit, which is
the clearest evidence that arrival volume became impact. Flow logs alone can show a large number
that the service absorbed without difficulty — volume is not damage until this query says it is.

#### Query 4 — Characterise the sources against the baseline

```bash
REGION="us-east-1"
LOG_GROUP="/aws/vpc/flowlogs"
TARGET="<target-private-ip>"

echo "[i] The question is not 'who are these addresses' — a SYN flood spoofs them. The question"
echo "    is whether the SET resembles last week's. Run Query 1's stats grouped by pktSrcAddr for"
echo "    the incident window and for the same window seven days earlier, then compare:"
echo "      - overlap high  -> a traffic surge from a real client base"
echo "      - overlap near zero, thousands of new addresses seen once -> distributed flood"
echo "      - a handful of addresses, none familiar -> concentrated flood, blockable"
echo
echo "[!] Do not build a blocklist from a distributed flood's source list. The addresses are"
echo "    spoofed by design, so the list may block nobody who attacked you and somebody who did"
echo "    not — and it will not keep up regardless."
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**The shape decides the response, and nothing else should be attempted before it is known.** A
concentrated flood is blocked at a network ACL in one call. A distributed flood cannot be blocked
by address at all, and time spent trying is time the service stays down.

> Run every command under the **break-glass responder credentials** from §1.

#### Step 1 — Establish the shape

```bash
SOURCES="<distinct-source-count-from-Query-1>"
PACKETS="<summed-packets-from-Query-1>"

if [ "$SOURCES" -le 5 ] 2>/dev/null; then
  echo "[i] CONCENTRATED — $SOURCES source(s), $PACKETS packets. Step 2 applies: a network ACL"
  echo "    deny is stateless, evaluates before security groups, and takes effect immediately."
elif [ "$SOURCES" -ge 500 ] 2>/dev/null; then
  echo "[i] DISTRIBUTED — $SOURCES sources, $PACKETS packets. Step 3 applies. Do NOT build an"
  echo "    address blocklist: the sources are spoofed and the list will not keep up."
else
  echo "[i] AMBIGUOUS — $SOURCES sources. Re-run Query 1 over a longer window before acting;"
  echo "    a flood ramping up looks like this, and so does a genuine surge."
fi
```

#### Step 2 — Concentrated flood: deny at the network ACL

```bash
REGION="us-east-1"
ACL_ID="<network-acl-id-for-the-target-subnet>"
ATTACKER_CIDR="<source>/32"
RULE_NUM=10          # low numbers evaluate first; confirm this number is free below

EXISTING=$(aws ec2 describe-network-acls --network-acl-ids "$ACL_ID" --region "$REGION" \
  --output json | jq -r --argjson n "$RULE_NUM" \
  '[.NetworkAcls[].Entries[] | select(.Egress == false and .RuleNumber == $n)] | length')

if [ "$EXISTING" -ne 0 ]; then
  echo "[FAIL] ingress rule $RULE_NUM already exists on $ACL_ID — pick a free number, do not overwrite"
else
  aws ec2 create-network-acl-entry --network-acl-id "$ACL_ID" --ingress \
    --rule-number "$RULE_NUM" --protocol -1 --rule-action deny \
    --cidr-block "$ATTACKER_CIDR" --region "$REGION" \
    && echo "[OK] denied $ATTACKER_CIDR at $ACL_ID rule $RULE_NUM"
  echo "[i] NACLs are ORDERED and stateless — the lowest matching rule wins, and this rule blocks"
  echo "    return traffic too. Remove it once the flood stops; it is containment, not a control."
fi
```

A security group cannot express a deny, which is why this is a NACL. The existence check matters:
overwriting a rule number that already carries an allow is a way to cause a second outage while
responding to the first.

#### Step 3 — Distributed flood: absorb, do not block

```bash
REGION="us-east-1"
LB_ARN="<load-balancer-arn>"

echo "== is Shield Advanced subscribed on this resource =="
aws shield describe-protection --resource-arn "$LB_ARN" --region us-east-1 --output json 2>/dev/null | \
  jq -r '"[OK] protected: \(.Protection.Name)"' \
  || echo "[i] no Shield Advanced protection on this resource — Standard applies automatically and there is no engagement path"

echo
echo "[i] Levers that work against a distributed flood, in order of speed:"
echo "    1. If Shield Advanced is subscribed, engage the response team NOW — this is what it is for."
echo "    2. Put a load balancer in front of any raw instance target. An NLB absorbs SYN floods"
echo "       at the AWS edge in a way an instance's own network stack cannot."
echo "    3. Scale the target group out. This buys connection-table headroom, not a fix."
echo "    4. If the endpoint need not be public at all, remove it from the internet — see §4."
echo "[!] Not on this list: an address blocklist. The sources are spoofed."
```

#### Step 4 — Protect the target while the traffic continues

Reduce the half-open timeout on the target hosts so slots are recycled faster, and confirm the
health check interval is not itself failing the targets out under load — an aggressive health
check during a flood removes healthy capacity and completes the attack on its behalf. Both are
target-side changes and neither is an AWS API call.

---

## 4. Eradication

### Remove Attacker Access

#### Reduce what is reachable

A flood can only target what it can reach. If the target is an instance with a public address
because that was convenient, moving it behind a load balancer removes the direct path and puts
AWS's absorption capacity in front of it. If the endpoint has no reason to be public, the
eradication is removing it from the internet, not tuning a threshold.

#### Remove the emergency NACL rules

```bash
REGION="us-east-1"
ACL_ID="<network-acl-id>"
RULE_NUM=10

if aws ec2 describe-network-acls --network-acl-ids "$ACL_ID" --region "$REGION" --output json | \
   jq -e --argjson n "$RULE_NUM" '[.NetworkAcls[].Entries[] | select(.Egress == false and .RuleNumber == $n)] | length > 0' >/dev/null; then
  aws ec2 delete-network-acl-entry --network-acl-id "$ACL_ID" --ingress \
    --rule-number "$RULE_NUM" --region "$REGION" \
    && echo "[OK] removed emergency deny rule $RULE_NUM"
else
  echo "[i] rule $RULE_NUM not present — already removed"
fi
```

A deny left in a NACL after the incident is an outage waiting for the address to be reassigned to
a legitimate client. Remove it, and record in the incident that it was removed.

#### Fix the subscription format if Query 2 reported `[FAIL]`

The subscription must be deleted and recreated with `tcp-flags` in the format. This is the only
item in this playbook that cannot be done during an incident, and it is the one that decides
whether the next one is visible.

---

## 5. Recovery

### Restore Clean State

#### Verify traffic and target health have returned to baseline

```bash
REGION="us-east-1"
TG_ARN="<target-group-arn>"

UNHEALTHY=$(aws elbv2 describe-target-health --target-group-arn "$TG_ARN" --region "$REGION" \
  --output json | jq -r '[.TargetHealthDescriptions[] | select(.TargetHealth.State != "healthy")] | length')
[ "$UNHEALTHY" -eq 0 ] && echo "[OK] all targets healthy" \
                       || echo "[FAIL] $UNHEALTHY target(s) still unhealthy — the flood may be ongoing, or the targets need restarting"
```

#### Verify no emergency denies remain

```bash
REGION="us-east-1"
DENIES=$(aws ec2 describe-network-acls --region "$REGION" --output json | \
  jq '[.NetworkAcls[].Entries[] | select(.Egress == false and .RuleAction == "deny" and .CidrBlock != "0.0.0.0/0")] | length')
echo "[i] non-default ingress deny rules across the account: $DENIES"
[ "$DENIES" -eq 0 ] && echo "[OK] none left over" \
                    || echo "[!] review each — an incident deny left in place becomes an outage later"
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  flow-direction=ingress  protocol=6  tcp-flags=3   (SYN OR FIN — a short connection)"
echo "  600 distinct pkt-srcaddr to one pkt-dstaddr within 15 minutes"
echo "and MUST fire equally on:"
echo "  tcp-flags=19  (SYN-ACK OR FIN)  — this is the case the source rule misses"
echo "The rule MUST NOT fire on:"
echo "  tcp-flags=1   (FIN alone — no SYN bit set)"
echo "  tcp-flags=4   (RST alone)"
echo "and there is NO test for tcp-flags on a version 2 subscription — the field does not exist"
echo "  there, so the rule is silent rather than wrong. Query 2 is what catches that."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| The flood reached the target's connection table | The target was directly internet-reachable rather than behind a load balancer that absorbs at the AWS edge |
| The detection did not fire, or fired late | It matched `tcp-flags` exactly 2 against a field AWS OR-s across the interval, and thresholded on record count rather than packets |
| Detection latency was 15 minutes at best | The subscription used the default 10-minute aggregation interval on an internet-facing subnet |
| Nobody could tell the two shapes apart | Source cardinality was not measured, so the response defaulted to an address blocklist that could not work |
| The health check completed the attack | Health check intervals were tuned for a healthy service and removed capacity under load |

### Recommended Guardrails

**Protect the flow-log configuration that makes this visible**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["ec2:DeleteFlowLogs"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Put a load balancer in front of every internet-facing target. AWS absorbs SYN floods at the edge
  at a scale an instance's network stack cannot reach, and this is the single change that most
  reduces exposure.
- Subscribe to Shield Advanced for the endpoints whose availability matters, and rehearse the
  engagement path. Its detection does not depend on flow logs, so it works even where the format
  is wrong.
- Set a 1-minute aggregation interval on internet-facing subnets. The default puts a 15-minute
  floor under detection latency for an attack measured in minutes.
- Standardise the flow-log format organisation-wide, including `tcp-flags`. The format cannot be
  changed after creation, so this is decided once — deliberately or by accident.

**Detection improvements**
- Measure packets and source cardinality, never record count. A flow log record is an aggregate,
  and treating it as an event under-measures a flood by orders of magnitude.
- Alert on the *absence* of the `tcp-flags` field in any subscription's format, as a standing
  configuration check. It is the difference between a rule that is quiet and a rule that cannot
  speak.
- Pair every volumetric detection with a service-health signal. Arrival volume is not impact, and
  an alert that cannot distinguish a surge from an attack will be treated as a surge.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1498 — Network Denial of Service |
| MITRE tactic | Impact (TA0040) |
| Primary API | None — the technique is network traffic. Containment uses `ec2:CreateNetworkAclEntry` |
| Event source | VPC flow logs (custom format including `tcp-flags`, a version 3 field) |
| Key discriminator | The SYN bit set in the OR-ed `tcp-flags` value, with high summed `packets` or high distinct-source cardinality to one `pkt-dstaddr` |
| Ground-truth signal | Service impact in CloudWatch — `RejectedConnectionCount` rising, or targets failing health checks. Arrival volume alone is not damage |
| "Was it used" pivot | Not applicable; the traffic is the attack. The equivalent question is whether it caused impact, which is Query 3 |
| Blast radius | Availability of the target and anything sharing its connection capacity or its subnet's NAT gateway |
| Error strings | Not applicable — flow logs carry `action: REJECT`, which AWS documents as covering security-group and NACL denials **and** "packets arrived after the connection was closed" |

**MITRE mapping note:** the source's `T1498` is correct and is kept. No sub-technique is claimed:
`T1498.001` (Direct Network Flood) and `T1498.002` (Reflection Amplification) are both plausible
readings of a SYN flood, and the flow log cannot distinguish them — a reflection attack's sources
are legitimate hosts responding to spoofed requests, which looks identical from the target's side.
Claiming a sub-technique here would be asserting something the telemetry does not support.

### Residual Risk

Every count in this playbook is a floor. `log-status: SKIPDATA` means AWS dropped records *"because
of an internal capacity constraint, or an internal error"*, and a traffic flood is exactly the
condition that makes that likely — so the measured volume during the worst part of an attack is
the least reliable. The source addresses are spoofed by design, so there is no attribution to be
had and no blocklist worth keeping. If the subscription lacked `tcp-flags`, the historical record
of this incident cannot be reconstructed at all and never will be, because the format cannot be
applied retroactively. And a flood that stopped on its own stopped for the attacker's reasons, not
yours — nothing in the response above removes their capability to start again.
