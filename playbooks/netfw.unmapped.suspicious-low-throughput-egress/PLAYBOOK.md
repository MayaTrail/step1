# IR Playbook: Slow Egress and Beaconing — a long-lived low-rate transfer in the `netflow` log, or many short flows at a fixed interval

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Exfiltration and command-and-control (data leaving over a persistent low-rate channel, or a host polling an external controller) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High once the destination is unexplained. Both shapes exist specifically to stay under volumetric alerting — one by moving slowly, the other by moving in pieces — so neither trips a conventional throughput threshold, and both can run for weeks. |
| MITRE Tactics | Exfiltration, Command and Control |
| MITRE Techniques | T1071 |
| Services in Scope | AWS Network Firewall, VPC, CloudWatch, CloudTrail |

**What the technique does:** two shapes with one purpose — moving data past a control tuned for
volume. **Slow exfiltration** opens one connection and leaves it open, moving a few kilobytes a
second for hours. **Beaconing** does the opposite: a short connection every sixty seconds carrying
a few hundred bytes, receiving instructions and returning results. Neither looks like a transfer to
anything measuring bytes per minute.

**Why the usual reflexes miss it.** The reflex is a volume threshold, and both shapes are designed
around one. The source rule sets a threshold that catches the first shape and cannot catch the
second — while being named for the second. And a second reflex fails here too: the record for a
long-lived flow is written when the flow **ends**, so the alert arrives after the data has gone.
That is not a tuning problem; it is what the log format does.

**Detection thesis:** measure duration and rate for the slow shape, and **interval regularity** for
the beaconing shape. Read `event.direction` rather than inferring outbound from volume, because
netflow records one leg per event and a download looks identical to an upload.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **Flow logging enabled on every firewall**, alongside alert logging.
  `../netfw.stealth.no-logs-from-aws-network-firewall-in-4-hours/` covers its absence — and note
  that a policy handling traffic statelessly produces no netflow records at all.
- **TLS inspection where the workload permits it.** Without it, `event.tls.sni` may be everything
  known about a destination, and `tls_inspected` is **omitted** rather than false when it did not
  apply.
- **An inventory of expected long-lived and periodic destinations** — backup targets, log shipping
  endpoints, container registries, update channels, monitoring and telemetry SDKs. This is the
  entire tuning surface for both shapes and it must be a list of destinations, not a threshold.

**Alerting (must be pre-configured)**
- **60 or more outbound flows from one source to one destination in 6 hours with a near-constant interval and low total volume → P0**
- **An outbound flow with `age` ≥ 3600 and `bytes` ≥ 5 MB at a median rate below 5 KB/s → P0**
- **An outbound flow with `age` ≥ 3600 and `bytes` ≥ 5 MB to a destination not on the inventory → P1**
- **The same destination also appearing in an alert log entry at severity 1 or 2 → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- A small, high-priority, empty stateful rule group for incident blocks — the same one
  `../netfw.unmapped.high-severity-alert-detected/` asks for.

**Known IOC Baselines**
- The destinations above, by address and by SNI. Tuning by threshold loses the technique; tuning by
  destination loses the noise.
- Normal beacon intervals for your own agents. A monitoring agent at 60 seconds and a beacon at 60
  seconds are separated by the destination, not by the interval.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | ≥ 60 outbound flows, one source to one destination, in 6h with interval regularity < 0.15 and total volume < 5 MB | Network Firewall flow logs (correlation + KQL) | T1071 |
| P0 | Outbound flow with `netflow.age` ≥ 3600 and `netflow.bytes` ≥ 5 MB at a median rate below 5 KB/s | Network Firewall flow logs | T1041 |
| P1 | Outbound flow with `netflow.age` ≥ 3600 and `netflow.bytes` ≥ 5 MB to a destination not on the inventory | Network Firewall flow logs | T1041 |
| P1 | The same destination appearing in an alert log entry at severity 1 or 2 | Network Firewall alert logs | T1071 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | ≥ 60 outbound flows to one destination with interval regularity below 0.3 | Network Firewall flow logs | T1071 |
| P2 | A long-lived outbound flow where `app_proto` is `tls` and `tls_inspected` is absent — the destination is known only by SNI | Network Firewall flow logs | T1573 |
| P3 | Sustained outbound flows to a destination with no SNI and no resolvable name | Network Firewall flow logs | T1071 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| The name says beaconing; the logic detects a long high-volume flow | `age >= 3600 AND bytes >= 5,000,000` is low rate and substantial volume — slow exfiltration. Beaconing is many short flows of a few hundred bytes each, every one of which is orders of magnitude below both thresholds. The rule cannot detect the shape it is named for | Both shapes shipped: the corrected volume rule, and an `event_count` correlation on flows per source-destination pair with the interval regularity computed in the KQL |
| `netflow` is uni-directional and direction is not read | AWS: each netflow event *"represents traffic going in a single direction"*. So `bytes` is one leg — a large download matches identically to a large upload, and only one is exfiltration | `event.direction: to_server` filters to the outbound leg. Intent is read from the field, not inferred from volume |
| 10-minute window on flows lasting an hour or more | Netflow records are emitted at flow **end** or timeout, so the record for a matching flow arrives at least an hour after it began. The window measures record arrival, not traffic — and the data has already moved when it fires | Stated rather than tuned: no window setting changes it. The playbook frames this detection as scoping the loss, not preventing it. Beaconing, whose flows are short, is the shape where fast detection is genuinely available |
| Geo-enrichment used for "external" | The destination address answers this directly, and the enrichment makes the rule depend on a pipeline that may not exist | Private destination space excluded on `event.dest_ip` |
| Threshold of zero grouped only by source | Every matching flow alerts individually, rather than per source-destination pair — which is the unit an analyst acts on and the unit that gets blocked | Group by the pair in both the correlation and the query |
| Ignores `app_proto`, `tls.sni` and the alert log | The destination's identity is the thing that settles every one of these findings, and three fields carrying it are unused | Projected in the KQL and named in §1 as the tuning surface |

**Recommended detection — both shapes, with regularity where Sigma cannot express it.**

```yaml
# Long-lived low-rate egress, and the beaconing the rule is named for (T1071 / T1041)
#
# THE RULE'S NAME AND ITS LOGIC DESCRIBE DIFFERENT THINGS. It matches a flow with age >= 3600
# seconds AND bytes >= 5,000,000 — a session lasting at least an hour and moving at least 5 MB.
# That is roughly 1.4 KB/s, which is low RATE but substantial VOLUME: it detects slow exfiltration
# over a persistent connection.
#
# Classic command-and-control BEACONING is the opposite shape — many SHORT flows at regular
# intervals, each carrying a few hundred bytes. Every one of those has an age near zero and a byte
# count far below the threshold, so the rule cannot see beaconing at all. Both shapes are shipped
# below because both are real and the pack has a rule for only one of them.
#
# `netflow` IS UNI-DIRECTIONAL AND THIS BREAKS THE VOLUME TEST QUIETLY. AWS: "The log type
# `netflow` logs uni-directional flows, so each event represents traffic going in a single
# direction." So `bytes` is ONE LEG of a conversation. A large download and a large upload both
# produce a matching record, and only one of them is exfiltration. The rules below read
# `event.direction` — to_server is the outbound leg — rather than inferring intent from volume.
#
# THE ALERT IS STRUCTURALLY LATE AND THE WINDOW DOES NOT CHANGE THAT. Netflow records are emitted
# when a flow ENDS or times out, not continuously. A flow matching age >= 3600 produces its record
# at least an hour after it started, so a 10-minute evaluation window is a window on RECORD ARRIVAL
# and not on traffic. The data has already moved by the time anything fires. This is stated rather
# than tuned away, because no window setting fixes it — it is a property of the log format.
#
# THE STATELESS ENGINE IS INVISIBLE. AWS: "Firewall logging is only available for traffic that you
# forward to the stateful rules engine." Traffic a stateless rule handled produces no netflow record
# at all, so absence here is never evidence that a transfer did not happen.
#
# `group_by src_ip` WITH A THRESHOLD OF ZERO means every matching flow alerts individually. The
# correlations below group by the source and destination pair, which is the unit an analyst acts on.
title: Long-lived outbound flow carrying substantial volume
id: 3e91c704-27b6-4f5a-8d13-608a5e2bc47f
name: netfw_slow_egress_flow
status: experimental
description: >-
  An outbound flow lasting an hour or more and carrying at least 5 MB. Low rate, substantial
  volume — the shape of a deliberate slow transfer designed to stay under volumetric thresholds.
  Direction is read from event.direction rather than inferred, because netflow records one leg per
  event and a large inbound transfer would otherwise match identically. Note that the record is
  emitted when the flow ends, so this fires after the data has moved; it is a detection of what
  happened rather than an interception.
references:
  - https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-logging-contents.html
  - https://attack.mitre.org/techniques/T1041/
tags:
  - attack.exfiltration
  - attack.t1041
logsource:
  product: aws
  service: networkfirewall
detection:
  netflow_event:
    event.event_type: 'netflow'
  outbound:
    event.direction: 'to_server'
  long_lived:
    event.netflow.age|gte: 3600
  substantial:
    event.netflow.bytes|gte: 5000000
  # Private destination space is excluded rather than public space enumerated. An internal
  # long-lived transfer is a different question and usually a backup.
  internal_destination:
    event.dest_ip|startswith:
      - '10.'
      - '192.168.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.2'
      - '172.30.'
      - '172.31.'
  condition: netflow_event and outbound and long_lived and substantial and not internal_destination
falsepositives:
  - >-
    Backup jobs, log shipping, container image pulls and software update channels — all long-lived
    and all substantial. This is a large false-positive surface and the tuning is by destination
    address or SNI, not by threshold: raising the byte count only moves the line, while naming the
    known destinations removes them.
level: medium
---
title: Outbound flow to an external destination
id: 8b47d0e2-5193-4c86-a7f0-2e63175bc9d4
name: netfw_egress_flow
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. Every outbound flow to a
  non-private destination. It exists so the beaconing correlation below has something to count, and
  it matches essentially all egress traffic.
references:
  - https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-logging-contents.html
tags:
  - attack.command-and-control
  - attack.t1071
logsource:
  product: aws
  service: networkfirewall
detection:
  netflow_event:
    event.event_type: 'netflow'
  outbound:
    event.direction: 'to_server'
  internal_destination:
    event.dest_ip|startswith:
      - '10.'
      - '192.168.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.2'
      - '172.30.'
      - '172.31.'
  condition: netflow_event and outbound and not internal_destination
level: informational
---
title: Many short outbound flows from one source to one destination
id: c25f68a1-9d04-4b73-85e6-701da9c34b28
status: experimental
description: >-
  The shape the source rule is named for and cannot detect. Command-and-control beaconing is many
  SHORT flows at regular intervals, each carrying a few hundred bytes — every one of which has an
  age near zero and a byte count far below any volumetric threshold. Counting flows per
  source-destination pair is what makes it visible. This rule cannot measure the interval
  regularity that would confirm beaconing, because Sigma correlations have no variance operator;
  the KQL computes it, and this rule's job is to surface the candidate.
references:
  - https://attack.mitre.org/techniques/T1071/
tags:
  - attack.command-and-control
  - attack.t1071
correlation:
  type: event_count
  rules:
    - netfw_egress_flow
  group-by:
    - event.src_ip
    - event.dest_ip
  timespan: 6h
  condition:
    gte: 60
falsepositives:
  - >-
    Monitoring agents, telemetry SDKs, health checks and metrics push endpoints all beacon by
    design and produce exactly this shape. They are a nameable set of destinations — exclude by
    dest_ip or SNI, and note that the interval regularity in the KQL is what separates them from a
    tool trying to look like them, though neither is conclusive alone.
level: medium
```

What this set structurally cannot do: it cannot see traffic the stateless engine handled, it cannot
show payload — netflow is a counter — and where TLS inspection did not apply the SNI may be all
that is known about the destination. And for the slow-transfer shape it cannot be timely, because
the record does not exist until the flow ends.

---

### Key Investigation Queries

> Queries 1 and 2 read the flow logs, most often through CloudWatch Logs Insights over the
> configured log group. Field names follow `../_ground-truth/netfw.md` §3. Queries 3 and 4 read the
> alert log and the EC2 API.

#### Query 1 — Reconstruct: the flow pattern between this pair

```bash
REGION="us-east-1"
LOG_GROUP="/aws/network-firewall/flow"
SRC="<src-ip-from-the-alert>"
DEST="<dest-ip-from-the-alert>"
START=$(date -u -v-7d +%s 2>/dev/null || date -u -d '7 days ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string "fields @timestamp, event.netflow.bytes, event.netflow.pkts, event.netflow.age,
                         event.dest_port, event.app_proto, event.tls.sni, event.direction
                  | filter event.event_type = 'netflow'
                        and event.src_ip = '${SRC}' and event.dest_ip = '${DEST}'
                        and event.direction = 'to_server'
                  | sort @timestamp asc
                  | limit 1000")

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'
```

Read the timestamps as a series. Evenly spaced entries with small byte counts is a beacon, and the
spacing is its interval. One entry with a large `age` and a large `bytes` is the slow-transfer
shape — and remember its timestamp is the flow's **end**, so subtract `age` to find when it
started. `event.direction = 'to_server'` is not optional: without it the inbound leg appears and
doubles every count.

#### Query 2 — Sweep: which pairs across the estate have either shape

```bash
REGION="us-east-1"
LOG_GROUP="/aws/network-firewall/flow"
START=$(date -u -v-24H +%s 2>/dev/null || date -u -d '24 hours ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string 'fields event.src_ip, event.dest_ip, event.netflow.bytes, event.netflow.age, event.tls.sni
                  | filter event.event_type = "netflow" and event.direction = "to_server"
                  | stats count() as flows,
                          sum(`event.netflow.bytes`) as total_bytes,
                          max(`event.netflow.age`) as max_age,
                          max(`event.netflow.bytes`) as max_flow_bytes
                          by `event.src_ip`, `event.dest_ip`
                  | sort flows desc
                  | limit 200')

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add' | \
  jq -s 'map(select((.flows | tonumber) >= 60 or ((.max_age | tonumber) >= 3600 and (.max_flow_bytes | tonumber) >= 5000000)))'
```

Two populations come out of this and they need reading differently. High `flows` with low
`total_bytes` is the beaconing candidate set — and it will be full of monitoring agents, which is
expected. High `max_age` with high `max_flow_bytes` is the slow-transfer set, full of backups. In
both cases the destination is what separates the finding from the furniture, which is why §1 asks
for the inventory rather than for a better threshold.

#### Query 3 — Inspect: what else is known about this destination

```bash
REGION="us-east-1"
DEST="<dest-ip>"
LOG_GROUP_ALERT="/aws/network-firewall/alert"
START=$(date -u -v-7d +%s 2>/dev/null || date -u -d '7 days ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP_ALERT" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string "fields @timestamp, event.alert.severity, event.alert.signature,
                         event.alert.action, event.tls.sni, event.http.hostname, event.aws_category
                  | filter event.dest_ip = '${DEST}' and event.event_type = 'alert'
                  | sort @timestamp desc
                  | limit 100")

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'

echo
echo "[!] An empty result here means no stateful signature matched — NOT that the destination is"
echo "    clean. Signatures only exist for known-bad infrastructure, and a freshly registered"
echo "    controller matches nothing. Treat this as corroboration when present and as no"
echo "    information when absent."
```

#### Query 4 — Identify the source host and what it holds

```bash
REGION="us-east-1"
SRC="<src-ip>"

aws ec2 describe-instances --region "$REGION" --filters "Name=private-ip-address,Values=$SRC" \
  --output json | jq -r '.Reservations[].Instances[] |
    "instance=\(.InstanceId)  state=\(.State.Name)  profile=\(.IamInstanceProfile.Arn // "<none>")  vpc=\(.VpcId)  subnet=\(.SubnetId)  launched=\(.LaunchTime)"' \
  || echo "[i] no EC2 instance with that private address — check ECS tasks, EKS pods and Lambda ENIs"

echo
echo "[i] For the slow-transfer shape, the question is what this host could read. For the beaconing"
echo "    shape, the question is what it has been told to do — and the answer is on the host, not"
echo "    in any network log."
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**The two shapes have different urgency and that should drive the order.** A beacon is a live
channel and blocking it interrupts an operator mid-session. A completed slow transfer is already
finished, and blocking the destination prevents the next one rather than this one.

> Run every command under the **break-glass responder credentials** from §1.

#### Step 1 — Establish which shape, and therefore what blocking achieves

```bash
FLOWS="<flows-from-Query-2>"
MAX_AGE="<max_age-from-Query-2>"
TOTAL_BYTES="<total_bytes-from-Query-2>"

if [ "${FLOWS:-0}" -ge 60 ] && [ "${TOTAL_BYTES:-0}" -lt 5000000 ]; then
  echo "[i] BEACONING shape — a live channel. Blocking it interrupts an active session and the"
  echo "    operator will notice. Decide deliberately whether to block now or observe first."
elif [ "${MAX_AGE:-0}" -ge 3600 ]; then
  echo "[i] SLOW TRANSFER shape — the record was written when the flow ENDED, so this has already"
  echo "    completed. Blocking prevents the next one. The urgent work is scoping what left."
else
  echo "[!] Shape not determined — re-read Query 2's row for this pair before acting."
fi
```

#### Step 2 — Block the destination in the incident rule group

```bash
REGION="us-east-1"
RULE_GROUP_ARN="<ir-block-rule-group-arn>"
DEST="<dest-ip>"

if ! aws network-firewall describe-rule-group --rule-group-arn "$RULE_GROUP_ARN" --region "$REGION" >/dev/null 2>&1; then
  echo "[FAIL] IR rule group not found — the §1 prerequisite. Falling back to a policy edit under"
  echo "       time pressure is how an outage gets added to an incident."
else
  echo "[i] Add a drop rule for $DEST to the IR group. Review before applying:"
  echo "    drop ip any any -> $DEST any (msg:\"IR block\"; sid:<unique>; rev:1;)"
  echo "[!] Confirm the IR group's priority is ahead of any pass rule in the policy, or the drop"
  echo "    never evaluates. Query 3 of ../netfw.unmapped.high-severity-alert-detected/ shows the order."
fi
```

Emitted for review rather than executed. A Suricata rule with a malformed body is rejected at
update time — a safe failure — but one that is too broad is not, and a drop on a shared CDN address
takes out more than the incident.

#### Step 3 — Scope what left

For the slow-transfer shape, `total_bytes` from Query 2 is the volume — of **one leg**, in the
outbound direction, for flows the stateful engine saw. It is a lower bound. Netflow carries no
payload, so what those bytes were is a question for the host: its file access records, its
application logs, and what its instance profile could reach.

For the beaconing shape the volume is small by design and irrelevant; what matters is that the host
has been under external instruction for the duration, and the scope is everything it could do in
that time.

#### Step 4 — Isolate the host

Move the interface to a quarantine security group as in
`../vpc.initial-access.possible-ssrf-attempt-hit-to-169254169254/` §3 — the procedure is
identical and is not restated. Preserve the instance: for the beaconing shape the implant on disk is
the only thing that says what the channel was doing, and no network log will ever answer that.

---

## 4. Eradication

### Remove Attacker Access

#### Find the other hosts talking to the same destination

Re-run Query 2 filtered to the destination rather than the source. A controller usually has more
than one client, and this is the fastest way to size the footprint.

#### Rebuild rather than clean

For a beaconing implant, the code is the attacker's choice and rebuilding from a known-good image is
the only reliable removal. The forensic copy from Step 4 preserves what the investigation needs.

#### Close the entry path

The channel is not the entry. Query 4's host details and the host's own logs are where that is, and
removing the channel without finding it means the next one arrives the same way.

#### Extend the destination inventory

Every destination confirmed legitimate during this response belongs in the §1 inventory. That list
is what makes the next occurrence of these rules triageable in minutes rather than hours, and it is
the only tuning that does not also lose the technique.

---

## 5. Recovery

### Restore Clean State

#### Verify the destination is unreachable

```bash
REGION="us-east-1"
LOG_GROUP="/aws/network-firewall/flow"
DEST="<dest-ip>"
START=$(date -u -v-1H +%s 2>/dev/null || date -u -d '1 hour ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string "fields @timestamp, event.src_ip, event.netflow.bytes
                  | filter event.event_type = 'netflow' and event.dest_ip = '${DEST}'
                  | stats count() as flows by \`event.src_ip\`")

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
RESULTS=$(aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | jq '.results | length')
[ "$RESULTS" -eq 0 ] && echo "[OK] no flows to $DEST in the last hour" \
                     || echo "[FAIL] $RESULTS source(s) still reaching $DEST — check the IR rule group's priority"
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  event.event_type=netflow  event.direction=to_server"
echo "  event.netflow.age=7200  event.netflow.bytes=8000000  dest outside RFC1918"
echo "and MUST fire on the shape the source rule cannot see:"
echo "  120 netflow events, same src/dest pair, 6 hours, ~400 bytes each, 60s apart"
echo "  (every individual flow is far below both of the source rule's thresholds)"
echo "The rule MUST NOT fire on:"
echo "  the same long flow with event.direction=to_client  (an inbound download)"
echo "  the same long flow to a destination in 10.0.0.0/8  (internal backup)"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A beaconing channel ran undetected | The rule named for beaconing used volume thresholds that beaconing is designed to stay below |
| An inbound transfer would have alerted identically to an outbound one | `event.direction` was not read, and netflow records one leg per event |
| The slow-transfer alert arrived after the data had gone | Netflow records are written at flow end; no window setting changes that |
| Alerts were dominated by backups and monitoring agents | Tuning was attempted by threshold rather than by destination inventory |
| The destination could not be identified | TLS inspection was not enabled, leaving SNI as the only available identity |

### Recommended Guardrails

**Keep the firewall policy and its logging out of general credentials**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["network-firewall:UpdateFirewallPolicy", "network-firewall:UpdateRuleGroup",
             "network-firewall:UpdateLoggingConfiguration"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Maintain the destination inventory as a reviewed artifact. It is the only tuning that removes the
  noise without also removing the technique, and both shapes are unusable without it.
- Enable TLS inspection where the workload allows. Without it the destination is known by SNI at
  best, and a controller that omits SNI is known by address alone.
- Restrict egress at the firewall policy to named destinations for workloads that have a fixed set.
  A host that can only reach three places cannot beacon to a fourth.
- Keep the incident rule group empty, high-priority and associated. Containment is then one rule
  rather than a policy rewrite.

**Detection improvements**
- Detect shape, not volume. Both techniques here are defined by their relationship to a volume
  threshold, so any rule built on one is being designed around by the attacker.
- Measure interval regularity for periodic traffic. It is the one property a beacon cannot easily
  give up without becoming unreliable for its operator.
- Read `event.direction` in every netflow rule. Uni-directional records make an upload and a
  download indistinguishable by volume, and only that field separates them.
- State the emission timing in any rule reading `netflow.age`. A detection that cannot be timely
  should say so, so the response is scoped as recovery rather than interception.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1071 — Application Layer Protocol |
| MITRE tactic | Command and Control (TA0011); the slow-transfer shape is Exfiltration (TA0010) |
| Primary API | None — the technique is network traffic. Containment uses `network-firewall:UpdateRuleGroup` |
| Event source | AWS Network Firewall flow logs (Suricata EVE `netflow`, **uni-directional**) |
| Key discriminator | For slow transfer: `netflow.age` ≥ 3600 with a low byte rate on the `to_server` leg. For beaconing: many short flows to one destination at a near-constant interval |
| Ground-truth signal | The flow records themselves — but only for traffic forwarded to the stateful engine, and only after each flow ends |
| "Was it used" pivot | Not applicable — the flows **are** the activity. The equivalent question is what the host could read, which is Query 4 |
| Blast radius | For slow transfer, whatever the host could access; for beaconing, whatever it was instructed to do, which is on the host and in no network log |
| Error strings | Not applicable. `netflow` records carry counters — `bytes`, `pkts`, `age` — and no status |

**MITRE mapping note:** the source carries bare `T1071`. `T1041 — Exfiltration Over C2 Channel` is
added for the slow-transfer rule, which observes data leaving rather than a channel existing, while
`T1071 — Application Layer Protocol` stays on the beaconing correlation. Both verified live
2026-08-30. No sub-technique is claimed for the beaconing case: `T1071.001` (Web Protocols) would
require knowing the application protocol, and where TLS inspection did not apply the log records
`tls` and nothing beneath it — asserting the sub-technique would be asserting something the
telemetry does not support.

### Residual Risk

For the slow-transfer shape the data has already left by the time anything fires — netflow records
are written when the flow ends, so this detection scopes a loss rather than preventing one, and the
byte figure is a lower bound covering one direction of the traffic the stateful engine happened to
see. Anything the stateless engine handled produced no record at all. Netflow carries no payload, so
what was in those bytes is answerable only from the host. For the beaconing shape the volume is
small and irrelevant: the host was under external instruction for the whole period, and what it was
told to do exists on the host and in no network log. And blocking the destination ends that channel
and not the technique — a new address costs the operator nothing, and the next one will match no
signature either.
