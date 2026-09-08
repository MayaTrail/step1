# IR Playbook: VPC Flow Log Delivery Stopped — `DeleteFlowLogs`, a downgraded format, or a destination that no longer exists

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment (the network telemetry every other VPC playbook depends on stops, or silently loses the fields that make it useful) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. Nothing is destroyed and nothing is accessed, which is why this is easy to under-rate — but every detection in `playbooks/vpc.*` reads from this source, and so does GuardDuty. The blast radius is the visibility of everything else. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | VPC (flow logs), EC2, CloudWatch Logs, S3, IAM, AWS Config, CloudTrail, GuardDuty |

**What the technique does:** three routes to one outcome. `DeleteFlowLogs` removes the
subscription outright. Deleting the destination log group, or cutting its retention to a day,
leaves the subscription reporting `ACTIVE` while nothing is retained. And the quietest — deleting
a subscription and recreating it without the custom format — keeps records flowing at exactly the
same rate while removing the fields that every version 3+ detection depends on.

**Why the usual reflexes miss it.** The reflex is an absence alert: fire when no records arrive.
Its input is precisely what the attacker removed, and four different things produce an empty
window of which only one is an incident. Worse, an idle interface still emits records —
`log-status: NODATA` — so record *presence* is not evidence that anything is being observed. And
the downgrade case produces no absence at all: the volume is unchanged, and only the fields are
gone.

**Detection thesis:** move the detection to the control plane, where the act is recorded,
attributed and timestamped. Keep the absence view as a corroborator that says *which resource*
went quiet, grouped per resource rather than account-wide — never as the alert.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail management events for `ec2.amazonaws.com` and `logs.amazonaws.com`.** There is no
  flow-log-specific event source: `CreateFlowLogs`, `DeleteFlowLogs` and `DescribeFlowLogs` are
  EC2 events, so a narrowly filtered trail will not carry them.
- **AWS Config recording `AWS::EC2::FlowLog`.** This is the only source that can answer "what
  fields did this subscription have last month", and the format cannot be read from anywhere else
  after a delete.
- **A scheduled `describe-flow-logs` snapshot**, stored with history, capturing `FlowLogStatus`,
  `DeliverLogsErrorMessage`, `LogFormat` and `MaxAggregationInterval` per subscription. A
  subscription whose delivery role lost its permissions reports `ACTIVE`, delivers nothing, and
  generates **no CloudTrail event at the moment it starts failing** — nothing was called. Only
  this snapshot finds it.
- **The organisation's standard log format, in version control**, so "downgraded" is a diff rather
  than a judgement.

**Alerting (must be pre-configured)**
- **`DeleteFlowLogs` succeeded, by a principal outside the provisioning allowlist → P0**
- **`CreateFlowLogs` succeeded with a format omitting `pkt-srcaddr`, `flow-direction` or `tcp-flags` → P0**
- **`DeleteLogGroup` on a flow log destination → P0**
- **`PutRetentionPolicy` cutting a flow log group to seven days or fewer → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under
  investigation; `jq`.
- The standard flow-log format string, ready to paste. Recreating a subscription during an
  incident from memory is how a downgrade happens twice.

**Known IOC Baselines**
- Which roles legitimately create and delete flow logs. This should be one infrastructure-as-code
  role, and the allowlist is the tuning surface for the deletion rule.
- The complete list of subscriptions, their resources and their formats, from the scheduled
  snapshot. Without it, "which one is missing" is unanswerable after the fact.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `DeleteFlowLogs` succeeded, principal outside the provisioning allowlist | CloudTrail (`ec2`) | T1685.002 |
| P0 | `CreateFlowLogs` succeeded with `logFormat` omitting `pkt-srcaddr`, `flow-direction` or `tcp-flags` — or omitted entirely | CloudTrail (`ec2`) | T1685.002 |
| P0 | `DeleteLogGroup` on a group used as a flow log destination | CloudTrail (`logs`) | T1685.002 |
| P1 | `PutRetentionPolicy` setting a flow log group to ≤ 7 days | CloudTrail (`logs`) | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A subscription reporting `FlowLogStatus: ACTIVE` with a non-empty `DeliverLogsErrorMessage` | `describe-flow-logs` state sweep | T1685.002 |
| P2 | `log-status: SKIPDATA` records present — AWS dropped records it had, so the window is incomplete by an unknown amount | VPC flow logs | T1685.002 |
| P3 | No flow records from a specific `vpc-id` for two hours — corroborating only, never the alert | VPC flow logs (per resource) | T1685.002 |

### Detection Rule Quality Notes

The source rule carries no query body — it counts every record from the integration, fewer than
one in two hours, grouped by nothing — so every row below is auditable against
`_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| An absence alert whose input is what the attacker removed | The rule can only infer the event from its own blindness, and it cannot attribute it. Nothing tells you which resource, which principal, or when | Move the detection to CloudTrail, where the act is recorded, attributed and timestamped. Absence becomes the corroborator |
| `group_by` is empty — the count is account-wide | Deleting one VPC's subscription in an account with several changes the total by a fraction and the rule never fires. The blind spot is proportional to how much else is still logging, so the rule is weakest in the largest estates | Group by resource. A gap per `vpc-id` is at least attributable, and it is the only form of the absence view worth keeping |
| Record presence treated as evidence of observation | `log-status: NODATA` means *"there was no network traffic to or from the network interface during the aggregation interval"* — an idle interface emits records saying nothing happened. So the count cannot distinguish a healthy quiet resource from a healthy busy one, and cannot use presence as proof anything is being watched | Split the count by `log-status` and read `OK`, `NODATA` and `SKIPDATA` separately. They mean three different things and one number cannot carry them |
| `SKIPDATA` is invisible to it | AWS drops records *"because of an internal capacity constraint, or an internal error"*. Partial loss produces records, so a presence check reports healthy while an unknown fraction is missing — and this is the likeliest failure during a flood, when the records matter most | A dedicated P2 trigger on `SKIPDATA` presence, treated as "this window is incomplete" rather than as an outage |
| Two-hour window against best-effort delivery | AWS gives *"about 5 minutes"* to CloudWatch Logs and *"about 10 minutes"* to S3 and states delivery *"is on a best effort basis"* with **no published maximum**. So a gap is never conclusive, and a shorter window would be worse rather than better | The window is kept for the corroborating view and explicitly not treated as conclusive. The conclusive signals are the CloudTrail events and the state sweep |
| No coverage of a format downgrade | A recreate that omits `logFormat` silently takes the version 2 default. Records arrive at the same rate, no absence alert fires, and every rule reading `tcp-flags`, `pkt-srcaddr`, `pkt-dstaddr` or `flow-direction` goes silent at once | `ec2_flow_logs_created_downgraded`, matching the **absence** of the required fields in the request — which catches a short custom format and an omitted one alike |

**Recommended detection — the control-plane acts, including the one that produces no absence at all.**

```yaml
# VPC flow log delivery stopped or downgraded (T1685.002)
#
# AN ABSENCE ALERT'S INPUT IS PRECISELY WHAT THE ATTACKER REMOVED. The source rule fires when
# fewer than one flow record arrives in two hours. That is the right instinct and the wrong
# control, for four reasons that the CloudTrail rules below exist to replace:
#
#   1. IT IS GROUPED ACCOUNT-WIDE. group_by is empty, so the rule counts every flow record in the
#      account. Deleting ONE VPC's subscription in an account with several changes the total by a
#      fraction and the rule never fires. The blind spot is exactly proportional to how much else
#      is still logging, which means the rule is weakest in the estates that need it most.
#   2. NODATA IS A RECORD. AWS: log-status NODATA means "there was no network traffic to or from
#      the network interface during the aggregation interval". An idle interface emits records
#      saying nothing happened, so record presence does not mean traffic is being observed — and
#      a genuinely quiet resource is indistinguishable from a healthy busy one by count alone.
#   3. SKIPDATA IS INVISIBLE TO IT. AWS: "some flow log records were skipped during the
#      aggregation interval... because of an internal capacity constraint, or an internal error."
#      Partial loss produces records, so a presence check reports healthy while an unknown
#      fraction of traffic is missing. This is the failure mode during a flood, when it matters.
#   4. DELIVERY IS BEST EFFORT WITH NO PUBLISHED MAXIMUM. AWS gives "about 5 minutes" to
#      CloudWatch Logs and "about 10 minutes" to Amazon S3 and states delivery "is on a best
#      effort basis". A gap is therefore never conclusive on its own, in either direction.
#
# THE AUTHORITATIVE SIGNAL IS THE CONTROL PLANE, AND IT IS THE SAME EVENT SOURCE AS EC2. There is
# no flow-log-specific eventSource; CreateFlowLogs, DeleteFlowLogs and DescribeFlowLogs are
# ec2.amazonaws.com. AWS Config records AWS::EC2::FlowLog, which gives configuration history for
# the subscription including the log format.
#
# THE DOWNGRADE IS THE QUIET ATTACK, AND ALSO THE COMMON ACCIDENT. A subscription's format cannot
# be changed — AWS: "you can't change its configuration or the flow log record format... Instead,
# you can delete the flow log and create a new one." So the delete-then-recreate pair is ordinary
# maintenance AND the way a custom format becomes the version 2 default. Records keep arriving,
# every absence alert stays quiet, and every rule that reads tcp-flags, pkt-srcaddr, pkt-dstaddr
# or flow-direction goes silent at once. Nothing is missing except the fields; that is why the
# second rule below reads the format rather than counting events.
title: VPC flow log subscription deleted
id: 8b3f27e1-5c04-49da-a760-14e9b28c6035
name: ec2_flow_logs_deleted
status: experimental
description: >-
  DeleteFlowLogs removed one or more flow log subscriptions. This is the event the absence rule
  is trying to infer, recorded directly, immediately, and attributed to a principal. It fires
  whether or not other subscriptions in the account continue delivering, which is the specific
  blind spot of an account-wide count. Deletion is also routine during infrastructure changes —
  the point is not that it is always malicious but that it must always be accounted for, and a
  deletion with no corresponding creation within minutes is the shape worth reading.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteFlowLogs.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'DeleteFlowLogs'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the infrastructure-as-code roles that own flow log lifecycle.
  # An empty list is a defensible start — it reports every deletion once, and the roles that
  # legitimately do this are few and named.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    A subscription being replaced to change its format or destination, which is the only way to
    change either. Expect a CreateFlowLogs within minutes; a deletion without one is the finding.
level: high
---
title: VPC flow log created without the organisation's standard fields
id: 4c918b70-2e36-4d51-8f24-a05e7c31d968
name: ec2_flow_logs_created_downgraded
status: experimental
description: >-
  CreateFlowLogs succeeded with a log format that omits the version 3+ fields the detection estate
  depends on. This is the silent half of the technique: records keep arriving at the same rate, no
  absence alert fires, AWS Config shows a healthy resource — and every rule reading tcp-flags,
  pkt-srcaddr, pkt-dstaddr or flow-direction stops matching, because the default format is version
  2 and contains none of them. It is also the shape of an ordinary mistake, since the format
  cannot be edited and a recreate that omits the format argument silently takes the default. The
  filter below matches the ABSENCE of the standard fields, so a subscription created with no
  logFormat at all is caught as well as one created with a short custom format.
references:
  - https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'CreateFlowLogs'
  success:
    errorCode: null
  has_packet_fields:
    requestParameters.logFormat|contains: 'pkt-srcaddr'
  has_direction:
    requestParameters.logFormat|contains: 'flow-direction'
  has_flags:
    requestParameters.logFormat|contains: 'tcp-flags'
  condition: selection and success and not (has_packet_fields and has_direction and has_flags)
falsepositives:
  - >-
    A deliberately minimal subscription for a low-value network segment, created to control cost.
    Legitimate, and it should be a recorded exception rather than a silent one — the cost of the
    exception is that every version 3+ detection is blind on that segment.
level: medium
---
title: VPC flow log delivery destination removed or truncated
id: e207a45c-6913-4b8f-90d7-3c68f1eb2a54
name: flow_log_destination_tampered
status: experimental
description: >-
  The subscription still exists and its destination does not. Deleting the CloudWatch log group,
  or cutting its retention to a day, achieves the same result as deleting the flow log while
  leaving DescribeFlowLogs reporting an ACTIVE subscription — so a state check that reads only
  FlowLogStatus is satisfied. Retention deserves particular attention: the CloudWatch Logs default
  is Never Expire, so a PutRetentionPolicy on a flow log group is always a deliberate act, and one
  setting it to a very short period destroys history without touching a single flow log API.
references:
  - https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'logs.amazonaws.com'
    eventName:
      - 'DeleteLogGroup'
      - 'PutRetentionPolicy'
  success:
    errorCode: null
  # ADJUST to the log group naming used for flow log destinations in this estate.
  flow_log_group:
    requestParameters.logGroupName|contains:
      - 'flowlog'
      - 'flow-log'
      - '/aws/vpc/'
  condition: selection and success and flow_log_group
falsepositives:
  - >-
    A deliberate retention reduction for cost. Real, and worth reading every time — the number
    chosen is the number of days of network history the organisation will have during its next
    incident, and that decision should not be made silently.
level: medium
```

What this set structurally cannot do: it cannot detect a delivery role quietly losing its
permissions, because nothing is called at the moment delivery starts failing — the subscription
reports `ACTIVE` with an error message and no event exists. Query 2 is the only thing that finds
it, and it has to run on a schedule rather than during an incident.

---

### Key Investigation Queries

> All CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log
> platform for busy windows. Flow log configuration is regional: every query here must be run in
> every Region that holds a VPC.

#### Query 1 — Reconstruct: every flow-log lifecycle event, in order

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in CreateFlowLogs DeleteFlowLogs; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       resources: (.requestParameters.resourceIds // .requestParameters.flowLogIds),
       format: (.requestParameters.logFormat // "<default: version 2 only>"),
       destination: (.requestParameters.logDestination // .requestParameters.logGroupName // "-"),
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'sort_by(.time)'
```

Read the pairs. A `DeleteFlowLogs` followed within minutes by a `CreateFlowLogs` on the same
resource is ordinary maintenance — **unless the `format` on the create reads
`<default: version 2 only>` or is missing `pkt-srcaddr`, `flow-direction` or `tcp-flags`.** That
pair is the downgrade, and it is the case no absence alert will ever report. A delete with no
matching create is the obvious one.

#### Query 2 — Sweep: the state neither log carries

```bash
REGION="us-east-1"

aws ec2 describe-flow-logs --region "$REGION" --output json | jq -r '
  .FlowLogs[] |
  ((.LogFormat // "") | contains("pkt-srcaddr")) as $pkt |
  ((.LogFormat // "") | contains("flow-direction")) as $dir |
  ((.LogFormat // "") | contains("tcp-flags")) as $flg |
  "\(if .FlowLogStatus != "ACTIVE" then "[FAIL]" elif (.DeliverLogsErrorMessage // "") != "" then "[FAIL]" elif ($pkt and $dir and $flg) then "[OK]  " else "[!]   " end) \(.FlowLogId)  resource=\(.ResourceId)  status=\(.FlowLogStatus)  interval=\(.MaxAggregationInterval)s
      fields: pkt-srcaddr=\($pkt) flow-direction=\($dir) tcp-flags=\($flg)
      error: \(.DeliverLogsErrorMessage // "none")"'

echo
echo "== every VPC, and whether anything is logging it =="
COVERED=$(aws ec2 describe-flow-logs --region "$REGION" --output json | jq -r '[.FlowLogs[].ResourceId] | unique | .[]')
for V in $(aws ec2 describe-vpcs --region "$REGION" --output json | jq -r '.Vpcs[].VpcId'); do
  echo "$COVERED" | grep -qx "$V" && echo "[OK]   $V has a flow log subscription" \
                                 || echo "[FAIL] $V has NO flow log subscription at all"
done
```

`[FAIL]` on a status or error line is a subscription that exists and is not delivering — the case
that generates no CloudTrail event, because nothing was called. `[!]` is a subscription delivering
a downgraded format: records are arriving and a subset of your detections are silent. The second
block answers the question the log cannot: a VPC that never had a subscription looks identical to
one whose subscription was removed before the retention window.

#### Query 3 — Inspect: the destination, and whether history survives

```bash
REGION="us-east-1"
LOG_GROUP="/aws/vpc/flowlogs"

aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP" --region "$REGION" --output json | \
  jq -r '.logGroups[] | "\(.logGroupName)\tretention=\(.retentionInDays // "NeverExpire")\tstored=\(.storedBytes) bytes\tcreated=\(.creationTime)"'

echo
echo "== retention changes, which destroy history without touching a flow log API =="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutRetentionPolicy \
  --start-time "$(date -u -v-90d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select((.requestParameters.logGroupName // "") | test("flow")) |
    {time: .eventTime, caller: .userIdentity.arn,
     group: .requestParameters.logGroupName,
     days: .requestParameters.retentionInDays, ip: .sourceIPAddress}' | jq -s 'sort_by(.time)'
```

The CloudWatch Logs default is **Never Expire**, so any retention value at all is a deliberate
choice somebody made. `storedBytes` dropping sharply after such a change is the history already
gone; there is no undo and no export from a group after expiry.

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

Turning off logging is rarely the objective. Read what the same principal did in the surrounding
hours — this event is usually a preparation step, and its value in an investigation is as a
timestamp that brackets everything else.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore observation first — every minute without it is a minute of the incident nobody will be
able to reconstruct later. Then establish what was lost.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being investigated.

#### Step 1 — Recreate the subscription with the standard format

```bash
REGION="us-east-1"
VPC_ID="<vpc-id>"
LOG_GROUP="/aws/vpc/flowlogs"
DELIVERY_ROLE_ARN="<flow-logs-delivery-role-arn>"

FORMAT='${version} ${account-id} ${interface-id} ${vpc-id} ${subnet-id} ${instance-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${flow-direction} ${traffic-path} ${pkt-src-aws-service} ${pkt-dst-aws-service}'

EXISTING=$(aws ec2 describe-flow-logs --region "$REGION" --output json | \
  jq -r --arg v "$VPC_ID" '[.FlowLogs[] | select(.ResourceId == $v)] | length')

if [ "$EXISTING" -gt 0 ]; then
  echo "[i] $VPC_ID already has $EXISTING subscription(s) — check the format with Query 2 before adding another"
else
  aws ec2 create-flow-logs --region "$REGION" \
    --resource-type VPC --resource-ids "$VPC_ID" \
    --traffic-type ALL --max-aggregation-interval 60 \
    --log-destination-type cloud-watch-logs \
    --log-group-name "$LOG_GROUP" \
    --deliver-logs-permission-arn "$DELIVERY_ROLE_ARN" \
    --log-format "$FORMAT" --output json | \
    jq -r 'if (.Unsuccessful | length) > 0 then "[FAIL] " + (.Unsuccessful | tostring)
           else "[OK] created " + (.FlowLogIds | join(",")) end'
fi
```

The format is pasted, not remembered — recreating from memory during an incident is how a
downgrade happens a second time. `--max-aggregation-interval 60` is deliberate: the default is 600
and it puts a 15-minute floor under every detection that reads this data.

#### Step 2 — Verify records are actually arriving, not merely that the subscription exists

```bash
REGION="us-east-1"
FLOW_LOG_ID="<flow-log-id>"

aws ec2 describe-flow-logs --flow-log-ids "$FLOW_LOG_ID" --region "$REGION" --output json | \
  jq -r '.FlowLogs[] | "status=\(.FlowLogStatus)  error=\(.DeliverLogsErrorMessage // "none")  lastStatus=\(.DeliverLogsStatus // "-")"'

echo "[i] ACTIVE is not delivery. Wait for the aggregation interval plus AWS's typical delivery"
echo "    latency — roughly 6 minutes on a 60-second subscription to CloudWatch Logs — then"
echo "    confirm records exist before declaring this restored."
```

`FlowLogStatus: ACTIVE` means the subscription object is healthy, not that anything is landing. A
delivery role without permission on the destination produces exactly this state, and it is the
failure mode with no CloudTrail event behind it.

#### Step 3 — Establish the size of the gap

The window from the `DeleteFlowLogs` in Query 1 to the create in Step 1 is unrecoverable network
history. Record the exact interval in the incident, and mark every conclusion drawn about that
period as unsupported by flow data — including any *negative* conclusion. This is the step people
skip, and it is the one that stops a future reviewer reading an empty result as an all-clear.

#### Step 4 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')      # user ARN: name = last segment
  aws iam put-user-policy --user-name "$U" --policy-name IR-Deny-All \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')       # role ARN: name = 2nd segment
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$R" --policy-name AWSRevokeOlderSessions \
    --policy-document file:///tmp/revoke.json
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

---

## 4. Eradication

### Remove Attacker Access

#### Bring every subscription up to the standard

Query 2's `[!]` lines are subscriptions delivering a downgraded format. Each one must be deleted
and recreated — the format cannot be edited — and each one is a set of detections that are
currently silent rather than quiet. Do them together, and record which resources were affected and
for how long.

#### Cover every VPC

Query 2's second block lists VPCs with no subscription at all. A VPC that never had one is
indistinguishable from one whose subscription was deleted before the CloudTrail retention window,
so treat both as gaps to close rather than as history to investigate.

#### Right-size who can touch flow log lifecycle

`ec2:DeleteFlowLogs`, `ec2:CreateFlowLogs`, `logs:DeleteLogGroup` and `logs:PutRetentionPolicy`
belong to an infrastructure role, not to application deploy credentials. Query 4's principal is
the starting point.

#### Remove emergency policies once clean

Delete `IR-Deny-All` and `AWSRevokeOlderSessions` once the principal is rebuilt or cleared.

---

## 5. Recovery

### Restore Clean State

#### Verify every VPC is covered by a standard-format subscription

```bash
REGION="us-east-1"
BAD=$(aws ec2 describe-flow-logs --region "$REGION" --output json | jq '
  [ .FlowLogs[]
    | select(.FlowLogStatus != "ACTIVE"
             or ((.DeliverLogsErrorMessage // "") != "")
             or (((.LogFormat // "") | contains("pkt-srcaddr")) | not)
             or (((.LogFormat // "") | contains("flow-direction")) | not)
             or (((.LogFormat // "") | contains("tcp-flags")) | not)) ] | length')
[ "$BAD" -eq 0 ] && echo "[OK] every subscription is ACTIVE, error-free and carries the standard fields" \
                 || echo "[FAIL] $BAD subscription(s) failing or downgraded — re-run Query 2"

UNCOVERED=0
COVERED=$(aws ec2 describe-flow-logs --region "$REGION" --output json | jq -r '[.FlowLogs[].ResourceId] | unique | .[]')
for V in $(aws ec2 describe-vpcs --region "$REGION" --output json | jq -r '.Vpcs[].VpcId'); do
  echo "$COVERED" | grep -qx "$V" || UNCOVERED=$((UNCOVERED + 1))
done
[ "$UNCOVERED" -eq 0 ] && echo "[OK] every VPC in $REGION has a subscription" \
                       || echo "[FAIL] $UNCOVERED VPC(s) with no flow log at all"
```

#### Confirm records are landing with the fields present

```bash
echo "[i] Query the destination for records in the last 15 minutes and confirm that pktSrcAddr,"
echo "    flowDirection and tcpFlags are populated — not merely that rows exist. A downgraded"
echo "    subscription produces rows at the normal rate with those columns absent, which is the"
echo "    exact state this playbook exists to catch."
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  eventSource=ec2.amazonaws.com  eventName=DeleteFlowLogs  no errorCode"
echo "  by an ARN outside known_provisioners"
echo "and MUST fire on the case the source rule cannot see at all:"
echo "  eventName=CreateFlowLogs  no errorCode  requestParameters.logFormat absent"
echo "  (records keep arriving at the normal rate; no absence alert will ever fire)"
echo "The rule MUST NOT fire on:"
echo "  CreateFlowLogs whose logFormat contains pkt-srcaddr, flow-direction and tcp-flags"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| Flow log delivery stopped and the alert did not fire | The rule counted records account-wide, so one subscription's removal changed the total by a fraction |
| A downgraded subscription went unnoticed | No rule read the log format; volume was unchanged, so every absence-based check reported healthy |
| A failing delivery role was invisible | The subscription reports `ACTIVE` and nothing is called when delivery starts failing, so no CloudTrail event exists — only a scheduled state read finds it |
| The gap could not be sized afterwards | No scheduled snapshot of subscriptions and formats existed, so "what did we lose" had no baseline |
| GuardDuty was quiet and that was read as reassurance | GuardDuty consumes VPC flow logs as a data source, so this technique degrades it too |

### Recommended Guardrails

**Fence flow log lifecycle and its destination**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["ec2:DeleteFlowLogs", "ec2:CreateFlowLogs",
             "logs:DeleteLogGroup", "logs:PutRetentionPolicy"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Define the standard log format once, organisation-wide, and create every subscription from it.
  The format cannot be changed after creation, so this decision is made once — deliberately, or by
  accident on the day somebody recreates a subscription in a hurry.
- Record `AWS::EC2::FlowLog` in AWS Config. It is the only source of configuration history for the
  format, and the only way to answer "what fields did this have last month" after a delete.
- Deliver to a destination in a separate account with a bucket policy the workload account cannot
  modify. This separates the ability to stop logging from the ability to destroy what was logged.
- Set retention deliberately and treat the number as a decision about future incident response.
  The default is Never Expire, so every value is a choice.

**Detection improvements**
- Alert on the *format* of a created subscription, not only on the fact of creation. The downgrade
  is the one path through this technique that produces no absence signal whatsoever.
- Run the state sweep on a schedule and alert on `FlowLogStatus` or `DeliverLogsErrorMessage`.
  There is no event for the moment delivery starts failing, so a scheduled read is the only way.
- Split absence monitoring by resource and by `log-status`. `OK`, `NODATA` and `SKIPDATA` mean
  three different things, and a single count of records carries none of them.
- Alert on a VPC having **no** subscription at all, as a coverage check independent of everything
  above. A resource that was never logged is invisible to every rule in this file.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log |
| MITRE tactic | Defense Impairment (TA0112) |
| Primary API | `ec2:DeleteFlowLogs`; `ec2:CreateFlowLogs` with a downgraded format; `logs:DeleteLogGroup`; `logs:PutRetentionPolicy` |
| Event source | ec2.amazonaws.com and logs.amazonaws.com — there is **no** flow-log-specific event source |
| Key discriminator | The control-plane act itself. For the downgrade, the absence of `pkt-srcaddr`, `flow-direction` and `tcp-flags` from `requestParameters.logFormat` |
| Ground-truth signal | `describe-flow-logs` — `FlowLogStatus`, `DeliverLogsErrorMessage` and `LogFormat` per subscription. Live state, not a log |
| "Was it used" pivot | The gap between the delete and the recreate, cross-referenced against what the same principal did in that window |
| Blast radius | Every detection in `playbooks/vpc.*`, plus GuardDuty, which consumes flow logs as a data source |
| Error strings | `UnsuccessfulItem` entries in the `CreateFlowLogs` response; `DeliverLogsErrorMessage` on a subscription that is `ACTIVE` and not delivering |

**MITRE mapping note:** `T1685.002` is the correct current identifier and describes this exactly. Verified live
2026-08-30.

### Residual Risk

The window between the deletion and the restoration is unrecoverable, and no negative conclusion
about that period is supportable — including "nothing happened". If the subscription was
downgraded rather than deleted, the gap is subtler and longer: records exist for the whole period
and simply cannot answer any question that needs `pkt-srcaddr`, `flow-direction` or `tcp-flags`,
which is most of what the other `vpc.*` playbooks ask. Any window containing `SKIPDATA` is
incomplete by an amount AWS does not report. And because GuardDuty reads this same source, its
silence over the affected period carries no information either — a fact worth writing into the
incident explicitly, because "GuardDuty saw nothing" is otherwise read as evidence.

---

## Source

Adapted from the standalone IR playbook `playbooks/vpc.stealth.no-logs-from-amazon-vpc-flow-logs/`, which covers the same detection use
case more broadly than this emulation exercises. That folder also carries the full Sigma and KQL
rule set for the use case; only the rules this emulation's attack actually fires are shipped in
`detections/` here.
