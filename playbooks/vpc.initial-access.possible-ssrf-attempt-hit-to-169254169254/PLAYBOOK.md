# IR Playbook: Server-Side Request Forgery Against the VPC — `ModifyInstanceMetadataOptions` and the half AWS actually records

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Exploitation of a public-facing application, used to reach hosts and ports the application itself is trusted to reach |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. An SSRF primitive inherits the application's network position, which is usually inside every security group that matters. The ceiling is whatever the reachable backends hold, plus the instance profile's permissions if the metadata half also succeeded — and the metadata half leaves no network trace at all. The source rule rates this P2; the rating is not the problem with it. |
| MITRE Tactics | Initial Access, Discovery |
| MITRE Techniques | T1190 |
| Services in Scope | VPC (flow logs), EC2 (instance metadata options, security groups), IAM, STS, CloudTrail, GuardDuty |

**What the technique does:** an attacker finds a request parameter the application will fetch on
their behalf — a webhook URL, an image importer, a PDF renderer, an XML parser resolving external
entities — and points it inward. The application makes the request, from inside the VPC, with the
application's own network position. The famous target is `169.254.169.254`, which returns instance
profile credentials. The more common one, and the one that works even where IMDSv2 has closed that
door, is everything else: the database subnet, the cache, the internal admin panel, the Kubernetes
API server, the other microservice with no authentication because "it's internal".

**Why the usual reflexes miss it, and this is the whole point of the playbook.** A responder
investigating suspected metadata SSRF queries VPC Flow Logs for `169.254.169.254`, gets nothing,
and concludes it did not happen. The query was correct and the conclusion is wrong. AWS's *Flow log
limitations* page lists, among the traffic flow logs do not capture:

> Traffic to and from `169.254.169.254` for instance metadata.

There is no configuration under which that record exists. **The source rule for this use case
matches exactly that address, and therefore cannot fire — in any account, ever.** A rule that
cannot fire is worse than a missing one: it reports clean forever and a coverage review reads it
as satisfied.

**Detection thesis:** only the link-local metadata address is excluded. Every other destination the
same primitive reaches is logged, so detect the primitive by its network behaviour — an
application server opening connections it has no client library for — rather than by the one
destination AWS declines to record.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **A flow-log subscription created with a custom format, not the default.** This is the single
  prerequisite that cannot be met retroactively: AWS states *"After you create a flow log, you
  can't change its configuration or the flow log record format... Instead, you can delete the flow
  log and create a new one with the required configuration."* The minimum useful format is:

  ```
  ${version} ${account-id} ${interface-id} ${vpc-id} ${subnet-id} ${instance-id}
  ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes}
  ${start} ${end} ${action} ${log-status} ${tcp-flags} ${type}
  ${pkt-srcaddr} ${pkt-dstaddr} ${flow-direction} ${traffic-path}
  ${pkt-src-aws-service} ${pkt-dst-aws-service}
  ```

  The default format is version 2 and contains none of `pkt-srcaddr`, `pkt-dstaddr`,
  `flow-direction`, `tcp-flags` or `vpc-id`. Rules built on those fields against a default-format
  subscription are **silent**, not noisy.
- **A 1-minute maximum aggregation interval** where the cost is acceptable. The default is 10
  minutes, which sets the floor on every alerting window.
- **CloudTrail management events for `ec2.amazonaws.com`**, for `ModifyInstanceMetadataOptions`,
  `CreateFlowLogs` and `DeleteFlowLogs`.
- **An inventory of which interfaces belong to which tier**, keyed by `interface-id`. Every rule
  here is an allowlist of expected behaviour, and the allowlist is the tier map.

**Alerting (must be pre-configured)**
- **An application-tier interface opened an accepted egress TCP flow to an internal address on a database or control-plane port → P0**
- **One interface reached 50 or more distinct internal destinations within 30 minutes → P0**
- **`ModifyInstanceMetadataOptions` set `httpTokens` to `optional` or raised `httpPutResponseHopLimit` above 1 → P1**
- **An instance-profile role session was used from an address outside the fleet's egress range → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any instance role under
  investigation; `jq`.
- A pre-created **quarantine security group** with no ingress and no egress, in every VPC. The
  containment step attaches it; creating one during an incident costs the minutes that matter.
- The application's own dependency list — which backends it is *supposed* to reach. Without it,
  every finding is a judgement call.

**Known IOC Baselines**
- The fleet's NAT gateway and egress addresses, so an instance-profile session used from anywhere
  else is a one-field test.
- Which instances run with `HttpTokens: optional`, as a standing inventory rather than a query
  run during an incident.
- The expected fan-out of service-mesh sidecars, health checkers and monitoring agents. These
  legitimately reach many destinations and are the entire false-positive surface of the fan-out
  rule.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `flow-direction: egress`, `action: ACCEPT`, `protocol: 6`, `pkt-dstaddr` private, `dstport` in the backend set, from an interface not on the backend-client allowlist | VPC flow logs (v5 format) | T1046 |
| P0 | One `interface-id` reached ≥ 50 distinct `pkt-dstaddr` values in 30 minutes | VPC flow logs (correlation) | T1046 |
| P1 | `ModifyInstanceMetadataOptions` with `httpTokens: optional` or `httpPutResponseHopLimit` > 1 | CloudTrail (`ec2`) | T1552.005 |
| P1 | An instance-profile role session used from an address outside the fleet's egress range — this technique's outcome, detected by `../ec2.credential-access.imds-credential-theft/` | CloudTrail | T1552.005 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Wide internal fan-out in which rejections outnumber accepts five to one | VPC flow logs | T1046 |
| P2 | An inbound request carrying a metadata SSRF signature reached the application — detected by `../waf.credential-access.crs-ssrf-ec2-metadata/` | Web ACL logs | T1190 |
| P3 | Flow logs for the VPC under investigation deleted, or `log-status: SKIPDATA` present in the window — this playbook's only telemetry is unreliable for that period | CloudTrail (`ec2`), VPC flow logs | T1685.002 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Matches `169.254.169.254` in VPC Flow Logs | **The rule cannot fire.** AWS lists "Traffic to and from `169.254.169.254` for instance metadata" among traffic flow logs do not capture. No format, interval or field selection changes this. It reports clean in every account forever, and a coverage review reads that as satisfied | No correction exists for the rule as written. Detect the primitive by its network behaviour against every destination that *is* logged, and get the metadata half from CloudTrail and web ACL logs — the two playbooks named in §1 |
| Groups by a geo-enrichment address field | Behind a NAT gateway, AWS shows *"the primary private IPv4 address"* of the interface rather than the packet's address, so every client in the VPC collapses to one value and any per-source threshold is meaningless | Group by `interface-id`, and read addresses from `pkt-srcaddr` / `pkt-dstaddr` — version 3 fields, which is why §1 specifies the custom format |
| No direction filter | Without `flow-direction`, an inbound connection *to* the application and an outbound connection *from* it are the same match. The technique is entirely about the outbound half | `flow-direction: egress` — a version 5 field, absent from the default format, which is why its absence is surfaced as a `Degraded` column rather than silently tolerated |
| Success-only, via `action: "ACCEPT"` | Correct here, and worth stating: the refused half is the enumeration and is the earlier signal. It is kept as a separate ratio-based trigger rather than folded in, because AWS documents `REJECT` as also covering *"packets arrived after the connection was closed"* — ordinary teardown races, which would swamp a raw count | A P2 trigger on the accept-to-reject ratio, not on rejection volume |
| A 15-minute window on a threshold of zero | The default maximum aggregation interval is 10 minutes and delivery is *"about 10 minutes"* to S3, best effort. A threshold of zero makes the window moot for this rule, but the same 15-minute figure is reused across the pack for rules where it is not | Windows stated relative to the aggregation interval, with 30m as the shipped default and an explicit note that it may only be shortened on a 1-minute subscription |

**Recommended detection — the primitive's network behaviour, plus the control-plane precondition.**

```yaml
# Server-side request forgery seen from the network side (T1190 / T1046 / T1552.005)
#
# THE SOURCE RULE CANNOT FIRE, AND THIS IS NOT A TUNING OPINION. It matches
# `dstaddr: 169.254.169.254` in VPC Flow Logs. AWS's flow log limitations page lists, among the
# traffic that is not logged:
#
#     "Traffic to and from 169.254.169.254 for instance metadata."
#
# There is no configuration, no custom format, no aggregation interval and no field selection
# that makes that record appear. The rule reports clean forever, in every account, which is worse
# than absent — it occupies the slot a working detection would fill and it makes an audit look
# satisfied. Nothing below matches that address.
#
# WHAT IS ACTUALLY VISIBLE, AND WHY IT IS WORTH MORE THAN THE ORIGINAL INTENT. Only the link-local
# metadata address is excluded. Every OTHER destination an SSRF primitive reaches IS logged, and
# an application server making connections it has no business making is the same primitive
# producing a signal the platform does record. An SSRF that can reach 169.254.169.254 can reach
# the database subnet, the Redis node, the internal admin panel and the EKS API server — and
# those flows are in the log. The rules below detect the primitive by its network behaviour
# rather than by the one destination AWS declines to record.
#
# The IMDS half of this technique is covered by two other playbooks and is NOT restated here:
# ../../ec2.credential-access.imds-credential-theft/ detects the stolen session being used
# off-instance in CloudTrail, and ../../waf.credential-access.crs-ssrf-ec2-metadata/ detects the
# inbound request carrying the metadata signature. This playbook is the third, disjoint view.
#
# FIELDS USED HERE ARE NOT ALL IN THE DEFAULT FORMAT. `flow-direction` is version 5 and
# `pkt-srcaddr`/`pkt-dstaddr` are version 3; the default format is version 2 only. AWS: "After
# you create a flow log, you can't change its configuration or the flow log record format...
# Instead, you can delete the flow log and create a new one with the required configuration." So
# a subscription created with the default format makes every rule below silent, not noisy. The
# required custom format is stated in §1 of ../PLAYBOOK.md and must be in place BEFORE an
# incident. Field names are given in the hyphenated log-record form; a pipeline that renames them
# to snake_case must be adjusted for consistently.
#
# `protocol` IS AN IANA NUMBER, NOT A NAME. 6 is TCP, 17 UDP, 1 ICMP. A rule written as
# protocol: 'TCP' matches nothing.
title: Application tier initiated connections to internal management ports
id: 0f4b7a2e-6c39-4d81-95b7-3a08e26cf417
name: vpc_apptier_internal_probe
status: experimental
description: >-
  An interface in an application subnet opened egress connections to private addresses on ports
  that belong to databases, caches and management planes. A web server talks to the small fixed
  set of backends its code names; it does not reach a port it has no client library for. This is
  the network shape of a server-side request forgery being used to explore the VPC, and it is the
  half of the technique AWS actually records. Ports are grouped deliberately: a single application
  reaching several of these classes in one window is not a misconfiguration.
references:
  - https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html
  - https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
  - https://attack.mitre.org/techniques/T1046/
tags:
  - attack.discovery
  - attack.t1046
  - attack.t1190
logsource:
  product: aws
  service: vpcflowlogs
detection:
  outbound:
    flow-direction: 'egress'
    action: 'ACCEPT'
    protocol: 6
  internal_target:
    pkt-dstaddr|startswith:
      - '10.'
      - '192.168.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.2'
      - '172.30.'
      - '172.31.'
  sensitive_port:
    dstport:
      - 3306      # MySQL / MariaDB / Aurora MySQL
      - 5432      # PostgreSQL / Aurora PostgreSQL
      - 1433      # SQL Server
      - 1521      # Oracle
      - 5439      # Redshift
      - 27017     # MongoDB / DocumentDB
      - 6379      # Redis / ElastiCache
      - 11211     # Memcached
      - 9200      # OpenSearch / Elasticsearch HTTP
      - 2379      # etcd
      - 6443      # Kubernetes API server
      - 8500      # Consul
      - 9000      # MinIO and assorted admin panels
  # POPULATE BEFORE DEPLOYING with the interfaces of the tier that legitimately talks to these
  # ports — the application's own database clients. This is the entire tuning surface, it is
  # small, and it is stable. Leaving it empty is a defensible start: the rule then reports every
  # backend connection in the VPC once, which is how the allowlist gets built.
  known_backend_clients:
    interface-id:
      - 'eni-0000000000000000a'
      - 'eni-0000000000000000b'
  condition: outbound and internal_target and sensitive_port and not known_backend_clients
falsepositives:
  - >-
    A new service genuinely adopting a backend it did not previously use. Real, and it should
    arrive with a deployment — correlate against the change, and add the interface, not the port.
  - >-
    The 172.16.0.0/12 range is matched by prefix here because Sigma has no CIDR operator that
    every backend implements. '172.2' covers 172.20-172.29 and also matches 172.2.x, which is
    public space. A backend supporting CIDR should use 172.16.0.0/12 instead; the imprecision is
    stated rather than hidden, and it errs toward matching more.
level: high
---
title: Outbound TCP flow from an interface
id: 8c15d340-7ba2-49e6-8f03-d21e694b5c78
name: vpc_egress_tcp_flow
status: experimental
description: >-
  Base rule — correlation component only, not for direct alerting. Every outbound TCP flow. It
  exists so the fan-out correlation below has something to count, and it fires on essentially all
  egress traffic, so it must never be routed anywhere on its own.
references:
  - https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
tags:
  - attack.discovery
  - attack.t1046
logsource:
  product: aws
  service: vpcflowlogs
detection:
  outbound:
    flow-direction: 'egress'
    protocol: 6
  condition: outbound
level: informational
---
title: One source reached many distinct internal destinations in a short window
id: d7290b6e-4c31-48fa-9057-1e63bc80a94d
status: experimental
description: >-
  A single interface opened connections to an unusual number of DISTINCT internal addresses. An
  SSRF primitive is driven by whoever holds it, and the first thing they do with it is enumerate —
  the same shape as a port scan but originating from a trusted host, which is why perimeter
  controls do not see it. This counts distinct destinations rather than volume on purpose:
  exploration is wide and shallow, and a byte-count threshold misses it entirely. Note the field —
  pkt-dstaddr, not dstaddr. Behind a NAT gateway or an EKS node ENI, AWS states dstaddr shows
  "the primary private IPv4 address" of the interface rather than the real destination, which
  would collapse the fan-out to one value and guarantee this never fires. Timespan is 30m against
  the DEFAULT 10-minute aggregation interval plus AWS's typical delivery latency; on a 1-minute
  Nitro subscription it can be shortened, on the default it must not be, because a window shorter
  than the aggregation interval measures nothing.
references:
  - https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
  - https://attack.mitre.org/techniques/T1046/
tags:
  - attack.discovery
  - attack.t1046
correlation:
  type: value_count
  rules:
    - vpc_egress_tcp_flow
  group-by:
    - interface-id
  timespan: 30m
  condition:
    field: pkt-dstaddr
    gte: 50
falsepositives:
  - >-
    Service-mesh sidecars, health checkers and monitoring agents legitimately fan out. They are a
    small, named set of interfaces — exclude them by interface-id, and keep the threshold.
level: medium
---
title: EC2 instance metadata options weakened
id: 43e9c706-1f58-4a02-b6d3-90c7581ea24b
name: ec2_imds_weakened
status: experimental
description: >-
  ModifyInstanceMetadataOptions set HttpTokens to optional, re-enabling IMDSv1, or raised
  HttpPutResponseHopLimit above 1. This is the control-plane precondition for the whole technique
  and it is the one part of it that CloudTrail does record — which is why it is in this file even
  though its logsource differs from the rules above. IMDSv1 answers an unauthenticated GET, so a
  forged request reaches it; IMDSv2 requires a token from a prior PUT carrying a header a
  server-side forgery cannot set. A hop limit above 1 lets a container on the host reach the
  metadata service through the host's network namespace, which is the same weakening by a
  different route.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html
  - https://attack.mitre.org/techniques/T1552/005/
tags:
  - attack.credential-access
  - attack.t1552.005
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'ModifyInstanceMetadataOptions'
  success:
    errorCode: null
  weakened:
    requestParameters.httpTokens: 'optional'
  hop_raised:
    requestParameters.httpPutResponseHopLimit:
      - 2
      - 3
      - 4
      - 5
  condition: selection and success and (weakened or hop_raised)
falsepositives:
  - >-
    A legacy application that cannot be made to perform the IMDSv2 handshake. Real, and it is a
    finding rather than an exception — the instance is one SSRF away from handing out a role
    session, and the correct fix is the application.
  - >-
    Container platforms that require a hop limit of 2 to serve pods. Also real; allowlist the
    provisioning role, and note that the raised limit is exactly the exposure being accepted.
level: medium
```

What this set structurally cannot do: it cannot see the metadata request. Nothing can, on the
network. It cannot tell you what happened inside an accepted flow — flow logs are 5-tuple counters,
so a connection to port 3306 proves reachability and says nothing about whether a query ran. And
it cannot distinguish "no matching flow" from "records dropped": `log-status: SKIPDATA` means AWS
discarded records *"because of an internal capacity constraint, or an internal error"*.

---

### Key Investigation Queries

> Queries 1 and 2 read **CloudWatch Logs Insights** against the flow log group. Insights
> auto-discovers VPC flow log fields in **camelCase** — `srcAddr`, `dstAddr`, `dstPort`, `action`,
> `logStatus`, `flowDirection`, `pktSrcAddr`, `pktDstAddr`, `interfaceId` — while the log record
> format uses hyphens. Both spellings appear in this playbook on purpose, each in its own context.
> Queries 3 and 4 read CloudTrail. Extraction uses
> `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50
> events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: everything this interface reached

```bash
REGION="us-east-1"
LOG_GROUP="/aws/vpc/flowlogs"
ENI="<interface-id-from-the-alert>"
START=$(date -u -v-24H +%s 2>/dev/null || date -u -d '24 hours ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string "fields @timestamp, pktSrcAddr, pktDstAddr, dstPort, protocol, action,
                         flowDirection, bytes, packets, logStatus
                  | filter interfaceId = '${ENI}'
                  | filter logStatus = 'OK'
                  | stats count() as flows, sum(bytes) as total_bytes
                          by pktDstAddr, dstPort, action
                  | sort flows desc
                  | limit 200")

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'
```

`filter logStatus = 'OK'` is deliberate and must stay: `SKIPDATA` rows mean records were dropped
and `NODATA` rows mean the interface was idle, and including either turns a count into a guess.
Read the destination list against the application's dependency list from §1. A port the service
has no client library for is the finding, regardless of volume — one connection to 6379 matters
more than a million to 443.

#### Query 2 — Sweep: what the flow logs can actually tell you

```bash
REGION="us-east-1"

aws ec2 describe-flow-logs --region "$REGION" --output json | jq -r '
  .FlowLogs[] |
  "\(.FlowLogId)\t\(.ResourceId)\tstatus=\(.FlowLogStatus)\tinterval=\(.MaxAggregationInterval)s\n    format: \(.LogFormat // "DEFAULT (version 2 only)")"'

echo
echo "== does the format carry the fields this playbook needs? =="
for F in pkt-srcaddr pkt-dstaddr flow-direction tcp-flags vpc-id; do
  N=$(aws ec2 describe-flow-logs --region "$REGION" --output json | \
      jq -r --arg f "$F" '[.FlowLogs[] | select((.LogFormat // "") | contains($f))] | length')
  T=$(aws ec2 describe-flow-logs --region "$REGION" --output json | jq -r '.FlowLogs | length')
  [ "$N" -eq "$T" ] && echo "[OK]   $F present on all $T subscription(s)" \
                    || echo "[FAIL] $F present on only $N of $T — rules using it are SILENT on the rest"
done
```

Run this **before** trusting any negative result from Query 1. A `[FAIL]` row does not mean the
rule is noisy; it means the rule produces nothing, and the format cannot be changed — the
subscription must be deleted and recreated. Note also `MaxAggregationInterval`: at 600 seconds,
no alerting window under about 20 minutes is sound.

#### Query 3 — Inspect: the metadata door, which the network cannot show you

```bash
REGION="us-east-1"
INSTANCE="<instance-id>"

echo "== this instance =="
aws ec2 describe-instances --instance-ids "$INSTANCE" --region "$REGION" --output json | \
  jq -r '.Reservations[].Instances[] |
    "state=\(.State.Name)\nprofile=\(.IamInstanceProfile.Arn // "<none>")\nIMDS: tokens=\(.MetadataOptions.HttpTokens) hop=\(.MetadataOptions.HttpPutResponseHopLimit) endpoint=\(.MetadataOptions.HttpEndpoint)"'

echo
echo "== the whole fleet — IMDSv1 still answers an unauthenticated GET =="
WEAK=$(aws ec2 describe-instances --region "$REGION" --output json | \
  jq -r '[.Reservations[].Instances[] | select(.MetadataOptions.HttpTokens != "required")
         | .InstanceId] | length')
[ "$WEAK" -eq 0 ] && echo "[OK] every instance requires IMDSv2" \
                  || echo "[FAIL] $WEAK instance(s) accept IMDSv1 — each is one SSRF from a role session"

echo
echo "== who changed metadata options recently =="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyInstanceMetadataOptions \
  --start-time "$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     instance: .requestParameters.instanceId,
     tokens: .requestParameters.httpTokens,
     hop: .requestParameters.httpPutResponseHopLimit,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | jq -s 'sort_by(.time)'
```

`HttpTokens: required` is what makes the metadata half fail: IMDSv2 needs a token from a prior
`PUT`, presented in a header a server-side forgery cannot set. A hop limit above 1 reopens the
door for a container reaching the host's namespace.

#### Query 4 — Full session reconstruction of the instance's role

```bash
REGION="us-east-1"
ROLE_NAME="<role-name-from-Query-3>"
SINCE=$(date -u -v-24H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$ROLE_NAME" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     arn: .userIdentity.arn, ip: .sourceIPAddress,
     error: (.errorCode // "SUCCESS")}' | \
  jq -s 'group_by(.ip) | map({ip: .[0].ip, calls: length, sources: (map(.src) | unique)})'
```

This is the decisive question and it is not answered by any network telemetry. If the role's
session appears from an address that is not the instance and not the fleet's NAT egress, the
credential left the host — and the incident is the one in
`../ec2.credential-access.imds-credential-theft/`, which has the full procedure for a
credential with no IAM object behind it.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Cut the primitive first — it is a live capability, not a past event, and while the application is
serving requests the attacker can re-run every step including re-fetching credentials. Preserve
the instance; do not terminate it.

> Run every command under the **break-glass responder credentials** from §1, never under the
> instance's own role.

#### Step 1 — Isolate the interface without destroying it

```bash
REGION="us-east-1"
INSTANCE="<instance-id>"
QUARANTINE_SG="<pre-created-sg-with-no-rules>"

if ! aws ec2 describe-security-groups --group-ids "$QUARANTINE_SG" --region "$REGION" >/dev/null 2>&1; then
  echo "[FAIL] quarantine SG $QUARANTINE_SG does not exist — create it in §1, not now"
else
  ORIG=$(aws ec2 describe-instances --instance-ids "$INSTANCE" --region "$REGION" --output json | \
         jq -r '[.Reservations[].Instances[].SecurityGroups[].GroupId] | join(",")')
  echo "[i] original security groups: $ORIG   — record this before replacing them"
  ENI_ID=$(aws ec2 describe-instances --instance-ids "$INSTANCE" --region "$REGION" --output json | \
           jq -r '.Reservations[].Instances[].NetworkInterfaces[0].NetworkInterfaceId')
  aws ec2 modify-network-interface-attribute --network-interface-id "$ENI_ID" \
    --groups "$QUARANTINE_SG" --region "$REGION" \
    && echo "[OK] $ENI_ID moved to quarantine"
fi
```

Replacing the security groups stops new connections while leaving the instance running, its memory
intact and its disk attached. Terminating it destroys the evidence that explains how the SSRF got
in, and does nothing about the credentials — those are already elsewhere if they left.

#### Step 2 — Close the metadata door on this instance and the fleet

```bash
REGION="us-east-1"

aws ec2 modify-instance-metadata-options --instance-id "$INSTANCE" \
  --http-tokens required --http-put-response-hop-limit 1 \
  --http-endpoint enabled --region "$REGION" --output json | \
  jq -r '"[OK] \(.InstanceId): tokens=\(.InstanceMetadataOptions.HttpTokens) hop=\(.InstanceMetadataOptions.HttpPutResponseHopLimit)"'

echo
echo "[i] fleet-wide — review before running, this can break an application that uses IMDSv1:"
aws ec2 describe-instances --region "$REGION" --output json | \
  jq -r '.Reservations[].Instances[] | select(.MetadataOptions.HttpTokens != "required")
         | "aws ec2 modify-instance-metadata-options --instance-id \(.InstanceId) --http-tokens required --http-put-response-hop-limit 1 --region '"$REGION"'"'
```

The fleet-wide form is emitted as commands rather than executed. An application that reads
metadata over IMDSv1 stops working the moment `required` is set, and turning that into an outage
during an active incident helps nobody.

#### Step 3 — Revoke the role's existing sessions

```bash
ROLE_NAME="<role-name-from-Query-3>"

if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name AWSRevokeOlderSessions \
    --policy-document file:///tmp/revoke.json \
    && echo "[OK] sessions issued before now are denied on $ROLE_NAME"
  echo "[!] this is defeated by a single re-fetch if the SSRF primitive still works."
  echo "    Step 1 must be complete first, or this buys nothing."
fi
```

The ordering matters and is the reason this is Step 3. `aws:TokenIssueTime` denies sessions issued
before a moment; an attacker who still holds the primitive simply fetches a new one.

#### Step 4 — Establish what the reachable backends hold

Query 1's destination list is the blast radius. For each backend the interface reached and should
not have, treat the data as accessed: flow logs record that the connection was accepted, never
what crossed it. Database audit logs, if enabled, are the only source that can narrow it.

---

## 4. Eradication

### Remove Attacker Access

#### Fix the application, because everything else is compensating control

The SSRF is a defect in request handling — a URL taken from user input and fetched without an
allowlist. Metadata hardening, egress rules and network segmentation all raise the cost; only the
code fix removes the primitive. Record the parameter and the code path in the incident.

#### Remove the reachability that made enumeration productive

```bash
REGION="us-east-1"
APP_SG="<application-tier-sg>"

aws ec2 describe-security-groups --group-ids "$APP_SG" --region "$REGION" --output json | \
  jq -r '.SecurityGroups[].IpPermissionsEgress[] |
    "egress: proto=\(.IpProtocol) ports=\(.FromPort // "all")-\(.ToPort // "all") to=\([.IpRanges[]?.CidrIp, .UserIdGroupPairs[]?.GroupId] | join(","))"'
```

An application tier with unrestricted egress lets one SSRF reach everything in the VPC. Egress
rules naming the specific backend security groups turn a full enumeration into a handful of
refused flows — which the P2 ratio trigger then reports.

#### Right-size the instance profile

The credentials are only worth stealing for what they can do. Compare the role's policies against
the API calls the application actually makes, from Query 4's `sources` list over a normal week.

#### Remove emergency policies once clean

Delete `AWSRevokeOlderSessions` after the instance is rebuilt and the application fixed, and
return the interface's security groups to the recorded originals from Step 1.

---

## 5. Recovery

### Restore Clean State

#### Verify the metadata service is closed fleet-wide

```bash
REGION="us-east-1"
WEAK=$(aws ec2 describe-instances --region "$REGION" --output json | \
  jq -r '[.Reservations[].Instances[]
         | select(.State.Name == "running")
         | select(.MetadataOptions.HttpTokens != "required" or .MetadataOptions.HttpPutResponseHopLimit > 1)
         | .InstanceId] | length')
[ "$WEAK" -eq 0 ] && echo "[OK] every running instance requires IMDSv2 with hop limit 1" \
                  || echo "[FAIL] $WEAK instance(s) still reachable by a forged request"
```

#### Verify the flow logs can still answer the question

Re-run Query 2. Every subscription must carry `pkt-srcaddr`, `pkt-dstaddr` and `flow-direction`,
or the detections in this playbook are silent — and a silent detection is the failure this whole
playbook exists to document.

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  flow-direction=egress  action=ACCEPT  protocol=6"
echo "  pkt-dstaddr=10.0.2.44  dstport=6379  interface-id=<app-tier-eni not on the allowlist>"
echo "The rule MUST NOT fire on:"
echo "  the same flow from an interface listed in known_backend_clients"
echo "  the same flow with dstport=443 (ordinary outbound HTTPS)"
echo "and there is NO synthetic test for:"
echo "  dstaddr=169.254.169.254 — AWS does not write that record, so no rule can fire on it."
echo "  Any rule that claims to is a rule nobody has ever seen fire."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| The application fetched a URL taken from request input | No allowlist on outbound fetches; the SSRF primitive itself |
| The primitive reached backends the application never uses | Application-tier security group permitted unrestricted egress inside the VPC |
| Instance profile credentials were obtainable | `HttpTokens` left at `optional`, or a hop limit above 1, so an unauthenticated GET succeeded |
| The detection for this technique had never fired and nobody noticed | It matched an address AWS documents as not logged. Nothing distinguishes "no attacks" from "cannot fire" without reading the platform's limitations |
| The negative result from flow logs was read as absence | The limitation is on a page nobody reads during an incident; the empty result looked like an answer |

### Recommended Guardrails

**Make IMDSv2 non-optional at the account boundary**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["ec2:RunInstances"],
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": { "StringNotEquals": { "ec2:MetadataHttpTokens": "required" } }
}
```

**Stop the flow-log format being downgraded**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["ec2:DeleteFlowLogs", "ec2:ModifyInstanceMetadataOptions"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Set the flow-log format once, centrally, as the organisation's standard, and create every
  subscription from it. The format cannot be changed later, so this is a one-shot decision made
  either deliberately or by accident.
- Egress security groups on application tiers, naming backend security groups rather than CIDRs.
  This converts a successful enumeration into refused flows, which are themselves a signal.
- `HttpPutResponseHopLimit: 1` unless a container platform genuinely requires 2 — and where it
  does, record that the exposure is being accepted rather than treating it as a default.

**Detection improvements**
- Audit every detection rule against the platform's documented limitations, not only against its
  field names. This rule was syntactically valid, semantically sensible, and structurally
  incapable of matching. Nothing but reading the limitations page would have caught it.
- Alert on a flow-log subscription being created **without** the standard format, not only on one
  being deleted. A downgraded subscription is a silent loss of every rule that depends on a
  version 3+ field.
- Treat a rule that has never fired as a finding to investigate rather than as good news, and
  review the never-fired list on a schedule.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1190 — Exploit Public-Facing Application |
| MITRE tactic | Initial Access (TA0001); the observed behaviour is Discovery (TA0007) |
| Primary API | None — the technique is an HTTP request made by the application. The AWS-visible parts are `ec2:ModifyInstanceMetadataOptions` and the flows themselves |
| Event source | VPC flow logs (custom format, version 3+ fields); `ec2.amazonaws.com` in CloudTrail |
| Key discriminator | An application-tier interface opening an accepted egress TCP flow to an internal address on a port its service has no client library for |
| Ground-truth signal | The accepted flow itself, with `log-status: OK`, read from `pkt-dstaddr` rather than `dstaddr` |
| "Was it used" pivot | Not available on the network. The instance-profile session appearing in CloudTrail from an address that is not the instance is the proof, and it lives in a different playbook |
| Blast radius | Every backend the interface reached, plus everything the instance profile permits if the metadata half succeeded |
| Error strings | Not applicable — flow logs carry `action: REJECT`, which AWS documents as covering security-group and NACL denials **and** "packets arrived after the connection was closed" |

**MITRE mapping note:** the source's `T1190` is correct and is kept — the SSRF is exploitation of a
public-facing application. It is under-descriptive of what the shipped rules observe, which is
`T1046 — Network Service Discovery`, so both are tagged. `T1552.005 — Unsecured Credentials: Cloud
Instance Metadata API` names the objective and is the mapping used by the two playbooks that cover
the metadata half. All three verified live 2026-08-30.

### Residual Risk

**You cannot prove the metadata service was not reached.** AWS does not write that record, so the
absence of evidence here is structural and permanent. If the instance ran IMDSv1 at any point
during the exposure window, treat the instance profile's credentials as compromised on that basis
alone rather than waiting for confirmation that cannot arrive.

Anything the reachable backends hold should be treated as accessed: flow logs prove the connection
was accepted and never what crossed it. Credentials that left the host self-renew for as long as
the primitive exists, so the revoke in §3 Step 3 is worth nothing until Step 1 is complete. And any
window containing `log-status: SKIPDATA` records is a window where AWS dropped flows it had — the
reconstruction for that period is incomplete by an unknown amount, and no query closes that gap.
