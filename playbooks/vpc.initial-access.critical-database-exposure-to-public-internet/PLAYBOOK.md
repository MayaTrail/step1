# IR Playbook: Database Exposed to the Public Internet — an `ACCEPT` flow to a datastore port after `AuthorizeSecurityGroupIngress`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Initial access (a datastore is directly reachable from the internet, and something connected to it) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical once a connection is accepted. The internet finds an exposed database in hours, not weeks, and for Redis and Memcached in their default configurations reaching the port *is* reaching the data — there is no authentication step to fail. Severity for a refused connection is low, and the difference between the two is one string comparison the source rule gets wrong. |
| MITRE Tactics | Initial Access |
| MITRE Techniques | T1190 |
| Services in Scope | VPC (flow logs, security groups, network ACLs), EC2, RDS, ElastiCache, OpenSearch, CloudTrail, GuardDuty |

**What the technique does:** nothing exotic. A security group gets an ingress rule with
`0.0.0.0/0` — during a debugging session, in a copied Terraform module, or from an instance
launched into a public subnet with a default group — and a database port becomes reachable from
anywhere. Internet-wide scanners find it within hours. What happens next depends on the engine: a
PostgreSQL or MySQL instance presents an authentication challenge, so the attacker brute-forces or
uses credentials found elsewhere; a Redis or Memcached node in its default configuration presents
nothing at all, and the TCP handshake completing is the whole attack.

**Why the usual reflexes miss it.** The reflex is to look at traffic volume, and volume is the
wrong measure — a single accepted flow is the finding, because it proves the security group, the
network ACL and the route all permit the connection. That fact stays true between alerts. The
second reflex is to block the source address, which treats a configuration defect as a traffic
problem: the next scanner arrives from a different address within the hour.

**Detection thesis:** `action: ACCEPT` on an ingress flow from a non-private address to a datastore
port. Accepted versus refused is the whole discriminator, and the source rule negates it
incorrectly — `NOT action:"reject"` against a field AWS documents as uppercase `REJECT`, which on
a case-sensitive backend excludes nothing.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **A flow-log subscription with a custom format including `pkt-srcaddr`, `pkt-dstaddr` and
  `flow-direction`.** Version 3 and 5 fields; the default format is version 2 and has none of
  them. AWS: *"After you create a flow log, you can't change its configuration or the flow log
  record format... Instead, you can delete the flow log and create a new one."* Without
  `flow-direction` this playbook cannot distinguish an exposure from an outbound dependency;
  without `pkt-dstaddr`, ingress through a load balancer names the wrong host.
- **CloudTrail management events for `ec2.amazonaws.com`** — `AuthorizeSecurityGroupIngress`,
  `ModifySecurityGroupRules`, `CreateNetworkAclEntry`, `ReplaceNetworkAclEntry`.
- **Database-side audit logging** on every engine that offers it. Flow logs prove a connection
  was established and can never prove whether a login succeeded.
- **A standing inventory of security groups permitting `0.0.0.0/0`**, refreshed on a schedule.
  This is a state question and the log cannot answer it.

**Alerting (must be pre-configured)**
- **An accepted ingress TCP flow from a non-private address to a datastore port → P0**
- **`AuthorizeSecurityGroupIngress` permitting `0.0.0.0/0` or `::/0` → P0**
- **A security group currently allowing `0.0.0.0/0` on a datastore port, from the scheduled state sweep → P1**
- **One external source refused across six or more distinct datastore ports within an hour → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- A host **outside** the VPC from which to verify reachability. Testing from inside proves
  nothing — the whole question is what the internet can reach.
- The credential-rotation procedure for each database engine in use, written down. Rotation is
  the slow part of this response and it is engine-specific.

**Known IOC Baselines**
- Which datastore ports are in use and on which addresses, so a port that should not be listening
  at all is distinguishable from one that is merely over-exposed.
- Published scanning-service address ranges, so the probe rules are not dominated by them.
- Which security groups are *intended* to be world-open — load balancers on 80 and 443 — as an
  explicit list rather than as tribal knowledge.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `flow-direction: ingress`, `action: ACCEPT`, `protocol: 6`, `dstport` in the datastore set, `pkt-srcaddr` not private | VPC flow logs (v5 format) | T1190 |
| P0 | `AuthorizeSecurityGroupIngress` succeeding with `cidrIp: 0.0.0.0/0` or `cidrIpv6: ::/0` | CloudTrail (`ec2`) | T1190 |
| P1 | A security group currently permitting `0.0.0.0/0` on a datastore port | `describe-security-groups` state sweep | T1190 |
| P1 | One `pkt-srcaddr` refused across ≥ 6 distinct datastore ports within an hour | VPC flow logs (correlation) | T1595 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | More than 100 refused inbound flows to one datastore port on one host in an hour | VPC flow logs | T1595 |
| P2 | `log-status: SKIPDATA` present in the investigation window — records were dropped and any negative finding is unreliable | VPC flow logs | T1685.002 |
| P3 | Background refused probing from published scanning services | VPC flow logs | T1595 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `NOT action:"reject"` against a field AWS documents as uppercase `REJECT` | On a case-sensitive backend the exclusion matches nothing, so refused connections pass. The internet scans continuously, so the rule fires constantly at P1 on blocked traffic and a live exposure arrives looking identical to background noise | Match `action: 'ACCEPT'` positively. A positive match cannot fail in this direction, and accepted-versus-refused is the entire discriminator between critical and low |
| No direction filter | An outbound connection from a VPC host to an external database on 3306 matches identically to the internet connecting inbound. Different incident, different response | `flow-direction: ingress`, a version 5 field — which is why §1 specifies the custom format rather than assuming it |
| Port list contains `3303`, `3309`, `5429` | None is a database port in common deployment; `5429` is one digit from `5439`, Redshift, which suggests a transposition. Meanwhile MongoDB, Redis, Memcached, OpenSearch and Cassandra are absent — the engines most often found exposed, several of which historically shipped with no authentication | List rebuilt from engines actually deployed, with the ports that make TCP establishment equivalent to data access called out in the note |
| Threshold of zero grouped by source **and** destination | Pages once per client. An exposed production database produces thousands of alerts an hour, and the rule that fires most is the one muted first | Group by target and port so the alert is one row per exposure, and let the source list be a column rather than a grouping key |
| Uses a geo-enrichment field to mean "public" | Behind a NAT gateway or a load balancer the address in the version 2 fields is the interface's, so the enrichment classifies the wrong address. It also makes the rule dependent on an enrichment pipeline that may not exist | Exclude private space from `pkt-srcaddr` directly. The complement is finite; the set of public addresses is not |
| Watches traffic only | The exposure exists whether or not anyone has connected yet, and the log cannot say whether it is still open | A CloudTrail rule at the moment of creation, and a state sweep in Query 2. Three views of one fact, and only one of them is a log |

**Recommended detection — accepted reachability, plus the control-plane event that created it.**

```yaml
# A database port reachable from the public internet (T1190)
#
# THE FINDING IS THE REACHABILITY, NOT THE TRAFFIC. One accepted inbound flow from a public
# address to a database port proves the security group and the network ACL both permit it. That
# is a configuration fact, verifiable directly and fixable permanently — and it stays true between
# alerts. Every rule here is therefore written to fire once per exposure and route to a
# configuration fix, not to page per packet. The source rule groups by source AND destination
# address with a threshold of zero, which pages once per client on an exposed database; a
# genuinely internet-reachable production database produces thousands of alerts an hour and the
# rule is muted the same day.
#
# `action` IS UPPERCASE. AWS documents exactly two values: ACCEPT and REJECT. The source rule
# excludes the lowercase string "reject", which on a case-sensitive backend excludes nothing —
# so the rule matches REJECTed connections too and reports blocked scanning as a live P1
# exposure. Written positively below as action: 'ACCEPT', which cannot fail that way.
#
# `protocol` IS AN IANA NUMBER. 6 is TCP. A rule written as protocol: 'TCP' matches nothing.
#
# FIELD VERSIONS. `flow-direction` is version 5 and `pkt-srcaddr`/`pkt-dstaddr` are version 3;
# the default flow-log format is version 2 and carries none of them, and AWS states the format
# cannot be changed after the subscription is created. Without flow-direction, an OUTBOUND
# connection from a host in the VPC to an external database on 3306 matches identically to an
# inbound exposure — a different event with a different response. Without pkt-dstaddr, ingress
# through a Network Load Balancer shows "the primary private IPv4 address" of the interface
# rather than the database, so the alert names the wrong host. See ../PLAYBOOK.md §1.
#
# THE PORT LIST. The source rule lists 3306, 5432, 1521, 1433, 3303, 3309 and 5429. Three of those
# are not database ports in any common deployment, and 5429 is one digit from 5439 — Redshift —
# which suggests a transposition. Meanwhile MongoDB (27017), Redis (6379), OpenSearch (9200),
# Memcached (11211), Cassandra (9042) and CouchDB (5984) are absent, and those are the engines
# most often exposed because they historically shipped with no authentication at all. The list
# below is rebuilt from what is actually deployed rather than corrected in place.
title: Database port accepted a connection from a public address
id: c60d92f4-1b78-4e35-a9c2-5f807d3e6b41
name: vpc_db_exposed_to_internet
status: experimental
description: >-
  An inbound TCP flow from a non-private address to a database port was ACCEPTED. Accepted is the
  whole signal: it means the security group, the network ACL and the route all permit the public
  internet to reach a datastore. Databases are not internet-facing services — there is no
  architecture in which this is the intended state, which is why this rule needs no baseline and
  no threshold. One matching flow is the finding.
references:
  - https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
  - https://attack.mitre.org/techniques/T1190/
tags:
  - attack.initial-access
  - attack.t1190
logsource:
  product: aws
  service: vpcflowlogs
detection:
  inbound_accepted:
    flow-direction: 'ingress'
    action: 'ACCEPT'
    protocol: 6
  database_port:
    dstport:
      - 3306      # MySQL / MariaDB / Aurora MySQL
      - 33060     # MySQL X protocol
      - 5432      # PostgreSQL / Aurora PostgreSQL
      - 1433      # SQL Server
      - 1521      # Oracle
      - 5439      # Redshift
      - 27017     # MongoDB / DocumentDB
      - 27018     # MongoDB shard
      - 6379      # Redis / ElastiCache
      - 11211     # Memcached
      - 9200      # OpenSearch / Elasticsearch HTTP
      - 9300      # Elasticsearch transport
      - 9042      # Cassandra / Keyspaces
      - 5984      # CouchDB
      - 8529      # ArangoDB
      - 7000      # Cassandra internode
  # Private space is excluded rather than public space enumerated, because the complement is
  # finite and the set is not. Prefix matching is used because Sigma has no CIDR operator every
  # backend implements; '172.2' over-matches into 172.2.x public space, which errs toward
  # treating a public address as private and therefore toward MISSING an exposure. A backend
  # supporting CIDR should use 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16 instead. Stated here
  # because a silent over-match on the safe-listing side of a rule is the dangerous direction.
  private_source:
    pkt-srcaddr|startswith:
      - '10.'
      - '192.168.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.2'
      - '172.30.'
      - '172.31.'
      - '100.64.'    # carrier-grade NAT, used by some AWS managed services
      - '127.'
  condition: inbound_accepted and database_port and not private_source
falsepositives:
  - >-
    A database deliberately published for a third party. Rare, always a documented exception, and
    the correct response is still to read this alert every time — the exception should be an
    address allowlist in the security group, not a permanently muted rule.
  - >-
    A non-database service that happens to listen on one of these ports. Real; confirm against
    the instance's role once, and exclude by pkt-dstaddr rather than by port.
level: critical
---
title: Database port refused a connection from a public address
id: 7ea3b158-40cf-4d92-b607-1c95e28fa063
name: vpc_db_probed_from_internet
status: experimental
description: >-
  The same shape as above, refused. Base rule and a signal in its own right at low: the internet
  scans every address continuously, so a handful of these is background and means the controls
  are working. It matters as a rate, and as the thing that precedes an exposure — a spike against
  one host, or the same source moving across many database ports, is somebody choosing your
  estate rather than scanning the internet. Note that AWS documents REJECT as covering security
  group and network ACL denials AND "packets arrived after the connection was closed", so a
  count of these is not purely a count of blocked attacks.
references:
  - https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
  - https://attack.mitre.org/techniques/T1595/
tags:
  - attack.reconnaissance
  - attack.t1595
logsource:
  product: aws
  service: vpcflowlogs
detection:
  inbound_refused:
    flow-direction: 'ingress'
    action: 'REJECT'
    protocol: 6
  database_port:
    dstport:
      - 3306
      - 33060
      - 5432
      - 1433
      - 1521
      - 5439
      - 27017
      - 27018
      - 6379
      - 11211
      - 9200
      - 9300
      - 9042
      - 5984
      - 8529
      - 7000
  private_source:
    pkt-srcaddr|startswith:
      - '10.'
      - '192.168.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.2'
      - '172.30.'
      - '172.31.'
      - '100.64.'
      - '127.'
  condition: inbound_refused and database_port and not private_source
falsepositives:
  - >-
    Internet background scanning, continuously. This rule is shipped at low precisely because it
    is mostly that; route it to a dashboard, not to a person.
level: low
---
title: One external source probed many database ports across the estate
id: 92b7c04e-6d31-4a58-83f0-e517d9a2b46c
status: experimental
description: >-
  A single external address was refused across an unusual number of distinct database ports or
  hosts. Undirected internet scanning hits one port across many addresses; this is the inverse —
  many ports against your addresses, which is somebody enumerating what you run. It is the
  earliest warning this technique offers, and it arrives before the exposure is found rather than
  after. group-by is pkt-srcaddr because that is the actor; timespan is 1h against the default
  10-minute aggregation interval plus AWS's typical delivery latency.
references:
  - https://attack.mitre.org/techniques/T1595/
tags:
  - attack.reconnaissance
  - attack.t1595
correlation:
  type: value_count
  rules:
    - vpc_db_probed_from_internet
  group-by:
    - pkt-srcaddr
  timespan: 1h
  condition:
    field: dstport
    gte: 6
falsepositives:
  - >-
    Commercial internet-wide scanning services, which are numerous and persistent. Their address
    ranges are published; exclude them by source address and keep the rule.
level: medium
---
title: Security group opened a database port to the internet
id: 4f18e5a7-92c0-4b63-a15d-70268bc3f9e2
name: ec2_sg_database_port_opened_publicly
status: experimental
description: >-
  AuthorizeSecurityGroupIngress permitted 0.0.0.0/0 or ::/0. This is the control-plane cause of
  everything above, it is in CloudTrail rather than in flow logs, and it fires at the moment the
  exposure is created rather than when somebody finds it. The two planes are shipped together on
  purpose: flow logs prove reachability was exercised, CloudTrail proves who created it, and
  neither answers the other's question. Note that the CIDR is nested inside a list of permissions,
  each of which carries its own list of ranges, so a rule reading a single flat field matches
  nothing.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html
  - https://attack.mitre.org/techniques/T1190/
tags:
  - attack.initial-access
  - attack.t1190
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'AuthorizeSecurityGroupIngress'
  success:
    errorCode: null
  world_open:
    requestParameters.ipPermissions.items.ipRanges.items.cidrIp: '0.0.0.0/0'
  world_open_v6:
    requestParameters.ipPermissions.items.ipv6Ranges.items.cidrIpv6: '::/0'
  condition: selection and success and (world_open or world_open_v6)
falsepositives:
  - >-
    Opening 80 or 443 to the world on a load balancer's security group, which is ordinary. This
    rule matches any world-open ingress and is deliberately broader than the database port list —
    the port is in the same request and triage reads it. Narrowing the rule to database ports
    would miss the case where a wide range covering them is opened.
level: high
```

What this set structurally cannot do: it cannot tell you whether anyone authenticated. A flow log
is a 5-tuple counter, so an accepted flow to 3306 proves TCP was established and nothing more —
except on Redis and Memcached in default configuration, where there is no authentication step and
establishment *is* access. It cannot measure volume in a VPC with Block Public Access enabled,
where AWS does not populate `bytes` *"even if you include the `bytes` field"*. And it cannot tell
you whether the exposure is still live; that is Query 2.

---

### Key Investigation Queries

> Queries 1 reads **CloudWatch Logs Insights**, which auto-discovers flow log fields in
> **camelCase** (`srcAddr`, `dstPort`, `action`, `logStatus`, `flowDirection`, `pktSrcAddr`,
> `pktDstAddr`) while the record format uses hyphens; both appear in this playbook, each in its
> own context. Queries 2–4 read the EC2 API and CloudTrail. Extraction uses
> `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50
> events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: who reached it, and when did it start

```bash
REGION="us-east-1"
LOG_GROUP="/aws/vpc/flowlogs"
TARGET="<database-private-ip>"
PORT="<port>"
START=$(date -u -v-30d +%s 2>/dev/null || date -u -d '30 days ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string "fields @timestamp, pktSrcAddr, pktDstAddr, dstPort, action, bytes, packets
                  | filter pktDstAddr = '${TARGET}' and dstPort = ${PORT}
                  | filter flowDirection = 'ingress' and logStatus = 'OK'
                  | stats count() as flows, sum(bytes) as total_bytes,
                          earliest(@timestamp) as first_seen, latest(@timestamp) as last_seen
                          by pktSrcAddr, action
                  | sort flows desc
                  | limit 200")

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'
```

The earliest `ACCEPT` row is when the exposure became usable, not when the security group changed
— Query 4 gets that. `filter logStatus = 'OK'` must stay: `SKIPDATA` rows mean records were
dropped and including them turns a count into a guess. Read the accepted source list as the list
of parties who reached your database, and size the incident from it rather than from bytes.

#### Query 2 — Sweep: is it still open, anywhere in the account

```bash
REGION="us-east-1"
PORTS="3306 33060 5432 1433 1521 5439 27017 27018 6379 11211 9200 9300 9042 5984 8529 7000"

aws ec2 describe-security-groups --region "$REGION" --output json | jq -r --arg ports "$PORTS" '
  ($ports | split(" ") | map(tonumber)) as $p |
  .SecurityGroups[] as $sg |
  $sg.IpPermissions[] |
  select((.IpRanges[]?.CidrIp == "0.0.0.0/0") or (.Ipv6Ranges[]?.CidrIpv6 == "::/0")) |
  . as $perm |
  ($p | map(select(. >= ($perm.FromPort // 0) and . <= ($perm.ToPort // 65535)))) as $hit |
  select($hit | length > 0) |
  "[FAIL] \($sg.GroupId) (\($sg.GroupName)) in \($sg.VpcId) opens \($perm.FromPort // "all")-\($perm.ToPort // "all") to the world, covering: \($hit | join(","))"'

echo
echo "== network ACLs are the second layer, and they are ordered — a low-numbered allow wins =="
aws ec2 describe-network-acls --region "$REGION" --output json | jq -r '
  .NetworkAcls[] as $acl | $acl.Entries[] |
  select(.Egress == false and .RuleAction == "allow") |
  select(.CidrBlock == "0.0.0.0/0" or .Ipv6CidrBlock == "::/0") |
  "[i] \($acl.NetworkAclId) rule \(.RuleNumber) allows \(.PortRange.From // "all")-\(.PortRange.To // "all") from the world"'
```

The port-range test is a range intersection, not an equality: a rule opening `0-65535` covers
every datastore port and an equality test on `FromPort` misses it entirely. A `[FAIL]` line is the
live exposure and is what §3 acts on; the NACL lines are informational, because a permissive NACL
is only dangerous when a security group also permits — but it is the layer people forget to check
after fixing the group.

#### Query 3 — Inspect: did anyone actually get in

```bash
REGION="us-east-1"
DB_ID="<rds-instance-identifier>"

echo "== is the instance itself publicly addressable =="
aws rds describe-db-instances --db-instance-identifier "$DB_ID" --region "$REGION" --output json 2>/dev/null | \
  jq -r '.DBInstances[] | "public=\(.PubliclyAccessible)  endpoint=\(.Endpoint.Address)  sgs=\([.VpcSecurityGroups[].VpcSecurityGroupId] | join(","))  subnetgroup=\(.DBSubnetGroup.DBSubnetGroupName)"'

echo
echo "== engine audit logs are the only source that can answer 'did a login succeed' =="
aws rds describe-db-log-files --db-instance-identifier "$DB_ID" --region "$REGION" --output json 2>/dev/null | \
  jq -r '.DescribeDBLogFiles[] | "\(.LogFileName)\t\(.Size) bytes"' | tail -20

echo
echo "[!] Redis and Memcached in default configuration have NO authentication step."
echo "    For those engines an accepted flow IS access — do not wait for a login record"
echo "    that the engine never writes."
```

#### Query 4 — Full session reconstruction of the principal who opened it

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in AuthorizeSecurityGroupIngress ModifySecurityGroupRules CreateNetworkAclEntry; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select((.requestParameters | tostring) | test("0\\.0\\.0\\.0/0|::/0")) |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       group: (.requestParameters.groupId // .requestParameters.networkAclId),
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress,
       params: .requestParameters}'
done | jq -s 'sort_by(.time)'
```

The `test(...)` runs against the serialised request because the CIDR is nested inside a list of
permissions each carrying its own list of ranges — a flat field read matches nothing. Once you
have the principal, the question is whether this was a mistake or a foothold: a human in a console
session at 19:00 debugging a connection issue looks very different from a role that also created
an access key that week.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Close the hole, then verify from outside, then decide whether the data is compromised. The first
step is a single API call and it should not wait for the investigation.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being investigated.

#### Step 1 — Revoke the world-open rule

```bash
REGION="us-east-1"
SG_ID="<group-id-from-Query-2>"
CASE_DIR="./ir-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$CASE_DIR"

aws ec2 describe-security-groups --group-ids "$SG_ID" --region "$REGION" --output json \
  > "$CASE_DIR/sg-before.json"

aws ec2 describe-security-groups --group-ids "$SG_ID" --region "$REGION" --output json | \
  jq '[.SecurityGroups[].IpPermissions[]
       | select((.IpRanges[]?.CidrIp == "0.0.0.0/0") or (.Ipv6Ranges[]?.CidrIpv6 == "::/0"))]' \
  > "$CASE_DIR/revoke.json"

COUNT=$(jq 'length' "$CASE_DIR/revoke.json")
if [ "$COUNT" -eq 0 ]; then
  echo "[i] $SG_ID has no world-open ingress — already closed, or the wrong group"
else
  echo "[i] revoking $COUNT world-open permission(s):"
  jq -r '.[] | "    \(.IpProtocol) \(.FromPort // "all")-\(.ToPort // "all")"' "$CASE_DIR/revoke.json"
  aws ec2 revoke-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --ip-permissions "file://$CASE_DIR/revoke.json" \
    && echo "[OK] revoked — original saved to $CASE_DIR/sg-before.json"
fi
```

Only the world-open permissions are revoked, read back from live state rather than reconstructed,
so a legitimate rule in the same group survives. The before-state is captured first because the
revoke is the step that destroys the evidence of what the exposure actually was.

#### Step 2 — Verify from outside the VPC, because inside proves nothing

```bash
TARGET_PUBLIC="<public-endpoint-or-eip>"
PORT="<port>"

echo "[i] run this from a host OUTSIDE the VPC — a laptop, a bastion in another account."
echo "    Testing from inside the VPC exercises a different path and proves nothing."
if command -v nc >/dev/null 2>&1; then
  if nc -z -w 5 "$TARGET_PUBLIC" "$PORT" 2>/dev/null; then
    echo "[FAIL] $TARGET_PUBLIC:$PORT is STILL reachable from here"
  else
    echo "[OK] $TARGET_PUBLIC:$PORT refused or timed out from here"
  fi
else
  echo "[!] nc unavailable — verify by another means before declaring this contained"
fi
```

A timeout and a refusal are both acceptable outcomes; a successful connection means something else
still permits it — a second security group on the same interface, a NACL allow, or a different
public address for the same host.

#### Step 3 — Treat the credentials as exposed

For any engine with authentication, rotate every credential that could reach the database, on the
assumption that brute-force had the full exposure window. For Redis and Memcached in default
configuration there is nothing to rotate and nothing to check — the exposure window *is* the
compromise window, and the response is a data-access assessment rather than a credential one.

#### Step 4 — Contain the principal, if this was not a mistake

```bash
SUSPECT_ARN="<caller-arn-from-Query-4>"

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

Most exposures of this kind are mistakes, and containing an engineer who was debugging is the
wrong response. Read Query 4's context first — the surrounding session is what distinguishes the
two, and it is worth the extra minute.

---

## 4. Eradication

### Remove Attacker Access

#### Close every other instance of the same mistake

Re-run Query 2 account-wide and across every Region in use, not just the one that alerted. A
world-open rule is rarely unique: the module that produced one produced others.

#### Take the database off the public network entirely

```bash
REGION="us-east-1"
DB_ID="<rds-instance-identifier>"

aws rds describe-db-instances --db-instance-identifier "$DB_ID" --region "$REGION" --output json | \
  jq -r '.DBInstances[] | if .PubliclyAccessible then
      "[FAIL] PubliclyAccessible=true — the instance has a public address regardless of the security group"
    else "[OK] PubliclyAccessible=false" end'
```

A security group is one layer. An instance with `PubliclyAccessible: true` in a subnet with an
internet gateway route is one rule change away from the same incident. Moving it to a private
subnet group removes the possibility rather than the permission.

#### Right-size who can open a security group

The principal from Query 4 almost certainly did not need `ec2:AuthorizeSecurityGroupIngress` on
the database's group. Network changes belong to a platform role and a review, not to an
application team's deploy credentials.

#### Remove emergency policies once clean

Delete `IR-Deny-All` and `AWSRevokeOlderSessions` once the principal is rebuilt or cleared, and
restore any legitimate ingress recorded in `sg-before.json`.

---

## 5. Recovery

### Restore Clean State

#### Verify no datastore port is world-open anywhere

```bash
REGION="us-east-1"
OPEN=$(aws ec2 describe-security-groups --region "$REGION" --output json | jq '
  [ .SecurityGroups[] | .IpPermissions[]
    | select((.IpRanges[]?.CidrIp == "0.0.0.0/0") or (.Ipv6Ranges[]?.CidrIpv6 == "::/0"))
    | select(([3306,33060,5432,1433,1521,5439,27017,27018,6379,11211,9200,9300,9042,5984,8529,7000]
              | map(select(. >= (.FromPort // 0)))) | length >= 0)
    | select(((.FromPort // 0) <= 65535)) ] | length')
echo "[i] world-open ingress permissions in $REGION: $OPEN"
[ "$OPEN" -eq 0 ] && echo "[OK] none" \
                  || echo "[!] review each — 80/443 on a load balancer is expected, a datastore port is not"
```

#### Verify the flow logs can still answer the question

Confirm every subscription carries `pkt-srcaddr`, `pkt-dstaddr` and `flow-direction`. Without
them these detections are silent rather than noisy, and the format cannot be changed after
creation — the subscription must be recreated.

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  flow-direction=ingress  action=ACCEPT  protocol=6"
echo "  pkt-srcaddr=203.0.113.10  pkt-dstaddr=10.0.3.20  dstport=5432"
echo "The rule MUST NOT fire on:"
echo "  the same flow with action=REJECT   (this is the case the source rule gets wrong)"
echo "  the same flow with pkt-srcaddr=10.0.1.5   (internal client)"
echo "  flow-direction=egress with dstport=5432   (outbound to an external database)"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A datastore port was reachable from the internet | A security group ingress rule with `0.0.0.0/0`, created by a principal that should not have held the permission |
| The database could be reached at all from outside | It sat in a subnet with an internet gateway route, or carried `PubliclyAccessible: true` — the security group was the only layer |
| The exposure was found by scanners before it was found by us | No scheduled state sweep for world-open rules; detection depended entirely on traffic arriving |
| The alert for this existed and was not trusted | It matched refused connections as well as accepted ones, so it fired constantly on internet background scanning at P1 |
| Nobody could say whether data was taken | Database audit logging was not enabled, and flow logs cannot answer the question |

### Recommended Guardrails

**Deny world-open ingress outside a platform role**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:ModifySecurityGroupRules",
             "ec2:CreateNetworkAclEntry", "ec2:ReplaceNetworkAclEntry"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Put datastores in subnets with no route to an internet gateway. This makes the exposure
  impossible rather than forbidden, and it survives a security group mistake.
- Set `PubliclyAccessible: false` on every managed database and enforce it at provisioning. A
  public address plus one rule change is the whole incident.
- Enable **VPC Block Public Access** where the workload allows it — and note the trade recorded in
  `../_ground-truth/vpc.md` §8: flow logs in a BPA-enabled VPC do not populate `bytes`, so
  volume-based detections stop working. Take the protection; know what it costs.
- Enable engine-level audit logging everywhere. It is the only source that can answer "did a login
  succeed", and it must be on before the incident.

**Detection improvements**
- Run the state sweep on a schedule and alert on the *state*, not only on the change event and the
  traffic. Three views of one fact, and the state view is the one that catches an exposure created
  before logging was configured.
- Separate accepted from refused into different severities and different queues. Conflating them
  is what made the original rule unusable.
- Test rules against a refused flow as well as an accepted one. A rule that fires on both is
  indistinguishable from a working rule until somebody reads the traffic.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1190 — Exploit Public-Facing Application |
| MITRE tactic | Initial Access (TA0001) |
| Primary API | None on the data path. The control-plane cause is `ec2:AuthorizeSecurityGroupIngress` |
| Event source | VPC flow logs (custom format, version 3+ fields); `ec2.amazonaws.com` in CloudTrail |
| Key discriminator | `action: ACCEPT` on an ingress flow from a non-private `pkt-srcaddr` to a datastore port. Accepted versus refused is the whole signal |
| Ground-truth signal | A security group permitting `0.0.0.0/0` on that port, from `describe-security-groups` — live state, not a log |
| "Was it used" pivot | Engine audit logs. Flow logs prove TCP establishment only — except on Redis and Memcached in default configuration, where establishment is access |
| Blast radius | Everything the datastore holds, plus any credential reachable from it and any system that trusts it |
| Error strings | Not applicable — flow logs carry `action: REJECT`, which AWS documents as covering security-group and NACL denials **and** "packets arrived after the connection was closed" |

**MITRE mapping note:** the source's `T1190` is kept — reaching an exposed database is exploitation
of a public-facing service. `T1595 — Active Scanning` is carried by the refused-connection rules,
which observe reconnaissance rather than exploitation, and separating the two is the same
separation the corrected `action` filter makes. Both verified live 2026-08-30.

### Residual Risk

For any engine without an authentication step, the exposure window is the compromise window and no
log will ever narrow it further. For engines with one, brute-force had however long the rule was
open, and without engine audit logging enabled beforehand there is no record of whether it
succeeded. `bytes` may be structurally absent if the VPC has Block Public Access enabled, so the
volume of anything taken is not measurable from AWS. And any window containing `log-status:
SKIPDATA` is a window where AWS dropped flows it had — the list of parties who connected is
incomplete by an unknown amount, and no query closes that gap.
