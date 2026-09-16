# IR Playbook: Remote Administration Reachable From the Internet — an `ACCEPT` flow to SSH, RDP, VNC or WinRM

## Classification

| Field | Value |
|-------|-------|
| Incident Type | External remote services (a remote-administration port is reachable from the public internet, and something connected to it) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High, and critical when the source also carries a reputation hit. An accepted connection to SSH or RDP from outside the admin allowlist means the only remaining control is the authentication on the host, and credential stuffing against an exposed SSH port is continuous and automated. The source rule rates this P2 and, more importantly, will not fire at all unless a threat feed already knows the address. |
| MITRE Tactics | Lateral Movement, Initial Access |
| MITRE Techniques | T1021 |
| Services in Scope | VPC (flow logs, security groups, network ACLs), EC2, Systems Manager, CloudTrail, GuardDuty |

**What the technique does:** an attacker connects to a remote-administration service exposed to
the internet and authenticates — with credentials from a breach corpus, a key found in a
repository, or a default that was never changed. There is no exploit. The port is open, the
service is doing what it is designed to do, and every step looks like administration because it
is administration, performed by the wrong person.

**Why the usual reflexes miss it.** The reflex is to filter on known-bad source addresses, and
that is precisely the wrong gate: an attacker's address is unreported until somebody reports it,
which is after the first victim. Filtering on reputation makes the detection blind to exactly the
connections that arrive first. The second reflex is to treat an accepted flow as proof of
compromise or a rejected one as proof of safety; neither holds. A flow log is a 5-tuple counter
and says nothing about whether authentication succeeded.

**Detection thesis:** the finding is that the port is reachable at all from outside the admin
allowlist. That needs no enrichment, no baseline and no threshold — one accepted flow states it.
Reputation is a prioritiser layered on top, which raises urgency when present and proves nothing
when absent.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **A flow-log subscription with a custom format including `pkt-srcaddr`, `pkt-dstaddr` and
  `flow-direction`.** Version 3 and 5 fields; the default format is version 2 and carries none of
  them. AWS: *"After you create a flow log, you can't change its configuration or the flow log
  record format... Instead, you can delete the flow log and create a new one."* Without
  `flow-direction`, an outbound administrative session from a bastion matches identically to an
  inbound intrusion.
- **CloudTrail management events for `ec2.amazonaws.com`** — `AuthorizeSecurityGroupIngress` and
  `ModifySecurityGroupRules` are how the exposure is created.
- **Host authentication logs shipped off the host** — `sshd` on Linux, Security event log on
  Windows. Flow logs prove a connection; only these prove a login, and a host's local logs are
  among the first things an intruder edits.
- **GuardDuty enabled.** `UnauthorizedAccess:EC2/SSHBruteForce` and `.../RDPBruteForce` cover the
  authentication half these rules structurally cannot see.

**Alerting (must be pre-configured)**
- **An accepted inbound TCP flow from a public address outside the admin allowlist to a remote-service port → P0**
- **The same connection where the source also carries a high-confidence reputation hit → P0**
- **One external source refused across four or more distinct remote-service ports within an hour → P1**
- **`AuthorizeSecurityGroupIngress` permitting `0.0.0.0/0` on a remote-service port → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- **AWS Systems Manager Session Manager configured and working on every instance.** This is what
  makes closing SSH to the internet possible without losing access — if the only way in is the
  port you need to close, the containment is an outage.
- A host **outside** the VPC from which to verify reachability after the fix.

**Known IOC Baselines**
- **The admin source allowlist**: the corporate VPN's public addresses and any managed bastion.
  This is the entire tuning surface of the main rule, it should be short, and it should be in
  version control.
- Which instances are *meant* to accept remote administration at all. In an estate using Session
  Manager the answer is often none, which makes every alert actionable.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `flow-direction: ingress`, `action: ACCEPT`, `protocol: 6`, `dstport` in the remote-service set, `pkt-srcaddr` public and not on the admin allowlist | VPC flow logs (v5 format) | T1133 |
| P0 | The same accepted flow where the source carries a high-confidence reputation verdict or score | VPC flow logs + enrichment | T1021 |
| P1 | One `pkt-srcaddr` refused across ≥ 4 distinct remote-service ports within an hour | VPC flow logs (correlation) | T1595 |
| P1 | `AuthorizeSecurityGroupIngress` succeeding with `0.0.0.0/0` covering a remote-service port | CloudTrail (`ec2`) | T1133 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | An accepted flow carrying more than 100 packets — a session that outlasted a failed login | VPC flow logs | T1021 |
| P2 | GuardDuty `UnauthorizedAccess:EC2/SSHBruteForce` or `.../RDPBruteForce` on a host in scope | GuardDuty | T1110 |
| P3 | Background refused probing of remote-service ports from published scanning services | VPC flow logs | T1595 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Requires a threat-intel reputation score before firing | The gate sits in front of the only fact that matters. Every address is unreported on its first day, and an attacker rents fresh addresses precisely because they are unreported — so the rule is blind to exactly the connections that arrive first | The accepted connection is the rule, at high, with no enrichment. Reputation becomes a second rule at critical, layered on top |
| The reputation field lives in an enrichment pipeline, not in the flow log | If the pipeline is absent or its schema changes, the rule reports clean forever and nothing indicates why. A detection whose base case depends on an optional pipeline has a silent off switch | Reputation carried as an optional column in the KQL and an ORed pair of alternative schemas in the Sigma, so its absence degrades the rule to *not firing* rather than the whole use case to silence |
| Port list is 22, 3389, 5900 | Misses **5985/5986** (WinRM — the standard Windows remote-management transport and the least watched), **23** (still on appliances), **5901–5903** (5900 is VNC display `:0` only) and **2222** (an alternate SSH port chosen because rules list 22) | List rebuilt; each addition is named in the Sigma header with the reason |
| Geo-enrichment used as a direction proxy | `is_local` on source and destination stands in for `flow-direction`. Behind a NAT gateway the version 2 address fields hold *"the primary private IPv4 address"* of the interface, so the enrichment classifies the wrong address and concludes the source is internal | `flow-direction: ingress` plus private-space exclusion on `pkt-srcaddr` — version 5 and version 3 fields, which is why §1 specifies the format |
| Groups by source with a threshold of zero | Workable only because the reputation gate suppresses volume. Remove the gate — which the correction does — and it pages per client | Group by target and port, so one exposure is one row however many clients found it, with the source list as a column |
| Watches traffic only | The exposure exists before anyone connects and the log cannot say whether it is still open | A CloudTrail rule at creation, and a state sweep in Query 2 |

**Recommended detection — the exposure first, the reputation second.**

```yaml
# Remote-service port accepting connections from the public internet (T1021 / T1133)
#
# THE SOURCE RULE'S ENTIRE DISCRIMINATOR IS AN ENRICHMENT, AND THAT INVERTS THE PRIORITY.
# It requires a threat-intel reputation score on the source address before it will fire. So a
# connection from an address nobody has reported yet — which is every address on its first day,
# and every address an attacker rents fresh — produces no alert at all, while the finding that
# actually matters, that SSH is reachable from the whole internet, is never stated. Worse, the
# field lives in an enrichment pipeline rather than in the flow log: if that pipeline is not
# configured, or its schema changes, the rule reports clean forever and nothing indicates why.
#
# INVERTED HERE. The accepted inbound connection on a remote-service port IS the finding, at high,
# with no enrichment required. Reputation is carried as a SEPARATE, higher-severity rule layered
# on top — it raises urgency when present and proves nothing when absent. A detection whose base
# case depends on an optional pipeline is a detection with a silent off switch.
#
# THE PORT LIST. The source covers 22, 3389 and 5900. Missing: 5985 and 5986 (WinRM, the standard
# Windows remote-management transport and the one least likely to be noticed), 23 (telnet, which
# still appears on appliances and IoT), 5901-5904 (additional VNC displays — 5900 alone covers
# display :0 only), and 2222 (a conventional alternate SSH port that is chosen precisely because
# rules list 22).
#
# FIELD VERSIONS. `flow-direction` is version 5 and `pkt-srcaddr`/`pkt-dstaddr` are version 3; the
# default flow-log format is version 2 and carries none of them, and AWS states the format cannot
# be changed after the subscription is created. Without flow-direction, an OUTBOUND administrative
# SSH session from a bastion matches identically to an inbound intrusion. Without pkt-srcaddr,
# ingress through a load balancer or NAT shows "the primary private IPv4 address" of the
# interface, so the source is recorded as internal and the rule never fires. See ../PLAYBOOK.md §1.
#
# `protocol` IS AN IANA NUMBER — 6 is TCP. `action` is uppercase ACCEPT or REJECT.
title: Remote-service port accepted a connection from a public address
id: 2f8c04d1-7e59-4b36-a840-91d76e3b5c02
name: vpc_remote_service_from_internet
status: experimental
description: >-
  An inbound TCP flow from a non-private address to SSH, RDP, VNC, WinRM or telnet was ACCEPTED.
  Accepted is the signal: the security group, the network ACL and the route all permit the public
  internet to reach a remote-administration service. No reputation feed is consulted, on purpose —
  the exposure is the finding whether or not anybody has reported the source yet, and the first
  connection from a fresh address is exactly the one a reputation gate cannot see.
references:
  - https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
  - https://attack.mitre.org/techniques/T1133/
tags:
  - attack.initial-access
  - attack.lateral-movement
  - attack.t1021
  - attack.t1133
logsource:
  product: aws
  service: vpcflowlogs
detection:
  inbound_accepted:
    flow-direction: 'ingress'
    action: 'ACCEPT'
    protocol: 6
  remote_service_port:
    dstport:
      - 22        # SSH
      - 2222      # conventional alternate SSH
      - 23        # telnet
      - 3389      # RDP
      - 3390      # alternate RDP
      - 5900      # VNC display :0
      - 5901      # VNC display :1
      - 5902
      - 5903
      - 5985      # WinRM HTTP
      - 5986      # WinRM HTTPS
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
  # POPULATE BEFORE DEPLOYING with the public addresses of the corporate VPN and any managed
  # bastion service. This is the only legitimate way a remote-service port should be reachable
  # from a public address, the list is short, and it is the entire tuning surface. An empty list
  # is a defensible start — it reports every such connection once, which is how the list is built.
  known_admin_sources:
    pkt-srcaddr:
      - '203.0.113.10'
      - '203.0.113.11'
  condition: inbound_accepted and remote_service_port and not private_source and not known_admin_sources
falsepositives:
  - >-
    A managed bastion or a vendor support session arriving from an address not yet on the list.
    Real, and each one is worth confirming once — the answer becomes an allowlist entry, and the
    number of such entries should stay countable on one hand.
level: high
---
title: Remote-service port accepted a connection from a reported-malicious address
id: b47a1e93-c026-4d58-9f31-807be2c4a6d5
name: vpc_remote_service_from_known_bad
status: experimental
description: >-
  The same accepted connection, where the source also carries a high-confidence reputation hit.
  This is a PRIORITISER layered on the rule above, not a gate in front of it — the field below is
  populated by an enrichment pipeline rather than by the flow log itself, so its absence means
  "not enriched" and never "not malicious". Shipped at critical because a reputation hit on an
  address that successfully reached SSH removes the ambiguity about intent, and it should page
  rather than queue. Field name and confidence scale differ by enrichment provider; the two below
  are alternatives, matched permissively so the rule degrades to not-firing rather than to a
  parse error.
references:
  - https://attack.mitre.org/techniques/T1021/
tags:
  - attack.lateral-movement
  - attack.t1021
logsource:
  product: aws
  service: vpcflowlogs
detection:
  inbound_accepted:
    flow-direction: 'ingress'
    action: 'ACCEPT'
    protocol: 6
  remote_service_port:
    dstport:
      - 22
      - 2222
      - 23
      - 3389
      - 3390
      - 5900
      - 5901
      - 5902
      - 5903
      - 5985
      - 5986
  # ADJUST TO THE LOCAL ENRICHMENT SCHEMA. Two common shapes are listed; a deployment will have
  # one of them or neither. If neither is populated this rule never fires, and the rule above
  # still carries the whole use case — which is the point of separating them.
  reputation_verdict:
    threat_intel.verdict:
      - 'malicious'
      - 'suspicious'
  reputation_score:
    threat_intel.confidence|gte: 7
  condition: inbound_accepted and remote_service_port and (reputation_verdict or reputation_score)
falsepositives:
  - >-
    A stale or low-quality feed. Reputation data ages badly, and a residential address recycled by
    an ISP inherits somebody else's history — which is why this is a prioritiser on top of a
    behavioural rule rather than the rule itself.
level: critical
---
title: One external source refused across many remote-service ports
id: 6d0f582b-93ca-41e7-b5a4-2c718e930fd6
status: experimental
description: >-
  A single external address was refused across an unusual number of distinct remote-service ports
  or hosts. Undirected internet scanning hits port 22 across many addresses; this is the inverse —
  many administration ports against your addresses, which is somebody enumerating your remote
  access surface rather than the internet's. It arrives before an exposure is found rather than
  after, and it requires no enrichment. Timespan is 1h against the default 10-minute aggregation
  interval plus AWS's typical delivery latency.
references:
  - https://attack.mitre.org/techniques/T1595/
tags:
  - attack.reconnaissance
  - attack.t1595
correlation:
  type: value_count
  rules:
    - vpc_remote_service_refused
  group-by:
    - pkt-srcaddr
  timespan: 1h
  condition:
    field: dstport
    gte: 4
falsepositives:
  - >-
    Commercial internet-wide scanning services, which are numerous, persistent and publish their
    address ranges. Exclude them by source address and keep the rule.
level: medium
---
title: Remote-service port refused a connection from a public address
id: a3591c7e-4b82-40df-9026-e5c84317bad9
name: vpc_remote_service_refused
status: experimental
description: >-
  Base rule for the correlation above, and background at low on its own. The internet scans every
  address continuously, so a steady rate of these means the controls are working and should go to
  a dashboard rather than to a person. Note that AWS documents REJECT as covering security-group
  and network-ACL denials AND "packets arrived after the connection was closed", so this is not
  purely a count of blocked attacks.
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
  remote_service_port:
    dstport:
      - 22
      - 2222
      - 23
      - 3389
      - 3390
      - 5900
      - 5901
      - 5902
      - 5903
      - 5985
      - 5986
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
  condition: inbound_refused and remote_service_port and not private_source
falsepositives:
  - >-
    Internet background scanning, continuously and by design. Shipped at low precisely because it
    is mostly that.
level: low
```

What this set structurally cannot do: it cannot tell you whether anyone authenticated. A flow log
is a 5-tuple counter, and `sshd`'s logs or the Windows Security log are the only sources that can
answer it. Packet volume is the one available proxy — a refused login closes in a handful of
packets and an interactive session does not — and it is labelled as a proxy wherever it appears.

---

### Key Investigation Queries

> Query 1 reads **CloudWatch Logs Insights**, which auto-discovers flow log fields in **camelCase**
> (`pktSrcAddr`, `pktDstAddr`, `dstPort`, `action`, `logStatus`, `flowDirection`) while the record
> format uses hyphens. Queries 2–4 read the EC2, GuardDuty and CloudTrail APIs. Extraction uses
> `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50
> events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: who reached this port, and did anyone stay

```bash
REGION="us-east-1"
LOG_GROUP="/aws/vpc/flowlogs"
TARGET="<target-private-ip>"
PORT="<port>"
START=$(date -u -v-30d +%s 2>/dev/null || date -u -d '30 days ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string "fields @timestamp, pktSrcAddr, dstPort, action, packets, bytes
                  | filter pktDstAddr = '${TARGET}' and dstPort = ${PORT} and protocol = 6
                  | filter flowDirection = 'ingress' and logStatus = 'OK'
                  | stats sum(packets) as pkts, sum(bytes) as bytes_total, count() as flows,
                          earliest(@timestamp) as first_seen, latest(@timestamp) as last_seen
                          by pktSrcAddr, action
                  | sort pkts desc
                  | limit 200")

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'
```

Sort by packets, not by flows. A source with `action=ACCEPT` and a few dozen packets probably
failed to authenticate and gave up; a source with thousands held a session. That distinction is
the closest this telemetry comes to "did they get in", and it is a proxy — the host's own
authentication log is the answer, and Query 3 goes for it.

#### Query 2 — Sweep: which remote-service ports are open to the world right now

```bash
REGION="us-east-1"
PORTS="22 2222 23 3389 3390 5900 5901 5902 5903 5985 5986"

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
echo "== which instances use those groups =="
aws ec2 describe-instances --region "$REGION" --output json | jq -r '
  .Reservations[].Instances[] |
  "\(.InstanceId)\t\(.State.Name)\tpublic=\(.PublicIpAddress // "-")\tsgs=\([.SecurityGroups[].GroupId] | join(","))"' | \
  grep -v 'public=-' || echo "[OK] no running instance has a public address"
```

The port test is a range intersection, not an equality: a rule opening `0-65535` covers every one
of these ports and an equality check on `FromPort` misses it entirely. An instance with no public
address is not reachable directly even if its group is permissive — read both lines together
before deciding what is actually exposed.

#### Query 3 — Inspect: did anyone authenticate

```bash
REGION="us-east-1"
INSTANCE="<instance-id>"

echo "== GuardDuty, which sees the authentication half flow logs cannot =="
DET=$(aws guardduty list-detectors --region "$REGION" --output text --query 'DetectorIds[0]' 2>/dev/null)
if [ -n "$DET" ] && [ "$DET" != "None" ]; then
  aws guardduty list-findings --detector-id "$DET" --region "$REGION" \
    --finding-criteria "{\"Criterion\":{\"resource.instanceDetails.instanceId\":{\"Eq\":[\"$INSTANCE\"]}}}" \
    --output json | jq -r '.FindingIds[]' | head -20 | while read -r F; do
      aws guardduty get-findings --detector-id "$DET" --finding-ids "$F" --region "$REGION" \
        --output json | jq -r '.Findings[] | "\(.UpdatedAt)\t\(.Severity)\t\(.Type)\t\(.Title)"'
    done
else
  echo "[!] GuardDuty not enabled in $REGION — the authentication half of this incident is unobserved"
fi

echo
echo "== the host's own logs are the answer, and they are on the host =="
echo "[i] Linux:   /var/log/auth.log or /var/log/secure — 'Accepted publickey', 'Accepted password'"
echo "[i] Windows: Security log event 4624 with LogonType 10 (RemoteInteractive)"
echo "[!] Pull these through Session Manager, not over the port under investigation, and treat"
echo "    them as potentially edited — an intruder with root reaches them before you do."
```

#### Query 4 — Full session reconstruction of who opened the port

```bash
REGION="us-east-1"
SINCE=$(date -u -v-90d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in AuthorizeSecurityGroupIngress ModifySecurityGroupRules; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select((.requestParameters | tostring) | test("0\\.0\\.0\\.0/0|::/0")) |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       group: .requestParameters.groupId,
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress,
       params: .requestParameters}'
done | jq -s 'sort_by(.time)'
```

The `test(...)` runs against the serialised request because the CIDR is nested inside a list of
permissions each carrying its own list of ranges — a flat field read matches nothing. Ninety days
is deliberate: exposures of this kind are usually old, opened for a debugging session that ended
and a rule that never did.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Close the port, then find out whether anyone got in. Closing it is one call and does not depend on
the investigation — but **check Session Manager first**, because closing the only way in is an
outage rather than a containment.

> Run every command under the **break-glass responder credentials** from §1.

#### Step 1 — Confirm you will still have access after closing the port

```bash
REGION="us-east-1"
INSTANCE="<instance-id>"

ONLINE=$(aws ssm describe-instance-information --region "$REGION" --output json | \
  jq -r --arg i "$INSTANCE" '[.InstanceInformationList[] | select(.InstanceId == $i)] | length')
if [ "$ONLINE" -eq 1 ]; then
  echo "[OK] $INSTANCE is managed by Systems Manager — Session Manager access survives closing the port"
else
  echo "[FAIL] $INSTANCE is NOT SSM-managed. Closing the port removes your own access too."
  echo "       Restrict the rule to the responder's address instead of removing it, and fix"
  echo "       SSM enrolment as an eradication item."
fi
```

#### Step 2 — Close or narrow the ingress rule

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

Only the world-open permissions are revoked, read from live state, so a legitimate rule in the
same group survives. If Step 1 reported `[FAIL]`, replace this with a narrowed rule permitting the
responder's address only.

#### Step 3 — Treat the host as compromised if a session sustained

If Query 1 showed an accepted flow with substantial packet volume from an address outside the
allowlist, the correct posture is compromise until the host's own authentication log says
otherwise — and that log is on a host the intruder may have had root on. Rotate every credential
and key reachable from the instance, revoke its instance-profile sessions, and treat the
authentication log as evidence to corroborate rather than to rely on.

```bash
ROLE_NAME="<instance-profile-role>"
if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name AWSRevokeOlderSessions \
    --policy-document file:///tmp/revoke.json \
    && echo "[OK] sessions issued before now are denied on $ROLE_NAME"
fi
```

#### Step 4 — Contain the principal who opened the port, if this was not a mistake

Most of these exposures are old debugging rules nobody removed. Read Query 4's surrounding session
before containing anyone — a console session at the end of an incident three months ago looks very
different from a role that also created an access key that week.

---

## 4. Eradication

### Remove Attacker Access

#### Close every other instance of the same rule

Re-run Query 2 across every Region in use. A world-open remote-service port is rarely unique: the
module or the habit that produced one produced others.

#### Remove the need for the port at all

Systems Manager Session Manager provides shell access with no inbound port, no bastion and no key
material, and it logs the session. Where it is enrolled, SSH and RDP need not be reachable from
anywhere — which turns this detection from a frequent alert into one that never fires, and makes
every future occurrence unambiguous.

#### Right-size who can open a security group

The principal from Query 4 probably did not need `ec2:AuthorizeSecurityGroupIngress` on a
production group. Network changes belong to a platform role and a review.

#### Remove emergency policies once clean

Delete `AWSRevokeOlderSessions` after the host is rebuilt, and restore any legitimate ingress
recorded in `sg-before.json`.

---

## 5. Recovery

### Restore Clean State

#### Verify no remote-service port is world-open

```bash
REGION="us-east-1"
OPEN=$(aws ec2 describe-security-groups --region "$REGION" --output json | jq '
  [ .SecurityGroups[] | .IpPermissions[]
    | select((.IpRanges[]?.CidrIp == "0.0.0.0/0") or (.Ipv6Ranges[]?.CidrIpv6 == "::/0"))
    | select([22,2222,23,3389,3390,5900,5901,5902,5903,5985,5986]
             | any(. >= (.FromPort // 0) and . <= (.ToPort // 65535))) ] | length' 2>/dev/null || echo "?")
echo "[i] world-open permissions covering a remote-service port: $OPEN"
[ "$OPEN" = "0" ] && echo "[OK] none" || echo "[FAIL] review each with Query 2"
```

#### Verify from outside the VPC

```bash
TARGET_PUBLIC="<public-address>"
PORT="<port>"
echo "[i] run from a host OUTSIDE the VPC — testing from inside exercises a different path"
if command -v nc >/dev/null 2>&1; then
  nc -z -w 5 "$TARGET_PUBLIC" "$PORT" 2>/dev/null \
    && echo "[FAIL] $TARGET_PUBLIC:$PORT still reachable" \
    || echo "[OK] $TARGET_PUBLIC:$PORT refused or timed out"
else
  echo "[!] nc unavailable — verify by another means before declaring this contained"
fi
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  flow-direction=ingress  action=ACCEPT  protocol=6"
echo "  pkt-srcaddr=198.51.100.7  pkt-dstaddr=10.0.1.20  dstport=22"
echo "  with NO reputation data present at all — this is the case the source rule misses"
echo "and MUST fire at critical on:"
echo "  the same flow where the source carries a high-confidence reputation verdict"
echo "The rule MUST NOT fire on:"
echo "  the same flow with pkt-srcaddr on the admin allowlist"
echo "  flow-direction=egress with dstport=22 (an outbound administrative session)"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A remote-administration port was reachable from the internet | A security group rule with `0.0.0.0/0`, usually opened for a debugging session and never removed |
| The detection did not fire | It required a threat-intel hit on the source, and the source was not on any feed at the time |
| The exposure survived for months | Detection depended entirely on traffic; no scheduled state sweep looked for world-open remote-service ports |
| Closing the port was not an obvious action | Session Manager was not enrolled, so the exposed port was also the operators' only way in |
| Nobody could say whether a login succeeded | Host authentication logs were not shipped off the host, and GuardDuty was not enabled in the Region |

### Recommended Guardrails

**Deny world-open ingress outside a platform role**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:ModifySecurityGroupRules"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Enrol every instance in Systems Manager and remove inbound SSH and RDP entirely. This is the
  control that makes the detection almost never fire, which is what a good control looks like.
- Ship host authentication logs off the host, in real time. They are the only source that can
  answer whether a login succeeded, and they are the first thing an intruder with root edits.
- Enable GuardDuty in every Region in use. Its brute-force findings cover the authentication half
  these rules structurally cannot see, and the two are complementary rather than redundant.
- Keep the admin source allowlist in version control, short, and reviewed. It is the tuning
  surface of the main rule and its length is a measure of the estate's exposure.

**Detection improvements**
- Never let an enrichment gate a base detection. Enrichment prioritises; behaviour detects. This
  rule is the clearest example in the corpus of the inversion and what it costs.
- Run the security-group state sweep on a schedule and alert on the state, not only on the change
  event and the traffic. It is the only view that finds an exposure created before logging existed.
- Alert on an accepted flow with high packet volume separately from one with low volume. The
  difference is a failed login versus a session, and it is the only session-length signal
  available at the network layer.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1021 — Remote Services |
| MITRE tactic | Lateral Movement (TA0008); the external-facing case is Initial Access (TA0001) |
| Primary API | None on the data path. The control-plane cause is `ec2:AuthorizeSecurityGroupIngress` |
| Event source | VPC flow logs (custom format, version 3+ fields); `ec2.amazonaws.com` in CloudTrail; GuardDuty for the authentication half |
| Key discriminator | `action: ACCEPT` on an ingress flow to a remote-service port from a public `pkt-srcaddr` outside the admin allowlist — no enrichment required |
| Ground-truth signal | A security group permitting `0.0.0.0/0` on that port, from `describe-security-groups` — live state, not a log |
| "Was it used" pivot | The host's authentication log, and GuardDuty brute-force findings. Packet volume on the accepted flow is the only network-layer proxy and is a proxy |
| Blast radius | The host, everything its instance profile permits, and every credential or key stored on it |
| Error strings | Not applicable — flow logs carry `action: REJECT`, which AWS documents as covering security-group and NACL denials **and** "packets arrived after the connection was closed" |

**MITRE mapping note:** the source's `T1021 — Remote Services` is kept, and `T1133 — External
Remote Services` added, because the observable here is an externally-facing remote-access service
being reached rather than movement between internal hosts — `T1021` describes the technique once
an attacker is inside, `T1133` describes it as the way in, and this rule cannot distinguish which
it is looking at. `T1595 — Active Scanning` is carried by the refusal rules and `T1110` by the
GuardDuty brute-force trigger. All verified live 2026-08-30.

### Residual Risk

An accepted flow proves TCP was established and nothing more, so absent host logs there is no way
to close the question of whether anyone authenticated — and if they did and had root, the host log
is not trustworthy evidence either way. Reputation data ages badly and a recycled residential
address inherits somebody else's history, so an empty reputation column tomorrow does not mean the
source was benign today. Any window containing `log-status: SKIPDATA` is a window where AWS
dropped flows it had, so the list of parties who connected is a floor. And closing the port removes
the path, not the credentials: anything harvested during the exposure — a key, a password, a token
on disk — remains valid until it is rotated, and no network change reaches it.
