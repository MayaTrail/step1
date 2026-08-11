# IR Playbook - Open Ingress Port 22 on Security Group - Internet-Exposed SSH via `ec2:AuthorizeSecurityGroupIngress`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense Evasion / Cloud Firewall Modification (internet-exposed admin port) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, exposes SSH on every instance in the group to the entire internet, enabling brute-force and direct access |
| MITRE Tactics | Defense Evasion (MANIFEST tags Exfiltration, see mapping note in §6) |
| MITRE Techniques | T1562.007 |
| Services in Scope | EC2 (Security Groups), CloudTrail, GuardDuty, AWS Config, VPC Flow Logs |
| Infrastructure Created | 1 EC2 Security Group with no initial ingress (via `infra/`) |

**What the emulation does:** calls `ec2:AuthorizeSecurityGroupIngress` to add an inbound rule allowing TCP **port 22 from `0.0.0.0/0`** - SSH open to the entire internet, on the target security group. Its revert removes the rule with `ec2:RevokeSecurityGroupIngress`. Every EC2 instance associated with that group instantly becomes reachable on SSH from any IP on the planet.

**Why the rule content is the signal, not the API call.** `ec2:AuthorizeSecurityGroupIngress` is a routine operation, teams add ingress rules constantly. What makes *this* one an incident is the **combination inside `ipPermissions`**: a port range that includes an admin port (22 SSH, 3389 RDP), a source of `0.0.0.0/0` (or `::/0`), and a principal/context that isn't a reviewed infrastructure change. The shipped rule (§2) matches every authorize/revoke with no inspection of port or CIDR, so it is both noise and blind to the actual condition.

**Generalise beyond literal port 22.** The emulation opens 22, but the same technique opens 3389 (RDP), a wide range (`0-65535`) that *contains* 22, or uses IPv6 `::/0`. A detection that matches only `fromPort == 22` and only `cidrIp` misses the range-containment and IPv6 variants. Match on **range-contains-admin-port AND world-CIDR (v4 or v6)**.

**The exposure is the emergency; the follow-on is the damage.** The open rule is a door; brute-force or direct SSH through it is the intrusion. Close the door first (revoke), then determine who walked through it (Flow Logs / GuardDuty brute-force / on-host auth logs).

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to a log platform. `AuthorizeSecurityGroupIngress` is a management event, so `lookup-events` works
- CloudTrail records the full `ipPermissions` structure (ports, protocol, `ipRanges`/`ipv6Ranges` CIDRs) in `requestParameters`, so the port/CIDR discriminator is available in the event itself
- GuardDuty enabled in all regions, `UnauthorizedAccess:EC2/SSHBruteForce` / `RDPBruteForce` confirm follow-on attacks through the opened port
- **AWS Config** with the managed rules `restricted-ssh` (a.k.a. `INCOMING_SSH_DISABLED`) and `vpc-sg-open-only-to-authorized-ports`, detective control that flags any SG open to `0.0.0.0/0` on 22, and can drive auto-remediation
- VPC Flow Logs on all VPCs, to see inbound connections on the exposed port

**Alerting (must be pre-configured)**
- **`ec2:AuthorizeSecurityGroupIngress` where the new rule opens an admin port (22/3389), or a range containing one, or all ports, to `0.0.0.0/0` or `::/0` → alert.** This is the primary control; it must inspect the `ipPermissions` content
- The same for `ec2:ModifySecurityGroupRules` (the newer API that can achieve the same exposure) and `ec2:AuthorizeSecurityGroupIngress` referencing a prefix list that resolves to broad ranges
- GuardDuty `UnauthorizedAccess:EC2/SSHBruteForce` → SNS → on-call
- AWS Config `restricted-ssh` non-compliant → auto-remediation (revoke) + notify

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` installed
- A map of security groups → the instances (and other ENIs) attached to each, so blast radius is immediate
- On-host SSH auth-log access (or centralised auth logs) for the exposed instances, to see successful/failed logins

**Known IOC Baselines**
- Baseline which principals modify security groups, normally a small IaC/network-admin set; an ad-hoc world-open rule from anyone else is anomalous
- Baseline the expected ingress of each SG so an added world-open rule is a diff, not a mystery
- Prefer SSM Session Manager for shell access so **no** SG ever needs port 22 open, a world-open-22 rule is then unambiguously an incident

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `AuthorizeSecurityGroupIngress`/`ModifySecurityGroupRules` opening an admin port (22/3389), or a range containing one, to `0.0.0.0/0` or `::/0` | CloudTrail | T1562.007 |
| P0 | Any ingress rule opening **all ports** (`0-65535` or `-1`) to `0.0.0.0/0` | CloudTrail | T1562.007 |
| P1 | GuardDuty `UnauthorizedAccess:EC2/SSHBruteForce` on an instance in the newly-exposed group | GuardDuty | T1562.007 |
| P1 | World-open ingress rule added by a principal not on the network-admin/IaC allowlist | CloudTrail | T1562.007 |
| P1 | AWS Config `restricted-ssh` flips to NON_COMPLIANT | AWS Config | T1562.007 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | World-open ingress on a non-admin but sensitive port (databases: 3306/5432/6379/27017/9200) | CloudTrail | T1562.007 |
| P2 | Inbound SSH connections on the exposed port from many distinct external IPs (scanning/brute force) | VPC Flow Logs | T1562.007 |
| P2 | `AuthorizeSecurityGroupIngress` denied at volume (`errorCode = Client.UnauthorizedOperation`), permission probing | CloudTrail | T1562.007 |
| P3 | World-open ingress on 80/443 (often legitimate for public web tiers), review against baseline | CloudTrail | T1562.007 |

### Detection Rule Quality Notes

The rules in `detections/` are unusable as written. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (AuthorizeSecurityGroupIngress, RevokeSecurityGroupIngress)` with `condition: selection` | Noisy and blind. Adding ingress rules is routine; the rule fires on every SG change and inspects nothing. `RevokeSecurityGroupIngress` is the *cleanup*, not the attack, pure noise | Alert on `Authorize`/`ModifySecurityGroupRules` only, and inspect the `ipPermissions` for port + world-CIDR |
| No port / CIDR inspection | The entire signal (admin port + `0.0.0.0/0`) is exactly what an event-name match ignores | Parse `ipPermissions`: `fromPort <= <admin-port> <= toPort` (range containment) AND `cidrIp == 0.0.0.0/0` or `cidrIpv6 == ::/0` |
| Only literal port 22, only IPv4 (per the description) | Misses range-contains-22, all-ports, 3389/RDP, and IPv6 `::/0` variants | Check range containment for the admin-port set and both `ipRanges` and `ipv6Ranges` |
| `ModifySecurityGroupRules` absent | The newer API achieves the same exposure and evades an Authorize-only rule | Include it |
| No principal allowlist | Cannot separate a reviewed IaC change from an attacker | Compare against the network-admin/IaC allowlist |
| Header TODO "verify acronym casing"; `level: medium` on a HIGH-severity exposure | Stale marker; under-rated | Resolve TODO; world-open admin port → `level: high` |

**Recommended detection, inspect the rule content.** This needs field extraction over `ipPermissions`, best expressed in the log platform (Query 3). A single-event Sigma rule can approximate it where the backend supports nested field matching:

```yaml
title: Security group ingress opened to the world on an admin port
id: 1a9c3e58-7b24-4d90-8f61-2c0b7a9d4e65
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName:
      - 'AuthorizeSecurityGroupIngress'
      - 'ModifySecurityGroupRules'
  world_v4:
    requestParameters|contains: '0.0.0.0/0'
  world_v6:
    requestParameters|contains: '::/0'
  admin_port:
    requestParameters|contains:
      - '"fromPort":22'
      - '"fromPort":3389'
      - '"fromPort":0'      # all-ports range start
  condition: selection and (world_v4 or world_v6) and admin_port
level: high
```

The `|contains` substring approach is a pragmatic approximation, it can miss a
range like `fromPort:20,toPort:23` that *contains* 22 without equalling it. The
authoritative check is the structured range-containment logic in Query 3; deploy
that as the real detection and treat the Sigma rule as a coarse first alert.

**On error strings:** EC2 CloudTrail errors carry a `Client.` prefix,
`Client.UnauthorizedOperation`, `Client.InvalidPermission.Duplicate` (rule already
exists). Match the prefixed form and confirm against a sample event.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`, robust, unlike `--output text | jq`.

#### Query 1: Find world-open ingress authorizations and inspect the rule content

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    . as $e |
    (.requestParameters.ipPermissions.items // [])[] as $perm |
    # world-open if any v4 range is 0.0.0.0/0 or any v6 range is ::/0
    ((($perm.ipRanges.items // []) | any(.cidrIp == "0.0.0.0/0")) or
     (($perm.ipv6Ranges.items // []) | any(.cidrIpv6 == "::/0"))) as $world |
    select($world) |
    {time: $e.eventTime,
     caller: $e.userIdentity.arn,
     access_key: $e.userIdentity.accessKeyId,        # feeds ACCESS_KEY_ID in Query 5
     sg: $e.requestParameters.groupId,
     protocol: $perm.ipProtocol,
     fromPort: $perm.fromPort,
     toPort: $perm.toPort,
     error: ($e.errorCode // "SUCCESS"),
     ip: $e.sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Flag any row whose `[fromPort,toPort]` range contains 22 or 3389, or where
`protocol == "-1"` (all traffic). `fromPort: -1` with `protocol: -1` means **all
ports, all protocols** to the world, the worst case.

#### Query 2 - Blast radius: which instances/ENIs are in the exposed group?

```bash
REGION="us-east-1"
SG_ID="<sg-id-from-Query-1>"

# Instances in the exposed SG (reachable on the opened port right now)
aws ec2 describe-instances --region "$REGION" \
  --filters "Name=instance.group-id,Values=$SG_ID" "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].{Id:InstanceId,PublicIp:PublicIpAddress,PrivateIp:PrivateIpAddress}' \
  --output table

# Any other ENIs (load balancers, RDS, etc.) attached to the SG
aws ec2 describe-network-interfaces --region "$REGION" \
  --filters "Name=group-id,Values=$SG_ID" \
  --query 'NetworkInterfaces[].{ENI:NetworkInterfaceId,Type:InterfaceType,Desc:Description,PublicIp:Association.PublicIp}' \
  --output table
```

Instances with a **public IP** in this group are internet-reachable on the opened
port *now*, prioritise those.

#### Query 3 - Deployable detection (log platform): range-aware content inspection

**Dialect: Sentinel / Azure Log Analytics KQL**, not CloudWatch Logs Insights. Expands `ipPermissions` and checks range-containment + world-CIDR.

```kql
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventSource == "ec2.amazonaws.com"
| where EventName in ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules")
| extend Req = parse_json(RequestParameters)
| mv-expand Perm = Req.ipPermissions.items
| extend FromPort = toint(Perm.fromPort), ToPort = toint(Perm.toPort),
         Proto = tostring(Perm.ipProtocol)
// Use `contains` (substring), NOT `has`, `has` is whole-term and CIDR strings
// contain `.`/`/` delimiters, so `has "0.0.0.0/0"` silently never matches.
| extend WorldV4 = tostring(Perm.ipRanges) contains "0.0.0.0/0"
| extend WorldV6 = tostring(Perm.ipv6Ranges) contains "::/0"
| where WorldV4 or WorldV6
| extend AllPorts = (Proto == "-1") or (FromPort == 0 and ToPort >= 65535)
// range-containment covers exact matches too (fromPort==toPort==22); no separate
// set_has_element check needed
| extend HitsAdminPort = AllPorts
         or (isnotnull(FromPort) and isnotnull(ToPort)
             and ((FromPort <= 22 and ToPort >= 22) or (FromPort <= 3389 and ToPort >= 3389)))
| where HitsAdminPort
| project TimeGenerated, UserIdentityArn, SourceIpAddress,
          SG = tostring(Req.groupId), Proto, FromPort, ToPort, WorldV4, WorldV6, AllPorts
| extend Verdict = iff(AllPorts, "ALL PORTS OPEN TO WORLD - P0", "ADMIN PORT OPEN TO WORLD - P0")
| order by TimeGenerated desc
```

CloudWatch Logs Insights cannot expand the `ipPermissions` array or do range math
inline; there, alert coarsely and pivot to Query 1 for the structured check:

```
fields @timestamp, userIdentity.arn, requestParameters.groupId
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["AuthorizeSecurityGroupIngress","ModifySecurityGroupRules"]
| filter @message like "0.0.0.0/0" or @message like "::/0"
| filter @message like /"fromPort":(22|3389|0)/
```

#### Query 4: Did anyone connect through the open port? (the follow-on)

```bash
# VPC Flow Logs (CloudWatch Logs): inbound ACCEPT on port 22 to an exposed ENI
LOG_GROUP="/vpc/flowlogs"
ENI_ID="<eni-of-an-exposed-instance-from-Query-2>"
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '4 hours ago' +%s 2>/dev/null \
        || date -u -v-4H +%s)

aws logs filter-log-events --log-group-name "$LOG_GROUP" \
  --start-time "${START}000" --filter-pattern "\"$ENI_ID\"" \
  --query 'events[*].message' --output text 2>/dev/null | \
  awk '$7=="22" && $13=="ACCEPT" && $NF=="OK" {print $4" -> "$5":"$7}' | sort | uniq -c | sort -rn | head
  # v2 flow log fields: $4=srcaddr $5=dstaddr $7=dstport $13=action $NF=log-status
```

Many distinct source IPs = internet scanning/brute force. Cross-check accepted
sources against the on-host SSH auth logs for **successful** logins, a successful
login from an unrecognised IP escalates this to a host-compromise incident.

#### Query 5: Full session reconstruction of the principal

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

ACCESS_KEY_ID="<access-key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$START" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Look for *other* SG changes by the same principal (they may have opened more than
one group / port) and for what they did next through the opened access.

#### Query 6: Multi-region + account-wide sweep for world-open admin ports

Independent of this incident, find every SG currently exposing an admin port to
the world, the attacker may have opened several, and legacy exposures may exist.

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  aws ec2 describe-security-groups --region "$REGION" \
    --query 'SecurityGroups[?IpPermissions[?(FromPort<=`22` && ToPort>=`22`) &&
               (IpRanges[?CidrIp==`0.0.0.0/0`] || Ipv6Ranges[?CidrIpv6==`::/0`])]].
             {SG:GroupId,Name:GroupName,Vpc:VpcId}' \
    --output text 2>/dev/null | while read -r LINE; do
      [ -n "$LINE" ] && echo "[!] $REGION world-open-22: $LINE"
    done
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The open rule is the emergency. **Revoke it first**, that closes the door
instantly and is fully reversible if it turns out legitimate. Then contain the
principal and assess who connected.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1: Revoke the world-open rule (close the door)

```bash
REGION="us-east-1"
SG_ID="<sg-id-from-Query-1>"

# Revoke the exact rule the attacker added (port 22 from 0.0.0.0/0). Mirror the
# real fromPort/toPort/protocol from Query 1 if they opened a range or all ports.
aws ec2 revoke-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
  --ip-permissions 'IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0}]'
echo "[OK] Revoked world-open port 22 on $SG_ID"

# If they also opened IPv6, revoke that too
aws ec2 revoke-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
  --ip-permissions 'IpProtocol=tcp,FromPort=22,ToPort=22,Ipv6Ranges=[{CidrIpv6=::/0}]' 2>/dev/null

# Verify no world-open admin rule remains on this SG
aws ec2 describe-security-groups --group-ids "$SG_ID" --region "$REGION" \
  --query 'SecurityGroups[0].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`] || Ipv6Ranges[?CidrIpv6==`::/0`]]' \
  --output json
```

#### Step 2: Contain the principal that opened it

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')          # user ARN: name = last segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] Disabled key $K for $U"
  done
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')           # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]}'
  echo "[OK] Revoked sessions for role $R"
fi
```

#### Step 3: Deny further SG modification by the principal

The steps below (and the Eradication/Recovery cleanups that reference
`SUSPECT_ROLE`) are for a **role** principal. If the suspect is an **IAM user**,
Step 2 already contained it by disabling its access keys; to add a scoped deny,
use the `put-user-policy` / `delete-user-policy` equivalents with the same policy
document.

```bash
SUSPECT_ROLE="<role-name>"    # role principals; for an IAM user use put-user-policy
aws iam put-role-policy --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenySGChanges" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":["ec2:AuthorizeSecurityGroupIngress","ec2:ModifySecurityGroupRules","ec2:AuthorizeSecurityGroupEgress"],"Resource":"*"}]
  }'
echo "[OK] Security-group modification denied for $SUSPECT_ROLE"
```

#### Step 4: If instances were connected to, isolate them

If Query 4 shows accepted inbound SSH from unrecognised IPs (especially a
*successful* login), isolate those instances into a no-egress quarantine SG and
snapshot for forensics (per the credential-theft playbook's helper), treat them
as potentially compromised, not merely exposed.

```bash
REGION="us-east-1"
CONNECTED_INSTANCE="<i-with-successful-inbound-ssh>"
for VOL in $(aws ec2 describe-instances --instance-ids "$CONNECTED_INSTANCE" --region "$REGION" \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId' --output text); do
  aws ec2 create-snapshot --volume-id "$VOL" --region "$REGION" \
    --description "IR-T1562.007-$CONNECTED_INSTANCE-$(date -u +%Y%m%dT%H%M%SZ)" --query 'SnapshotId' --output text
done
echo "[OK] Snapshot started for $CONNECTED_INSTANCE, apply quarantine SG next"
```

---

## 4. Eradication

### Remove Attacker Access

#### Sweep for every world-open admin rule the attacker (or legacy drift) left

Query 6 across all regions; remove each world-open admin-port rule found. Do not
assume only the one SG from Query 1 was touched.

```bash
REGION="us-east-1"
# For each SG flagged by Query 6, revoke its world-open admin rules. Example for one SG:
SG_ID="<flagged-sg>"
aws ec2 revoke-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
  --ip-permissions 'IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0}]' 2>/dev/null && \
  echo "[OK] Revoked world-open 22 on $SG_ID"
```

#### Assess whether the exposure was used

```bash
# For every exposed instance, correlate Query 4 accepted-inbound sources against
# on-host SSH auth logs. A SUCCESSFUL login from an unrecognised IP means the host
# is compromised: pivot to host IR and rebuild it.
echo "For each exposed instance: review /var/log/auth.log (or secure) for 'Accepted'"
echo "SSH logins from the Query 4 source IPs. Any success => host compromised => rebuild."
```

#### Right-size security-group permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove ec2:AuthorizeSecurityGroupIngress / ModifySecurityGroupRules from principals
# that are not network-admin/IaC. NOTE: IAM cannot condition these actions on the
# CIDR/port of the rule (see Guardrails): restriction is by principal, plus a
# Config auto-remediation backstop.
```

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenySGChanges" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify no world-open admin rule remains anywhere

```bash
FAIL=0
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  HITS=$(aws ec2 describe-security-groups --region "$REGION" \
    --query 'SecurityGroups[?IpPermissions[?(FromPort<=`22` && ToPort>=`22`) &&
               (IpRanges[?CidrIp==`0.0.0.0/0`] || Ipv6Ranges[?CidrIpv6==`::/0`])]].GroupId' \
    --output text 2>/dev/null)
  [ -n "$HITS" ] && { echo "[FAIL] $REGION still has world-open-22: $HITS"; FAIL=1; }
done
[ "$FAIL" -eq 0 ] && echo "[OK] No security group exposes port 22 to the world in any region"
```

#### Verify no further SG modification since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | select(.errorCode == null) | .eventTime' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No further ingress authorizations from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further authorizations, containment did not hold"
```

#### Verify the credential is dead

```bash
SUSPECT_ARN="<principal-arn>"
if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  ACTIVE=$(aws iam list-access-keys --user-name "$U" \
    --query 'AccessKeyMetadata[?Status==`Active`]' --output text)
  [ -z "$ACTIVE" ] && echo "[OK] No active keys for $U" || echo "[FAIL] $U still has active keys"
fi
```

#### Verify AWS Config is compliant again

```bash
REGION="us-east-1"
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name "restricted-ssh" --region "$REGION" \
  --compliance-types NON_COMPLIANT \
  --query 'EvaluationResults[].EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId' \
  --output text 2>/dev/null | grep . && echo "[FAIL] restricted-ssh still has NON_COMPLIANT resources" \
  || echo "[OK] restricted-ssh reports compliant"
```

#### Confirm the corrected detection fires

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
SG_ID="<test-sg-id>"

# Re-run the emulation and assert the world-open-22 authorization is captured with
# the port + CIDR content the corrected rule keys on
HIT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg sg "$SG_ID" '[.Events[].CloudTrailEvent | fromjson |
    select(.requestParameters.groupId == $sg) |
    select((.requestParameters.ipPermissions.items // [])[] |
      (.fromPort <= 22 and .toPort >= 22) and
      ((.ipRanges.items // []) | any(.cidrIp == "0.0.0.0/0")))] | length')

[ -n "$HIT" ] && [ "$HIT" -gt 0 ] && echo "[OK] World-open-22 authorization captured, the rule has data to fire on" \
                                  || echo "[FAIL] Not captured, check trail / ipPermissions field path"
echo "Confirm the deployed rule classified it ADMIN PORT OPEN TO WORLD, and did NOT"
echo "fire on the benign RevokeSecurityGroupIngress cleanup."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could open SSH to the world | `ec2:AuthorizeSecurityGroupIngress` granted to a principal outside network-admin/IaC; no guardrail preventing world-open admin ports |
| Exposure undetected | Shipped rule matched all authorize/revoke with no port/CIDR inspection; no AWS Config `restricted-ssh` rule; no world-open alert |
| SSH reachable from the internet at all | Instances depended on SSH/port 22 rather than SSM Session Manager, so opening 22 was even useful to the attacker |
| No auto-remediation | A world-open rule stayed open until manually noticed instead of being auto-revoked within minutes |
| Possible undetected access | No correlation of the exposure with inbound Flow Logs / on-host auth logs |

### Recommended Guardrails

**Auto-remediate world-open admin ports (the primary control)**
- IAM **cannot** condition `AuthorizeSecurityGroupIngress` on the rule's CIDR or port, there is no request-context key for the rule content. So prevention-by-IAM is not possible for the rule itself; the effective control is **detective + auto-remediation**:
  - AWS Config managed rule `restricted-ssh` (and `restricted-common-ports`) → **auto-remediation** (`AWS-DisablePublicAccessForSecurityGroup` / a Lambda) that revokes the offending rule within minutes
  - An EventBridge rule on `AuthorizeSecurityGroupIngress` → Lambda that inspects `ipPermissions` and auto-revokes world-open admin rules, alerting the owner

**Restrict who can modify security groups**

```json
// SCP: only network-admin / IaC principals may modify SG ingress
{
  "Effect": "Deny",
  "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:ModifySecurityGroupRules"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/network-admin", "arn:aws:iam::*:role/ci-*", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

**Remove the need for open SSH entirely**
- Use **SSM Session Manager** for shell access so no security group ever needs port 22 open to anything, this eliminates the attack's usefulness (and ties to the SSM-session playbook's guidance). If SSH is truly required, restrict source to a bastion/VPN CIDR, never `0.0.0.0/0`

**Detection improvements**
- Deploy the content-inspection rule (Query 3): world-CIDR + admin-port range-containment on `Authorize`/`ModifySecurityGroupRules`, never the shipped all-event match
- Alert GuardDuty `UnauthorizedAccess:EC2/SSHBruteForce` and correlate with the exposure event
- Alert AWS Config `restricted-ssh` NON_COMPLIANT

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1562.007 - Impair Defenses: Disable or Modify Cloud Firewall |
| MITRE tactic | Defense Evasion (TA0005) |
| Primary API | `ec2:AuthorizeSecurityGroupIngress` (also `ec2:ModifySecurityGroupRules`); `Revoke...` on cleanup |
| Event source | `ec2.amazonaws.com` |
| Key discriminator | An `ipPermissions` rule whose port range contains an admin port (22/3389), or all ports, with source `0.0.0.0/0` or `::/0`. The event name alone is not a signal |
| Generalise | Match range-containment (not `fromPort==22`), both IPv4 and IPv6, and the all-ports (`-1`) case |
| Follow-on confirmation | GuardDuty `UnauthorizedAccess:EC2/SSHBruteForce`; inbound Flow Logs; on-host SSH auth logs |
| IAM limitation | `AuthorizeSecurityGroupIngress` is NOT conditionable on CIDR/port, guardrail is Config auto-remediation + principal restriction, not an IAM condition on the rule |
| Error strings (`Client.`-prefixed) | `Client.UnauthorizedOperation`, `Client.InvalidPermission.Duplicate` |
| Resources created | 1 EC2 security group (no initial ingress) |
| Follow-on to watch for | SSH brute force / successful login through the opened port → host compromise |

**MITRE mapping note:** T1562.007 is correctly the *technique* (Disable or Modify
Cloud Firewall), but its canonical **tactic is Defense Evasion**, not Exfiltration
as the MANIFEST/Stratus catalogue tags it. Opening SSH to the world impairs a
network defense to enable access; it is not itself exfiltration. Treat the
technique ID as correct and the "Exfiltration" tactic label as a catalogue
artefact. Recorded for the end-of-run MITRE-mapping finding.

### Revert

`pulumi destroy` in `infra/` removes the security group. The emulation's revert
also calls `RevokeSecurityGroupIngress` to remove the world-open rule, so a normal
run self-cleans. After a **real** incident, `pulumi destroy` is irrelevant, revoke
the rule immediately (§3), sweep for other world-open rules (§4), and rebuild any
instance that was successfully accessed through the opening; tearing down one SG
does not address other exposures or a host that was logged into.
