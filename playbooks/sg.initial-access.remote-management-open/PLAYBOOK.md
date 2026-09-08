# IR Playbook: Security Group Opened to the Internet — remote management via `AuthorizeSecurityGroupIngress`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Firewall weakening — an ingress rule allows the internet to reach a security group, on a remote-management port or on all protocols |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical for remote-management ports or all-protocols to `0.0.0.0/0` or `::/0`; high for any other port and for a modified existing rule. |
| MITRE Tactics | Defense Impairment; Initial Access |
| MITRE Techniques | T1686.001; T1133 |
| Services in Scope | EC2 (security groups), VPC (flow logs), CloudTrail, IAM |

**What the technique does:** the actor adds an inbound rule permitting `0.0.0.0/0` or `::/0`. The
change is effectively immediate — AWS: *"Rule changes are propagated to instances associated with
the security group as quickly as possible"* — so there is no approval step and no window to
intervene in. Detection here is after the fact by construction.

**Why the usual reflexes miss it, and this one has four distinct ways to be wrong.** The first is to
read `requestParameters.cidrIp`: that field exists only in the **flat** request form, and AWS says
four separate times to *"use IP permissions instead"* — which is what the console, CLI and SDKs
emit. The second follows from it: the flat form **cannot express IPv6 at all**, so `::/0` is
invisible to any rule keyed on it. The third is to match a port list: `IpProtocol: -1` opens every
port with no `fromPort` present, and AWS adds that an *unsupported* protocol value *"allows traffic
on all ports, regardless of any ports that you specify"*. The fourth is to watch only the
`Authorize` calls, when `ModifySecurityGroupRules` changes an existing rule's CIDR and ports with no
`Authorize` event at all.

**Detection thesis:** read both request shapes and both address families, treat all-protocols as
equivalent to a management port, and cover the modify path the pack watches nowhere for.

**Adjacent playbooks.** Opening an outbound path is `../sg.exfiltration.egress-rule-opened/`.
Accepted inbound traffic observed in flow logs — the consequence rather than the change — is
`../vpc.lateral-movement.incoming-requests-over-remote-service-ports-accepted-from/` and
`../vpc.initial-access.critical-database-exposure-to-public-internet/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. `AuthorizeSecurityGroupIngress` and
`ModifySecurityGroupRules` are management events, on by default.

**VPC flow logs on the subnets these groups protect.** The security group event says the door was
opened; only flow logs say whether anything came through it. They are the sole evidence of use, they
have their own retention, and they cannot be enabled retroactively for a window that has passed.

The recorded set of security groups that are **internet-facing by design** — bastions, VPN
concentrators, public load balancer groups. Without it every alert needs a conversation before it
can be rated.

**Alerting (must be pre-configured)**

- **An ingress rule opening `0.0.0.0/0` or `::/0` on a remote-management port, or on all protocols → P0**
- **An ingress rule opening `0.0.0.0/0` or `::/0` with `IpProtocol: -1` — every port reachable, and no `fromPort` field says so → P0**
- **An ingress rule opening `::/0` on any port — invisible to any rule reading the flat `cidrIp` field → P0**

**Response Tooling**

An IAM principal that can call `ec2 revoke-security-group-ingress`, `describe-security-group-rules`
and `modify-security-group-rules` outside the change pipeline, in every region.

Access to flow logs for the affected subnets, queryable by time range and destination port. That
query is the difference between "a port was open" and "a port was open and used".

**Known IOC Baselines**

The roles that own network configuration, populating `known_provisioners`. Infrastructure applies
create ingress rules routinely.

Normal deployment cadence per security group. An open-then-close pair matching the deploy schedule
is a deployment; one at 03:00 on a group nobody has touched in months is not.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | Ingress opened to `0.0.0.0/0` or `::/0` with `IpProtocol: -1` — every port reachable, and no `fromPort` field says so | CloudTrail | T1686.001 |
| P0 | Ingress opened to `0.0.0.0/0` or `::/0` on SSH, RDP, VNC, telnet or WinRM | CloudTrail | T1686.001 / T1133 |
| P0 | Ingress opened to `::/0` on any port — the flat `cidrIp` field cannot carry IPv6, so a rule reading it is blind here | CloudTrail | T1686.001 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `ModifySecurityGroupRules` changing an existing rule's CIDR, ports or protocol | CloudTrail | T1686.001 |
| P2 | Ingress opened to `0.0.0.0/0` on a non-management port by a principal not on the provisioner list | CloudTrail | T1686.001 |

### Detection Rule Quality Notes

The four ingress source rules are threshold and immediate queries, fully readable, so every row
below is auditable against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `requestParameters.cidrIp` reads only the flat request form | That field exists only when a single IPv4 rule is submitted without `ipPermissions`. AWS directs callers to *"use IP permissions instead"* four times, and that is what the console, CLI and SDKs emit — so in most estates this rule has never fired | Both shapes matched. The KQL counts flat-form usage so a reviewer can confirm, from their own account, whether the original could ever have worked |
| The flat form cannot express IPv6 | *"To specify an IPv6 address range, use IP permissions instead."* `::/0` is exactly as open and is structurally invisible to the source rule | `::/0` matched in both shapes, and rated identically to `0.0.0.0/0` |
| A port list misses all-protocols rules | `IpProtocol: -1` opens port 22 with no `fromPort: 22` present. AWS adds that an unsupported protocol value allows all ports regardless of the ports specified | An all-protocols sibling block, treated as equivalent to a management port |
| The P1 rule regexes `ipPermissions.items_str` | That is a pipeline-flattened field, not a CloudTrail field. The rule works where it was authored and matches nothing elsewhere | Plain field paths; Sigma is mapping-agnostic and the backend applies its own conventions |
| `ModifySecurityGroupRules` not covered anywhere | It changes an existing rule's CIDR and ports with no `Authorize` event. Narrow for a review, widen afterwards, and nothing in the pack sees it | A dedicated rule at high |
| The two ingress rules group by different fields | `Added` groups by `sessionIssuer.userName` (the role), `Revoked` by `userIdentity.arn` (the session). Sibling rules at two granularities, so they cannot be correlated with each other | One grouping across both, which is what makes the open-then-close correlation possible |

**Recommended detection — both request shapes, both address families, and the modify path.**

```yaml
# Security group ingress opened to the internet (T1686.001)
#
# THE `0.0.0.0/0` RULE READS ONLY THE LEGACY REQUEST SHAPE, WHICH MOST TOOLING DOES NOT SEND.
# `AuthorizeSecurityGroupIngress` accepts either top-level flat parameters (`CidrIp`, `FromPort`,
# `IpProtocol` — all Required: No) or the structured `IpPermissions.N` array. The source rule
# matches `requestParameters.cidrIp`, which exists ONLY in the flat form. AWS says four separate
# times to "use IP permissions instead" for IPv6 or for multiple rules, and every example in the API
# reference uses IpPermissions — which is what the console, the CLI and the SDKs emit. The rules
# below read BOTH shapes, because reading one is not a partial detection, it is a detection that
# misses whichever shape the estate happens to produce.
#
# AND THE FLAT FORM CANNOT CARRY IPv6 AT ALL. AWS: "To specify an IPv6 address range, use IP
# permissions instead." So a rule keyed on `cidrIp` is IPv4-only by construction. `::/0` is exactly
# as open as `0.0.0.0/0` and lives at ipPermissions.items[].ipv6Ranges.items[].cidrIpv6.
#
# `0.0.0.0/0` IS NOT THE ONLY WAY TO BE OPEN, AND A PORT LIST IS NOT THE ONLY WAY TO REACH SSH.
#   * IpProtocol -1 means ALL protocols — port 22 is open with no `fromPort: 22` anywhere.
#   * "If you specify a protocol other than one of the supported values, traffic is allowed on all
#     ports, regardless of any ports that you specify." An unrecognised protocol opens everything
#     while carrying port fields that look restrictive.
#   * 0.0.0.0/1 plus 128.0.0.0/1 covers the internet in two rules, and neither string matches.
# The all-protocols case is a sibling block below; the split-CIDR case is stated as a residual gap
# in ../PLAYBOOK.md rather than pretended away.
#
# THE `items_str` FIELD THE P1 RULE REGEXES IS NOT A CLOUDTRAIL FIELD. It is a flattened
# representation produced by an ingestion pipeline. A rule depending on it works where it was
# authored and silently matches nothing elsewhere — the same portability failure as an
# enrichment-only field.
#
# AND NOTHING IN THE PACK WATCHES `ModifySecurityGroupRules`, which changes an existing rule's CIDR
# and ports with no Authorize call at all.
title: Security group opened to the internet on a remote-management port
id: 6a3f18d7-5b04-42e9-93c1-0d78e256af4b
name: sg_remote_management_open_to_internet
status: experimental
description: >-
  An ingress rule was added allowing the internet to reach a remote-management port. Matches both
  request shapes — the flat cidrIp form and the structured ipPermissions form — and both address
  families, because the flat form cannot express IPv6 and most tooling does not send it. The
  all-protocols sibling block covers the case where port 22 is open with no port field present at all.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html
  - https://attack.mitre.org/techniques/T1686/001/
  - https://attack.mitre.org/techniques/T1133/
tags:
  - attack.defense-evasion
  - attack.initial-access
  - attack.t1686.001
  - attack.t1133
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'AuthorizeSecurityGroupIngress'
  success:
    errorCode: null
  # Sibling blocks — each is a complete alternative shape of "open to the world".
  # NOTE: `|contains` over the serialised ipPermissions subtree cannot scope a port and a CIDR to
  # the SAME permission entry, so a request adding port 22 to a corporate CIDR alongside port 443 to
  # 0.0.0.0/0 matches. That is a deliberate over-match; §2 Query 2 resolves it by parsing.
  open_world_flat:
    requestParameters.cidrIp:
      - '0.0.0.0/0'
      - '::/0'
  open_world_structured:
    requestParameters.ipPermissions|contains:
      - '0.0.0.0/0'
      - '::/0'
  remote_ports_flat:
    requestParameters.fromPort:
      - 22
      - 23
      - 3389
      - 5900
      - 5985
      - 5986
  remote_ports_structured:
    requestParameters.ipPermissions|contains:
      - '"fromPort":22'
      - '"fromPort":23'
      - '"fromPort":3389'
      - '"fromPort":5900'
      - '"fromPort":5985'
      - '"fromPort":5986'
  # IpProtocol -1 is ALL protocols: every remote-management port is open and no port field says so.
  all_protocols:
    requestParameters.ipProtocol: '-1'
  all_protocols_structured:
    requestParameters.ipPermissions|contains: '"ipProtocol":"-1"'
  condition: selection and success and (open_world_flat or open_world_structured)
    and (remote_ports_flat or remote_ports_structured or all_protocols or all_protocols_structured)
falsepositives:
  - >-
    A bastion or VPN concentrator deliberately reachable from the internet. It should be a short
    recorded list; if it is not, the exposure inventory is the finding rather than the event.
level: critical
---
title: Security group opened to the internet on any port
id: b70c294e-8d61-4a35-bf08-31e5c7920da6
name: sg_ingress_open_to_internet
status: experimental
description: >-
  An ingress rule was added allowing 0.0.0.0/0 or ::/0 on any port. Shipped below the
  remote-management rule because a public web tier legitimately looks like this, and above the base
  rule because most workloads should be reached through a load balancer rather than directly.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html
  - https://attack.mitre.org/techniques/T1686/001/
tags:
  - attack.defense-evasion
  - attack.t1686.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'AuthorizeSecurityGroupIngress'
  success:
    errorCode: null
  open_world_flat:
    requestParameters.cidrIp:
      - '0.0.0.0/0'
      - '::/0'
  open_world_structured:
    requestParameters.ipPermissions|contains:
      - '0.0.0.0/0'
      - '::/0'
  # POPULATE BEFORE DEPLOYING with the roles that own network configuration.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and (open_world_flat or open_world_structured) and not known_provisioners
falsepositives:
  - >-
    A public-facing web tier on 80 or 443. Common and usually correct; the security groups that
    front the internet should be a known set, and one that is not on it is the finding.
level: high
---
title: Existing security group rule modified
id: 2f8b510a-c497-41d6-a03e-6b91d24e7c85
name: sg_rule_modified
status: experimental
description: >-
  ModifySecurityGroupRules succeeded. This changes an existing rule's CIDR, ports or protocol with
  no Authorize call at all, so a rule set scoped to AuthorizeSecurityGroupIngress and
  AuthorizeSecurityGroupEgress never sees it — and the source pack watches nowhere for it. Narrowing
  a rule during a review and widening it back afterwards produces exactly one of these events and
  nothing else.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySecurityGroupRules.html
  - https://attack.mitre.org/techniques/T1686/001/
tags:
  - attack.defense-evasion
  - attack.t1686.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'ModifySecurityGroupRules'
  success:
    errorCode: null
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    Rule description edits, which use the same API and are harmless. The request carries the updated
    rule, so the triage step is reading whether the CIDR or the ports changed — not whether the
    event occurred.
level: high
---
title: Security group opened to the internet and then closed by the same principal
id: 9c4e0b73-2a58-4f19-86d0-e5137ba296cf
status: experimental
description: >-
  A principal opened an ingress rule to the internet and revoked it again. The end state is correct,
  so every configuration review and every posture scan shows nothing — the exposure exists only as
  an interval between two events. The revoke rule the source pack ships at P4 is the second half of
  this pair and is the reason it is worth keeping at all.
references:
  - https://attack.mitre.org/techniques/T1686/001/
  - https://attack.mitre.org/techniques/T1133/
tags:
  - attack.defense-evasion
  - attack.initial-access
  - attack.t1686.001
  - attack.t1133
correlation:
  type: temporal_ordered
  rules:
    - sg_ingress_open_to_internet
    - sg_ingress_revoked
  group-by:
    - userIdentity.arn
  timespan: 24h
falsepositives:
  - >-
    A deployment that opens a rule, completes a task and tidies up. Allowlist the provisioning role
    on the base rules rather than shortening the timespan — a deliberate actor is the patient one.
level: high
---
title: Security group ingress rule revoked
id: 4d16a8f2-70be-4c53-91a7-b8032ed5f649
name: sg_ingress_revoked
status: experimental
description: >-
  Base rule — correlation component and change accounting, never for direct alerting. A successful
  RevokeSecurityGroupIngress. On its own this is a firewall rule being removed, which is a good
  thing happening; its value is as the closing half of an open-then-close pair.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RevokeSecurityGroupIngress.html
tags:
  - attack.defense-evasion
  - attack.t1686.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'RevokeSecurityGroupIngress'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: tie a port and a CIDR to the same permission entry. A request
adding port 22 to a corporate range alongside port 443 to `0.0.0.0/0` matches. That is a deliberate
over-match, resolved by parsing in §2 Query 2.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> Security group events are **regional** — run these in the region holding the group.

Run Query 1 first; it produces the group and the window that Query 3 uses against flow logs.

#### Query 1 — Reconstruct: what was opened, in which request shape

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in AuthorizeSecurityGroupIngress RevokeSecurityGroupIngress ModifySecurityGroupRules; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | .requestParameters as $r
      # FLAT form: top-level cidrIp exists only for a single IPv4 rule submitted without
      # ipPermissions. It CANNOT carry IPv6 — AWS: "To specify an IPv6 address range, use IP
      # permissions instead." STRUCTURED form is what the console, CLI and SDKs emit.
      | ($r.ipPermissions | tostring) as $perms
      | (($r.cidrIp // "") == "0.0.0.0/0" or ($perms | test("0\\.0\\.0\\.0/0"))) as $v4
      | (($r.cidrIp // "") == "::/0" or ($perms | test("::/0"))) as $v6
      # ipProtocol -1 is ALL protocols: every port open, no fromPort field to match on.
      | ((($r.ipProtocol // "") == "-1") or ($perms | test("\"ipProtocol\":\"-1\""))) as $allproto
      | (if ($r.cidrIp // "") != "" then "FLAT" else "structured" end) as $shape
      | "\(.eventTime)  \(.eventName)  shape=\($shape)  " +
        "open=\(if $v4 then "0.0.0.0/0 " else "" end)\(if $v6 then "::/0 " else "" end)" +
        "\(if $allproto then "ALL-PROTOCOLS " else "" end)" +
        " group=\($r.groupId // "-")  by=\(.userIdentity.arn)  ip=\(.sourceIPAddress)"'
done | sort
```

Count the `shape=FLAT` lines across the whole window. If there are none while open-to-the-world
rules were created, every one of them was submitted in the structured form — and the source rule,
which reads only `requestParameters.cidrIp`, has never fired in this account and never will. That is
worth establishing before anything else, because it changes whether this is a detection gap or an
incident.

#### Query 2 — Parse the live rules, because matching the request is not enough

```bash
GROUP_ID="${1:?security group id from Query 1}"
REGION="${AWS_REGION:-us-east-1}"

# describe-security-group-rules returns each rule as its own object, which is what makes the
# port-and-CIDR pairing unambiguous — the thing no substring match over the request can do.
aws ec2 describe-security-group-rules --region "$REGION" \
  --filters "Name=group-id,Values=${GROUP_ID}" --output json 2>/dev/null \
| jq -r '.SecurityGroupRules[]
    | select(.IsEgress == false)
    | (.CidrIpv4 // .CidrIpv6 // .ReferencedGroupInfo.GroupId // .PrefixListId // "?") as $src
    | (if (.IpProtocol == "-1") then "ALL-PROTOCOLS" else "\(.IpProtocol) \(.FromPort)-\(.ToPort)" end) as $ports
    | (if ($src == "0.0.0.0/0" or $src == "::/0") then "[!] OPEN" else "[ ]     " end) as $flag
    | "\($flag) \(.SecurityGroupRuleId)  \($ports)  from \($src)  \(.Description // "")"'

echo
echo "[!] A PrefixListId source hides the CIDRs — a managed prefix list can contain 0.0.0.0/0 and"
echo "    the rule names only the list. Resolve it:"
echo "    aws ec2 get-managed-prefix-list-entries --prefix-list-id <id> --region $REGION"
```

#### Query 3 — Did anything actually come through

```bash
GROUP_ID="${1:?security group id}"
OPEN_TIME="${2:?open timestamp from Query 1}"
CLOSE_TIME="${3:-now}"
REGION="${AWS_REGION:-us-east-1}"

# The security group event says the door was open. Only flow logs say whether it was used, and they
# are a separate data source with separate retention — this is not answerable from CloudTrail.
ENIS="$(aws ec2 describe-network-interfaces --region "$REGION" \
         --filters "Name=group-id,Values=${GROUP_ID}" \
         --query 'NetworkInterfaces[].NetworkInterfaceId' --output text 2>/dev/null)"
echo "Interfaces in this group: ${ENIS:-none}"

LG="$(aws ec2 describe-flow-logs --region "$REGION" \
       --query 'FlowLogs[?LogDestinationType==`cloud-watch-logs`].LogGroupName | [0]' \
       --output text 2>/dev/null)"
if [ -z "$LG" ] || [ "$LG" = "None" ]; then
  echo "[FAIL] no CloudWatch flow log destination found — whether the open port was used is"
  echo "       UNANSWERABLE, and that is the finding to record rather than 'no evidence of access'."
  exit 0
fi

echo "[OK] flow logs in $LG — query ACCEPT records to these interfaces between"
echo "     $OPEN_TIME and $CLOSE_TIME, filtering on the exposed destination port:"
echo "     fields @timestamp, srcAddr, dstPort, action | filter action=\"ACCEPT\""
```

#### Query 4 — Full session reconstruction of the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 1 required}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

# For an assumed role the CloudTrail username is the SESSION name: the second slash-separated
# segment after `assumed-role/`, not the role name and not the last segment.
case "$PRINCIPAL" in
  *:assumed-role/*) LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $2}')" ;;
  *)                LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')" ;;
esac

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$LOOKUP" \
  --start-time "$START" --region "$REGION" --max-results 200 \
  --query 'Events[].[EventTime,EventName,EventSource]' --output text 2>/dev/null | sort
```

Look for `DescribeSecurityGroups` or `DescribeSecurityGroupRules` before the change, and for
`RunInstances` or `AuthorizeSecurityGroupEgress` after it. Opening ingress to reach something is one
half; what the instance then does outbound is `../sg.exfiltration.egress-rule-opened/`.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Revoke the rule first. It is one call, it takes effect as quickly as the opening did, and unlike most
containment in this project it carries little risk of breaking something silently — a rule that
should not exist has no dependents.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 2 shows an
`ALL-PROTOCOLS` rule open to `0.0.0.0/0`, every port on every instance in that group is currently
reachable from the internet. Revoke before investigating, and treat any instance in the group as
potentially reached.

#### Step 1 — Revoke the rule

```bash
GROUP_ID="${1:?security group id}"
RULE_ID="${2:?security group rule id from Query 2}"
REGION="${AWS_REGION:-us-east-1}"

# Preserve the rule before removing it — the rule id and its contents are the evidence, and
# describe-security-group-rules will not return it once revoked.
aws ec2 describe-security-group-rules --region "$REGION" \
  --security-group-rule-ids "$RULE_ID" --output json \
  > "./evidence-${GROUP_ID}-${RULE_ID}.json" 2>/dev/null \
  && echo "[OK] rule preserved at ./evidence-${GROUP_ID}-${RULE_ID}.json"

aws ec2 revoke-security-group-ingress --region "$REGION" \
  --group-id "$GROUP_ID" --security-group-rule-ids "$RULE_ID" \
  && echo "[OK] rule $RULE_ID revoked from $GROUP_ID" \
  || echo "[FAIL] revoke failed — check the rule id and that it has not already been removed"
```

Revoking by **rule id** rather than by protocol and CIDR is deliberate: it removes exactly the rule
found, and it cannot accidentally match a different rule that happens to share a CIDR.

#### Step 2 — Check every other rule in the group

```bash
GROUP_ID="${1:?security group id}"
REGION="${AWS_REGION:-us-east-1}"

OPEN="$(aws ec2 describe-security-group-rules --region "$REGION" \
         --filters "Name=group-id,Values=${GROUP_ID}" --output json 2>/dev/null \
       | jq -r '[.SecurityGroupRules[] | select(.IsEgress == false)
                 | select(.CidrIpv4 == "0.0.0.0/0" or .CidrIpv6 == "::/0")] | length')"
if [ "${OPEN:-0}" -eq 0 ]; then
  echo "[OK] no remaining ingress rule in $GROUP_ID is open to the internet"
else
  echo "[FAIL] $OPEN further open ingress rule(s) remain in $GROUP_ID — revoking one is not the fix"
fi
```

#### Step 3 — Contain the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 1 required}"

case "$PRINCIPAL" in
  *:user/*)
    U="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')"
    aws iam list-access-keys --user-name "$U" --query 'AccessKeyMetadata[].AccessKeyId' \
      --output text 2>/dev/null | tr '\t' '\n' | while read -r K; do
        [ -z "$K" ] && continue
        aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive \
          && echo "[OK] key $K deactivated"
      done
    ;;
  *:assumed-role/*)
    # Role name is the FIRST segment after `assumed-role/`; the second is the session name.
    R="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $1}')"
    echo "[!] assumed role: $R — existing session credentials remain valid until expiry."
    echo "    Save as revoke.json and attach with put-role-policy:"
    cat <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"}}}]}
JSON
    ;;
  *) echo "[!] unrecognised principal shape: $PRINCIPAL — contain manually" ;;
esac
```

#### Step 4 — Treat the instances behind the group as reached, until flow logs say otherwise

Query 3 decides this and it has three outcomes, not two. If flow logs show `ACCEPT` records to the
exposed port, the instances were reached and each is its own incident. If they show none, the port
was open and unused. If there are no flow logs, the answer is **unknown** — and that is what the
report should say, rather than "no evidence of access", which reads as a negative result when it is
an absent one.

---

## 4. Eradication

### Remove Attacker Access

#### Close the `ModifySecurityGroupRules` blind spot

This is the eradication step that generalises. The pack watches only the `Authorize` calls, so an
actor who narrows a rule for a review and widens it back afterwards leaves one event that nothing
inspects. Adding the rule is cheap; the alternative is a control that can be walked around by
editing rather than adding.

#### Sweep for the shapes the original rule could not see

Three populations exist that no `cidrIp`-based rule has ever surfaced, and they are worth enumerating
once rather than waiting for an event:

- rules opened to **`::/0`**, which the flat form cannot express at all;
- rules with **`IpProtocol: -1`**, which are open on every port with no port field;
- rules whose source is a **prefix list** containing `0.0.0.0/0`, where the rule names only the list.

#### Deny internet-facing management ports by SCP

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyOpeningManagementPortsToTheInternet",
  "Effect": "Deny",
  "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:ModifySecurityGroupRules"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": "arn:aws:iam::*:role/YourBreakGlassRole"}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. `YourBreakGlassRole` must
be a role that genuinely exists — an `ArnNotLike` against a non-existent role denies the action to
everyone including you. Note this denies **all** ingress authorisation outside that role, not only
management ports: an SCP condition cannot inspect a CIDR or a port inside `ipPermissions`, so
principal-scoping is the control actually available. Test in a non-production OU first.

#### Prefer a bastion or Session Manager to an open port

The durable fix is that nothing needs an internet-facing management port. AWS Systems Manager
Session Manager reaches an instance with no inbound rule at all, which removes the technique rather
than detecting it — and it makes the SCP above operationally survivable, because the legitimate
reason to open port 22 disappears.

---

## 5. Recovery

### Restore Clean State

#### Verify no ingress rule anywhere is open on a management port

```bash
REGION="${AWS_REGION:-us-east-1}"
FOUND=0

aws ec2 describe-security-group-rules --region "$REGION" --output json 2>/dev/null \
| jq -r '.SecurityGroupRules[]
    | select(.IsEgress == false)
    | select(.CidrIpv4 == "0.0.0.0/0" or .CidrIpv6 == "::/0")
    | select(.IpProtocol == "-1"
             or ((.FromPort // 0) <= 22   and (.ToPort // 0) >= 22)
             or ((.FromPort // 0) <= 3389 and (.ToPort // 0) >= 3389)
             or ((.FromPort // 0) <= 5985 and (.ToPort // 0) >= 5986))
    | "[FAIL] \(.GroupId) \(.SecurityGroupRuleId) \(.IpProtocol) \(.FromPort)-\(.ToPort) from \(.CidrIpv4 // .CidrIpv6)"' \
| tee /tmp/sg-open-mgmt.txt

[ -s /tmp/sg-open-mgmt.txt ] && FOUND=1
[ "$FOUND" -eq 0 ] && echo "[OK] no internet-facing management port in $REGION" \
                   || echo "[FAIL] see above — recovery is not complete"
```

The port test uses a **range** comparison rather than equality on purpose: a rule from 1 to 65535
contains 22 without `FromPort` ever equalling it, and that is exactly the shape a port-list match
misses.

#### Verify the exposure window was closed, and for how long it was open

```bash
GROUP_ID="${1:?security group id}"
OPEN_TIME="${2:?open timestamp}"
CLOSE_TIME="${3:?revoke timestamp}"

python3 - "$OPEN_TIME" "$CLOSE_TIME" <<'PY'
import sys, datetime
fmt = "%Y-%m-%dT%H:%M:%SZ"
try:
    a = datetime.datetime.strptime(sys.argv[1], fmt)
    b = datetime.datetime.strptime(sys.argv[2], fmt)
except ValueError:
    print("[!] timestamps must be ISO8601 like 2026-08-30T14:05:00Z"); raise SystemExit(1)
mins = int((b - a).total_seconds() // 60)
print("[OK] exposure window closed after %d minute(s)" % mins if mins >= 0
      else "[FAIL] close time precedes open time — check the inputs")
PY
echo "[!] Record this window in the report. It is the interval Query 3's flow-log search must cover,"
echo "    and it is the only thing that scopes 'was it used'."
```

#### Confirm the corrected detection fires

```bash
GROUP_ID="${1:?a NON-PRODUCTION security group id}"
REGION="${AWS_REGION:-us-east-1}"

# Exercise the STRUCTURED form with IPv6 — the shape the source rule cannot see at all, because the
# flat cidrIp field it reads cannot carry an IPv6 range. Port 9999 is used so nothing reachable is
# exposed even briefly.
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$GROUP_ID" \
  --ip-permissions 'IpProtocol=tcp,FromPort=9999,ToPort=9999,Ipv6Ranges=[{CidrIpv6=::/0}]' \
  && echo "[OK] ::/0 opened on 9999 — expect the open-to-internet rule within 15 min"

sleep 60
RID="$(aws ec2 describe-security-group-rules --region "$REGION" \
        --filters "Name=group-id,Values=${GROUP_ID}" --output json 2>/dev/null \
      | jq -r '.SecurityGroupRules[] | select(.CidrIpv6 == "::/0" and .FromPort == 9999)
               | .SecurityGroupRuleId' | head -1)"
[ -n "$RID" ] && aws ec2 revoke-security-group-ingress --region "$REGION" \
  --group-id "$GROUP_ID" --security-group-rule-ids "$RID" && echo "[OK] test rule revoked"
```

If nothing fires, the deployment is reading only the flat `cidrIp` field and the IPv6 half of this
use case is not covered.

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Was the request flat or structured? | If structured, the original rule could never have fired, and the finding is the detection gap rather than the change. |
| Was it IPv6? | The flat field cannot carry IPv6 at all, so `::/0` exposure was structurally invisible before this playbook. |
| Was `IpProtocol: -1` involved? | Then every port was open and no port-list rule would have matched, whatever ports it listed. |
| Did flow logs cover the window? | Decides whether "was it used" is answerable. If not, the honest verdict is unknown. |
| Was it `ModifySecurityGroupRules` rather than an `Authorize` call? | That path is unwatched in the source pack, and a rule can be widened without ever being added. |
| Was the rule opened and closed by the same principal? | A clean end state means no posture scan would ever show it — only the event history does. |

### Recommended Guardrails

**Read both request shapes.** This is the single change that decides whether the detection works at
all, and the flat-form counter in the KQL will tell you within one query which shape your estate
actually emits.

**Treat `IpProtocol: -1` as equivalent to opening every management port**, because it is. A port list
is a filter on a field that an all-protocols rule does not carry.

**Cover `ModifySecurityGroupRules`.** Otherwise the control watches additions and ignores edits.

**Enable VPC flow logs on anything with an internet-facing group.** The configuration event tells you
a port was open; only flow logs tell you whether it was reached, and they cannot be backfilled.

**Move management access to Session Manager.** It reaches an instance with no inbound rule at all,
which removes the legitimate reason to open port 22 and makes a principal-scoped SCP survivable.

### Technique Reference

**T1686.001 — Disable or Modify System Firewall: Cloud Firewall.** Verified live at
https://attack.mitre.org/techniques/T1686/001/ on 2026-08-30.

**T1133 — External Remote Services** is tagged on the remote-management rule: an internet-facing SSH
or RDP port is an external remote service whether or not it was intended as one. Verified live
2026-08-30.

The source rules carried **no** MITRE mapping.

AWS references relied on throughout, all verified 2026-08-30:

- `AuthorizeSecurityGroupIngress` — the two request shapes, the IPv6 restriction on the flat form,
  `IpProtocol: -1`, the unsupported-protocol behaviour, CIDR canonicalization, and the prefix-list
  and source-security-group source types:
  https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html
- `ModifySecurityGroupRules` — the edit path with no `Authorize` event:
  https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySecurityGroupRules.html

Service-wide verified behaviour shared by every `sg.*` playbook is in `../_ground-truth/sg.md`.

### Residual Risk

**Same-entry scoping is unresolvable at rule level.** A substring over the serialised
`ipPermissions` cannot bind a port to a CIDR within one permission entry, so a request mixing a
corporate-CIDR management rule with a public web rule matches. Parsing
`describe-security-group-rules`, which returns each rule as its own object, is the resolution — and
it is a triage step rather than a rule.

**Split CIDRs cover the internet without matching.** `0.0.0.0/1` plus `128.0.0.0/1` is exactly as
open as `0.0.0.0/0` and matches no test here. So is any sufficiently broad range. A prefix-length
threshold would catch it and would also fire on legitimate large ranges; neither choice is clean.

**Prefix lists hide their contents from the event.** A managed prefix list containing `0.0.0.0/0`
produces an ingress rule naming only the list ID. Resolving it needs
`GetManagedPrefixListEntries`, and a change to the *list* — which re-scopes every rule referencing
it — is a different event this playbook does not cover at all.

**Detection here is always after the fact.** AWS propagates rule changes *"as quickly as possible"*,
so there is no approval step and no window to intervene in. That is why the SCP and Session Manager
recommendations matter more than the rules do, and why the correlation on open-then-close exists —
it is the only way to see an exposure that has already been tidied away.
