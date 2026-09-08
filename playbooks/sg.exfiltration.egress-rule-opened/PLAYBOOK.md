# IR Playbook: Security Group Egress Re-Widened — outbound path restored via `AuthorizeSecurityGroupEgress`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Firewall weakening on the outbound path — an egress restriction that somebody deliberately applied is removed, restoring an unrestricted route out |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High when a narrowed group is re-widened; medium for a bare egress-open event, because unrestricted outbound is the **default** state of every security group. The source pack rates both rules as building blocks — that is, not at all. |
| MITRE Tactics | Defense Impairment; Exfiltration |
| MITRE Techniques | T1686.001 |
| Services in Scope | EC2 (security groups), VPC (flow logs), Route 53 Resolver, CloudTrail |

**What the technique does:** the actor restores an unrestricted outbound path. The important context
comes first, because it inverts the obvious reading — AWS: *"When you first create a security group,
it has an outbound rule that allows all outbound traffic from the resource. You can remove the rule
and add outbound rules that allow specific outbound traffic only. If your security group has no
outbound rules, no outbound traffic is allowed."*

So **open is where every security group starts**. An `AuthorizeSecurityGroupEgress` to `0.0.0.0/0`
is frequently tooling restating a state nobody removed. What matters is the *re-widening* of a group
that somebody deliberately narrowed, which exists only as a sequence: a revoke, then an authorize.

**Why the usual reflexes miss it.** The first is to rate an egress-open event highly, which produces
a stream of alerts about groups being returned to their birth configuration and gets the rule
switched off. The second is the opposite error the source pack makes — carrying both rules as
unrated building blocks, so the re-widening case has no output at all. The third is to look for an
event when the common finding is an **absence**: a group nobody ever hardened generates nothing. The
fourth is to assume an egress rule can restrict DNS; AWS states security groups cannot block requests
to the Route 53 Resolver.

**Detection thesis:** rate the sequence, not the event, and answer the unrestricted-by-default
population as a posture sweep rather than waiting for an alert that will never come.

**Adjacent playbooks.** The inbound half is `../sg.initial-access.remote-management-open/`. Outbound
traffic actually observed is `../netfw.unmapped.suspicious-low-throughput-egress/` and
`../route53dns.exfiltration.suspicious-query-with-base64-encoded-string/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. `AuthorizeSecurityGroupEgress` and
`RevokeSecurityGroupEgress` are management events, on by default.

**VPC flow logs on the subnets these groups protect.** The egress rule says a path exists; only flow
logs say whether anything left through it. They cannot be enabled retroactively for a window that
has already passed, and without them the exfiltration question is unanswerable rather than negative.

**A recorded list of the security groups with deliberately narrowed egress.** This is the
prerequisite that makes the whole use case work: since open is the default, a group is only
interesting if someone restricted it on purpose, and nothing in AWS records that intent.

Route 53 Resolver DNS Firewall, if DNS exfiltration is in scope. AWS: *"Security groups cannot block
DNS requests to or from the Route 53 Resolver."* No egress rule substitutes for it.

**Alerting (must be pre-configured)**

- **An egress rule revoked and an internet-facing one added on the same group by the same principal within 1h → P0**
- **The same sequence where the re-opened rule is `IpProtocol: -1` — a deliberate restriction removed entirely → P0**

**Response Tooling**

An IAM principal that can call `ec2 revoke-security-group-egress`, `authorize-security-group-egress`
and `describe-security-group-rules` outside the change pipeline, in every region.

Flow log query access by ENI and time range, for the window between the revoke and the re-open.

**Known IOC Baselines**

The roles that own network configuration, populating `known_provisioners`. Infrastructure applies
recreate default egress routinely, which is why the bare event is medium.

The expected outbound destinations per workload. Narrowing egress safely means knowing what the
workload legitimately talks to, and assembling that during an incident is what makes teams restore
the open rule instead.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | An egress rule revoked and an internet-facing one added on the same group by the same principal within 1h | Correlation rule | T1686.001 |
| P0 | The same sequence where the re-opened rule is `IpProtocol: -1` — a deliberate restriction removed entirely | Correlation rule | T1686.001 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | All-protocol egress opened to `0.0.0.0/0` or `::/0` on a group that already existed | CloudTrail | T1686.001 |
| P2 | `ModifySecurityGroupRules` changing an existing egress rule's destination — no `Authorize` event is produced | CloudTrail | T1686.001 |
| P2 | Egress opened to the internet with no prior revoke — usually a default being restated, and worth reading only against the group's history | CloudTrail | T1686.001 |

### Detection Rule Quality Notes

Both source rules are immediate queries and fully readable, so every row below is auditable against
`_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Both rules are building blocks — neither is rated | An unrestricted outbound path is the same class of finding as an open ingress rule, and the pack carries it as accounting with no output | The **sequence** is rated, not the event: a correlation at high, with the bare event at medium |
| The obvious correction would also be wrong | Rating an egress-open event highly produces alerts about groups being returned to their **default** state, because AWS creates every security group with an allow-all outbound rule. That rule gets switched off within a week | Medium for the event, and the verdict text says why, so a responder does not escalate a restored default |
| Neither rule is correlated with the other | A revoke followed by an authorize is a deliberate restriction being reversed; that is the only shape here that is unambiguous, and the pack has both halves and joins them nowhere | A `temporal_ordered` correlation over 1h, grouped by principal |
| The flat request form cannot express IPv6 | Same defect as the ingress rules: a rule reading `requestParameters.cidrIp` is IPv4-only by construction, and `::/0` is exactly as open | Both request shapes matched, both address families rated alike |
| No coverage of `ModifySecurityGroupRules` | It changes an existing rule's destination with no `Authorize` event | Noted in the query verdicts; the rule for it ships in `../sg.initial-access.remote-management-open/`, which owns that event |
| MITRE: none on both | | `T1686.001` |

**Recommended detection — the sequence, rated; the event, deliberately not.**

```yaml
# Security group egress re-widened to the internet (T1686.001)
#
# THE DEFAULT IS ALREADY FULLY OPEN OUTBOUND, WHICH INVERTS THE OBVIOUS READING.
# AWS: "When you first create a security group, it has an outbound rule that allows all outbound
# traffic from the resource. You can remove the rule and add outbound rules that allow specific
# outbound traffic only. If your security group has no outbound rules, no outbound traffic is
# allowed."
# So `AuthorizeSecurityGroupEgress` opening 0.0.0.0/0 is usually NOT a weakening — the group was
# born that way and most groups still are. The event that matters is the RE-WIDENING of a group
# somebody had deliberately narrowed, and that is only visible as a sequence: a revoke, then an
# authorize. The source pack ships both halves as unrated building blocks and correlates neither.
#
# THE ABSENCE OF A REVOKE IS THE POSTURE FINDING, AND NO EVENT WILL EVER CARRY IT.
# A group nobody ever hardened has unrestricted egress and generates no CloudTrail event at all,
# because nothing happened. That is a state question, answered by describe-security-group-rules in
# §2 of ../PLAYBOOK.md — not by any rule here, and not by any rule that could exist.
#
# TWO REQUEST SHAPES, SAME AS INGRESS. `AuthorizeSecurityGroupEgress` accepts flat top-level
# parameters or the structured `ipPermissions` array, and the flat form cannot express IPv6. Both
# are matched below. See ../../_ground-truth/sg.md §1.
#
# AND A CROSS-ACCOUNT REFERENCED GROUP PRODUCES NO EVENT FOR ITS OWNER.
# AWS: "When a referenced security group is owned by another account, the owner account does not
# receive CloudTrail events for these actions." So an egress rule pointing at a security group in
# another account is invisible to that account entirely. Stated as a gap, not closed.
title: Security group egress opened to the internet
id: 8b52f0d4-1e97-46a3-b70c-52e83a1d6f9b
name: sg_egress_opened_to_internet
status: experimental
description: >-
  AuthorizeSecurityGroupEgress added an outbound rule to 0.0.0.0/0 or ::/0. Rated medium rather than
  high on its own, because a newly created security group already allows all outbound traffic by
  default — so this event is frequently restoring a state that was never removed. It becomes a
  finding when it follows a revoke on the same group, which is the correlation below.
references:
  - https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupEgress.html
  - https://attack.mitre.org/techniques/T1686/001/
tags:
  - attack.defense-evasion
  - attack.exfiltration
  - attack.t1686.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'AuthorizeSecurityGroupEgress'
  success:
    errorCode: null
  # Sibling blocks — the flat form cannot carry IPv6, so both shapes must be read.
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
    An infrastructure apply recreating a group's default egress. Extremely common, which is why this
    rule is medium and why the correlation below carries the severity.
level: medium
---
title: Security group egress narrowed and then re-widened to the internet
id: 3c07e6b1-94da-4f28-8165-0b7e29ac54d3
status: experimental
description: >-
  A principal revoked an egress rule and then added an internet-facing one on the same group. This
  is the sequence that matters, because the default state is already open — a group only has
  restricted egress if somebody deliberately narrowed it, so re-widening it undoes a decision rather
  than restoring a default. Either half alone is ordinary; the pair is someone removing an outbound
  restriction that was put there on purpose.
references:
  - https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html
  - https://attack.mitre.org/techniques/T1686/001/
tags:
  - attack.defense-evasion
  - attack.exfiltration
  - attack.t1686.001
correlation:
  type: temporal_ordered
  rules:
    - sg_egress_revoked
    - sg_egress_opened_to_internet
  group-by:
    - userIdentity.arn
  timespan: 1h
falsepositives:
  - >-
    A rule being replaced rather than removed — narrowing a CIDR is a revoke followed by an
    authorize, and legitimately produces this pair. The distinguishing question is whether the new
    rule is WIDER than the old one, which §2 Query 1 answers by showing both.
level: high
---
title: Security group egress rule revoked
id: f1a4703c-58be-4d92-a06f-c37e91b5824a
name: sg_egress_revoked
status: experimental
description: >-
  Base rule — correlation component and change accounting, never for direct alerting. A successful
  RevokeSecurityGroupEgress. On its own this is outbound access being restricted, which is a good
  thing happening and is the only way a group stops allowing all outbound traffic.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RevokeSecurityGroupEgress.html
tags:
  - attack.defense-evasion
  - attack.t1686.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'RevokeSecurityGroupEgress'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: see the largest population of all. A security group nobody
ever hardened has unrestricted egress and generates no event, because nothing happened. §2 Query 3
answers that as a posture question; no rule can.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> Security group events are **regional** — run these in the region holding the group.

Run Query 1 first; it decides whether this is a restored default or a reversed decision.

#### Query 1 — Reconstruct: was this group ever narrowed

```bash
GROUP_ID="${1:?security group id from the alert}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-90d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '90 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in AuthorizeSecurityGroupEgress RevokeSecurityGroupEgress ModifySecurityGroupRules CreateSecurityGroup; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r --arg g "$GROUP_ID" '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | select((.requestParameters.groupId // .responseElements.groupId // "") == $g)
      | .requestParameters as $r
      | ($r.ipPermissions | tostring) as $perms
      # The flat cidrIp field cannot carry IPv6 — both shapes are read.
      | (($r.cidrIp // "") == "0.0.0.0/0" or ($perms | test("0\\.0\\.0\\.0/0"))) as $v4
      | (($r.cidrIp // "") == "::/0" or ($perms | test("::/0"))) as $v6
      | ((($r.ipProtocol // "") == "-1") or ($perms | test("\"ipProtocol\":\"-1\""))) as $allproto
      | "\(.eventTime)  \(.eventName)  " +
        "\(if $v4 or $v6 then "OPEN-TO-WORLD " else "" end)\(if $allproto then "ALL-PROTOCOLS " else "" end)" +
        " by=\(.userIdentity.arn)"'
done | sort
```

Read this as the group's whole life. A `CreateSecurityGroup` with no subsequent
`RevokeSecurityGroupEgress` means the group **has never had restricted egress** — the alerted event
restored a default and is a P3. A `Revoke` earlier in the timeline followed by the alerted
`Authorize` means a deliberate restriction was reversed, and that is the finding.

#### Query 2 — What the group's egress allows right now

```bash
GROUP_ID="${1:?security group id}"
REGION="${AWS_REGION:-us-east-1}"

aws ec2 describe-security-group-rules --region "$REGION" \
  --filters "Name=group-id,Values=${GROUP_ID}" --output json 2>/dev/null \
| jq -r '.SecurityGroupRules[]
    | select(.IsEgress == true)
    | (.CidrIpv4 // .CidrIpv6 // .ReferencedGroupInfo.GroupId // .PrefixListId // "?") as $dst
    | (if (.IpProtocol == "-1") then "ALL-PROTOCOLS" else "\(.IpProtocol) \(.FromPort)-\(.ToPort)" end) as $ports
    | (if (($dst == "0.0.0.0/0" or $dst == "::/0") and .IpProtocol == "-1")
       then "[!] DEFAULT-OPEN" elif ($dst == "0.0.0.0/0" or $dst == "::/0")
       then "[!] OPEN       " else "[ ]            " end) as $flag
    | "\($flag) \(.SecurityGroupRuleId)  \($ports)  to \($dst)  \(.Description // "")"'

echo
echo "[!] A DEFAULT-OPEN row is the rule AWS creates with every security group. Its presence is not"
echo "    evidence of tampering — its ABSENCE is what makes a group interesting, and its return"
echo "    after an absence is the finding."
```

#### Query 3 — The population no alert will ever surface

```bash
REGION="${AWS_REGION:-us-east-1}"

# A group nobody ever hardened generates no event, because nothing happened. This is the posture
# question, and in most estates it finds far more unrestricted egress than any rule will.
TOTAL=0; OPEN=0
for G in $(aws ec2 describe-security-groups --region "$REGION" \
            --query 'SecurityGroups[].GroupId' --output text 2>/dev/null | tr '\t' '\n'); do
  [ -z "$G" ] && continue
  TOTAL=$((TOTAL + 1))
  N="$(aws ec2 describe-security-group-rules --region "$REGION" \
        --filters "Name=group-id,Values=${G}" --output json 2>/dev/null \
      | jq -r '[.SecurityGroupRules[] | select(.IsEgress == true)
                | select((.CidrIpv4 == "0.0.0.0/0" or .CidrIpv6 == "::/0") and .IpProtocol == "-1")] | length')"
  if [ "${N:-0}" -gt 0 ]; then
    OPEN=$((OPEN + 1)); echo "[!] $G — unrestricted egress (default rule never removed)"
  fi
done
echo
echo "[i] $OPEN of $TOTAL security groups in $REGION allow all outbound traffic."
echo "    This is the baseline, not an incident. Narrowing it is a project; knowing the number is"
echo "    what makes the alerts in this directory meaningful."
```

#### Query 4 — Did anything leave through the path

```bash
GROUP_ID="${1:?security group id}"
WINDOW_START="${2:?timestamp the path was opened}"
REGION="${AWS_REGION:-us-east-1}"

ENIS="$(aws ec2 describe-network-interfaces --region "$REGION" \
         --filters "Name=group-id,Values=${GROUP_ID}" \
         --query 'NetworkInterfaces[].NetworkInterfaceId' --output text 2>/dev/null)"
echo "Interfaces in this group: ${ENIS:-none}"

LG="$(aws ec2 describe-flow-logs --region "$REGION" \
       --query 'FlowLogs[?LogDestinationType==`cloud-watch-logs`].LogGroupName | [0]' \
       --output text 2>/dev/null)"
if [ -z "$LG" ] || [ "$LG" = "None" ]; then
  echo "[FAIL] no CloudWatch flow log destination — whether anything left is UNANSWERABLE."
  echo "       Record that as unknown rather than as 'no evidence of exfiltration'."
else
  echo "[OK] flow logs in $LG — query outbound ACCEPT records from these interfaces since"
  echo "     $WINDOW_START, sorted by bytes:"
  echo "     fields @timestamp, srcAddr, dstAddr, dstPort, bytes | filter action=\"ACCEPT\""
  echo "     | sort bytes desc"
fi

echo
echo "[!] DNS is excluded from this analysis by design: security groups cannot block requests to the"
echo "    Route 53 Resolver, so no egress rule ever restricted it and its absence here proves nothing."
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Containment here is genuinely riskier than on the ingress side, because removing outbound access
breaks workloads that need it. Establish first whether the group was ever narrowed — if it was not,
there is no restriction to restore and the correct action is a change request, not an incident
response.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 1 shows a revoke
followed by the alerted authorize, a deliberate restriction was reversed. Restore it, and accept that
whatever motivated the reversal may break — that is the safer failure.

#### Step 1 — Restore the narrowed rule, if there was one

```bash
GROUP_ID="${1:?security group id}"
RULE_ID="${2:?the rule id of the re-opened rule, from Query 2}"
REGION="${AWS_REGION:-us-east-1}"

aws ec2 describe-security-group-rules --region "$REGION" \
  --security-group-rule-ids "$RULE_ID" --output json \
  > "./evidence-${GROUP_ID}-${RULE_ID}.json" 2>/dev/null \
  && echo "[OK] rule preserved at ./evidence-${GROUP_ID}-${RULE_ID}.json"

echo "[!] Before revoking, confirm from Query 1 what the egress rules were BEFORE the re-opening."
echo "    Removing this rule without restoring the narrower ones leaves the group with NO egress"
echo "    rules at all — AWS: 'If your security group has no outbound rules, no outbound traffic is"
echo "    allowed.' That is a full outbound outage for every instance in the group."

read -r -p "Revoke $RULE_ID from $GROUP_ID? [y/N] " ANS
[ "$ANS" = "y" ] && aws ec2 revoke-security-group-egress --region "$REGION" \
  --group-id "$GROUP_ID" --security-group-rule-ids "$RULE_ID" \
  && echo "[OK] revoked — now re-add the narrower rules from Query 1's history"
```

The prompt and the warning are the point of this step. On the ingress side revoking is close to
free; here it can take a workload offline, and the failure mode is silent until something times out.

#### Step 2 — Re-add the intended destinations

```bash
GROUP_ID="${1:?security group id}"
REGION="${AWS_REGION:-us-east-1}"
DEST_CIDR="${2:?the destination the workload legitimately needs}"
PORT="${3:-443}"

aws ec2 authorize-security-group-egress --region "$REGION" --group-id "$GROUP_ID" \
  --ip-permissions "IpProtocol=tcp,FromPort=${PORT},ToPort=${PORT},IpRanges=[{CidrIp=${DEST_CIDR},Description=restored-after-incident}]" \
  && echo "[OK] egress to ${DEST_CIDR}:${PORT} restored on $GROUP_ID"

aws ec2 describe-security-group-rules --region "$REGION" \
  --filters "Name=group-id,Values=${GROUP_ID}" --output json 2>/dev/null \
| jq -r '[.SecurityGroupRules[] | select(.IsEgress == true)] | length as $n
         | if $n == 0 then "[FAIL] NO egress rules — all outbound traffic is now blocked"
           else "[OK] \($n) egress rule(s) in place" end'
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

#### Step 4 — Scope the exfiltration question honestly

Query 4 has three outcomes and only one of them is "nothing left". If flow logs cover the window and
show no outbound `ACCEPT` to an unexpected destination, the path was open and unused. If they show
volume, each destination is its own investigation. If there are no flow logs, the answer is
**unknown** — and DNS is excluded from all three, because security groups never restricted it.

---

## 4. Eradication

### Remove Attacker Access

#### Treat the default-open population as the real work

Query 3 gives the number. In most estates it is most of the groups, and every one of them is an
unrestricted outbound path that no alert in this directory will ever fire on. Narrowing them is a
project rather than an incident action, but the number belongs in the report — it is the context that
makes a single re-widening event meaningful or trivial.

#### Record which groups have deliberately narrowed egress

The entire use case rests on distinguishing a restored default from a reversed decision, and AWS
records no intent. A tag or an inventory entry marking "egress deliberately restricted" turns that
triage step from a CloudTrail archaeology exercise into a lookup.

#### Use Route 53 Resolver DNS Firewall for the path security groups cannot reach

AWS: *"Security groups cannot block DNS requests to or from the Route 53 Resolver."* An estate that
has narrowed egress everywhere still has an unrestricted DNS channel, and no work in this directory
changes that.

#### Deny egress authorisation outside the provisioning path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyEgressWidening",
  "Effect": "Deny",
  "Action": ["ec2:AuthorizeSecurityGroupEgress", "ec2:ModifySecurityGroupRules"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourProvisioningRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the pipeline. Note the condition cannot inspect the CIDR inside `ipPermissions`,
so this denies all egress authorisation outside those roles rather than only the internet-facing
kind. Test in a non-production OU first.

---

## 5. Recovery

### Restore Clean State

#### Verify the group's egress matches its intended destinations

```bash
GROUP_ID="${1:?security group id}"
REGION="${AWS_REGION:-us-east-1}"

N="$(aws ec2 describe-security-group-rules --region "$REGION" \
      --filters "Name=group-id,Values=${GROUP_ID}" --output json 2>/dev/null \
    | jq -r '[.SecurityGroupRules[] | select(.IsEgress == true)] | length')"
OPEN="$(aws ec2 describe-security-group-rules --region "$REGION" \
         --filters "Name=group-id,Values=${GROUP_ID}" --output json 2>/dev/null \
       | jq -r '[.SecurityGroupRules[] | select(.IsEgress == true)
                 | select((.CidrIpv4 == "0.0.0.0/0" or .CidrIpv6 == "::/0") and .IpProtocol == "-1")] | length')"

if [ "${N:-0}" -eq 0 ]; then
  echo "[FAIL] $GROUP_ID has NO egress rules — all outbound traffic is blocked, which is an outage"
elif [ "${OPEN:-0}" -gt 0 ]; then
  echo "[FAIL] $GROUP_ID still has an unrestricted egress rule"
else
  echo "[OK] $GROUP_ID has $N scoped egress rule(s) and none open to the internet"
fi
```

The zero-rules branch is a real failure state and it is easy to reach: revoking the re-opened rule
without re-adding the narrower ones leaves the group blocking all outbound traffic, which presents as
a workload outage rather than as a security finding.

#### Verify from the workload's side, not only the configuration

```bash
GROUP_ID="${1:?security group id}"
REGION="${AWS_REGION:-us-east-1}"

# A correct rule set that breaks the application is not recovery. Confirm the instances behind the
# group are still reaching what they need before closing.
aws ec2 describe-network-interfaces --region "$REGION" \
  --filters "Name=group-id,Values=${GROUP_ID}" \
  --query 'NetworkInterfaces[].[NetworkInterfaceId,Attachment.InstanceId,Description]' \
  --output text 2>/dev/null | sed 's/^/  /'
echo "[!] Confirm with the owning team that these workloads are healthy. An egress restriction fails"
echo "    silently and shows up as timeouts, often minutes to hours later."
```

#### Confirm the corrected detection fires

```bash
GROUP_ID="${1:?a NON-PRODUCTION security group id}"
REGION="${AWS_REGION:-us-east-1}"

# Exercise the SEQUENCE, which is the routable output — a bare open would only produce the medium
# event rule. A scoped rule is added and removed, so the group's real egress is never widened.
aws ec2 authorize-security-group-egress --region "$REGION" --group-id "$GROUP_ID" \
  --ip-permissions 'IpProtocol=tcp,FromPort=9999,ToPort=9999,IpRanges=[{CidrIp=192.0.2.0/24}]' \
  >/dev/null 2>&1 && echo "[OK] scoped test rule added"

RID="$(aws ec2 describe-security-group-rules --region "$REGION" \
        --filters "Name=group-id,Values=${GROUP_ID}" --output json 2>/dev/null \
      | jq -r '.SecurityGroupRules[] | select(.IsEgress == true and .FromPort == 9999)
               | .SecurityGroupRuleId' | head -1)"
[ -n "$RID" ] && aws ec2 revoke-security-group-egress --region "$REGION" \
  --group-id "$GROUP_ID" --security-group-rule-ids "$RID" >/dev/null 2>&1 \
  && echo "[OK] revoked — now re-open to the internet to complete the sequence"

aws ec2 authorize-security-group-egress --region "$REGION" --group-id "$GROUP_ID" \
  --ip-permissions 'IpProtocol=tcp,FromPort=9999,ToPort=9999,IpRanges=[{CidrIp=0.0.0.0/0}]' \
  >/dev/null 2>&1 && echo "[OK] re-widened — expect the HIGH correlation, not the medium event rule"

sleep 60
RID2="$(aws ec2 describe-security-group-rules --region "$REGION" \
         --filters "Name=group-id,Values=${GROUP_ID}" --output json 2>/dev/null \
       | jq -r '.SecurityGroupRules[] | select(.IsEgress == true and .FromPort == 9999)
                | .SecurityGroupRuleId' | head -1)"
[ -n "$RID2" ] && aws ec2 revoke-security-group-egress --region "$REGION" \
  --group-id "$GROUP_ID" --security-group-rule-ids "$RID2" && echo "[OK] test rule removed"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Had this group's egress ever been narrowed? | If not, the alerted event restored a default and is not an incident. This is the first and cheapest question. |
| Was there a revoke before the authorize? | That is the reversal shape, and it is the only unambiguous one available. |
| Did flow logs cover the window? | Decides whether "did anything leave" is answerable. If not, the verdict is unknown. |
| How many groups in the account have unrestricted egress? | Query 3's number is the context. A single re-widening means something different in an estate where 5% are open than in one where 90% are. |
| Was the restriction restored, or was the rule simply removed? | Removing the re-opened rule without re-adding the narrower ones blocks all outbound traffic — an outage that looks like success in the configuration. |
| Is DNS covered by anything? | Security groups never restricted it, so an otherwise-tight egress posture still has an open DNS channel. |

### Recommended Guardrails

**Record which groups have deliberately narrowed egress.** The whole use case turns on distinguishing
a restored default from a reversed decision, and AWS stores no intent. A tag makes the triage a
lookup instead of a CloudTrail investigation.

**Rate the sequence, not the event.** Rating egress-open highly generates alerts about groups
returning to their birth state and will be switched off. The revoke-then-authorize pair is the
signal.

**Narrow egress as a programme, not an incident response.** Query 3 will find most of the estate
open. That is a baseline to work down deliberately, and treating each instance as an alert is the
wrong shape.

**Add Route 53 Resolver DNS Firewall.** Security groups cannot restrict DNS to the resolver at all,
so an estate with perfect egress rules still has that channel open.

**Never revoke without restoring.** A group with zero egress rules blocks all outbound traffic. That
failure is silent and presents as an application outage rather than as a security action.

### Technique Reference

**T1686.001 — Disable or Modify System Firewall: Cloud Firewall.** Verified live at
https://attack.mitre.org/techniques/T1686/001/ on 2026-08-30. Both source rules carried **no** MITRE
mapping and were shipped as building blocks.

AWS references relied on throughout, all verified 2026-08-30:

- Security group rules — the default allow-all outbound rule, the consequence of having no outbound
  rules, the DNS-resolver limitation, and the cross-account referenced-group behaviour:
  https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html
- `AuthorizeSecurityGroupEgress`:
  https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupEgress.html

Service-wide verified behaviour shared by every `sg.*` playbook is in `../_ground-truth/sg.md`.

### Residual Risk

**The default-open population is invisible to every rule here.** A group nobody hardened produces no
event. That is the majority case in most estates and it is a posture problem, not a detection one —
Query 3 is the only thing that surfaces it, and it has to be run rather than waited for.

**DNS cannot be restricted by a security group at all.** AWS is explicit. An estate that has narrowed
every egress rule still has an unrestricted channel to the Route 53 Resolver, and DNS-based
exfiltration is entirely outside what this playbook can influence.

**A cross-account referenced group produces no event for its owner.** AWS: *"When a referenced
security group is owned by another account, the owner account does not receive CloudTrail events for
these actions."* An egress rule pointing at a group in another account is invisible to that account.

**Flow logs answer "did anything leave", and they are frequently absent.** Without them the outbound
question has no answer, and the honest report says unknown. Enabling them afterwards does not cover
the window that mattered.
