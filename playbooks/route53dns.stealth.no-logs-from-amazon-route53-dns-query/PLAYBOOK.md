# IR Playbook: Resolver Query Logging Stopped — `DisassociateResolverQueryLogConfig` and its neighbours

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment (the only record of DNS activity inside a VPC stops, along with the DNS Firewall verdicts recorded in it) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. VPC flow logs explicitly do not capture queries to the Amazon DNS server, so there is **no second source** for this traffic. Losing it takes every `route53dns.*` detection and every GuardDuty DNS finding with it, and their subsequent silence carries no information. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | Route 53 Resolver, Route 53 Resolver DNS Firewall, VPC, GuardDuty, CloudWatch Logs, S3, CloudTrail |

**What the technique does:** three paths, and the quietest is the most likely.
`DisassociateResolverQueryLogConfig` removes one VPC from a logging configuration — the
configuration survives, every other VPC keeps logging, and only the named VPC goes dark.
`DeleteResolverQueryLogConfig` removes the configuration outright, taking every VPC with it. Or
`DisassociateFirewallRuleGroup` removes DNS Firewall, which stops the blocking *and* empties the
only fields in the query log that state a verdict.

**Why the usual reflexes miss it.** The reflex is an absence alert, and this telemetry is
unusually bad ground for one. Logging is opt-in per VPC, so a VPC that never had it looks exactly
like one just silenced. Only unique queries are logged, so a VPC with a small stable set of
destinations legitimately produces almost nothing once its caches are warm. And AWS ships an
`is_delayed` flag precisely because delivery delay is a normal state with no published maximum. An
account-wide record count, which is what the source rule uses, moves barely at all when one VPC
goes dark.

**Detection thesis:** the control-plane event names the VPC, which is the unit that matters and the
one absence cannot identify. Keep the absence view grouped per VPC as a corroborator, and pair both
with a scheduled read of association state — because the failure mode where an association exists
and delivers nothing produces no event at all.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail management events for `route53resolver.amazonaws.com`**, covering the query-log and
  the DNS Firewall families.
- **A scheduled `list-resolver-query-log-config-associations` snapshot**, stored with history,
  capturing `Status` and `ResourceId` per association. This is the only way to find an association
  that exists and is not delivering — **no CloudTrail event marks the moment delivery starts
  failing**, because nothing is called.
- **A scheduled inventory of VPCs without an association at all.** Coverage is opt-in per VPC, so
  this is a standing question rather than a one-time setup.
- **The log destination in a separate account** where the workload account cannot modify the bucket
  policy or log group, so stopping the logging and destroying it require different access.

**Alerting (must be pre-configured)**
- **`DisassociateResolverQueryLogConfig` by a principal outside the provisioning allowlist → P0**
- **`DeleteResolverQueryLogConfig` by a principal outside the provisioning allowlist → P0**
- **`DisassociateFirewallRuleGroup` or `DeleteFirewallRuleGroup` → P0**
- **`DeleteFirewallRule` or `UpdateFirewallRuleGroupAssociation` changing priority → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- The query log configuration ID and the DNS Firewall rule group ID for the estate, written down.
  Re-associating during an incident from memory is how a VPC gets attached to the wrong one.

**Known IOC Baselines**
- Which roles legitimately manage Resolver configuration — one infrastructure role.
- The full map of VPC to query-log-configuration to firewall-rule-group, from the scheduled
  snapshot. Without it, "which VPC lost coverage" is unanswerable after the fact.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `DisassociateResolverQueryLogConfig` succeeded, principal outside the provisioning allowlist | CloudTrail (`route53resolver`) | T1685.002 |
| P0 | `DeleteResolverQueryLogConfig` succeeded, principal outside the provisioning allowlist | CloudTrail (`route53resolver`) | T1685.002 |
| P0 | `DisassociateFirewallRuleGroup` or `DeleteFirewallRuleGroup` succeeded | CloudTrail (`route53resolver`) | T1685.002 |
| P1 | `DeleteFirewallRule`, or `UpdateFirewallRuleGroupAssociation` changing priority | CloudTrail (`route53resolver`) | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | An association whose `Status` is not `ACTIVE` in the scheduled state sweep | `list-resolver-query-log-config-associations` | T1685.002 |
| P2 | A VPC with no query log association at all | State sweep against `describe-vpcs` | T1685.002 |
| P3 | No query records from a specific `vpc_id` for four hours — corroborating only, never the alert | Resolver query logs (per VPC) | T1685.002 |

### Detection Rule Quality Notes

The source rule counts records over four hours grouped by the ingestion pipeline's own labels, so
every row below is auditable against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Grouped by the ingestion pipeline's application and subsystem labels | Tells you a shipper went quiet and never which **VPC** stopped being logged. Query logging is configured and associated per VPC, so the VPC is the only useful unit and it is exactly the one the rule cannot name | Detect on the control-plane events, which carry the VPC in `resourceId`. Where absence is kept, group by `vpc_id` |
| Watches only for records stopping account-wide | `DisassociateResolverQueryLogConfig` removes one VPC while the configuration survives and every other VPC keeps logging. The account-wide count barely moves — and this is the most likely form of the technique | A dedicated rule on disassociation, at the same level as deletion |
| Absence used on telemetry where low volume is normal | AWS logs *"only unique queries, not queries that VPC Resolver is able to respond to from the cache"*. A VPC with a small stable set of destinations produces almost nothing once warm, so the rule fires on healthy VPCs | Absence demoted to a P3 corroborator, with the caching rule stated wherever a count appears |
| No account of opt-in coverage | Logging is opt-in per VPC and association is a separate step from creation. A VPC never associated has always produced nothing and is indistinguishable from one just silenced | A state sweep for VPCs with no association, shipped as its own P2 trigger |
| Four-hour window against a documented delay flag | `additional_properties.is_delayed` exists precisely because delivery delay is a normal state, and AWS publishes no maximum. A gap is never conclusive in either direction | Window kept for the corroborating view only and explicitly not treated as conclusive |
| No coverage of DNS Firewall | Removing the rule group stops the blocking **and** empties the only fields in the query log that state a verdict. Afterwards an empty `firewall_rule_action` correctly means "no match" and reads like "allowed" | Three firewall events shipped alongside, with the semantics of the empty field stated in the rule |

**Recommended detection — the control-plane acts, including the one that leaves everything looking healthy.**

```yaml
# Route 53 Resolver query logging stopped (T1685.002)
#
# THE SOURCE RULE GROUPS BY THE INGESTION PLATFORM'S OWN LABELS, NOT BY AN AWS RESOURCE. Its
# group_by is the log pipeline's application and subsystem names, so it can tell you that records
# stopped arriving from a shipper — and never which VPC stopped being logged. Resolver query
# logging is configured per VPC, so the resource that went dark is the only useful unit and it is
# the one the rule cannot name.
#
# THREE PROPERTIES OF THIS TELEMETRY MAKE AN ABSENCE RULE WEAK, EACH DOCUMENTED BY AWS:
#
#   1. LOGGING IS OPT-IN PER VPC, AND ASSOCIATION IS A SEPARATE STEP FROM CREATION. A query log
#      configuration is created once and then ASSOCIATED with each VPC. A VPC that was never
#      associated produces nothing at all, which is indistinguishable from one whose association
#      was removed — and only one of those is an incident.
#   2. ONLY UNIQUE QUERIES ARE LOGGED. "VPC Resolver query logging logs only unique queries, not
#      queries that VPC Resolver is able to respond to from the cache." A VPC with a small, stable
#      set of destinations legitimately produces very few records once its caches are warm, so low
#      volume is a normal state rather than a fault.
#   3. DELIVERY DELAY IS A DOCUMENTED STATE. additional_properties carries `is_delayed` — "If there
#      is a delay in delivering the logs" — with no published maximum. A gap is therefore never
#      conclusive on its own.
#
# AND THE COMMON CASE IS DISASSOCIATION, NOT DELETION. DisassociateResolverQueryLogConfig stops one
# VPC's logging while the configuration itself survives, so a rule watching only
# DeleteResolverQueryLogConfig misses the surgical version of this entirely — the one that leaves
# every other VPC logging and the console showing a healthy configuration.
title: Resolver query log configuration disassociated from a VPC
id: 2c9f4b71-6d08-4e35-a917-83e04c2f65db
name: r53resolver_query_log_disassociated
status: experimental
description: >-
  DisassociateResolverQueryLogConfig removed a VPC from a query logging configuration. This is the
  surgical form of the technique and the one an account-wide absence rule cannot see: the
  configuration still exists, every other VPC keeps logging, and the console shows a healthy
  resource. Only the named VPC goes dark. It is also the AWS event that identifies which VPC — the
  question the source rule's grouping structurally cannot answer.
references:
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logging-configurations-managing.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53resolver.amazonaws.com'
    eventName: 'DisassociateResolverQueryLogConfig'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the infrastructure-as-code roles that own Resolver
  # configuration. An empty list reports every disassociation once, which is how the list is built.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    A VPC being decommissioned. Real, and it should be visible — a disassociation with no
    corresponding VPC deletion shortly afterwards is the finding.
level: high
---
title: Resolver query log configuration deleted
id: 8e51a2c6-4703-4b9d-86f2-1c790de35b48
name: r53resolver_query_log_deleted
status: experimental
description: >-
  DeleteResolverQueryLogConfig removed a query logging configuration outright, taking every VPC
  associated with it. Louder than disassociation and correspondingly rarer. Note that AWS requires
  associations to be removed before a configuration can be deleted, so this event is usually
  preceded by one or more DisassociateResolverQueryLogConfig calls — which means the rule above
  fires first, and a deletion arriving without those preceding events is worth reading closely.
references:
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logging-configurations-managing.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53resolver.amazonaws.com'
    eventName: 'DeleteResolverQueryLogConfig'
  success:
    errorCode: null
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    Consolidating several configurations into one. Legitimate, and it should be accompanied by
    fresh associations for every affected VPC within minutes.
level: high
---
title: DNS Firewall protection removed from a VPC
id: 4a08c73e-91b5-42f0-b8d6-57e21649ac30
name: r53resolver_firewall_disassociated
status: experimental
description: >-
  DisassociateFirewallRuleGroup or DeleteFirewallRule removed DNS Firewall coverage. This is the
  companion to losing the logs and it is worse in one specific way: the firewall fields in the
  query log are the only place AWS states a verdict, so removing the rule group both stops the
  blocking and empties the field that would have shown it. An analyst reading an empty
  firewall_rule_action afterwards sees "no match", which is true and reads like "allowed".
references:
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-rule-groups.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53resolver.amazonaws.com'
    eventName:
      - 'DisassociateFirewallRuleGroup'
      - 'DeleteFirewallRule'
      - 'DeleteFirewallRuleGroup'
      - 'UpdateFirewallRuleGroupAssociation'
  success:
    errorCode: null
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    Rule group priority changes during tuning, which arrive as UpdateFirewallRuleGroupAssociation.
    Common enough to be worth reading rather than muting — a priority change can move a permissive
    group in front of a blocking one without deleting anything.
level: medium
```

What this set structurally cannot do: it cannot detect an association that exists and stops
delivering. Nothing is called at that moment, so no event exists — Query 2 and the scheduled state
read are the only things that find it.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log
> platform for busy windows. Resolver configuration is regional: run every query in every Region
> that holds a VPC.

#### Query 1 — Reconstruct: every Resolver configuration change, in order

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in CreateResolverQueryLogConfig DeleteResolverQueryLogConfig \
          AssociateResolverQueryLogConfig DisassociateResolverQueryLogConfig \
          AssociateFirewallRuleGroup DisassociateFirewallRuleGroup \
          DeleteFirewallRule UpdateFirewallRuleGroupAssociation; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       config: (.requestParameters.resolverQueryLogConfigId // .requestParameters.firewallRuleGroupId // "-"),
       resource: (.requestParameters.resourceId // .requestParameters.vpcId // "-"),
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'sort_by(.time)'
```

Read the pairs. A `Disassociate` followed within minutes by an `Associate` for the same
`resource` is ordinary maintenance. A `Disassociate` with no matching `Associate` is the finding,
and the `resource` field names the VPC that has been dark since. AWS requires associations to be
removed before a configuration can be deleted, so a `Delete` should be preceded by
`Disassociate` events — one arriving without them is worth reading closely.

#### Query 2 — Sweep: coverage state, which no log carries

```bash
REGION="us-east-1"

echo "== associations and their status =="
aws route53resolver list-resolver-query-log-config-associations --region "$REGION" --output json | \
  jq -r '.ResolverQueryLogConfigAssociations[] |
    "\(if .Status == "ACTIVE" then "[OK]  " else "[FAIL]" end) vpc=\(.ResourceId) config=\(.ResolverQueryLogConfigId) status=\(.Status) error=\(.Error // "none") msg=\(.ErrorMessage // "-")"'

echo
echo "== every VPC, and whether anything logs it =="
COVERED=$(aws route53resolver list-resolver-query-log-config-associations --region "$REGION" \
  --output json | jq -r '[.ResolverQueryLogConfigAssociations[] | select(.Status == "ACTIVE") | .ResourceId] | unique | .[]')
for V in $(aws ec2 describe-vpcs --region "$REGION" --output json | jq -r '.Vpcs[].VpcId'); do
  echo "$COVERED" | grep -qx "$V" && echo "[OK]   $V logged" \
                                  || echo "[FAIL] $V has NO active query log association"
done

echo
echo "== DNS Firewall coverage =="
FW=$(aws route53resolver list-firewall-rule-group-associations --region "$REGION" --output json | \
     jq -r '[.FirewallRuleGroupAssociations[] | select(.Status == "COMPLETE") | .VpcId] | unique | .[]')
for V in $(aws ec2 describe-vpcs --region "$REGION" --output json | jq -r '.Vpcs[].VpcId'); do
  echo "$FW" | grep -qx "$V" && echo "[OK]   $V has DNS Firewall" \
                             || echo "[!]    $V has no DNS Firewall rule group"
done
```

The first block finds an association that exists and is failing — the state with no CloudTrail
event behind it. The second answers the question the absence rule cannot: a VPC that was never
associated looks identical in the logs to one just disassociated, and only this separates them.

#### Query 3 — Inspect: is the destination still writable

```bash
REGION="us-east-1"
CONFIG_ID="<config-id-from-Query-2>"

DEST=$(aws route53resolver get-resolver-query-log-config --resolver-query-log-config-id "$CONFIG_ID" \
  --region "$REGION" --output json | jq -r '.ResolverQueryLogConfig.DestinationArn')
echo "[i] destination: $DEST"

case "$DEST" in
  arn:aws:logs:*)
    GROUP="${DEST##*log-group:}"; GROUP="${GROUP%%:*}"
    aws logs describe-log-groups --log-group-name-prefix "$GROUP" --region "$REGION" --output json | \
      jq -r '.logGroups[] | "[i] \(.logGroupName) retention=\(.retentionInDays // "NeverExpire") stored=\(.storedBytes)"' \
      || echo "[FAIL] log group not found — the configuration points at a destination that no longer exists" ;;
  arn:aws:s3:*)
    BUCKET="${DEST#arn:aws:s3:::}"; BUCKET="${BUCKET%%/*}"
    aws s3api list-objects-v2 --bucket "$BUCKET" --max-items 3 --region "$REGION" \
      --query 'reverse(sort_by(Contents,&LastModified))[:3].[Key,LastModified]' --output text 2>/dev/null \
      || echo "[FAIL] cannot list $BUCKET — deleted, or the policy no longer permits delivery" ;;
  *) echo "[i] Firehose or other destination — check the delivery stream's own error metrics" ;;
esac
```

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

Turning off DNS logging is preparation. Its value in an investigation is as a timestamp that
brackets what the same principal did next — and given the technique this most often precedes is DNS
tunnelling, the queries immediately before the disassociation are worth as much as the ones after.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore coverage first. Unlike most telemetry there is no fallback source — VPC flow logs
explicitly exclude queries to the Amazon DNS server — so every minute uncovered is DNS activity
that was never recorded anywhere.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being investigated.

#### Step 1 — Re-associate the VPC with the logging configuration

```bash
REGION="us-east-1"
CONFIG_ID="<query-log-config-id>"
VPC_ID="<vpc-from-Query-1>"

EXISTING=$(aws route53resolver list-resolver-query-log-config-associations --region "$REGION" \
  --output json | jq -r --arg v "$VPC_ID" \
  '[.ResolverQueryLogConfigAssociations[] | select(.ResourceId == $v and .Status == "ACTIVE")] | length')

if [ "$EXISTING" -gt 0 ]; then
  echo "[i] $VPC_ID already has an active association — check Query 2 for its status and destination"
else
  aws route53resolver associate-resolver-query-log-config \
    --resolver-query-log-config-id "$CONFIG_ID" --resource-id "$VPC_ID" --region "$REGION" \
    --output json | jq -r '"[OK] association \(.ResolverQueryLogConfigAssociation.Id) status=\(.ResolverQueryLogConfigAssociation.Status)"'
fi
```

#### Step 2 — Restore DNS Firewall, if it was removed

```bash
REGION="us-east-1"
RULE_GROUP_ID="<firewall-rule-group-id>"
VPC_ID="<vpc-from-Query-1>"

FW=$(aws route53resolver list-firewall-rule-group-associations --region "$REGION" --output json | \
  jq -r --arg v "$VPC_ID" '[.FirewallRuleGroupAssociations[] | select(.VpcId == $v and .Status == "COMPLETE")] | length')
if [ "$FW" -gt 0 ]; then
  echo "[OK] $VPC_ID already has an active rule group association"
else
  aws route53resolver associate-firewall-rule-group \
    --firewall-rule-group-id "$RULE_GROUP_ID" --vpc-id "$VPC_ID" \
    --priority 101 --name "ir-restore-$(date -u +%Y%m%d)" --region "$REGION" \
    --output json | jq -r '"[OK] \(.FirewallRuleGroupAssociation.Name) status=\(.FirewallRuleGroupAssociation.Status)"'
fi
echo "[i] Priority matters: a lower number evaluates first. Confirm no permissive group sits in"
echo "    front of this one — moving priority achieves the same result as deleting a rule."
```

#### Step 3 — Confirm records are actually arriving

```bash
REGION="us-east-1"
VPC_ID="<vpc-from-Query-1>"

echo "[i] Association status ACTIVE is not delivery. Generate a unique lookup from a host in the"
echo "    VPC — a name nothing has resolved before, so it cannot be answered from cache — then"
echo "    confirm the record appears. AWS logs only unique queries, so a repeat of a warm name"
echo "    proves nothing."
echo "[i] Then confirm the destination received it, with Query 3."
```

This step is written as instruction rather than as a command because the verification requires
generating traffic inside the VPC, which the responder's break-glass credentials may not be able to
do directly. The caching rule makes the choice of test name load-bearing: a name already in cache
produces no record even on a perfectly healthy configuration.

#### Step 4 — Size the gap, and contain the principal

The window from the disassociation in Query 1 to the confirmed delivery in Step 3 is DNS activity
that was never recorded anywhere — there is no second source. Write the exact interval into the
incident and mark every conclusion about it as unsupported, including negative ones. Then contain
the principal using the standard procedure in §3 Step 4 of
`../vpc.stealth.no-logs-from-amazon-vpc-flow-logs/`, which is identical and not restated here.

---

## 4. Eradication

### Remove Attacker Access

#### Cover every VPC, in every Region

Query 2's `[FAIL]` lines are VPCs with no association. Most of them will be VPCs nobody ever
configured rather than victims — that is the coverage gap this technique exploits, and closing it is
the durable fix.

#### Repair failing associations

An association whose `Status` is not `ACTIVE`, or whose destination Query 3 shows as unwritable,
delivers nothing while looking configured. There is no event for this state; only the scheduled
sweep finds it, and it should be a standing check rather than an incident step.

#### Right-size who can manage Resolver configuration

`route53resolver:DisassociateResolverQueryLogConfig` and the DNS Firewall write actions belong to
an infrastructure role. Query 4's principal is the starting point.

#### Consider what the gap was for

This technique is preparation. If DNS logging was disabled for a VPC and later restored, look at
what ran in that VPC during the window using every other source available — the tunnelling playbook
at `../route53dns.exfiltration.suspicious-query-with-base64-encoded-string/` is the most likely
thing the gap was hiding.

---

## 5. Recovery

### Restore Clean State

#### Verify coverage across every Region

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  COVERED=$(aws route53resolver list-resolver-query-log-config-associations --region "$REGION" \
    --output json 2>/dev/null | jq -r '[.ResolverQueryLogConfigAssociations[] | select(.Status == "ACTIVE") | .ResourceId] | unique | .[]')
  for V in $(aws ec2 describe-vpcs --region "$REGION" --output json 2>/dev/null | jq -r '.Vpcs[].VpcId'); do
    echo "$COVERED" | grep -qx "$V" || echo "[FAIL] $REGION $V has no active query log association"
  done
done
echo "[i] no [FAIL] lines above means every VPC in every Region is covered"
```

#### Verify no association is failing

```bash
REGION="us-east-1"
BAD=$(aws route53resolver list-resolver-query-log-config-associations --region "$REGION" \
  --output json | jq '[.ResolverQueryLogConfigAssociations[] | select(.Status != "ACTIVE")] | length')
[ "$BAD" -eq 0 ] && echo "[OK] every association is ACTIVE" \
                 || echo "[FAIL] $BAD association(s) not ACTIVE — re-run Query 2 for the error messages"
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  eventSource=route53resolver.amazonaws.com"
echo "  eventName=DisassociateResolverQueryLogConfig  no errorCode"
echo "  by an ARN outside known_provisioners"
echo "  (this is the case an account-wide record count cannot see: the configuration survives and"
echo "   every other VPC keeps logging)"
echo "and MUST fire on:"
echo "  eventName=DisassociateFirewallRuleGroup — which removes the blocking AND empties the only"
echo "  field in the query log that states a verdict"
echo "The rule MUST NOT fire on:"
echo "  AssociateResolverQueryLogConfig by the provisioning role"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| One VPC stopped being logged and the alert did not fire | The rule counted records account-wide, grouped by the ingestion pipeline's labels rather than by VPC |
| Nobody could say which VPC lost coverage | The grouping key was a log-shipper label, and the VPC is the unit of configuration |
| VPCs existed with no query logging at all | Coverage is opt-in per VPC, and no scheduled check looked for VPCs without an association |
| An association that existed and was not delivering went unnoticed | No CloudTrail event marks the moment delivery starts failing, and no scheduled state read existed |
| The subsequent silence from GuardDuty was read as reassurance | GuardDuty's DNS findings consume Resolver query logs, so this technique disables them too |

### Recommended Guardrails

**Fence Resolver logging and DNS Firewall configuration**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["route53resolver:DeleteResolverQueryLogConfig",
             "route53resolver:DisassociateResolverQueryLogConfig",
             "route53resolver:DisassociateFirewallRuleGroup",
             "route53resolver:DeleteFirewallRuleGroup",
             "route53resolver:DeleteFirewallRule",
             "route53resolver:UpdateFirewallRuleGroupAssociation"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Associate query logging with every VPC at creation, in the provisioning module. Coverage is
  opt-in, so a VPC created outside the module is uncovered by default and silently so.
- Deliver to a destination in a separate account whose policy the workload account cannot modify.
  Stopping the logging and destroying what was logged should require different access.
- Alert on a VPC with no association as a standing coverage check, independent of any event. It is
  the only way to find a VPC that was never covered rather than newly uncovered.
- Associate a DNS Firewall rule group with every VPC as well. Losing it costs both the control and
  the evidence that the control was present.

**Detection improvements**
- Alert on the control-plane event, grouped by the resource the event names. For this telemetry the
  absence signal is structurally weak in three separate documented ways.
- Watch `Disassociate`, not only `Delete`. The surgical form is the likely one and it leaves every
  account-wide count essentially unchanged.
- Read association `Status` on a schedule. The failing-but-present state produces no event, so a
  scheduled read is the only thing that finds it.
- Never treat an empty `firewall_rule_action` as approval — after a rule group is removed, every
  record looks exactly like an allowed query.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log |
| MITRE tactic | Defense Impairment (TA0112) |
| Primary API | `route53resolver:DisassociateResolverQueryLogConfig`, `DeleteResolverQueryLogConfig`, `DisassociateFirewallRuleGroup` |
| Event source | route53resolver.amazonaws.com |
| Key discriminator | The control-plane call itself, with `resourceId` naming the VPC that lost coverage |
| Ground-truth signal | `list-resolver-query-log-config-associations` — `Status` per association, and the set of VPCs with no association at all. Live state, not a log |
| "Was it used" pivot | The gap between the disassociation and the restoration, cross-referenced against what the same principal did in that window |
| Blast radius | Every `route53dns.*` detection and every GuardDuty DNS finding for the affected VPC. **VPC flow logs do not cover the gap** — they exclude queries to the Amazon DNS server |
| Error strings | None on the disassociation itself. A failing association surfaces as a non-`ACTIVE` `Status` with an `ErrorMessage`, and produces **no event** at the moment it starts failing |

**MITRE mapping note:** `T1685.002` is the correct current identifier. Verified live 2026-08-30.

### Residual Risk

The window between the disassociation and the restoration is DNS activity recorded nowhere, and
there is genuinely no second source — VPC flow logs exclude queries to the Amazon DNS server by
design. No conclusion about that period is supportable, including "nothing happened". If the
affected VPC never had an association in the first place, there is no gap to size because there was
never any history. GuardDuty's DNS findings were silent for the same window and for the same
reason, so their silence is not evidence either. And if DNS Firewall was removed alongside, every
query record from that period carries an empty `firewall_rule_action` — which correctly means "no
match" and will read, to anyone reviewing it later, exactly like "allowed".
