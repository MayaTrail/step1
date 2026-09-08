# IR Playbook: RDS DB Security Group Change — A Retired API and the Firewall Change That Replaced It (`rds:CreateDBSecurityGroup`, `rds:ModifyDBInstance`)

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Firewall change in front of a database — and, on the legacy half, a call to an API whose resource type no longer exists |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **Medium** for a legacy DB security group call, which in a VPC-only account cannot change anything and is interesting only as an anomaly; **High** if one *succeeds*, because that means this account still has an EC2-Classic estate more than four years after retirement; **High** for a non-pipeline replacement of a live database's VPC security groups, which is the observable the source rule was reaching for and does not have. The source rates the legacy rule **P2**, over-rating a call that cannot act and under-rating its successor entirely |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1686.001 (primary), T1578.005 (secondary) — both verified live 2026-08-29 |
| Services in Scope | RDS, EC2 (security groups and their rules), CloudTrail (management), IAM, Organizations (SCP) |

**What happens — and the honest answer is usually nothing.** `CreateDBSecurityGroup` and
`DeleteDBSecurityGroup` manage **DB security groups**, which AWS documents as controlling *"access
to EC2-Classic DB instances that are not in a VPC"*, above a note that reads *"EC2-Classic was
retired on August 15, 2022."* `CreateDBSecurityGroup` documents the error
**`DBSecurityGroupNotSupported`** — *"A DB security group isn't allowed for this action"* — and
every account created since the retirement is VPC-only. `CreateDBInstance`'s own `DBSecurityGroups`
parameter now reads *"This setting applies to the legacy EC2-Classic platform, which is no longer
used to create new DB instances. Use the `VpcSecurityGroupIds` setting instead."* So a call to
these APIs today changes nothing, and the source rule — which requires the absence of an error code
— **excludes the only outcome the API can produce.** The call is still worth seeing, because in an
account with no EC2-Classic estate nothing legitimate emits it: it is stale tooling, a script older
than the retirement, or an actor walking the API reference for something unmonitored. And if a call
*succeeds*, the finding is bigger than the alert: this account has DB instances outside a VPC.

**What the technique does:** The discriminator for the legacy half is **the call itself, not its outcome**
— the success filter is what makes the source rule unfireable. The discriminator for the half that
still matters is `requestParameters.vpcSecurityGroupIds` on `ModifyDBInstance`, and its trap is
that the parameter is the **complete new set rather than a delta**: the groups it does not name are
the groups being detached, so a removal is invisible in the event and visible only against prior
state.

**Why the usual reflexes miss it.** The first is to treat a legacy `CreateDBSecurityGroup` call as
an attack in progress: in a VPC-only account it cannot change anything, and AWS answers it with
`DBSecurityGroupNotSupported`. The second is the inverse — dismissing it entirely, when a call to a
retired API is a strong signal about the tooling or the operator behind it. The third is to stop at
the legacy API and never watch its successor, which is where an actual firewall change in front of a
database happens.

**Detection thesis:** rate the legacy call on what it reveals rather than on what it did, and put
the real severity on `ModifyDBInstance` changing `VpcSecurityGroupIds` outside the pipeline — the
observable the source rule was reaching for and does not have.

> The *rules inside* an attached security group are a different observable on a different service.
> `../_superseded/aws.initial-access.sg-remote-management-open/` owns `ec2:AuthorizeSecurityGroupIngress`,
> including port-range containment. This playbook covers which groups are **attached**.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing RDS **management** events. Legacy calls carry
  `requestParameters.dBSecurityGroupName`, and the authorize and revoke variants add `cIDRIP`,
  `eC2SecurityGroupName`, `eC2SecurityGroupId` and `eC2SecurityGroupOwnerId` — **note the
  leading-acronym lowercasing**, which is not derivable and is the same convention that produces
  `cACertificateIdentifier` elsewhere in RDS
- The same trail must carry **EC2** management events. Half of any real firewall finding is
  `ec2:AuthorizeSecurityGroupIngress`, and a trail scoped to RDS sees which groups are attached
  with no way to know what they permit
- **A recorded intended security-group set per database**, in infrastructure code. The
  `vpcSecurityGroupIds` parameter replaces rather than merges, so the only way to tell an addition
  from a removal is to compare against what the set should be
- A baseline of which principals own database lifecycle — one deployment role and one break-glass
  role in most accounts
- If this account predates August 2022: an explicit inventory of any surviving EC2-Classic estate.
  Its absence is what makes the legacy rule meaningful, and nobody should be discovering it during
  an incident

**Alerting (must be pre-configured)**
- **A legacy DB security group mutating API call succeeding — `CreateDBSecurityGroup`, `DeleteDBSecurityGroup`, `AuthorizeDBSecurityGroupIngress` or `RevokeDBSecurityGroupIngress` → P0**
- **`ModifyDBInstance` or `ModifyDBCluster` replacing `vpcSecurityGroupIds` by a principal outside the database-lifecycle allowlist → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- Which principals and automation roles touch this service at all. In most estates the list is short, which makes an unfamiliar caller a finding before any threshold is evaluated.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | A legacy DB security group mutating API **succeeding** — this account has an EC2-Classic estate | CloudTrail (management) | T1686.001 |
| P1 | `ModifyDBInstance`/`ModifyDBCluster` replacing `vpcSecurityGroupIds`, no `errorCode`, principal not on the lifecycle allowlist | CloudTrail (management) | T1686.001, T1578.005 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A legacy DB security group API **called at all**, whatever the outcome — including `DBSecurityGroupNotSupported` | CloudTrail (management) | T1686.001 |
| P2 | `DescribeDBSecurityGroups` followed within an hour by a mutating legacy call, same principal — enumerate-then-call | CloudTrail (management) | T1580, T1686.001 |
| P2 | `vpcSecurityGroupIds` replaced across three or more databases by one principal within an hour | CloudTrail (management) | T1686.001 |
| P3 | `ec2:AuthorizeSecurityGroupIngress` with a `/0` source on a group attached to a database | CloudTrail (management) | T1686.001 |

### Detection Rule Quality Notes

The source rule matches a retired API and then filters out the only result that API can return.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Requires `NOT _exists_:errorCode` on a retired API | `CreateDBSecurityGroup` documents `DBSecurityGroupNotSupported` (400) and that is what a VPC-only account gets. The success filter excludes it, so **the rule can never fire** — and it reads as coverage on a dashboard while covering nothing | Match the **call**, not the outcome. The bare `condition: selection` is deliberate and carries a `# justified:` comment |
| Covers a construct that no longer exists | DB security groups control *"access to EC2-Classic DB instances that are not in a VPC"*, and EC2-Classic retired on 15 August 2022. `CreateDBInstance` now directs callers to `VpcSecurityGroupIds` instead, and the User Guide's security-group page no longer mentions DB security groups at all | Keep the rule as an anomaly detector — nothing legitimate emits these calls — and add the successor observable, which the source set does not have |
| Only `Create` and `Delete` | `AuthorizeDBSecurityGroupIngress` and `RevokeDBSecurityGroupIngress` are the calls that would actually change access, and `DescribeDBSecurityGroups` is the enumeration that precedes them. All three are uncovered | Match all four mutating calls; ship the read as a base rule feeding an enumerate-then-call correlation |
| Nothing covers `vpcSecurityGroupIds` | The live equivalent — replacing the security groups on a running database — produces an ordinary `ModifyDBInstance` and no alert anywhere in the source set | Ship the modern rule at `high` with a pipeline allowlist |
| No handling of replace-versus-add | `vpcSecurityGroupIds` is the complete new set, so a call that drops the restrictive group looks identical to one that adds a group. Sigma cannot see the difference | State it in the rule, and do the before/after comparison in the KQL and in Query 1 |

**Recommended detection — the retired API called at all, outcome irrelevant.**

```yaml
# RDS DB Security Group APIs — Legacy (EC2-Classic) and the Modern Equivalent (T1686.001 / T1578.005)
#
# READ THIS BEFORE DEPLOYING ANYTHING BELOW. The source rule matches
# `eventName:("CreateDBSecurityGroup" OR "DeleteDBSecurityGroup")` AND `NOT _exists_:errorCode`.
# Those APIs manage **DB security groups**, which are an EC2-Classic construct. AWS's own note,
# carried verbatim on the CreateDBSecurityGroup, DeleteDBSecurityGroup, DescribeDBSecurityGroups
# and AuthorizeDBSecurityGroupIngress pages and on the CloudFormation resource:
#
#     "A DB security group controls access to EC2-Classic DB instances that are not in a VPC."
#     "EC2-Classic was retired on August 15, 2022."
#
# And on CreateDBInstance's own DBSecurityGroups parameter: "This setting applies to the legacy
# EC2-Classic platform, which is no longer used to create new DB instances. Use the
# VpcSecurityGroupIds setting instead." The RDS User Guide's "Controlling access with security
# groups" page no longer mentions DB security groups as a mechanism at all - only the API
# reference retains them.
#
# THE CONSEQUENCE FOR THE SOURCE RULE IS THAT IT CANNOT FIRE. CreateDBSecurityGroup documents the
# error `DBSecurityGroupNotSupported` - "A DB security group isn't allowed for this action", HTTP
# 400 - and in a VPC-only account, which is every account created since the retirement, that is
# what the call returns. The rule's `NOT _exists_:errorCode` success filter therefore excludes the
# only outcome the API can produce. DeleteDBSecurityGroup is worse: it can only succeed against a
# DB security group that exists, and none can be created.
#
# WHAT COULD NOT BE VERIFIED, stated rather than assumed: no AWS statement was found asserting
# that the operation now ALWAYS fails, and this analysis had no account in which to test it. The
# rules below are therefore written to fire on the CALL rather than on its success, which is
# correct under either reading and is the stronger detection in both.
#
# SO THE RULE IS INVERTED. In an account with no EC2-Classic estate, a CreateDBSecurityGroup call
# in 2026 is worth seeing precisely BECAUSE nothing legitimate emits it: it is stale tooling, a
# copied script, or an actor enumerating API surface to find something unmonitored. The failure IS
# the signal. Rule 1 matches the call, not the outcome.
#
# AND THE REAL OBSERVABLE IS SOMEWHERE ELSE. What the source rule was reaching for - a change to
# the firewall in front of a database - happens today in two places, and the source set covers
# neither: `ModifyDBInstance` with `vpcSecurityGroupIds`, which REPLACES the whole set of groups
# on an instance in one call, and `ec2:AuthorizeSecurityGroupIngress` on a group attached to one.
# Rule 3 covers the first. The second is owned by
# ../../_superseded/aws.initial-access.sg-remote-management-open/, which handles port-range containment and
# the nested ipPermissions.items[] request form properly.
#
# FIELD SHAPE. eventSource `rds.amazonaws.com`, management plane, regional. Legacy:
# `requestParameters.dBSecurityGroupName`, plus `cIDRIP`, `eC2SecurityGroupName`,
# `eC2SecurityGroupId` and `eC2SecurityGroupOwnerId` on the authorize and revoke calls - note the
# leading-acronym lowercasing, which is the same convention that produces `cACertificateIdentifier`
# elsewhere in RDS. Modern: `requestParameters.vpcSecurityGroupIds` is an ARRAY and it is the
# COMPLETE new set, not a delta - the groups it omits are the groups being removed.
title: Legacy EC2-Classic DB security group API called
id: fb10e29a-8616-4dc6-af61-3115d9e371a3
name: rds_legacy_dbsecuritygroup_called
status: experimental
description: >-
  A DB security group API was called. These manage EC2-Classic DB security groups, and EC2-Classic
  was retired on 15 August 2022; in a VPC-only account nothing legitimate calls them, and
  CreateDBSecurityGroup is documented to return DBSecurityGroupNotSupported. The call itself is
  the signal, whether or not it succeeded.
references:
  - https://attack.mitre.org/techniques/T1686/001/                                                     # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBSecurityGroup.html            # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html              # retrieved 2026-08-29
tags:
  - attack.defense-impairment
  - attack.t1686.001
logsource:
  product: aws
  service: cloudtrail
detection:
  # justified: bare `selection` is intentional and is the whole point of this rule. Adding a
  # success filter - which is what the source rule does - excludes DBSecurityGroupNotSupported,
  # the only outcome these APIs can produce in a VPC-only account, and leaves a rule that can
  # never fire. In an account with a genuine EC2-Classic estate, add the principal allowlist that
  # owns it; everywhere else, any call at all is the finding.
  selection:
    eventSource: 'rds.amazonaws.com'
    eventName:
      - 'CreateDBSecurityGroup'
      - 'DeleteDBSecurityGroup'
      - 'AuthorizeDBSecurityGroupIngress'
      - 'RevokeDBSecurityGroupIngress'
  # justified: EC2-Classic DB security groups are a retired construct. A call to
  # this API surface in a current account is legacy tooling nobody removed or
  # somebody probing for an old path — both warrant a read, and there is no
  # field on the event that would narrow it further.
  condition: selection
falsepositives:
  - >-
    An account with a surviving EC2-Classic estate, or a configuration-management tool still
    emitting these calls from a template written before August 2022. Both are worth knowing about:
    the first is a migration that never finished, the second is tooling nobody has read in years.
level: medium
---
# Base rule — sequence component only, not for direct alerting. DescribeDBSecurityGroups is the
# read half and is what an actor enumerating API surface calls first. It is separated from the
# mutating rule because a scanner that only reads is a different finding from one that writes.
title: Legacy EC2-Classic DB security groups enumerated
id: b2e17555-5f1b-436f-993e-488c792bfc66
name: rds_legacy_dbsecuritygroup_read_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBSecurityGroups.html   # retrieved 2026-08-29
tags:
  - attack.discovery
  - attack.t1580
logsource:
  product: aws
  service: cloudtrail
detection:
  # justified: informational base rule feeding the correlation below; the API is retired, so any
  # call is anomalous and no further filter is meaningful.
  selection:
    eventSource: 'rds.amazonaws.com'
    eventName: 'DescribeDBSecurityGroups'
  condition: selection
level: informational
---
# THE MODERN EQUIVALENT, and the rule the source set does not have. `ModifyDBInstance` with
# `vpcSecurityGroupIds` changes the firewall in front of a live database - and it REPLACES the
# entire set rather than adding to it, so the groups the call omits are the groups being removed.
# A call that drops the restrictive group and leaves a permissive one looks, in the event, exactly
# like a call that adds a group: the removal is invisible except by comparison with prior state.
#
# `vpcSecurityGroupIds: null` matches when the field is ABSENT - Sigma's documented null semantics
# - so `not sg_absent` is how this rule requires the parameter to be present without depending on
# an `exists` modifier that not every backend supports.
title: RDS instance security groups replaced by a principal outside the database-lifecycle pipeline
id: 7e5edb5c-cffe-47df-9e31-23aa0899a693
name: rds_vpc_security_groups_replaced
status: experimental
description: >-
  The set of VPC security groups on a DB instance or cluster was replaced. This is the live
  equivalent of the retired DB security group APIs, and the parameter is the complete new set - the
  groups it does not name are the groups being removed.
references:
  - https://attack.mitre.org/techniques/T1578/005/                                          # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html      # retrieved 2026-08-29
tags:
  - attack.defense-impairment
  - attack.t1686.001
  - attack.t1578.005
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'rds.amazonaws.com'
    eventName:
      - 'ModifyDBInstance'
      - 'ModifyDBCluster'
  sg_absent:
    requestParameters.vpcSecurityGroupIds: null
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING. Unpopulated this fires on every pipeline apply that touches a
  # database. The allowlist IS the discriminator - the parameter carries no signal on its own.
  database_lifecycle_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace with this account's deployment role
      - ':role/BreakGlassAdmin'     # replace with this account's break-glass role
  condition: selection and success and not sg_absent and not database_lifecycle_pipeline
falsepositives:
  - >-
    An engineer attaching a temporary bastion group during a debugging session. Should be rare and
    should be followed by a call putting the original set back - if the second call never comes,
    that is the finding.
level: high
---
# THRESHOLD BASIS, with no observed baseline to derive one from. Changing the security groups on
# one database is maintenance. Doing it to three inside an hour is a fleet-wide firewall change,
# and the response is to compare every affected database against its intended group set rather
# than to triage them one at a time. `gte` at the baseline, never `gt`, so a run that touches
# exactly three does not fall through. Re-baseline against your own change windows before deploying.
title: RDS security groups replaced across multiple databases by one principal
id: ba674cb0-c56b-4f56-b0fc-8e09ba2bfd95
status: experimental
description: >-
  One non-pipeline principal replaced the security groups on three or more distinct databases
  within an hour. The recovery work-list is every database in the group.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html   # retrieved 2026-08-29
tags:
  - attack.defense-impairment
  - attack.t1686.001
correlation:
  type: value_count
  rules:
    - rds_vpc_security_groups_replaced
  group-by:
    - userIdentity.arn
  field: requestParameters.dBInstanceIdentifier
  timespan: 1h
  condition:
    gte: 3
level: high
---
# ENUMERATE-THEN-CALL is what API-surface probing looks like from the outside: read the retired
# resource type, discover it is empty or refused, try to create one anyway. Neither half is
# interesting alone - a single stale call is tooling - but the pair, from one principal inside an
# hour, is somebody working through an API reference rather than running a deployment.
title: Legacy DB security groups enumerated and then modified by one principal
id: 80e99d8d-ce21-42f7-ba5f-878c69f4627c
status: experimental
description: >-
  One principal listed DB security groups and then called a mutating DB security group API within
  an hour. Against a retired EC2-Classic resource type this reads as API-surface enumeration, not
  as administration.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBSecurityGroups.html   # retrieved 2026-08-29
tags:
  - attack.discovery
  - attack.defense-impairment
  - attack.t1580
  - attack.t1686.001
correlation:
  type: temporal_ordered
  rules:
    - rds_legacy_dbsecuritygroup_read_bb
    - rds_legacy_dbsecuritygroup_called
  group-by:
    - userIdentity.arn
  timespan: 1h
level: high
```

Neither the rule nor any Sigma correlation can say whether a group *removal* opened the database:
that needs the removed group's rules, which live in EC2 and may have been deleted since.
`detections/kql_t1686_001.kql` reconstructs the before/after group set per database, and Query 2
below reads what the currently attached groups permit.

**One thing this playbook does not claim.** No AWS statement was found asserting that
`CreateDBSecurityGroup` *always* fails in 2026, and this analysis had no account in which to test
it. An account with a surviving EC2-Classic estate may still succeed — which is why the P0 row
above is the *success* case and why the shipped rule keys on the call rather than the outcome.

---

### Key Investigation Queries

> RDS is regional — run these in each region the account uses. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: both halves, and the before/after group set

```bash
REGION="us-east-1"
LEGACY="CreateDBSecurityGroup DeleteDBSecurityGroup AuthorizeDBSecurityGroupIngress RevokeDBSecurityGroupIngress DescribeDBSecurityGroups"
RAW=$(for EV in $LEGACY ModifyDBInstance ModifyDBCluster; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region, or"
  echo "    missing cloudtrail:LookupEvents. This is NOT 'no firewall change happened'."
else
  # Legacy field names use LEADING-ACRONYM lowercasing - cIDRIP, eC2SecurityGroupId - which is not
  # derivable from the modern convention. The modern half is filtered to calls that actually carry
  # vpcSecurityGroupIds, because a ModifyDBInstance without it is a different change entirely.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "rds.amazonaws.com") |
    select((.requestParameters.dBSecurityGroupName != null) or
           (.requestParameters.vpcSecurityGroupIds != null)) |
    {time: .eventTime, event: .eventName, region: .awsRegion,
     caller_arn: .userIdentity.arn, access_key: .userIdentity.accessKeyId,
     half: (if .requestParameters.dBSecurityGroupName != null then "legacy-ec2-classic" else "modern-vpc" end),
     db_security_group: (.requestParameters.dBSecurityGroupName // null),
     legacy_cidr: (.requestParameters.cIDRIP // null),
     legacy_ec2_group: (.requestParameters.eC2SecurityGroupId // .requestParameters.eC2SecurityGroupName // null),
     db_identifier: (.requestParameters.dBInstanceIdentifier //
                     .requestParameters.dBClusterIdentifier // null),
     new_group_set: (.requestParameters.vpcSecurityGroupIds // null),
     resulting_groups: [ (.responseElements.vpcSecurityGroups // [])[] | .vpcSecurityGroupId ],
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.time)'
fi
```

On `half: legacy-ec2-classic` rows, read `error` first. `DBSecurityGroupNotSupported` is AWS
refusing a call against a resource type that cannot exist here — the call is the finding and
nothing changed. `SUCCESS` on a mutating legacy call is a **larger** finding: this account has an
EC2-Classic estate, and the DB instances behind those groups are not in a VPC.

On `half: modern-vpc` rows, `new_group_set` is the **complete replacement set**, not a delta.
Compare it against `resulting_groups` on the same row and against the previous row for the same
`db_identifier`: a group present before and absent now was **detached**, and that is the direction
that matters. Carry `db_identifier` into Query 2.

#### Query 2 — What the currently attached groups actually permit

```bash
REGION="us-east-1"; DB_ID="<db-identifier-from-Query-1>"
INST=$(aws rds describe-db-instances --db-instance-identifier "$DB_ID" --region "$REGION" --output json)
PORT=$(printf '%s' "$INST" | jq -r '.DBInstances[0].Endpoint.Port // empty')
SGS=$(printf '%s' "$INST" | jq -r '[.DBInstances[0].VpcSecurityGroups[]?.VpcSecurityGroupId] | join(" ")')
if [ -z "$SGS" ]; then
  echo "[!] INCONCLUSIVE - no security groups returned for $DB_ID. Every DB instance in a VPC has"
  echo "    at least one, so an empty value is a failed call or a cluster identifier - not an"
  echo "    unprotected database. Try describe-db-clusters."
  exit 0
fi
echo "[i] $DB_ID currently attached to: $SGS (port ${PORT:-unknown})"
for SG in $SGS; do
  RULES=$(aws ec2 describe-security-group-rules --region "$REGION" \
            --filters Name=group-id,Values="$SG" --output json)
  N=$(printf '%s' "$RULES" | jq '.SecurityGroupRules | length')
  # A group always has at least its egress default, so zero rules means the call did not run.
  if [ -z "$N" ] || [ "$N" -eq 0 ]; then
    echo "[!] INCONCLUSIVE - could not read rules for $SG; what it permits is unknown, not nothing"
    continue
  fi
  HITS=$(printf '%s' "$RULES" | jq -r --arg p "${PORT:-0}" '
    .SecurityGroupRules[] | select(.IsEgress == false) |
    select((.CidrIpv4 // "") | endswith("/0") or ((.CidrIpv6 // "") | endswith("/0"))) |
    select(.IpProtocol == "-1" or ((.FromPort <= ($p|tonumber)) and (.ToPort >= ($p|tonumber)))) |
    "\(.SecurityGroupRuleId) \(.IpProtocol) \(.FromPort)-\(.ToPort) \(.CidrIpv4 // .CidrIpv6)"')
  if [ -n "$HITS" ]; then
    echo "[FAIL] $SG permits an unrestricted source to port ${PORT:-?}:"
    printf '%s\n' "$HITS" | sed 's/^/        /'
  else
    echo "[OK] $SG has no unrestricted ingress spanning port ${PORT:-?}"
  fi
done
# A group that Query 1 shows as REMOVED may itself have been deleted since, in which case its rules
# are unrecoverable and what the change opened is unanswerable. Check before concluding:
echo "[i] for each removed group id: aws ec2 describe-security-groups --group-ids <id> --region $REGION"
echo "    An InvalidGroup.NotFound there means the evidence is gone - record it as unknown."
```

An unrestricted rule here only matters if the database is also publicly addressable — the flag and
the firewall are both required, and `../rds.exfiltration.database-instancecluster-made-public/`
owns the other condition and the full reachability walk.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="AuthorizeDBSecurityGroupIngress CreateDBSecurityGroup DeleteDBSecurityGroup ModifyDBCluster ModifyDBInstance RevokeDBSecurityGroupIngress"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "rds.amazonaws.com") |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'group_by(.caller) | map({caller: .[0].caller, calls: length,
                                       events: (map(.event) | unique),
                                       keys: (map(.access_key) | unique),
                                       first: (map(.time) | min), last: (map(.time) | max)})
             | sort_by(-.calls)'
```

The alerting event named one resource; this asks whether the same principal did the same thing
elsewhere, and whether anyone else did it too. Group by caller rather than by resource: the
question the eradication phase needs answered is *how much of this is one actor's work*, and a
per-resource list cannot say. `access_key` is emitted here because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` regardless of whether it happened — see the caveat in the preamble.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-3>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique),
                               errors: (map(.error) | unique),
                               ips: (map(.ip) | unique | .[0:5])})'
```

Keyed on the access key rather than the ARN, because one credential is used across many
sessions and the key is what identifies the credential. The per-service grouping answers the
question this playbook cannot: whether this technique was the objective or one stop on a tour.
A service in that list with no business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID — so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

If the finding is legacy-only and every call failed, there is nothing to contain on the resource:
the calls could not act. Go straight to Step 2 and find what is emitting them. If a group set was
replaced, put the intended set back **naming every group you want attached** — the parameter
replaces rather than merges, so a partial list detaches everything it omits, which is how a
containment step becomes the outage.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Restore the intended security-group set

```bash
REGION="us-east-1"; DB_ID="<db-identifier-from-Query-1>"
# The COMPLETE intended set, from infrastructure code. Naming a subset detaches the rest.
INTENDED="<sg-id-1> <sg-id-2>"
case "$INTENDED" in
  *"<sg-id"*) echo "[FAIL] INTENDED is still a placeholder. Read the full intended set from IaC"
              echo "       before running this - modify-db-instance REPLACES, it does not merge."
              exit 1;;
esac
BEFORE=$(aws rds describe-db-instances --db-instance-identifier "$DB_ID" --region "$REGION" \
           --query 'DBInstances[0].VpcSecurityGroups[].VpcSecurityGroupId' --output text)
if [ -z "$BEFORE" ]; then
  echo "[!] INCONCLUSIVE - could not read the current set for $DB_ID; do not overwrite blind"
  exit 1
fi
echo "[i] current set: $BEFORE"
aws rds modify-db-instance --db-instance-identifier "$DB_ID" --region "$REGION" \
  --vpc-security-group-ids $INTENDED --apply-immediately >/dev/null \
  && echo "[OK] requested restore of the intended set; verify in §5, the change is asynchronous" \
  || echo "[FAIL] modify-db-instance did not succeed - the database is still on $BEFORE"
```

#### Step 2 — Contain the principal, or find the stale tooling

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
# A run of failed legacy calls is almost always a configuration-management tool older than the
# EC2-Classic retirement. Identify it from the userAgent in Query 1 before containing anyone: a
# deny on the deployment role causes an outage and fixes nothing.
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["rds:ModifyDBInstance","rds:ModifyDBCluster","rds:CreateDBSecurityGroup","rds:DeleteDBSecurityGroup","rds:AuthorizeDBSecurityGroupIngress","rds:RevokeDBSecurityGroupIngress","ec2:AuthorizeSecurityGroupIngress"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyRdsFirewall" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyRdsFirewall" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied RDS firewall changes for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or a"
     echo "    service principal. Contain manually; neither branch above applies.";;
esac
```

---

## 4. Eradication

### Remove Attacker Access

- **Find and retire whatever emits the legacy calls.** The `userAgent` and `sourceIPAddress` from
  Query 1 identify it. A tool still calling `CreateDBSecurityGroup` in 2026 has not been read since
  before August 2022, and whatever else it manages deserves the same look.
- **If a legacy call succeeded, the incident is the estate, not the alert.** DB instances outside a
  VPC have no security-group model anyone still supports and no VPC flow logs. Migrating them is a
  project; opening it is the eradication step here.
- **Reconcile every database's attached group set against infrastructure code**, not just the one
  that alerted. `vpcSecurityGroupIds` replaces rather than merges, so a single careless apply
  detaches groups across everything it touches, and the fan-out correlation's group is the
  work-list.
- **Right-size the permission.** `rds:ModifyDBInstance` is not needed by any workload at runtime.
  Neither is `ec2:AuthorizeSecurityGroupIngress`, which is the other half of the same problem.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyRdsFirewall EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyRdsFirewall"
    LEFT=$(aws iam list-user-policies --user-name "$N" --query 'PolicyNames[]' --output text);;
  *) N=""; LEFT="UNCHECKED";;
esac
case "$LEFT" in
  UNCHECKED)   echo "[!] INCONCLUSIVE - neither user nor role; check manually";;
  *Emergency*) echo "[FAIL] an emergency policy is still attached: $LEFT";;
  *)           echo "[OK] no emergency policy remains on $N";;
esac
```

---

## 5. Recovery

### Restore Clean State

#### Verify the attached set is the intended one, and that it does not permit the internet

```bash
REGION="us-east-1"; DB_ID="<db-identifier-from-Query-1>"
INTENDED="<sg-id-1> <sg-id-2>"; VERDICT="clean"

INST=$(aws rds describe-db-instances --db-instance-identifier "$DB_ID" --region "$REGION" --output json)
NOW=$(printf '%s' "$INST" | jq -r '[.DBInstances[0].VpcSecurityGroups[]?
        | select(.Status == "active") | .VpcSecurityGroupId] | sort | join(" ")')
PORT=$(printf '%s' "$INST" | jq -r '.DBInstances[0].Endpoint.Port // empty')
WANT=$(printf '%s\n' $INTENDED | sort | tr '\n' ' ' | sed 's/ $//')
if [ -z "$NOW" ]; then
  echo "[!] INCONCLUSIVE - no ACTIVE security group returned for $DB_ID. Every VPC database has at"
  echo "    least one, so this is a failed call or a modification still in progress - re-run."
  VERDICT="inconclusive"
elif [ "$NOW" != "$WANT" ]; then
  echo "[FAIL] attached set is [$NOW]; intended is [$WANT]"
  VERDICT="fail"
else
  echo "[OK] $DB_ID is attached to exactly the intended set"
fi

# Matching the intended set is not the same as being safe: the intended group may itself permit the
# internet. Both questions are asked, and neither answer is inferred from the other.
for SG in $NOW; do
  RULES=$(aws ec2 describe-security-group-rules --region "$REGION" \
            --filters Name=group-id,Values="$SG" --output json)
  N=$(printf '%s' "$RULES" | jq '.SecurityGroupRules | length')
  if [ -z "$N" ] || [ "$N" -eq 0 ]; then
    echo "[!] INCONCLUSIVE - could not read rules for $SG"; VERDICT="inconclusive"; continue
  fi
  OPEN=$(printf '%s' "$RULES" | jq -r --arg p "${PORT:-0}" '[.SecurityGroupRules[]
    | select(.IsEgress == false)
    | select((.CidrIpv4 // "") | endswith("/0") or ((.CidrIpv6 // "") | endswith("/0")))
    | select(.IpProtocol == "-1" or ((.FromPort <= ($p|tonumber)) and (.ToPort >= ($p|tonumber))))] | length')
  if [ "$OPEN" -gt 0 ]; then
    echo "[FAIL] intended group $SG still permits an unrestricted source to port ${PORT:-?}"
    VERDICT="fail"
  else
    echo "[OK] $SG permits no unrestricted source to port ${PORT:-?}"
  fi
done
case "$VERDICT" in
  clean)        echo "[OK] $DB_ID is on the intended groups and none of them is open to the internet";;
  fail)         echo "[FAIL] recovery is not complete - see the lines above";;
  inconclusive) echo "[!] INCONCLUSIVE - at least one check could not run. Do not close on this.";;
esac
```

Both branches stay reachable after the remediation: `describe-db-instances` keeps returning the
attached set whatever it is, and the rule listing is untouched by anything in §3 — which is the
point, because restoring the *intended* set proves nothing about whether that set is safe.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     CreateDBSecurityGroup, DeleteDBSecurityGroup, AuthorizeDBSecurityGroupIngress"
echo "  or RevokeDBSecurityGroupIngress on rds.amazonaws.com - WITH OR WITHOUT an errorCode, which"
echo "  is the correction: DBSecurityGroupNotSupported is the only outcome a VPC-only account gets,"
echo "  and the source rule's success filter excludes it. Also ModifyDBInstance carrying"
echo "  vpcSecurityGroupIds from a principal outside the lifecycle allowlist."
echo "MUST NOT fire on: ModifyDBInstance WITHOUT vpcSecurityGroupIds - a password change or a class"
echo "  change is a different event; the pipeline role replacing groups during a normal apply."
echo "EXPECTED FP, by design: configuration-management tooling still emitting legacy calls from a"
echo "  template written before August 2022. That is a real false positive for the alert and a real"
echo "  finding for whoever owns the tool."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A deployed rule covered a retired API and could never fire | The rule was written against `CreateDBSecurityGroup` with a success filter, and nobody checked that the API returns `DBSecurityGroupNotSupported` in a VPC-only account. It read as coverage for years |
| The observable that replaced it was uncovered | Nothing in the source set matches `vpcSecurityGroupIds` on `ModifyDBInstance`, so the live firewall change in front of every database produced no alert |
| A group removal was indistinguishable from an addition | `vpcSecurityGroupIds` is the complete new set, and no record of the intended set existed to compare against |
| Tooling was still emitting calls to an API retired in 2022 | No inventory of what calls AWS from this account, and no review of configuration-management templates since the EC2-Classic retirement |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike, not StringNotEquals: the value is wildcarded, and * expands only in Resource and
// in the *Like operators. Deny + StringNotEquals against a wildcarded ARN matches every principal
// and denies database modification outright - an outage, not a control.
{
  "Effect": "Deny",
  "Action": ["rds:ModifyDBInstance", "rds:ModifyDBCluster", "rds:CreateDBSecurityGroup",
             "rds:DeleteDBSecurityGroup", "rds:AuthorizeDBSecurityGroupIngress",
             "rds:RevokeDBSecurityGroupIngress"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy",
                                            "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- The four legacy actions are included **not because they can do damage** — they cannot, in a
  VPC-only account — but because denying them turns a puzzling `DBSecurityGroupNotSupported` into an
  unambiguous `AccessDeniedException` attributable to a policy you wrote. Every one of them is a
  real IAM action name, which matters: IAM accepts unknown actions silently, so a deny naming a
  fictional action is a no-op that reads as protection.
- Hold every database's intended security-group set in infrastructure code. It is the only thing
  that makes a *removal* detectable, and it is what §3 Step 1 and §5 both read from.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1686.001 — Disable or Modify System Firewall: Cloud Firewall (primary); T1578.005 — Modify Cloud Compute Configurations (secondary, for the `vpcSecurityGroupIds` half) |
| Primary API | Legacy: `rds:CreateDBSecurityGroup`, `rds:DeleteDBSecurityGroup`, `rds:AuthorizeDBSecurityGroupIngress`, `rds:RevokeDBSecurityGroupIngress`. Modern: `rds:ModifyDBInstance` / `rds:ModifyDBCluster` with `vpcSecurityGroupIds` |
| Event source | `rds.amazonaws.com`, **management** plane, regional — verified against AWS's RDS CloudTrail documentation |
| Key discriminator | Legacy: the **call**, not its outcome — the success filter is what makes the source rule unfireable. Modern: `requestParameters.vpcSecurityGroupIds`, which is the **complete new set**, so the groups it omits are the groups detached |
| Field shape | Legacy: `requestParameters.dBSecurityGroupName`, `cIDRIP`, `eC2SecurityGroupName`, `eC2SecurityGroupId`, `eC2SecurityGroupOwnerId` — **leading-acronym lowercasing, not derivable**. Modern: `requestParameters.vpcSecurityGroupIds` (array), `responseElements.vpcSecurityGroups[].vpcSecurityGroupId` (flat, and reflecting state at call time because `ModifyDBInstance` is asynchronous) |
| "Was it used" pivot | For the legacy half there is nothing to exercise — the resource type cannot exist. For the modern half, whether a removed group was restricting anything: read its rules with `ec2:DescribeSecurityGroupRules`, and treat `InvalidGroup.NotFound` on a since-deleted group as unanswerable rather than empty |
| Blast radius | Whatever the detached group was restricting, on every database the call touched. Reachability additionally requires the database to be publicly addressable — see `../rds.exfiltration.database-instancecluster-made-public/` |
| Error strings | `CreateDBSecurityGroup`: `DBSecurityGroupAlreadyExists`, `QuotaExceeded.DBSecurityGroup`, **`DBSecurityGroupNotSupported`**. `DeleteDBSecurityGroup`: `InvalidDBSecurityGroupState`, `DBSecurityGroupNotFound`. `AuthorizeDBSecurityGroupIngress`: `DBSecurityGroupNotFound`, `InvalidDBSecurityGroupState`, `AuthorizationAlreadyExists`, `AuthorizationQuotaExceeded`. `RevokeDBSecurityGroupIngress`: `DBSecurityGroupNotFound`, `AuthorizationNotFound`, `InvalidDBSecurityGroupState`. `DescribeDBSecurityGroups`: `DBSecurityGroupNotFound`. `ModifyDBInstance` (relevant subset): `InvalidDBSecurityGroupState`, `DBSecurityGroupNotFound`, `InvalidDBInstanceState`, `InvalidVPCNetworkStateFault`, `DBInstanceNotFound`. Denials: `AccessDeniedException` (403), `NotAuthorized` (401); the bare `AccessDenied` form is **not** documented for RDS and `Client.UnauthorizedOperation` is EC2's |

**MITRE mapping note.** `T1686.001 — Disable or Modify System Firewall: Cloud Firewall` is the
primary mapping, with `T1578.005 — Modify Cloud Compute Configurations` as the second mapping for
the modern half. Both verified live 2026-08-31.

### Residual Risk

**The legacy half has no residual risk, because it never had any risk.** What remains is the
question the alert could not answer: whether anything else in this account is driven by tooling
written before August 2022, and what else that tooling manages.

The modern half leaves more. Restoring the intended group set proves the *attachment* is right and
says nothing about what those groups permit — which is why §5 asks both questions separately. A
group detached during the incident and deleted since takes its rules with it, so what the change
actually opened may be permanently unanswerable; record that as unknown rather than as nothing. And
attachment is only one of the two conditions for a reachable database: a correct group set in front
of a `publiclyAccessible` instance is still an internet-facing database if that group permits the
port, which is `../rds.exfiltration.database-instancecluster-made-public/`'s problem and not this
one's.
