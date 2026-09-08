# IR Playbook: RDS Database Made Public — Internet-Addressable Database Endpoint via `rds:ModifyDBInstance` / `rds:CreateDBInstance`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Exposure / Initial access precondition (a production database's DNS endpoint begins resolving to a public address from outside the VPC) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High** outside the database-lifecycle pipeline. Not Critical: one event establishes that the database is publicly *addressable*, not that anything can reach it — AWS requires a permitting security group and an internet-gateway route as well. It becomes Critical when Query 2's reachability walk comes back positive. The source rates it **P2**: too low for a live exposure, about right for the precondition it actually detects |
| MITRE Tactics | Defense Impairment, Initial Access |
| MITRE Techniques | T1578.005 (primary), T1133 (secondary) — both verified live 2026-08-29 |
| Services in Scope | RDS, EC2 (security groups, route tables, network ACLs, Elastic IPs), CloudTrail (management), VPC Flow Logs, the database engine's own audit log, IAM, Organizations (SCP), AWS Config |

**What the technique does:** the actor calls `rds:ModifyDBInstance` with `--publicly-accessible`, or
creates a database and lets AWS choose. In the modify case the request carries
`publiclyAccessible: true` and applies at the next maintenance window unless
`--apply-immediately` is passed. In the create case the actor may not have asked at all: AWS
documents that when `PubliclyAccessible` is unspecified and no `DBSubnetGroup` is given it
**defaults to true for non-Aurora instances**, and likewise when the subnet group named is
`default`. Either way the endpoint's DNS now resolves to a public IPv4 address from outside the
VPC, drawn from EC2's public pool and visible in `aws ec2 describe-addresses` with
`service_managed` = `"rds"`. The actor still needs the security group to permit the engine port
and the subnets to have an internet-gateway route — in accounts where databases sit in the
default VPC both are usually already true, and the next thing to reach the database is a
credential-stuffing scanner rather than a person.

**Detection thesis.** The discriminator is `publiclyAccessible: true` **in the response**, not
in the request: the request settles a `ModifyDBInstance` (whose response lags, because
`PendingModifiedValues` does not carry the field) while the response settles a create (whose
request may omit the field entirely and inherit the documented default). The source rule reads
only the request, so the single most common accidental exposure in AWS — a create against the
`default` subnet group — produces an event it cannot match.

> The database's *contents* can leave without the endpoint ever being touched, by
> `../rds.exfiltration.snapshot-made-public/` or `../rds.exfiltration.rds-snapshot-export/`.
> Flipping this flag back does not address either, and §5 checks for both.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing RDS **management** events — every RDS action is one,
  in Event history and returned by `lookup-events` with no trail configuration. Field paths are
  lower-camel with a `dB` prefix (`requestParameters.dBInstanceIdentifier`), and
  `responseElements` is **flat**: `responseElements.publiclyAccessible`, not
  `responseElements.dBInstance.publiclyAccessible`. **`responseElements.endpoint` is absent on a
  create** — AWS states the endpoint "might not be shown for instances with the status of
  `creating`", and its published sample event confirms it
- CloudTrail **EC2** management events in the same trail. Half of this exposure is
  `AuthorizeSecurityGroupIngress` on `ec2.amazonaws.com`; a trail scoped to RDS alone sees the
  addressing change with no way to tell whether anything can use it
- **VPC Flow Logs on the database's ENI** and the engine's audit log in CloudWatch Logs. RDS
  connection attempts are **not** CloudTrail events at any level, so these are the only places a
  connection from the internet is recorded — without them, "did anyone reach it" is unanswerable
- AWS Config `rds-instance-public-access-check` **and** `rds-instance-subnet-igw-check` — the
  first evaluates the flag, the second the network path; Security Hub **RDS.2** aggregates the
  first at Critical. A baseline of which principals own database lifecycle, and a list of
  databases public **by design** recorded by principal, never by identifier — identifiers are
  attacker-chosen

**Alerting (must be pre-configured)**
- **`publiclyAccessible` true in the response of an RDS create, restore or modify by a principal outside the database-lifecycle allowlist → P0**
- **One principal making a database public and authorising a `/0` ingress rule within one hour → P1**

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
| P0 | `publiclyAccessible` true in the **response** of `CreateDBInstance`/`ModifyDBInstance`/`RestoreDB*`/`CreateDBCluster`, no `errorCode`, principal not on the lifecycle allowlist | CloudTrail (management) | T1578.005 |
| P1 | The same principal makes a database public and authorises an ingress rule whose CIDR ends `/0` within one hour | CloudTrail (management) | T1578.005, T1686.001 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A create whose request carries **no** `publiclyAccessible` and whose response carries `true` — public by AWS default, nobody asked | CloudTrail (management) | T1578.005 |
| P2 | `publiclyAccessible: true` refused with `AccessDeniedException`/`NotAuthorized`, or `InvalidVPCNetworkStateFault` in a burst — boundary mapping, not exposure | CloudTrail (management) | T1578.005 |
| P3 | An Elastic IP with `service_managed` = `rds` for an instance not on the public-by-design list | `ec2:DescribeAddresses` | T1133 |
| P3 | `Discovery:RDS/MaliciousIPCaller` or `Discovery:RDS/TorIPCaller` | GuardDuty | T1133 |

### Detection Rule Quality Notes

The source rule matches ten event names ANDed with one request parameter, and never checks
whether the call succeeded.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Reads only `requestParameters.publiclyAccessible` | The most common real exposure in AWS — a `CreateDBInstance` omitting the DB subnet group or naming the `default` one — is documented to default `PubliclyAccessible` to **true** for non-Aurora engines, producing an event with no such request parameter. AWS's own published sample CloudTrail event for `CreateDBInstance` is that case, and the rule does not match it | Read the response as a sibling block and OR the two: the response is authoritative for creates, the request for modifies |
| Two of the ten event names cannot match | `ModifyDBCluster` has no `PubliclyAccessible` parameter (a cluster becomes public at create time or through its member instances), and `CreateDBClusterFromSnapshot` is not an RDS API action — the real call, `RestoreDBClusterFromSnapshot`, is already in the same list. Both read as coverage and have never matched anything | Remove both; add `CreateDBShardGroup`, which does accept the parameter and is uncovered |
| No success filter | A refusal fires the same P2 as a completed exposure, so a principal denied ten times outranks one live exposure. The only rule of the five reviewed that omits it | `errorCode: null` on the alerting rule; refusals become a separate `medium` rule |
| Fires on the flag alone | AWS requires a permitting security group **and** an internet-gateway route before the flag means anything, so the rule pages on databases nothing can reach and gets muted before the one that matters arrives | Keep the single-event rule at `high` as the trigger for the reachability walk; ship the `critical` correlation requiring both halves |

**Recommended detection — a database entering a publicly addressable state, by request or by default.**

```yaml
# RDS DB Instance or Cluster Made Publicly Accessible (T1578.005 / T1133)
#
# WHAT THE SOURCE RULE DOES, AND THE THREE WAYS IT MISSES. The original matches ten event
# names ANDed with `requestParameters.publiclyAccessible:"true"`, with no success filter.
#
#   1. THE MOST COMMON REAL EXPOSURE CARRIES NO SUCH REQUEST PARAMETER. AWS: "The default
#      behavior when PubliclyAccessible is not specified depends on whether a DBSubnetGroup
#      is specified. If DBSubnetGroup isn't specified, PubliclyAccessible defaults to false
#      for Aurora instances and true for non-Aurora instances. If DBSubnetGroup is
#      specified, PubliclyAccessible defaults to false unless the value of DBSubnetGroup is
#      `default`, in which case PubliclyAccessible defaults to true." So a CreateDBInstance
#      that omits the subnet group, or names the `default` one, produces a PUBLIC MySQL or
#      PostgreSQL instance from an event whose requestParameters contain no
#      `publiclyAccessible` key at all. AWS's own published CloudTrail sample event for
#      CreateDBInstance is exactly this case - requestParameters has no publiclyAccessible,
#      responseElements has `"publiclyAccessible": true` and `"dBSubnetGroupName": "default"`.
#      The rule below therefore reads the RESPONSE as well as the request.
#   2. `ModifyDBCluster` HAS NO PubliclyAccessible PARAMETER. It is absent from the entire
#      request-parameter list of that API; a cluster becomes public at create time or through
#      its member instances, never through ModifyDBCluster. That disjunct can never match.
#      `CreateDBClusterFromSnapshot`, also in the source list, IS NOT AN RDS API ACTION - the
#      real call is `RestoreDBClusterFromSnapshot`, which appears in the same list. Two of the
#      ten names are dead.
#   3. NO SUCCESS FILTER. A denied attempt fires the same alert as a completed exposure.
#      Successes and denials are split below: one is an incident, the other is boundary
#      mapping, and they do not belong on one triage path.
#
# WHY REQUEST AND RESPONSE ARE BOTH READ, AND WHY THEY ARE SEPARATE BLOCKS. `ModifyDBInstance`
# is asynchronous: the returned DBInstance reflects state at the time of the call, and
# `PendingModifiedValues` - verified against the DBInstance data type - does NOT carry
# PubliclyAccessible. So a modify that turns public access ON can return
# `publiclyAccessible: false` and record the intent only in requestParameters. Creates are the
# mirror image: the request may omit the field entirely while the response states the outcome.
# Neither field is sufficient alone, and the two never both settle the question on one event,
# so they are sibling blocks ORed in the condition - never two keys in one block, which would
# AND them into a rule that fires on almost nothing.
#
# THE FLAG IS NOT THE EXPOSURE. AWS: "Access to the DB instance is ultimately controlled by
# the security group it uses. That public access is not permitted if the security group
# assigned to the DB instance doesn't include inbound rules that permit it. In addition, for a
# DB instance to be publicly accessible, the subnets in its DB subnet group must have an
# internet gateway." A fourth condition is easy to miss: the VPC needs DNS hostnames and DNS
# resolution enabled. This rule fires on the ADDRESSING half only. The correlation at the end
# of this file pairs it with the firewall half; the full reachability walk is Query 2 of
# ../PLAYBOOK.md, and it is what turns a hit into a disposition.
#
# FIELD SHAPE. eventSource `rds.amazonaws.com`, management plane, regional. CloudTrail
# lower-camel-cases RDS API parameters and renders the DB prefix as `dB`
# (`dBInstanceIdentifier`, `dBSubnetGroup`), but the convention is not uniform inside a single
# event - the same published sample carries `dbInstancePort`, `dbiResourceId`,
# `cACertificateIdentifier` and `iAMDatabaseAuthenticationEnabled`. Do not derive a path from
# the rule; read one real event. `responseElements` for CreateDBInstance is FLAT: the DBInstance
# wrapper does not appear, so it is `responseElements.publiclyAccessible`, not
# `responseElements.dBInstance.publiclyAccessible`.
title: RDS database made publicly accessible
id: 8a0b57f1-9681-421a-a456-fc94241843ac
name: rds_made_publicly_accessible
status: experimental
description: >-
  A DB instance or Multi-AZ DB cluster entered a publicly accessible state - by an explicit
  publiclyAccessible request parameter, or by the documented default-true behaviour of a create
  that omits a DB subnet group or names the default one.
references:
  - https://attack.mitre.org/techniques/T1578/005/                                                    # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1133/                                                        # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html                # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html  # retrieved 2026-08-29
tags:
  - attack.defense-impairment
  - attack.initial-access
  - attack.t1578.005
  - attack.t1133
logsource:
  product: aws
  service: cloudtrail
detection:
  # ModifyDBCluster and CreateDBClusterFromSnapshot are ABSENT on purpose: the first has no such
  # parameter, the second is not an API action. CreateDBShardGroup does accept it and is added.
  selection:
    eventSource: 'rds.amazonaws.com'
    eventName:
      - 'CreateDBInstance'
      - 'ModifyDBInstance'
      - 'CreateDBInstanceReadReplica'
      - 'RestoreDBInstanceFromDBSnapshot'
      - 'RestoreDBInstanceToPointInTime'
      - 'RestoreDBInstanceFromS3'
      - 'CreateDBCluster'
      - 'RestoreDBClusterFromSnapshot'
      - 'RestoreDBClusterToPointInTime'
      - 'CreateDBShardGroup'
  # Asked for. Authoritative for ModifyDBInstance, whose response reflects pre-change state.
  public_requested:
    requestParameters.publiclyAccessible: true
  # Got. Authoritative for creates, where the request may omit the field and the subnet-group
  # default decides. Pipelines that index CloudTrail booleans as the STRING "true" need 'true'
  # added as a second value under both keys.
  public_returned:
    responseElements.publiclyAccessible: true
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING. Where public read replicas are genuinely run, allowlist the
  # PRINCIPAL, never the instance identifier - the identifier is attacker-chosen.
  database_lifecycle_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace with this account's deployment role
      - ':role/BreakGlassAdmin'     # replace with this account's break-glass role
  condition: selection and success and (public_requested or public_returned) and not database_lifecycle_pipeline
falsepositives:
  - >-
    A deliberately public read replica provisioned outside the pipeline. Rare - and if it is not
    rare here, the finding is that database lifecycle is not owned by the pipeline.
  - >-
    A sandbox create that omits the DB subnet group and inherits the documented default-true.
    A real exposure rather than a false positive, but a configuration default rather than intent.
level: high
---
# Denied attempts are a SEPARATE rule at a lower level, not a filtered-out nuisance. The source
# rule has no success filter and therefore rates a refusal identically to a completed exposure.
# A principal repeatedly refused on publiclyAccessible is mapping its boundary, which is worth
# knowing and is not worth waking anyone.
#
# LIMITATION, stated because it is invisible otherwise: a DENIED create that would have relied
# on the subnet-group default carries no publiclyAccessible in the request and produces no
# response at all, so it cannot be distinguished from any other denied create. This rule sees
# only explicit attempts.
title: RDS public-accessibility change refused
id: b8bff61d-222b-45b1-bd11-d16c533c5b17
name: rds_public_change_denied
status: experimental
description: >-
  A principal asked RDS to make a database publicly accessible and was refused. Treated as
  boundary mapping rather than as an exposure - nothing changed, but somebody tried.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/CommonErrors.html   # retrieved 2026-08-29
tags:
  - attack.defense-impairment
  - attack.t1578.005
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'rds.amazonaws.com'
    eventName:
      - 'CreateDBInstance'
      - 'ModifyDBInstance'
      - 'CreateDBInstanceReadReplica'
      - 'RestoreDBInstanceFromDBSnapshot'
      - 'RestoreDBInstanceToPointInTime'
      - 'RestoreDBInstanceFromS3'
      - 'CreateDBCluster'
      - 'RestoreDBClusterFromSnapshot'
      - 'RestoreDBClusterToPointInTime'
      - 'CreateDBShardGroup'
  public_requested:
    requestParameters.publiclyAccessible: true
  # RDS documents AccessDeniedException (403) and NotAuthorized (401) as its own denial forms.
  # The bare `AccessDenied` string is NOT in the RDS common-error list, and
  # Client.UnauthorizedOperation is EC2's. Matched by substring so a prefixed variant still hits.
  denied:
    errorCode|contains:
      - 'AccessDenied'
      - 'NotAuthorized'
      - 'UnauthorizedOperation'
  condition: selection and public_requested and denied
falsepositives:
  - >-
    A permissions-boundary or SCP working as designed against a developer who did not know the
    control existed. Confirm the principal, then leave it alone.
level: medium
---
# Base rule - sequence component only, not for direct alerting. Carries the success filter so a
# refused ingress cannot compose into the high-severity correlation below.
#
# This deliberately duplicates a narrow slice of ../../_superseded/aws.initial-access.sg-remote-management-open/,
# which owns the general case including port-RANGE containment and the nested
# ipPermissions.items[] request form. This slice exists only so the correlation has something to
# join to inside one file; deploy that playbook's rules for the firewall problem itself.
title: EC2 security group ingress opened to the internet on a database port
id: 3468f117-e246-4c89-91de-0f3ba2c69deb
name: sg_ingress_world_open_db_port_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html  # retrieved 2026-08-29
tags:
  - attack.defense-impairment
  - attack.t1686.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'AuthorizeSecurityGroupIngress'
  # `|endswith: '/0'` rather than the literal 0.0.0.0/0: AWS canonicalizes CIDRs, so a rule
  # submitted as 1.2.3.4/0 is stored fully open, and no other prefix length ends in '/0'.
  world_open:
    requestParameters.cidrIp|endswith: '/0'
  success:
    errorCode: null
  condition: selection and world_open and success
level: informational
---
# THE EXPOSURE IS THE PAIR, NOT EITHER HALF. AWS requires BOTH the addressing flag AND a
# permitting security group before a database is reachable from the internet. One principal
# doing both inside an hour is a deliberate exposure and is rated accordingly.
#
# WHAT THIS CORRELATION CANNOT DO, and it matters: the common real case is that the two halves
# have DIFFERENT causes - an engineer flips publiclyAccessible on an instance whose security
# group was already open to 0.0.0.0/0 from some earlier change, or from a shared group nobody
# owns. Grouping by principal misses that entirely, and so does any time window, because the
# firewall half happened months ago. Only a live reachability walk answers it. That walk is
# Query 2 of ../PLAYBOOK.md and it is not optional.
#
# Sigma also cannot check that the opened security group is the one ATTACHED to the exposed
# database - that join needs live state. Confirm it before rating the correlation as critical.
title: RDS database made public and a database port opened to the internet by one principal
id: 49d45bdc-e6c7-47e2-8b07-c22dd295e772
status: experimental
description: >-
  Within one hour, the same principal made an RDS database publicly accessible and authorised
  an unrestricted-source ingress rule. Both halves of internet reachability were supplied by
  one actor; if the security group is the one attached to that database, it is live.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html  # retrieved 2026-08-29
tags:
  - attack.defense-impairment
  - attack.initial-access
  - attack.t1578.005
  - attack.t1686.001
correlation:
  type: temporal
  rules:
    - rds_made_publicly_accessible
    - sg_ingress_world_open_db_port_bb
  group-by:
    - userIdentity.arn
  timespan: 1h
level: critical
```

The rule proves addressability, not reachability: Sigma has no access to live security-group,
route-table or NACL state, and the correlation that pairs the two halves only fires when one
principal supplies both inside an hour — which misses the ordinary case where the security
group was opened months ago by somebody else. `detections/kql_t1578_005.kql` narrows that by
joining the RDS event to the EC2 ingress event **on the security group ID** rather than on the
principal, and Query 2 below closes it with live state.

---

### Key Investigation Queries

> RDS is regional — run these in the database's region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: which databases became public, who did it, and whether anyone asked

```bash
REGION="us-east-1"
EVENTS="CreateDBInstance ModifyDBInstance CreateDBInstanceReadReplica RestoreDBInstanceFromDBSnapshot RestoreDBInstanceToPointInTime RestoreDBInstanceFromS3 CreateDBCluster RestoreDBClusterFromSnapshot RestoreDBClusterToPointInTime CreateDBShardGroup"
RAW=$(for EV in $EVENTS; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region, or"
  echo "    missing cloudtrail:LookupEvents. This is NOT 'no database was made public'."
else
  # requestParameters.publiclyAccessible is ABSENT on a create that inherits the documented
  # default. responseElements is FLAT (no dBInstance wrapper) and carries the outcome. Both are
  # emitted so the analyst can tell "asked for" from "got".
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "rds.amazonaws.com") |
    {time: .eventTime, event: .eventName, region: .awsRegion,
     caller_arn: .userIdentity.arn, access_key: .userIdentity.accessKeyId,
     db_identifier: (.requestParameters.dBInstanceIdentifier //
                     .requestParameters.dBClusterIdentifier //
                     .responseElements.dBInstanceIdentifier //
                     .responseElements.dBClusterIdentifier // "unknown"),
     db_arn: (.responseElements.dBInstanceArn // .responseElements.dBClusterArn // null),
     requested: (.requestParameters.publiclyAccessible // "not-in-request"),
     returned:  (.responseElements.publiclyAccessible  // "not-in-response"),
     subnet_group: (.requestParameters.dBSubnetGroupName //
                    .responseElements.dBSubnetGroup.dBSubnetGroupName // null),
     security_groups: [ (.responseElements.vpcSecurityGroups // [])[] | .vpcSecurityGroupId ],
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent} |
    select(.requested == true or .returned == true)' |
  jq -s 'sort_by(.time)'
fi
```

Read `requested` and `returned` together. `requested: true` is an instruction, and the only
reliable field on a `ModifyDBInstance`, whose response reflects pre-change state because
`PendingModifiedValues` does not carry this attribute. `requested: "not-in-request"` with
`returned: true` is the **defaulted** case — nobody asked, AWS chose, and `subnet_group` will be
`null` or `default`, which is the tell. An `error` other than `SUCCESS` is an attempt, not an
exposure. Record `db_identifier`, `caller_arn`, `security_groups` and `access_key` as IOCs.

#### Query 2 — Establish actual reachability: can anything on the internet reach it

```bash
REGION="us-east-1"
DB_ID="<db-identifier-from-Query-1>"

INST=$(aws rds describe-db-instances --db-instance-identifier "$DB_ID" --region "$REGION" --output json)
PUB=$(printf '%s' "$INST" | jq -r '.DBInstances[0].PubliclyAccessible // empty')
PORT=$(printf '%s' "$INST" | jq -r '.DBInstances[0].Endpoint.Port // empty')
SGS=$(printf '%s' "$INST" | jq -r '[.DBInstances[0].VpcSecurityGroups[]?.VpcSecurityGroupId] | join(" ")')
# describe-db-instances ALWAYS returns PubliclyAccessible, so an empty value is a failed call, a
# wrong region, or a CLUSTER identifier (use describe-db-clusters) - never a private database.
if [ -z "$PUB" ]; then
  echo "[!] INCONCLUSIVE - no PubliclyAccessible in the record; the call did not run."; exit 0
fi
echo "[i] $DB_ID  publiclyAccessible=$PUB  port=${PORT:-?}  groups=${SGS:-none}"

# CONDITION 2 - the firewall. A group always has at least its egress default, so zero rules means
# the call did not run; absence of an open rule is only meaningful once the call is known to have.
OPEN=0
for SG in $SGS; do
  RULES=$(aws ec2 describe-security-group-rules --region "$REGION" \
            --filters Name=group-id,Values="$SG" --output json)
  N=$(printf '%s' "$RULES" | jq '.SecurityGroupRules | length')
  if [ -z "$N" ] || [ "$N" -eq 0 ]; then
    echo "[!] INCONCLUSIVE - could not read rules for $SG; its exposure is unknown, not absent"
    continue
  fi
  HITS=$(printf '%s' "$RULES" | jq -r --arg p "${PORT:-0}" '
    .SecurityGroupRules[] | select(.IsEgress == false) |
    select((.CidrIpv4 // "") | endswith("/0") or ((.CidrIpv6 // "") | endswith("/0"))) |
    select(.IpProtocol == "-1" or ((.FromPort <= ($p|tonumber)) and (.ToPort >= ($p|tonumber)))) |
    "\(.SecurityGroupRuleId) \(.IpProtocol) \(.FromPort)-\(.ToPort) \(.CidrIpv4 // .CidrIpv6)"')
  if [ -n "$HITS" ]; then
    OPEN=1; echo "[FAIL] $SG permits an unrestricted source to port ${PORT:-?}:"
    printf '%s\n' "$HITS" | sed 's/^/        /'
  else
    echo "[OK] $SG has no unrestricted ingress spanning port ${PORT:-?}"
  fi
done

# CONDITIONS 3 AND 4 - the route and the network ACL - are the shared walk, which handles the two
# inverted defaults that turn empty output into a confident wrong answer: a subnet with no
# explicit route-table association uses the VPC MAIN table, and one with no explicit NACL
# association uses the DEFAULT NACL, which allows everything. CAVEAT: the walk decides "public
# address" from the ENI's Association.PublicIp, which an RDS-MANAGED interface may lack even
# while the endpoint resolves publicly - RDS allocates from EC2's public pool and surfaces it in
# `aws ec2 describe-addresses` with service_managed = "rds". Treat its "no-public-address" line
# as INCONCLUSIVE here and read its route line; the verdict above is the RDS-specific half.
for SG in $SGS; do bash tools/sg_reachability.sh "$SG" "$REGION"; done

if [ "$PUB" = "true" ] && [ "$OPEN" = "1" ]; then
  echo "[FAIL] LIVE EXPOSURE - addressable AND permitted. Escalate to Critical and go to §3."
elif [ "$PUB" = "true" ]; then
  echo "[i] addressable, no permitting ingress found. Still fix it: the next rule added to any"
  echo "    attached group exposes the database with no further change."
else
  echo "[OK] $DB_ID is not publicly accessible"
fi
```

`[FAIL] LIVE EXPOSURE` is the only line that changes the severity; every other outcome is a
finding to fix rather than an incident to page on. Carry the security-group IDs into §3 Step 1.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="AccessDenied CreateDBCluster CreateDBInstance CreateDBInstanceReadReplica CreateDBShardGroup ModifyDBInstance NotAuthorized RestoreDBClusterFromSnapshot"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "ec2.amazonaws.com") |
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

Close the firewall before you touch the database: revoking an ingress rule is instantaneous,
while `modify-db-instance --no-publicly-accessible --apply-immediately` takes time to apply and
does nothing about sessions already established. **Capture the security group's rules before
revoking them** — the revoke deletes the record of what was open, and §6's RCA needs it.

> Run under the **break-glass responder credentials** from §1. **Check first whether the group
> is shared** — `aws ec2 describe-network-interfaces --filters Name=group-id,Values=$SG_ID` — and
> if it fronts anything besides this database, move the database to a new restrictive group with
> `modify-db-instance --vpc-security-group-ids` instead of revoking from the shared one.

#### Step 1 — Close the network path, after preserving what it was

```bash
REGION="us-east-1"
DB_ID="<db-identifier-from-Query-1>"
SG_ID="<security-group-id-from-Query-2>"

EVIDENCE=$(aws ec2 describe-security-group-rules --region "$REGION" \
             --filters Name=group-id,Values="$SG_ID" --output json)
if [ -z "$EVIDENCE" ]; then
  echo "[!] INCONCLUSIVE - could not read $SG_ID. Do NOT revoke blind: capture the rules first."
  exit 1
fi
printf '%s' "$EVIDENCE" > "./evidence-${SG_ID}-$(date -u +%Y%m%dT%H%M%SZ).json"
echo "[OK] rules for $SG_ID preserved"

# Revoke only the unrestricted rules, one rule ID at a time, so a failure on one is visible
# rather than swallowed by a bulk call.
for RID in $(printf '%s' "$EVIDENCE" | jq -r '.SecurityGroupRules[] | select(.IsEgress == false) |
      select((.CidrIpv4 // "") | endswith("/0") or ((.CidrIpv6 // "") | endswith("/0"))) |
      .SecurityGroupRuleId'); do
  aws ec2 revoke-security-group-ingress --region "$REGION" \
    --group-id "$SG_ID" --security-group-rule-ids "$RID" \
    && echo "[OK] revoked $RID" || echo "[FAIL] revoke of $RID did not succeed"
done

# The durable fix. Applied immediately rather than at the maintenance window; clients holding a
# cached DNS answer for the public address keep it until their TTL expires.
aws rds modify-db-instance --db-instance-identifier "$DB_ID" --region "$REGION" \
  --no-publicly-accessible --apply-immediately \
  && echo "[OK] publiclyAccessible set to false; verify in §5, not here - the change is async" \
  || echo "[FAIL] modify-db-instance did not succeed - the database is still addressable"
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["rds:ModifyDBInstance","rds:CreateDBInstance","rds:CreateDBInstanceReadReplica","rds:RestoreDBInstanceFromDBSnapshot","rds:ModifyDBSnapshotAttribute","ec2:AuthorizeSecurityGroupIngress"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyRdsExposure" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyRdsExposure" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied RDS exposure APIs for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or a"
     echo "    service principal. Contain manually; neither branch above applies.";;
esac
```

---

## 4. Eradication

### Remove Attacker Access

- **Rotate the master credentials and every application credential stored in the database.**
  The endpoint was reachable and RDS records no connection attempt in CloudTrail, so you cannot
  prove nobody authenticated; rotation is the only step that survives that uncertainty. Do it
  before removing the emergency deny, which covers `rds:ModifyDBInstance` and the master password.
- **Sweep the account, not just this database.** Run Query 2's logic over every instance where
  `PubliclyAccessible` is true, and fix the DB **subnet group** rather than the instances — the
  `default` group re-creates the problem on the next deploy, so the module must set
  `publicly_accessible = false` and name a non-default subnet group explicitly.
- **Right-size the permission.** Neither `rds:ModifyDBInstance` nor
  `ec2:AuthorizeSecurityGroupIngress` is needed by any workload at runtime.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyRdsExposure EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyRdsExposure"
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

#### Verify the database is private, and that nothing left by another door

```bash
REGION="us-east-1"; DB_ID="<db-identifier-from-Query-1>"; VERDICT="clean"

INST=$(aws rds describe-db-instances --db-instance-identifier "$DB_ID" --region "$REGION" --output json)
PUB=$(printf '%s' "$INST" | jq -r '.DBInstances[0].PubliclyAccessible // empty')
PENDING=$(printf '%s' "$INST" | jq -r '.DBInstances[0].PendingModifiedValues // {} | keys | join(",")')
if [ -z "$PUB" ]; then
  echo "[!] INCONCLUSIVE - no PubliclyAccessible returned. describe-db-instances always returns"
  echo "    one, so an empty value is a failed call, not a private database."; VERDICT="inconclusive"
elif [ "$PUB" = "true" ]; then
  echo "[FAIL] $DB_ID is STILL publicly accessible (pending: ${PENDING:-none})"; VERDICT="fail"
else
  echo "[OK] $DB_ID is not publicly accessible"
fi

# A private instance says NOTHING about the snapshots taken while it was public. A snapshot
# shared with `all` is a full readable copy that survives every step above, and flipping the
# instance flag does not touch it. This is the check that gets skipped.
SNAPS=$(aws rds describe-db-snapshots --region "$REGION" --db-instance-identifier "$DB_ID" \
          --snapshot-type manual --output json)
if [ -z "$SNAPS" ]; then
  echo "[!] INCONCLUSIVE - could not list manual snapshots; their sharing is unknown"
  VERDICT="inconclusive"
else
  for SNAP in $(printf '%s' "$SNAPS" | jq -r '.DBSnapshots[].DBSnapshotIdentifier'); do
    ATTR=$(aws rds describe-db-snapshot-attributes --db-snapshot-identifier "$SNAP" \
             --region "$REGION" --output json)
    if [ -z "$ATTR" ]; then
      echo "[!] INCONCLUSIVE - could not read attributes of $SNAP"; VERDICT="inconclusive"; continue
    fi
    SHARED=$(printf '%s' "$ATTR" | jq -r '[.DBSnapshotAttributesResult.DBSnapshotAttributes[]?
      | select(.AttributeName == "restore") | .AttributeValues[]?] | join(",")')
    case "$SHARED" in
      "")    echo "[OK] $SNAP is not shared with anyone";;
      *all*) echo "[FAIL] $SNAP is PUBLIC - readable by every AWS account. Go to"
             echo "        ../rds.exfiltration.snapshot-made-public/ before closing"; VERDICT="fail";;
      *)     echo "[FAIL] $SNAP is shared with: $SHARED"; VERDICT="fail";;
    esac
  done
fi
case "$VERDICT" in
  clean)        echo "[OK] $DB_ID is private and none of its manual snapshots is shared";;
  fail)         echo "[FAIL] recovery is not complete - see the lines above";;
  inconclusive) echo "[!] INCONCLUSIVE - at least one check could not run. Do not close on this.";;
esac
```

Every branch stays reachable after the remediation: `describe-db-instances` keeps returning
`PubliclyAccessible` whatever its value, and nothing in §3 or §4 touches the snapshot attribute
list — which is why it belongs here. Confirming the flag is `false` proves nothing about a copy
of the database that left while it was `true`.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     CreateDBInstance, no errorCode, responseElements.publiclyAccessible"
echo "  = true - INCLUDING the case where requestParameters carries no publiclyAccessible at all"
echo "  because dBSubnetGroupName was absent or 'default'. Also ModifyDBInstance with"
echo "  requestParameters.publiclyAccessible = true."
echo "MUST NOT fire on: the same calls by an allowlisted lifecycle principal; any call returning"
echo "  AccessDeniedException or NotAuthorized (that is the separate medium rule); ModifyDBCluster,"
echo "  which has no publiclyAccessible parameter and never could."
echo "EXPECTED FP, by design: a deliberately public read replica provisioned outside the pipeline."
echo "  Rare - and if it is not rare here, database lifecycle is not owned by the pipeline."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the pipeline could make a production database internet-addressable | `rds:ModifyDBInstance` granted to a runtime identity; no SCP confining database lifecycle |
| The database was public and nobody noticed until an alert fired days later | AWS Config `rds-instance-public-access-check` not deployed, or deployed without `rds-instance-subnet-igw-check`, so the network half was never evaluated |
| Nobody could say whether anything connected | VPC Flow Logs off on the database's ENI and the engine audit log not published to CloudWatch Logs. RDS connection attempts are not CloudTrail events, so there is no fallback |
| The exposure came back on the next deploy | The module omitted `publicly_accessible` and the DB subnet group, and AWS's documented default for a non-Aurora instance with no subnet group is `true` |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike, not StringNotEquals: the value is wildcarded, and * expands only in Resource
// and in the *Like operators. Deny + StringNotEquals against a wildcarded ARN matches every
// principal and denies database lifecycle outright - an outage, not a bypass.
{
  "Effect": "Deny",
  "Action": ["rds:ModifyDBInstance", "rds:CreateDBInstance", "rds:CreateDBInstanceReadReplica",
             "rds:RestoreDBInstanceFromDBSnapshot", "ec2:AuthorizeSecurityGroupIngress"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy",
                                            "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- **The SCP gates the principal, not the parameter — a limitation, not a choice.** No condition
  key for `PubliclyAccessible` could be confirmed in the RDS service-authorization reference (the
  page would not render for retrieval), so this playbook does not claim one exists. Verify before
  assuming an SCP can deny the flag directly; until then the parameter-level control is AWS
  Config `rds-instance-public-access-check` in **proactive** mode.
- Give every database an explicit, non-`default` DB subnet group built from private subnets. That
  removes the documented default-true path entirely and is the only control here that works when
  nobody is watching.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1578.005 — Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations (primary); T1133 — External Remote Services (secondary) |
| Primary API | `rds:ModifyDBInstance` / `rds:CreateDBInstance` and the restore family; `ec2:AuthorizeSecurityGroupIngress` as the other half |
| Event source | `rds.amazonaws.com`, **management** plane, regional — verified against AWS's RDS CloudTrail documentation and its published sample event |
| Key discriminator | `publiclyAccessible: true` **in the response**. The request settles a modify, the response settles a create — a create can omit the field and inherit AWS's documented default-true |
| Field shape | `requestParameters.publiclyAccessible`, `requestParameters.dBInstanceIdentifier`; `responseElements` is **flat** — `responseElements.publiclyAccessible`, `.dBInstanceArn`, `.vpcSecurityGroups[].vpcSecurityGroupId`, `.dBSubnetGroup.subnets[].subnetIdentifier`. `responseElements.endpoint` is **absent** while status is `creating`. `PendingModifiedValues` does **not** carry `PubliclyAccessible` |
| "Was it used" pivot | Not answerable from CloudTrail: RDS connection attempts are not CloudTrail events at any level, and the only RDS data-event type is `AWS::RDS::DBCluster` for the RDS Data API. Use VPC Flow Logs on the instance's ENI and the engine's audit log in CloudWatch Logs; if both were off, record it as unknown |
| Blast radius | Every row in the database, any credential stored in it, and the engine's own attack surface. `aws ec2 describe-addresses` shows the allocated public address with `service_managed` = `rds` |
| Error strings | Denials: `AccessDeniedException` (403) and `NotAuthorized` (401); the bare `AccessDenied` form is **not** documented for RDS and `Client.UnauthorizedOperation` is EC2's. `ModifyDBInstance`: `InvalidDBInstanceState`, `DBInstanceNotFound`, `InvalidVPCNetworkStateFault`, `InvalidDBSecurityGroupState`, `DBInstanceAlreadyExists`, `DBParameterGroupNotFound`, `DBSecurityGroupNotFound`, `DBUpgradeDependencyFailure`, `InsufficientDBInstanceCapacity`, `StorageQuotaExceeded`, `StorageTypeNotSupported`, `ProvisionedIopsNotAvailableInAZFault`, `OptionGroupNotFoundFault`, `AuthorizationNotFound`, `CertificateNotFound`, `DomainNotFoundFault`, `BackupPolicyNotFoundFault`, `KMSKeyNotAccessibleFault`, `InvalidDBClusterStateFault`, `NetworkTypeNotSupported`, `TenantDatabaseQuotaExceeded`, `VpcEncryptionControlViolation`. `CreateDBInstance` adds `InvalidSubnet`, `DBSubnetGroupNotFoundFault`, `DBSubnetGroupDoesNotCoverEnoughAZs`, `InstanceQuotaExceeded`, `DBClusterNotFoundFault` and drops `DBInstanceNotFound`. Common: `InvalidParameterValue`, `InvalidParameterCombination`, `ValidationError`, `ThrottlingException` |

**MITRE mapping note.** The source maps **T1530 / TA0010** — *Data from Cloud Storage* under the
Exfiltration tactic. T1530 is live but its scope is object storage, not a relational engine
reached over its native protocol, and T1530's own tactic is Collection, so the pairing
contradicts itself. Corrected to T1578.005 (the configuration change that is actually observed)
with T1133 as a genuine second mapping (an internet-reachable database endpoint is an external
remote service). T1686.001 — *Cloud Firewall* — covers the security-group half and is tagged on
the correlation document rather than on the primary rule, which observes no firewall change.

### Residual Risk

The flag is `false` and the ingress rule is gone, and neither step tells you whether anyone
connected while it was open — RDS produces no CloudTrail record of a connection at any event
level, so without VPC Flow Logs and an engine audit log that question is closed permanently as
unknown. Credential rotation is therefore not belt-and-braces; it is the only remediation that
does not depend on evidence you do not have. Anything copied out during the window is gone: a
snapshot taken while the database was public is a full copy whose sharing state is independent
of the instance's, which is why §5 checks it and why `../rds.exfiltration.snapshot-made-public/`
may outlive this incident. And the default that caused it is still the default — a create
against the `default` DB subnet group produces another public non-Aurora database tomorrow.
