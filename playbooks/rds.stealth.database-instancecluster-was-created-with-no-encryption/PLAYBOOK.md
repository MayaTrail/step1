# IR Playbook: RDS Database Created Without Encryption — A Publicly Shareable Snapshot Made Possible via `rds:CreateDBInstance`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Control failure creating an exfiltration precondition (a database exists whose snapshots can be released to every AWS account) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **Medium** for one database, **High** for three or more from one principal in a day, **Critical** where a snapshot of the unencrypted database has already been shared out. The source rates it **P2**. Medium is right for a single instance because nothing is compromised and a rule that pages on posture gets muted; High for the fan-out because that is one template defect rather than three incidents; Critical for the chain because at that point the exposure the encryption would have blocked has happened |
| MITRE Tactics | Defense Impairment, Exfiltration |
| MITRE Techniques | T1578.002 (primary), T1537 (secondary) — both verified live 2026-08-29 |
| Services in Scope | RDS, KMS, CloudTrail (management), AWS Config, IAM, Organizations (SCP), and every client holding the database's connection string |

**What the technique does:** a database is created with `storageEncrypted: false`, or — far more often — with
the parameter never sent, because AWS documents the `CreateDBInstance` default as *"By default, it
isn't encrypted."* Nothing is attacked. What now exists is a database from which a **publicly
shareable snapshot** can be produced, and AWS's sharing rules are a hard ladder: an unencrypted
snapshot can be shared with `all`; one encrypted with a customer-managed key can be shared only
with named accounts, because *"You can't use `all` as a value for that parameter in this case"*;
one encrypted with the default `aws/rds` key *"can't be shared"* at all. Encryption at rest is what
makes `../rds.exfiltration.snapshot-made-public/` impossible rather than merely detectable — and it
**cannot be turned on afterwards**: *"You can only encrypt an Amazon RDS DB instance when you create
it, not after the DB instance is created."* `ModifyDBInstance` has no `StorageEncrypted` parameter;
the API cannot express the operation. The fix is snapshot, copy under a key, restore to a **new
instance with a new endpoint**, cut over. That is downtime, and it is why this finding gets
deferred.

**Detection thesis.** The discriminator is `storageEncrypted: false` **in the response**, because
five of the seven APIs the source rule lists cannot carry the parameter in the request at all —
restores and read replicas inherit encryption from their source, so there is nothing to set and
nothing to log. The response is also the only arm that sees the ordinary case, where nobody sent
the field and AWS applied its documented unencrypted default.

> The other parameter on the same create calls is covered by
> `../rds.exfiltration.database-instancecluster-made-public/`. A database can be created public,
> unencrypted, both or neither; the two findings share an event and nothing else.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing RDS **management** events. `responseElements` is **flat**
  — AWS's published CloudTrail sample for `CreateDBInstance` carries `"storageEncrypted": false` at
  the top level with no `DBInstance` wrapper — so the path is `responseElements.storageEncrypted`.
  `requestParameters.storageEncrypted` exists on only five RDS operations: `CreateDBInstance`,
  `CreateDBCluster`, `CreateGlobalCluster`, `RestoreDBInstanceFromS3` and `RestoreDBClusterFromS3`
- **A periodic live sweep, because CloudTrail cannot answer this retrospectively.** Encryption is
  decided once and never changes, so the oldest unencrypted databases are the ones whose create
  event has aged out of every trail. Query 2 is that sweep and belongs on a schedule
- AWS Config `rds-storage-encrypted` (`RDS_STORAGE_ENCRYPTED`) in **proactive** mode,
  `rds-cluster-encrypted-at-rest` and `rds-snapshot-encrypted`. Proactive evaluation is the only
  form of this control that helps: a reactive finding is a scheduled outage, not a fix
- **A customer-managed KMS key for RDS provisioned in advance, with a key policy that already
  admits RDS**, and the connection-string owners for every database. The remediation runs through
  `CopyDBSnapshot --kms-key-id`, where `KMSKeyNotAccessibleFault` stalls migrations half-finished,
  and it ends in a new endpoint somebody has to cut over to

**Alerting (must be pre-configured)**
- **An unencrypted database created and a snapshot of it later shared out of the account → P0**
- **Three or more distinct unencrypted databases created by one principal within 24 hours → P1**

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
| P0 | An unencrypted database created and a snapshot of it later granted restore rights to another account | CloudTrail (management) | T1537 |
| P1 | Three or more **distinct** unencrypted database identifiers created by one principal within 24 hours | CloudTrail (management) | T1578.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `responseElements.storageEncrypted` false on a create or restore, no `errorCode` — and separately, the subset where `requestParameters.storageEncrypted` was **never sent**, which is unencrypted by AWS default rather than by decision | CloudTrail (management) | T1578.002 |
| P3 | AWS Config `rds-storage-encrypted` or `rds-cluster-encrypted-at-rest` turning NON_COMPLIANT | AWS Config | T1578.002 |
| P3 | `KMSKeyNotAccessibleFault` on `CopyDBSnapshot` — an encryption migration failing mid-flight, leaving the unencrypted original in service | CloudTrail (management) | T1578.002 |

### Detection Rule Quality Notes

The source rule tests a request parameter that most of its own event names do not have, and a
literal value that the common case does not produce.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Five of its seven event names cannot carry `storageEncrypted` in the request | `RestoreDBInstanceFromDBSnapshot`, `RestoreDBInstanceToPointInTime`, `RestoreDBClusterFromSnapshot`, `RestoreDBClusterToPointInTime` and `CreateDBInstanceReadReplica` **inherit** encryption from their source; the parameter is absent from all five APIs, so the request arm is dead for them and only the response arm keeps the rule alive | Make the response the primary block, the request corroboration |
| Tests for the literal `"false"` | AWS documents `CreateDBInstance` as *"By default, it isn't encrypted"*, so the ordinary case comes from a template that never sent the field — an event with no such key, which `field: "false"` does not match | Read `responseElements.storageEncrypted`, which states the outcome either way |
| `RestoreDBInstanceFromS3`, `RestoreDBClusterFromS3` and `CreateGlobalCluster` are missing | All three accept `StorageEncrypted`. The from-S3 restores are how a database arrives from outside AWS, which is when the setting is most likely wrong | Add all three |
| No account of the Aurora amplifier | *"This setting doesn't apply to Amazon Aurora DB instances. The encryption for DB instances is managed by the DB cluster."* An unencrypted three-node cluster produces four matching events for one control failure, and a per-event count reads it as four incidents | Count **distinct database identifiers**, not events |
| Priority does not move when the precondition becomes an exposure | A dev database and a production one whose snapshot has been shared are the same P2, so the second arrives in a queue tuned for the first | Ship the `temporal_ordered` correlation at `critical` |

**Recommended detection — a database created into an unencrypted state.**

```yaml
# RDS Database Created Without Storage Encryption (T1578.002 / T1537)
#
# WHY THIS IS A SECURITY USE CASE AND NOT A COMPLIANCE ONE. An unencrypted database is the
# PRECONDITION for the worst exfiltration path RDS offers. AWS: "If the manual DB snapshot is
# encrypted, it can be shared, but only by specifying a list of authorized AWS account IDs for
# the ValuesToAdd parameter. You can't use `all` as a value for that parameter in this case."
# And separately: "Snapshots that have been encrypted with the default AWS KMS key can't be
# shared." So the three states are not on a spectrum - they are a hard ladder:
#
#   unencrypted                -> a snapshot can be made PUBLIC to every AWS account
#   customer-managed key       -> a snapshot can be shared with NAMED accounts only
#   default aws/rds key        -> a snapshot cannot be shared AT ALL
#
# Encryption at rest is therefore the control that makes ../../rds.exfiltration.snapshot-made-public/
# impossible rather than merely detectable. That is the reason this rule exists, and it is the
# reason its severity is not a compliance severity.
#
# WHAT THE SOURCE RULE DOES, AND WHY FIVE OF ITS SEVEN EVENT NAMES CANNOT MATCH ON THE REQUEST.
# It lists CreateDBInstance, CreateDBInstanceReadReplica, RestoreDBInstanceFromDBSnapshot,
# RestoreDBInstanceToPointInTime, CreateDBCluster, RestoreDBClusterFromSnapshot and
# RestoreDBClusterToPointInTime, and tests requestParameters.storageEncrypted OR
# responseElements.storageEncrypted for "false".
#
# `StorageEncrypted` is a request parameter of only FIVE RDS operations: CreateDBInstance,
# CreateDBCluster, CreateGlobalCluster, RestoreDBInstanceFromS3 and RestoreDBClusterFromS3.
# It is absent from every restore-from-snapshot and point-in-time API and from
# CreateDBInstanceReadReplica, because those INHERIT encryption from their source and there is
# nothing to set. So the request arm of the source rule is dead for five of its seven names, and
# the rule survives only on its response arm - which is correct, and which is the arm to build on.
#
# TWO NAMES ARE ALSO MISSING: RestoreDBInstanceFromS3 and RestoreDBClusterFromS3 both accept
# StorageEncrypted and neither is covered. CreateGlobalCluster likewise.
#
# ABSENCE IS NOT FALSE, EXCEPT WHEN IT IS. AWS documents the CreateDBInstance default as "By
# default, it isn't encrypted", so a create that never mentions StorageEncrypted produces an
# unencrypted database - and an event whose requestParameters contain no such key. A rule testing
# only for the literal "false" misses the ordinary case. The response settles it either way, which
# is why the response block below is the primary one and the request block is corroboration.
#
# THE AURORA AMPLIFIER. AWS: "This setting doesn't apply to Amazon Aurora DB instances. The
# encryption for DB instances is managed by the DB cluster." An unencrypted three-node Aurora
# cluster therefore produces FOUR matching events - one CreateDBCluster and three
# CreateDBInstance - for a single control failure. Group by database identifier before you count,
# and treat the cluster event as the finding.
#
# FIELD SHAPE. eventSource `rds.amazonaws.com`, management plane, regional. `responseElements` is
# FLAT: AWS's own published CloudTrail sample for CreateDBInstance carries `"storageEncrypted":
# false` at the top level, with no DBInstance wrapper. Note also that the SNAPSHOT data types name
# the same idea differently - DBSnapshot uses `Encrypted`, DBClusterSnapshot uses
# `StorageEncrypted` - so a sweep written against one shape returns null against the other.
title: RDS database created without storage encryption
id: 239904d2-175f-4830-93cb-b18f81c9fe00
name: rds_created_without_encryption
status: experimental
description: >-
  A DB instance, cluster or global cluster was created or restored into an unencrypted state -
  by an explicit storageEncrypted of false, or by omitting it and taking AWS's documented
  unencrypted default. Snapshots of this database can be shared with every AWS account.
references:
  - https://attack.mitre.org/techniques/T1578/002/                                          # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html      # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html          # retrieved 2026-08-29
tags:
  - attack.defense-impairment
  - attack.exfiltration
  - attack.t1578.002
  - attack.t1537
logsource:
  product: aws
  service: cloudtrail
detection:
  # The restore and read-replica APIs cannot carry storageEncrypted in the REQUEST - they inherit
  # from their source - so they are matched on the response only. RestoreDBInstanceFromS3,
  # RestoreDBClusterFromS3 and CreateGlobalCluster do accept it and the source rule omits them.
  selection:
    eventSource: 'rds.amazonaws.com'
    eventName:
      - 'CreateDBInstance'
      - 'CreateDBCluster'
      - 'CreateGlobalCluster'
      - 'CreateDBInstanceReadReplica'
      - 'RestoreDBInstanceFromDBSnapshot'
      - 'RestoreDBInstanceToPointInTime'
      - 'RestoreDBInstanceFromS3'
      - 'RestoreDBClusterFromSnapshot'
      - 'RestoreDBClusterToPointInTime'
      - 'RestoreDBClusterFromS3'
  # PRIMARY. The service states the outcome, whether or not the caller expressed an opinion.
  # Pipelines that index CloudTrail booleans as the STRING "false" need 'false' added here.
  unencrypted_result:
    responseElements.storageEncrypted: false
  # CORROBORATION, and the only arm that works when the response is not captured.
  unencrypted_requested:
    requestParameters.storageEncrypted: false
  success:
    errorCode: null
  condition: selection and success and (unencrypted_result or unencrypted_requested)
falsepositives:
  - >-
    An Aurora member instance in an unencrypted cluster. Real, but not a separate finding - the
    cluster is the finding and its members repeat it. Deduplicate by cluster identifier.
  - >-
    A short-lived test database on an instance class that does not support encryption at all
    (db.m1.*, db.m2.*, db.t2.micro). The finding there is the instance class, not the flag.
level: medium
---
# Base rule — sequence component only, not for direct alerting. Fires on any snapshot leaving the
# account, which is the event that turns an unencrypted database from a posture finding into an
# exfiltration. Deliberately narrower than the equivalent rule in
# ../../rds.exfiltration.snapshot-made-public/: this one does not care WHO the recipient is,
# because in this playbook the question is only whether the unencrypted data left.
title: RDS snapshot restore attribute granted to another account
id: c0201851-a70f-4dc0-b800-2250e9ac5748
name: rds_snapshot_shared_out_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBSnapshotAttribute.html  # retrieved 2026-08-29
tags:
  - attack.exfiltration
  - attack.t1537
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'rds.amazonaws.com'
    eventName:
      - 'ModifyDBSnapshotAttribute'
      - 'ModifyDBClusterSnapshotAttribute'
  share_attribute:
    requestParameters.attributeName: 'restore'
  values_absent:
    requestParameters.valuesToAdd: null
  success:
    errorCode: null
  condition: selection and share_attribute and success and not values_absent
level: informational
---
# THE LADDER, REALISED. A principal that creates an unencrypted database and then shares a
# snapshot out of the account has walked the exact path AWS's encryption rules exist to block: an
# encrypted database could not have produced a snapshot shareable with `all`, and a default-key
# one could not have produced a shareable snapshot at all.
#
# SEVEN DAYS is deliberately long and is a trade. The causal link is real but slow - provision,
# populate, snapshot, share - and no shorter window captures it. The cost is that correlation
# engines hold state for a week and that an unrelated pairing inside seven days will occasionally
# compose. Treat a hit as a question about one principal's week, not as a proven sequence, and use
# the join in kql_t1578_002.kql, which matches the SNAPSHOT back to the unencrypted database
# rather than relying on the principal alone.
title: Unencrypted RDS database created and a snapshot then shared out of the account
id: dd55737a-710a-4393-b826-71fb5bfe6402
status: experimental
description: >-
  One principal created an unencrypted database and later granted another account restore rights
  on a snapshot. Encryption at rest would have made the second step impossible or account-limited;
  its absence is what allowed it.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html   # retrieved 2026-08-29
tags:
  - attack.exfiltration
  - attack.t1537
correlation:
  type: temporal_ordered
  rules:
    - rds_created_without_encryption
    - rds_snapshot_shared_out_bb
  group-by:
    - userIdentity.arn
  timespan: 7d
level: critical
---
# THRESHOLD BASIS, with no observed baseline to derive one from. One unencrypted database is a
# mistake; three by one principal inside a day is a module or a template, and the response is to
# fix the code once rather than to migrate three databases three times. Counted on the DATABASE
# IDENTIFIER rather than on events, so an unencrypted Aurora cluster and its member instances do
# not reach the threshold on their own - that amplification is documented above and is exactly the
# false signal a per-event count would produce. `gte` at the baseline, never `gt`.
title: Multiple unencrypted RDS databases created by one principal
id: 35c8e712-63a9-4e80-9cea-b6ec6ecb75a9
status: experimental
description: >-
  One principal created three or more distinct unencrypted databases within a day. This is a
  systemic defect in whatever produced them, not three separate incidents.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html   # retrieved 2026-08-29
tags:
  - attack.defense-impairment
  - attack.t1578.002
correlation:
  type: value_count
  rules:
    - rds_created_without_encryption
  group-by:
    - userIdentity.arn
  field: responseElements.dBInstanceIdentifier
  timespan: 24h
  condition:
    gte: 3
level: high
```

The rule cannot find a database created before your CloudTrail retention began, and those are the
ones most likely to be unencrypted — the setting is immutable, so the oldest resources carry the
oldest defaults. Only the live sweep in Query 2 finds them.
`detections/kql_t1578_002.kql` adds the two distinctions Sigma cannot draw: explicit `false` versus
an omission, and an Aurora member instance versus its cluster.

---

### Key Investigation Queries

> RDS is regional — run these in each region the account uses. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: which databases were created unencrypted, and did anyone choose it

```bash
REGION="us-east-1"
EVENTS="CreateDBInstance CreateDBCluster CreateGlobalCluster CreateDBInstanceReadReplica RestoreDBInstanceFromDBSnapshot RestoreDBInstanceToPointInTime RestoreDBInstanceFromS3 RestoreDBClusterFromSnapshot RestoreDBClusterToPointInTime RestoreDBClusterFromS3"
RAW=$(for EV in $EVENTS; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region, or"
  echo "    missing cloudtrail:LookupEvents. This is NOT 'everything is encrypted'."
else
  # responseElements is FLAT for RDS. `requested` distinguishes an explicit false from an omission;
  # "not-in-request" plus returned:false is AWS's documented default, which is the ordinary case
  # and the one the source rule cannot see.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "rds.amazonaws.com") |
    {time: .eventTime, event: .eventName, region: .awsRegion,
     caller_arn: .userIdentity.arn, access_key: .userIdentity.accessKeyId,
     db_identifier: (.responseElements.dBInstanceIdentifier //
                     .responseElements.dBClusterIdentifier //
                     .requestParameters.dBInstanceIdentifier //
                     .requestParameters.dBClusterIdentifier //
                     .requestParameters.globalClusterIdentifier // "unknown"),
     cluster: (.responseElements.dBClusterIdentifier // null),
     engine: (.responseElements.engine // .requestParameters.engine // null),
     instance_class: (.responseElements.dBInstanceClass // .requestParameters.dBInstanceClass // null),
     requested: (.requestParameters.storageEncrypted // "not-in-request"),
     returned:  (.responseElements.storageEncrypted  // "not-in-response"),
     kms_key: (.responseElements.kmsKeyId // .requestParameters.kmsKeyId // "none"),
     db_arn: (.responseElements.dBInstanceArn // .responseElements.dBClusterArn // null),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent} |
    select(.requested == false or .returned == false)' |
  jq -s 'sort_by(.time)'
fi
```

`requested: false` is a decision and the question is why. `requested: "not-in-request"` with
`returned: false` is an omission whose owner is the template rather than the person who ran it —
two different follow-ups. An `instance_class` of `db.m1.*`, `db.m2.*` or `db.t2.micro` cannot be
encrypted at all, so the finding there is the class. Rows sharing a `cluster` are Aurora members
repeating their cluster's state. Carry `db_identifier` into Query 2 and §3.

#### Query 2 — Sweep the account: what is unencrypted now, and has any of it already left

```bash
REGION="us-east-1"
INST=$(aws rds describe-db-instances --region "$REGION" --output json)
CLUS=$(aws rds describe-db-clusters --region "$REGION" --output json)
if [ -z "$INST" ] || [ -z "$CLUS" ]; then
  echo "[!] INCONCLUSIVE - a describe call returned nothing at all. Not an empty fleet: a failed"
  echo "    call, a wrong region or a missing permission. Do not report this region as clean."
else
  printf '%s' "$INST" | jq -r '.DBInstances[] | select(.StorageEncrypted == false) |
    "[FAIL] instance  \(.DBInstanceIdentifier)  engine=\(.Engine)  class=\(.DBInstanceClass)  cluster=\(.DBClusterIdentifier // "standalone")"'
  printf '%s' "$CLUS" | jq -r '.DBClusters[] | select(.StorageEncrypted == false) |
    "[FAIL] cluster   \(.DBClusterIdentifier)  engine=\(.Engine)"'
  NI=$(printf '%s' "$INST" | jq '[.DBInstances[] | select(.StorageEncrypted == false)] | length')
  NC=$(printf '%s' "$CLUS" | jq '[.DBClusters[] | select(.StorageEncrypted == false)] | length')
  [ "$NI" -eq 0 ] && [ "$NC" -eq 0 ] && echo "[OK] every instance and cluster in $REGION is encrypted"
fi

# The snapshots are the part that can leave, and the two data types NAME THE FLAG DIFFERENTLY:
# DBSnapshot exposes `Encrypted`, DBClusterSnapshot exposes `StorageEncrypted`. Querying one shape
# against the other returns null - which is not false, it is a field that does not exist there.
SN=$(aws rds describe-db-snapshots --snapshot-type manual --region "$REGION" --output json)
if [ -z "$SN" ]; then
  echo "[!] INCONCLUSIVE - the snapshot listing returned nothing; sharing state unchecked"
else
  for S in $(printf '%s' "$SN" | jq -r '.DBSnapshots[] | select(.Encrypted == false) | .DBSnapshotIdentifier'); do
    A=$(aws rds describe-db-snapshot-attributes --db-snapshot-identifier "$S" --region "$REGION" --output json)
    if [ -z "$A" ]; then
      echo "[!] INCONCLUSIVE - could not read attributes of unencrypted snapshot $S"; continue
    fi
    V=$(printf '%s' "$A" | jq -r '[.DBSnapshotAttributesResult.DBSnapshotAttributes[]?
          | select(.AttributeName == "restore") | .AttributeValues[]?] | join(",")')
    case "$V" in
      "")    echo "[i] unencrypted snapshot $S is not shared";;
      *all*) echo "[FAIL] unencrypted snapshot $S is PUBLIC - go to ../rds.exfiltration.snapshot-made-public/";;
      *)     echo "[FAIL] unencrypted snapshot $S is shared with: $V";;
    esac
  done
fi
# Repeat the block above with describe-db-cluster-snapshots, `.DBClusterSnapshots[]`, the
# StorageEncrypted flag and describe-db-cluster-snapshot-attributes. Aurora snapshots are a
# separate API with a separate flag name and are routinely forgotten.
```

An unencrypted snapshot that is shared is no longer a posture finding; it is the incident next
door, and this playbook stops being the right one. An unencrypted snapshot that is **not** shared
is the thing to delete first in §3, because it is the shortest path from this finding to that one.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="CreateDBCluster CreateDBInstance CreateDBInstanceReadReplica CreateGlobalCluster ModifyDBClusterSnapshotAttribute ModifyDBSnapshotAttribute RestoreDBClusterFromS3 RestoreDBClusterFromSnapshot"
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

There is nothing to contain on the database itself — encryption cannot be switched on and the data
is not going anywhere. Containment means **closing the path from this precondition to the exposure
it enables**: stop snapshots of it being shared, and delete the unshared unencrypted snapshots that
already exist. Only then look at who created it, distinguishing a bad template from a bad actor
before treating anyone as either.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Close the sharing path and remove the unencrypted snapshots

```bash
REGION="us-east-1"; DB_ID="<db-identifier-from-Query-1>"
SNAPS=$(aws rds describe-db-snapshots --db-instance-identifier "$DB_ID" --snapshot-type manual \
          --region "$REGION" --output json)
if [ -z "$SNAPS" ]; then
  echo "[!] INCONCLUSIVE - could not list manual snapshots of $DB_ID. Do not proceed as if there"
  echo "    are none; an unlisted unencrypted snapshot is the whole risk here."
else
  for S in $(printf '%s' "$SNAPS" | jq -r '.DBSnapshots[].DBSnapshotIdentifier'); do
    A=$(aws rds describe-db-snapshot-attributes --db-snapshot-identifier "$S" --region "$REGION" --output json)
    V=$(printf '%s' "$A" | jq -r '[.DBSnapshotAttributesResult.DBSnapshotAttributes[]?
          | select(.AttributeName == "restore") | .AttributeValues[]?] | join(" ")')
    if [ -z "$A" ]; then
      echo "[!] INCONCLUSIVE - attributes of $S unreadable; neither revoked nor confirmed clean"
    elif [ -n "$V" ]; then
      echo "[FAIL] $S is shared with: $V - revoke it with ../rds.exfiltration.snapshot-made-public/"
      echo "       and CAPTURE THE RECIPIENT LIST FIRST; the revoke erases it."
    else
      aws rds delete-db-snapshot --db-snapshot-identifier "$S" --region "$REGION" >/dev/null \
        && echo "[OK] deleted unshared unencrypted snapshot $S" \
        || echo "[FAIL] could not delete $S - it remains shareable"
    fi
  done
fi
```

#### Step 2 — Freeze what produced it, and contain the principal only if it was a principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
# An unencrypted database is far more often a template defect than an act. Contain the identity
# only when Query 1 shows an EXPLICIT storageEncrypted:false from an interactive session; an
# omission by a pipeline role is a code change, and disabling the deploy role causes an outage
# while fixing nothing.
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["rds:ModifyDBSnapshotAttribute","rds:ModifyDBClusterSnapshotAttribute","rds:CreateDBInstance","rds:CreateDBCluster"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyUnencryptedRds" --policy-document "$DENY" \
      && echo "[OK] denied unencrypted-create and snapshot sharing for user $U" \
      || echo "[FAIL] could not attach the deny to $U";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyUnencryptedRds" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied unencrypted creates for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or a"
     echo "    service principal. Contain manually; neither branch above applies.";;
esac
```

---

## 4. Eradication

### Remove Attacker Access

### The migration, and what it costs

**Encryption cannot be enabled in place.** AWS: *"You can only encrypt an Amazon RDS DB instance
when you create it, not after the DB instance is created"*, *"You can't create an encrypted
snapshot of an unencrypted DB instance"*, and *"You can't restore from a DB snapshot to an existing
DB instance; you create a new DB instance when you restore the snapshot."* `ModifyDBInstance` has no
`StorageEncrypted` parameter at all — the API cannot express the operation.

So the fix is snapshot, copy under a key, restore to a **new instance with a new endpoint**, cut
over, and delete the original. **That is a maintenance window with a connection-string change in
every client**, and saying so plainly is part of the remediation: a fix presented as a
configuration change and delivered as an outage is a fix that gets deferred forever.

```bash
REGION="us-east-1"; DB_ID="<db-identifier-from-Query-1>"
KMS_KEY="<customer-managed-key-arn>"
SNAP="${DB_ID}-preenc-$(date -u +%Y%m%d%H%M)"; ENC_SNAP="${SNAP}-encrypted"; NEW_ID="${DB_ID}-enc"

aws rds create-db-snapshot --db-instance-identifier "$DB_ID" --db-snapshot-identifier "$SNAP" \
  --region "$REGION" >/dev/null || { echo "[FAIL] snapshot of $DB_ID failed; stop here"; exit 1; }
aws rds wait db-snapshot-available --db-snapshot-identifier "$SNAP" --region "$REGION"

# The copy is where encryption is added, and KMSKeyNotAccessibleFault here is the most common way
# this migration stalls with the unencrypted original still serving traffic. The copy needs
# kms:DescribeKey, kms:CreateGrant, kms:Decrypt, kms:Encrypt, kms:GenerateDataKey,
# kms:GenerateDataKeyWithoutPlaintext and kms:ReEncrypt on $KMS_KEY.
OUT=$(aws rds copy-db-snapshot --source-db-snapshot-identifier "$SNAP" \
        --target-db-snapshot-identifier "$ENC_SNAP" --kms-key-id "$KMS_KEY" \
        --region "$REGION" --output json 2>&1)
case "$OUT" in
  *KMSKeyNotAccessible*) echo "[FAIL] the key policy on $KMS_KEY does not admit RDS. Fix it before"
                         echo "       retrying - the unencrypted original is still in service."; exit 1;;
  *DBSnapshot*)          echo "[OK] encrypted copy $ENC_SNAP created";;
  *)                     echo "[!] INCONCLUSIVE - unexpected copy-db-snapshot output: $OUT"; exit 1;;
esac
aws rds wait db-snapshot-available --db-snapshot-identifier "$ENC_SNAP" --region "$REGION"

# A restore takes the DEFAULT VPC security group, DB subnet group, parameter group and option group
# unless each is passed explicitly. Omitting them silently drops the hardening the original had -
# read them off the original and pass them here.
aws rds restore-db-instance-from-db-snapshot --db-instance-identifier "$NEW_ID" \
  --db-snapshot-identifier "$ENC_SNAP" --region "$REGION" \
  --db-subnet-group-name "<subnet-group-from-the-original>" \
  --vpc-security-group-ids "<security-group-from-the-original>" \
  --db-parameter-group-name "<parameter-group-from-the-original>" \
  --no-publicly-accessible >/dev/null \
  && echo "[OK] restoring $NEW_ID from the encrypted copy - NEW ENDPOINT, cut clients over" \
  || echo "[FAIL] restore did not start; the migration is incomplete"
```

### Then, and only after the cutover is verified

- **Delete the plaintext intermediate snapshot `$SNAP`.** It is unencrypted and shareable, and it
  exists only because AWS refuses to make an encrypted snapshot of an unencrypted database.
- **Delete the original instance — and control its final snapshot.** `DeleteDBInstance` takes a
  final snapshot unless `--skip-final-snapshot` is passed, and a final snapshot of an unencrypted
  database is itself **unencrypted and shareable**. Deleting the problem this way creates one more
  copy of it. Pass `--skip-final-snapshot` once the encrypted restore is verified, or take the
  final snapshot deliberately and delete it after.
- **Fix the template, not the instance.** Set `storage_encrypted = true` and a `kms_key_id`
  explicitly in the module. The next database inherits AWS's unencrypted default otherwise.
- **Remove the emergency policies once clean, and assert it** — both branches:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyUnencryptedRds EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyUnencryptedRds"
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

#### Verify the replacement is encrypted and the unencrypted originals are gone

```bash
REGION="us-east-1"; NEW_ID="<new-instance-identifier>"; OLD_ID="<db-identifier-from-Query-1>"
VERDICT="clean"

NEW=$(aws rds describe-db-instances --db-instance-identifier "$NEW_ID" --region "$REGION" --output json)
ENC=$(printf '%s' "$NEW" | jq -r '.DBInstances[0].StorageEncrypted // empty')
KEY=$(printf '%s' "$NEW" | jq -r '.DBInstances[0].KmsKeyId // empty')
if [ -z "$ENC" ]; then
  echo "[!] INCONCLUSIVE - describe-db-instances returned no StorageEncrypted for $NEW_ID. It"
  echo "    always returns one, so an empty value is a failed call, not an unencrypted database."
  VERDICT="inconclusive"
elif [ "$ENC" != "true" ]; then
  echo "[FAIL] the replacement $NEW_ID is NOT encrypted - the restore used the wrong snapshot"
  VERDICT="fail"
elif [ -z "$KEY" ]; then
  echo "[FAIL] $NEW_ID reports encrypted with no KmsKeyId; treat as unverified"
  VERDICT="fail"
else
  echo "[OK] $NEW_ID is encrypted under $KEY"
fi

# describe-db-instances on a DELETED identifier errors with DBInstanceNotFound, which is the
# success condition here - so the error text is read rather than suppressed, and any other error
# reaches INCONCLUSIVE rather than the clean branch.
OLD=$(aws rds describe-db-instances --db-instance-identifier "$OLD_ID" --region "$REGION" --output json 2>&1)
case "$OLD" in
  *DBInstanceNotFound*) echo "[OK] the unencrypted original $OLD_ID no longer exists";;
  *StorageEncrypted*)   echo "[FAIL] $OLD_ID is still present and serving"; VERDICT="fail";;
  *)                    echo "[!] INCONCLUSIVE - unexpected output for $OLD_ID: $OLD"; VERDICT="inconclusive";;
esac

# Every remaining unencrypted snapshot of the original, INCLUDING the final snapshot that
# DeleteDBInstance takes by default. This is the check that gets skipped, and the one that leaves a
# shareable plaintext copy behind after a migration everyone believes is finished.
SN=$(aws rds describe-db-snapshots --db-instance-identifier "$OLD_ID" --snapshot-type manual \
       --region "$REGION" --output json 2>&1)
case "$SN" in
  *DBSnapshots*)
    LEFT=$(printf '%s' "$SN" | jq -r '[.DBSnapshots[] | select(.Encrypted == false) | .DBSnapshotIdentifier] | join(" ")')
    if [ -z "$LEFT" ]; then echo "[OK] no unencrypted snapshot of $OLD_ID remains"
    else echo "[FAIL] shareable plaintext snapshot(s) of $OLD_ID remain: $LEFT"; VERDICT="fail"; fi;;
  *) echo "[!] INCONCLUSIVE - could not list snapshots of $OLD_ID: $SN"; VERDICT="inconclusive";;
esac

case "$VERDICT" in
  clean)        echo "[OK] migration complete: encrypted replacement, original gone, no plaintext snapshots";;
  fail)         echo "[FAIL] recovery is not complete - see the lines above";;
  inconclusive) echo "[!] INCONCLUSIVE - at least one check could not run. Do not close on this.";;
esac
```

Each branch stays reachable after the remediation, deliberately: `describe-db-instances` keeps
returning `StorageEncrypted` whatever its value, the deleted original produces a *specific* error
that is read rather than suppressed, and the snapshot listing survives everything in §3 and §4 —
which is why the plaintext final snapshot, the artefact this migration creates by default, cannot
hide inside an `[OK]`.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     CreateDBInstance / rds.amazonaws.com / no errorCode with"
echo "  responseElements.storageEncrypted = false - INCLUDING the case where requestParameters"
echo "  carries no storageEncrypted at all, which is AWS's documented default for non-Aurora."
echo "  Also RestoreDBInstanceFromS3 and CreateGlobalCluster, which the source rule omits."
echo "MUST NOT fire on: a create whose response reports storageEncrypted = true; any call that"
echo "  returned an errorCode; a request-arm match on RestoreDBInstanceFromDBSnapshot, which has"
echo "  no such parameter and inherits from its source."
echo "EXPECTED FP, by design: Aurora MEMBER instances of an unencrypted cluster. Real, and not a"
echo "  separate finding - the cluster is. The value_count correlation counts distinct database"
echo "  identifiers so those members cannot reach the threshold on their own."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A production database was provisioned unencrypted | The module omitted `storage_encrypted`, and AWS's documented default for a non-Aurora instance is unencrypted. Nobody chose this and nobody was asked |
| The finding was not caught before provisioning | AWS Config `rds-storage-encrypted` was absent or deployed reactively. Reactive detection of an immutable setting produces a scheduled outage, not a fix |
| The alert did not distinguish an omission from a decision | The deployed rule tested for the literal `"false"` on a request parameter that five of its own event names do not have |
| The remediation was deferred | Nobody had established that encryption cannot be enabled in place, so a change budgeted as a flag flip turned out to need a snapshot, a copy, a restore and a cutover |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike, not StringNotEquals: the value is wildcarded, and * expands only in Resource and
// in the *Like operators. Deny + StringNotEquals against a wildcarded ARN matches every principal
// and denies database creation outright - an outage, not a control.
{
  "Effect": "Deny",
  "Action": ["rds:ModifyDBSnapshotAttribute", "rds:ModifyDBClusterSnapshotAttribute"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- **The SCP above denies the sharing, not the unencrypted create, and that is deliberate.** No
  condition key gating `StorageEncrypted` could be confirmed in the RDS service-authorization
  reference — the page would not render for retrieval — so this playbook does not claim one exists.
  Verify before assuming an SCP can deny the parameter directly. Until then the parameter-level
  control is AWS Config `rds-storage-encrypted` in **proactive** mode, and the outcome-level control
  is denying the share, which is the only thing an unencrypted database actually enables.
- Provision a customer-managed KMS key for RDS in advance, with a key policy that already admits
  RDS. Every encryption migration runs through `CopyDBSnapshot --kms-key-id`, and
  `KMSKeyNotAccessibleFault` on that call is where migrations stall half-finished.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1578.002 — Modify Cloud Compute Infrastructure: Create Cloud Instance (primary); T1537 — Transfer Data to Cloud Account (secondary, for what the absence enables) |
| Primary API | `rds:CreateDBInstance` / `rds:CreateDBCluster`; `rds:CreateDBSnapshot` → `rds:CopyDBSnapshot --kms-key-id` → `rds:RestoreDBInstanceFromDBSnapshot` for the fix |
| Event source | `rds.amazonaws.com`, **management** plane, regional — verified against AWS's RDS CloudTrail documentation and its published sample event |
| Key discriminator | `responseElements.storageEncrypted` being `false`. The request parameter exists on only five RDS operations, and absence of it means unencrypted rather than unknown for non-Aurora instances |
| Field shape | `responseElements` is **flat**: `responseElements.storageEncrypted`, `.dBInstanceIdentifier`, `.dBInstanceArn`, `.kmsKeyId`. `requestParameters.storageEncrypted` exists only on `CreateDBInstance`, `CreateDBCluster`, `CreateGlobalCluster`, `RestoreDBInstanceFromS3`, `RestoreDBClusterFromS3`. **`DBSnapshot` names the flag `Encrypted`; `DBClusterSnapshot` names it `StorageEncrypted`** |
| "Was it used" pivot | Whether a snapshot of this database was shared out: `describe-db-snapshot-attributes` per manual snapshot, and the `temporal_ordered` correlation over the create-then-share chain. Unencrypted is a precondition, so the pivot asks what it *enabled*, not whether the create itself was exercised |
| Blast radius | Everything the database holds, if a snapshot of it is ever shared with `all` — which is possible only because it is unencrypted. Encryption at rest would cap the exposure at named accounts, or remove it entirely under the default `aws/rds` key |
| Error strings | `CreateDBInstance`: `DBInstanceAlreadyExists`, `InsufficientDBInstanceCapacity`, `InstanceQuotaExceeded`, `StorageQuotaExceeded`, `DBSubnetGroupNotFoundFault`, `DBSubnetGroupDoesNotCoverEnoughAZs`, `InvalidSubnet`, `InvalidVPCNetworkStateFault`, `KMSKeyNotAccessibleFault`, `StorageTypeNotSupported`, `NetworkTypeNotSupported`, `OptionGroupNotFoundFault`, `DBParameterGroupNotFound`, `DBSecurityGroupNotFound`, `AuthorizationNotFound`, `CertificateNotFound`, `DomainNotFoundFault`, `BackupPolicyNotFoundFault`, `ProvisionedIopsNotAvailableInAZFault`, `InvalidDBClusterStateFault`, `DBClusterNotFoundFault`, `TenantDatabaseQuotaExceeded`, `VpcEncryptionControlViolation`. `CopyDBSnapshot`: `DBSnapshotAlreadyExists`, `DBSnapshotNotFound`, `InvalidDBSnapshotState`, `SnapshotQuotaExceeded`, `KMSKeyNotAccessibleFault`, `CustomAvailabilityZoneNotFound`. Denials: `AccessDeniedException` (403), `NotAuthorized` (401); the bare `AccessDenied` form is **not** documented for RDS |

**MITRE mapping note.** `T1578.002 — Create Cloud Instance` (Defense Impairment) is the primary
mapping, with `T1537 — Transfer Data to Cloud Account` (Exfiltration) as the second mapping for the
enabling relationship. Both verified live 2026-08-31. Stated plainly: **ATT&CK has no technique
for "provisioned without encryption at rest."** `T1600` (*Weaken Encryption*) is live but scoped
to network devices. This pair is the closest defensible mapping and it is carried for what the
absence enables, not for what the act is.

### Residual Risk

Until the migration completes the database is exactly as exposed as it was when the alert fired,
and there is no interim mitigation — the setting is immutable and the only lever is denying the
share. Afterwards the residue is plaintext: the intermediate snapshot the copy step required, and
the final snapshot `DeleteDBInstance` takes by default, are both unencrypted, both shareable, and
both outlive the database they came from. §5 asserts on them for that reason.

Nothing here touches anything created earlier. Encryption is decided once and cannot be revisited,
so the account's oldest databases carry its oldest defaults and have no create event left in any
trail — the scheduled sweep in Query 2 is the only thing that will ever find them. And the template
that produced this one produces the next: unless `storage_encrypted` is set explicitly, AWS's
documented default applies again tomorrow.
