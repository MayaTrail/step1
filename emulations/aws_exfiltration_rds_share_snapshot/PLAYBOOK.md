# IR Playbook: RDS Snapshot Made Public — Full Offline Database Copy Released via `rds:ModifyDBSnapshotAttribute`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data exfiltration (a complete, restorable copy of the database is released to accounts outside this one — publicly, or to a named party) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **Critical** where the value added is `all`, **High** where it is a 12-digit account ID. The source rates both **P2**. Critical is right for the public case because the disclosure set is unbounded and unidentifiable and no subsequent action undoes it — there is containment of the *window*, never of the *data*. High is right for a named account because the recipient can be identified and asked, which is a materially different incident one parameter apart |
| MITRE Tactics | Exfiltration, Defense Impairment |
| MITRE Techniques | T1537 (primary), T1578.001 (secondary) — both verified live 2026-08-29 |
| Services in Scope | RDS, KMS, CloudTrail (management), IAM, Organizations (SCP), AWS Config, Security Hub, Trusted Advisor, and every system whose credentials the database held |

**What the technique does:** The actor calls `rds:ModifyDBSnapshotAttribute` — or its cluster twin
`rds:ModifyDBClusterSnapshotAttribute` — with `--attribute-name restore` and
`--values-to-add all`. One API call, one parameter, no data movement, no network egress, and
nothing in the database changes. From that second every AWS account on earth can run
`RestoreDBInstanceFromDBSnapshot` against a full, consistent, point-in-time copy of the database
and query it at leisure in their own account, on their own bill. If the value added is a
12-digit account ID instead, the same is true for that one account, up to a documented cap of
twenty. The snapshot must be a **manual** one — AWS refuses to share automated system snapshots,
directing you to *"create a manual DB snapshot by copying the automated snapshot, and then share
that copy"* — and it must not be encrypted with the default `aws/rds` key, which *"can't be
shared"* at all. Making it **public** narrows it further: AWS refuses `all` on any encrypted
snapshot. So a deliberate actor working from a protected database runs a create or a copy first,
and the correlation in §2 is built on exactly that.

**Why the usual reflexes miss it.** Every instinct trained on network exfiltration is wrong here.
There is no egress to watch: nothing leaves over a wire, so flow logs, egress filtering and
DLP see nothing. There is no S3 bucket to check, no `GetObject` to count, no bandwidth anomaly.
The single API call looks identical to the legitimate one a DBA makes to hand a snapshot to a
sibling account, and it is a `Modify*` verb in a service where `Modify*` calls are constant. The
posture controls that would catch it are all slow: AWS Config's
`rds-snapshots-public-prohibited` warns in its own documentation that *"It can take up to 12
hours for compliance results to be captured"*, Trusted Advisor's `rSs93HQwa1` refreshes on its
own schedule and cannot be refreshed on demand, and **GuardDuty does not cover this at all** —
there is no `Policy:RDS/*` finding namespace, and its nine RDS finding types are login-behaviour
detectors that fire on connections a snapshot share never makes. CloudTrail on
`ModifyDBSnapshotAttribute` is the only near-real-time signal that exists.

**Detection thesis.** The discriminator is the **contents of `requestParameters.valuesToAdd`**,
and the split inside it — `all` versus a 12-digit account ID — is the severity. The source rule
reaches for the right field and misses it twice: its share-value clause names a parser-derived
field rather than a CloudTrail path, so it is silently dead wherever that extraction is not
configured, and its response clause reads `responseElements.attributeName`, which is not a path
at all because `attributeName` lives two levels down inside `dBSnapshotAttributes[]`.

> This use case is written at **Tier 1**. The three promotion tests it meets, and the ordering
> hazard they produce, are recorded in `_source/PROVENANCE.md`. The short version: the full
> recipient list exists only in live state, the remediation destroys it, and consumption of the
> snapshot is invisible in this account forever.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing RDS **management** events. Every RDS action is one,
  in Event history and returned by `lookup-events` with no trail configuration; the only RDS
  data-event type is `AWS::RDS::DBCluster` for the RDS Data API and it is irrelevant here.
  `ModifyDBSnapshotAttribute` carries `requestParameters.dBSnapshotIdentifier`,
  `.attributeName`, `.valuesToAdd` and `.valuesToRemove`; the cluster variant carries
  `.dBClusterSnapshotIdentifier`. The response is **nested two levels**:
  `responseElements.dBSnapshotAttributesResult.dBSnapshotAttributes[].attributeName` and
  `.attributeValues[]` — a flat `responseElements.attributeName` yields null silently
- **CloudTrail retention long enough to cover the whole share history**, not just the alert
  window. The recipient list accumulates: a snapshot shared with four accounts last year and one
  today produces one event today. If the older events have aged out, the response's cumulative
  attribute list on the newest event is the only record they ever existed
- **KMS events in the same trail.** For an *encrypted* snapshot shared with a named account, the
  consumer must use this account's key, which produces a `kms.amazonaws.com` event **here**. That
  is the only cross-account consumption breadcrumb AWS provides, and it does not exist for public
  snapshots, which are unencrypted by construction
- AWS Config `rds-snapshots-public-prohibited` (`RDS_SNAPSHOTS_PUBLIC_PROHIBITED`) on both
  `AWS::RDS::DBSnapshot` and `AWS::RDS::DBClusterSnapshot`, plus `rds-snapshot-encrypted`.
  Treat both as posture reporting, not detection — the 12-hour capture latency is documented, and
  the rule is unavailable in six Regions. Security Hub control **RDS.1** aggregates at Critical
- A recorded list of **legitimate partner account IDs**, maintained as data rather than as tribal
  knowledge. The recipient ID is the entire signal in the cross-account case, and a responder who
  has to ask around at 3 a.m. loses the window

**Alerting (must be pre-configured)**
- **`ModifyDBSnapshotAttribute` or `ModifyDBClusterSnapshotAttribute` adding `all` to the `restore` attribute, no `errorCode` → P0**
- **A manual snapshot created or copied and then shared out of the account by the same principal within one hour → P0**
- **The `restore` attribute gaining an account ID that is not on the partner list → P1**
- **Three or more distinct snapshots shared out of the account by one principal within one hour → P1**

**Response Tooling**
- Break-glass responder credentials with `rds:DescribeDBSnapshots`,
  `rds:DescribeDBSnapshotAttributes`, `rds:ModifyDBSnapshotAttribute`, `iam:PutRolePolicy` and
  `cloudtrail:LookupEvents`, held outside the account's normal identity provider
- A pre-agreed **disclosure decision path**. A public snapshot is a data-release event, not just a
  misconfiguration, and the question of whether it is notifiable should not be researched during
  the incident
- The account ID, to hand: it is needed to filter the public-snapshot sweep in §2 Query 2, and
  the field it must be matched against is **not** the one you would guess (see that query)

**Known IOC Baselines**
- Which principals legitimately create manual snapshots, and which — a much shorter list, often
  empty — legitimately modify their attributes
- Which snapshots are deliberately published, if any. A published benchmark or sample database is
  a real thing; it is also always a decision somebody can name
- The engines and sizes of the databases whose snapshots exist, so the blast radius of a share is
  answerable from the snapshot identifier alone

---

## 2. Identification

### Detection Triggers — high confidence

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ModifyDBSnapshotAttribute`/`ModifyDBClusterSnapshotAttribute`, `attributeName: restore`, `valuesToAdd` containing `all`, no `errorCode` | CloudTrail (management) | T1537 |
| P0 | A manual snapshot created or copied, then shared out of the account by the same principal within one hour | CloudTrail (management) | T1537, T1578.001 |
| P1 | `attributeName: restore` gaining an account ID absent from the partner list, no `errorCode` | CloudTrail (management) | T1537 |
| P1 | Three or more distinct snapshots shared out of the account by one principal within one hour | CloudTrail (management) | T1537 |

### Detection Triggers — medium confidence and corroboration

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `SharedSnapshotQuotaExceeded` — the 20-account cap was hit, which only happens at volume | CloudTrail (management) | T1537 |
| P2 | `InvalidDBSnapshotState` on an `all` attempt — usually AWS refusing to make an encrypted snapshot public. The control worked; the intent is still evidence | CloudTrail (management) | T1537 |
| P2 | `CopyDBSnapshot` with a `kmsKeyId` differing from the source's, on a database whose snapshots are otherwise default-key encrypted — the documented way to make an unshareable snapshot shareable | CloudTrail (management) | T1578.001 |
| P2 | `DescribeDBSnapshots` or `DescribeDBSnapshotAttributes` in a burst from a principal that owns no backup process | CloudTrail (management) | T1580 |
| P3 | AWS Config `rds-snapshots-public-prohibited` turning NON_COMPLIANT, or Security Hub RDS.1 | AWS Config / Security Hub | T1537 |
| P3 | Trusted Advisor check `rSs93HQwa1` reporting a red status | Trusted Advisor | T1537 |

### Detection Rule Quality Notes

The source rule reaches for the right field on the right API and misses it twice, then collapses
two different incidents into one priority.

| Issue | Impact | Correction |
|-------|--------|-----------|
| The share-value clause names a **parser-derived field**, not a CloudTrail path | Wherever that extraction is not configured the clause matches nothing and the rule is silently dead — in the direction that hides a public database snapshot. A rule that cannot fire reads as coverage on a dashboard | Match `requestParameters.valuesToAdd`, which the API reference declares as an array of strings |
| `responseElements.attributeName` is not a path | The operation returns `DBSnapshotAttributesResult { DBSnapshotIdentifier, DBSnapshotAttributes[] { AttributeName, AttributeValues[] } }`, so `attributeName` sits two levels down inside an array. A flat path yields null with no error, so the `OR` arm contributes nothing | Read `responseElements.dBSnapshotAttributesResult.dBSnapshotAttributes[]` at its real depth — it carries the **cumulative** share list, which the request does not |
| `all` and a 12-digit account ID are one priority, and only `all` is matched | Sharing with the world and sharing with a named partner have different verdicts, different notification obligations and different eradication work-lists. The cross-account case — the more common real event — is not detected at all | Two rules: `critical` for `all`, `high` for a named account not on the partner list |
| Nothing distinguishes a share from an **unshare** | `valuesToRemove` is the remediation for this very alert. A rule keyed on the `restore` attribute alone fires on its own cleanup, which is how an alert teaches its audience to close it | Use Sigma's documented `field: null` absence semantics to require `valuesToAdd` present |
| Nothing covers create-then-share | Every AWS constraint on sharing — no automated snapshots, no default-key snapshots, no `all` on encrypted ones — forces a deliberate actor to create or copy first. That sequence is the strongest available signal and it produces two ordinary events | Ship the `temporal_ordered` correlation |

**Recommended detection — a snapshot released to every AWS account.**

```yaml
# RDS Snapshot Shared Publicly or Cross-Account (T1537 / T1578.001)
#
# WHAT THE SOURCE RULE DOES. It matches ModifyDBSnapshotAttribute or
# ModifyDBClusterSnapshotAttribute, requires `attributeName: restore` from EITHER
# requestParameters OR responseElements, requires a parser-derived field to equal `all`, and
# filters to successes. The intent is exactly right and three of its four mechanics are wrong.
#
#   1. IT DEPENDS ON A FIELD CLOUDTRAIL DOES NOT PRODUCE. The share-value clause names a
#      parser-extracted field, not a CloudTrail path. Wherever that extraction is not
#      configured the clause matches nothing and the rule is silently dead - and it is dead in
#      the direction that hides a public database snapshot. The real path is
#      `requestParameters.valuesToAdd`, an array of strings.
#   2. `responseElements.attributeName` IS NOT A PATH. The API returns
#      DBSnapshotAttributesResult { DBSnapshotIdentifier, DBSnapshotAttributes[] { AttributeName,
#      AttributeValues[] } }, so `attributeName` lives inside an array element and never at the
#      top of responseElements. A flat path yields null silently. The response is still worth
#      reading - it carries the FULL post-change share list, including accounts added by earlier
#      calls that have aged out of your retention - but it must be read at its real depth.
#   3. `all` AND A 12-DIGIT ACCOUNT ID ARE DIFFERENT INCIDENTS. The source rates both P2 and
#      matches only `all`. Public means every AWS account on earth can restore it; a named
#      account means one identified party can. They are split below at different levels, and
#      the cross-account case is covered at all - the source rule does not see it.
#
# WHAT MAKES THIS TECHNIQUE DIFFERENT FROM EVERY OTHER EXPOSURE IN THIS SET. A shared snapshot
# is a COPY. Once another account restores or copies it, the data is theirs permanently: AWS
# states "You can delete only the public snapshots that you own", and a copy taken by someone
# else is outside your account, your billing and your logs. Worse, AWS raises no event and
# sends no notification when a foreign account consumes the snapshot - the RDS event catalogue
# has entries for snapshot creation, deletion, copy, export and restore, and NONE for an
# attribute change or for third-party consumption. The consumer's RestoreDBInstanceFromDBSnapshot
# lands in THEIR trail.
#
# AND THE ONE CROSS-ACCOUNT BREADCRUMB DOES NOT EXIST IN THE PUBLIC CASE. For an ENCRYPTED
# snapshot shared with a named account, the consumer must use the owner's KMS key, which
# produces a kms.amazonaws.com event in the OWNER's trail. But AWS refuses `all` on an encrypted
# snapshot - "If the manual DB snapshot is encrypted, it can be shared, but only by specifying a
# list of authorized AWS account IDs for the ValuesToAdd parameter. You can't use `all` as a
# value for that parameter in this case." A public snapshot is therefore necessarily
# unencrypted, there is no KMS call, and there is no breadcrumb of any kind. The configuration
# that maximises exposure is the one that removes the only cross-account telemetry AWS offers.
#
# TWO MORE CONSTRAINTS THAT SHAPE TRIAGE. Automated system snapshots cannot be shared at all -
# "To share an automated DB snapshot, create a manual DB snapshot by copying the automated
# snapshot, and then share that copy" - so a share is always preceded by a create or a copy,
# which is what the temporal_ordered correlation below looks for. And a snapshot encrypted with
# the default aws/rds key "can't be shared" in any form, so an actor who wants to share an
# encrypted database must first CopyDBSnapshot it under a customer-managed key.
#
# FIELD SHAPE. eventSource `rds.amazonaws.com`, management plane, regional. Instance variant:
# `requestParameters.dBSnapshotIdentifier`; cluster variant:
# `requestParameters.dBClusterSnapshotIdentifier`. Both carry `attributeName`, `valuesToAdd`
# and `valuesToRemove`. `valuesToAdd` is declared as an array of strings and should render as a
# bare JSON list; AWS publishes no CloudTrail sample event for this API, so the rules below
# match on the VALUE rather than on a fixed index path, which is correct under either rendering.
title: RDS snapshot shared with all AWS accounts
id: a86f846a-1ed6-480c-a974-234ed87d3766
name: rds_snapshot_shared_public
status: experimental
description: >-
  A manual DB or DB cluster snapshot had its restore attribute set to `all` - every AWS account
  can now copy or restore a full offline copy of the database. Consumption produces no event in
  this account and no notification, and copies already taken cannot be recalled.
references:
  - https://attack.mitre.org/techniques/T1537/                                                          # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBSnapshotAttribute.html         # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html                       # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html                      # retrieved 2026-08-29
tags:
  - attack.exfiltration
  - attack.defense-impairment
  - attack.t1537
  - attack.t1578.001
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
  # `|contains` rather than an exact match because the field is a LIST and backends flatten
  # lists differently. It is safe here: the only legal values are `all` and 12-digit account
  # IDs, and no account ID contains letters.
  public_value:
    requestParameters.valuesToAdd|contains: 'all'
  success:
    errorCode: null
  condition: selection and share_attribute and public_value and success
falsepositives:
  - >-
    A deliberately published dataset - a public sample or benchmark database. Genuinely exists,
    and is always a decision somebody can name. If nobody can name it, it is an incident.
level: critical
---
# Sharing with a NAMED account is a different incident from sharing with the world, and the
# source rule sees neither of them as distinct. `not values_absent` uses Sigma's documented
# null semantics - `field: null` matches when the field is ABSENT - so this fires only when
# valuesToAdd is present, which excludes the UNSHARE call (valuesToRemove) that is the
# remediation for this very rule. Matching the remediation alongside the exposure is how an
# alert buries itself in its own cleanup.
title: RDS snapshot shared with a named AWS account
id: e2e6bd1e-ebcf-4db5-8653-13e7c5298a43
name: rds_snapshot_shared_cross_account
status: experimental
description: >-
  A manual DB or DB cluster snapshot was shared with one or more specific AWS accounts. Lower
  than the public case only because the recipient is identified; the data has still left the
  account and cannot be recalled once copied.
references:
  - https://attack.mitre.org/techniques/T1537/                                                   # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html                # retrieved 2026-08-29
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
  public_value:
    requestParameters.valuesToAdd|contains: 'all'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the account IDs of legitimate partners, if any exist.
  known_partner_accounts:
    requestParameters.valuesToAdd|contains:
      - '000000000000'          # replace with a real partner account, or delete this block
  condition: selection and share_attribute and success and not values_absent and not public_value and not known_partner_accounts
falsepositives:
  - >-
    A sanctioned cross-account restore for a partner or a sibling account in the same
    organisation. Allowlist the account ID above rather than muting the rule - the ID is the
    whole signal.
level: high
---
# Base rule — sequence component only, not for direct alerting. Carries the success filter so a
# failed create cannot compose into the correlation below.
#
# CopyDBSnapshot is here for two reasons beyond completeness. It is the documented way to make a
# shareable copy of an AUTOMATED snapshot, which cannot be shared directly, and it is the
# documented way to re-encrypt a snapshot under a customer-managed key so that it can be shared
# at all. Both are the first move of a deliberate exfiltration.
title: RDS manual snapshot created or copied
id: 8ab61527-e2d0-45da-b67f-723ecb4222fb
name: rds_manual_snapshot_created_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CopySnapshot.html   # retrieved 2026-08-29
tags:
  - attack.defense-impairment
  - attack.t1578.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'rds.amazonaws.com'
    eventName:
      - 'CreateDBSnapshot'
      - 'CreateDBClusterSnapshot'
      - 'CopyDBSnapshot'
      - 'CopyDBClusterSnapshot'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
# CREATE-THEN-SHARE IS THE DELIBERATE SHAPE, and AWS's own constraints force it. An automated
# system snapshot cannot be shared, so an actor working from backups must copy it to a manual
# snapshot first; a snapshot encrypted with the default aws/rds key cannot be shared at all, so
# an actor must copy it under a customer-managed key first; and `all` is refused on any
# encrypted snapshot, so an actor who wants it PUBLIC must produce an unencrypted copy. Every
# path to a shared snapshot that started from a protected database runs through a create or a
# copy, and this correlation is that path.
#
# One hour spans a snapshot creation on a large database plus the share; a legitimate backup
# job creates snapshots and never touches their attributes, so it does not compose.
title: RDS snapshot created and then shared out of the account by one principal
id: a12c6739-66d7-4512-baf5-eaef4b67124e
status: experimental
description: >-
  One principal created or copied a manual snapshot and then shared it - publicly or with a
  named account - inside an hour. That sequence is the documented way around every AWS
  constraint on sharing protected data, and no backup process performs it.
references:
  - https://attack.mitre.org/techniques/T1537/   # retrieved 2026-08-29
tags:
  - attack.exfiltration
  - attack.defense-impairment
  - attack.t1537
  - attack.t1578.001
correlation:
  type: temporal_ordered
  rules:
    - rds_manual_snapshot_created_bb
    - rds_snapshot_shared_public
  group-by:
    - userIdentity.arn
  timespan: 1h
level: critical
---
# THRESHOLD BASIS, since there is no observed baseline to derive one from. AWS caps a single
# snapshot at 20 recipient accounts, so an actor wanting breadth works across SNAPSHOTS rather
# than across accounts - which is what this counts. Three distinct snapshots shared by one
# principal inside an hour is not a person restoring a backup; it is a sweep. `gte` at the
# baseline, never `gt`, so a run that touches exactly three does not fall through. Re-baseline
# before deploying: in an account that genuinely publishes datasets, raise it rather than
# muting the rule.
title: Multiple RDS snapshots shared out of the account by one principal
id: 42e72162-875f-4945-b35c-dca57b4e5bec
status: experimental
description: >-
  One principal shared three or more distinct snapshots inside an hour. The work-list for
  recovery is every snapshot in the group, and the exposure window starts at the first.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html   # retrieved 2026-08-29
tags:
  - attack.exfiltration
  - attack.t1537
correlation:
  type: value_count
  rules:
    - rds_snapshot_shared_cross_account
  group-by:
    - userIdentity.arn
  field: requestParameters.dBSnapshotIdentifier
  timespan: 1h
  condition:
    gte: 3
level: critical
```

Sigma cannot measure the exposure window, because that requires pairing a share with the later
removal of the **same value** on the **same snapshot**; it cannot read the cumulative recipient
list, because that is an array inside an array in the response; and it cannot see a share that
happened before your retention window began. `detections/kql_t1537.kql` does the first two.
Only the live enumeration in Query 2 does the third, and it must run before §3.

---

### Key Investigation Queries

> RDS is regional — run these in the snapshot's region, and repeat per region: a snapshot copied cross-Region is shareable from the destination. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: every share and unshare, who, when, and to whom

```bash
REGION="us-east-1"
RAW=$(for EV in ModifyDBSnapshotAttribute ModifyDBClusterSnapshotAttribute; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region, or"
  echo "    missing cloudtrail:LookupEvents. This is NOT 'no snapshot was shared'."
else
  # valuesToAdd is declared as an array of strings. It is normalised to a list here so the same
  # jq works whether the backend renders it as a bare list or wraps it, and the VALUE is what is
  # tested - never a fixed index path.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "rds.amazonaws.com") |
    (.requestParameters.valuesToAdd    | if type == "array" then . elif . == null then [] else [.] end) as $add |
    (.requestParameters.valuesToRemove | if type == "array" then . elif . == null then [] else [.] end) as $rem |
    {time: .eventTime, event: .eventName, region: .awsRegion,
     caller_arn: .userIdentity.arn, access_key: .userIdentity.accessKeyId,
     snapshot_id: (.requestParameters.dBSnapshotIdentifier //
                   .requestParameters.dBClusterSnapshotIdentifier // "unknown"),
     attribute: .requestParameters.attributeName,
     added: $add, removed: $rem,
     direction: (if ($add | length) > 0 then "SHARE" elif ($rem | length) > 0 then "UNSHARE" else "read-or-noop" end),
     public: ($add | index("all") != null),
     cumulative: ((.responseElements.dBSnapshotAttributesResult.dBSnapshotAttributes //
                   .responseElements.dBClusterSnapshotAttributesResult.dBClusterSnapshotAttributes //
                   .responseElements.dBSnapshotAttributes // []) |
                  map(select(.attributeName == "restore") | .attributeValues) | flatten),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent} |
    select(.attribute == "restore")' |
  jq -s 'sort_by(.time)'
fi
```

`public: true` is the Critical case. `direction` separates the share from the unshare, and the
unshare is somebody's remediation — do not count it as an exposure. `cumulative` is the field to
read hardest: it is the **full recipient list after the change**, so an event that added one
account to a snapshot already shared with four shows all five, and those four may predate your
retention entirely. An `error` of `SharedSnapshotQuotaExceeded` means the twenty-account cap was
reached, which is volume; `InvalidDBSnapshotState` on an `all` attempt is usually AWS refusing to
make an encrypted snapshot public. Record `snapshot_id`, `caller_arn`, `access_key` and every
value in `added` and `cumulative` as IOCs.

#### Query 2 — Enumerate the live share state, account-wide, BEFORE anything is revoked

```bash
REGION="us-east-1"
ACCT=$(aws sts get-caller-identity --query Account --output text)
if [ -z "$ACCT" ]; then
  echo "[!] INCONCLUSIVE - could not resolve the account ID; the ownership filter below cannot run."
  exit 1
fi

# `--snapshot-type public --include-public` returns EVERY public snapshot visible in the Region,
# from every account in the world - not just yours. It must be filtered to this account, and the
# field to filter on is the ARN: the DBSnapshot data type has NO OwnerId member. A JMESPath
# filter on `?OwnerId==...` matches nothing and returns an empty list, which reads exactly like
# "no public snapshots" and is the false [OK] this whole playbook exists to prevent.
PUBS=$(aws rds describe-db-snapshots --snapshot-type public --include-public --region "$REGION" \
         --output json --query "DBSnapshots[?contains(DBSnapshotArn, ':${ACCT}:')].[DBSnapshotIdentifier,DBInstanceIdentifier,Encrypted,SnapshotCreateTime]")
if [ -z "$PUBS" ]; then
  echo "[!] INCONCLUSIVE - the public-snapshot listing call returned nothing at all. That is a"
  echo "    failed call or a missing permission, not an empty result set."
else
  N=$(printf '%s' "$PUBS" | jq 'length')
  if [ "$N" -eq 0 ]; then
    echo "[OK] no snapshot owned by $ACCT is public in $REGION"
  else
    echo "[FAIL] $N snapshot(s) owned by $ACCT are PUBLIC in $REGION:"
    printf '%s' "$PUBS" | jq -r '.[] | "        \(.[0])  from=\(.[1])  encrypted=\(.[2])  created=\(.[3])"'
  fi
fi

# Now the authoritative per-snapshot recipient list. This is the ONLY place the full set of
# authorised accounts exists, and §3 Step 2 destroys it - so it is captured to disk here.
OUT="./share-state-$(date -u +%Y%m%dT%H%M%SZ).json"
MANUAL=$(aws rds describe-db-snapshots --snapshot-type manual --region "$REGION" \
           --query 'DBSnapshots[].DBSnapshotIdentifier' --output text)
if [ -z "$MANUAL" ]; then
  echo "[!] INCONCLUSIVE - no manual snapshots listed. If this account has manual snapshots, the"
  echo "    call failed; re-run before proceeding to §3."
else
  : > "$OUT"
  for S in $MANUAL; do
    A=$(aws rds describe-db-snapshot-attributes --db-snapshot-identifier "$S" \
          --region "$REGION" --output json)
    if [ -z "$A" ]; then
      echo "[!] INCONCLUSIVE - could not read attributes of $S; its recipients are unknown"
      continue
    fi
    printf '%s' "$A" | jq --arg s "$S" '{snapshot: $s, attributes: .DBSnapshotAttributesResult.DBSnapshotAttributes}' >> "$OUT"
    V=$(printf '%s' "$A" | jq -r '[.DBSnapshotAttributesResult.DBSnapshotAttributes[]?
          | select(.AttributeName == "restore") | .AttributeValues[]?] | join(",")')
    case "$V" in
      "")    :;;
      *all*) echo "[FAIL] $S is PUBLIC";;
      *)     echo "[FAIL] $S is shared with: $V";;
    esac
  done
  echo "[i] full share state written to $OUT - this file is the evidence §3 is about to destroy"
fi
```

Run this **first, in every region**, and keep the output file. It is the only artefact that
survives containment. A snapshot listed here that Query 1 does not explain was shared before your
CloudTrail retention began and has no event anywhere.

#### Query 3 — What is actually in the exposed snapshot

```bash
REGION="us-east-1"; SNAP_ID="<snapshot-id-from-Query-1>"
S=$(aws rds describe-db-snapshots --db-snapshot-identifier "$SNAP_ID" --region "$REGION" --output json)
if [ -z "$S" ]; then
  echo "[!] INCONCLUSIVE - the snapshot could not be described. It may have been deleted, or the"
  echo "    call failed. Its contents are unknown, not empty."
else
  # DBSnapshot names the encryption flag `Encrypted`; DBClusterSnapshot names it
  # `StorageEncrypted`. Reading the wrong one on the wrong type yields null, which is not false.
  printf '%s' "$S" | jq -r '.DBSnapshots[0] |
    "source instance : \(.DBInstanceIdentifier)
engine          : \(.Engine) \(.EngineVersion)
master username : \(.MasterUsername)
size            : \(.AllocatedStorage) GiB
encrypted       : \(.Encrypted)   kms: \(.KmsKeyId // "none")
snapshot type   : \(.SnapshotType)
copied from     : \(.SourceDBSnapshotIdentifier // "not a copy")
source region   : \(.SourceRegion // "same region")
taken at        : \(.SnapshotCreateTime)"'
fi
```

`encrypted: false` on a snapshot that is public is not a coincidence and not a second finding —
AWS refuses `all` on an encrypted snapshot, so **every public snapshot is unencrypted by
construction**. `copied from` being populated is the create-then-share chain made visible: a copy
taken specifically to escape the default-key sharing prohibition. `master username` and the
engine tell you which credential set to rotate and which application owns the data.

#### Query 4 — The rest of the session: what else did this principal do

```bash
REGION="us-east-1"; SUSPECT_ARN="<caller-arn-from-Query-1>"
# For an assumed-role session, AttributeKey=Username matches the SESSION NAME, not the role name -
# for an instance-profile session that is the instance ID. Keyed on the session name here, with
# the role confirmed by post-filtering on sessionIssuer.
SESSION=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
RAW=$(aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION" \
        --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" --region "$REGION" --output json)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - no events returned for session $SESSION. Either the session name is"
  echo "    wrong, or the lookup failed. This is NOT 'the principal did nothing else'."
else
  printf '%s' "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, source: .eventSource, event: .eventName,
     role: (.userIdentity.sessionContext.sessionIssuer.userName // "n/a"),
     target: (.requestParameters.dBSnapshotIdentifier //
              .requestParameters.dBInstanceIdentifier //
              .requestParameters.s3BucketName // null),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | jq -s 'sort_by(.time)'
fi
```

Read this for the shape of the visit, not for the snapshot. `DescribeDBSnapshots` and
`DescribeDBSnapshotAttributes` immediately before the share is reconnaissance and dates the
decision. `StartExportTask` in the same session is a **second, independent exfiltration path** —
go to `playbooks/rds.exfiltration.rds-snapshot-export/`. A run of `AccessDeniedException` across
unrelated services is boundary mapping and tells you the actor did not know what it had.

#### Query 5 — Account-wide sweep: is this the only one, and is it only here

```bash
ACCT=$(aws sts get-caller-identity --query Account --output text)
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  P=$(aws rds describe-db-snapshots --snapshot-type public --include-public --region "$R" \
        --output json --query "DBSnapshots[?contains(DBSnapshotArn, ':${ACCT}:')].DBSnapshotIdentifier")
  C=$(aws rds describe-db-cluster-snapshots --snapshot-type public --include-public --region "$R" \
        --output json --query "DBClusterSnapshots[?contains(DBClusterSnapshotArn, ':${ACCT}:')].DBClusterSnapshotIdentifier")
  if [ -z "$P" ] || [ -z "$C" ]; then
    echo "[!] INCONCLUSIVE $R - a listing call returned nothing at all; this region is unchecked"
    continue
  fi
  NP=$(printf '%s' "$P" | jq 'length'); NC=$(printf '%s' "$C" | jq 'length')
  if [ "$NP" -eq 0 ] && [ "$NC" -eq 0 ]; then
    echo "[OK] $R clean"
  else
    echo "[FAIL] $R has $NP public DB snapshot(s) and $NC public cluster snapshot(s) owned by $ACCT"
    printf '%s' "$P" | jq -r '.[] | "        db: \(.)"'
    printf '%s' "$C" | jq -r '.[] | "        cluster: \(.)"'
  fi
done
```

Cluster snapshots are a separate API with a separate ARN field and are routinely forgotten; a
sweep that checks only `describe-db-snapshots` reports a clean account with a public Aurora
snapshot in it. `describe-regions` returns only regions this account has enabled — a snapshot in
a region you have never used cannot exist, but a snapshot in a region you enabled and forgot can.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**Query 2 must have completed and its output file must exist before anything below runs.**
Revoking the share is a `ModifyDBSnapshotAttribute --values-to-remove`, and once it lands the
`restore` attribute list is empty: the identity of every account that held restore rights is gone,
irrecoverably, because the older grants may have no surviving CloudTrail event. This is the one
ordering hazard in this playbook and it is unforgiving — the step that stops the bleeding is the
step that destroys the evidence of who was bleeding on.

Then revoke, then contain the principal, then decide about the data. Deleting the snapshot is
last and is not containment: it recalls nothing.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Confirm the evidence exists before destroying it

```bash
STATE_FILE="<share-state-file-from-Query-2>"
if [ ! -s "$STATE_FILE" ]; then
  echo "[FAIL] $STATE_FILE is missing or empty. STOP. Run Query 2 first - the revoke below"
  echo "       erases the recipient list and nothing reconstructs it."
  exit 1
fi
RECIPIENTS=$(jq -r '.attributes[]? | select(.AttributeName == "restore") | .AttributeValues[]?' "$STATE_FILE" | sort -u)
if [ -z "$RECIPIENTS" ]; then
  echo "[!] INCONCLUSIVE - the captured state names no recipients. Either nothing was shared, or"
  echo "    Query 2 ran after somebody already revoked. Check Query 1 before assuming the former."
else
  echo "[OK] recipients captured and preserved:"
  printf '%s\n' "$RECIPIENTS" | sed 's/^/        /'
fi
```

#### Step 2 — Revoke the share

```bash
REGION="us-east-1"; SNAP_ID="<snapshot-id-from-Query-1>"
STATE_FILE="<share-state-file-from-Query-2>"
VALUES=$(jq -r --arg s "$SNAP_ID" 'select(.snapshot == $s) | .attributes[]? |
           select(.AttributeName == "restore") | .AttributeValues[]?' "$STATE_FILE" | sort -u)
if [ -z "$VALUES" ]; then
  echo "[!] INCONCLUSIVE - no captured recipients for $SNAP_ID; revoking blind would leave any"
  echo "    grant not named here in place. Re-run Query 2 for this snapshot."
else
  for V in $VALUES; do
    aws rds modify-db-snapshot-attribute --db-snapshot-identifier "$SNAP_ID" \
      --attribute-name restore --values-to-remove "$V" --region "$REGION" >/dev/null \
      && echo "[OK] removed $V from $SNAP_ID" \
      || echo "[FAIL] could not remove $V from $SNAP_ID - it is still authorised"
  done
fi
# Cluster snapshots use a different verb and a different identifier flag. Running the instance
# verb against a cluster snapshot fails with DBSnapshotNotFound, which reads as "already clean".
echo "[i] for a cluster snapshot: aws rds modify-db-cluster-snapshot-attribute"
echo "    --db-cluster-snapshot-identifier <id> --attribute-name restore --values-to-remove <v>"
```

#### Step 3 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["rds:ModifyDBSnapshotAttribute","rds:ModifyDBClusterSnapshotAttribute","rds:CreateDBSnapshot","rds:CreateDBClusterSnapshot","rds:CopyDBSnapshot","rds:CopyDBClusterSnapshot","rds:StartExportTask"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenySnapshotSharing" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenySnapshotSharing" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied snapshot sharing for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or a"
     echo "    service principal. Contain manually; neither branch above applies.";;
esac
```

The `aws:TokenIssueTime` deny kills tokens **issued before** the cutoff. A credential re-fetched
after the policy lands gets a newer issue time and is not denied — it kills what is currently
leaked, and it does not gate the role.

#### Step 4 — Sweep the account and revoke everything else that is shared

```bash
REGION="us-east-1"; ACCT=$(aws sts get-caller-identity --query Account --output text)
STATE_FILE="<share-state-file-from-Query-2>"
REMAINING=$(jq -r 'select((.attributes[]? | select(.AttributeName == "restore") | .AttributeValues[]?) != null)
              | .snapshot' "$STATE_FILE" | sort -u)
if [ -z "$REMAINING" ]; then
  echo "[!] INCONCLUSIVE - the captured state lists no shared snapshots at all. If Query 2 found"
  echo "    any, this parse is wrong; do not treat it as an all-clear."
else
  echo "[i] every snapshot to revoke, from the preserved state:"
  printf '%s\n' "$REMAINING" | sed 's/^/        /'
  echo "[i] repeat Step 2 for each, then re-run Query 5 across all regions."
fi
```

#### Step 5 — Decide about the data, not just the snapshot

Deleting the snapshot is not containment: AWS states *"You can delete only the public snapshots
that you own"*, and a copy another account already took is theirs. Delete it anyway — it removes
the ongoing exposure and it is cheap — but record in the incident that deletion changed nothing
about copies already made. Then start the disclosure decision from §1's pre-agreed path, using
Query 3's engine, size and source instance to scope what was in it.

---

## 4. Eradication

### Remove Attacker Access

### Remove the ability to do it again

- **Rotate every credential the database held.** The master user password first, then every
  application credential, API key and token stored in a table. A restored copy hands the holder
  the credentials at rest as well as the data; rotation is the only step that reaches them.
  `ModifyDBInstance --master-user-password` is covered by the emergency deny in §3, so sequence
  the rotation before removing it or use a different principal.
- **Re-encrypt the source database's future snapshots.** A snapshot encrypted with a
  customer-managed key can be shared only with named accounts, never with `all`; a snapshot
  encrypted with the default `aws/rds` key cannot be shared at all. Encryption at rest is
  therefore not just confidentiality here — it is the control that makes this technique
  impossible. If the source database is unencrypted, the migration path is in
  `playbooks/rds.stealth.database-instancecluster-was-created-with-no-encryption/` and it means downtime.
- **Right-size the permission.** `rds:ModifyDBSnapshotAttribute` and
  `rds:ModifyDBClusterSnapshotAttribute` are needed by no workload at runtime and by almost no
  human. Separate them from `rds:CreateDBSnapshot`, which a backup process legitimately needs.

### Remove the emergency policies, and assert it

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenySnapshotSharing EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenySnapshotSharing"
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

#### Assertion 1 — the specific snapshot authorises nobody

```bash
REGION="us-east-1"; SNAP_ID="<snapshot-id-from-Query-1>"
A=$(aws rds describe-db-snapshot-attributes --db-snapshot-identifier "$SNAP_ID" \
      --region "$REGION" --output json)
if [ -z "$A" ]; then
  echo "[!] INCONCLUSIVE - the attribute read returned nothing. If the snapshot was DELETED in §3"
  echo "    this call fails with DBSnapshotNotFound, which is a clean outcome for a different"
  echo "    reason - confirm which by listing it. An empty read is never proof of no sharing."
else
  V=$(printf '%s' "$A" | jq -r '[.DBSnapshotAttributesResult.DBSnapshotAttributes[]?
        | select(.AttributeName == "restore") | .AttributeValues[]?] | join(",")')
  if [ -z "$V" ]; then echo "[OK] $SNAP_ID authorises no account"
  else echo "[FAIL] $SNAP_ID still authorises: $V"; fi
fi
```

This assertion stays reachable after the remediation on purpose: the snapshot attribute API keeps
answering whether the list is empty or full, so `[FAIL]` is a live branch rather than a
by-construction impossibility. The one case that would fool it — the snapshot having been deleted
— is called out rather than folded into `[OK]`.

#### Assertion 2 — nothing owned by this account is public, in any region

```bash
ACCT=$(aws sts get-caller-identity --query Account --output text)
BAD=0; UNCHECKED=0
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  P=$(aws rds describe-db-snapshots --snapshot-type public --include-public --region "$R" \
        --output json --query "DBSnapshots[?contains(DBSnapshotArn, ':${ACCT}:')].DBSnapshotIdentifier")
  C=$(aws rds describe-db-cluster-snapshots --snapshot-type public --include-public --region "$R" \
        --output json --query "DBClusterSnapshots[?contains(DBClusterSnapshotArn, ':${ACCT}:')].DBClusterSnapshotIdentifier")
  if [ -z "$P" ] || [ -z "$C" ]; then UNCHECKED=$((UNCHECKED+1)); continue; fi
  N=$(( $(printf '%s' "$P" | jq 'length') + $(printf '%s' "$C" | jq 'length') ))
  [ "$N" -gt 0 ] && { BAD=$((BAD+N)); echo "[FAIL] $R still has $N public snapshot(s) owned by $ACCT"; }
done
if   [ "$UNCHECKED" -gt 0 ] && [ "$BAD" -eq 0 ]; then
  echo "[!] INCONCLUSIVE - $UNCHECKED region(s) could not be listed. Not an all-clear."
elif [ "$BAD" -eq 0 ]; then
  echo "[OK] no snapshot owned by $ACCT is public in any enabled region"
else
  echo "[FAIL] $BAD public snapshot(s) remain"
fi
```

#### Assertion 3 — the master credential was actually rotated

```bash
REGION="us-east-1"; DB_ID="<source-instance-from-Query-3>"
CUTOFF="<iso8601-time-of-the-share-from-Query-1>"
RAW=$(aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyDBInstance \
        --start-time "$CUTOFF" --region "$REGION" --output json)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - the lookup returned nothing at all; rotation is unverified, not absent."
else
  HITS=$(printf '%s' "$RAW" | jq -r --arg d "$DB_ID" '.Events[].CloudTrailEvent | fromjson |
    select(.requestParameters.dBInstanceIdentifier == $d) |
    select(.requestParameters.masterUserPassword != null) |
    select(.errorCode == null) | .eventTime')
  if [ -n "$HITS" ]; then
    echo "[OK] master password changed on $DB_ID after the share:"; printf '%s\n' "$HITS" | sed 's/^/        /'
  else
    echo "[FAIL] no successful masterUserPassword change on $DB_ID since $CUTOFF."
    echo "       A restored copy hands the holder the credentials at rest as well as the data."
  fi
fi
```

CloudTrail redacts the value as `****` but records the **parameter's presence**, which is exactly
what this asserts. Managed rotation through Secrets Manager appears instead as
`rds:ModifyDBInstance` with `masterUserSecretKmsKeyId`, or as `secretsmanager:RotateSecret` — if
the database uses managed master passwords, assert on that event instead and say so in the record.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     ModifyDBSnapshotAttribute / rds.amazonaws.com / no errorCode, with"
echo "  requestParameters.attributeName = 'restore' and requestParameters.valuesToAdd containing"
echo "  'all' -> critical. The same with a 12-digit account ID not on the partner list -> high."
echo "  A CreateDBSnapshot or CopyDBSnapshot followed by either, same principal, inside 1h -> critical."
echo "MUST NOT fire on: a call carrying only valuesToRemove - that is the UNSHARE, which is this"
echo "  playbook's own remediation; a share to an allowlisted partner account; any call returning"
echo "  AccessDeniedException, NotAuthorized, InvalidDBSnapshotState or SharedSnapshotQuotaExceeded."
echo "EXPECTED FP, by design: a deliberately published sample or benchmark database. It is always"
echo "  a decision somebody can name - and if nobody can name it, it is not a false positive."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| One API call released a full copy of the database to every AWS account | `rds:ModifyDBSnapshotAttribute` granted to a principal that never needs it; no SCP separating snapshot *creation* from snapshot *sharing* |
| The snapshot could be made public at all | The source database was unencrypted. AWS refuses `all` on an encrypted snapshot and refuses any share of a default-key one — encryption at rest would have made the technique impossible, not merely harder |
| Nobody can say whether the data was taken | Structural. There is no event, no notification and no API for third-party consumption, and a public snapshot is unencrypted by construction so it leaves no KMS trace either |
| The alert did not fire | The deployed rule tested a parser-derived field that this pipeline does not produce, and read the response at a depth the API does not use. It had never fired and nothing indicated that |
| The exposure was found days late | AWS Config's snapshot rule is documented at up to 12 hours; Trusted Advisor refreshes on its own schedule; GuardDuty has no coverage. CloudTrail was the only fast path and its rule was broken |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike, not StringNotEquals: the value is wildcarded, and * expands only in Resource
// and in the *Like operators. Deny + StringNotEquals against a wildcarded ARN matches every
// principal and denies snapshot sharing outright - which is nearly the intent here, but as an
// outage rather than a control, and it would also block the break-glass revocation in §3.
{
  "Effect": "Deny",
  "Action": ["rds:ModifyDBSnapshotAttribute", "rds:ModifyDBClusterSnapshotAttribute"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

### Structural controls, in the order they actually help

- **Encrypt every database at rest with a customer-managed key.** This is the only control on the
  list that removes the technique rather than detecting it: `all` is refused on encrypted
  snapshots, and default-key snapshots cannot be shared at all. Everything else here is a tripwire.
- **Separate creation from sharing in IAM.** A backup process needs `rds:CreateDBSnapshot` and
  nothing else. The two are almost always granted together and almost never both needed.
- **Keep the partner account list as data**, in the detection allowlist and in the runbook. The
  recipient ID is the entire discriminator in the cross-account case.
- **Run the Query 5 sweep on a schedule**, across every enabled region and both snapshot APIs. It
  is the only control that catches a share which predates your CloudTrail retention.

### Detection improvements

- Replace the parser-derived share-value test with `requestParameters.valuesToAdd`, and split
  `all` from a named account into two rules at two levels.
- Add the `temporal_ordered` create-then-share correlation. AWS's own sharing constraints force
  that sequence for any protected database, which makes it the highest-signal shape available.
- Alert on `SharedSnapshotQuotaExceeded`. The twenty-account cap is not reached by accident.
- Feed the response's cumulative `dBSnapshotAttributes[].attributeValues[]` into the alert
  payload. It is the only field that shows recipients added before the retention window.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1537 — Transfer Data to Cloud Account (primary); T1578.001 — Modify Cloud Compute Infrastructure: Create Snapshot (secondary) |
| Primary API | `rds:ModifyDBSnapshotAttribute` / `rds:ModifyDBClusterSnapshotAttribute`, `attributeName = restore` |
| Event source | `rds.amazonaws.com`, **management** plane, regional — verified against AWS's RDS CloudTrail documentation |
| Key discriminator | The contents of `requestParameters.valuesToAdd`: `all` is public and Critical, a 12-digit account ID is a named party and High. `valuesToRemove` is the remediation, not the incident |
| Field shape | Request: `dBSnapshotIdentifier` (or `dBClusterSnapshotIdentifier`), `attributeName`, `valuesToAdd`, `valuesToRemove`. Response nests **two levels**: `responseElements.dBSnapshotAttributesResult.dBSnapshotAttributes[].attributeName` / `.attributeValues[]`. `DBSnapshot` names its encryption flag `Encrypted`; `DBClusterSnapshot` names it `StorageEncrypted`. **Neither data type has an `OwnerId` member** — filter ownership on the ARN |
| "Was it used" pivot | **None exists.** No RDS event, no notification, no API. The consumer's `CopyDBSnapshot`/`RestoreDBInstanceFromDBSnapshot` lands in their trail under their `recipientAccountId`. For an *encrypted* named-account share the consumer must call this account's KMS key, producing a `kms.amazonaws.com` event here — but `all` is refused on encrypted snapshots, so the public case has no trace of any kind |
| Blast radius | Every row in the database at snapshot time, plus every credential stored in it, plus the schema. Unbounded and unidentifiable for `all`; bounded by the recipient list, capped at 20 accounts, for a named share |
| Error strings | `ModifyDBSnapshotAttribute`: `DBSnapshotNotFound` (404), `InvalidDBSnapshotState` (400), `SharedSnapshotQuotaExceeded` (400). `ModifyDBClusterSnapshotAttribute`: `DBClusterSnapshotNotFoundFault` (404), `InvalidDBClusterSnapshotStateFault` (400), `SharedSnapshotQuotaExceeded` (400) — the cluster codes carry `Fault` and the quota code does not, on both operations. CloudTrail carries the wire code, not the SDK shape name. Denials: `AccessDeniedException` (403), `NotAuthorized` (401); the bare `AccessDenied` form is **not** documented for RDS. Common: `InvalidParameterValue`, `InvalidParameterCombination`, `ValidationError`, `ThrottlingException` |

**MITRE mapping note.** The source maps **T1526 / TA0010** — *Cloud Service Discovery* under the
Exfiltration tactic. T1526 is live but wrong on the merits: making a snapshot restorable by
another account discovers nothing. T1537 is the technique whose own description covers
transferring data to another cloud account on the same service in order to avoid network-based
exfiltration detection, which is this exactly. T1578.001 (*Create Snapshot*) is carried as a
genuine second mapping because AWS's constraints force a create or a copy ahead of any share of
protected data.

**A note on what could not be verified.** AWS publishes no CloudTrail sample event for
`ModifyDBSnapshotAttribute`. The request paths above come from the API reference; the response
nesting comes from the documented `DBSnapshotAttributesResult` shape plus the flattening
convention observable in AWS's published `CreateDBInstance` sample. The shipped rules match on
the **value** rather than on a fixed index path, and the KQL tries both plausible response
renderings, so neither depends on that inference being right. Confirm against one real event in
your own pipeline before deploying.

### Residual Risk

**The data is disclosed and stays disclosed.** Every step above closes the window; none of them
recalls a copy. AWS is explicit that you can delete only public snapshots you own, that a copy
taken by another account belongs to that account, and that you are not even billed for their
storage of it — so the copy is absent from your bill, your logs and your control plane alike. You
cannot enumerate who took one, you will never be told, and the only cross-account telemetry AWS
offers, a KMS call against your key, is structurally impossible here because a public snapshot
must be unencrypted.

The exposure window measured in §2 is a **floor**: a share that predates your CloudTrail retention
produces no event, so the live enumeration in Query 2 is the only thing that can find it, and it
tells you the grant exists without telling you when it began. Treat the credentials the database
held as compromised regardless of what the timeline says, and treat the schema itself as
published — it names the tables an actor should ask for next time. And if the source database is
still unencrypted, the technique is still available: the next manual snapshot of it can be made
public by the same one-parameter call.

---

## Source

Adapted from the standalone IR playbook `playbooks/rds.exfiltration.snapshot-made-public/`, which covers the same detection use
case more broadly than this emulation exercises. That folder also carries the full Sigma and KQL
rule set for the use case; only the rules this emulation's attack actually fires are shipped in
`detections/` here.
