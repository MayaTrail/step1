# IR Playbook: Multiple DNS Zones Deleted by a Single User — an account-wide DNS sweep via repeated `route53:DeleteHostedZone`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Destruction of availability at scale (several DNS zones and every record in them are destroyed; each name stops resolving and, while its registration still delegates to Route 53, becomes claimable by somebody else) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **Critical.** The single-zone case is High; volume raises it because the recovery cost is *per zone*, needs a second party *per zone* — the registrar — and runs against a window AWS describes as hijackable. The source rates it **P2** and presents its count as the scope; the count is a floor, and no Route 53 API can enumerate what is missing |
| MITRE Tactics | Impact |
| MITRE Techniques | T1485 — verified live 2026-08-29. |
| Services in Scope | Route 53 (hosted zones), Route 53 Domains and every external registrar holding a delegation, AWS Config, CloudTrail, IAM, Organizations (SCP) |

**What the technique does:** the actor loops. For each zone, one or more `ChangeResourceRecordSets` batches
with `action: DELETE` strip it — Route 53 refuses `DeleteHostedZone` on a zone that still holds
records — and then `DeleteHostedZone` removes the shell. Every delete carries
`requestParameters.id` and nothing else, and once a zone is gone it is **absent from
`list-hosted-zones`**: there is no live-state call that enumerates what is missing, only what
survives. Recreating the zones does not undo it either. AWS assigns four *different* name servers
to every hosted zone, so each restored zone needs a delegation change at whatever registrar holds
that domain, with *"up to 48 hours to take effect"*. That cost is per zone and does not
parallelise, so recovery is a prioritised queue against a running clock.

**Detection thesis.** The discriminator is the **purge sweep**, several minutes ahead of the
delete sweep, while every zone still exists and every record is still recoverable from the
`DELETE` changes. The source rule counts the deletions instead, and presents that count as the
scope of the incident when it is only a lower bound on it.

> The same observable at N=1 is `../route53.stealth.dns-zone-deleted/`, which owns the field
> shape, the region trap and the error sets for this event; they are documented once there. These
> are separate use cases because the response differs — see `_source/PROVENANCE.md`.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail management events for `route53.amazonaws.com`. **Route 53 is global: every event is
  stamped `awsRegion: us-east-1`**, AWS requires the console Region selector to be US East
  (N. Virginia) to see them, and a `lookup-events` call anywhere else returns zero forever
- **AWS Config recording `AWS::Route53::HostedZone`.** At volume this stops being a convenience
  and becomes the response's precondition: it is the only source that can name a zone that no
  longer exists, and the work-list here is built by diffing it against surviving state
- A **per-zone registrar map** — which registrar holds each zone's delegation, and who in the
  organisation can change it. Recovery needs one registrar action per zone and the registrar may
  not be AWS; assembling that map during an incident is the step that stalls
- **Reusable delegation sets** on every zone that matters, recorded. A zone created with a
  `DelegationSetId` comes back on the same four name servers, which removes the registrar from
  its recovery path entirely. The count of zones *without* one is the count of registrar actions
  a mass deletion will cost you
- Zone exports (`list-resource-record-sets`) in version control. `DELETE` changes in CloudTrail
  are exact by API requirement, but a purge above CloudTrail's 100 KB `requestParameters`
  omission threshold leaves nothing at all, and Route 53 permits 1,000 `ResourceRecord` elements
  per request

**Alerting (must be pre-configured)**
- **Three or more distinct hosted zones deleted by one principal within an hour → P0**
- **Records deleted from three or more distinct hosted zones by one principal within an hour → P0**
- **A `DeleteHostedZone` by a non-pipeline principal while a sweep correlation is already open → P1**
- **`HostedZoneNotEmpty` refusals against two or more distinct zone IDs from one principal → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- A host **outside** the VPC from which to verify reachability. Testing from inside exercises a different path and proves nothing.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- **The normal value for this measure, per resource, from a quiet week.** The rule compares against a resource's own history rather than a fleet average, so without the baseline the threshold is a guess.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Three or more distinct `requestParameters.id` values on successful `DeleteHostedZone` from one principal within an hour | CloudTrail (management, `us-east-1`) | T1485 |
| P0 | Three or more distinct `requestParameters.hostedZoneId` values on successful `ChangeResourceRecordSets` `DELETE` from one principal within an hour — the same sweep, earlier, while everything is still recoverable | CloudTrail (management, `us-east-1`) | T1485 |
| P1 | Any further `DeleteHostedZone` by a non-pipeline principal while a sweep correlation is open — the count is a floor, so every subsequent deletion extends the work-list | CloudTrail (management, `us-east-1`) | T1485 |
| P1 | `HostedZoneNotEmpty` against two or more distinct zone IDs from one principal — an actor working through the precondition, before anything is unrecoverable | CloudTrail (management, `us-east-1`) | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `CreateHostedZone` for a name this account recently deleted, by anyone — either your recovery or somebody claiming the name | CloudTrail (management, `us-east-1`) | T1485 |
| P2 | An `AWS::Route53::HostedZone` present in AWS Config history and absent from `list-hosted-zones`, outside a change window | AWS Config + Route 53 | T1485 |

### Detection Rule Quality Notes

The source rule counts the last event of each iteration, and reports its threshold as the scope.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Counts deletions only | Route 53 refuses to delete a non-empty zone, so N deletions were preceded by N purges. The purge sweep is the same actor minutes earlier, on more zones, while every record is still recoverable from the `DELETE` changes | Ship a second `value_count` correlation over distinct `hostedZoneId` on `ChangeResourceRecordSets` `DELETE`, at the same threshold |
| No success filter on the counted event | A principal probing permissions and collecting refusals fires the identical alert as one completing destructions, and the eradication work-list is then wrong in both directions | `errorCode: null` on the base rule (B6) |
| No principal filter | Infrastructure code tears down zones in batches — that is what it is for. Undifferentiated, a volume rule on zone deletion is muted in the first week of any IaC rollout | Allowlist the pipeline principal on the **base** rules so both correlations inherit it |
| Presents the count as the scope | The rule cannot know how many zones went after it fired, and a deleted zone is absent from `list-hosted-zones` — there is no forward-looking call that enumerates the missing. Treating the count as the scope under-scopes the recovery | Reconcile AWS Config against surviving zones (Query 1) before closing the work-list |
| Nothing on the recovery cost | Every restored zone needs a registrar delegation change unless it used a reusable delegation set. The alert says how many zones died and nothing about how many parties must act | Carry `delegationSetId` into triage; the KQL projects `ZonesNeedingRegistrar` |

**Recommended detection — a mass hosted-zone destruction by one principal.**

```yaml
# Multiple DNS Zones Deleted by a Single User (T1485 — Data Destruction)
#
# WHAT THE SOURCE RULE DOES. A unique-count of successful `DeleteHostedZone` events grouped by
# caller. The observable is identical to the single-zone rule next door
# (`../../route53.stealth.dns-zone-deleted/`); what differs is the RESPONSE, which is why the two
# ship as separate use cases rather than as one playbook with two trigger rows.
#
# DOCUMENT ORDER IS DELIBERATE. The correlation comes FIRST because it IS the use case - no
# single event can express volume - and its base rules follow it. Every rule referenced by a
# correlation is defined by `name:` in this same file.
#
# WHY A COUNT OF DELETES IS ALREADY LATE. Route 53 refuses `DeleteHostedZone` on a zone that
# still holds records: "You can delete a hosted zone only if it contains only the default SOA and
# NS records... Attempting to delete a hosted zone with additional records or DNSSEC enabled
# returns a `HostedZoneNotEmpty` error." So N deletions were preceded by N purges, and the purge
# sweep - the third and fourth documents below - is the same actor several minutes earlier, while
# the zones still exist. That is the rule worth paging on.
#
# THE COUNT IS A FLOOR, NOT THE SCOPE. The correlation fires the moment the threshold is crossed
# and the actor is not finished. `lookup-events` pages at 50, and - decisively - a deleted zone is
# ABSENT from `list-hosted-zones`, so live state cannot enumerate what is missing. The work-list
# has to be reconciled against an AWS Config inventory before any restoration begins. That is
# what makes this a different response and not a louder version of the same one.
#
# THRESHOLD BASIS, with no observed baseline to derive one from. An AWS account carries 500
# hosted zones by default and AWS documents no rate limit on `DeleteHostedZone`, so an actor
# sweeping an account is bounded only by how fast the purges complete. Against that, a
# legitimate environment teardown removes one or two zones, and it does so through the pipeline
# role. THREE distinct zones from one principal inside an hour is a sweep. `gte` at the baseline,
# never `gt`, so a run that removes exactly three does not fall through (F6). Re-baseline against
# your own teardown history before deploying.
#
# REGION. Route 53 is global; every `route53.amazonaws.com` event is stamped `us-east-1`.
title: Multiple Route 53 hosted zones deleted by one principal
id: c26bc8b7-9209-4ec4-a392-db1135371de5
status: experimental
description: >-
  One principal destroyed three or more Route 53 hosted zones within an hour. Deletion is
  irreversible and each recreated zone is assigned four DIFFERENT name servers, so the recovery
  work-list is one registrar delegation change per zone, not one restore.
references:
  - https://attack.mitre.org/techniques/T1485/                                                    # retrieved 2026-08-29
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_DeleteHostedZone.html             # retrieved 2026-08-29
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zone-public-considerations.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: value_count
  rules:
    - route53_zone_deleted_bb
  group-by:
    - userIdentity.arn
  field: requestParameters.id
  timespan: 1h
  condition:
    gte: 3
level: critical
---
# Base rule — sequence and volume component only, not for direct alerting. The success filter is
# not optional: without it a principal probing permissions and collecting three AccessDenied
# results fires the same critical alert as three completed destructions (D-f, B6).
#
# The pipeline exclusion lives here rather than on the correlation so that BOTH correlations
# inherit it. Zones are torn down legitimately by infrastructure code, and an unpopulated
# allowlist reproduces the source rule's false-positive rate.
title: Route 53 hosted zone deleted
id: 0e50f739-8faf-4537-ab19-06d7e834ad22
name: route53_zone_deleted_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_DeleteHostedZone.html             # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53.amazonaws.com'
    eventName: 'DeleteHostedZone'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING — allowlist the PRINCIPAL. Zone IDs are unpredictable and cannot
  # be allowlisted in advance.
  iac_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace with this account's Terraform/CDK execution role
      - ':role/cloudformation-exec' # replace with this account's CloudFormation service role
  condition: selection and success and not iac_pipeline
level: informational
---
# Base rule — the purge that MUST precede every deletion. Route 53 will not delete a non-empty
# zone, so this fires first, on more zones, and while every one of them still exists.
#
# ARRAY ADDRESSING. `changes` is a list; the dotted form below is what Elastic-family and
# Sentinel backends produce from a flattened event. A backend requiring explicit indices needs
# `[0]` inserted. Confirm against one real event before deploying — an unmatched path fails
# silently, and this is the rule whose silence costs the most.
title: Route 53 records deleted from a hosted zone
id: 7bde402e-6cbd-4f61-a9e2-1f0663cf9443
name: route53_zone_purged_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html     # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53.amazonaws.com'
    eventName: 'ChangeResourceRecordSets'
  delete_action:
    requestParameters.changeBatch.changes.action: 'DELETE'
  success:
    errorCode: null
  iac_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/cloudformation-exec'
  condition: selection and delete_action and success and not iac_pipeline
level: informational
---
# THE RULE THAT ARRIVES IN TIME. One principal stripping records from three or more DISTINCT
# hosted zones inside an hour is the sweep, observed while every zone still exists and every
# record is still recoverable from the DELETE changes themselves ("To delete a resource record
# set, you must specify all the same values that you specified when you created it").
#
# Same threshold as the deletion correlation, and deliberately so: the two count the same set of
# zones at two points in time, so a different figure on each would mean the earlier rule stayed
# silent while the later one fired.
title: Records stripped from multiple Route 53 hosted zones by one principal
id: 2eca96a8-de87-4e65-820e-ebe0d20f6499
status: experimental
description: >-
  One principal deleted records from three or more distinct hosted zones within an hour. Route 53
  refuses to delete a zone that still holds records, so this is the destruction itself and it
  precedes every deletion that follows. Nothing is unrecoverable yet.
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html     # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: value_count
  rules:
    - route53_zone_purged_bb
  group-by:
    - userIdentity.arn
  field: requestParameters.hostedZoneId
  timespan: 1h
  condition:
    gte: 3
level: high
```

The correlation cannot name the zones, cannot say which were public, and — structurally — cannot
know the scope, because it counts what it saw rather than what is gone.
`detections/kql_t1485.kql` builds the ordered restoration queue and flags the zones it could not
name; Query 1 below closes the scope against AWS Config.

---

### Key Investigation Queries

> **Route 53 is global — every `route53.amazonaws.com` event lands in `us-east-1` and a query in any other Region returns zero.** Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — at sweep volume you *will* hit that; paginate on `NextToken` before trusting a count.

#### Query 1 — Reconstruct and reconcile: which zones are actually gone, not just which ones alerted

```bash
REGION="us-east-1"
RAW=$(for EV in DeleteHostedZone ChangeResourceRecordSets CreateHostedZone; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: a failed call, a missing"
  echo "    cloudtrail:LookupEvents permission, or a Region other than us-east-1. Route 53 is"
  echo "    GLOBAL. This is NOT 'no zones were deleted'."
else
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "route53.amazonaws.com") |
    ((.requestParameters.id // .requestParameters.hostedZoneId
      // .responseElements.hostedZone.id // "") | sub("^.*/"; "")) as $zid |
    (.requestParameters.changeBatch.changes // []) as $ch |
    {time: .eventTime, event: .eventName, zone_id: $zid,
     zone_name: (.requestParameters.name
                 // ($ch[0].resourceRecordSet.name // "not-on-this-event")),
     delegation_set: (.requestParameters.delegationSetId // "none"),
     private: (.requestParameters.hostedZoneConfig.privateZone // "unknown"),
     caller_arn: .userIdentity.arn, access_key: .userIdentity.accessKeyId,
     deletes: [$ch[] | select(.action == "DELETE") | {name: .resourceRecordSet.name,
                type: .resourceRecordSet.type, ttl: (.resourceRecordSet.tTL // "alias - no ttl"),
                values: [(.resourceRecordSet.resourceRecords // [])[].value],
                alias: (.resourceRecordSet.aliasTarget.dNSName // "not-an-alias")}],
     params_omitted: (.eventName == "ChangeResourceRecordSets"
                      and (.errorCode // "") == "" and ($ch | length) == 0),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.time) |
         (map(select(.event == "DeleteHostedZone" and .error == "SUCCESS")) | group_by(.caller_arn) |
          map({caller_arn: .[0].caller_arn, zones_destroyed: ([.[] | .zone_id] | unique | length),
               first: (.[0].time), last: (.[-1].time),
               ips: ([.[] | .ip] | unique), agents: ([.[] | .agent] | unique)})) as $actors |
         (group_by(.zone_id) | map({zone_id: .[0].zone_id,
              zone_name: ([.[] | .zone_name | select(. != "not-on-this-event")] | first // "UNRESOLVED"),
              delegation_set: ([.[] | .delegation_set | select(. != "none")] | first // "none - REGISTRAR CHANGE NEEDED"),
              private: ([.[] | .private | select(. != "unknown")] | first // "unknown"),
              destroyed_records: [.[] | .deletes[]],
              omitted_batches: ([.[] | select(.params_omitted)] | length),
              refusals: ([.[] | select(.error == "HostedZoneNotEmpty")] | length),
              deleted: ([.[] | select(.event == "DeleteHostedZone" and .error == "SUCCESS")] | length > 0)})
          | map(select(.deleted)) | sort_by(-(.destroyed_records | length))) as $queue |
         {actors: $actors, queue: $queue, queue_length: ($queue | length),
          registrar_actions_needed: ([$queue[] | select(.delegation_set | startswith("none"))] | length),
          unnamed: ([$queue[] | select(.zone_name == "UNRESOLVED")] | length)}'
fi

# THE RECONCILIATION. CloudTrail shows what it saw; AWS Config shows what existed. A deleted zone
# is ABSENT from list-hosted-zones, so the missing set is a DIFFERENCE, never a listing.
LIVE=$(aws route53 list-hosted-zones --output json 2>&1)
CFG=$(aws configservice list-discovered-resources --resource-type AWS::Route53::HostedZone \
        --include-deleted-resources --region "$REGION" --output json 2>&1)
if [ -z "$LIVE" ] || [ -z "$CFG" ]; then
  echo "[!] INCONCLUSIVE - one of the two inventories returned nothing. The scope CANNOT be"
  echo "    closed without both; do not treat the alert's count as the work-list."
else
  case "$CFG" in
    *resourceIdentifiers*)
      printf '%s\n%s' "$LIVE" "$CFG" | jq -s '
        (.[0].HostedZones // [] | map(.Id | sub("^.*/"; ""))) as $live |
        (.[1].resourceIdentifiers // []) as $known |
        {config_known: ($known | length), still_live: ($live | length),
         missing: [$known[] | select((.resourceId | IN($live[])) | not)
                   | {zone_id: .resourceId, zone_name: (.resourceName // "unnamed in Config")}]}' ;;
    *) echo "[!] INCONCLUSIVE - AWS Config did not return resourceIdentifiers: $CFG"
       echo "    If Config does not record AWS::Route53::HostedZone in this account, the scope"
       echo "    of this incident is NOT establishable. Record that, and say so in the report.";;
  esac
fi
```

`actors` gives the principals and `zones_destroyed` each. `queue` is the restoration work-list,
**already ordered** by how many records each zone lost, and `registrar_actions_needed` is the
number of those that cannot be fixed from this account alone. `unnamed` above zero means
CloudTrail cannot name every destroyed zone and the reconciliation below is not optional.
`missing` from the reconciliation is the authoritative scope: anything Config knew about and
`list-hosted-zones` does not return. Carry `caller_arn`, and the `queue` array, into §3.

#### Query 2 — Sweep the queue: which destroyed names are still delegated, and to whom

```bash
# Space-separated zone names from Query 1's queue. Assign first — a bare placeholder inside a
# for-list is redirection syntax and a syntax error (D5).
ZONE_NAMES="<zone-names-from-Query-1>"
if ! command -v dig >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE - dig is not installed. The delegation state of every destroyed zone is"
  echo "    UNKNOWN, and it is the field that separates an outage from a takeover. Use another host."
else
  for Z in $ZONE_NAMES; do
    STATUS=$(dig NS "$Z" 2>&1 | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
    NSSET=$(dig +short NS "$Z" 2>&1 | sed 's/\.$//' | sort | tr '\n' ' ')
    case "${STATUS:-none}" in
      SERVFAIL) echo "[FAIL] $Z - the parent still delegates to name servers that no longer hold"
                echo "        the zone. This is the window AWS warns can be hijacked: $NSSET";;
      NOERROR)  echo "[FAIL] $Z - somebody is authoritative for this name RIGHT NOW: $NSSET"
                echo "        If those are not your name servers, the name has been taken over.";;
      NXDOMAIN) echo "[OK] $Z - no delegation survives; the name is not reachable and not claimable"
                echo "     through a stale delegation. It is still an outage.";;
      none)     echo "[!] INCONCLUSIVE - $Z: dig printed no status line; the lookup failed";;
      *)        echo "[!] INCONCLUSIVE - $Z: unexpected DNS status '$STATUS'";;
    esac
  done
fi
```

Work `SERVFAIL` and `NOERROR` first — those are the names where the delegation outlived the zone.
`NXDOMAIN` is the least urgent case and still an outage. A `NOERROR` whose name servers are not
yours is no longer an availability incident; it is a takeover, and it goes to
`../route53.stealth.ns-record-created-or-updated/`.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="ChangeResourceRecordSets DeleteHostedZone"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "route53.amazonaws.com") |
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
elsewhere, and whether anyone else did it too. Grouped by caller rather than by resource,
because the question eradication needs answered is *how much of this is one actor's work* — a
per-resource list cannot say. `access_key` is emitted because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` whether or not it happened; the preamble's caveat applies.

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

Keyed on the access key rather than the ARN: one credential is used across many sessions, and
the key identifies the credential. The per-service grouping answers what this playbook cannot —
whether this technique was the objective or one stop on a tour. A service in that list with no
business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID, so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**Sever the principal before recreating a single zone**, and this order is not a preference. A
newly created hosted zone contains only its default SOA and NS records — which is exactly the
state `DeleteHostedZone` requires — so a recreate loop racing an uncontained delete loop hands
back zones that are immediately re-deletable and loses ground already recovered. This inverts the
order used at `../route53.stealth.dns-zone-deleted/`, where there is nothing to race.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Sever the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["route53:DeleteHostedZone","route53:ChangeResourceRecordSets","route53:DisableHostedZoneDNSSEC","route53:DeleteQueryLoggingConfig","route53:CreateHostedZone","route53domains:UpdateDomainNameservers"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyRoute53Destroy" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyRoute53Destroy" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied Route 53 destruction for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or a"
     echo "   service principal. Contain manually; neither branch above applies.";;
esac
echo "[i] The deny includes route53:CreateHostedZone deliberately: an actor who can recreate a"
echo "    zone can also claim a name you have not reclaimed yet. Remove it before §5 recreates."
```

The session revocation denies only tokens issued **before** `$CUTOFF`; a credential re-fetched
afterwards carries a newer `aws:TokenIssueTime` and is not denied.

#### Step 2 — Reclaim the names, in the queue's order

```bash
# Space-separated, highest priority first, from Query 1's queue and Query 2's SERVFAIL/NOERROR set.
RECLAIM="<zone-names-from-Query-1>"
DSET="<delegation-set-from-Query-1>"      # "none" if the zones did not use one
for Z in $RECLAIM; do
  REF="ir-$(date -u +%Y%m%dT%H%M%S)-$Z"
  case "$DSET" in
    none|"") NEW=$(aws route53 create-hosted-zone --name "$Z" --caller-reference "$REF" --output json 2>&1);;
    *)       NEW=$(aws route53 create-hosted-zone --name "$Z" --caller-reference "$REF" \
                     --delegation-set-id "$DSET" --output json 2>&1);;
  esac
  case "$NEW" in
    *DelegationSet*)
      echo "[OK] $Z recreated. Name servers now:"
      printf '%s' "$NEW" | jq -r '.DelegationSet.NameServers[] | "        " + .';;
    *ConflictingDomainExists*|*HostedZoneAlreadyExists*)
      echo "[FAIL] $Z - Route 53 refused: a zone for this name already exists, here or in another"
      echo "       account. Somebody may have claimed it. Do not retry blindly; investigate.";;
    *TooManyHostedZones*)
      echo "[FAIL] $Z - hosted-zone quota reached. Raise it before continuing the queue.";;
    *) echo "[!] INCONCLUSIVE - $Z: create-hosted-zone returned no delegation set: $NEW";;
  esac
done
echo "[i] Compare every printed name-server set against Query 2's output for that name. Where"
echo "    they differ, the registrar must be updated - up to 48 hours to take effect - and that"
echo "    is one action per zone, by whoever holds that registration."
```

---

## 4. Eradication

### Remove Attacker Access

- **Capture Query 1's whole output to a file before anything else.** `destroyed_records` is the
  only machine-readable copy of these zones that will exist, its retention is CloudTrail's, and
  at this volume nobody will reconstruct it from memory.
- **Close the scope with AWS Config, not with the alert.** The correlation's count is a floor.
  Anything in Config's history and absent from `list-hosted-zones` is in the work-list, including
  zones deleted before the lookback window opened.
- **Check what else the principal reached.** `DeleteQueryLoggingConfig` and
  `DisableHostedZoneDNSSEC` sit in the same permission neighbourhood, and the second had to
  precede any delete on a DNSSEC-signed zone. Confirm neither was left off across the whole set.
- **Right-size the permission.** `route53:DeleteHostedZone` belongs to the pipeline role and to
  nothing else; pair it with the SCP in §6. Then create a **reusable delegation set** and move
  the zones onto it, so the next sweep costs zero registrar actions.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyRoute53Destroy EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyRoute53Destroy"
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

#### Verify every zone in the work-list exists again, and count the ones still needing a registrar

```bash
EXPECTED="<zone-names-from-Query-1>"    # every name from Query 1's queue AND the Config reconciliation
MISSING=0; PRESENT=0; VERDICT="clean"

# list-hosted-zones returns whatever exists NOW, so this stays able to fail after §3 recreated
# some of the set: a name still absent prints [FAIL], not a zero-by-construction [OK].
LIVE=$(aws route53 list-hosted-zones --output json 2>&1)
case "$LIVE" in
  *HostedZones*)
    for Z in $EXPECTED; do
      HIT=$(printf '%s' "$LIVE" | jq -r --arg n "$Z" \
              '[.HostedZones[] | select(.Name == ($n | sub("\\.?$"; ".")))] | length')
      if [ "${HIT:-0}" -gt 0 ]; then PRESENT=$((PRESENT+1))
      else echo "[FAIL] $Z is still missing"; MISSING=$((MISSING+1)); VERDICT="fail"; fi
    done
    echo "[i] $PRESENT of $((PRESENT+MISSING)) work-list zones exist again";;
  *) echo "[!] INCONCLUSIVE - could not list hosted zones: $LIVE"; VERDICT="inconclusive";;
esac

# Existing is not resolving. The delegation is the second half and it is not in this account.
if command -v dig >/dev/null 2>&1; then
  STALE=0
  for Z in $EXPECTED; do
    ZID=$(printf '%s' "$LIVE" | jq -r --arg n "$Z" \
            '[.HostedZones[] | select(.Name == ($n | sub("\\.?$"; ".")))] | .[0].Id // ""')
    [ -z "$ZID" ] && continue
    MINE=$(aws route53 get-hosted-zone --id "$ZID" --output json 2>&1 |
             jq -r '.DelegationSet.NameServers[]? // empty' | sort | tr '\n' ' ')
    LIVENS=$(dig +short NS "$Z" 2>&1 | sed 's/\.$//' | sort | tr '\n' ' ')
    if [ -z "$MINE" ]; then
      echo "[!] INCONCLUSIVE - $Z: could not read this account's name servers for $ZID"
      VERDICT="inconclusive"
    elif [ "$MINE" != "$LIVENS" ]; then
      echo "[FAIL] $Z still delegates to '$LIVENS' but the zone answers on '$MINE'"
      STALE=$((STALE+1)); VERDICT="fail"
    fi
  done
  echo "[i] $STALE zone(s) still need a registrar delegation change - up to 48h each to take effect"
else
  echo "[!] INCONCLUSIVE - dig is not installed; no delegation could be checked"; VERDICT="inconclusive"
fi

case "$VERDICT" in
  clean)        echo "[OK] every work-list zone exists and its delegation matches its name servers";;
  fail)         echo "[FAIL] recovery is not complete - see the lines above";;
  inconclusive) echo "[!] INCONCLUSIVE - at least one check could not run. Do not close on this.";;
esac
echo "[i] None of this speaks to the RECORDS. A zone that exists and resolves but is empty is"
echo "    still an outage. Reconcile against destroyed_records from Query 1, zone by zone."
```

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     three or more DISTINCT requestParameters.id values on successful"
echo "  DeleteHostedZone from one userIdentity.arn within an hour, in us-east-1, where that ARN"
echo "  is not on the pipeline allowlist - and, at high, on the same count of distinct"
echo "  hostedZoneId values on ChangeResourceRecordSets DELETE, which arrives EARLIER."
echo "MUST NOT fire on: the pipeline role's environment teardown; three DeleteHostedZone calls"
echo "  returning HostedZoneNotEmpty, NoSuchHostedZone or AccessDenied - refusals are not"
echo "  destructions; three deletes of the SAME zone ID retried, which is one zone, not three."
echo "EXPECTED FP, by design: a hand-run decommissioning of a whole environment outside the"
echo "  pipeline. If that is common here, the finding is that DNS is not under change control."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| One principal could destroy several production hosted zones in a single session | `route53:DeleteHostedZone` granted broadly, with no SCP confining it to the deployment role and no rate or scope limit anywhere |
| The alert's count was smaller than the incident | The rule counted deletions inside a window and reported that as the scope; a deleted zone is absent from `list-hosted-zones`, so the true scope is a difference against an inventory that did not exist |
| The purge sweep that preceded every deletion was not alerted on | Only `DeleteHostedZone` was matched. The `ChangeResourceRecordSets` `DELETE` sweep is the same actor, minutes earlier, on more zones, while everything is still recoverable |
| Recovery needed one external party per zone | The zones were not on a reusable delegation set, so every recreated zone came back on different name servers and each registration had to be changed separately |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike, not StringNotEquals: the value is wildcarded, and * expands only in Resource
// and in the *Like operators. Deny + StringNotEquals against a wildcarded ARN matches every
// principal and denies all DNS teardown outright - an outage, not a control.
{
  "Effect": "Deny",
  "Action": ["route53:DeleteHostedZone", "route53:DisableHostedZoneDNSSEC"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy"] }
  }
}
```

- **Put every production zone on a reusable delegation set.** It converts the most expensive part
  of this incident — one registrar action and 48 hours per zone — into nothing at all, because a
  zone recreated against the set returns on the same four name servers. 100 sets per account,
  100 zones per set.
- **Record `AWS::Route53::HostedZone` in AWS Config.** At volume this is not a nice-to-have: it
  is the only way to answer "what is missing", because Route 53 can only list what survives.
- **Export zones to version control on a schedule**, so restoration is a replay rather than a
  reconstruction from CloudTrail — and so a purge above CloudTrail's 100 KB omission threshold
  is survivable at all.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1485 — Data Destruction (Impact, TA0040), lists IaaS. |
| Primary API | `route53:ChangeResourceRecordSets` with `action: DELETE`, then `route53:DeleteHostedZone`, per zone. The order is forced by the API |
| Event source | `route53.amazonaws.com`, **management** plane, **global — every event is stamped `awsRegion: us-east-1`** |
| Key discriminator | Distinct **zone count** from one principal, and the purge sweep that precedes it. A repeat delete of one zone ID is one zone, not N |
| Field shape | `DeleteHostedZone`: `requestParameters.id` (flat). `ChangeResourceRecordSets`: `requestParameters.hostedZoneId` and `changeBatch.changes[].{action,resourceRecordSet}`. Documented in full at `../route53.stealth.dns-zone-deleted/detections/detection_note_t1485.md` |
| "Was it used" pivot | None in a default account. Route 53 query logging is opt-in, one config per zone, `us-east-1` log group, **public zones only**, and AWS warns it may carry *"only one query out of every several thousand queries"* |
| Blast radius | Every record in every zone in the sweep, **plus the zones the alert never saw**. Not enumerable forward: a deleted zone is absent from `list-hosted-zones`, so scope is AWS Config minus surviving state |
| Error strings | `DeleteHostedZone`: `HostedZoneNotEmpty`, `InvalidDomainName`, `InvalidInput`, `NoSuchHostedZone`, `PriorRequestNotComplete`. `CreateHostedZone` (recovery): `InvalidDomainName`, `HostedZoneAlreadyExists`, `TooManyHostedZones`, `InvalidVPCId`, `InvalidInput`, `DelegationSetNotAvailable`, `ConflictingDomainExists`, `NoSuchDelegationSet`, `DelegationSetNotReusable`. Denials: `AccessDenied` and `AccessDeniedException` — match both |

### Residual Risk

The principal is severed and the queue is worked, and the names still do not resolve: every zone
recreated without a reusable delegation set answers on four different name servers, and until each
registration is changed — one action per zone, by whoever holds it, up to 48 hours to take effect —
the delegation points at Route 53 nameservers that no longer hold the zone. AWS's own warning
covers that entire window: someone could hijack the domain and route traffic to their own
resources using your domain name, and whether anyone did is not answerable from AWS, because query
logging is off by default and covers public zones only. The scope closes no further than AWS Config
reaches: zones destroyed before Config was recording, or before the CloudTrail lookback opened, are
gone with no record that they existed. And the records return only as far as the evidence goes —
`DELETE` changes are exact, but any purge large enough to push `requestParameters` past 100 KB left
nothing in the log at all.
