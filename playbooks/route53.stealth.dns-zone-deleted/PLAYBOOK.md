# IR Playbook: DNS Zone Deleted — a hosted zone destroyed via `route53:DeleteHostedZone`, after the records were already gone

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Destruction of availability (a DNS zone and every record in it are destroyed; the name stops resolving and, while the registrar still delegates to it, becomes claimable by somebody else) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High** for a deletion by a principal outside the infrastructure pipeline; **Critical** where the zone was public and the registration still delegates to it, because AWS states outright that "if you delete a hosted zone, someone could hijack the domain and route traffic to their own resources using your domain name". The source rates it **P2** and treats the event as the incident — but the event is the *end* of the incident, and the deletion cannot be undone |
| MITRE Tactics | Impact |
| MITRE Techniques | T1485 — verified live 2026-08-29. |
| Services in Scope | Route 53 (hosted zones), Route 53 Domains or the external registrar holding the delegation, AWS Config, CloudTrail, CloudWatch Logs (query logging, if configured), IAM, Organizations (SCP) |

**What the technique does:** the actor cannot call `DeleteHostedZone` on a zone that still holds records —
AWS refuses it with `HostedZoneNotEmpty` unless the zone contains only its default SOA and NS
records and DNSSEC signing is off. So the sequence is forced: one or more
`ChangeResourceRecordSets` batches with `action: DELETE` strip the zone, then `DeleteHostedZone`
removes what is left. Resolution stopped at the first batch. The delete event that fires the
alert carries `requestParameters.id` and nothing else — no zone name, no record count — and once
it succeeds `GetHostedZone` returns `NoSuchHostedZone`, so Route 53 can no longer tell you what
the zone was called. Recreating it fixes nothing by itself: Route 53 assigns four
**different** name servers to every hosted zone, so the registration still points at nameservers
that no longer hold it until the registrar is updated — *"which can require up to 48 hours to
take effect"*.

**Detection thesis.** The discriminator is the **precursor batch**, not the delete: a successful
`DeleteHostedZone` proves a `ChangeResourceRecordSets` purge already happened, and that purge is
where the outage began and where the destroyed records are recorded. The source rule matches
only the last event of the chain, and hands the analyst a zone ID that no Route 53 API can turn
back into a name.

> The same observable at volume is `../route53.stealth.multiple-dns-zones-deleted-by-a-single-user/`,
> which is a separate use case because the work-list has to be reconciled rather than read off
> the event and the principal must be severed before any zone is recreated. The delegation half
> of the hijack risk — a name handed away while the zone survives — is
> `../route53.stealth.ns-record-created-or-updated/`.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail management events for `route53.amazonaws.com`. **Route 53 is a global service and
  every one of its events is stamped `awsRegion: us-east-1`** — AWS requires the console Region
  selector to be US East (N. Virginia) to see them at all, so a `lookup-events` call in the
  account's home Region returns zero forever, which reads as "nothing happened"
- `DeleteHostedZone` carries `requestParameters.id` — **flat, and a different field name from
  `ChangeResourceRecordSets`'s `requestParameters.hostedZoneId`** — plus
  `responseElements.changeInfo.{id,status,submittedAt}`, and nothing else
- `ChangeResourceRecordSets` carries `requestParameters.hostedZoneId` and
  `requestParameters.changeBatch.changes[].action` /
  `.changes[].resourceRecordSet.{name,type,tTL}` / `.resourceRecordSet.resourceRecords[].value`.
  **`changes[]` holds the change objects directly — there is no `changes[].change` level — and
  the TTL field is `tTL`.** Alias records carry **no** `resourceRecords` and no `tTL`; their
  target is under `resourceRecordSet.aliasTarget`
- **AWS Config recording `AWS::Route53::HostedZone`.** This is the single highest-value item on
  this list: it is the only reliable way to recover a deleted zone's name and its record set,
  because Route 53 itself cannot and CloudTrail is explicitly labelled *"Do not use to
  reconstruct hosted zone"* by AWS on this very event
- An exported zone file or IaC state per zone, held outside Route 53. Without one, recovery means
  reading `DELETE` changes back out of CloudTrail — which works only because the API requires a
  delete to specify exact values, and only below CloudTrail's 100 KB omission threshold
- A recorded map of **which registrar holds each zone's delegation**, and who can change it —
  recovery needs a registrar change and the registrar may not be AWS
- Route 53 public-zone query logging where it is affordable — opt-in, one configuration per
  zone, log group in `us-east-1`, public zones only, and sampled by resolver caching (§6)

**Alerting (must be pre-configured)**
- **`DeleteHostedZone` succeeding for a principal outside the infrastructure pipeline → P0**
- **A zone emptied by `ChangeResourceRecordSets` and then deleted by the same principal within an hour → P0**
- **`DeleteHostedZone` refused with `HostedZoneNotEmpty` → P1**
- **A successful `ChangeResourceRecordSets` whose `requestParameters` is absent → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- A host **outside** the VPC from which to verify reachability. Testing from inside exercises a different path and proves nothing.
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
| P0 | `DeleteHostedZone` succeeding for a principal not on the infrastructure-pipeline allowlist | CloudTrail (management, `us-east-1`) | T1485 |
| P0 | A zone emptied by `ChangeResourceRecordSets` `DELETE` and then deleted by the same principal within an hour | CloudTrail (management, `us-east-1`) | T1485 |
| P1 | `DeleteHostedZone` refused with `HostedZoneNotEmpty` — the destruction attempted before its own precondition, and the only point at which nothing is lost yet | CloudTrail (management, `us-east-1`) | T1485 |
| P1 | A successful `ChangeResourceRecordSets` with no `changes[]` parsed — CloudTrail omits `requestParameters` above 100 KB, so this is a bulk zone rewrite whose contents are not in the log | CloudTrail (management, `us-east-1`) | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A child zone deleted while the parent zone still carries the matching NS record — the dangling-delegation window AWS documents | CloudTrail + live DNS | T1485 |

### Detection Rule Quality Notes

The source rule matches the last event in a chain the API itself forces, and passes on a bare zone ID.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Fires only on `DeleteHostedZone` | The record deletions that actually broke resolution are already minutes old when the alert arrives, and the `HostedZoneNotEmpty` refusal — the one moment nothing had been lost — is not matched at all | Ship the `DELETE`-action base rule and the `temporal_ordered` correlation, and alert separately on the refusal |
| No principal filter | Infrastructure code deletes hosted zones routinely, so in any account with IaC the rule is muted within weeks — and muted in the direction that hides the deletion nobody planned | Allowlist the pipeline **principal**; the zone ID is unpredictable and cannot be allowlisted in advance |
| Passes a zone ID with no name, and treats the deletion as the damage | `requestParameters.id` is the whole payload, and after the delete `GetHostedZone` returns `NoSuchHostedZone` — an analyst holding `Z1PA6795UKMFR9` cannot say which service stopped resolving. Meanwhile AWS's own warning is that the *name* becomes claimable: "if you delete a hosted zone, someone could hijack the domain and route traffic to their own resources using your domain name" | Enrich at alert time from AWS Config, or from an earlier CloudTrail event on the same ID — the KQL does the join — and carry the registrar's delegation state into triage |
| Assumes `requestParameters` is always there | CloudTrail **omits** the field above 100 KB rather than truncating it, and Route 53 allows 1,000 `ResourceRecord` elements per request — so a bulk rewrite parses to zero changes and scores as clean | Score an absent `requestParameters` on a successful change as a finding in its own right |

**Recommended detection — a hosted zone destroyed by a principal outside the deployment pipeline.**

```yaml
# DNS Zone Deleted (T1485 — Data Destruction)
#
# WHAT THE SOURCE RULE DOES. `eventName:"DeleteHostedZone"` plus a success filter, grouped by
# caller. It fires on the LAST call of the sequence and on nothing else, and the event it fires
# on is the least informative one in the whole chain.
#
# THE DELETE IS THE TIDY-UP, NOT THE DESTRUCTION. AWS: "You can delete a hosted zone only if it
# contains only the default SOA and NS records and has DNSSEC signing disabled. If the hosted
# zone contains other records or has DNSSEC enabled, you must delete the records and disable
# DNSSEC before deletion. Attempting to delete a hosted zone with additional records or DNSSEC
# enabled returns a `HostedZoneNotEmpty` error." So a SUCCESSFUL DeleteHostedZone PROVES that a
# ChangeResourceRecordSets batch already emptied the zone, and that batch is where resolution
# actually stopped. The correlation below is therefore not a bonus - it is the rule that catches
# the incident while it is still in progress, and `HostedZoneNotEmpty` is the actor who tried the
# delete before finishing the purge.
#
# THE EVENT CARRIES A ZONE ID AND NOTHING ELSE. `requestParameters.id` - flat, and a DIFFERENT
# field name from ChangeResourceRecordSets' `hostedZoneId`. No zone name, no record count, no
# public/private flag. After the delete, GetHostedZone returns NoSuchHostedZone, so the NAME IS
# NOT RECOVERABLE FROM ANY ROUTE 53 API. Enrichment must come from AWS Config
# (`AWS::Route53::HostedZone` is a recorded resource type) or from an earlier CloudTrail event on
# the same ID. An alert that reaches an analyst carrying only `Z1PA6795UKMFR9` is not actionable.
#
# WHY THIS IS NOT MERELY AN OUTAGE. AWS, on the same page: "if you delete a hosted zone, someone
# could hijack the domain and route traffic to their own resources using your domain name." The
# registrar's delegation still names four Route 53 nameservers that no longer hold the zone. AWS
# also documents the correct teardown ORDER for a child zone - "We suggest that you delete the NS
# record first, and wait for the TTL on that NS record to expire before you delete the child
# hosted zone. This ensures that no one can hijack the child hosted zone while DNS resolvers
# still have the child hosted zone's name servers cached." An actor deleting the zone while the
# parent NS record stands is operating in exactly the window AWS warns about.
#
# REGION. `route53.amazonaws.com` events are stamped `us-east-1` and AWS requires the console
# Region selector to be US East (N. Virginia) to see them at all. A pipeline that filters
# Route 53 to the account's home Region receives nothing, forever.
title: Route 53 public or private hosted zone deleted outside the deployment pipeline
id: 13089582-c23d-4ef0-923c-4982be648044
name: route53_hosted_zone_deleted
status: experimental
description: >-
  A Route 53 hosted zone was destroyed by a principal that does not own the infrastructure
  pipeline. Deletion cannot be undone; a recreated zone is assigned four DIFFERENT name servers,
  so resolution stays broken until the registrar is updated, and until then AWS warns the name
  can be hijacked.
references:
  - https://attack.mitre.org/techniques/T1485/                                                    # retrieved 2026-08-29
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_DeleteHostedZone.html             # retrieved 2026-08-29
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DeleteHostedZone.html               # retrieved 2026-08-29
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/logging-using-cloudtrail.html       # retrieved 2026-08-29
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
  # POPULATE BEFORE DEPLOYING. Hosted zones are torn down legitimately by infrastructure code,
  # and an unpopulated allowlist reproduces the source rule's false-positive rate. Allowlist the
  # PRINCIPAL: the zone ID is not predictable and cannot be allowlisted in advance.
  iac_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace with this account's Terraform/CDK execution role
      - ':role/cloudformation-exec' # replace with this account's CloudFormation service role
  condition: selection and success and not iac_pipeline
falsepositives:
  - >-
    Decommissioning a domain, or collapsing a subdomain zone into its parent. Legitimate, and it
    should arrive with a change record; if it routinely does not, the finding is that DNS is not
    under change control. Service-linked teardowns (AWS Cloud Map and similar) carry
    userIdentity.invokedBy — check it before treating a deletion as human activity.
level: high
---
# Base rule — sequence component only, not for direct alerting. Carries the success filter so a
# refused purge cannot compose into the correlation below (D-f).
#
# The DELETE action is the one Route 53 change that records what it removed: "To delete a
# resource record set, you must specify all the same values that you specified when you created
# it." So this event's `resourceRecords` ARE the destroyed records - the only machine-readable
# copy of them that will exist. UPSERT carries no such guarantee.
#
# ARRAY ADDRESSING. `changes` is a list and `resourceRecords` is a list inside it. The dotted
# form below is what Elastic-family and Sentinel backends produce from a flattened event; a
# backend requiring explicit indices needs `[0]` inserted. Confirm against one real event.
title: Route 53 records deleted from a hosted zone
id: 01f6f23e-faa8-4b10-8e27-9ace91c22d03
name: route53_zone_records_purged_bb
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
  condition: selection and delete_action and success
level: informational
---
# A zone emptied and then deleted by one principal is one operation, and the emptying is where
# resolution actually stopped. Route 53 REFUSES DeleteHostedZone on a non-empty zone, so this
# ordering is not a heuristic about attacker behaviour - it is the only order in which the API
# permits the sequence to complete. One hour covers a scripted purge of a large zone; Route 53
# rejects a second change to the same zone while the first is in flight
# (`PriorRequestNotComplete`), which serialises a bulk purge and stretches it.
title: Route 53 hosted zone emptied and then deleted by one principal
id: 5afa532b-d279-46cb-9339-6323588403ba
status: experimental
description: >-
  One principal deleted records from a hosted zone and then deleted the zone within an hour. The
  record deletions are the destruction; the zone deletion is the tidy-up behind them and the
  point past which the zone name is no longer recoverable from any Route 53 API.
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_DeleteHostedZone.html             # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: temporal_ordered
  rules:
    - route53_zone_records_purged_bb
    - route53_hosted_zone_deleted
  group-by:
    - userIdentity.arn
  timespan: 1h
level: critical
---
# THE EARLY WARNING, AND THE ONLY ONE THIS TECHNIQUE OFFERS. `HostedZoneNotEmpty` is somebody
# calling DeleteHostedZone on a zone that still holds records - the destruction attempted before
# its own precondition was met. It is intent observed BEFORE any record is lost, and no
# legitimate pipeline produces it: infrastructure code deletes the records it created and then
# the zone, in that order, and gets no refusal.
#
# No allowlist is applied and that is deliberate: the refusal itself is the finding, it is rare
# enough to alert on unfiltered, and adding a principal filter would hide precisely the case
# where the pipeline role is the compromised one.
title: Route 53 hosted zone deletion refused because the zone still holds records
id: f3af98a2-e2f0-4caf-b039-0f45d4d52e74
name: route53_hosted_zone_delete_refused
status: experimental
description: >-
  A DeleteHostedZone call was refused with HostedZoneNotEmpty. Somebody tried to destroy a zone
  before emptying it. Nothing has been lost yet; the next events in this principal's session are
  the record deletions that make the retry succeed.
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
  refused:
    errorCode: 'HostedZoneNotEmpty'
  condition: selection and refused
falsepositives:
  - >-
    An operator exploring the console and backing out. Should be traceable to a person within
    minutes; if it is not, treat it as the first event of the incident.
level: medium
```

The rule cannot tell you what the zone was called, cannot see whether the parent still delegates
to it, and cannot distinguish a public zone from a private one — `hostedZoneConfig.privateZone`
is on `CreateHostedZone`, not on the delete. `detections/kql_t1485.kql` resolves the name by
joining backward on the zone ID; Query 2 below settles the delegation question against live DNS.

---

### Key Investigation Queries

> **Route 53 is global — every `route53.amazonaws.com` event lands in `us-east-1` and a query in any other Region returns zero.** Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: which zone was destroyed, what was in it, and who did both halves

```bash
REGION="us-east-1"
RAW=$(for EV in DeleteHostedZone ChangeResourceRecordSets CreateHostedZone; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: a failed call, a missing"
  echo "    cloudtrail:LookupEvents permission, or a Region other than us-east-1. Route 53 is"
  echo "    GLOBAL and only us-east-1 carries its events. This is NOT 'no zone was deleted'."
else
  # The delete calls the zone `id` and the change calls it `hostedZoneId`. Either may arrive
  # bare or path-qualified, so both are reduced to the last path segment before they are joined.
  # An absent changes[] on a SUCCESSFUL change is reported as omitted, not as zero changes:
  # CloudTrail drops requestParameters entirely above 100 KB.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "route53.amazonaws.com") |
    ((.requestParameters.id // .requestParameters.hostedZoneId
      // .responseElements.hostedZone.id // "") | sub("^.*/"; "")) as $zid |
    (.requestParameters.changeBatch.changes // []) as $ch |
    {time: .eventTime, event: .eventName, zone_id: $zid,
     zone_name: (.requestParameters.name // "not-on-this-event"),
     delegation_set: (.requestParameters.delegationSetId // "none - new name servers on recreate"),
     caller_arn: .userIdentity.arn, access_key: .userIdentity.accessKeyId,
     invoked_by: (.userIdentity.invokedBy // "direct"), change_count: ($ch | length),
     params_omitted: (.eventName == "ChangeResourceRecordSets"
                      and (.errorCode // "") == "" and ($ch | length) == 0),
     deleted: [$ch[] | select(.action == "DELETE") | {name: .resourceRecordSet.name,
                type: .resourceRecordSet.type, ttl: (.resourceRecordSet.tTL // "alias - no ttl"),
                values: [(.resourceRecordSet.resourceRecords // [])[].value],
                alias: (.resourceRecordSet.aliasTarget.dNSName // "not-an-alias")}],
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.time) | group_by(.zone_id) |
         map({zone_id: .[0].zone_id,
              zone_name: ([.[] | .zone_name | select(. != "not-on-this-event")] | first // "UNRESOLVED"),
              delegation_set: ([.[] | .delegation_set] | unique | join(",")),
              caller_arn: ([.[] | .caller_arn] | unique | join(",")),
              deleted_records: [.[] | .deleted[]],
              omitted_batches: ([.[] | select(.params_omitted)] | length),
              refusals: ([.[] | select(.error == "HostedZoneNotEmpty")] | length),
              timeline: [.[] | {time, event, error, caller_arn, change_count}]})'
fi
```

Read it zone by zone. `zone_name` of `UNRESOLVED` means neither a `CreateHostedZone` nor a record
name survives the window — go to AWS Config, because no Route 53 API will answer.
`deleted_records` is the **only machine-readable copy of the zone that survives**, and it is
exact: AWS requires a `DELETE` to specify all the same values the record was created with.
`omitted_batches` above zero means a purge was large enough that CloudTrail dropped
`requestParameters`; those records are not in the log and the export is the only source.
`refusals` dates the earliest observable moment. `delegation_set` of `none` means a recreated
zone gets **different** name servers. Carry `zone_id`, `zone_name` and `caller_arn` below.

#### Query 2 — Inspect live state: is the name still delegated to Route 53, and who answers for it now

```bash
ZONE_NAME="<zone-name-from-Query-1>"
ZONE_ID="<zone-id-from-Query-1>"

# 1. Does the zone still exist? An error here is a failed call, not an absence.
Z=$(aws route53 get-hosted-zone --id "$ZONE_ID" --output json 2>&1)
case "$Z" in
  *NoSuchHostedZone*) echo "[FAIL] $ZONE_ID is gone. Deletion is irreversible; a new zone gets"
                      echo "       four DIFFERENT name servers and the registrar must be updated.";;
  *HostedZone*)       echo "[OK] $ZONE_ID still exists - the delete did not complete, or somebody"
                      echo "     recreated it. Find out who before standing down.";;
  *)                  echo "[!] INCONCLUSIVE - unexpected get-hosted-zone output: $Z";;
esac

# 2. What does the internet think? The parent's NS records are the delegation, and they outlive
# the zone. `dig +short NS` returns nothing on NXDOMAIN and nothing on a failed lookup, so the
# two are separated by asking for the status explicitly.
if command -v dig >/dev/null 2>&1; then
  DELEG=$(dig +noall +authority +answer NS "$ZONE_NAME" 2>&1)
  STATUS=$(dig NS "$ZONE_NAME" 2>&1 | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
  case "${STATUS:-none}" in
    NOERROR)  echo "[FAIL] somebody is authoritative for $ZONE_NAME. If it is not you, the name"
              echo "       has been taken over:"; echo "$DELEG";;
    NXDOMAIN) echo "[OK] $ZONE_NAME does not exist in the parent - the delegation is gone too";;
    SERVFAIL) echo "[FAIL] SERVFAIL - the parent still delegates to name servers that no longer"
              echo "       hold the zone. This is the hijack window AWS warns about, and it stays"
              echo "       open until the registrar is updated:"; echo "$DELEG";;
    none)     echo "[!] INCONCLUSIVE - dig printed no status line; the lookup failed. Resolve by hand.";;
    *)        echo "[!] INCONCLUSIVE - unexpected DNS status '$STATUS' for $ZONE_NAME";;
  esac
else
  echo "[!] INCONCLUSIVE - dig is not installed. The delegation state is UNKNOWN, and it is the"
  echo "    field that decides whether this is an outage or a takeover. Check from another host."
fi

# 3. Is the registration in this account at all? Route 53 Domains is a DIFFERENT service, capped
# at 20 domains per account, so this is one cheap call - and it decides who can fix the delegation.
D=$(aws route53domains list-domains --region us-east-1 --output json 2>&1)
case "$D" in
  *Domains*) printf '%s' "$D" | jq -r --arg z "$ZONE_NAME" '.Domains[] |
               select(($z | rtrimstr(".")) | endswith(.DomainName)) |
               "[i] registered here: \(.DomainName)  transferLock=\(.TransferLock)  expires=\(.Expiry)"'
             echo "[i] no output above means the registration is NOT in this account - the"
             echo "    delegation change needed for recovery is somebody else's action.";;
  *)         echo "[!] INCONCLUSIVE - could not list registered domains: $D";;
esac
```

The three answers combine into the severity: a zone that is gone, a parent that still delegates
and a registration held elsewhere is the worst case. `SERVFAIL` means the delegation survived the
zone — resolvers are being sent to Route 53 nameservers that no longer answer for the name.

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

Nothing here restores service: the deletion is irreversible and the recreated zone carries
different name servers. Containment closes **the window in which the name can be claimed by
somebody else** and stops the principal taking the next zone. Do them in that order only if
Query 2 showed the parent still delegating — otherwise contain the principal first, because a
recreated zone holds only its default SOA and NS records, which is exactly the state
`DeleteHostedZone` requires, so an uncontained actor deletes it again immediately.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Reclaim the name before anybody else does

```bash
ZONE_NAME="<zone-name-from-Query-1>"; DSET="<delegation-set-from-Query-1>"
REF="ir-$(date -u +%Y%m%dT%H%M%SZ)"

if [ "$ZONE_NAME" = "UNRESOLVED" ] || [ -z "$ZONE_NAME" ]; then
  echo "[!] INCONCLUSIVE - the zone name is unknown, so nothing can be recreated. Recover it"
  echo "    from AWS Config (AWS::Route53::HostedZone) before continuing; no Route 53 API will"
  echo "    return it and CloudTrail is labelled 'Do not use to reconstruct hosted zone'."
else
  # A reusable delegation set returns the SAME four name servers, which makes this a restore
  # rather than a re-delegation. Without one, the new zone answers on different names.
  case "$DSET" in
    none|"") NEW=$(aws route53 create-hosted-zone --name "$ZONE_NAME" \
                     --caller-reference "$REF" --output json 2>&1);;
    *)       NEW=$(aws route53 create-hosted-zone --name "$ZONE_NAME" \
                     --caller-reference "$REF" --delegation-set-id "$DSET" --output json 2>&1);;
  esac
  case "$NEW" in
    *DelegationSet*)
      echo "[OK] $ZONE_NAME recreated. Its name servers are now:"
      printf '%s' "$NEW" | jq -r '.DelegationSet.NameServers[]'
      echo "[i] Compare these against the delegation Query 2 printed. If they differ, resolution"
      echo "    stays broken until the registrar is updated - up to 48 hours to take effect.";;
    *ConflictingDomainExists*|*HostedZoneAlreadyExists*)
      echo "[FAIL] Route 53 refused: a zone for $ZONE_NAME already exists, in this account or"
      echo "       another. Somebody may already have claimed it. Investigate before retrying.";;
    *) echo "[!] INCONCLUSIVE - create-hosted-zone did not return a delegation set: $NEW";;
  esac
fi
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["route53:DeleteHostedZone","route53:ChangeResourceRecordSets","route53:DisableHostedZoneDNSSEC","route53:DeleteQueryLoggingConfig","route53domains:UpdateDomainNameservers"],"Resource":"*"}]}'
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
```

The session revocation denies only tokens issued **before** `$CUTOFF`; a credential re-fetched
afterwards carries a newer `aws:TokenIssueTime` and is not denied. It kills what is currently
leaked; it does not gate the role.

---

## 4. Eradication

### Remove Attacker Access

- **Capture Query 1's output to a file before anything else.** `deleted_records` is the only
  machine-readable copy of the zone that will exist, and its retention is CloudTrail's, not yours.
- **Check every other zone the principal touched**, not just the one that alerted — Query 1's
  grouping already lists them — and confirm `DeleteQueryLoggingConfig` and
  `DisableHostedZoneDNSSEC` were not also left off. Both sit in the same permission
  neighbourhood, and the second had to precede a delete on a DNSSEC-signed zone.
- **Right-size the permission.** `route53:DeleteHostedZone` belongs to the pipeline role and to
  nothing else; pair it with the SCP in §6. And create a **reusable delegation set** for every
  zone that matters, so the next deletion is a restore rather than a re-delegation — it is the
  only control that removes the registrar from the recovery path.
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

#### Verify the zone answers, and that the delegation points at the zone that answers

```bash
ZONE_NAME="<zone-name-from-Query-1>"; VERDICT="clean"

# The zone must exist AND its name servers must be the ones the parent delegates to. Both halves
# can fail after the recreation in §3, so [FAIL] stays reachable: list-hosted-zones-by-name
# returns whatever exists now, and the delegation is read live from DNS.
H=$(aws route53 list-hosted-zones-by-name --dns-name "$ZONE_NAME" --output json 2>&1)
case "$H" in
  *HostedZones*)
    ZID=$(printf '%s' "$H" | jq -r --arg n "$ZONE_NAME" \
            '[.HostedZones[] | select(.Name == ($n | sub("\\.?$"; ".")))] | .[0].Id // ""')
    if [ -z "$ZID" ]; then
      echo "[FAIL] no hosted zone named $ZONE_NAME exists in this account"; VERDICT="fail"
    else
      NS=$(aws route53 get-hosted-zone --id "$ZID" --output json 2>&1)
      case "$NS" in
        *DelegationSet*) echo "[OK] $ZONE_NAME exists as $ZID, answering on:"
                         printf '%s' "$NS" | jq -r '.DelegationSet.NameServers[]';;
        *) echo "[!] INCONCLUSIVE - could not read the delegation set for $ZID: $NS"; VERDICT="inconclusive";;
      esac
    fi;;
  *) echo "[!] INCONCLUSIVE - could not list hosted zones: $H"; VERDICT="inconclusive";;
esac

# The independent half. Ask the internet, not the API.
if command -v dig >/dev/null 2>&1; then
  LIVE=$(dig +short NS "$ZONE_NAME" 2>&1 | sed 's/\.$//' | sort | tr '\n' ' ')
  if [ -z "$LIVE" ]; then
    echo "[FAIL] $ZONE_NAME publishes no NS records - the delegation is not restored"; VERDICT="fail"
  else
    echo "[i] the parent delegates $ZONE_NAME to: $LIVE - compare against the set above. A"
    echo "    mismatch means the registrar is not updated and the name does not reach your zone."
  fi
else
  echo "[!] INCONCLUSIVE - dig is not installed; the delegation could not be checked"
  VERDICT="inconclusive"
fi

case "$VERDICT" in
  clean)        echo "[OK] the zone exists and its delegation was readable - now confirm the two name-server sets match";;
  fail)         echo "[FAIL] recovery is not complete - see the lines above";;
  inconclusive) echo "[!] INCONCLUSIVE - at least one check could not run. Do not close on this.";;
esac
echo "[i] None of this speaks to the RECORDS - a zone that resolves but is empty is still an"
echo "    outage. Reconcile against deleted_records from Query 1."
```

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     DeleteHostedZone / route53.amazonaws.com / no errorCode, in us-east-1,"
echo "  where userIdentity.arn is NOT on the pipeline allowlist - and, at critical, on a"
echo "  ChangeResourceRecordSets DELETE batch followed by that delete within one hour."
echo "MUST NOT fire on: the pipeline role's scheduled teardown; a DeleteHostedZone returning"
echo "  NoSuchHostedZone, InvalidInput or AccessDenied; a ChangeResourceRecordSets that only"
echo "  CREATEs or UPSERTs. HostedZoneNotEmpty is the SEPARATE medium rule, not this one."
echo "EXPECTED FP, by design: a decommissioning that a human performed by hand outside the"
echo "  pipeline. If that is common here, the finding is that DNS is not under change control."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the pipeline could empty and destroy a production hosted zone | `route53:ChangeResourceRecordSets` and `route53:DeleteHostedZone` granted broadly, with no SCP confining the delete to the deployment role |
| The alert arrived after resolution had already stopped | The deployed rule matched only `DeleteHostedZone`, which the API forces to be the *last* call in the sequence; the record deletions and the `HostedZoneNotEmpty` refusal were not matched at all |
| Nobody could name the destroyed zone from the alert | AWS Config was not recording `AWS::Route53::HostedZone`, and the delete event carries only `requestParameters.id` |
| Recovery needed a party outside the account | The zone was not created against a reusable delegation set, so the recreated zone answered on four different name servers and the registrar's delegation had to be changed |

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

- **Create every production zone against a reusable delegation set.** It is the only control that
  makes a deleted zone genuinely restorable: the recreated zone keeps the same four name servers,
  so the registrar never enters the recovery path and the 48-hour propagation cost disappears.
- **Turn on AWS Config for `AWS::Route53::HostedZone`** — Route 53 cannot tell you a deleted
  zone's name, and AWS labels its own CloudTrail record *"Do not use to reconstruct hosted zone"*.
- **Export every zone on a schedule.** `list-resource-record-sets` into version control turns
  recovery from CloudTrail archaeology into a replay, and it is the only thing that covers a
  purge large enough that CloudTrail omitted `requestParameters` altogether.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1485 — Data Destruction (Impact, TA0040), which lists IaaS. |
| Primary API | `route53:ChangeResourceRecordSets` with `action: DELETE`, then `route53:DeleteHostedZone`. The order is forced by the API, not chosen by the actor |
| Event source | `route53.amazonaws.com`, **management** plane, **global — every event is stamped `awsRegion: us-east-1`** and a query elsewhere returns zero |
| Key discriminator | The preceding `DELETE` batch. A successful delete *proves* one happened; the delete alone says only that a zone ID stopped existing |
| Field shape | `DeleteHostedZone`: `requestParameters.id` (flat) and `responseElements.changeInfo.{id,status,submittedAt}`. `ChangeResourceRecordSets`: `requestParameters.hostedZoneId` — a **different name for the same thing** — plus `changeBatch.changes[].action` and `.changes[].resourceRecordSet.{name,type,tTL}` / `.resourceRecords[].value`. **No `changes[].change` level. `tTL`, not `ttl`. Alias records carry no `resourceRecords` and no `tTL`** |
| "Was it used" pivot | There generally is not one. Route 53 public-zone query logging is opt-in, one config per zone, log group in `us-east-1`, **public zones only**, and AWS warns it may hold *"only one query out of every several thousand"*. In a default account, whether anything tried to resolve the name after it went is unanswerable from AWS |
| Blast radius | Every record in the zone, and every name below it. Not in the event: reconstruct from the `DELETE` changes (exact, because the API demands exact values) or from AWS Config. Above 100 KB CloudTrail **omits** `requestParameters` entirely and those records are simply gone |
| Error strings | `DeleteHostedZone`: `HostedZoneNotEmpty`, `InvalidDomainName`, `InvalidInput`, `NoSuchHostedZone`, `PriorRequestNotComplete`. `ChangeResourceRecordSets`: `InvalidChangeBatch`, `InvalidInput`, `NoSuchHealthCheck`, `NoSuchHostedZone`, `PriorRequestNotComplete`. Throttling: code `Throttling`, message *"Rate exceeded"*. Denials: `AccessDenied` and `AccessDeniedException` — match both |

### Residual Risk

The zone is recreated and the principal is contained, and neither restores resolution: the new
zone answers on four different name servers, and until the registrar's delegation is changed —
up to 48 hours to take effect, by whoever holds the registration, which may not be this account —
the name resolves to nothing. During that window AWS's own warning stands: someone can hijack the
domain and route traffic to their own resources using your domain name. Whether anybody did is
not answerable from AWS, because query logging is off by default and covers public zones only. And
the records are restored only as far as the evidence reaches: `DELETE` changes are exact, but a
purge large enough to push `requestParameters` past 100 KB left nothing in the log at all, and
AWS's own label on this event is *"Do not use to reconstruct hosted zone"*.
