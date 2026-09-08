# IR Playbook: Domain Shadowing — a subdomain delegated away via an NS record in `ChangeResourceRecordSets`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Resource development (part of the organisation's namespace is handed to third-party nameservers, with nothing else disturbed) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High, and critical when the nameservers are not Route 53's. The ceiling is complete control of a subtree of the organisation's own namespace — including the ability to satisfy DNS-based domain-control validation and obtain a publicly trusted certificate for names under it. The source rule's low rating reflects how ordinary the event looks, not what it grants. |
| MITRE Tactics | Resource Development |
| MITRE Techniques | T1584.001 |
| Services in Scope | Route 53 (hosted zones), AWS Config, CloudTrail, and any certificate authority the organisation uses |

**What the technique does:** an attacker with DNS write permission creates one NS record in an
existing hosted zone — say `cdn.example.com` — pointing at nameservers they control. AWS
documents the mechanism as a feature: *"You can also delegate a subdomain to other DNS services
by creating NS records that point to those services' name servers instead."* From that moment
Route 53 stops answering for anything at or below `cdn.example.com`, and the attacker's
nameservers answer instead. The alternative form is an `UPSERT` on the zone's **apex** NS RRset,
which changes which nameservers Route 53 itself claims are authoritative for the entire zone.

The reason the usual reflexes miss it is that nothing breaks. Every existing record stays where
it was. Every service keeps working. No log stops flowing. Monitoring is green, because the names
being monitored still resolve — they resolve through Route 53, and only the new subtree is
delegated away. ATT&CK describes exactly this: *"As service will not be disrupted, the malicious
subdomains may go unnoticed for long periods of time."*

**Detection thesis:** the discriminating fact is **whose nameservers the record names**. Route
53's are always `ns-<n>.awsdns-<n>.{com,net,org,co.uk}`, so a delegation whose values do not
contain `awsdns` points at somebody else's infrastructure — a one-field test needing no baseline.
The source rule matches the event and never reads the values.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail management events for `route53.amazonaws.com`, read in `us-east-1`.** AWS states
  the rule outright: *"To view events for Route 53 API requests, you must choose US East (N.
  Virginia) in the Region selector."* Anywhere else returns zero.
- **AWS Config recording `AWS::Route53::HostedZone`.** `UPSERT` carries only the new nameservers
  and Route 53 keeps no version history, so this is the only before-and-after the platform offers
  and the only way to answer "what did this delegate to yesterday".
- **A committed inventory of every NS record in every zone**, apex and delegation alike, in
  version control. A delegation created before the log window opened is invisible to CloudTrail
  forever; only a state comparison finds it.
- **Certificate transparency monitoring for the domain and its wildcards.** Whoever holds a
  delegation can complete DNS-based domain-control validation for names under it.

**Alerting (must be pre-configured)**
- **An NS `CREATE`/`UPSERT` whose values are not Route 53 nameservers and not an approved external provider → P0**
- **An NS `CREATE`/`UPSERT` at the zone apex → P0**
- **Any successful NS `CREATE`/`UPSERT` by a principal outside the DNS automation allowlist → P1**
- **A `DeleteHostedZone` on a child zone while the parent still carries the matching NS record → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under
  investigation; `jq`; `dig` or an equivalent that can query a specific nameserver directly.

**Known IOC Baselines**
- **The approved external DNS providers**, if any. Both the Sigma and the KQL carry a placeholder
  and say they are inert until it is populated. For most estates the correct value is an empty
  list, and every external delegation is then a finding.
- Which principals may write DNS. This should be an IaC role, not a person.
- The current apex NS RRset of every zone, so a change to it is a diff rather than a judgement.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ChangeResourceRecordSets`, `CREATE`/`UPSERT`, type `NS`, values containing no `awsdns` and no approved external suffix | CloudTrail (`us-east-1`) | T1584.002 |
| P0 | An NS `CREATE`/`UPSERT` whose record name equals the hosted zone's own name — the apex RRset | CloudTrail + zone-name resolve | T1584.001 |
| P1 | Any successful NS `CREATE`/`UPSERT` by a principal outside the DNS automation allowlist | CloudTrail (`us-east-1`) | T1584.001 |
| P1 | `DeleteHostedZone` on a child zone while the parent zone still carries the matching NS record — a live dangling delegation | CloudTrail + `ListResourceRecordSets` | T1584.001 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A delegation published with `tTL` ≥ 172800 (48h) or ≤ 300 — expensive to undo, or built to be swapped | CloudTrail (`us-east-1`) | T1584.001 |
| P2 | An NS change refused with `InvalidChangeBatch`, `AccessDenied` or repeated `PriorRequestNotComplete` | CloudTrail (`us-east-1`) | T1584.001 |
| P3 | A delegated subtree whose nameservers stop responding, or begin answering differently | External resolution check | T1584.002 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Never reads the nameservers | This is the entire detection. A delegation to Route 53's own nameservers is routine subdomain plumbing; a delegation to anything else hands the subtree away. The rule cannot distinguish them, so it fires identically on both and gets muted by the routine case | `route53_ns_delegated_outside_route53` at critical — values not containing `awsdns`, minus an explicit approved-provider list |
| No allowlist of DNS-writing principals | In an IaC estate, creating any child hosted zone writes an NS record into the parent, so every apply fires the rule | `known_dns_automation` on the core rule; an NS change by anything else is the finding |
| Ignores TTL | AWS recommends 172800s for a delegation, and that same number is the cache tail inherited on revert. A very long TTL is expensive to undo; a very short one was built to be swapped. The field showing this is discarded | `tTL` projected and read in both directions; note the spelling is `tTL`, lower `t` upper `TL` — `ttl` resolves to null and silently disables it |
| Success-only | A refused NS change is intent observed, and batches are transactional so nothing was applied — the operator simply failed validation on the first attempt | A refusal rule at medium over the API's closed error set |
| Cannot see a delegation that predates the log | CloudTrail answers "what changed", never "what is". A delegation created before the retention window is invisible to every event-based rule, permanently | Query 2 walks `ListResourceRecordSets` per zone against current state, and it is a standing control rather than an incident step |

**Recommended detection — read whose nameservers the record names, not merely that it changed.**

```yaml
# Subdomain delegation created — domain shadowing via an NS record (T1584.001 / T1584.002)
#
# WHAT AN NS RECORD DOES DEPENDS ENTIRELY ON ITS NAME, AND AWS DISTINGUISHES THE TWO USES:
#   name == the hosted zone's own name  -> the APEX NS RRset. It declares which nameservers
#     Route 53 itself claims are authoritative. AWS: "Except in rare circumstances, we recommend
#     that you don't add, change, or delete name servers in this record." UNVERIFIED: no AWS page
#     states that Route 53 ENFORCES this. Treated here as permitted, rare, and very high signal.
#   name is a label below the zone      -> a DELEGATION. AWS: "You can also delegate a subdomain
#     to other DNS services by creating NS records that point to those services' name servers."
#
# A DELEGATION HANDS THE ENTIRE SUBTREE BELOW THAT LABEL TO WHOEVER OPERATES THE LISTED
# NAMESERVERS. Route 53 stops answering for anything under it. No other record is touched, no
# service breaks, nothing in the account changes. That is why the technique is quiet, and it is
# exactly what ATT&CK calls domain shadowing: "the malicious subdomains may go unnoticed for long
# periods of time."
#
# THE RULE BELOW CANNOT TELL APEX FROM DELEGATION AND DOES NOT PRETEND TO. The event carries
# requestParameters.hostedZoneId — an ID — and resourceRecordSet.name, a name. Deciding which is
# which requires the zone's NAME, which is not in the event. That comparison is in Query 2 of
# ../PLAYBOOK.md, which resolves the ID to a name and classifies every NS record in the account.
#
# THE DISCRIMINATOR THAT IS IN THE EVENT: WHOSE NAMESERVERS. Route 53's own nameservers are always
# ns-<n>.awsdns-<n>.{com,net,org,co.uk}. A delegation whose values do not contain `awsdns` points
# the subtree at somebody else's infrastructure. That is a one-field test needing no baseline, and
# it is the second rule here.
#
# TTL IS THE UNDO COST. AWS recommends 172800 seconds — 48 hours — for a delegation NS record, and
# that same number is the cache lifetime a responder inherits after reverting one. A delegation
# created with a very long TTL is expensive to undo; one created with a very short TTL is designed
# to be swapped. Neither is matched here (Sigma has no reliable numeric comparison across
# backends for this field) — the value is projected in the KQL and carries its own trigger row.
#
# FIELD SHAPES — verified against AWS's published CloudTrail sample for ChangeResourceRecordSets:
#   changes[] holds the change objects DIRECTLY; there is no intermediate `change` key.
#   The TTL member is `tTL` — lower t, upper TL. `ttl` and `TTL` both resolve to null.
#   resourceRecordSet.name carries a TRAILING DOT and is stored normalised.
#   NS records are never alias records — AWS: NS is not aliasable, is unavailable for weighted,
#   latency, geolocation and failover routing, and "You can't use the * wildcard for resource
#   records sets that have a type of NS." So resourceRecords[] is always populated here, unlike
#   for A records, and the value test below cannot be evaded by using an alias.
#   ONE EVENT CAN CARRY MANY CHANGES OF MANY TYPES, so the two keys in each block below are ANDed
#   across the BATCH, not proven to belong to one element. Deliberate superset; the element-level
#   walk is in kql_t1584_001.kql (mv-expand) and Query 1. Triage reads which element changed.
#
# REGIONALITY. route53.amazonaws.com events carry awsRegion us-east-1 and AWS states the console
# rule outright. A lookup in any other Region returns zero, and that zero is INCONCLUSIVE.
title: NS record created or updated in a hosted zone
id: 7c1a45e9-3f82-4d60-b9e4-08a5d726fb31
name: route53_ns_record_changed
status: experimental
description: >-
  An NS record was created or replaced. If the record's name is the zone's own name this changes
  which nameservers Route 53 claims are authoritative for the whole zone; if it is a label below
  the zone it delegates that entire subtree to whoever operates the listed nameservers. Both are
  rare, both are deliberate, and neither is a side effect of ordinary application work. UPSERT is
  the dangerous action — it replaces the record set outright, the event carries only the NEW
  nameservers, and Route 53 keeps no version history, so the previous delegation is recoverable
  only from IaC state, from AWS Config, or from an earlier event that set it.
references:
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/CreatingNewSubdomain.html
  - https://attack.mitre.org/techniques/T1584/001/
tags:
  - attack.resource-development
  - attack.t1584.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53.amazonaws.com'
    eventName: 'ChangeResourceRecordSets'
  ns_write:
    requestParameters.changeBatch.changes.resourceRecordSet.type: 'NS'
    requestParameters.changeBatch.changes.action:
      - 'CREATE'
      - 'UPSERT'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the roles that own DNS through infrastructure-as-code. If this
  # is empty the rule still works and simply has no exclusions, which is a defensible default for
  # a record type most zones change once and never again.
  known_dns_automation:
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/PlatformAutomation'
  condition: selection and ns_write and success and not known_dns_automation
falsepositives:
  - >-
    Standing up a genuine subdomain on a third-party DNS provider. Legitimate and planned; confirm
    against the change ticket, and note that the nameservers named in it are the tuning surface.
  - >-
    Creating a new hosted zone through IaC, which writes the child's NS record into the parent.
    Allowlist the automation role — never the record type.
level: high
---
title: Subdomain delegated to nameservers outside Route 53
id: b5e0937c-24da-4f18-8c67-3e91b40d5a62
name: route53_ns_delegated_outside_route53
status: experimental
description: >-
  An NS record was published whose values are not Route 53 nameservers. Route 53's own nameservers
  are always of the form ns-<n>.awsdns-<n>.com, .net, .org or .co.uk, so a delegation naming
  anything else hands that subtree to third-party infrastructure. This is the one test in the file
  that needs no baseline and no zone-name lookup: it reads the values in the event. It is the
  domain-shadowing case — Route 53 stops answering for everything below the label, nothing else in
  the account changes, and no service breaks, so the delegation can stand for months. Anyone who
  controls those nameservers can also complete DNS-based domain-control validation for that name
  and obtain a certificate for it.
references:
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/CreatingNewSubdomain.html
  - https://attack.mitre.org/techniques/T1584/002/
tags:
  - attack.resource-development
  - attack.t1584.001
  - attack.t1584.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53.amazonaws.com'
    eventName: 'ChangeResourceRecordSets'
  ns_write:
    requestParameters.changeBatch.changes.resourceRecordSet.type: 'NS'
    requestParameters.changeBatch.changes.action:
      - 'CREATE'
      - 'UPSERT'
  success:
    errorCode: null
  route53_nameservers:
    requestParameters.changeBatch.changes.resourceRecordSet.resourceRecords.value|contains: 'awsdns'
  # POPULATE BEFORE DEPLOYING if the organisation genuinely delegates subdomains to a third-party
  # DNS provider. Add that provider's nameserver suffix here and nothing else — this list is the
  # complete set of parties permitted to answer for part of the estate, and it should read like it.
  approved_external_dns:
    requestParameters.changeBatch.changes.resourceRecordSet.resourceRecords.value|contains:
      - 'dns.example-provider.net'
  condition: selection and ns_write and success and not route53_nameservers and not approved_external_dns
falsepositives:
  - >-
    A planned migration of a subdomain to another DNS provider. Real, and it should be the only
    reason this ever fires — the nameserver suffix goes in approved_external_dns once, by ticket.
level: critical
---
title: NS record change refused
id: 9a6b3e28-71c5-4f04-a3d9-c25e807f1b4d
name: route53_ns_change_refused
status: experimental
description: >-
  An NS change was submitted and rejected. Base rule, and intent observed. Route 53 change batches
  are transactional — "Route 53 validates the changes in the request and then either makes all or
  none of the changes in the change batch request" — so an InvalidChangeBatch means nothing was
  applied and the first attempt simply failed validation. AccessDenied means a principal without
  DNS write permission tried. PriorRequestNotComplete appearing repeatedly against one zone is
  evidence of scripted change volume: Route 53 rejects a second change while the first is still
  processing, so a burst of it means something is submitting faster than a person would.
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html
  - https://attack.mitre.org/techniques/T1584/001/
tags:
  - attack.resource-development
  - attack.t1584.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53.amazonaws.com'
    eventName: 'ChangeResourceRecordSets'
    requestParameters.changeBatch.changes.resourceRecordSet.type: 'NS'
  refused:
    errorCode:
      - 'AccessDenied'
      - 'AccessDeniedException'
      - 'InvalidChangeBatch'
      - 'InvalidInput'
      - 'NoSuchHostedZone'
      - 'PriorRequestNotComplete'
  condition: selection and refused
falsepositives:
  - >-
    An operator attempting to edit the apex NS RRset by hand and being rejected. Worth one look
    every time: AWS advises against touching that record, so the attempt is the interesting part.
level: medium
```

What this set structurally cannot do: it cannot tell an apex change from a delegation, because
the event carries the zone's **ID** and the record's **name**, and the comparison needs the zone's
name — Query 2 resolves it. It matches at batch granularity rather than per change element, which
the header states and the KQL's `mv-expand` resolves. And it cannot see what the delegated
nameservers are serving, because Route 53 stops being involved the moment the delegation exists.

---

### Key Investigation Queries

> **Every query here must run in `us-east-1`.** `route53.amazonaws.com` events appear nowhere
> else, and an empty result from another Region is `[!] INCONCLUSIVE`, never clean. Hosted zones
> are global, so one `us-east-1` query covers the account. Extraction uses
> `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50
> events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: every NS change, walked element by element

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ChangeResourceRecordSets \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    . as $e |
    (($e.requestParameters.changeBatch.changes // []) | length) as $n |
    if $n == 0 then
      {time: $e.eventTime, caller: $e.userIdentity.arn, zone: "<params-omitted>",
       action: "?", name: "?", ttl: null, nameservers: [],
       note: "requestParameters absent — batch over 100 KB, contents unknowable",
       error: ($e.errorCode // "SUCCESS"), ip: $e.sourceIPAddress}
    else
      $e.requestParameters.changeBatch.changes[]
      | select(.resourceRecordSet.type == "NS")
      | {time: $e.eventTime, caller: $e.userIdentity.arn,
         access_key: $e.userIdentity.accessKeyId,
         zone: $e.requestParameters.hostedZoneId,
         action: .action, name: .resourceRecordSet.name, ttl: .resourceRecordSet.tTL,
         nameservers: [(.resourceRecordSet.resourceRecords // [])[].value],
         external: ([(.resourceRecordSet.resourceRecords // [])[].value]
                    | map(test("awsdns")) | all | not),
         error: ($e.errorCode // "SUCCESS"), ip: $e.sourceIPAddress}
    end' | jq -s 'sort_by(.time)'
```

`"external": true` is the row to read first — those nameservers are not Route 53's, and the
subtree under that name is being answered by whoever runs them. An `UPSERT` tells you the new
nameservers and nothing about the old ones; compare against AWS Config or IaC state, never
against CloudTrail. A `DELETE` row is the exception and is genuinely useful: the API requires an
exact match of every existing value, so its `nameservers` array is what was removed.

#### Query 2 — Sweep: every NS record in the account, classified

```bash
REGION="us-east-1"

for Z in $(aws route53 list-hosted-zones --region "$REGION" --output json | \
           jq -r '.HostedZones[] | "\(.Id)|\(.Name)"'); do
  ZID="${Z%%|*}"; ZNAME="${Z##*|}"
  aws route53 list-resource-record-sets --hosted-zone-id "$ZID" --region "$REGION" \
    --output json | jq -r --arg n "$ZNAME" '
      .ResourceRecordSets[]
      | select(.Type == "NS")
      | . as $r
      | ([($r.ResourceRecords // [])[].Value] | map(test("awsdns")) | all) as $r53
      | "\(if $r.Name == $n then "APEX      " else "DELEGATION" end)\t\($n)\t\($r.Name)\tttl=\($r.TTL)\troute53=\($r53)\t\([($r.ResourceRecords // [])[].Value] | join(","))"'
done | sort

echo
echo "== dangling delegations: a parent NS record with no child zone behind it =="
ZONES=$(aws route53 list-hosted-zones --region "$REGION" --output json | jq -r '.HostedZones[].Name')
for Z in $(aws route53 list-hosted-zones --region "$REGION" --output json | \
           jq -r '.HostedZones[] | "\(.Id)|\(.Name)"'); do
  ZID="${Z%%|*}"; ZNAME="${Z##*|}"
  for D in $(aws route53 list-resource-record-sets --hosted-zone-id "$ZID" --region "$REGION" \
             --output json | jq -r --arg n "$ZNAME" \
             '.ResourceRecordSets[] | select(.Type == "NS" and .Name != $n) | .Name'); do
    echo "$ZONES" | grep -qx "$D" || echo "[!] $ZNAME delegates $D but no hosted zone of that name exists here"
  done
done
```

The first block is the standing control, and it is the only thing that finds a delegation created
before the log window opened. `route53=false` is the finding. `APEX` rows should match the zone's
delegation set exactly and should never change — AWS: *"Except in rare circumstances, we recommend
that you don't add, change, or delete name servers in this record."*

The second block is the dangling-delegation case, and AWS documents the window in its own words:
*"We suggest that you delete the NS record first, and wait for the TTL on that NS record to
expire before you delete the child hosted zone. This ensures that no one can hijack the child
hosted zone while DNS resolvers still have the child hosted zone's name servers cached."* A
parent NS record with no child zone behind it is exactly that hijackable state. Note that the
delegated nameservers may legitimately live in another account — treat a hit as a question, not
a verdict, and answer it by asking whose they are.

#### Query 3 — Inspect: what the delegated nameservers actually answer

```bash
DELEGATED="cdn.example.com"                     # from Query 1 or Query 2
NS_LIST="<nameservers-from-the-record>"         # space-separated

for NS in $NS_LIST; do
  echo "== $NS =="
  dig +short SOA "$DELEGATED" "@$NS" 2>/dev/null || echo "  [!] no response"
  dig +short A "$DELEGATED" "@$NS" 2>/dev/null
  dig +short A "www.$DELEGATED" "@$NS" 2>/dev/null
  dig +short TXT "_acme-challenge.$DELEGATED" "@$NS" 2>/dev/null
done
```

The `_acme-challenge` lookup is the one that matters most: it is the record a CA reads for
DNS-based domain-control validation, and its presence means somebody is proving control of your
name to a certificate authority. Follow any hit into certificate transparency for the delegated
name and every label under it. Route 53 has no view of any of this — the delegation is precisely
the point at which AWS stops being involved.

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

Look for CAA changes in the same session — weakening issuance policy and delegating a subtree are
two halves of the same objective — and for `DeleteHostedZone`, which pairs with a parent NS record
to produce a dangling delegation.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Delete the delegation first, then accept that you cannot make resolvers forget it. The TTL is the
containment timeline and nothing shortens it, so the second half of the response is about what
was served during the window rather than about stopping it now.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being contained.

#### Step 1 — Capture the record, then delete it

```bash
REGION="us-east-1"
ZONE_ID="<zone-id-from-Query-1>"
NAME="cdn.example.com."                        # trailing dot — names are stored normalised
CASE_DIR="./ir-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$CASE_DIR"

aws route53 list-resource-record-sets --hosted-zone-id "$ZONE_ID" --region "$REGION" \
  --output json | jq --arg n "$NAME" \
  '[.ResourceRecordSets[] | select(.Type == "NS" and .Name == $n)]' > "$CASE_DIR/ns.json"

COUNT=$(jq 'length' "$CASE_DIR/ns.json")
if [ "$COUNT" -ne 1 ]; then
  echo "[FAIL] expected exactly one NS RRset named $NAME, found $COUNT — resolve by hand"
else
  jq --argjson r "$(jq '.[0]' "$CASE_DIR/ns.json")" -n \
    '{Comment: "IR: remove unauthorised delegation", Changes: [{Action: "DELETE", ResourceRecordSet: $r}]}' \
    > "$CASE_DIR/delete.json"
  echo "[i] deleting — this is the record being removed:"
  jq '.Changes[].ResourceRecordSet' "$CASE_DIR/delete.json"
  CHANGE_ID=$(aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" \
    --change-batch "file://$CASE_DIR/delete.json" --region "$REGION" \
    --output json | jq -r '.ChangeInfo.Id')
  echo "[i] submitted $CHANGE_ID"
fi
```

`DELETE` requires an exact match of every existing value, which is why the record is read back
from live state rather than reconstructed — and why the resulting CloudTrail event is itself a
usable record of what was removed. If the delegation was a legitimate subdomain that an attacker
repointed, restore the correct nameservers with an `UPSERT` from the committed inventory instead
of deleting the record.

#### Step 2 — Prove propagation, and state the cache tail you cannot shorten

```bash
REGION="us-east-1"
STATUS=$(aws route53 get-change --id "$CHANGE_ID" --region "$REGION" --output json | \
         jq -r '.ChangeInfo.Status')
[ "$STATUS" = "INSYNC" ] && echo "[OK] Route 53 reports INSYNC" \
                         || echo "[FAIL] status=$STATUS — PENDING is the initial state of every change"

TTL=$(jq -r '.[0].TTL' "$CASE_DIR/ns.json")
echo "[!] resolvers that cached the delegation keep asking those nameservers for up to ${TTL}s"
echo "    ($(( TTL / 3600 ))h). There is no mechanism to flush them. Treat the subtree as"
echo "    attacker-controlled until that elapses, and tell whoever owns the affected service."

NS=$(aws route53 get-hosted-zone --id "$ZONE_ID" --region "$REGION" --output json | \
     jq -r '.DelegationSet.NameServers[0]')
dig +short NS "${NAME%.}" "@$NS" || echo "[!] dig unavailable — verify by another resolver"
```

`INSYNC` is Route 53's *internal* propagation only: it says the Route 53 nameservers now answer
consistently. It says nothing about the resolver caches still holding the delegation, and
`PENDING` is the initial status of every change batch, so `[FAIL]` here is reachable.

#### Step 3 — Establish what was served under the delegation

Run Query 3 against the nameservers from `ns.json` while they still answer, and search
certificate transparency for the delegated name and every label under it over the exposure
window. A certificate issued for a name in a delegated subtree remains valid after the
delegation is gone, and that certificate — not the DNS record — is what can still be used.

#### Step 4 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')      # user ARN: name = last segment
  aws iam put-user-policy --user-name "$U" --policy-name IR-Deny-All \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
  for K in $(aws iam list-access-keys --user-name "$U" --output json | jq -r '.AccessKeyMetadata[].AccessKeyId'); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
  done
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')       # role ARN: name = 2nd segment
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$R" --policy-name AWSRevokeOlderSessions \
    --policy-document file:///tmp/revoke.json
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

---

## 4. Eradication

### Remove Attacker Access

#### Clear every delegation nobody can account for

Query 2's full listing is the work item, not just the alerting record. Every `route53=false` row
and every dangling delegation needs an owner or a deletion. Delegations that predate the log
window will never appear in CloudTrail, so this state comparison is the only way they surface.

#### Fix the teardown order that creates the same exposure

Where a child zone is being retired, delete the parent's NS record first and wait out its TTL
before deleting the child zone — AWS's own instruction, and the reason is a hijack window. An
actor who deletes the zone first and never removes the NS record has done it in the order that
maximises that window; so has a careless engineer, which is why this belongs in a runbook rather
than only in a detection.

#### Right-size the permission that made this possible

```bash
for P in $(aws iam list-policies --scope Local --output json | jq -r '.Policies[].Arn'); do
  V=$(aws iam get-policy --policy-arn "$P" --output json | jq -r '.Policy.DefaultVersionId')
  aws iam get-policy-version --policy-arn "$P" --version-id "$V" --output json | \
    jq -e '.PolicyVersion.Document.Statement
      | (if type == "object" then [.] else . end)
      | map(select(.Effect == "Allow"))
      | map(select((.Action // .NotAction // []) | (if type == "string" then [.] else . end)
            | any(. == "*" or . == "route53:*" or . == "route53:ChangeResourceRecordSets")))
      | map(select((.Resource // "*") | (if type == "string" then [.] else . end) | any(. == "*")))
      | length > 0' >/dev/null 2>&1 && echo "[!] $P allows unscoped route53 record writes"
done
```

Hosted zones have resource ARNs — `arn:aws:route53:::hostedzone/<id>` — so
`route53:ChangeResourceRecordSets` can and should be scoped per zone. A grant on `"*"` is a grant
over every zone in the account.

#### Remove emergency policies once clean

Delete `IR-Deny-All` and `AWSRevokeOlderSessions` once the principal is rebuilt or retired.

---

## 5. Recovery

### Restore Clean State

#### Verify every NS record in the account is accounted for

```bash
REGION="us-east-1"
EXTERNAL=$(for Z in $(aws route53 list-hosted-zones --region "$REGION" --output json | \
                      jq -r '.HostedZones[].Id'); do
  aws route53 list-resource-record-sets --hosted-zone-id "$Z" --region "$REGION" --output json | \
    jq -r '[.ResourceRecordSets[] | select(.Type == "NS")
            | select(([(.ResourceRecords // [])[].Value] | map(test("awsdns")) | all) | not)
            | .Name] | .[]'
done)

if [ -z "$EXTERNAL" ]; then
  echo "[OK] every NS record in every zone points at Route 53 nameservers"
else
  echo "[FAIL] delegations to non-Route 53 nameservers remain:"
  echo "$EXTERNAL" | sed 's/^/    /'
  echo "    each must match an entry in the approved-provider list, or be deleted"
fi
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  eventSource=route53.amazonaws.com  eventName=ChangeResourceRecordSets  no errorCode"
echo "  changes[0].action=CREATE  resourceRecordSet.type=NS  name=cdn.example.com."
echo "  resourceRecords[0].value=ns1.attacker.example    (contains no 'awsdns')"
echo "The rule MUST NOT fire on:"
echo "  the same event where resourceRecords[*].value are ns-1234.awsdns-56.org etc."
echo "  submitted by an ARN in known_dns_automation"
echo "and MUST still fire (at high, via the core rule) on:"
echo "  an UPSERT of the apex NS RRset to Route 53 nameservers of a DIFFERENT delegation set"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could delegate part of the namespace to third-party nameservers | `route53:ChangeResourceRecordSets` granted on `"*"` when hosted zones support resource-level ARNs |
| The change looked identical to routine subdomain plumbing | The rule matched the record type and never the nameserver values, so a legitimate child zone and a hijack were indistinguishable |
| Nothing noticed for as long as it stood | Nothing broke: every existing record, service and log was untouched, and monitoring watches names that still resolve through Route 53 |
| A delegation predating the log window would never have surfaced | No standing state comparison existed — only event-based detection, which answers "what changed" and never "what is" |

### Recommended Guardrails

**Scope DNS writes to the zones a principal owns**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["route53:ChangeResourceRecordSets"],
  "Resource": "arn:aws:route53:::hostedzone/*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Run Query 2's classification on a schedule and diff it against a committed inventory. This is
  the only control that finds a delegation older than the log, and it is cheap.
- Keep delegation TTLs short. AWS recommends 48 hours; that number is also how long you are stuck
  with a hijack after removing it. Weigh the two deliberately rather than accepting the default.
- Retire child zones NS-record-first, waiting out the TTL before deleting the zone. AWS documents
  this order and the hijack window it exists to close.
- Record `AWS::Route53::HostedZone` in AWS Config. `UPSERT` makes it the only source that can
  answer "what did this delegate to before".

**Detection improvements**
- Alert on the nameserver values, not the record type. That single change is most of the value in
  this playbook.
- Alert on an apex NS RRset changing at all, as a standing rule. AWS advises against touching it,
  so any change is either a rare planned event or the finding.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1584.001 — Compromise Infrastructure: Domains |
| MITRE tactic | Resource Development (TA0042) |
| Primary API | `route53:ChangeResourceRecordSets` with `Action` `CREATE` or `UPSERT` on `Type: NS` |
| Event source | route53.amazonaws.com (visible **only** in `us-east-1`) |
| Key discriminator | Whether the record's values contain `awsdns`. Route 53's nameservers are always `ns-<n>.awsdns-<n>.{com,net,org,co.uk}`, so anything else delegates the subtree away — one field, no baseline |
| Ground-truth signal | The live NS RRset from `ListResourceRecordSets`, classified apex-vs-delegation by comparing its name to the zone's name |
| "Was it used" pivot | Resolve names under the delegated label against the delegated nameservers directly, and search certificate transparency. Route 53 query logging cannot help: it is opt-in, public-zone only, samples roughly one query in several thousand, and stops at the delegation |
| Blast radius | Everything at or below the delegated label, including names that do not yet exist — plus any certificate obtainable for them through DNS-based domain-control validation |
| Error strings | `NoSuchHostedZone`, `NoSuchHealthCheck`, `InvalidChangeBatch`, `InvalidInput`, `PriorRequestNotComplete`, plus `AccessDenied` / `AccessDeniedException`. Throttling is code `Throttling`, message "Rate exceeded" |

**MITRE mapping note:** The replacement is wrong as well: `T1685` is Defence Impairment, and a delegation
impairs no defence and clears no log. `T1584.001` covers this in its own words — "subdomain
hijacking", and "domain shadowing by creating malicious subdomains under their control while
keeping any existing DNS records" — with `T1584.002` for the delegated-away nameservers. Both are
PRE-platform techniques, which is why an IaaS ID does not appear: the convention and its reason
are settled once in `../_ground-truth/route53.md` §10.

### Residual Risk

Resolvers that cached the delegation keep asking the attacker's nameservers until the TTL
expires — up to 48 hours at AWS's recommended value — and nothing flushes them. Any certificate
obtained for a name in the delegated subtree stays valid after the delegation is gone, and
certificate transparency is the only place that record exists. If the delegation predated the
CloudTrail retention window there is no event to reconstruct from, only current state. And a
delegation that pointed at nameservers in another account you do not control may still hold a
zone for that name on the other side, ready to be re-pointed at the moment anyone recreates the
record.
