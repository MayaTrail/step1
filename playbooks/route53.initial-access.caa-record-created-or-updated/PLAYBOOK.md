# IR Playbook: CAA Policy Weakened — certificate-issuance restrictions changed via `ChangeResourceRecordSets`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment (a preventative control is removed so a certificate can be obtained for a domain the attacker does not own) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High, and critical when the published value names a certificate authority the organisation does not use. The ceiling is a valid, publicly trusted certificate for your own domain, which defeats TLS as an identity control for everything served under that name. The source rule's middle rating matches the *event*; it does not match a certificate that stays valid long after the record is fixed. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685 |
| Services in Scope | Route 53 (hosted zones), ACM, AWS Config, CloudTrail, and every certificate authority the organisation uses |

**What the technique does:** an attacker with DNS write permission calls
`ChangeResourceRecordSets` with a `CREATE` or `UPSERT` on a CAA record. They do not delete
anything. CAA authorisations are **additive**, and AWS documents the consequence with its own
example: publish `0 issue ";"` and `0 issue "ca.example.net"` together and *"a CA that is using
the value ca.example.net can issue the certificate for example.com"*. One added value beside a
deny-all opens issuance to that CA, and the record still exists afterwards. Alternatively they
publish a permissive CAA one label down — at `pay.example.com` — which, because RFC 8659's
lookup *"climbs the DNS name tree... until a CAA RRset is found"*, shadows the strict apex policy
for that subdomain while leaving the apex record, the thing anyone would review, untouched.

The reason the usual reflexes miss it is that the fix and the remediation are different things.
A defender restores the CAA record, confirms it propagated, and closes the incident. But RFC 8659
§1 says *"Relying Parties MUST NOT use CAA records as part of certificate validation"* — a
certificate issued while the policy was weak stays valid, trusted, and entirely unaffected by the
restoration. The DNS change closes the window; it does not undo what came through it.

**Detection thesis:** the discriminating fact is not that a CAA record changed but **what it now
authorises**. The organisation's own CAs are a short, closed, stable list, so a CAA value naming
none of them is anomalous without any baseline. The source rule matches the event and never reads
the values.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail management events for `route53.amazonaws.com`, read in `us-east-1`.** AWS states
  the rule outright: *"To view events for Route 53 API requests, you must choose US East (N.
  Virginia) in the Region selector."* A query anywhere else returns zero.
- **AWS Config recording `AWS::Route53::HostedZone`.** This is the single highest-value item in
  this service: it is the only reliable before-and-after record of a zone's record set, and it is
  what turns "the CAA was UPSERTed" into "here is what it was". There is **no** Config managed
  rule for CAA content — the comparison is yours to run.
- **Certificate transparency monitoring for every domain and wildcard the organisation owns.**
  AWS holds no record of another CA's issuance decisions, so this is the only place a
  maliciously obtained certificate appears at all.
- **The zone's CAA policy in version control**, as the authoritative known-good. CloudTrail is
  not a backup — AWS attaches `"Note": "Do not use to reconstruct hosted zone"` to this very
  event.

**Alerting (must be pre-configured)**
- **A CAA `CREATE`/`UPSERT` whose values name no approved certificate authority → P0**
- **Any successful CAA `CREATE`/`UPSERT` by a principal outside the DNS automation allowlist → P0**
- **A successful `ChangeResourceRecordSets` whose `requestParameters` are absent → P1**
- **A CAA RRset present on a name below the zone apex while a stricter apex CAA exists → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under
  investigation; `jq`; `dig` or an equivalent that can query a specific nameserver directly.
- A certificate-transparency search tool, and the revocation contact for each CA in use.

**Known IOC Baselines**
- **The approved CA list.** Both the Sigma and the KQL are inert until it is populated, and both
  say so in the file. It is short and it changes about once a year.
- The current CAA RRset for every zone and every name within it, including which zones have none
  at all — a zone with no CAA record does not restrict issuance and never alerts.
- Which principals may write DNS. This should be an IaC role, not a person.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ChangeResourceRecordSets`, `CREATE`/`UPSERT`, type `CAA`, values naming no approved CA, no `errorCode` | CloudTrail (`us-east-1`) | T1588.004 |
| P0 | Any successful CAA `CREATE`/`UPSERT` by a principal outside the DNS automation allowlist | CloudTrail (`us-east-1`) | T1685 |
| P1 | A successful `ChangeResourceRecordSets` with `requestParameters` absent — a batch over 100 KB | CloudTrail (`us-east-1`) | T1685 |
| P1 | A CAA RRset on a name below the zone apex where a stricter apex CAA exists | `ListResourceRecordSets` sweep | T1685 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A CAA change carrying `tTL` ≥ 86400 — the issuance window follows the TTL | CloudTrail (`us-east-1`) | T1685 |
| P2 | A CAA change refused with `InvalidChangeBatch`, `InvalidInput` or `AccessDenied` | CloudTrail (`us-east-1`) | T1685 |
| P3 | A certificate in CT logs issued by a CA the zone's CAA policy does not authorise | Certificate transparency (external) | T1588.004 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Matches the event, never the values | The malicious change is an *addition*, not a deletion — one `issue` value beside a deny-all opens issuance to that CA and the record still exists. The rule fires identically on a routine CA rotation and on the attack, so it is triaged as noise and eventually muted | Invert the test: enumerate the organisation's own CAs and alert on a CAA value naming none of them. `route53_caa_unapproved_authority`, critical |
| No allowlist of DNS-writing principals | In an IaC estate every apply fires this rule, which is the fastest route to a muted P2 | `known_dns_automation` on the core rule, and a CAA change by anything else treated as the finding |
| Blind to an oversized batch | CloudTrail omits `requestParameters` entirely above 100 KB rather than truncating, so a CAA change inside a bulk rewrite presents as zero changes and every type-matching rule reports clean | `route53_change_parameters_omitted` — absence of parameters as a signal in its own right |
| Ignores TTL | CA/Browser Forum BR §4.2.2.1 ties the issuance window to the record's TTL or 8 hours, whichever is greater. A TTL raised shortly before a weakening extends the exploit window deliberately, and the rule discards the field that shows it | `tTL` projected and thresholded; note the field is `tTL`, lower `t` upper `TL` — `ttl` resolves to null and silently disables the check |
| Success-only | A refused CAA change is intent observed, and Route 53 batches are transactional so a rejected batch changed nothing — the operator simply got the syntax wrong on the first attempt | A refusal rule at medium over the API's closed error set |
| Nothing addresses shadowing | A permissive CAA one label below the apex defeats the apex policy for that name, and no event-based rule can see it because the question is about *current* state of ancestor names | Query 2 walks `ListResourceRecordSets` per zone and compares each CAA name against the apex |

**Recommended detection — read what the record now authorises, not merely that it changed.**

```yaml
# CAA policy weakened — a certificate-issuance restriction changed in a hosted zone (T1685)
#
# WHAT CAA IS, AND WHY RESTORING IT DOES NOT FIX ANYTHING. CAA is a PREVENTATIVE control read by
# a certificate authority at issuance time and by nobody afterwards. RFC 8659 §1: "A set of CAA
# records describes only current grants of authority to issue certificates... it is possible that
# a certificate that is not conformant with the CAA records currently published was conformant
# with the CAA records published at the time that the certificate was issued. Relying Parties
# MUST NOT use CAA records as part of certificate validation." So a certificate issued while the
# policy was weak stays valid after the policy is restored.
#
# THE MALICIOUS CHANGE IS AN ADDITION, NOT A DELETION. Authorizations are additive, and AWS's own
# documentation supplies the example: "If you create a CAA record for example.com and specify both
# of the following values, a CA that is using the value ca.example.net can issue the certificate:
#   0 issue ";"
#   0 issue "ca.example.net"
# So adding one issue value beside a deny-all opens issuance to that CA, and the record still
# EXISTS afterwards. A rule keyed on the CAA record being absent does not fire. This is why the
# core rule below matches CREATE and UPSERT and reads the VALUES, not the record's existence.
#
# A PERMISSIVE SUBDOMAIN RECORD SILENTLY OVERRIDES A STRICT APEX. RFC 8659 §3: "The search for a
# CAA RRset climbs the DNS name tree from the specified label up to, but not including, the DNS
# root '.' until a CAA RRset is found." A nearer RRset shadows a further one — so publishing
# `0 issue "attacker-ca.example"` at `pay.example.com` defeats a deny-all at `example.com` for
# that subdomain, while leaving the apex record untouched and every review of it clean.
#
# THE WINDOW IS AT LEAST EIGHT HOURS AND THE TTL EXTENDS IT. CA/Browser Forum Baseline
# Requirements v2.2.9 (6 Aug 2026) §4.2.2.1: "If the CA issues a certificate after processing a
# CAA record, it MUST do so within the TTL of the CAA record, or 8 hours, whichever is greater."
# A CAA record whose tTL was raised shortly before it was weakened is a deliberate extension of
# the exploit window, which is why TTL is projected in the KQL rather than ignored.
#
# FIELD SHAPES — verified against AWS's published CloudTrail sample for ChangeResourceRecordSets:
#   requestParameters.changeBatch.changes[] holds the change objects DIRECTLY. There is no
#   intermediate `change` key; changes[].change.resourceRecordSet matches nothing.
#   The TTL member is `tTL` — lower t, upper TL. Not `ttl`, not `TTL`.
#   resourceRecordSet.name carries a TRAILING DOT and is stored normalised.
#   The response is changeInfo-wrapped: responseElements.changeInfo.status, values PENDING|INSYNC.
#   ONE EVENT CAN CARRY MANY CHANGES OF MANY TYPES. Matching `type: 'CAA'` proves a CAA change is
#   somewhere in the batch; it does not say which name, and nothing in Sigma can walk the array.
#   The investigation queries in ../PLAYBOOK.md do that walk, and §2 says so rather than implying
#   the rule resolves it.
#
# THE ARRAY-CONJUNCTION APPROXIMATION, STATED RATHER THAN HIDDEN. Because changes[] is an array,
# matching `type: CAA` and `action: CREATE|UPSERT` as two keys in one block means "this batch
# contains a CAA record somewhere AND contains a CREATE or UPSERT somewhere" — NOT "one change is
# a CAA CREATE". A batch that deletes a CAA record and creates an A record satisfies both keys and
# fires. Sigma has no per-element conjunction and inventing one would be worse than the
# approximation: the alternative is dropping the action filter, which loses the distinction from
# the CAA-deletion use case entirely. So the rule is a deliberate SUPERSET, the element-level walk
# lives in kql_t1685.kql (mv-expand) and in Query 1 of ../PLAYBOOK.md, and the triage step is
# "read which element actually changed" rather than "trust the match". Recall is preserved;
# precision is bought back by the analyst in one look.
#
# REGIONALITY. route53.amazonaws.com events carry awsRegion us-east-1 and AWS states the console
# rule outright: "To view events for Route 53 API requests, you must choose US East (N. Virginia)
# in the Region selector." A lookup in any other Region returns zero. No rule here filters on
# awsRegion — the queries pin the Region instead, and an empty result is INCONCLUSIVE.
title: CAA certificate-issuance policy created or updated
id: 6f3c81b0-49d7-4e25-8a16-b2705e94cd83
name: route53_caa_record_changed
status: experimental
description: >-
  A CAA record was created or replaced in a hosted zone. CAA is the only DNS-level control over
  which certificate authorities may issue for a name, and weakening it is the precondition for
  obtaining a valid certificate for a domain you do not own. UPSERT is the dangerous action: it
  replaces the record set outright, the event carries only the NEW values, and Route 53 keeps no
  version history — so "what was it before?" is answerable only from IaC state or from an earlier
  event that set it. Matches at BATCH granularity, not per change element — see the header note on
  the array-conjunction approximation before triaging a hit.
references:
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values.html
  - https://www.rfc-editor.org/rfc/rfc8659
  - https://attack.mitre.org/techniques/T1685/
tags:
  - attack.defense-impairment
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53.amazonaws.com'
    eventName: 'ChangeResourceRecordSets'
  caa_write:
    requestParameters.changeBatch.changes.resourceRecordSet.type: 'CAA'
    requestParameters.changeBatch.changes.action:
      - 'CREATE'
      - 'UPSERT'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the roles that own DNS through infrastructure-as-code. CAA
  # changes are rare and planned; if this allowlist is empty the rule still works and simply has
  # no exclusions, which is the right default for a record type most zones never touch.
  known_dns_automation:
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/PlatformAutomation'
  condition: selection and caa_write and success and not known_dns_automation
falsepositives:
  - >-
    Onboarding a new certificate authority. Legitimate, planned, and it should already be a
    change ticket — confirm against the ticket, not against the actor's seniority.
  - >-
    A batch that changes several record types at once and happens to include a CAA record.
    Real: the rule matches the batch, and the walk in the playbook's Query 1 resolves which name.
level: high
---
title: CAA record published naming a certificate authority outside the approved set
id: 2a94d76e-5b03-41f8-97c2-e60d38b1a45f
name: route53_caa_unapproved_authority
status: experimental
description: >-
  A CAA change was published whose values name no approved certificate authority. This is the
  tuning surface of the whole use case and it inverts the usual allowlist: the organisation's own
  CAs are enumerated below, and a CAA record that authorises anything else is the finding. Note
  the two shapes that both mean "restriction removed" — an issue value naming an unfamiliar CA,
  and an issuewild value, which governs wildcard certificates separately and is frequently
  forgotten when a deny-all is written. Batch granularity applies here too: the unapproved value
  and the CAA type are matched across the batch, not proven to belong to the same element.
references:
  - https://www.rfc-editor.org/rfc/rfc8659
  - https://attack.mitre.org/techniques/T1588/004/
tags:
  - attack.resource-development
  - attack.t1588.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53.amazonaws.com'
    eventName: 'ChangeResourceRecordSets'
  caa_write:
    requestParameters.changeBatch.changes.resourceRecordSet.type: 'CAA'
    requestParameters.changeBatch.changes.action:
      - 'CREATE'
      - 'UPSERT'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the CA domains this organisation actually uses. The values
  # below are placeholders and the rule is INERT until they are replaced — an allowlist that
  # matches nothing marks every change unapproved, and an allowlist left as an example matches
  # the example. Deny-all is `0 issue ";"`, which is why the semicolon form is listed as approved.
  approved_authorities:
    requestParameters.changeBatch.changes.resourceRecordSet.resourceRecords.value|contains:
      - 'amazon.com'
      - 'amazontrust.com'
      - 'awstrust.com'
      - 'amazonaws.com'
      - 'letsencrypt.org'
      - '";"'
  condition: selection and caa_write and success and not approved_authorities
falsepositives:
  - >-
    An approved CA missing from the list above. Expect exactly one round of these when the rule
    is first deployed; enumerate the organisation's CAs once and it goes quiet.
level: critical
---
title: Route 53 record change submitted with request parameters omitted
id: e8517b3d-0c46-4a92-b1f5-73d9e2604a8c
name: route53_change_parameters_omitted
status: experimental
description: >-
  A successful ChangeResourceRecordSets whose requestParameters are absent. CloudTrail's field
  contract is omit-not-truncate — "This field has a maximum size of 100 KB. When the field size
  exceeds 100 KB, the requestParameters content is omitted" — so there is no partial-array case:
  a detection reading changeBatch.changes[] on an oversized batch sees ZERO changes, not a short
  list. Route 53 permits 1,000 ResourceRecord elements and 32,000 Value characters per request,
  and a batch that size plausibly clears 100 KB. This rule exists because it is the exact blind
  spot of every other rule in this file: a CAA change buried in a bulk zone rewrite is invisible
  to a type match and visible here. Absence of parameters is treated as a signal, not as a
  parsing gap.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
  - https://attack.mitre.org/techniques/T1685/
tags:
  - attack.defense-impairment
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53.amazonaws.com'
    eventName: 'ChangeResourceRecordSets'
  success:
    errorCode: null
  parameters_present:
    requestParameters.changeBatch.changes.resourceRecordSet.type|exists: true
  condition: selection and success and not parameters_present
falsepositives:
  - >-
    A genuine bulk zone import or a large IaC apply. Both are real, both are rare, and both are
    worth confirming — a zone rewrite nobody planned is a finding whatever record types it holds.
level: medium
---
title: CAA record change refused
id: 4b06e29f-8d51-4730-a6c8-1f92e5470bd3
name: route53_caa_change_refused
status: experimental
description: >-
  A CAA change was submitted and rejected. Base rule, and intent observed. Route 53 change
  batches are transactional — "Route 53 validates the changes in the request and then either
  makes all or none of the changes in the change batch request" — so an InvalidChangeBatch means
  nothing was applied and the operator got the syntax wrong on the first try. AccessDenied means
  a principal without DNS write permission attempted it. Both are worth reading before the second
  attempt succeeds; the whole error set for this API is closed and short, and it is listed here.
  Batch granularity applies: the CAA type is matched anywhere in the rejected batch.
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html
  - https://attack.mitre.org/techniques/T1685/
tags:
  - attack.defense-impairment
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53.amazonaws.com'
    eventName: 'ChangeResourceRecordSets'
    requestParameters.changeBatch.changes.resourceRecordSet.type: 'CAA'
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
    A malformed CAA value from an operator learning the `flags tag "value"` syntax. Common, and
    still worth one look — the second attempt is the one that lands.
level: medium
```

What this set structurally cannot do: it matches at **batch** granularity, not per change
element — `changes[]` is an array and two keys in one Sigma block are ANDed across the whole
batch, so a batch that deletes a CAA record and creates an A record satisfies both. That is a
deliberate superset, stated in the rule header; `mv-expand` in the KQL and Query 1 below do the
element-level walk. It also cannot resolve shadowing, and it cannot tell you whether a
certificate was issued — AWS has no record of another CA's decisions.

---

### Key Investigation Queries

> **Every query here must run in `us-east-1`.** `route53.amazonaws.com` events appear nowhere
> else, and an empty result from another Region is `[!] INCONCLUSIVE`, never clean. Hosted zones
> are global objects, so one `us-east-1` query covers the whole account and there is no
> per-Region sweep. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log
> platform for busy windows.

#### Query 1 — Reconstruct: every CAA change, walked element by element

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
       action: "?", type: "?", name: "?", ttl: null, values: [],
       note: "requestParameters absent — batch over 100 KB, contents unknowable",
       error: ($e.errorCode // "SUCCESS"), ip: $e.sourceIPAddress}
    else
      $e.requestParameters.changeBatch.changes[]
      | select(.resourceRecordSet.type == "CAA")
      | {time: $e.eventTime, caller: $e.userIdentity.arn,
         access_key: $e.userIdentity.accessKeyId,
         zone: $e.requestParameters.hostedZoneId,
         action: .action, type: .resourceRecordSet.type,
         name: .resourceRecordSet.name, ttl: .resourceRecordSet.tTL,
         values: [(.resourceRecordSet.resourceRecords // [])[].value],
         error: ($e.errorCode // "SUCCESS"), ip: $e.sourceIPAddress}
    end' | jq -s 'sort_by(.time)'
```

`resourceRecords` is read with `// []` because an absent array would otherwise drop the record
silently. `tTL` is the correct spelling — lower `t`, upper `TL`. A row whose `name` is not the
zone apex is a shadowing candidate and goes to Query 2. An `UPSERT` row tells you the new values
and nothing about the old ones: Route 53 keeps no version history, so compare against IaC state
or AWS Config, never against CloudTrail.

#### Query 2 — Sweep: the current CAA policy of every zone, and the shadowing check

```bash
REGION="us-east-1"

for Z in $(aws route53 list-hosted-zones --region "$REGION" --output json | \
           jq -r '.HostedZones[] | "\(.Id)|\(.Name)"'); do
  ZID="${Z%%|*}"; ZNAME="${Z##*|}"
  APEX=$(aws route53 list-resource-record-sets --hosted-zone-id "$ZID" --region "$REGION" \
    --output json | jq -r --arg n "$ZNAME" \
    '[.ResourceRecordSets[] | select(.Type == "CAA" and .Name == $n)
      | .ResourceRecords[].Value] | join(" | ")')
  BELOW=$(aws route53 list-resource-record-sets --hosted-zone-id "$ZID" --region "$REGION" \
    --output json | jq -r --arg n "$ZNAME" \
    '[.ResourceRecordSets[] | select(.Type == "CAA" and .Name != $n)
      | "\(.Name) => \(.ResourceRecords | map(.Value) | join(" | "))"] | .[]')

  if [ -z "$APEX" ]; then
    echo "[!] $ZNAME  NO APEX CAA — issuance is unrestricted for this zone by default"
  else
    echo "[i] $ZNAME  apex: $APEX"
  fi
  if [ -n "$BELOW" ]; then
    echo "    [!] CAA records exist BELOW the apex — each one shadows the apex policy for its subtree:"
    echo "$BELOW" | sed 's/^/        /'
  fi
done
```

Two findings live here and they look nothing alike. A zone with **no** apex CAA never alerts on
anything, because there is no record to change — RFC 8659: if no relevant RRset exists, CAA does
not restrict issuance. And a CAA record below the apex overrides the apex for its subtree,
because the lookup climbs the tree and stops at the first RRset it finds. Read every entry under
`CAA records exist BELOW the apex` against the change tickets that created them.

#### Query 3 — Inspect: what was issued, which AWS does not record

```bash
REGION="us-east-1"

echo "== certificates AWS knows about (ACM only — not other CAs) =="
for R in us-east-1 eu-west-1; do
  aws acm list-certificates --region "$R" --output json 2>/dev/null | \
    jq -r --arg r "$R" '.CertificateSummaryList[] | "\($r)\t\(.DomainName)\t\(.CertificateArn)"'
done

echo
echo "[i] ACM is one CA. The attack's whole point is obtaining a certificate from a DIFFERENT"
echo "    one, which produces no AWS record of any kind. Certificate transparency is the only"
echo "    source. Search CT for the domain and every subdomain over the exposure window:"
echo "      - issuer NOT in the approved CA list  -> treat as issued under the weakened policy"
echo "      - notBefore inside the window between the CAA change and its restoration"
echo "    RFC 8659 s1: restoring the CAA record does NOT invalidate anything already issued."
```

The exposure window starts at the CAA change and ends at the restoration, extended forward by
the CA/Browser Forum rule: a CA may issue *"within the TTL of the CAA record, or 8 hours,
whichever is greater"*. Take the record's `tTL` from Query 1 and add it — this is why the TTL
mattered.

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

A CAA change rarely travels alone. Look for `RequestCertificate` in the same session, for TXT
records created for domain-control validation, and for `UpdateDomainNameservers` — each is a
different way to finish the same job.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore the policy first, because every hour it stays weak is another hour a CA will honour it.
Then find out what came through the window — that is the actual incident, and it is not in AWS.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being contained.

#### Step 1 — Restore the CAA policy from the authoritative source

```bash
REGION="us-east-1"
ZONE_ID="<zone-id-from-Query-1>"
DOMAIN="example.com."                 # trailing dot — Route 53 stores names normalised
CAA_FILE="/tmp/caa-restore.json"

cat > "$CAA_FILE" <<'JSON'
{ "Comment": "IR: restore CAA policy to known-good",
  "Changes": [ { "Action": "UPSERT",
    "ResourceRecordSet": { "Name": "DOMAIN_PLACEHOLDER", "Type": "CAA", "TTL": 300,
      "ResourceRecords": [
        { "Value": "0 issue \"amazon.com\"" },
        { "Value": "0 issuewild \"amazon.com\"" },
        { "Value": "0 iodef \"mailto:security@example.com\"" } ] } } ] }
JSON
sed -i.bak "s/DOMAIN_PLACEHOLDER/$DOMAIN/" "$CAA_FILE"

echo "[i] review before submitting — these values REPLACE the record set entirely:"
jq '.Changes[].ResourceRecordSet.ResourceRecords' "$CAA_FILE"

CHANGE_ID=$(aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" \
  --change-batch "file://$CAA_FILE" --region "$REGION" \
  --output json | jq -r '.ChangeInfo.Id')
echo "[i] submitted $CHANGE_ID"
```

The values above are an example and must be replaced with the organisation's own approved CAs
before this is run — `issuewild` is listed separately on purpose, because it governs wildcard
certificates independently and is the half most often forgotten when a deny-all is written. Set
a **short** TTL: it caps how long the restored policy takes to become authoritative for CAs that
cached the weak one.

#### Step 2 — Prove it propagated, twice, by two different means

```bash
REGION="us-east-1"
STATUS=$(aws route53 get-change --id "$CHANGE_ID" --region "$REGION" --output json | \
         jq -r '.ChangeInfo.Status')
[ "$STATUS" = "INSYNC" ] && echo "[OK] Route 53 reports INSYNC" \
                         || echo "[FAIL] status=$STATUS — PENDING is the initial state of every change"

NS=$(aws route53 get-hosted-zone --id "$ZONE_ID" --region "$REGION" --output json | \
     jq -r '.DelegationSet.NameServers[0]')
echo "[i] independent check against the zone's own nameserver $NS:"
dig +short CAA "${DOMAIN%.}" "@$NS" || echo "[!] dig unavailable — verify by another resolver"
```

`INSYNC` is Route 53's *internal* propagation and nothing more: it says the Route 53 nameservers
answer consistently. It says nothing about resolver caches still holding the old answer for its
TTL, and nothing about the delegation being correct. The `dig` against the zone's own nameserver
is the independent assertion, and `[FAIL]` is reachable on both — `PENDING` is the initial status
of every change batch.

#### Step 3 — Establish what was issued during the window

Run Query 3. Every certificate whose issuer is not in the approved list and whose `notBefore`
falls between the CAA change and the restoration — plus the CA/Browser Forum grace of the record
TTL or 8 hours, whichever is greater — is presumed issued under the weakened policy until proven
otherwise. Contact the issuing CA's revocation channel for each one. **Restoring the CAA record
does not revoke anything**, and there is no AWS action that does.

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

#### Remove every shadowing CAA record

Query 2's `CAA records exist BELOW the apex` list is the work item. Each entry overrides the apex
policy for its subtree, so restoring the apex alone leaves the hole open. Delete the ones nobody
can account for — and use `DELETE`, not `UPSERT`, because the API requires an exact match of
every existing value and the resulting event therefore records what was removed.

#### Revoke what was issued

This step is outside AWS. Each CA has its own revocation channel and its own turnaround. Track it
in the incident as an open item rather than closing on the DNS fix, because the certificate — not
the record — is the thing that can still be used against you.

#### Right-size the permission that made this possible

```bash
REGION="us-east-1"
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

Unlike the registrar API, hosted zones **do** have resource ARNs — `arn:aws:route53:::hostedzone/<id>`
— so `route53:ChangeResourceRecordSets` can and should be scoped per zone. A grant on `"*"` is a
grant over every zone in the account and is the finding here.

#### Remove emergency policies once clean

Delete `IR-Deny-All` and `AWSRevokeOlderSessions` once the principal is rebuilt or retired.

---

## 5. Recovery

### Restore Clean State

#### Verify the live CAA policy matches the committed baseline

```bash
REGION="us-east-1"
ZONE_ID="<zone-id>"
DOMAIN="example.com."
BASELINE_FILE="<path-to-committed-caa-values>"      # one value per line, sorted

LIVE=$(aws route53 list-resource-record-sets --hosted-zone-id "$ZONE_ID" --region "$REGION" \
  --output json | jq -r --arg n "$DOMAIN" \
  '[.ResourceRecordSets[] | select(.Type == "CAA" and .Name == $n) | .ResourceRecords[].Value] | sort | .[]')
BASE=$(sort "$BASELINE_FILE")

[ "$LIVE" = "$BASE" ] && echo "[OK] apex CAA matches the committed baseline" \
                      || { echo "[FAIL] apex CAA differs from baseline"; diff <(echo "$BASE") <(echo "$LIVE") || true; }
```

#### Confirm no CAA record remains below the apex

Re-run Query 2. It should report an apex policy for every zone and nothing below it.

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  eventSource=route53.amazonaws.com  eventName=ChangeResourceRecordSets  no errorCode"
echo "  changes[0].action=UPSERT  resourceRecordSet.type=CAA"
echo "  resourceRecords[0].value=0 issue \"unknown-ca.example\"   (names no approved CA)"
echo "The rule MUST NOT fire on:"
echo "  the same event where resourceRecords[0].value=0 issue \"amazon.com\""
echo "  submitted by an ARN in known_dns_automation"
echo "and MUST fire on:"
echo "  a successful ChangeResourceRecordSets with requestParameters entirely absent"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could weaken certificate-issuance policy for the whole estate | `route53:ChangeResourceRecordSets` granted on `"*"` when hosted zones support resource-level ARNs |
| The change looked like ordinary certificate management | The rule matched the event and never the values, so a CA rotation and an attack were indistinguishable |
| Nobody knew what the policy had been | Route 53 keeps no record-set version history and `UPSERT` records only new values; AWS Config was not recording `AWS::Route53::HostedZone` |
| A subdomain CAA overrode the apex unnoticed | No control or review looked below the apex, and no event-based rule can see shadowing |
| The incident was closed on the DNS fix | The team treated restoration as remediation; RFC 8659 means certificates issued during the window remain valid |

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
- Publish an apex CAA on **every** zone, including ones with no certificates today. A zone with
  no CAA record does not restrict issuance and cannot generate an alert, because there is nothing
  to change.
- Always publish `issuewild` alongside `issue`. A deny-all that omits `issuewild` leaves wildcard
  issuance unconstrained, and wildcards are the more valuable certificate.
- Keep CAA TTLs short. The CA/Browser Forum rule ties the issuance window to the TTL, so a short
  TTL both limits an attacker's window and shortens your own recovery.
- Record `AWS::Route53::HostedZone` in AWS Config. It is the only before-and-after the platform
  offers, and `UPSERT` makes it the only one that can answer "what was it before".

**Detection improvements**
- Populate the approved-CA list in both the Sigma and the KQL. Both files say they are inert
  until it is done; an allowlist left as an example matches the example.
- Alert on a CAA record appearing at any name other than a zone apex, as a standing rule rather
  than a sweep. Shadowing is the quiet half of this technique.
- Feed certificate-transparency hits into the same queue as the CAA rule. The DNS event is the
  precondition; the certificate is the incident, and only one of them is in AWS.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685 — Disable or Modify Tools |
| MITRE tactic | Defense Impairment (TA0112) |
| Primary API | `route53:ChangeResourceRecordSets` with `Action` `CREATE` or `UPSERT` on `Type: CAA` |
| Event source | route53.amazonaws.com (visible **only** in `us-east-1`) |
| Key discriminator | The published value names a certificate authority the organisation does not use — a short, closed, stable list, so no baseline is needed |
| Ground-truth signal | The live CAA RRset from `ListResourceRecordSets`, compared against the committed baseline |
| "Was it used" pivot | Certificate transparency. AWS holds no record of another CA's issuance, and Route 53 query logging is opt-in, public-zone only, and samples roughly one query in several thousand |
| Blast radius | Every name governed by the changed RRset — for an apex record, the whole zone and every subdomain without its own CAA |
| Error strings | `NoSuchHostedZone`, `NoSuchHealthCheck`, `InvalidChangeBatch`, `InvalidInput`, `PriorRequestNotComplete`, plus `AccessDenied` / `AccessDeniedException`. Throttling is code `Throttling`, message "Rate exceeded" |

**MITRE mapping note:** the source carries `T1596` — *Search Open Technical Databases* — which is
a Reconnaissance technique about an adversary reading public DNS data, and does not describe
writing your own CAA policy in any direction. `T1685` is a stretch (a CAA record is not a "tool")
and is chosen anyway: its description extends to "disrupting preventative, detection, and
response mechanisms across host, network, and cloud environments", CAA is precisely a
preventative mechanism, and it is the only live technique in this space carrying the IaaS
platform. `T1588.004` names the objective and `T1608.003` the stage after. Two IDs appear because
every DNS- and certificate-shaped ATT&CK technique is modelled adversary-centrically on the
**PRE** platform, so none of them returns under `platform=IaaS` — the same convention as the
other four `route53.*` playbooks.

### Residual Risk

Every certificate issued while the policy was weak remains valid and publicly trusted until it is
revoked or expires, and RFC 8659 guarantees no relying party will consult CAA to catch it. If the
attacker obtained a certificate and you did not find it in certificate transparency, you have no
other way to know. The prior CAA values are unrecoverable from AWS if the change was an `UPSERT`
and Config was not recording the zone. And any subdomain that was delegated elsewhere, or that
carries its own CAA record you did not enumerate, is still governed by whatever policy sits
nearest it in the tree — the apex you just restored does not reach past it.
