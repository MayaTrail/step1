# IR Playbook: Domain Registration Hijack — transfer lock removed via `DisableDomainTransferLock`, then the domain leaves the account

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Resource development / infrastructure loss (the domain registration itself is taken, not the DNS records under it) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical. This is the only technique in this service with **no recovery path**: once a registrar transfer completes, no AWS API reaches the domain, and AWS states it holds no information about the transfer because "all status updates go to the new registrar". Everything that authenticates by the name — certificates, email, published URLs, OIDC issuers, SAML entity IDs — belongs to whoever holds the registration. The source rule rates this at its middle level, which is defensible for the *event* and wrong for the *consequence*. |
| MITRE Tactics | Resource Development |
| MITRE Techniques | T1584.001 |
| Services in Scope | Route 53 Domains (registrar), Route 53 (hosted zones), IAM, CloudTrail, ACM / any CA the organisation uses |

**What the technique does:** an attacker with registrar-side permissions calls
`DisableDomainTransferLock`, which removes the `clientTransferProhibited` EPP status from a
registered domain. AWS's own API documentation warns against the call in the same breath as
describing it — *"We recommend you refrain from performing this action unless you intend to
transfer the domain to a different registrar."* They then call `RetrieveDomainAuthCode` to get
the transfer authorization code, and hand that code to a different registrar. **That last step
is not an AWS operation.** AWS's documented procedure ends: *"Use the process that is provided
by the new registrar to request a transfer of the domain."* Route 53 emails the registrant a
link to approve or reject — and then the sentence that sets the clock: *"If you don't take
action, the transfer will proceed automatically on the specified date."*

The usual reflexes miss it because they are pointed at the wrong service. A defender who pulls
`route53.amazonaws.com` sees a completely quiet hosted zone: no record changed, no zone was
deleted, resolution is perfect. The registration above the zone is a different service
(`route53domains.amazonaws.com`), with a different API shape, a different event-name convention,
and — on AWS's own published sample — a different `awsRegion`. A rule scoped to hosted zones
cannot see a single one of these events.

**Detection thesis:** the lock event is the alert, on its own, immediately. Waiting for a
confirming "transfer" event is waiting for something that will never be written, and the
approval email is a veto rather than a consent — so elapsed time, not event volume, is the
measure of danger.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail management events for `route53domains.amazonaws.com`.** Confirm the trail covers
  it: this is a global-ish service whose one published sample carries `awsRegion: us-west-2`
  while every hosted-zone event carries `us-east-1`, so a single-Region trail is not obviously
  sufficient. An organization trail across all Regions is.
- **Trail read access treated as sensitive.** UNVERIFIED but consequential: AWS publishes no
  statement about whether `RetrieveDomainAuthCode`'s `responseElements` carries the
  authorization code. The SDK model marks the type `sensitive`, which governs SDK logging and
  not CloudTrail. Assume the trail may hold a live transfer credential.
- **A scheduled `route53domains list-domains` snapshot**, stored with history. This is the only
  substitute for configuration history: `AWS::Route53Domains::*` is **not** an AWS Config
  recorded resource type, so nothing else records that a lock was ever on. The call is cheap —
  an account holds at most 20 registered domains (50 on accounts predating March 2021).
- **A scheduled `GetDomainDetail` snapshot per domain**, capturing `Nameservers`, `StatusList`
  and the three contact records. CloudTrail cannot show you what a contact was changed *to*.

**Alerting (must be pre-configured)**
- **`DisableDomainTransferLock` succeeded, either event-name casing → P0**
- **`RetrieveDomainAuthCode` succeeded, either event-name casing → P0**
- **The same principal removed a lock and then retrieved an auth code within 24 hours → P0**
- **`TransferDomainToAnotherAwsAccount` succeeded → P0**
- **`UpdateDomainContact` succeeded — the transfer-approval email may have been redirected → P1**
- **`UpdateDomainNameservers` succeeded — delegation moved without any hosted-zone change → P1**
- **A `TRANSFER_OUT_DOMAIN` operation in a non-terminal state in the scheduled operations poll → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under
  investigation, holding `route53domains:*` — because the containment action here is itself a
  registrar write and must not run as the suspect.
- `jq`; access to the registrant mailbox, or the ability to have it read within minutes.
- The registrar support escalation path **written down in advance**, and the registry's
  transfer-dispute procedure for each TLD in use. Both are outside AWS and both are slow.
- A certificate-transparency search tool, for the post-transfer question of what has since been
  issued for the name.

**Known IOC Baselines**
- Which principals are permitted to touch the registrar at all. This should be a list of one
  role, used through change management, and never an automation.
- The current `TransferLock` boolean for every domain, and the current `Nameservers` list — both
  from the scheduled snapshots above.
- The registrant, admin and tech contact addresses, held outside AWS, because AWS redacts them
  from the log.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `DisableDomainTransferLock` or `disableDomainTransferLock`, no `errorCode` | CloudTrail (`route53domains`) | T1584.001 |
| P0 | `RetrieveDomainAuthCode` or `retrieveDomainAuthCode`, no `errorCode` | CloudTrail (`route53domains`) | T1584.001 |
| P0 | Lock removed then auth code retrieved within 24h by the same `userIdentity.arn` | CloudTrail (correlation) | T1584.001 |
| P0 | `TransferDomainToAnotherAwsAccount`, no `errorCode` | CloudTrail (`route53domains`) | T1584.001 |
| P1 | `UpdateDomainContact`, no `errorCode` | CloudTrail (`route53domains`) | T1584.001 |
| P1 | `UpdateDomainNameservers`, no `errorCode` | CloudTrail (`route53domains`) | T1584.001 |
| P1 | An operation of type `TRANSFER_OUT_DOMAIN` in `SUBMITTED`, `IN_PROGRESS` or `PENDING_*` state | `route53domains list-operations` (live state) | T1584.001 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A registrar write refused with `AccessDenied`, `AccessDeniedException`, `TLDRulesViolation`, `UnsupportedTLD` or `DuplicateRequest` | CloudTrail (`route53domains`) | T1584.001 |
| P2 | A domain's `TransferLock` boolean flipped from `true` to `false` between two scheduled snapshots with no matching CloudTrail event | Scheduled inventory | T1584.001 |
| P3 | `DisableDomainAutoRenew` — expiry is a slower route to the same loss | CloudTrail (`route53domains`) | T1584.001 |

### Detection Rule Quality Notes

Both of the source flow's building blocks were recovered, so every row below is auditable
against `_source/original_rules.yml` rather than inferred from the rule's title.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Event names matched in the API's own upper-camel casing | AWS documents that registrar actions appear in CloudTrail with a lowercase first letter, and its published sample carries `updateDomainContact`. If that convention holds, **the rule never fires at all** — the highest-stakes rule in the service, silently dead | Match both forms explicitly in Sigma; compare `tolower(EventName)` in KQL. Cheap insurance against a convention that is documented but not re-confirmed |
| Second flow stage is `TransferDomainToAnotherAwsAccount` | That is the account-to-account move **inside** AWS (`INTERNAL_TRANSFER_OUT_DOMAIN`). The registrar transfer-out produces no AWS API call in this account, so the rule cannot fire on the irreversible case its own title names | Alert on the lock alone at P0. Ship `RetrieveDomainAuthCode` — the last AWS-visible step of a real transfer-out — as the ordered pair's second leg, and ship the internal transfer as its own rule rather than as a gate |
| One-hour flow window | A registrar transfer runs for days; AWS emails a link and proceeds automatically if it is ignored. An hour correlates nothing about this process | 24h on the ordered pair, and no window at all on the direct rules — the first event is already the alert |
| `group_by: requestParameters.domainName` | AWS's one published domains event nests the parameter as `{"domainName": {"name": "..."}}`. If that shape is general, the group-by key resolves to an object or to null and the two stages never join — the flow reports clean forever | Group by `userIdentity.arn`, which is bounded (≤20 domains per account) and always present, and read the domain off the matched events with a `coalesce` over both shapes |
| Success-only, on every stage | A `TLDRulesViolation`, `UnsupportedTLD` or `AccessDenied` on a registrar write is intent observed — somebody tried, and the next domain may not refuse | A dedicated refusal rule at medium, covering the IAM forms and the registry forms separately |
| Nothing watches the approval email's destination | `UpdateDomainContact` moves where the veto lands, and CloudTrail redacts the new value at source. Without this rule the transfer becomes silent as well as irreversible | `route53_domain_registration_altered` at medium, with the redaction stated in the rule so nobody wastes time looking for the new address in the log |

**Recommended detection — the registrar chain, alerting on the first step rather than waiting for a step that is never logged.**

```yaml
# Domain registration hijack — transfer lock removed, then the domain leaves the account (T1584.001)
#
# THE EVENT NAMES ARE LOWER-CAMEL IN CLOUDTRAIL AND THAT IS NOT A STYLE NOTE. AWS documents it:
# "In CloudTrail logs, the first letter is lowercase for domain registration actions even though
# it's uppercase in the names of the actions. For example, UpdateDomainContact appears as
# updateDomainContact in the logs." AWS's own published sample event carries
# "eventName": "updateDomainContact". A rule matching 'DisableDomainTransferLock' exactly is
# therefore at risk of never firing at all, which is the defect the source rule ships with.
# Every eventName below lists BOTH forms. Whether the convention is still current has not been
# re-confirmed against a recent event, so this is belt and braces on purpose.
#
# THE SECOND LEG OF THE SOURCE RULE'S FLOW IS THE WRONG TRANSFER. Its building blocks are
# DisableDomainTransferLock -> TransferDomainToAnotherAwsAccount. The second is the
# account-to-account move inside AWS (operation type INTERNAL_TRANSFER_OUT_DOMAIN). The
# registrar transfer-out — the one that takes the domain out of AWS permanently — is executed
# AT THE GAINING REGISTRAR. AWS's own transfer-out procedure ends: "Use the process that is
# provided by the new registrar to request a transfer of the domain." That step produces no API
# call and no CloudTrail event in this account. So a flow waiting for a transfer event waits
# forever on the case that matters most. The only AWS-visible successor is RetrieveDomainAuthCode,
# which is why it is a first-class rule here rather than an afterthought.
#
# SILENCE APPROVES. Route 53 emails the registrant a link to approve or reject, and AWS states:
# "If you don't take action, the transfer will proceed automatically on the specified date."
# The email is a veto, not a consent — and the address it goes to is itself changeable through
# UpdateDomainContact, whose contact content CloudTrail explicitly does not log. An alert
# triaged on Monday for a Friday-night lock removal may already be too late, which is why the
# lock rule is high on its own and does not wait for a second leg.
#
# REGIONALITY. route53domains events are a separate service from route53 hosted zones. AWS's
# one published domains sample carries "awsRegion": "us-west-2" while every hosted-zone event in
# the same document carries "us-east-1", so the two halves of Route 53 do NOT share a Region
# convention and no rule here filters on awsRegion. The investigation queries pin us-east-1 for
# the hosted-zone side only.
title: Route 53 domain transfer lock disabled
id: 5b7e2a94-3c61-4f08-9d2e-8a41c7b6053f
name: route53_domain_transfer_lock_disabled
status: experimental
description: >-
  The clientTransferProhibited status was removed from a registered domain. AWS's own guidance is
  "We recommend you refrain from performing this action unless you intend to transfer the domain
  to a different registrar" — so the operation announces intent by existing. This is high on its
  own and is not gated behind a second event, because the second event may never be written.
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_DisableDomainTransferLock.html
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-transfer-from-route-53.html
  - https://attack.mitre.org/techniques/T1584/001/
tags:
  - attack.resource-development
  - attack.t1584.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53domains.amazonaws.com'
    eventName:
      - 'DisableDomainTransferLock'
      - 'disableDomainTransferLock'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING. Legitimate registrar migrations are planned, rare and performed by
  # a known role. If this list is empty the rule still works — it just has no exclusions, which
  # is the correct starting position for an operation AWS itself advises against performing.
  known_registrars:
    userIdentity.arn|contains:
      - ':role/DomainAdministration'
  condition: selection and success and not known_registrars
falsepositives:
  - >-
    A planned migration to another registrar. Rare enough to confirm by hand every time, and the
    confirmation costs a message; the alternative costs the domain.
level: high
---
title: Route 53 domain authorization code retrieved
id: c4a9e061-27bd-4b53-8f10-6d3e59a2c847
name: route53_domain_auth_code_retrieved
status: experimental
description: >-
  RetrieveDomainAuthCode returned the transfer authorization code for a registered domain. This
  is step 3 of AWS's documented transfer-out procedure and it is the LAST AWS-visible step — the
  request itself is then made at the gaining registrar, outside this account entirely. There is
  no benign background use of this call: an auth code is retrieved to hand to another registrar.
  UNVERIFIED and consequential — AWS publishes no statement about whether responseElements
  carries the code in CloudTrail. The SDK service model marks DomainAuthCode `sensitive`, but
  that trait governs SDK logging, not CloudTrail. Treat the trail as possibly holding a live
  transfer credential and restrict read access to it accordingly; do not assert either way.
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_RetrieveDomainAuthCode.html
  - https://attack.mitre.org/techniques/T1584/001/
tags:
  - attack.resource-development
  - attack.t1584.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53domains.amazonaws.com'
    eventName:
      - 'RetrieveDomainAuthCode'
      - 'retrieveDomainAuthCode'
  success:
    errorCode: null
  condition: selection and success
falsepositives:
  - >-
    A migration already approved through change management. The same one as the lock rule, and
    it should already be an open ticket by the time this fires.
level: high
---
title: A registered domain was prepared for transfer out of AWS
id: 9e0d3f57-6a24-41cb-b7e8-25c1084fd396
status: experimental
description: >-
  The lock came off and the authorization code was taken. Those are steps 2 and 3 of AWS's
  documented transfer-out procedure, in order, and step 4 happens at the gaining registrar where
  this account cannot see it. Group-by is userIdentity.arn rather than the domain name
  deliberately: AWS's one published domains event nests the parameter as
  requestParameters.domainName.name rather than as a flat string, the generality of that shape is
  unverified, and a correlation keyed on a field that may resolve to null joins nothing. An
  account holds at most 20 registered domains (50 on accounts older than March 2021), so grouping
  by principal is bounded and the domain is read off the events themselves. Timespan is 24h
  because this is a deliberate multi-step procedure performed by a person, not a scripted burst.
references:
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-transfer-from-route-53.html
  - https://attack.mitre.org/techniques/T1584/001/
tags:
  - attack.resource-development
  - attack.t1584.001
correlation:
  type: temporal_ordered
  rules:
    - route53_domain_transfer_lock_disabled
    - route53_domain_auth_code_retrieved
  group-by:
    - userIdentity.arn
  timespan: 24h
level: critical
---
title: Route 53 domain transferred to another AWS account
id: 3a86c1d2-58f4-4e97-a0b6-91d7e4530c8b
name: route53_domain_transferred_to_another_account
status: experimental
description: >-
  TransferDomainToAnotherAwsAccount moved the registration to a different AWS account. This is
  operation type INTERNAL_TRANSFER_OUT_DOMAIN and it is a DIFFERENT event from a registrar
  transfer — both lose the domain from this account, only one leaves AWS. It is shipped as its
  own rule rather than as the second leg of a correlation because it does not require the
  transfer lock to have been removed first, and pairing the two produced a rule that could only
  fire on the less damaging path. The response elements of this call include a password used to
  accept the transfer; the service model marks it sensitive, with the same CloudTrail caveat as
  the auth code.
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_TransferDomainToAnotherAwsAccount.html
  - https://attack.mitre.org/techniques/T1584/001/
tags:
  - attack.resource-development
  - attack.t1584.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53domains.amazonaws.com'
    eventName:
      - 'TransferDomainToAnotherAwsAccount'
      - 'transferDomainToAnotherAwsAccount'
  success:
    errorCode: null
  condition: selection and success
falsepositives:
  - >-
    An account consolidation. Verifiable against the destination account ID in the request, and
    that ID is the first thing to read.
level: high
---
title: Route 53 domain contact or nameservers changed
id: 71c5b8e4-0d39-4a26-95f7-c8e2306b1a4d
name: route53_domain_registration_altered
status: experimental
description: >-
  UpdateDomainContact changes where the transfer-approval email goes; UpdateDomainNameservers
  changes which nameservers the TLD delegates to, which moves resolution for the entire domain
  without touching a single hosted-zone record. The first is how an attacker captures the veto
  before removing the lock; the second is a hijack that needs no transfer at all. CloudTrail
  cannot show what a contact was changed TO — AWS redacts it at source with
  "Personally-identifying contact information is not logged in the request" — so this rule can
  tell you the redirection happened and never where to, which is precisely why it must fire.
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_UpdateDomainContact.html
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_UpdateDomainNameservers.html
  - https://attack.mitre.org/techniques/T1584/001/
tags:
  - attack.resource-development
  - attack.t1584.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53domains.amazonaws.com'
    eventName:
      - 'UpdateDomainContact'
      - 'updateDomainContact'
      - 'UpdateDomainNameservers'
      - 'updateDomainNameservers'
  success:
    errorCode: null
  condition: selection and success
falsepositives:
  - >-
    An annual contact refresh, or a genuine move to a third-party DNS provider. Both are planned;
    neither happens in the same hour as a lock change.
level: medium
---
title: Route 53 domain registration change refused
id: 8d2f7095-4b1e-43ac-86d0-5e93a70c2b61
name: route53_domain_change_refused
status: experimental
description: >-
  A registrar-side change was refused. Base rule, and intent observed either way. AccessDenied
  and AccessDeniedException are the IAM refusals and mean a principal without the permission
  tried. TLDRulesViolation and UnsupportedTLD mean the registry refused the operation for that
  TLD — the attacker still tried, and will try the next domain. DuplicateRequest means the
  operation was already in progress, which is itself worth reading. Ships at medium because a
  refused attempt on a registrar API has no benign explanation that an approved change would not
  have made unnecessary.
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_DisableDomainTransferLock.html
  - https://attack.mitre.org/techniques/T1584/001/
tags:
  - attack.resource-development
  - attack.t1584.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'route53domains.amazonaws.com'
    eventName:
      - 'DisableDomainTransferLock'
      - 'disableDomainTransferLock'
      - 'RetrieveDomainAuthCode'
      - 'retrieveDomainAuthCode'
      - 'TransferDomainToAnotherAwsAccount'
      - 'transferDomainToAnotherAwsAccount'
      - 'UpdateDomainNameservers'
      - 'updateDomainNameservers'
  refused:
    errorCode:
      - 'AccessDenied'
      - 'AccessDeniedException'
      - 'TLDRulesViolation'
      - 'UnsupportedTLD'
      - 'DuplicateRequest'
      - 'OperationLimitExceeded'
  condition: selection and refused
falsepositives:
  - >-
    An automation holding stale permissions and retrying. Fix the automation — a service that
    retries a forbidden registrar call is a defect whichever way the permission question lands.
level: medium
```

What this set structurally cannot do: it cannot see the transfer request, because that request
is made at the gaining registrar and exists in no AWS account. It cannot tell you where a
contact was redirected to, because AWS redacts contact detail before the event is written. And
it cannot tell you whether a transfer is *in flight* — that is live state, and Query 3 is the
only place to get it.

---

### Key Investigation Queries

> Registrar events are `route53domains.amazonaws.com`; hosted-zone events are
> `route53.amazonaws.com` and **only appear in `us-east-1`** — AWS: *"To view events for Route 53
> API requests, you must choose US East (N. Virginia) in the Region selector."* The registrar
> half does not share that convention (its published sample is `us-west-2`), so registrar
> lookups below are not Region-pinned and an empty result from a single-Region trail is
> `[!] INCONCLUSIVE`, never clean. Extraction uses
> `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50
> events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: every registrar action, in order

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in DisableDomainTransferLock disableDomainTransferLock \
          RetrieveDomainAuthCode retrieveDomainAuthCode \
          TransferDomainToAnotherAwsAccount transferDomainToAnotherAwsAccount \
          UpdateDomainContact updateDomainContact \
          UpdateDomainNameservers updateDomainNameservers; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "route53domains.amazonaws.com") |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       domain: (.requestParameters.domainName.name // .requestParameters.domainName // "<not-in-event>"),
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}'
done | jq -s 'sort_by(.time)'
```

Read it as a sequence. Lock off, then auth code, is the transfer-out chain and the domain may
already be committed. A contact change *before* the lock came off means the veto was moved
first, which is the difference between a mistake and an operation. `"domain":
"<not-in-event>"` on every row means the nesting differs from AWS's published sample — read the
raw `requestParameters` before concluding anything about which domain was touched.

#### Query 2 — Sweep: the lock state of every domain in the account

```bash
REGION="us-east-1"

aws route53domains list-domains --region "$REGION" --output json | \
  jq -r '.Domains[] | "\(.DomainName)\tlock=\(.TransferLock)\texpiry=\(.Expiry)\tautorenew=\(.AutoRenew)"'

echo
UNLOCKED=$(aws route53domains list-domains --region "$REGION" --output json | \
  jq -r '[.Domains[] | select(.TransferLock == false) | .DomainName] | length')
[ "$UNLOCKED" -eq 0 ] && echo "[OK] every registered domain is transfer-locked" \
                      || echo "[FAIL] $UNLOCKED domain(s) are unlocked — enumerate and re-lock in §3"
```

This is the whole account: the registered-domain quota is 20 (50 on older accounts), so there is
no pagination story and no sampling. An unlocked domain that nobody planned to move is the
finding, whether or not CloudTrail shows how it got that way.

#### Query 3 — Inspect: is a transfer actually in flight? (CloudTrail cannot answer this)

```bash
REGION="us-east-1"
SINCE=$(date -u -v-90d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)

echo "== outbound registrar transfers =="
aws route53domains list-operations --region "$REGION" \
  --type TRANSFER_OUT_DOMAIN --submitted-since "$SINCE" --output json | \
  jq -r '.Operations[] | "\(.SubmittedDate)\t\(.DomainName)\t\(.Status)\t\(.StatusFlag // "-")\t\(.OperationId)"'

echo
echo "== account-to-account moves, and lock changes, from the same list =="
for T in INTERNAL_TRANSFER_OUT_DOMAIN DOMAIN_LOCK UPDATE_NAMESERVER UPDATE_DOMAIN_CONTACT; do
  aws route53domains list-operations --region "$REGION" \
    --type "$T" --submitted-since "$SINCE" --output json | \
    jq -r --arg t "$T" '.Operations[] | "\($t)\t\(.SubmittedDate)\t\(.DomainName)\t\(.Status)"'
done

echo
echo "== registry-side status per domain — pendingTransfer is the point of no return =="
for D in $(aws route53domains list-domains --region "$REGION" --output json | jq -r '.Domains[].DomainName'); do
  aws route53domains get-domain-detail --domain-name "$D" --region "$REGION" --output json | \
    jq -r '"\(.DomainName)\tstatus=\(.StatusList // [] | join(","))\tns=\(.Nameservers | map(.Name) | join(","))"'
done
```

`list-operations` is live state, not a log, and it is the single most valuable command in this
playbook: the detection can only tell you the lock came off; this tells you whether anyone acted
on it. A `TRANSFER_OUT_DOMAIN` in `SUBMITTED` or `IN_PROGRESS`, or a `StatusList` containing
`pendingTransfer`, means the domain is already at the registry and §3 Step 2 is the whole
response. `DOMAIN_LOCK` in the same list is an independent, non-CloudTrail record of the lock
change itself — useful precisely when the event-name casing question has left CloudTrail empty.

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
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time) | group_by(.src) | map({source: .[0].src, count: length, events: (map(.event) | unique)})'
```

Registrar access is rare enough that a principal touching it has almost always done other things
worth reading — a `CreateAccessKey` before, an `UpdateDomainContact` around it, hosted-zone
changes after. Run this in `us-east-1` and repeat in any Region the trail suggests, given the
registrar half's unsettled Region convention.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Re-lock first and investigate second — the lock is cheap, reversible, and stops a transfer that
has not yet been submitted. Then establish whether one already has been, because that single
fact decides whether you are running an incident or a dispute.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being contained.

#### Step 1 — Re-lock every domain in the account

```bash
REGION="us-east-1"

for D in $(aws route53domains list-domains --region "$REGION" --output json | \
           jq -r '.Domains[] | select(.TransferLock == false) | .DomainName'); do
  echo "[i] re-locking $D"
  aws route53domains enable-domain-transfer-lock --domain-name "$D" --region "$REGION" \
    --output json | jq -r '"    operation=\(.OperationId)"' \
    || echo "    [!] $D refused — read the error and continue with the rest"
done

REMAIN=$(aws route53domains list-domains --region "$REGION" --output json | \
         jq -r '[.Domains[] | select(.TransferLock == false)] | length')
[ "$REMAIN" -eq 0 ] && echo "[OK] all domains locked" \
                    || echo "[FAIL] $REMAIN still unlocked — a TLDRulesViolation means the registry refuses locking for that TLD"
```

The loop terminates because the account holds at most 20 domains. Re-locking a domain whose
transfer is already at the registry does **not** recall it — that is Step 2.

#### Step 2 — Establish whether a transfer is already in flight, and act accordingly

```bash
REGION="us-east-1"
SINCE=$(date -u -v-90d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)

INFLIGHT=$(aws route53domains list-operations --region "$REGION" \
  --type TRANSFER_OUT_DOMAIN --submitted-since "$SINCE" --output json | \
  jq -r '[.Operations[] | select(.Status == "SUBMITTED" or .Status == "IN_PROGRESS")] | length')

if [ "$INFLIGHT" -gt 0 ]; then
  echo "[FAIL] $INFLIGHT outbound transfer(s) in flight."
  echo "       1. REJECT the transfer from the approval email Route 53 sent the registrant."
  echo "          AWS: 'If you don't take action, the transfer will proceed automatically on"
  echo "          the specified date.' Silence approves. Find that mail now."
  echo "       2. Open an AWS support case in parallel, at the highest severity available."
  echo "       3. Open a transfer dispute with the registry for the TLD. AWS states it has no"
  echo "          information once a transfer starts: 'all status updates go to the new"
  echo "          registrar'. There is no AWS API that recalls the domain."
else
  echo "[OK] no outbound transfer submitted in the last 90 days — the lock in Step 1 holds"
fi
```

This is the step where the playbook has no command to offer, and says so. Every AWS lever has
already been pulled by Step 1; what remains is the approval email, AWS support, and the
registry's dispute process. Treat the email as a countdown, not a notification.

#### Step 3 — Restore the registration's own state

```bash
REGION="us-east-1"
DOMAIN="<domain-from-Query-1>"

aws route53domains get-domain-detail --domain-name "$DOMAIN" --region "$REGION" --output json | \
  jq '{DomainName, Nameservers: (.Nameservers | map(.Name)), StatusList,
       AutoRenew, ExpirationDate, RegistrarName,
       AdminEmailPresent: (.AdminContact.Email != null)}'

echo
echo "[i] Compare Nameservers against the hosted zone's delegation set:"
ZID=$(aws route53 list-hosted-zones-by-name --dns-name "$DOMAIN" --region us-east-1 \
      --output json | jq -r '.HostedZones[0].Id // empty')
if [ -n "$ZID" ]; then
  aws route53 get-hosted-zone --id "$ZID" --region us-east-1 --output json | \
    jq -r '.DelegationSet.NameServers[]' | sort > /tmp/zone_ns.txt
  aws route53domains get-domain-detail --domain-name "$DOMAIN" --region "$REGION" --output json | \
    jq -r '.Nameservers[].Name' | sort > /tmp/reg_ns.txt
  if diff -q /tmp/zone_ns.txt /tmp/reg_ns.txt >/dev/null; then
    echo "[OK] registrar delegation matches the hosted zone"
  else
    echo "[FAIL] registrar and hosted zone disagree — resolution is being served by someone else"
    diff /tmp/zone_ns.txt /tmp/reg_ns.txt || true
  fi
else
  echo "[!] no hosted zone found for $DOMAIN in this account — INCONCLUSIVE, not clean"
fi
```

The contact record cannot be compared against CloudTrail, because CloudTrail never held it.
Compare it against the scheduled `GetDomainDetail` snapshot from §1, or against public WHOIS,
and restore it with `update-domain-contact` from the known-good values.

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

#### Treat the authorization code as issued

If `RetrieveDomainAuthCode` succeeded, a transfer credential for that domain exists outside AWS
and re-locking does not invalidate it. Route 53 exposes no API to rotate an auth code
independently; the practical rotation is to leave the domain locked so the code cannot be
redeemed, and to raise a support case if the domain must be moved for a legitimate reason
afterwards. Record the assumption in the incident rather than assuming expiry.

#### Restrict who can read the trail

Because AWS makes no statement about whether the code appears in `responseElements`, the trail
itself is now potentially a credential store for this domain. Audit who can read the trail's S3
prefix and its CloudWatch Logs group, and remove anyone who does not need it.

#### Remove the permission that made this possible

```bash
for P in $(aws iam list-policies --scope Local --output json | jq -r '.Policies[].Arn'); do
  V=$(aws iam get-policy --policy-arn "$P" --output json | jq -r '.Policy.DefaultVersionId')
  aws iam get-policy-version --policy-arn "$P" --version-id "$V" --output json | \
    jq -e --arg p "$P" '
      .PolicyVersion.Document.Statement
      | (if type == "object" then [.] else . end)
      | map(select(.Effect == "Allow"))
      | map(select((.Action // .NotAction // []) | (if type == "string" then [.] else . end)
            | any(. == "*" or . == "route53domains:*" or startswith("route53domains:"))))
      | length > 0' >/dev/null 2>&1 && echo "[!] $P grants route53domains write"
done
```

The registrar API has **no resource-level ARNs and no service-specific condition keys**, so a
policy granting `route53domains:*` grants it over every domain in the account and cannot be
scoped down to one. The only granularity available is *which principal*, which is why the
guardrail in §6 is an SCP on `aws:PrincipalArn` and not a resource policy.

#### Remove emergency policies once clean

Delete `IR-Deny-All` and `AWSRevokeOlderSessions` once the principal has been rebuilt or
retired, and remove any break-glass grant created during the response.

---

## 5. Recovery

### Restore Clean State

#### Verify every domain is locked and delegating where it should

```bash
REGION="us-east-1"

UNLOCKED=$(aws route53domains list-domains --region "$REGION" --output json | \
           jq -r '[.Domains[] | select(.TransferLock == false)] | length')
[ "$UNLOCKED" -eq 0 ] && echo "[OK] every registered domain is transfer-locked" \
                      || echo "[FAIL] $UNLOCKED domain(s) unlocked"

PENDING=$(aws route53domains list-domains --region "$REGION" --output json | \
          jq -r '.Domains[].DomainName' | while read -r D; do
            aws route53domains get-domain-detail --domain-name "$D" --region "$REGION" \
              --output json | jq -r 'select((.StatusList // []) | any(. == "pendingTransfer")) | .DomainName'
          done | wc -l | tr -d ' ')
[ "$PENDING" -eq 0 ] && echo "[OK] no domain is in pendingTransfer at the registry" \
                     || echo "[FAIL] $PENDING domain(s) pendingTransfer — Step 2 of §3 is still live"
```

#### Confirm nothing was issued against the name while it was exposed

A domain that spent time under someone else's control may have had certificates issued for it.
Search certificate transparency for the name and every subdomain, over the exposure window, and
treat anything you did not request as an incident of its own. This is the same check the CAA
playbook makes for a different reason, and it is the only external evidence available.

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  eventSource=route53domains.amazonaws.com  eventName=disableDomainTransferLock  (lowercase d)"
echo "  no errorCode  — this is the casing the source rule misses"
echo "and MUST fire equally on:"
echo "  eventName=DisableDomainTransferLock  (uppercase D)"
echo "The rule MUST NOT fire on:"
echo "  eventSource=route53.amazonaws.com  eventName=ChangeResourceRecordSets"
echo "  (a hosted-zone change — different service, and outside this rule entirely)"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal other than the domain owner could remove the transfer lock | `route53domains` write actions were not restricted by SCP; the API has no resource-level scoping, so any grant is an account-wide grant |
| The lock removal was noticed only because a rule happened to fire | No configuration history exists for the registrar — `AWS::Route53Domains::*` is not an AWS Config recorded resource type, and nothing was polling `list-domains` |
| The detection could have been silently dead | The rule matched the API's casing rather than CloudTrail's documented lowercase-first-letter convention for registrar actions |
| The rule was waiting for a second event | The transfer-out is executed at the gaining registrar and produces no AWS event, so the correlation could never complete on the case that matters |
| The approval email was the only remaining control | Its destination is attacker-modifiable through `UpdateDomainContact`, and no alert watched that call |

### Recommended Guardrails

**Fence the registrar API by principal — the only granularity it offers**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["route53domains:DisableDomainTransferLock",
             "route53domains:RetrieveDomainAuthCode",
             "route53domains:TransferDomainToAnotherAwsAccount",
             "route53domains:UpdateDomainContact",
             "route53domains:UpdateDomainNameservers",
             "route53domains:DisableDomainAutoRenew",
             "route53domains:DeleteDomain"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/DomainAdministration"] } }
}
```

`"Resource": "*"` is not laziness here: Route 53 Domains publishes no resource ARNs and no
service-specific condition keys, so per-domain scoping does not exist and `aws:PrincipalArn` is
the whole control surface. Note also that an SCP constrains principals **in this organization**
only — it does nothing about a transfer initiated at another registrar with a stolen auth code.

**Structural controls**
- Keep the registration in a dedicated account whose only purpose is to hold domains, with no
  workloads and a very short principal list. The blast radius of every other account then stops
  short of the name itself.
- Set the registrant contact to a monitored distribution list, not an individual, and monitor it
  the way you monitor an on-call channel. It is the last control in the chain and it is a mailbox.
- Enable auto-renew and alert on it being disabled. Expiry reaches the same outcome as a
  transfer, more slowly and with less noise.
- Poll `list-domains` and `list-operations` on a schedule and store the results with history.
  This is the substitute for the AWS Config coverage that does not exist, and it is what makes
  the P2 "lock flipped with no matching event" trigger possible.

**Detection improvements**
- Match both event-name casings everywhere, not only here. The convention applies to every
  registrar action, so any rule written against this service has the same latent defect.
- Alert on the **absence** of registrar events as well: a quarter with no `list-domains` snapshot
  is a monitoring failure, and this service is quiet enough that absence is meaningful.
- Wire `DOMAIN_LOCK` operations from `list-operations` into the same alert path as the CloudTrail
  rule. Two independent sources for the same fact is the correct answer to an event-name
  convention nobody has re-confirmed.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1584.001 — Compromise Infrastructure: Domains |
| MITRE tactic | Resource Development (TA0042) |
| Primary API | `DisableDomainTransferLock` → `RetrieveDomainAuthCode` → *(transfer requested at the gaining registrar — no AWS call)* |
| Event source | route53domains.amazonaws.com |
| Key discriminator | A successful registrar-side write at all. AWS advises against `DisableDomainTransferLock` unless a transfer is intended, so the operation announces intent by existing — no baseline needed |
| Ground-truth signal | `TransferLock: false` in `list-domains`, or a `TRANSFER_OUT_DOMAIN` operation in `list-operations` — live state, not the log |
| "Was it used" pivot | `list-operations --type TRANSFER_OUT_DOMAIN`, and `StatusList` containing `pendingTransfer` on `get-domain-detail` |
| Blast radius | The domain and everything that authenticates by it: certificates, email, published URLs, OIDC issuer URLs, SAML entity IDs, and every subdomain delegated beneath it |
| Error strings | `AccessDenied` / `AccessDeniedException`, `TLDRulesViolation` (*"The top-level domain does not support this operation"*), `UnsupportedTLD`, `DuplicateRequest` (*"The request is already in progress for the domain"*), `OperationLimitExceeded`, `InvalidInput` |

**MITRE mapping note:** the source carries bare `T1584`. `T1584.001` names registration
hijacking exactly — "changing the registration of a domain name without the permission of the
original registrant" — and cites AWS Route 53 by name, so the sub-technique is strictly better.
`T1078` is secondary because the registrar API is reached with valid credentials. Both IDs are
needed for a reason that is general to this service: every DNS-, domain- and certificate-shaped
technique in ATT&CK is modelled adversary-centrically on the **PRE** platform, so filtering the
matrix by `platform=IaaS` returns none of them. Citing the PRE technique for the objective and
an IaaS technique for the observable AWS action is the convention across all five `route53.*`
playbooks.

### Residual Risk

If `RetrieveDomainAuthCode` succeeded, a transfer credential for the domain exists outside AWS
and outside your control; the lock is what stops it being redeemed, and the lock is one API call
away from being removed again. If the contact was changed, the address the approval email
reaches may still not be yours, and no AWS record shows what it was changed to — only the
scheduled snapshot or public WHOIS can tell you. If a transfer completed, the domain is gone:
no AWS API reaches it, and the remaining routes are the registry's dispute process and ICANN's.
Anything already issued against the name while it was exposed — a certificate, a mail-domain
verification, an OIDC trust — outlives the recovery of the name itself, and certificate
transparency is the only place that record exists.
