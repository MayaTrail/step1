# Ground truth — Amazon Route 53

Audited once, 2026-08-29, against AWS documentation. Every playbook under `techniques/route53.*`
is written from this file. Anything AWS does not state is marked **UNVERIFIED** and stays
unverified in the shipped files rather than being smoothed over.

Scope: Route 53 **hosted zones / DNS** (`route53.amazonaws.com`) and Route 53 **Domains /
registrar** (`route53domains.amazonaws.com`). Route 53 **Resolver**
(`route53resolver.amazonaws.com`) and the Resolver query-log stream are a different service and
belong to `techniques/route53dns.*`; they are **not** absorbed here.

---

## 1. Regionality — Route 53 is global and its trail records are not where you think

**`route53.amazonaws.com` events carry `"awsRegion": "us-east-1"`.** Every hosted-zone event in
AWS's own published CloudTrail sample — `ListHostedZones`, `CreateHealthCheck`,
`ChangeResourceRecordSets`, `DeleteHostedZone` — is stamped `us-east-1`, and AWS states the
console rule explicitly:

> "To view events for Route 53 API requests, you must choose **US East (N. Virginia)** in the
> Region selector at the top of the console."
> — *Logging Amazon Route 53 API calls with AWS CloudTrail*

AWS repeats the same constraint for the service's quotas: *"To view quotas and request higher
quotas for Route 53, you must change the Region to US East (N. Virginia)."*

**Consequence for every query in every Route 53 playbook:** `aws cloudtrail lookup-events
--region <anything-but-us-east-1>` returns **zero** for `route53.amazonaws.com`, exactly as it
does for IAM and STS global events. A responder who runs the query in the account's "home"
Region gets an empty result and reads it as "nothing happened". Every query block in this
service pins `--region us-east-1` and every empty result is routed to `[!] INCONCLUSIVE`, never
to a clean verdict.

Route 53 also has **no Region selector on the resource**: a hosted zone is a global object, so
there is no "sweep every Region" step in these playbooks — one `us-east-1` query is the whole
account. That is the inverse of the RDS/KMS pattern and it is a simplification, not a gap.

## 2. Two services, two event sources — and they are not interchangeable

| | Hosted zones (DNS) | Domains (registrar) |
|---|---|---|
| `eventSource` | `route53.amazonaws.com` | `route53domains.amazonaws.com` |
| What it controls | the *answers* the domain's nameservers give | the *registration* — who owns the name, and which nameservers the TLD delegates to |
| API shape | REST/XML (`/2013-04-01/hostedzone/...`) | JSON-RPC (`x-amz-target: Route53Domains_v20140515.<Action>`) |
| Losing it costs you | resolution for that zone, until you restore it | **the domain**, permanently, and no AWS API can get it back |

This split is the whole of the transfer-lock use case. A rule written against
`route53.amazonaws.com` cannot see a single registrar event, and a control that protects hosted
zones does not protect the registration above them.

**AWS's own sample event for `route53domains.amazonaws.com` carries two properties that break
naive rules**, and both are quoted from the Route 53 CloudTrail page:

1. **The event name is lower-camel, not upper-camel.**
   > "The `eventName` element identifies the action that occurred. (In CloudTrail logs, the
   > first letter is lowercase for domain registration actions even though it's uppercase in
   > the names of the actions. For example, `UpdateDomainContact` appears as
   > `updateDomainContact` in the logs)."

   The sample event that follows carries `"eventName": "updateDomainContact"`. A rule matching
   `eventName: 'DisableDomainTransferLock'` exactly is therefore at risk of never firing.
   **Match case-insensitively, or match both forms.** See §3 for what was and was not
   confirmed about the current behaviour.

2. **`awsRegion` on that sample is `us-west-2`, not `us-east-1`** — while every
   `route53.amazonaws.com` event in the same document is `us-east-1`. So the two halves of
   Route 53 do **not** share a Region convention, and a registrar rule scoped to `us-east-1`
   is not obviously safe. See §3.

3. **Contact detail is redacted at the source.** The sample carries
   `"additionalEventData": "Personally-identifying contact information is not logged in the
   request"` and a `requestParameters` reduced to `{"domainName": {"name": "example.com"}}` —
   note that even the domain name is **nested one level**, not flat. `responseElements` on that
   sample is `{"requestId": "..."}` — an operation handle, nothing else.

---

## 4. `ChangeResourceRecordSets` — one event name, every record type

This is the discriminator problem for three of the five use cases. **CAA, NS, A, MX, TXT and
every other record type are all created, changed and deleted by the same API call and produce
the same `eventName`.** Nothing at the top level of the event says what changed. The record
type is buried, and the nesting is exactly this — verified against AWS's published sample:

```
requestParameters.hostedZoneId                                     "Z1PA6795UKMFR9"
requestParameters.changeBatch.comment                              "Adding subdomains"
requestParameters.changeBatch.changes[]
  .action                                                          "CREATE" | "DELETE" | "UPSERT"
  .resourceRecordSet.name                                          "prod.example.com."   (trailing dot)
  .resourceRecordSet.type                                          "A" | "NS" | "CAA" | ...
  .resourceRecordSet.tTL                                           300
  .resourceRecordSet.resourceRecords[].value                       "192.0.1.1"
responseElements.changeInfo.id                                     "/change/C156SRE0X2ZB10"
responseElements.changeInfo.status                                 "PENDING"
responseElements.changeInfo.submittedAt                            "Jan 16, 2018 12:41:43 AM"
```

**Traps in that shape, each of which silently yields `null`:**

- `changes[]` holds the change objects **directly**. There is no intermediate `change` key —
  `changeBatch.changes[].change.resourceRecordSet` is wrong and matches nothing.
- **`tTL`, not `ttl` or `TTL`.** Lower `t`, upper `TL`. CloudTrail lower-cases only the first
  character of the API's `TTL` member.
- The record `name` carries a **trailing dot** and Route 53 stores it in a normalised form —
  an equality test against `prod.example.com` without the dot fails.
- `resourceRecords` is **absent** on an alias record; the target sits in
  `resourceRecordSet.aliasTarget` instead. A jq `select(.resourceRecords[] | ...)` over an
  alias change drops the record entirely (rule D2).
- The response is `changeInfo`-wrapped. `responseElements.status` is flat and wrong;
  `responseElements.changeInfo.status` is right, and its only values are `PENDING` and
  `INSYNC` (`GetChange`).
- **A single event can carry many changes of many types.** The batch is one event. A rule that
  reads `changes[0]` sees the first change only; a rule that matches `type: 'NS'` anywhere in
  the array cannot say which *name* the NS change was for without walking the array.

**AWS's own sample event carries a warning about this record, and it is load-bearing:**

> `"additionalEventData": {"Note": "Do not use to reconstruct hosted zone"}`

AWS puts this on the `ChangeResourceRecordSets` record itself. Treat CloudTrail as evidence of
*what was changed and by whom*, and **not** as a zone backup. Every recovery step in these
playbooks that restores records therefore names an authoritative source — IaC state or an
exported zone file — first, and CloudTrail only as a last resort with that caveat attached.

**Documented request maximums** (AWS Route 53 *Quotas*):

- 1,000 `ResourceRecord` elements per request — *"When the value of the `Action` element is
  `UPSERT`, each `ResourceRecord` element is counted twice."*
- 32,000 characters summed across all `Value` elements — again doubled for `UPSERT`.
- 10,000 records per hosted zone; 400 records per record set.

Those two request caps are far below CloudTrail's 100 KB `requestParameters` omission
threshold, so — as with IAM policy documents (`AUTHORING-BRIEF.md` D-h) — **there is no
size-based evasion path here** and no "oversized request" companion rule is shipped.

### `UPSERT` destroys the prior value and CloudTrail does not record it

`UPSERT` creates the record set if it is absent and **replaces** it if it is present. The event
carries the *new* values. The **old** values are in no AWS event and in no AWS API after the
call — Route 53 keeps no record-set version history. So for every NS/CAA/A change, "what was it
before?" is answerable only from an earlier `ChangeResourceRecordSets` event that set it, from
IaC state, or from passive DNS. This is stated plainly in the affected playbooks rather than
papered over with a "revert the change" step that has nothing to revert to.

## 5. `DeleteHostedZone` — the zone must already be empty, and the event names nothing

**Request shape is `requestParameters.id`** — flat, and a *different field name* from
`ChangeResourceRecordSets`'s `hostedZoneId`. Verified against AWS's published sample:
`"requestParameters": {"id": "Z1PA6795UKMFR9"}`, with
`responseElements.changeInfo.{id,status,submittedAt}`.

**The event does not carry the zone name, the record count, or anything else about what was
destroyed.** It carries a zone ID. That is the entire blast-radius content of the event.

**The precursor chain is real and AWS states it:**

> "You can delete a hosted zone only if it contains only the default SOA and NS records and has
> DNSSEC signing disabled. If the hosted zone contains other records or has DNSSEC enabled, you
> must delete the records and disable DNSSEC before deletion. Attempting to delete a hosted
> zone with additional records or DNSSEC enabled returns a `HostedZoneNotEmpty` error."
> — *DeleteHostedZone*, Amazon Route 53 API Reference

So **a successful `DeleteHostedZone` proves that a preceding `ChangeResourceRecordSets` batch
already emptied the zone**, and if DNSSEC was signing, a `DisableHostedZoneDNSSEC` /
`DeactivateKeySigningKey` pair ran too. The destruction happened in those calls; the delete is
the tidy-up behind it. Investigation therefore starts *before* the alerting event, not at it —
the same structure as a successful ECS `DeleteCluster`. `HostedZoneNotEmpty` in the log is the
attempt that ran ahead of its own cleanup, and it is the best early warning this technique
offers.

**Deletion is irreversible and AWS says so, together with the hijack consequence:**

> "If you delete a hosted zone, you can't undelete it. You must create a new hosted zone and
> update the name servers for your domain registration, which can require up to 48 hours to
> take effect. (If you delegated responsibility for a subdomain to a hosted zone and you delete
> the child hosted zone, you must update the name servers in the parent hosted zone.) In
> addition, **if you delete a hosted zone, someone could hijack the domain and route traffic to
> their own resources using your domain name.**"

That last sentence is why zone deletion is not merely an outage. The delegation at the
registrar still points at four Route 53 nameserver names; those names are shared infrastructure;
AWS itself warns that another party can end up answering for your zone.

**Error set for `DeleteHostedZone`:** `HostedZoneNotEmpty` (400), `InvalidDomainName` (400),
`InvalidInput` (400), `NoSuchHostedZone` (404), `PriorRequestNotComplete` (400).
`PriorRequestNotComplete` carries the message *"The request was rejected because Route 53 was
still processing a prior request."* Throttling surfaces as code `Throttling`, message *"Rate
exceeded"*.

**Error set for `ChangeResourceRecordSets`:** see §9.

## 6. Quotas that set thresholds

| Entity | Quota | Why it matters here |
|---|---|---|
| **Registered domains** | **20 per AWS account** (new accounts since March 2021; 50 on older accounts) | A registrar-side sweep is bounded and cheap. Any per-domain loop terminates. |
| Hosted zones | 500 per account (raisable) | A mass-deletion sweep is bounded but not small. |
| Records | 10,000 per hosted zone; 400 per record set | |
| Hosted zones per reusable delegation set | 100 | The delegation-set control in §8. |
| Query log configurations | **1 per hosted zone** | There is nothing to correlate across; a zone either has query logging or it does not. |

---

## 7. The domain-transfer chain — the highest-stakes case, and the one AWS cannot log

### What `DisableDomainTransferLock` actually does

> "This operation removes the transfer lock on the domain (specifically the
> `clientTransferProhibited` status) to allow domain transfers. **We recommend you refrain from
> performing this action unless you intend to transfer the domain to a different registrar.**
> Successful submission returns an operation ID that you can use to track the progress and
> completion of the action. If the request is not completed successfully, the domain registrant
> will be notified by email."
> — *DisableDomainTransferLock*, Amazon Route 53 API Reference

Request: `{"DomainName": "..."}` — one required parameter, max 255 characters.
Response: `{"OperationId": "string"}` — **nothing else**. Track with `GetOperationDetail`.

Errors: `DuplicateRequest` (400, *"The request is already in progress for the domain"*),
`InvalidInput` (400), `OperationLimitExceeded` (400), `TLDRulesViolation` (400,
*"The top-level domain does not support this operation"*), `UnsupportedTLD` (400). Plus the
common set. Note that a `TLDRulesViolation` or `UnsupportedTLD` refusal is still **intent
observed** — somebody tried.

AWS's sample request signs against `host:route53domains.us-east-1.amazonaws.com`.

### The transfer-out itself is not an AWS API call

This is the thesis of the use case and it inverts the source rule. AWS's documented procedure
for *Transferring a domain from Amazon Route 53 to another registrar* is:

1. Check the domain's status codes — the domain cannot be in `pendingDelete`, `pendingTransfer`,
   `redemptionPeriod`, `clientTransferProhibited` or `serverTransferProhibited`.
2. *"If the value of **Transfer lock** is **On**, choose **Turn off transfer lock**"* →
   `DisableDomainTransferLock`.
3. *"choose **Transfer to another registrar** from the **Transfer out** dropdown. In the
   **Transfer to another registrar** dialog box, choose **Copy** to copy the authorization code
   for the domain transfer."* → `RetrieveDomainAuthCode`.
4. *"**Use the process that is provided by the new registrar to request a transfer of the
   domain.**"* — **this step happens at the gaining registrar. It produces no AWS API call and
   no CloudTrail event in this account.**
5. Route 53 emails the registrant contact a link to approve or reject. And then the sentence
   that decides the response urgency: **"If you don't take action, the transfer will proceed
   automatically on the specified date."**

**So there is no "transfer request" event to correlate against.** The only AWS-visible successor
to `DisableDomainTransferLock` on an outbound transfer is `RetrieveDomainAuthCode`. After that,
AWS is blind until the domain is gone. A rule that waits for a transfer event as its second leg
waits forever; a rule that fires on the lock alone is the only rule that can fire in time.

Two further consequences:

- **Silence approves.** The confirmation email is a *veto*, not a consent. An incident that is
  triaged on Monday for a Friday-night lock removal may already have completed.
- **The email goes to the registrant contact**, which is itself attacker-modifiable through
  `UpdateDomainContact` — and whose content CloudTrail explicitly does not log
  (*"Personally-identifying contact information is not logged in the request"*). So the
  attacker can redirect the veto and the log will show the redirection happened without showing
  where to.

### The transfer prohibition window

AWS states the restriction as **14 days**, twice, on the transfer-out page:

> "You must have registered the domain with the current registrar or transferred registration
> for the domain to the current registrar at least **14 days** ago."

> "**Domains cannot be transferred within the first 14 days of registration.**"

**UNVERIFIED / CORRECTED FROM BRIEFING:** this audit was asked to establish a *60-day*
post-registration transfer prohibition. AWS's own transfer-out documentation says **14 days**,
and presents it as a *typical registrar requirement* (*"Requirements vary, but the following
requirements are typical"*) rather than as a Route 53 guarantee. See §7a for what the separate
research pass established about ICANN's 60-day rules; where the two disagree the shipped files
cite AWS's number for the AWS-side statement and mark the registry-side rule as registry
policy, not AWS behaviour. **Do not write "AWS blocks transfers for 60 days" anywhere.**

### Recovery path — there effectively is not one

Once the transfer completes, the domain is at another registrar and no AWS API reaches it.
AWS's own escalation route for a disputed transfer is a support case, and AWS states that it
holds no information: *"When you transfer a domain to another registrar, all status updates go
to the new registrar, so Route 53 has no information about why a transfer failed."* The
remaining levers are the registry's transfer-dispute process and ICANN's, both of which are
outside AWS entirely. **The playbook says this rather than offering a containment command that
does not exist.**

## 8. Restoring a deleted zone — the name servers change

**UNVERIFIED at the time this section was drafted; resolved in §8a.** The question that decides
whether zone-deletion recovery is one step or two: does re-creating a hosted zone with the same
name return the *same* four Route 53 nameservers, or a new randomly-assigned delegation set?
If it returns a new set, every recovery requires a registrar-side NS update and up to 48 hours
of propagation, per AWS's own `DeleteHostedZone` warning ("*update the name servers for your
domain registration, which can require up to 48 hours to take effect*"). The control that makes
recreation NS-stable is a **reusable delegation set** (`CreateReusableDelegationSet`, 100 per
account, up to 100 hosted zones per set) — a zone created with `DelegationSetId` gets that set's
nameservers rather than a fresh one.

## 9. Verifying propagation — `GetChange`

`GetChange` is the only assertion in this service that can tell you a change has actually taken
effect, and it can fail:

> "`PENDING` indicates that the changes in this request have not propagated to all Amazon
> Route 53 DNS servers managing the hosted zone. This is the initial status of all change batch
> requests. `INSYNC` indicates that the changes have propagated to all Route 53 DNS servers
> managing the hosted zone."

Errors: `InvalidInput` (400), `NoSuchChange` (404). Because `PENDING` is *"the initial status of
all change batch requests"*, a recovery block that reads `INSYNC` is a real assertion — it is
`PENDING` until Route 53 says otherwise, so `[FAIL]` is reachable.

**`INSYNC` is Route 53's internal propagation, not the internet's.** It says the Route 53
nameservers all answer consistently. It says nothing about resolver caches holding the old
answer for the record's TTL, and nothing at all about the *delegation* being correct — a zone
can be perfectly `INSYNC` and still be receiving no queries because the parent points elsewhere.
Every recovery in this service pairs `GetChange` with an independent resolution check against
the zone's own nameservers.
---

## 7a. `TRANSFER_OUT_DOMAIN` — the pivot CloudTrail cannot give you

The outbound transfer produces no API call, but it **does** produce a Route 53 Domains
*operation*. Verified against the shipped `route53domains` service model (API version
2014-05-15, read from AWS CLI v2.27.47): `OperationType` is a closed enum and it contains

```
REGISTER_DOMAIN  DELETE_DOMAIN  TRANSFER_IN_DOMAIN  UPDATE_DOMAIN_CONTACT  UPDATE_NAMESERVER
CHANGE_PRIVACY_PROTECTION  DOMAIN_LOCK  ENABLE_AUTORENEW  DISABLE_AUTORENEW  ADD_DNSSEC
REMOVE_DNSSEC  EXPIRE_DOMAIN  TRANSFER_OUT_DOMAIN  CHANGE_DOMAIN_OWNER  RENEW_DOMAIN
PUSH_DOMAIN  INTERNAL_TRANSFER_OUT_DOMAIN  INTERNAL_TRANSFER_IN_DOMAIN  RELEASE_TO_GANDI
TRANSFER_ON_RENEW  RESTORE_DOMAIN
```

`ListOperations` accepts `--type` and `--submitted-since` and `--status`, and
`OperationStatus` is `SUBMITTED | IN_PROGRESS | ERROR | SUCCESSFUL | FAILED`, with a
`StatusFlag` drawn from `PENDING_ACCEPTANCE | PENDING_CUSTOMER_ACTION | PENDING_AUTHORIZATION |
PENDING_PAYMENT_VERIFICATION | PENDING_SUPPORT_CASE`.

**`aws route53domains list-operations --type TRANSFER_OUT_DOMAIN` is therefore the definitive
"is a transfer actually in flight" check, and it is live state, not a log.** It is the single
most valuable command in the transfer playbook: the detection can only tell you the lock came
off; this tells you whether anyone acted on it. `DOMAIN_LOCK` in the same list is the operation
type produced by the lock being enabled or disabled, so the operations list also gives an
independent, non-CloudTrail record of the lock change itself.

`INTERNAL_TRANSFER_OUT_DOMAIN` is the AWS-account-to-AWS-account move
(`TransferDomainToAnotherAwsAccount`) and is a **different** event from a registrar transfer.
Both are losses of the domain from this account; only one leaves AWS.

**Secrets on this API surface.** The same service model marks `DomainAuthCode` (the return of
`RetrieveDomainAuthCode`), the `Password` returned by `TransferDomainToAnotherAwsAccount`,
`ContactDetail` and `Email` as `sensitive`. That trait governs SDK logging, **not** CloudTrail.
**UNVERIFIED:** AWS publishes no statement about whether `responseElements` for
`RetrieveDomainAuthCode` carries the auth code. AWS's one published domains event shows
`responseElements` reduced to `{"requestId": "..."}`, and the same event carries
`"additionalEventData": "Personally-identifying contact information is not logged in the
request"` — evidence of redaction on the *request* side for contacts, and nothing at all about
the response side for auth codes. Treat the trail as **possibly** carrying a live transfer
credential and restrict read access accordingly; do not assert either way.

**Error sets, read from the service model (they are short, and each is a complete set):**

| API | Errors |
|---|---|
| `DisableDomainTransferLock` / `EnableDomainTransferLock` | `InvalidInput`, `DuplicateRequest`, `TLDRulesViolation`, `OperationLimitExceeded`, `UnsupportedTLD` |
| `RetrieveDomainAuthCode` | `InvalidInput`, `UnsupportedTLD` |
| `TransferDomain` | `InvalidInput`, `UnsupportedTLD`, `DuplicateRequest`, `TLDRulesViolation`, `DomainLimitExceeded`, `OperationLimitExceeded` |
| `TransferDomainToAnotherAwsAccount` | `InvalidInput`, `OperationLimitExceeded`, `DuplicateRequest`, `UnsupportedTLD` |
| `UpdateDomainNameservers` / `UpdateDomainContact` | `InvalidInput`, `DuplicateRequest`, `TLDRulesViolation`, `OperationLimitExceeded`, `UnsupportedTLD` |

Denials are the ordinary IAM forms — `AccessDenied` and `AccessDeniedException` (rule A7);
match both.

`GetDomainDetail` returns `DomainName`, `Nameservers`, `AutoRenew`, the three contacts,
`RegistrarName`, `WhoIsServer`, `RegistrarUrl`, `AbuseContactEmail`, `RegistryDomainId`,
`CreationDate`, `UpdatedDate`, `ExpirationDate`, `Reseller`, `DnsSec`, **`StatusList`** and
`DnssecKeys`. `StatusList` carries the EPP status codes — `clientTransferProhibited` is the
transfer lock, and `pendingTransfer` is a transfer already at the registry.
`ListDomains` returns a per-domain **`TransferLock` boolean**, which makes the account-wide lock
assertion one cheap call over at most 20 domains (§6).

## 9a. Complete error sets — hosted zones

Read from the shipped `route53` service model (API version 2013-04-01) and cross-checked against
the API Reference. These are **closed** sets, not samples:

| API | Errors |
|---|---|
| `ChangeResourceRecordSets` | `NoSuchHostedZone`, `NoSuchHealthCheck`, `InvalidChangeBatch`, `InvalidInput`, `PriorRequestNotComplete` |
| `DeleteHostedZone` | `NoSuchHostedZone`, `HostedZoneNotEmpty`, `PriorRequestNotComplete`, `InvalidInput`, `InvalidDomainName` |
| `CreateHostedZone` | `InvalidDomainName`, `HostedZoneAlreadyExists`, `TooManyHostedZones`, `InvalidVPCId`, `InvalidInput`, `DelegationSetNotAvailable`, `ConflictingDomainExists`, `NoSuchDelegationSet`, `DelegationSetNotReusable` |
| `GetChange` | `InvalidInput`, `NoSuchChange` |
| `ListResourceRecordSets` / `GetHostedZone` | `NoSuchHostedZone`, `InvalidInput` |
| `CreateQueryLoggingConfig` | `ConcurrentModification`, `NoSuchHostedZone`, `NoSuchCloudWatchLogsLogGroup`, `InvalidInput`, `QueryLoggingConfigAlreadyExists`, `InsufficientCloudWatchLogsResourcePolicy` |
| `DeleteQueryLoggingConfig` | `ConcurrentModification`, `NoSuchQueryLoggingConfig`, `InvalidInput` |
| `DisableHostedZoneDNSSEC` | `NoSuchHostedZone`, `InvalidArgument`, `ConcurrentModification`, `KeySigningKeyInParentDSRecord`, `DNSSECNotFound`, `InvalidKeySigningKeyStatus`, `InvalidKMSArn`, `InvalidInput` |

Throttling is code `Throttling`, message *"Rate exceeded"*. `PriorRequestNotComplete` is code
and message both, and its presence in a burst is evidence of **scripted** change volume against
one zone — Route 53 rejects a second change to a zone while the first is still processing.

`RRType` is a closed enum: `SOA A TXT NS CNAME MX NAPTR PTR SRV SPF AAAA CAA DS TLSA SSHFP SVCB
HTTPS`. `ChangeAction` is `CREATE | DELETE | UPSERT`. `ChangeStatus` is `PENDING | INSYNC`.
`CreateHostedZone` accepts an optional **`DelegationSetId`** — the reusable-delegation-set hook.

---

## 10. MITRE ATT&CK — every ID below checked live 2026-08-29

Two IDs the source pack uses are **revoked**.

| ID | Status | Name | Tactic | IaaS? |
|---|---|---|---|---|
| `T1584.001` | live | Compromise Infrastructure: Domains | Resource Development | **no — PRE only** |
| `T1584.002` | live | Compromise Infrastructure: DNS Server | Resource Development | no — PRE only |
| `T1588.004` | live | Obtain Capabilities: Digital Certificates | Resource Development | no — PRE only |
| `T1608.003` | live | Stage Capabilities: Install Digital Certificate | Resource Development | no — PRE only |
| `T1596.001` | live | Search Open Technical Databases: DNS/Passive DNS | Reconnaissance | no — PRE only |
| `T1685` | live | Disable or Modify Tools | Defense Impairment (**TA0112**) | **yes** |
| `T1685.002` | live | Disable or Modify Tools: Disable or Modify Cloud Log | Defense Impairment | **yes** |
| `T1485` | live | Data Destruction | Impact | **yes** |
| `T1078` | live | Valid Accounts | Stealth, Persistence, Priv-Esc, Initial Access | **yes** |
| `T1098` | live | Account Manipulation | Persistence, Privilege Escalation | **yes** |

**TA0005 is now named _Stealth_** and **TA0112 _Defense Impairment_ is a new tactic**; both are
current. The corpus tags them `attack.stealth` and `attack.defense-impairment`.

### The platform mismatch, stated once so it is not re-argued five times

Every DNS-, domain- and certificate-shaped technique in ATT&CK — `T1584.*`, `T1583.*`,
`T1588.*`, `T1608.*`, `T1596.*`, `T1590.*` — is modelled **adversary-centrically**: the attacker
acquires or compromises infrastructure *in order to attack someone else*. Their platform is
**PRE**. Route 53 detections are IaaS control-plane events. Filtering the matrix by
`platform=IaaS` returns none of them.

That is a genuine gap in ATT&CK, not something a better ID choice resolves. The convention
adopted across these five playbooks: **cite the PRE technique for the adversary objective and an
IaaS technique for the observable AWS action**, and say in the mapping note that this is why two
IDs appear.

### Per use case

| Use case | Primary | Secondary |
|---|---|---|
| Transfer lock → transfer | `T1584.001` | `T1078` |
| NS record created/updated | `T1584.001` | `T1584.002` |
| CAA record created/updated | `T1685` | `T1588.004` (objective), `T1608.003` (next stage) |
| DNS zone deleted (single and mass) | `T1485` | — |

Rejected candidates, with the reason, so they are not revisited: `T1583.001` (acquiring a fresh
domain, not stealing one); `T1565.001/.002` (Impact, but no IaaS platform, and DNS records are
not "stored"/"transmitted data" in ATT&CK's sense); `T1071.004` (that is C2 *tunnelled inside*
the DNS protocol, not authoritative record manipulation); `T1553.004` (planting a root CA in a
host's trust store — the opposite direction from public CA issuance policy); `T1531` (deleting
user accounts, not infrastructure); `T1498`/`T1499` (resource exhaustion, not an API-driven
delete).
---

## 4a. Three more traps in `ChangeResourceRecordSets`, each of which silently loses events

**Alias records carry no `resourceRecords` and no `tTL` at all.** The API says to omit both when
creating an alias; the target lives in `resourceRecordSet.aliasTarget`, whose fields are subject
to the same lower-first-letter mangling (`dNSName` — **pattern-inferred from the confirmed `tTL`
and `iPAddress` manglings, not directly observed in a published event**). An attacker repointing
an apex alias at their own distribution or load balancer therefore produces a
`ChangeResourceRecordSets` event with **no `resourceRecords` array whatsoever**, and any jq or
KQL that reaches into `resourceRecords[].value` drops that record silently (rule D2). Every
query in this service reads `resourceRecords[]?.value` **and** `aliasTarget.dNSName`.

**An oversized change batch has its `requestParameters` OMITTED, not truncated.** CloudTrail's
field contract:

> "This field has a maximum size of 100 KB. When the field size exceeds 100 KB, the
> `requestParameters` content is omitted."
> — *CloudTrail record contents*

There is no partial-array case: a detection reading `changeBatch.changes[]` on an oversized
batch sees **zero** changes, not a short list. Route 53 permits 1,000 `ResourceRecord` elements
and 32,000 `Value` characters per request, and the surrounding JSON envelope for a batch that
size plausibly clears 100 KB. **So an absent or empty `requestParameters` on a successful
`ChangeResourceRecordSets` is itself a signal — a bulk zone rewrite — and is treated as one
rather than as a parsing gap.** `additionalEventData` has its own 28 KB cap with the same
omit-on-exceed behaviour.

**`DELETE` records the old values; `UPSERT` does not.** AWS: *"To delete a resource record set,
you must specify all the same values that you specified when you created it."* Because the API
demands an exact match, a `DELETE` event's `resourceRecords[]` **is** the record that was
removed — genuinely usable for restoration. `UPSERT` replaces and the event carries only the new
values, so the prior state is unrecoverable from the event. That asymmetry decides which
recovery steps are possible in which playbook, and it is stated where it applies rather than
assumed uniformly.

Batches are transactional: *"Route 53 validates the changes in the request and then either makes
all or none of the changes in the change batch request."* So one `InvalidChangeBatch` means
nothing in that batch was applied — a failed event is not a partial change.

## 8a. Recreating a hosted zone gives DIFFERENT name servers — resolved

The question left open in §8 is settled, verbatim:

> "**Multiple hosted zones that have the same name.** You can create more than one hosted zone
> with the same name and add different records to each. **Route 53 assigns four name servers to
> every hosted zone, and the name servers differ for each one.** When you update your
> registrar's name server records, be careful to use the Route 53 name servers for the correct
> hosted zone…"
> — *Considerations when working with a public hosted zone*

> "**Reusable delegation sets** — By default, Route 53 assigns a unique set of four name servers
> (called a delegation set) to each hosted zone that you create."

**Therefore re-creating a deleted zone does not restore resolution.** The new zone answers on
four different nameservers; the registrar's delegation still names the old four; nothing
resolves until the registrar is updated, *"which can take up to 48 hours to take effect"*. Zone
recovery is a two-party operation — Route 53 **and** whoever holds the registration, which may
not be AWS at all.

The one exception, and it is the guardrail: `CreateHostedZone` accepts a **`DelegationSetId`**.
A zone created against a reusable delegation set gets that set's nameservers, so a zone deleted
and recreated inside the same set comes back on the *same* four names and needs no registrar
change. 100 reusable delegation sets per account, 100 hosted zones per set.

**Detection consequence:** the `delegationSetId` on a `CreateHostedZone` that follows a deletion
tells you whether the actor could restore resolution without touching the registrar — and, if an
attacker recreates the zone, whether they inherited your delegation.

## 8b. AWS's own ordering rule for deleting a child zone — and the hijack window it defines

> "If you gave a subdomain its own hosted zone and you want to delete that child hosted zone,
> you must also update the parent hosted zone by deleting the NS record with the same name as
> the child hosted zone… **We suggest that you delete the NS record first, and wait for the TTL
> on that NS record to expire before you delete the child hosted zone. This ensures that no one
> can hijack the child hosted zone while DNS resolvers still have the child hosted zone's name
> servers cached.**"
> — *Deleting a public hosted zone*

This is AWS documenting the takeover window in its own words. **A `DeleteHostedZone` on a child
zone while the parent still carries the matching NS record is a live dangling delegation**, and
that is a detection, not just an operational note. It also means the *correct* order for a
legitimate teardown is NS-record-first — so an actor who deletes the zone first and the NS
record never is doing it in the order that maximises the hijack window.

## 11. CAA — what it constrains, and for how long

CAA is a **preventative** control read by certificate authorities at issuance time. It is not a
runtime control and nothing validates against it after the fact:

> "A set of CAA records describes only current grants of authority to issue certificates for the
> corresponding DNS domain name. Since certificates are valid for a period of time, it is
> possible that a certificate that is not conformant with the CAA records currently published
> was conformant with the CAA records published at the time that the certificate was issued.
> **Relying Parties MUST NOT use CAA records as part of certificate validation.**"
> — RFC 8659 §1

So restoring a CAA record does **not** revoke a certificate issued while it was weakened. That
single fact shapes the whole eradication phase for this use case: the remediation is CT-log
review and revocation, not the DNS change.

**The permissive default is a conditional, not an affirmative grant** — RFC 8659 §3:

> "Before issuing a certificate, a compliant CA MUST check for publication of a Relevant RRset.
> **If such an RRset exists**, a CA MUST NOT issue a certificate unless the CA determines that
> either (1) the certificate request is consistent with the applicable CAA RRset or (2) an
> exception specified in the relevant CP or CPS applies. If the Relevant RRset for an FQDN or
> Wildcard Domain Name contains no Property Tags that restrict issuance (for instance, if it
> contains only iodef Property Tags or only Property Tags unrecognized by the CA), CAA does not
> restrict issuance."

**Tree-climbing** — the reason a CAA record on a parent still protects a subdomain, and the
reason deleting the *apex* CAA is the highest-impact CAA change available (RFC 8659 §3):

> "The search for a CAA RRset climbs the DNS name tree from the specified label up to, but not
> including, the DNS root '.' until a CAA RRset is found."
> ```
> RelevantCAASet(domain):
>   while domain is not ".":
>     if CAA(domain) is not Empty: return CAA(domain)
>     domain = Parent(domain)
>   return Empty
> ```

Route 53 documents the same behaviour: *"If a CA receives a request for a certificate for a
subdomain (such as www.example.com) and if no CAA record for the subdomain exists, the CA
submits a DNS query for a CAA record for the parent domain (such as example.com)."*

**Because a nearer RRset shadows a further one, publishing a permissive CAA on a *subdomain*
silently overrides a strict apex policy for that subdomain.** That is a `CREATE`, not a
`DELETE`, and a rule watching only deletions misses it.

**Authorizations are additive, and AWS's own example is the trap.** RFC 8659 §4.2 and the
Route 53 record-type page, verbatim:

> "If you create a CAA record for example.com and specify both of the following values, a CA
> that is using the value ca.example.net can issue the certificate for example.com:
> ```
> 0 issue ";"
> 0 issue "ca.example.net"
> ```"

So **adding one `issue` value next to a deny-all opens issuance to that CA.** The malicious
change is a `CREATE`/`UPSERT` that *adds* a value, and the record still "exists" afterwards — a
rule keyed on the CAA record being absent does not fire.

Route 53's CAA value format is `flags tag "value"`, three space-separated settings; `tag` is
alphanumeric only; the value is always quoted; extra name-value pairs are semicolon-separated
(`0 issue "ca.example.net; account=123456"`). Flags `128` means *"prevents the CA from issuing a
certificate if the CA doesn't support the specified feature"*. Deny-all is `0 issue ";"` plus
`0 issuewild ";"` — and RFC 8659 §4.2 adds that a syntactically invalid issue-value **also**
forbids issuance, which means a *malformed* CAA is fail-closed while a *missing* one is
fail-open.

**How long a weakened CAA stays exploitable.** CA/Browser Forum Baseline Requirements v2.2.9
(6 Aug 2026) §4.2.2.1:

> "If the CA issues a certificate after processing a CAA record, it MUST do so within the TTL of
> the CAA record, or 8 hours, whichever is greater."

And: *"CAs MAY check CAA records at any other time."* So the exploit window is **at least eight
hours from the change**, and **longer if the record's TTL is longer** — which makes a CAA record
whose TTL was raised shortly before it was weakened a deliberate extension of the window, and a
signal in its own right. A CAA lookup failure may also be treated as permission to issue under
three stated conditions, so making the record *unreachable* is equivalent to removing it.

## 12. NS records — apex versus delegation, and what AWS will and will not stop

AWS distinguishes the two uses, verbatim:

> "An NS record identifies the name servers for the hosted zone… The most common use for an NS
> record is to control how internet traffic is routed for a domain. To use the records in a
> hosted zone to route traffic for a domain, you update the domain registration settings to use
> the four name servers in the default NS record. (**This is the NS record that has the same name
> as the hosted zone.**) … You can create a separate hosted zone for a subdomain
> (acme.example.com)… You set up this configuration, known as 'delegating responsibility for a
> subdomain to a hosted zone' by creating **another NS record in the hosted zone for the root
> domain**."

So the record `name` decides which of two entirely different things happened:

- **`name` equals the hosted zone's own name** → the apex NS RRset. Changing it changes which
  nameservers Route 53 itself claims are authoritative. AWS's guidance is a recommendation, not
  a lock: *"Except in rare circumstances, we recommend that you don't add, change, or delete
  name servers in this record,"* and the subdomain guides say *"Do not create extra name server
  (NS) or start of authority (SOA) records… Do not delete the existing NS and SOA records."*
  **UNVERIFIED:** no AWS page states that Route 53 *enforces* this. Treat an apex NS change as
  permitted, rare, and very high signal — not as impossible.
- **`name` is a label below the zone** → a delegation. *"You create a new NS record in the
  hosted zone for the domain (example.com). The NS record name must be the subdomain name
  (acme.example.com), and you specify the four name servers that you got in step 3 as the record
  values."* And, decisively for this use case: *"You can also delegate a subdomain to other DNS
  services by creating NS records that point to those services' name servers instead."*

**A delegation NS record hands the entire subtree below that label to whoever operates the
listed nameservers.** Route 53 stops answering for anything under it. Nothing in the account
changes; no other record is touched; no service breaks. This is why the technique is quiet, and
it is exactly what ATT&CK calls domain shadowing: *"the malicious subdomains may go unnoticed for
long periods of time."*

AWS's recommended TTL for a delegation NS record is **172800 seconds (48 hours)**, which is also
the cache lifetime a responder inherits after reverting one. A delegation created with a *long*
TTL is expensive to undo; one created with a very short TTL is designed to be swapped.

Route 53 restricts NS in three places worth knowing: NS is **not** available for weighted,
latency, geolocation or failover routing; NS is **not** aliasable; and *"You can't use the \*
wildcard for resource records sets that have a type of NS."*

## 13. Query logging — the "was it used" pivot, and its limits

**Public hosted zones only**, verbatim from `CreateQueryLoggingConfig`:

> "The ID of the hosted zone that you want to log queries for. **You can log queries only for
> public hosted zones.**"

**The log group must be in `us-east-1`**, and so must its CloudWatch Logs resource policy:

> "The log group must be in the US East (N. Virginia) Region."
> "You must create the log group in the us-east-1 region. You must use the same AWS account to
> create the log group and the hosted zone that you want to configure query logging for."

**It is opt-in.** AWS never writes "off by default" in those words; the feature is described as
a set of tasks *"To start logging DNS queries for a specified hosted zone"*, and the AWS Config
managed rule `route53-query-logging-enabled` exists precisely to flag zones without it —
*"NON_COMPLIANT if DNS query logging is not enabled for your Amazon Route 53 public hosted
zones."* **Off by default is an inference from those two facts, not a quoted AWS sentence.**
Quota: **1 query log configuration per hosted zone.**

Record fields, in order: log format version; query timestamp (ISO 8601 UTC); hosted zone ID;
query name; query type; response code; layer-4 protocol (`TCP`/`UDP`); Route 53 edge location;
resolver IP; EDNS client subnet. Log stream is `{hosted-zone-id}/{edge-location-ID}`.

**The honest limit, and it must be stated in every playbook that reaches for this pivot:**

> "query logs might contain information about only one query out of every several thousand
> queries"

Because recursive resolvers cache, Route 53 sees a query only on a cache miss. So query logging
answers *"is this name being resolved at all"* and **cannot** answer *"how many clients used it"*
or *"which client used it"*. And for a **private** hosted zone it answers nothing — private-zone
queries are outside this feature entirely and are visible only through Route 53 Resolver query
logging, which is a different service (`route53resolver.amazonaws.com`), a different API, a
different Region model and a different set of quotas. **That is `techniques/route53dns.*`, not
this service, and it is not absorbed here.**

**Bottom line for the five playbooks:** in a default account there is **no** DNS query data at
all, so "was the malicious record actually used" is **unanswerable from AWS**. Where that is the
case the playbooks say so and fall back to external evidence — certificate transparency logs for
the CAA case, passive DNS and the delegated nameservers' own behaviour for the NS case — rather
than reporting the absence of query logs as the absence of use.

## 14. Posture and detection controls that exist elsewhere — and the ones that do not

- **GuardDuty: no coverage.** There is no `Policy:Route53/*` finding namespace and no finding
  type of any prefix whose resource is a Route 53 hosted zone or a registered domain. Route 53
  appears in GuardDuty only as a **data source** — Resolver DNS query logs feeding EC2/EKS
  findings such as `Trojan:EC2/DNSDataExfiltration` and
  `Impact:EC2/MaliciousDomainRequest.Reputation`. Those are runtime detections about instances,
  and they say nothing about hosted-zone or registrar configuration. **These playbooks are the
  only control; there is nothing to defer to.**
- **AWS Config: `AWS::Route53::HostedZone` IS a recorded resource type**, along with
  `AWS::Route53::DNSSEC`, `AWS::Route53::HealthCheck` and the `AWS::Route53Resolver::*` family.
  This is the **only reliable way to recover a deleted zone's name and record set**, and it is
  the single highest-value preparation item in this service.
- **One substantive Config managed rule: `route53-query-logging-enabled`**
  (`ROUTE53_QUERY_LOGGING_ENABLED`), resource type `AWS::Route53::HostedZone`, configuration-change
  triggered, **available only in US East (N. Virginia)**. Every other Route 53 managed rule is a
  tag-compliance rule. **There is no managed rule for CAA content, NS delegation, transfer locks
  or zone deletion.**
- **The registrar side has no Config coverage at all** — `AWS::Route53Domains::*` is not a
  recorded resource type, so there is no configuration-history record of a transfer lock being
  turned off. `route53domains list-domains` (with its per-domain `TransferLock` boolean) run on
  a schedule is the substitute, and §1 of the transfer playbook asks for it.

## 15. What could NOT be verified — carried into the shipped files as such

1. **What AWS's `"Note": "Do not use to reconstruct hosted zone"` means.** No AWS page explains
   it. The 100 KB `requestParameters` omission rule and the alias-record shape are documented
   and sufficient on their own; that the Note refers to either is an inference. Written into the
   playbooks as "AWS says do not use this to reconstruct a zone" — the instruction, not a theory
   about it.
2. **Whether Route 53 technically blocks editing or deleting the apex NS RRset.** Only
   recommendations are documented. Treated as permitted.
3. **Whether `RetrieveDomainAuthCode`'s `responseElements` carries the auth code in CloudTrail.**
   The SDK model marks the type `sensitive`; that trait governs SDK logging, not CloudTrail. No
   AWS statement either way.
4. **Whether `route53domains` events reliably carry `us-east-1` in `awsRegion`.** AWS's own
   published sample says `us-west-2`. See §3.
5. **Whether the lower-first-letter `eventName` convention for domain-registration actions is
   still current.** AWS documents it and gives one sample; it has not been re-confirmed against
   a recent event. Every rule here matches case-insensitively or matches both forms.
6. **CloudTrail sample events for `CreateHostedZone`, `CreateQueryLoggingConfig` and
   `AssociateVPCWithHostedZone` do not exist in AWS documentation.** The shapes used are
   extrapolated from the API request bodies and the confirmed mangling pattern, and are flagged
   as such at each use. In particular `responseElements.delegationSet.nameServers[]` on
   `CreateHostedZone` — the only record of what a zone's nameservers were — is **predicted, not
   observed**.
7. **The mangled field names `vPCId`, `vPCRegion` and `dNSName`.** Inferred from the confirmed
   `tTL` and `iPAddress`; not directly observed.
8. **Exact Route 53 Resolver query-logging API action names.** Out of scope here; noted so no
   playbook in this service invents one.
