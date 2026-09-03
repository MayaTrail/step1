# Detection Note — T1485 (Data Destruction)

**Signal:** `DeleteHostedZone` destroyed a Route 53 hosted zone, and the destruction that
mattered happened in the `ChangeResourceRecordSets` calls that had to come first.

**This is the only destructive Route 53 use case where the API itself proves a precursor
chain.** AWS refuses the delete unless the zone is already empty:

> "You can delete a hosted zone only if it contains only the default SOA and NS records and has
> DNSSEC signing disabled. If the hosted zone contains other records or has DNSSEC enabled, you
> must delete the records and disable DNSSEC before deletion. Attempting to delete a hosted zone
> with additional records or DNSSEC enabled returns a `HostedZoneNotEmpty` error."

So a successful `DeleteHostedZone` is not the beginning of the investigation, it is the end of
one. Resolution stopped when the records went. That reframing decides where the queries look,
where the containment starts, and what the alert is actually late for.

## What the original rule got wrong

It matches `DeleteHostedZone` and the absence of an error, and hands the analyst a zone ID.

| Defect | Consequence |
|---|---|
| Fires on the last event of the sequence | The record deletions that broke resolution are already minutes old. The `HostedZoneNotEmpty` refusal — the one point at which nothing had been lost yet — is not matched at all |
| No principal filter | Infrastructure code deletes hosted zones as a matter of routine. Undifferentiated, the rule is muted, and it is muted in the direction that hides the deletion nobody planned |
| Passes on a zone ID with no name | `requestParameters.id` is the entire payload. After the delete, `GetHostedZone` returns `NoSuchHostedZone`, so the name cannot be recovered from Route 53 at all — it has to come from AWS Config or from a correlated earlier event. An alert that cannot name the zone cannot be triaged |
| Treats deletion as an outage | AWS's own warning is stronger: *"if you delete a hosted zone, someone could hijack the domain and route traffic to their own resources using your domain name."* The registrar still delegates to four Route 53 nameservers that no longer hold the zone |

## Field shape, and the traps in it

`eventSource` `route53.amazonaws.com`, **management** plane, and — because Route 53 is a global
service — every event is stamped **`awsRegion: us-east-1`**. AWS: *"To view events for Route 53
API requests, you must choose US East (N. Virginia) in the Region selector."* A `lookup-events`
call in any other Region returns zero forever.

```
DeleteHostedZone          requestParameters.id                       "Z1PA6795UKMFR9"   (flat)
                          responseElements.changeInfo.{id,status,submittedAt}
ChangeResourceRecordSets  requestParameters.hostedZoneId             (a DIFFERENT field name)
                          requestParameters.changeBatch.changes[].action
                          requestParameters.changeBatch.changes[].resourceRecordSet.{name,type,tTL}
                          requestParameters.changeBatch.changes[].resourceRecordSet.resourceRecords[].value
                          responseElements.changeInfo.{id,status,submittedAt}
```

- **`id` on the delete, `hostedZoneId` on the change.** One service, two names for the same
  value. Both may arrive bare or path-qualified (`/hostedzone/Z...`); normalise to the last
  segment before joining them.
- **`changes[]` holds change objects directly.** There is no `changes[].change` level.
- **`tTL`** — the same initial-lowercase mangling that gives `iPAddress` on `CreateHealthCheck`.
- **Alias records carry no `resourceRecords` and no `tTL`.** The target is under `aliasTarget`.
  A query that only reads `resourceRecords[].value` silently loses every alias.
- **`responseElements` is `changeInfo`-wrapped**, and `status` is only ever `PENDING` or
  `INSYNC`.

**AWS labels its own sample of this event `"additionalEventData": {"Note": "Do not use to
reconstruct hosted zone"}`.** AWS does not explain the note anywhere reachable, so take it as the
instruction it is: CloudTrail is evidence of who changed what, not a zone backup.

**An absent `requestParameters` is a finding, not a gap.** CloudTrail omits the field entirely —
not truncated, omitted — above 100 KB, and Route 53 permits 1,000 `ResourceRecord` elements and
32,000 `Value` characters per request. A successful `ChangeResourceRecordSets` whose `changes[]`
parses to nothing is a bulk zone rewrite whose contents are not in the log. Both shipped rules
and the KQL score it as high, not as noise.

## Recreating the zone does not restore it

> "Route 53 assigns four name servers to every hosted zone, and **the name servers differ for
> each one**."
> "You must create a new hosted zone and update the name servers for your domain registration,
> **which can require up to 48 hours to take effect**."

So recovery is a two-party operation: recreate in Route 53, then change the delegation at
whoever holds the registration — which may not be AWS. The exception is a **reusable delegation
set**: a zone created with a `DelegationSetId` comes back on the same four nameservers and needs
no registrar change. That is why `delegationSetId` is projected in the KQL at triage time.

AWS also documents the safe teardown order for a child zone, and it is the inverse of what an
attacker does:

> "We suggest that you delete the NS record first, and wait for the TTL on that NS record to
> expire before you delete the child hosted zone. This ensures that no one can hijack the child
> hosted zone while DNS resolvers still have the child hosted zone's name servers cached."

A `DeleteHostedZone` on a child zone while the parent still carries the matching NS record is a
live dangling delegation, and it is detectable — see `../../route53.stealth.ns-record-created-or-updated/`
for the delegation side of the same problem.

## Response levers

**Error strings:** `DeleteHostedZone`, complete: `HostedZoneNotEmpty` (400), `InvalidDomainName` (400),
`InvalidInput` (400), `NoSuchHostedZone` (404), `PriorRequestNotComplete` (400).
`ChangeResourceRecordSets`, complete: `InvalidChangeBatch` (400), `InvalidInput` (400),
`NoSuchHealthCheck` (404), `NoSuchHostedZone` (404), `PriorRequestNotComplete` (400).
Throttling arrives as code `Throttling`, message *"Rate exceeded"*. Denials are `AccessDenied`
and `AccessDeniedException` — match both (rule A7).

`PriorRequestNotComplete` in a burst is worth its own note: Route 53 rejects a second change to
a zone while the first is still processing, so its repetition is evidence of a **scripted**
change loop rather than console work.

## Query logging and posture controls

**There is no DNS query data in a default account.** Route 53 public-zone query logging is
opt-in, capped at one configuration per hosted zone, and its CloudWatch Logs group must be in
`us-east-1`. It covers **public zones only** — *"You can log queries only for public hosted
zones"* — and even where it is on, AWS warns that *"query logs might contain information about
only one query out of every several thousand queries"* because recursive resolvers cache. So it
answers "is this name being resolved at all", never "by whom" or "how often". Private-zone
queries are outside the feature entirely; those belong to Route 53 Resolver, a different service.

**AWS Config records `AWS::Route53::HostedZone`.** This is the only reliable way to recover a
deleted zone's name and record set, and it is the single highest-value preparation item for this
technique. The one substantive managed rule, `route53-query-logging-enabled`, is available only
in US East (N. Virginia) and checks query logging, not deletion.

**No GuardDuty coverage.** There is no `Policy:Route53/*` namespace and no finding type whose
resource is a hosted zone; Route 53 appears in GuardDuty only as a data source for EC2 and EKS
runtime findings.

**MITRE:** The mechanical replacement, `T1685` (*Disable or Modify Tools*,
Defense Impairment), is **also wrong on the merits**: destroying a hosted zone impairs no
defence and clears no log — it removes availability.

**`T1485` — Data Destruction (Impact)** is the mapping, and it lists **IaaS**: *"In cloud
environments, adversaries may leverage access to delete cloud storage objects, machine images,
database instances, and other infrastructure crucial to operations to damage an organization or
their customers."* A hosted zone is that. Rejected: `T1531` (account access removal), `T1498` /
`T1499` (resource exhaustion, not an API-driven delete), `T1565` (manipulation, and no IaaS
platform).

**Severity:** **High** for a deletion by a principal outside the infrastructure pipeline; **Critical** where
the zone was public and the registrar still delegates to it, because that is the window AWS
itself warns can be hijacked. The source rates it P2 and treats the event as terminal; High is
right because the deletion is unrecoverable in Route 53 and recovery needs a second party.

**GuardDuty:** no finding type covers Route 53 **configuration** changes. Route 53 Resolver DNS query logs are a GuardDuty data source, but they drive EC2 DNS findings such as `Trojan:EC2/DNSDataExfiltration` and `Backdoor:EC2/C&CActivity.B!DNS` — about what instances resolve, not about who edited a zone. This technique produces no GuardDuty signal.

**Files here:**

- `sigma_t1485.yml` — four documents: the primary deletion rule at `high` (successes only,
  pipeline-allowlisted); an `informational` base rule for record deletions; a `temporal_ordered`
  correlation at `critical` for purge-then-delete inside an hour; and a `medium` rule on the
  `HostedZoneNotEmpty` refusal, which is the only point in the chain at which nothing has been
  lost yet.
- `kql_t1485.kql` — resolves the zone **name** from earlier events on the same zone ID, which is
  a cross-event self-join Sigma cannot express; recovers the destroyed records from the `DELETE`
  changes, which are exact by API requirement; and scores an omitted `requestParameters` as a
  bulk rewrite rather than as a parse failure.

Sibling notes: `../../route53.stealth.multiple-dns-zones-deleted-by-a-single-user/detections/`
covers the same observable at volume, where the response differs — the work-list has to be built
by reconciling an inventory rather than read off the event, and the principal must be severed
before any zone is recreated. `../../route53.stealth.ns-record-created-or-updated/detections/`
owns the delegation half of the hijack risk this note ends on.

Full response procedure is in `../PLAYBOOK.md`.
