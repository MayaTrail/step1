# Detection Note — T1584.001 (Compromise Infrastructure: Domains)

**Signal:** an NS record was created or replaced in a hosted zone — either changing which
nameservers Route 53 claims are authoritative for the zone, or handing an entire subtree to
somebody else's nameservers.

**This is the quietest technique in the service, and it is quiet by construction.** A delegation
breaks nothing. Every existing record stays exactly where it was; every service keeps working;
no log stops flowing; nothing in the account changes except one record set. Route 53 simply stops
answering for everything below that label, and whoever runs the listed nameservers starts. ATT&CK
describes the result precisely: *"domain shadowing by creating malicious subdomains under their
control while keeping any existing DNS records. As service will not be disrupted, the malicious
subdomains may go unnoticed for long periods of time."*

**What the original rule got wrong** — it matches `CREATE` or `UPSERT` on an NS record and stops
there, and its MITRE mapping is doubly dead.

*It never reads the nameservers.* This is the whole detection. Route 53's own nameservers are
always `ns-<n>.awsdns-<n>.{com,net,org,co.uk}`, so a delegation whose values do not contain
`awsdns` points the subtree at third-party infrastructure — a one-field test needing no baseline
and no lookup. The corrected set makes it a rule of its own at critical, and it is the row an
analyst should read first.

`T1685` is Defence Impairment, which does not describe
this at all: a delegation impairs no defence and clears no log.

*It cannot tell an apex change from a delegation.* Neither can the corrected Sigma, and the rule
header says so rather than implying otherwise. The event carries `hostedZoneId` — an ID — and
`resourceRecordSet.name`, a name; deciding which is which needs the zone's *name*, which is not in
the event. Query 2 of the playbook resolves every zone ID and classifies every NS record in the
account, which also catches delegations created before the log window opens.

## Two mechanics that decide the response

**The TTL is the undo cost.** AWS recommends 172800 seconds — 48 hours — for a delegation NS
record, and that same number is the cache lifetime a responder inherits after deleting one.
Resolvers that cached the delegation keep asking the attacker's nameservers until it expires, and
there is no mechanism to flush them. A delegation created with a long TTL is expensive to undo; a
delegation created with a very short one was built to be swapped again. Both are worth reading,
which is why TTL is projected in the KQL and carries its own trigger row.

**Deleting a child zone while the parent still delegates to it creates the same exposure, from
the other direction.** AWS documents the window in its own words: *"We suggest that you delete
the NS record first, and wait for the TTL on that NS record to expire before you delete the child
hosted zone. This ensures that no one can hijack the child hosted zone while DNS resolvers still
have the child hosted zone's name servers cached."* So a `DeleteHostedZone` on a child zone while
the parent's NS record still stands is a live dangling delegation — a detection, not merely an
operational note, and the correct teardown order is NS-record-first.

## Response levers

**`UPSERT` destroys the prior delegation and nothing records it.** The event carries only the new
nameservers; Route 53 keeps no record-set version history. `DELETE` is the opposite — the API
requires an exact match of every existing value, so a `DELETE` event's `resourceRecords` **is**
the removed record and is genuinely usable for restoration. AWS Config recording
`AWS::Route53::HostedZone` is the only other before-and-after the platform offers.

**NS cannot be hidden behind an alias.** AWS states that NS is not aliasable, is unavailable for
weighted, latency, geolocation and failover routing, and that *"You can't use the `*` wildcard
for resource records sets that have a type of NS."* So `resourceRecords[]` is always populated
for this record type — unlike A records, where an alias carries no values at all — and the
nameserver test above cannot be evaded by changing routing policy.

**Error strings:** the set for `ChangeResourceRecordSets` is closed — `NoSuchHostedZone`,
`NoSuchHealthCheck`, `InvalidChangeBatch`, `InvalidInput`, `PriorRequestNotComplete` — plus the
IAM forms `AccessDenied` / `AccessDeniedException`. Throttling is code `Throttling`, message
*"Rate exceeded"*. Batches are transactional, so a rejected batch changed nothing;
`PriorRequestNotComplete` repeating against one zone is evidence of scripted change volume.

**Regionality.** `route53.amazonaws.com` events appear only in `us-east-1`, and an empty result
from any other Region is `[!] INCONCLUSIVE`, never clean.

**MITRE:** T1584.001 primary, T1584.002 secondary. `T1584.001` names subdomain hijacking and
domain shadowing explicitly.

**Severity:** high for any NS change; critical when the nameservers are not Route 53's and not on
the approved external list. The ceiling is complete control of a subtree of the organisation's
namespace, including the ability to satisfy DNS-based domain-control validation and obtain a
publicly trusted certificate for names under it.

**GuardDuty:** no coverage. There is no finding namespace whose resource is a hosted zone; Route
53 appears in GuardDuty only as a *data source* feeding EC2 and EKS findings. AWS Config records
`AWS::Route53::HostedZone` but ships no managed rule for NS delegation content, so the comparison
against a committed baseline is yours to run.

**Files here:**
- `sigma_t1584_001.yml` — three documents: `route53_ns_record_changed` (high),
  `route53_ns_delegated_outside_route53` (critical) and `route53_ns_change_refused` (medium).
- `kql_t1584_001.kql` — the element-level view via `mv-expand`, with the nameserver test, the TTL
  reading and the omitted-parameters case surfaced before the expand can drop it.

Full response procedure is in `../PLAYBOOK.md`.
