# Detection Note — T1485 (Data Destruction), at volume

**Signal:** one principal destroyed several Route 53 hosted zones. The observable is identical
to `../../route53.stealth.dns-zone-deleted/` — a successful `DeleteHostedZone` — and the field
shape, the region trap, the error sets and the `tTL`/alias-record traps are documented once in
that sibling's note rather than repeated here. **What is different is the response**, and that
is what this note is about.

**A count of deletions is a floor, not a scope.** The correlation fires the instant the
threshold is crossed and the actor is not finished. Two properties of Route 53 make the gap
worse than usual:

- **A deleted zone is absent from `list-hosted-zones`.** There is no live-state call that
  enumerates what is missing — only what survives. Every other AWS destruction technique lets
  you list the wreckage; this one does not.
- **`lookup-events` pages at 50** and `DeleteHostedZone` carries only `requestParameters.id`.

So the work-list has to be built by **reconciling an authoritative inventory against surviving
state** — AWS Config's `AWS::Route53::HostedZone` history against `list-hosted-zones` — and no
restoration can start until that reconciliation completes. That step does not exist when there
is one zone, and it is the first reason these are two use cases rather than one playbook with
two trigger rows.

## Why the containment order inverts at volume

With one zone, the zone is recreated first: it reclaims the name before anybody else can, and
the principal is contained after.

At volume that order loses zones. **A newly created hosted zone contains only its default SOA
and NS records — which is exactly the state `DeleteHostedZone` requires** ("You can delete a
hosted zone only if it contains only the default SOA and NS records…"). A recreate loop racing a
live delete loop therefore hands the attacker zones that are immediately re-deletable, and gives
back ground already recovered. The principal is severed **first**, and only then is the queue
worked.

## Why restoration is a queue and not a loop

> "Route 53 assigns four name servers to every hosted zone, and **the name servers differ for
> each one**."

Each recreated zone therefore needs a **registrar-side delegation change**, at whatever registrar
holds that domain — which may not be AWS — and AWS puts the propagation cost at *"up to 48 hours
to take effect"*. That cost is per zone and does not parallelise away. The order in which zones
are restored is a containment decision, not a convenience: AWS states that a deleted zone leaves
a name where *"someone could hijack the domain and route traffic to their own resources"*, so the
queue is a race, worked by which names an attacker can most profitably claim.

The exception, and the guardrail: a zone created with a **`DelegationSetId`** comes back on the
same four name servers and needs no registrar change at all. The KQL projects
`ZonesNeedingRegistrar` for exactly this reason — it is the number that says how much of this
incident this account can fix by itself.

## What the original rule got wrong

| Issue | Impact | Correction |
|---|---|---|
| Counts deletions only | Route 53 refuses to delete a non-empty zone, so N deletions were preceded by N purges. The purge sweep is the same actor, minutes earlier, while every zone still exists and every record is still recoverable from the `DELETE` changes | Ship a second `value_count` correlation over distinct `hostedZoneId` on `ChangeResourceRecordSets` `DELETE` at the same threshold |
| No success filter on the counted event | A principal probing permissions and collecting three `AccessDenied` results fires the same alert as three completed destructions | `errorCode: null` on the base rule (B6) |
| No principal filter | Infrastructure code tears down zones in batches — that is what it is for. Undifferentiated, a volume rule on zone deletion is muted in the first week of any IaC rollout | Allowlist the pipeline principal on the base rules so **both** correlations inherit it |
| Presents its count as the scope | The count is a floor. The rule cannot know how many more zones the actor removed after it fired, and no Route 53 API can enumerate the missing ones | Reconcile against AWS Config before treating the work-list as closed |

## Threshold basis

There is no observed baseline to derive one from, so it is derived from documented behaviour and
stated so a deployer can adjust it knowingly. An account carries **500 hosted zones** by default
and AWS documents no rate limit on `DeleteHostedZone`, so a sweep is bounded only by how fast the
purges complete. Against that, a legitimate environment teardown removes one or two zones and
does it through the pipeline role. **Three distinct zones from one principal inside an hour**,
`gte` at the baseline so a run of exactly three does not fall through (F6). Both correlations use
the same figure deliberately: a different threshold on each would let the earlier, more valuable
one stay silent while the later one fired.

## Response levers

**MITRE:** **`T1485` — Data
Destruction (Impact)**, verified live 2026-08-29, lists IaaS and covers cloud-resource deletion
in its own words. Full reasoning in `../../route53.stealth.dns-zone-deleted/detections/detection_note_t1485.md`.

**Severity:** **Critical.** The single-zone case is High; volume raises it because the recovery cost is per
zone, needs a second party per zone, and runs against a window AWS itself describes as
hijackable. The source rates it P2.

**GuardDuty:** no finding type covers Route 53 **configuration** changes. Route 53 Resolver DNS query logs are a GuardDuty data source, but they drive EC2 DNS findings such as `Trojan:EC2/DNSDataExfiltration` and `Backdoor:EC2/C&CActivity.B!DNS` — about what instances resolve, not about who edited a zone. This technique produces no GuardDuty signal.

**Files here:**

- `sigma_t1485.yml` — four documents, correlation-first because no single event can express
  volume: a `value_count` correlation on distinct zone IDs at `critical`; its `informational`
  base rule (success-filtered, pipeline-allowlisted); an `informational` base rule for the record
  purge; and a `value_count` correlation on distinct purged zones at `high`, which is the same
  sweep observed earlier, while everything is still recoverable.
- `kql_t1485.kql` — builds the **ordered restoration queue**, flags every zone that needs a
  registrar change, counts the zones that cannot be named from CloudTrail at all, and counts the
  purge batches CloudTrail omitted above 100 KB.

Sibling notes: `../../route53.stealth.dns-zone-deleted/detections/` owns the field shape, the
region trap and the error sets for this observable.
`../../route53.stealth.ns-record-created-or-updated/detections/` owns the delegation half
of the hijack risk.

Full response procedure is in `../PLAYBOOK.md`.
