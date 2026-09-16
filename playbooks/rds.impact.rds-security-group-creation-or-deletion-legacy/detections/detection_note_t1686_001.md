# Detection Note — T1686.001 (Disable or Modify System Firewall: Cloud Firewall)

**Signal:** a database's network exposure changed — in two halves that share a name and almost nothing else. The retired EC2-Classic **DB
security group** APIs being called at all, and `ModifyDBInstance`/`ModifyDBCluster` replacing the
set of **VPC security groups** on a live database — which is what the retired APIs used to do and
what the source rule was reaching for.

## The source rule, as written, cannot fire

It matches `CreateDBSecurityGroup` or `DeleteDBSecurityGroup` **and requires the absence of an
error code**. DB security groups are an EC2-Classic construct, and AWS carries the same note
verbatim on `CreateDBSecurityGroup`, `DeleteDBSecurityGroup`, `DescribeDBSecurityGroups`,
`AuthorizeDBSecurityGroupIngress` and the CloudFormation resource:

> *"A DB security group controls access to EC2-Classic DB instances that are not in a VPC."*
> *"**EC2-Classic was retired on August 15, 2022.**"*

`CreateDBSecurityGroup` documents the error **`DBSecurityGroupNotSupported`** — *"A DB security
group isn't allowed for this action"*, HTTP 400 — which is what it returns in a VPC-only account,
and every account created since the retirement is VPC-only. So the rule's success filter excludes
the only outcome the API can produce. `DeleteDBSecurityGroup` is worse still: it can only succeed
against a DB security group that exists, and none can be created.

Two further confirmations that the construct is gone rather than merely discouraged.
`CreateDBInstance`'s own `DBSecurityGroups` parameter reads *"This setting applies to the legacy
EC2-Classic platform, which is no longer used to create new DB instances. **Use the
`VpcSecurityGroupIds` setting instead.**"* And the RDS User Guide's "Controlling access with
security groups" page is now exclusively about VPC security groups — DB security groups are not
mentioned there as a mechanism at all. Only the API reference retains them.

**What could not be verified**, stated rather than assumed: AWS publishes no sentence saying the
operation *always* fails now, and this analysis had no AWS account in which to test a 2026 call. It
is possible that an account with a surviving EC2-Classic estate still succeeds. The shipped rules
are therefore written to fire on the **call** rather than on its success, which is correct under
either reading and is the stronger detection in both.

## So the rule is inverted, not deleted

In an account with no EC2-Classic estate, a `CreateDBSecurityGroup` call in 2026 is worth seeing
**precisely because nothing legitimate emits it**. It is stale tooling, a script copied from a
blog post written before 2022, or an actor walking the API reference looking for something
unmonitored. The failure is the signal. Rule 1 in `sigma_t1686_001.yml` matches the call and not
the outcome, and its bare `condition: selection` carries the `# justified:` comment the validator
requires, because adding a success filter is exactly the defect being corrected.

If a call *succeeds*, the finding is larger and different: this account has a surviving EC2-Classic
estate, more than four years after retirement, and the DB instances behind those security groups
are not in a VPC.

## The observable the source rule was reaching for

Today the firewall in front of a database is changed in two places, and the source set covers
neither.

**`ModifyDBInstance` / `ModifyDBCluster` with `vpcSecurityGroupIds`.** This is the direct successor
and it carries a trap: **the parameter is the complete new set, not a delta.** The groups it does
not name are the groups being detached. A call that quietly drops the restrictive group looks, in
the raw event, exactly like a call that adds one — the removal is invisible except by comparison
with prior state. `kql_t1686_001.kql` carries the previous set forward per database with `prev()`
to make the removal visible, guarded on the database identifier so the first change to each
database is not compared against an unrelated one.

**`ec2:AuthorizeSecurityGroupIngress` on a group attached to a database.** That is the other half
and it is owned by `../../_superseded/aws.initial-access.sg-remote-management-open/`, which handles port-RANGE
containment and the nested `ipPermissions.items[]` request form properly. It is not duplicated here.

## Field shape

`eventSource` `rds.amazonaws.com`, **management** plane, regional.

Legacy: `requestParameters.dBSecurityGroupName`; the authorize and revoke calls add
`cIDRIP`, `eC2SecurityGroupName`, `eC2SecurityGroupId` and `eC2SecurityGroupOwnerId`. **Note the
leading-acronym lowercasing** — `cIDRIP`, not `cidrIp`, and `eC2SecurityGroupId`, not
`ec2SecurityGroupId`. This is the same irregular convention that produces `cACertificateIdentifier`
and `iAMDatabaseAuthenticationEnabled` in the `CreateDBInstance` sample event. Do not derive these
from a rule; they are not derivable.

Modern: `requestParameters.vpcSecurityGroupIds` is an **array** and is the complete replacement set.
`responseElements` for `ModifyDBInstance` is flat and carries the resulting
`vpcSecurityGroups[].vpcSecurityGroupId` — but note that `ModifyDBInstance` is asynchronous, so
read the response as the state at call time rather than as the outcome.

## Error strings

`CreateDBSecurityGroup`: `DBSecurityGroupAlreadyExists` (400), `QuotaExceeded.DBSecurityGroup`
(400), **`DBSecurityGroupNotSupported`** (400). That last one is the whole story of this use case.
`DeleteDBSecurityGroup`: `InvalidDBSecurityGroupState` (400), `DBSecurityGroupNotFound` (404).
`AuthorizeDBSecurityGroupIngress`: `DBSecurityGroupNotFound`, `InvalidDBSecurityGroupState`,
`AuthorizationAlreadyExists`, `AuthorizationQuotaExceeded`.
`RevokeDBSecurityGroupIngress`: `DBSecurityGroupNotFound`, `AuthorizationNotFound`,
`InvalidDBSecurityGroupState`.
`DescribeDBSecurityGroups`: `DBSecurityGroupNotFound`.

For the modern half, `ModifyDBInstance`'s relevant codes are `InvalidDBSecurityGroupState`,
`DBSecurityGroupNotFound`, `InvalidDBInstanceState`, `InvalidVPCNetworkStateFault` and
`DBInstanceNotFound`; the full list is in
`../../rds.exfiltration.database-instancecluster-made-public/detections/detection_note_t1578_005.md`.

Denials: `AccessDeniedException` (403) and `NotAuthorized` (401). The bare `AccessDenied` form is
not documented for RDS, and `Client.UnauthorizedOperation` is EC2's. CloudTrail carries the **wire**
code, not the SDK shape name, and RDS is irregular about the `Fault` suffix.

## GuardDuty and posture controls

**No GuardDuty coverage** for either half — there is no `Policy:RDS/*` finding namespace, and the
nine RDS finding types are login-behaviour detectors. Trusted Advisor still ships an *Amazon RDS
Security Group Access Risk* check, but it is scoped to the EC2-Classic construct and is
correspondingly obsolete.

No AWS Config managed rule evaluates a database's security-group **set**. The nearest coverage is
`rds-instance-public-access-check` and `rds-instance-subnet-igw-check`, which evaluate the exposure
a group change can produce rather than the change itself.

## Response levers

For the legacy half there is nothing to remediate: the resource type cannot exist in a VPC-only
account. The response is to find and fix whatever is emitting the calls, and — if any call
*succeeded* — to treat the surviving EC2-Classic estate as the incident.

For the modern half, put the original group set back with `modify-db-instance
--vpc-security-group-ids` naming the **full intended set**, because the parameter replaces rather
than merges. Read the removed group's rules before concluding whether the change opened or closed
anything.

## MITRE mapping

**T1686.001 — Disable or Modify System Firewall: Cloud Firewall**, under the **Defense Impairment**
tactic, is the primary mapping, and it is the same ID the corpus already uses in
`../../_superseded/aws.initial-access.sg-remote-management-open/`. **T1578.005 — Modify Cloud Compute
Configurations** is the genuine second mapping for the modern half, where the observable is a
configuration parameter on a database rather than a firewall rule.

The directory's `impact` segment tracks the source's tactic label rather than the corrected one;
the corrected tactic is Defense Impairment.

## Severity

**Medium** for a legacy API call, **High** if one succeeds, **High** for a non-pipeline replacement
of a live database's security groups, **High** for that across three or more databases in an hour.
The source rates the legacy rule P2, which over-rates a call that cannot change anything and
under-rates the successor observable it does not detect at all.

**MITRE:** Verified live 2026-08-30.

**GuardDuty:** RDS Protection exists but covers **login activity** only — `CredentialAccess:RDS/AnomalousBehavior.SuccessfulLogin`, `.FailedLogin`, `.SuccessfulBruteForce`, and the `MaliciousIPCaller` / `TorIPCaller` variants, on supported Aurora and RDS databases. No finding type covers RDS **configuration** changes, so a control-plane technique like this one produces no GuardDuty signal.

**Files here:**

- `sigma_t1686_001.yml` — five documents: the legacy-API rule at `medium` with a deliberately bare
  `condition: selection` and the `# justified:` comment explaining why a success filter would make
  it unfireable; an `informational` base rule for `DescribeDBSecurityGroups`; the modern
  `vpcSecurityGroupIds` replacement rule at `high`; a `temporal_ordered` correlation at `high` for
  enumerate-then-call against the retired APIs; and a `value_count` correlation at `high` for a
  fleet-wide group replacement.
- `kql_t1686_001.kql` — shows the security-group set **before and after** each modify by carrying
  the previous set forward per database, which is the only way a *removal* becomes visible in a
  parameter that is a complete replacement.

Sibling notes: `../../_superseded/aws.initial-access.sg-remote-management-open/detections/` owns rule-level
security-group changes on `ec2.amazonaws.com`, and
`../../rds.exfiltration.database-instancecluster-made-public/detections/` owns the addressing half
of RDS exposure, which is the other condition a reachable database needs.

Full response procedure is in `../PLAYBOOK.md`.
