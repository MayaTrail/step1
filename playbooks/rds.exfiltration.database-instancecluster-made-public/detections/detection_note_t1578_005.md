# Detection Note — T1578.005 (Modify Cloud Compute Configurations)

**Signal:** an RDS DB instance or Multi-AZ DB cluster entered a publicly accessible state —
by an explicit `publiclyAccessible` request parameter, or by the documented default-true
behaviour of a create that omits a DB subnet group or names the `default` one.

**The flag is not the exposure, and the exposure is not the flag.** Every neighbour of this
rule in the RDS set describes something that is finished when the event lands: a snapshot is
shared, an export has started, a database was created unencrypted. This one describes a
*precondition*. AWS is explicit: *"Access to the DB instance is ultimately controlled by the
security group it uses. That public access is not permitted if the security group assigned to
the DB instance doesn't include inbound rules that permit it. In addition, for a DB instance
to be publicly accessible, the subnets in its DB subnet group must have an internet gateway."*
A fourth condition sits one page away — the VPC needs DNS hostnames and DNS resolution on.
So a hit here is a trigger for a reachability walk, never a disposition. Rating it as a
compromise produces a P0 for a database nothing can reach; rating it as noise produces a
muted rule in an account where the security group has been open since 2021.

## What the original rule got wrong

Three defects, each verified against the RDS API reference rather than inferred.

**It reads only `requestParameters.publiclyAccessible`, and the most common real exposure has
no such parameter.** AWS: *"The default behavior when `PubliclyAccessible` is not specified
depends on whether a `DBSubnetGroup` is specified. If `DBSubnetGroup` isn't specified,
`PubliclyAccessible` defaults to false for Aurora instances and **true for non-Aurora
instances**. If `DBSubnetGroup` is specified, `PubliclyAccessible` defaults to false unless the
value of `DBSubnetGroup` is `default`, in which case `PubliclyAccessible` **defaults to
true**."* A `CreateDBInstance` for MySQL or PostgreSQL that omits the subnet group, or names
the default one, produces a public database from an event whose request parameters never
mention public access. AWS's own published CloudTrail sample event for `CreateDBInstance` is
precisely this shape: no `publiclyAccessible` in the request, `"publiclyAccessible": true` and
`"dBSubnetGroupName": "default"` in the response. The canonical example does not fire the
canonical rule.

**Two of its ten event names cannot match.** `ModifyDBCluster` has no `PubliclyAccessible`
request parameter — it is absent from that API's entire parameter list, and a cluster becomes
public at create time or through its member instances. `CreateDBClusterFromSnapshot` is not an
RDS API action at all; the real call, `RestoreDBClusterFromSnapshot`, is already in the same
list. Neither disjunct has ever contributed a match.

**It has no success filter.** Alone among the five RDS rules reviewed in this batch that
should carry one, it omits the error-code exclusion, so a refusal fires the same P2 as a
completed exposure. The shipped rules split them: successes at `high`, refusals at `medium` as
boundary mapping.

## Request versus response, and why both

`ModifyDBInstance` is asynchronous. The returned `DBInstance` object reflects state at the
time of the call, and `PendingModifiedValues` — checked member by member against the
`DBInstance` data type — does **not** carry `PubliclyAccessible`. So a modify that turns public
access on can return `publiclyAccessible: false` and record the intent only in the request.
Creates are the mirror image: the request may omit the field while the response states the
outcome. Neither field settles the question alone, and they never both settle it on one event,
so they are **sibling blocks ORed** in the condition. Two keys in one selection block would AND
them into a rule that fires on almost nothing — the failure this corpus has shipped before.

## Field shape

`eventSource` is `rds.amazonaws.com`; every RDS action is a **management** event, present in
Event history and returned by `lookup-events` with no trail configuration. The only RDS data
event type is `AWS::RDS::DBCluster`, covering RDS Data API activity, and it is off by default —
irrelevant here.

CloudTrail lower-camel-cases RDS API parameters and renders the `DB` prefix as `dB`:
`dBInstanceIdentifier`, `dBSubnetGroup`, `dBSecurityGroups`. **The convention is not uniform
inside a single event** — AWS's published sample carries `dbInstancePort`, `dbiResourceId`,
`cACertificateIdentifier` and `iAMDatabaseAuthenticationEnabled` alongside them. Read one real
event; do not derive a path from a rule.

`responseElements` is **flat**. The `DBInstance` wrapper the API reference shows does not appear
in the CloudTrail record, so the paths are `responseElements.publiclyAccessible`,
`responseElements.storageEncrypted`, `responseElements.dBInstanceArn`,
`responseElements.vpcSecurityGroups[].vpcSecurityGroupId` and
`responseElements.dBSubnetGroup.subnets[].subnetIdentifier`.

**`responseElements.endpoint` is absent on `CreateDBInstance`.** AWS: *"The endpoint might not
be shown for instances with the status of `creating`."* The published sample confirms it —
`"dBInstanceStatus": "creating"`, `"dbInstancePort": 0`, no `endpoint` object. Any rule, query
or IOC extraction that reads `responseElements.endpoint.address` from a create yields null.
Get the endpoint from a follow-up `describe-db-instances`.

One vocabulary warning: RDS **CLI output is PascalCase** (`PubliclyAccessible`,
`Endpoint.Address`) while **CloudTrail JSON is lower-camel** (`publiclyAccessible`). Two
spellings of one field; a path copied from one into the other silently returns nothing.

## Error strings

Denials: RDS documents **`AccessDeniedException`** (403) and **`NotAuthorized`** (401) in its
common-error list. The bare `AccessDenied` form is *not* documented for RDS, and
`Client.UnauthorizedOperation` is EC2's — match by substring so both real forms and any
prefixed variant hit.

`ModifyDBInstance` failure codes, complete: `AuthorizationNotFound`, `BackupPolicyNotFoundFault`,
`CertificateNotFound`, `DBInstanceAlreadyExists`, `DBInstanceNotFound`, `DBParameterGroupNotFound`,
`DBSecurityGroupNotFound`, `DBUpgradeDependencyFailure`, `DomainNotFoundFault`,
`InsufficientDBInstanceCapacity`, `InvalidDBClusterStateFault`, `InvalidDBInstanceState`,
`InvalidDBSecurityGroupState`, `InvalidVPCNetworkStateFault`, `KMSKeyNotAccessibleFault`,
`NetworkTypeNotSupported`, `OptionGroupNotFoundFault`, `ProvisionedIopsNotAvailableInAZFault`,
`StorageQuotaExceeded`, `StorageTypeNotSupported`, `TenantDatabaseQuotaExceeded`,
`VpcEncryptionControlViolation`. `CreateDBInstance` adds `DBSubnetGroupDoesNotCoverEnoughAZs`,
`DBSubnetGroupNotFoundFault`, `InstanceQuotaExceeded`, `InvalidSubnet` and `DBClusterNotFoundFault`,
and drops `DBInstanceNotFound`.

`InvalidVPCNetworkStateFault` is the one worth reading as a signal rather than as noise: AWS
returns an error when `PubliclyAccessible` is true and the VPC has no internet gateway
attached. A burst of it is somebody trying to expose a database in a VPC that will not let
them.

RDS's wire error codes are irregular — `DBInstanceNotFound` has no `Fault` suffix while
`InvalidVPCNetworkStateFault` and `KMSKeyNotAccessibleFault` do. CloudTrail carries the wire
form, not the SDK shape name. Match on the stem.

## GuardDuty and posture controls

**GuardDuty does not detect this.** There is no `Policy:RDS/*` finding namespace — the
`Policy:` family covers S3, IAM users and Kubernetes only. GuardDuty's nine RDS finding types
are all login-behaviour (`CredentialAccess:RDS/AnomalousBehavior.*`,
`CredentialAccess:RDS/MaliciousIPCaller.*`, `CredentialAccess:RDS/TorIPCaller.*`,
`Discovery:RDS/MaliciousIPCaller`, `Discovery:RDS/TorIPCaller`), and they fire on connections,
not on configuration. The two `Discovery:RDS/*` types are the closest indirect signal — their
own documentation says the activity *"may indicate that a potentially malicious actor is
attempting to scan for a publicly accessible infrastructure"* — but that is an inference drawn
after somebody has already found the database.

AWS Config `rds-instance-public-access-check` (`RDS_INSTANCE_PUBLIC_ACCESS_CHECK`) evaluates
the flag; `rds-instance-subnet-igw-check` (`RDS_INSTANCE_SUBNET_IGW_CHECK`, periodic) catches
the network-path half the first one misses. Deploy both — either alone answers half the
question. Security Hub control **RDS.2** aggregates the first at Critical.

## Response levers

Flip `publiclyAccessible` back with `modify-db-instance --no-publicly-accessible
--apply-immediately`, and revoke the ingress rule — in that order only if you have already
captured the security group's rules as evidence, because the revoke destroys them. Neither
step reaches anything that already connected: RDS connection attempts are not CloudTrail
events at any level, so the engine's own audit log published to CloudWatch Logs, and VPC flow
logs on the instance's ENI, are the only record that a session happened. If either was off,
"was it used" is unanswerable and must be written down as unknown.

## MITRE mapping

The source labels this **T1530 / TA0010** — *Data from Cloud Storage* paired with the
Exfiltration tactic. Both halves are wrong: T1530's scope is object storage (S3, Azure Storage,
GCS), not a relational engine reached over its native wire protocol, and T1530's own tactic is
Collection, so the pairing contradicts itself.

Corrected: **T1578.005 — Modify Cloud Compute Configurations** (Defense Impairment) as primary,
because that is exactly what changing `publiclyAccessible` is, and **T1133 — External Remote
Services** (Initial Access) as a genuine second mapping, because an internet-reachable database
endpoint is an external remote service. **T1686.001 — Cloud Firewall** covers the security-group
half and is carried on the correlation document rather than on the primary rule, which observes
no firewall change.

T1578 and T1578.005 sit under the **Defense Impairment** tactic.

## Severity

**High** for a non-pipeline change, not Critical. The source rates it P2. High is right because
the flag plus an already-open security group is a live internet-facing database and that is
common; Critical is wrong because the single event does not establish reachability and a rule
that cries Critical on a precondition gets muted. The correlation document, which requires both
halves from one principal inside an hour, is Critical — that one has earned it.

**MITRE:** the source maps this to `T1530 — Data from Cloud Storage`, which is about object stores rather than database endpoints. Making an instance publicly accessible is a configuration change: `T1578.005 — Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations`. Verified live 2026-08-30.

**GuardDuty:** RDS Protection exists but covers **login activity** only — `CredentialAccess:RDS/AnomalousBehavior.SuccessfulLogin`, `.FailedLogin`, `.SuccessfulBruteForce`, and the `MaliciousIPCaller` / `TorIPCaller` variants, on supported Aurora and RDS databases. No finding type covers RDS **configuration** changes, so a control-plane technique like this one produces no GuardDuty signal.

**Files here:**

- `sigma_t1578_005.yml` — four documents: the primary rule at `high` (request OR response,
  successes only, pipeline-allowlisted); a `medium` rule for refused attempts; an
  `informational` base rule for world-open EC2 ingress; and a `temporal` correlation at
  `critical` joining the addressing half to the firewall half by principal.
- `kql_t1578_005.kql` — separates the explicitly-requested case from the AWS-defaulted case,
  and joins the RDS event to the EC2 ingress event **on the security group ID** rather than on
  the principal, which is the join Sigma cannot express.

Sibling notes sharing traps: `../../rds.stealth.database-instancecluster-was-created-with-no-encryption/detections/`
carries the same `responseElements`-is-flat and `dB`-casing warnings for the encryption
parameter, and `../../_superseded/aws.initial-access.sg-remote-management-open/detections/` owns the
security-group side including port-range containment and the nested `ipPermissions.items[]`
request form.

Full response procedure is in `../PLAYBOOK.md`.
