# Detection Note — T1578.002 (Modify Cloud Compute Infrastructure: Create Cloud Instance)

**Signal:** a DB instance, cluster or global cluster was created or restored into an unencrypted
state — by an explicit `storageEncrypted: false`, or by omitting the parameter and taking AWS's
documented unencrypted default.

**This is a precondition, not an event, and that is what makes it worth alerting on.** Nothing has
been attacked when this fires. What has happened is that a database now exists from which a
**publicly shareable snapshot** can be produced, and AWS's own rules make that a hard ladder rather
than a spectrum:

| State of the database | What can be done with its snapshot |
|---|---|
| Unencrypted | Shared with **`all`** — every AWS account can restore a full copy |
| Encrypted, customer-managed key | Shared with **named accounts only**; `all` is refused |
| Encrypted, default `aws/rds` key | **Cannot be shared at all**, in any form |

*"If the manual DB snapshot is encrypted, it can be shared, but only by specifying a list of
authorized AWS account IDs for the `ValuesToAdd` parameter. You can't use `all` as a value for that
parameter in this case."* Encryption at rest is therefore the control that makes
`../../rds.exfiltration.snapshot-made-public/` **impossible** rather than merely detectable — and
the reason the two playbooks cross-reference each other rather than being merged.

## What the original rule got wrong

**Five of its seven event names cannot match on the request arm.** `StorageEncrypted` is a request
parameter of exactly five RDS operations: `CreateDBInstance`, `CreateDBCluster`,
`CreateGlobalCluster`, `RestoreDBInstanceFromS3` and `RestoreDBClusterFromS3`. It is absent from
every restore-from-snapshot and point-in-time API and from `CreateDBInstanceReadReplica`, because
those **inherit** encryption from their source and there is nothing to set. The source rule lists
five such APIs and tests the request parameter on all of them. Its response arm is what keeps the
rule alive — which is correct, and is the arm the shipped rule builds on.

**Two names that do accept the parameter are missing**, `RestoreDBInstanceFromS3` and
`RestoreDBClusterFromS3`, along with `CreateGlobalCluster`.

**It tests for the literal `"false"`, and the ordinary case is an omission.** AWS documents
`CreateDBInstance` as *"Specifes whether the DB instance is encrypted. **By default, it isn't
encrypted.**"* (the typo is AWS's). Most unencrypted databases are produced by a template that
never mentioned the field, not by an engineer who turned it off. Those are different findings with
different owners, and only `kql_t1578_002.kql` distinguishes them.

**Nothing accounts for the Aurora amplifier.** *"This setting doesn't apply to Amazon Aurora DB
instances. The encryption for DB instances is managed by the DB cluster."* An unencrypted
three-node Aurora cluster produces **four** matching events — one `CreateDBCluster` and three
`CreateDBInstance` — for a single control failure. A per-event alert count reads that as four
incidents; the shipped `value_count` correlation counts distinct database identifiers for exactly
this reason.

## Field shape

`eventSource` `rds.amazonaws.com`, **management** plane, regional. `responseElements` is **flat** —
AWS's published CloudTrail sample event for `CreateDBInstance` carries `"storageEncrypted": false`
at the top level with no `DBInstance` wrapper, alongside `"publiclyAccessible": true` and a
`dBSubnetGroup` object.

**The snapshot data types name the same idea differently.** `DBSnapshot` exposes `Encrypted`;
`DBClusterSnapshot` exposes `StorageEncrypted`. A sweep written against one shape returns null
against the other, and null is not `false` — it is a field that does not exist there.

The `dB` lower-camel convention and its irregulars are shared with the rest of the RDS set; see
`../../rds.exfiltration.database-instancecluster-made-public/detections/detection_note_t1578_005.md`.

## Why the remediation is the interesting part

**Encryption cannot be enabled in place.** AWS states it four ways on one page:

> *"You can only encrypt an Amazon RDS DB instance when you create it, not after the DB instance is
> created."* · *"You can't turn off encryption on an encrypted DB instance."* · *"You can't create
> an encrypted snapshot of an unencrypted DB instance."* · *"You can't restore an unencrypted
> backup or snapshot to an encrypted DB instance."* · *"Once you have created an encrypted DB
> instance, you can't change the KMS key used by that DB instance."*

Structural corroboration: `ModifyDBInstance` has **no `StorageEncrypted` request parameter at all**.
The API cannot express the operation.

The documented path is therefore three calls — `CreateDBSnapshot`, then `CopyDBSnapshot` with
`--kms-key-id` (*"If you specify this parameter when you copy an unencrypted snapshot, the copy is
encrypted"*), then `RestoreDBInstanceFromDBSnapshot` from the encrypted copy. The third one is
where the cost lands: *"You can't restore from a DB snapshot to an existing DB instance; you create
a new DB instance when you restore the snapshot."* A new instance means a **new endpoint**, a
connection-string change in every client, and a cutover window. **Say that out loud in the incident
record** — a remediation described as a configuration change and delivered as an outage is how
remediation gets deferred indefinitely.

Two traps on that path, both documented: the restored instance takes the **default** VPC security
group, DB subnet group, parameter group and option group unless each is passed explicitly, so a
naive restore silently drops the hardening; and copying a snapshot under a KMS key needs
`kms:DescribeKey`, `kms:CreateGrant`, `kms:Decrypt`, `kms:Encrypt`, `kms:GenerateDataKey`,
`kms:GenerateDataKeyWithoutPlaintext` and `kms:ReEncrypt`.

## Response levers

**Error strings:** `CreateDBInstance`, complete: `AuthorizationNotFound`, `BackupPolicyNotFoundFault`,
`CertificateNotFound`, `DBClusterNotFoundFault`, `DBInstanceAlreadyExists`,
`DBParameterGroupNotFound`, `DBSecurityGroupNotFound`, `DBSubnetGroupDoesNotCoverEnoughAZs`,
`DBSubnetGroupNotFoundFault`, `DomainNotFoundFault`, `InstanceQuotaExceeded`,
`InsufficientDBInstanceCapacity`, `InvalidDBClusterStateFault`, `InvalidSubnet`,
`InvalidVPCNetworkStateFault`, `KMSKeyNotAccessibleFault`, `NetworkTypeNotSupported`,
`OptionGroupNotFoundFault`, `ProvisionedIopsNotAvailableInAZFault`, `StorageQuotaExceeded`,
`StorageTypeNotSupported`, `TenantDatabaseQuotaExceeded`, `VpcEncryptionControlViolation`.

`CopyDBSnapshot`, which the remediation depends on: `DBSnapshotAlreadyExists`,
`DBSnapshotNotFound`, `InvalidDBSnapshotState`, `SnapshotQuotaExceeded`, `KMSKeyNotAccessibleFault`,
`CustomAvailabilityZoneNotFound`.

`KMSKeyNotAccessibleFault` is the one to watch during remediation: it is what a copy returns when
the key policy does not admit RDS, and it is the most common reason an encryption migration stalls
half-finished with an unencrypted original still serving traffic.

Denials: `AccessDeniedException` (403) and `NotAuthorized` (401). The bare `AccessDenied` form is
not documented for RDS. CloudTrail carries the **wire** code, not the SDK shape name — RDS is
irregular about the `Fault` suffix and the stem is the reliable part.

**GuardDuty and posture controls:** **No GuardDuty coverage.** There is no `Policy:RDS/*` finding namespace and the nine RDS finding
types are login-behaviour detectors.

AWS Config `rds-storage-encrypted` (`RDS_STORAGE_ENCRYPTED`, with an optional `kmsKeyId` parameter)
and `rds-cluster-encrypted-at-rest` (`RDS_CLUSTER_ENCRYPTED_AT_REST`) evaluate the state, and
`rds-snapshot-encrypted` covers snapshots. `rds-storage-encrypted` supports **proactive** mode —
evaluating a resource before it is provisioned — and that is the only form of this control that
genuinely helps, because the setting cannot be changed after creation. A reactive rule tells you
about an outage you now have to schedule.

**Severity:** **Medium** for a single unencrypted database, **High** for three or more from one principal in a
day, **Critical** where a snapshot of an unencrypted database has been shared out. The source rates
it P2. Medium is right for one: nothing is compromised, and a rule that pages on a posture finding
gets muted before the correlation that matters arrives. High for the fan-out because that is a
template defect and the fix is one code change, not three migrations. Critical for the chain
because at that point the ladder above has been walked all the way down.

**MITRE:** **T1578.002 — Create Cloud Instance** (Defense Impairment) as primary — the observable
is the creation of a cloud database provisioned without a control that would otherwise constrain an
adversary — with **T1537 — Transfer Data to Cloud Account** (Exfiltration) as a genuine second
mapping for the enabling relationship set out at the top of this note.

Stated plainly because the honest answer belongs in the record: **ATT&CK has no technique for
"provisioned without encryption at rest."** T1600 (*Weaken Encryption*) is live but scoped to
network devices. The pair above is the closest defensible mapping and it is carried for what the
absence *enables*, not for what the act *is*.

**GuardDuty:** RDS Protection exists but covers **login activity** only — `CredentialAccess:RDS/AnomalousBehavior.SuccessfulLogin`, `.FailedLogin`, `.SuccessfulBruteForce`, and the `MaliciousIPCaller` / `TorIPCaller` variants, on supported Aurora and RDS databases. No finding type covers RDS **configuration** changes, so a control-plane technique like this one produces no GuardDuty signal.

**Files here:**

- `sigma_t1578_002.yml` — four documents: the primary rule at `medium`, reading the **response**
  first because five of the source rule's APIs cannot carry the request parameter at all; an
  `informational` base rule for a snapshot being shared out; a `temporal_ordered` correlation at
  `critical` over seven days for create-unencrypted-then-share; and a `value_count` correlation at
  `high` counting **distinct database identifiers**, which is what stops an unencrypted Aurora
  cluster reaching the threshold on its own members.
- `kql_t1578_002.kql` — separates "explicitly false" from "never mentioned", flags Aurora member
  instances as repetitions rather than findings, and joins an unencrypted database to a later share
  of its own snapshot **through the snapshot's source instance** rather than through the principal.

Sibling notes: `../../rds.exfiltration.snapshot-made-public/detections/` is the outcome this
prevents, and `../../rds.exfiltration.database-instancecluster-made-public/detections/` covers the
other parameter on the same create calls.

Full response procedure is in `../PLAYBOOK.md`.
