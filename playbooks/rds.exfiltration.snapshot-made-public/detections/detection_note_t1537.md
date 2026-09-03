# Detection Note — T1537 (Transfer Data to Cloud Account)

**Signal:** a manual RDS snapshot's `restore` attribute gained a value — `all`, which makes a
full offline copy of the database restorable by every AWS account, or a 12-digit account ID,
which makes it restorable by one identified party.

**This is the only exposure in the RDS set where the data leaves your control entirely, and the
only one where you can never find out whether it was taken.** Every neighbour leaves the data
inside a resource you still own: a public instance is still your instance, an export still lands
in your bucket, an unencrypted database is still your database. A shared snapshot is a copy, and
AWS is explicit about the asymmetry — *"You can delete only the public snapshots that you own"*,
and *"You aren't billed for the backup storage of public snapshots owned by other accounts. If
you copy a public snapshot, you own the copy."* The copy is not in your bill, not in your trail,
and not reachable by any API you can call.

## What the original rule got wrong

**Its share-value clause names a field CloudTrail does not produce.** The third condition tests a
parser-derived field for the value `all`, not a CloudTrail path. Wherever that extraction is not
configured the clause matches nothing and the rule is dead — silently, and in the direction that
hides a public database snapshot. The real path is `requestParameters.valuesToAdd`, declared in
the API reference as an array of strings.

**`responseElements.attributeName` is not a path.** The operation returns
`DBSnapshotAttributesResult { DBSnapshotIdentifier, DBSnapshotAttributes[] { AttributeName,
AttributeValues[] } }`, so `attributeName` sits inside an array element and never at the top of
`responseElements`. A flat path yields null with no error. The response is worth reading — it
carries the **full post-change share list**, including accounts added by calls that have aged
out of CloudTrail retention — but only at its real depth.

**It treats `all` and a named account as the same thing, and covers only the first.** Public
means every AWS account on earth; a named account means one party you can call. Those are
different verdicts, different notification obligations and different eradication work-lists. The
shipped rules split them at `critical` and `high`, and the cross-account case — which the source
rule does not detect at all — is the more common real event.

## The evidence problem, stated precisely

There is **no event** when a foreign account consumes a shared snapshot. The RDS event catalogue
carries entries for snapshot creation (`RDS-EVENT-0040`, `0042`, `0090`, `0091`), deletion
(`0041`), local and cross-Region copy (`0059`, `0060`, `0061`, `0190`, `0196`, `0197`), export
(`0159`–`0161`, `0484`–`0488`) and restoration (`RDS-EVENT-0043`) — and none for an attribute
change or for third-party consumption. `RDS-EVENT-0043` fires in the account performing the
restore, against the instance created there. The consumer's `CopyDBSnapshot` or
`RestoreDBInstanceFromDBSnapshot` is recorded in **their** trail under **their**
`recipientAccountId`. `describe-db-snapshot-attributes` answers who is *authorised*, never who
*acted*.

**And the one cross-account breadcrumb that would exist does not exist in the public case.** For
an encrypted snapshot shared with a named account, the consumer must use the owner's KMS key,
which produces a `kms.amazonaws.com` event in the owner's trail — that is why a cross-account
share is sometimes traceable. But AWS refuses `all` on an encrypted snapshot: *"If the manual DB
snapshot is encrypted, it can be shared, but only by specifying a list of authorized AWS account
IDs for the `ValuesToAdd` parameter. You can't use `all` as a value for that parameter in this
case."* A public snapshot is therefore **unencrypted by construction**, there is no KMS call, and
there is no breadcrumb of any kind. The configuration that maximises exposure is exactly the one
that removes the only cross-account telemetry AWS would otherwise give you.

This is why the enumeration in `../PLAYBOOK.md` §2 must run **before** the revocation in §3. The
revoke empties the attribute list, and the identity of everyone who held restore rights goes with
it.

## Constraints that shape the chain, and therefore the correlation

- **Automated system snapshots cannot be shared.** *"To share an automated DB snapshot, create a
  manual DB snapshot by copying the automated snapshot, and then share that copy."*
- **A snapshot encrypted with the default `aws/rds` key cannot be shared at all**, in any form.
  The documented workaround is `CopyDBSnapshot --kms-key-id` under a customer-managed key.
- **`all` is refused on any encrypted snapshot**, so making a protected database public requires
  producing an unencrypted copy first.
- **A shared *and* encrypted snapshot cannot be restored directly** — *"you can make a copy of
  the DB snapshot and restore the DB instance from the copy"* — so the consumer's first act is a
  copy, which is what touches your KMS key.
- **20 recipient accounts per snapshot**, and **Multi-AZ DB cluster snapshots cannot be shared**.

Together these mean every route from a protected database to a shared snapshot passes through a
create or a copy. That is the `temporal_ordered` correlation in `sigma_t1537.yml`, and it is why
the 20-account cap pushes an actor seeking breadth to work across *snapshots* — which is what the
`value_count` correlation counts.

## Field shape

`eventSource` `rds.amazonaws.com`, **management** plane, regional. Instance variant:
`requestParameters.dBSnapshotIdentifier`; cluster variant:
`requestParameters.dBClusterSnapshotIdentifier`. Both carry `attributeName` (only documented
value: `restore`, lowercase — AWS declines to enumerate a closed set and defers to
`DescribeDBSnapshotAttributes`), `valuesToAdd` and `valuesToRemove`.

`valuesToAdd` is **declared** as an array of strings, which renders as a bare JSON list. AWS's own
sample request on the same page uses the `ValuesToAdd.member.N` wire form while the parameter is
named `ValuesToAdd.AttributeValue.N`, and **no published CloudTrail sample event exists for this
API**. Match on the *value* rather than on a fixed index path; the shipped rules and queries do,
and the KQL tries both response renderings rather than guessing one.

The same `dB` lower-camel convention applies as elsewhere in RDS, and it is not uniform — see
`../../rds.exfiltration.database-instancecluster-made-public/detections/detection_note_t1578_005.md`
for the irregulars (`dbiResourceId`, `cACertificateIdentifier`) that appear in the same events.

## Error strings

`ModifyDBSnapshotAttribute`: `DBSnapshotNotFound` (404), `InvalidDBSnapshotState` (400),
`SharedSnapshotQuotaExceeded` (400).
`ModifyDBClusterSnapshotAttribute`: `DBClusterSnapshotNotFoundFault` (404),
`InvalidDBClusterSnapshotStateFault` (400), `SharedSnapshotQuotaExceeded` (400).

Note the irregularity, which is AWS's and not a transcription error: the two cluster-specific
codes carry `Fault` while `SharedSnapshotQuotaExceeded` does not, on **both** the instance and
the cluster operation. CloudTrail carries the wire code, not the SDK shape name — so
`DBSnapshotNotFoundFault` matches nothing. Match on the stem.

Two of these are signals rather than noise. `SharedSnapshotQuotaExceeded` means the 20-account
cap was hit — an actor sharing at volume. `InvalidDBSnapshotState` on an `all` attempt is very
often AWS refusing to make an encrypted snapshot public, which is the control working and worth
seeing.

Denials: `AccessDeniedException` (403) and `NotAuthorized` (401). The bare `AccessDenied` form is
not documented for RDS.

## GuardDuty and posture controls

**GuardDuty does not detect this.** There is no `Policy:RDS/*` finding namespace; the `Policy:`
family covers S3, IAM users and Kubernetes. GuardDuty's nine RDS finding types are all
login-behaviour, and sharing a snapshot generates no login traffic, so nothing fires.

AWS Config `rds-snapshots-public-prohibited` (`RDS_SNAPSHOTS_PUBLIC_PROHIBITED`, resource types
`AWS::RDS::DBSnapshot` and `AWS::RDS::DBClusterSnapshot`) is the managed control and carries an
explicit warning that *"It can take up to 12 hours for compliance results to be captured"*. It is
also unavailable in six Regions. Security Hub control **RDS.1** aggregates it at Critical.
Trusted Advisor check **`rSs93HQwa1`** ("Amazon RDS Public Snapshots") refreshes several times
daily and cannot be refreshed on demand; AWS points at the SSM runbook
`AWSSupport-ModifyRDSSnapshotPermission` for remediation.

**CloudTrail on `ModifyDBSnapshotAttribute` is the only near-real-time path.** Everything else is
hours to half a day behind.

## Response levers

Enumerate before you revoke — the revoke destroys the recipient list. Then
`modify-db-snapshot-attribute --attribute-name restore --values-to-remove all`, then rotate every
credential the database held, then treat the data as disclosed. Deleting the snapshot does not
recall a copy; nothing does.

## MITRE mapping

The source labels this **T1526 / TA0010** — *Cloud Service Discovery* paired with the Exfiltration
tactic. T1526 is live but making a snapshot restorable by another account discovers nothing.

Corrected: **T1537 — Transfer Data to Cloud Account** (Exfiltration) as primary, which is the
technique whose own description covers transferring data to another cloud account on the same
service to avoid network-based exfiltration detection; and **T1578.001 — Create Snapshot**
(Defense Impairment) as a genuine second mapping for the create-or-copy half that AWS's own
sharing constraints force.

## Severity

**Critical** for `all`, **High** for a named account. The source rates both P2. Critical is right
for the public case because the data is disclosed to an unbounded, unidentifiable set and no
subsequent action can undo it — there is no containment, only notification. High is right for the
cross-account case because the recipient is nameable and can be asked, which is a materially
different incident even though the technical act is one parameter apart.

**MITRE:** the source maps this to `T1526 — Cloud Service Discovery`, which is reconnaissance and not what sharing a snapshot does. `T1537 — Transfer Data to Cloud Account` is the act: the data moves to an account the owner does not control. Verified live 2026-08-30.

**GuardDuty:** RDS Protection exists but covers **login activity** only — `CredentialAccess:RDS/AnomalousBehavior.SuccessfulLogin`, `.FailedLogin`, `.SuccessfulBruteForce`, and the `MaliciousIPCaller` / `TorIPCaller` variants, on supported Aurora and RDS databases. No finding type covers RDS **configuration** changes, so a control-plane technique like this one produces no GuardDuty signal.

**Files here:**

- `sigma_t1537.yml` — five documents: the public-share rule at `critical`; the cross-account
  rule at `high`, using Sigma's documented `field: null` absence semantics so it cannot match the
  **unshare** that is its own remediation; an `informational` base rule for snapshot create and
  copy; a `temporal_ordered` correlation at `critical` for create-then-share; and a `value_count`
  correlation at `critical` for a sweep across three or more snapshots in an hour.
- `kql_t1537.kql` — measures the **exposure window** by pairing each share with the later removal
  of the same value on the same snapshot, reads the cumulative share list from the response at
  its real depth, and keeps unshares out of the exposure count.

Sibling notes: `../../rds.stealth.database-instancecluster-was-created-with-no-encryption/detections/`
covers the precondition — a public snapshot is necessarily unencrypted — and
`../../rds.exfiltration.rds-snapshot-export/detections/` covers the other way a snapshot's
contents leave, which lands in S3 rather than in someone else's account.

Full response procedure is in `../PLAYBOOK.md`.
