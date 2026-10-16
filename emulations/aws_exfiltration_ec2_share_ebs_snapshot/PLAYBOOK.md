# IR Playbook: EBS Snapshot Shared With an External Account — `ec2:ModifySnapshotAttribute` and `createVolumePermission`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data exfiltration (a point-in-time copy of a disk is made restorable by an account outside this one) |
| Threat Actor | N/A — single technique, not actor-attributed (Stratus Red Team `aws.exfiltration.ec2-share-ebs-snapshot`) |
| Platform | aws |
| Severity | High for a named external account; Critical for `group: all`, and Critical for any share followed by `SharedSnapshotCopyInitiated` or `SharedSnapshotVolumeCreated` — the recipient has taken the data |
| MITRE Tactics | Exfiltration |
| MITRE Techniques | T1537 (primary); T1578.001 (the create-or-copy that usually precedes it) |
| Services in Scope | EBS (snapshots), EC2, KMS, IAM, STS, CloudTrail, AWS Config |

**What the technique does:** the actor calls `ec2:ModifySnapshotAttribute` with
`Attribute=createVolumePermission` and `CreateVolumePermission.Add` naming an account ID (or
`group: all`). The recipient can then `CopySnapshot` it into their account or create a volume from
it, attach the volume to an instance they own, and read the whole disk. No data moves in this
account and nothing changes on the disk.

**How this emulation runs it.** The stack creates a 1 GiB lab volume and a snapshot of it — there is
no tenant data in either. The connected role assumes `stratus-red-team-share-snapshot-attacker-role`
(session `atomic-t1537-share-snapshot`), which may call `ec2:ModifySnapshotAttribute` on that one
snapshot ARN and `ec2:DescribeSnapshotAttribute` (no resource-level scoping). It adds
`createVolumePermission` for `193672423079`, the Stratus Red Team dummy account, reads it back,
waits 15 seconds and removes it. **If the tenant has EBS encryption by default with the AWS-managed
`aws/ebs` key, the lab snapshot is encrypted with that key and AWS refuses the share** — AWS states
that snapshots encrypted with the default AWS managed key cannot be shared. The run reports the
refusal, skips the revert, and the refused `ModifySnapshotAttribute` is still logged. Events:
`AssumeRole`, `ModifySnapshotAttribute` (add, possibly refused), `DescribeSnapshotAttribute`,
`ModifySnapshotAttribute` (remove, only if the add succeeded).

**Why the usual reflexes miss it.** Like every snapshot share, there is no network egress to see and
the call looks like a backup or DR operation. Block public access for snapshots refuses only public
sharing. What sets EBS apart — and what most playbooks miss — is that **AWS does record consumption
in the owner's account**: `SharedSnapshotCopyInitiated` when a recipient copies the shared snapshot
and `SharedSnapshotVolumeCreated` when it creates a volume from it. Those events answer the question
that is unanswerable for shared AMIs and RDS snapshots.

**Detection thesis:** alert on `ModifySnapshotAttribute` with `createVolumePermission.add` naming a
recipient outside the allowlist — any outcome, because the most common outcome in a well-run
account is a refusal — at Critical for `group: all`. Escalate on a consumption event for the same
snapshot. Ignore `createVolumePermission.remove`, which is the remediation.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- `ModifySnapshotAttribute`, `DescribeSnapshotAttribute`, `CreateSnapshot`, `CopySnapshot`,
  `SharedSnapshotCopyInitiated` and `SharedSnapshotVolumeCreated` are EC2 **management**-plane
  records in the snapshot's Region, visible in Event history for 90 days.
- Request shape: `requestParameters.snapshotId`, `requestParameters.attributeType`
  (`CREATE_VOLUME_PERMISSION`), `requestParameters.createVolumePermission.add.items[]` /
  `.remove.items[]` with `userId` or `group`.
- **EBS encryption by default with a customer-managed key whose policy trusts no foreign account.**
  A recipient cannot use a snapshot it cannot decrypt, and with the AWS-managed key the share is
  refused outright.

**Alerting (must be pre-configured)**
- **Share to `group: all` → P0. Consumption event on a snapshot shared outside the allowlist → P0.**
- **Share to an unlisted account, any outcome → P1.**
- **`CreateSnapshot`/`CopySnapshot` then an unlisted share by one principal within 1h → P1.**

**Response Tooling**
- Break-glass credentials with `ec2:DescribeSnapshots`, `DescribeSnapshotAttribute`,
  `ModifySnapshotAttribute`, `cloudtrail:LookupEvents`, `iam:PutRolePolicy`.
- The allowlist of legitimate recipients (organization accounts, backup/DR accounts) as data.

**Known IOC Baselines**
- Which principals share snapshots (usually AWS Backup or one DR role) and to which accounts.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ModifySnapshotAttribute` adding `group: all` | CloudTrail (management) | T1537 |
| P0 | `SharedSnapshotCopyInitiated` / `SharedSnapshotVolumeCreated` on a snapshot shared outside the allowlist | CloudTrail (owner account) | T1537 |
| P1 | `ModifySnapshotAttribute` adding an unlisted `userId`, any outcome | CloudTrail (management) | T1537 |
| P1 | `CreateSnapshot`/`CopySnapshot` then an unlisted share by the same principal within 1h | CloudTrail, correlation | T1537, T1578.001 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `CopySnapshot` with a `kmsKeyId` different from the source, by a principal outside the backup process — the re-encryption that makes a default-key snapshot shareable | CloudTrail (management) | T1578.001 |
| P2 | `kms:PutKeyPolicy` / `CreateGrant` adding a foreign account to a key that encrypts snapshots | CloudTrail (KMS) | T1537 |
| P3 | AWS Config `ebs-snapshot-public-restorable-check` NON_COMPLIANT | AWS Config | T1537 |

### Detection Rule Quality Notes

| Issue | Impact | Correction |
|-------|--------|-----------|
| The generated rule matched the substring `"createVolumePermission":{"add"` | Serialisation-dependent; never matched in the in-process evaluator | Address `requestParameters.createVolumePermission.add` and `.items` directly |
| Public and named shares were one rule | Different incidents at one level | Split into critical (public) and high (named, with allowlist) |
| No consumption signal | The one EBS-specific answer to "was it used?" was unused | Third document on `SharedSnapshotCopyInitiated` / `SharedSnapshotVolumeCreated`; KQL joins it per snapshot |
| A success filter would hide the common case | Default-key refusals are the emulation's usual outcome | No `errorCode` filter on any share rule |

### Key Investigation Queries

> EBS is regional: run these in the snapshot's Region.

#### Query 1 — Every snapshot permission change in the last 30 days

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifySnapshotAttribute \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,Username,CloudTrailEvent]' --output json
```

Read `requestParameters.snapshotId`, `createVolumePermission.add.items[]` and `.remove.items[]`,
`userIdentity.arn`, `sourceIPAddress`, `errorCode` and `errorMessage`. An `errorMessage` about the
default AWS managed key means the share was refused — the snapshot is safe, the principal is not.

#### Query 2 — Was a shared snapshot used?

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SharedSnapshotCopyInitiated \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,CloudTrailEvent]' --output json
```

Repeat with `AttributeValue=SharedSnapshotVolumeCreated`. A hit on a snapshot from Query 1 means
the recipient has the data: the acting account in the event is the recipient's, and this account
appears as `recipientAccountId`. Absence over the exposure window is meaningful evidence here —
unlike for AMIs — but only for the window your trail and Event history cover.

#### Query 3 — Who can create volumes from the snapshot right now (capture before revoking)

```bash
SNAP="<snapshot_id>"
aws ec2 describe-snapshot-attribute --snapshot-id "$SNAP" --attribute createVolumePermission > snapshot-permissions-$SNAP.json
cat snapshot-permissions-$SNAP.json
```

The authoritative recipient list, including grants older than your retention. The revoke destroys
it.

#### Query 4 — Every snapshot this account owns that is shared

```bash
aws ec2 describe-snapshots --owner-ids self \
  --query 'Snapshots[].[SnapshotId,VolumeId,StartTime,Encrypted,KmsKeyId]' --output table
```

Run Query 3 for each; any recipient outside the allowlist is in scope. Snapshots that are public
also appear under `aws ec2 describe-snapshots --restorable-by-user-ids all --owner-ids self`.

#### Query 5 — The principal's session

```bash
SESSION="<session-name-or-user-from-Query-1>"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION" \
  --start-time "$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,EventSource,EventName]' --output table
```

Look for `CreateSnapshot`/`CopySnapshot` before the share (and a `kmsKeyId` change on the copy),
`ModifyImageAttribute` (the AMI sibling), and KMS key-policy changes.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

> Query 3 must have been captured to disk before Step 1.

#### Step 1 — Revoke every unlisted recipient

```bash
SNAP="<snapshot_id>"; RECIPIENT="<account-id-from-Query-3>"
aws ec2 modify-snapshot-attribute --snapshot-id "$SNAP" --attribute createVolumePermission \
  --operation-type remove --user-ids "$RECIPIENT"
aws ec2 describe-snapshot-attribute --snapshot-id "$SNAP" --attribute createVolumePermission
```

For a public snapshot use `--group-names all`. Confirm the list is empty or allowlist-only.

#### Step 2 — Contain the principal

```bash
ROLE="<role-name-from-Query-1>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyDenySharing \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ec2:ModifySnapshotAttribute","ec2:ModifyImageAttribute","ec2:CopySnapshot","ec2:CreateSnapshot","kms:CreateGrant","kms:PutKeyPolicy"],"Resource":"*"}]}'
```

#### Step 3 — If Query 2 found consumption

The recipient holds a copy you cannot recall. If the snapshot is encrypted with your
customer-managed key and the recipient was granted use of it, revoke that grant and remove the
account from the key policy: a copy re-encrypted under their own key is beyond reach, but a volume
still using your key stops working. Then rotate every secret that lived on the disk.

---

## 4. Eradication

### Remove Attacker Access

- Trace the session to its source identity and contain it; separate snapshot creation (backup)
  from `ec2:ModifySnapshotAttribute` (sharing) in IAM.

### Prevent recurrence

- Enable **Block public access for snapshots** in `block-all-sharing` mode in every Region.
- The guardrail catalogue's **`data_perimeter_governance_scp`** lists `ec2:ModifySnapshotAttribute`
  in `PreventExternalResourceShare` (conditional data-perimeter control — adapt its conditions).
- EBS encryption by default with a customer-managed key whose policy trusts only your organization.

### Remove the emergency policies once clean

```bash
ROLE="<role-name-from-Query-1>"
aws iam delete-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions
aws iam delete-role-policy --role-name "$ROLE" --policy-name EmergencyDenySharing
aws iam list-role-policies --role-name "$ROLE"
```

---

## 5. Recovery

### Restore Clean State

#### Confirm nothing is shared outside the allowlist

```bash
aws ec2 describe-snapshots --owner-ids self --restorable-by-user-ids all --query 'Snapshots[].SnapshotId'
```

Empty, and Query 3 on every snapshot from Query 4 shows only allowlisted recipients.

#### Confirm the corrected detection fires

```text
MUST fire on:     ModifySnapshotAttribute with createVolumePermission.add naming an unlisted
                  account, with or without errorCode -> high; group all -> critical.
                  SharedSnapshotCopyInitiated / SharedSnapshotVolumeCreated -> high.
MUST NOT fire on: createVolumePermission.remove (the unshare); DescribeSnapshotAttribute; a
                  share to an allowlisted backup account.
EXPECTED FP:      AWS Backup / DR copies - allowlist the destination accounts.
```

Running this emulation is the test: the add from session `atomic-t1537-share-snapshot` must fire
`ebs_snapshot_shared_cross_account` whether AWS accepted or refused it.

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A disk copy was offered to a foreign account in one call | `ec2:ModifySnapshotAttribute` granted with snapshot creation; no data-perimeter SCP |
| The share succeeded | Snapshot unencrypted or under a customer-managed key the recipient could use |
| Consumption was not checked | `SharedSnapshot*` events were not collected or not known |

### Recommended Guardrails

- **Catalogue match:** `data_perimeter_governance_scp` (`PreventExternalResourceShare`,
  conditional) lists `ec2:ModifySnapshotAttribute`.
- **Catalogue gap:** no catalogue policy prevents disabling Block public access for snapshots; it
  would protect only the public case and this emulation never calls it.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1537 — Transfer Data to Cloud Account; T1578.001 — Create Snapshot (preceding step) |
| Primary API | `ec2:ModifySnapshotAttribute`, `Attribute=createVolumePermission`, `Add` |
| Revert API | the same with `Remove` |
| Consumption events (owner account) | `SharedSnapshotCopyInitiated`, `SharedSnapshotVolumeCreated` |
| Key fields | `requestParameters.snapshotId`, `requestParameters.createVolumePermission.add.items[]` (`userId` / `group`) |
| Refusal to expect | Snapshots encrypted with the default AWS managed key cannot be shared |
| Lab identity | Role `stratus-red-team-share-snapshot-attacker-role`, session `atomic-t1537-share-snapshot`, recipient `193672423079` |

### Residual Risk

Revoking closes the window; it does not recall a copy. Absence of `SharedSnapshot*` events is good
evidence only for the period your logs cover; a share that predates retention has no consumption
record you can still read, and a recipient who already copied the snapshot under their own key
holds the disk permanently.
