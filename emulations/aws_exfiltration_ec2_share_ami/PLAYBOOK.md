# IR Playbook: AMI Shared With an External Account — `ec2:ModifyImageAttribute` Hands Over a Server's Disks

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data exfiltration (an Amazon Machine Image — a complete, launchable copy of one or more volumes — is made usable by an account outside this one) |
| Threat Actor | N/A — single technique, not actor-attributed (Stratus Red Team `aws.exfiltration.ec2-share-ami`) |
| Platform | aws |
| Severity | High for a named external account; Critical for `group: all` (public). The recipient can launch or copy the image in its own account, and a copy once taken cannot be recalled or observed |
| MITRE Tactics | Exfiltration |
| MITRE Techniques | T1537 |
| Services in Scope | EC2 (AMIs), EBS (snapshots behind the AMI), KMS, IAM, STS, CloudTrail |

**What the technique does:** the actor calls `ec2:ModifyImageAttribute` with
`LaunchPermission.Add` naming an account ID (or an organization / OU ARN, or `group: all`). One
call, no data movement in this account. From then on the recipient can run `RunInstances` or
`CopyImage` against the AMI in **their** account and read every byte of every volume it was built
from — application code, configuration files, credentials and keys baked into the image, cached
data. AMIs are frequently made from running servers (`CreateImage`), so the content is often a
production host's root volume.

**How this emulation runs it.** The stack builds a lab AMI, `stratus-red-team-share-ami-ami`, from a
snapshot of an **empty 1 GiB volume** — there is no tenant data in it. The connected role assumes
`stratus-red-team-share-ami-attacker-role` (session `atomic-t1537-share-ami`), whose policy allows
`ec2:ModifyImageAttribute` on that one image ARN and `ec2:DescribeImageAttribute` (which supports no
resource-level scoping). It adds launch permission for `193672423079` — the Stratus Red Team dummy
account also used by the RDS snapshot emulation — reads the permission back, waits 15 seconds, and
removes it from a `finally` block. If AWS refuses the share (an AMI whose snapshot is encrypted with
the default `aws/ebs` key cannot be shared), the run reports the error and the attempt is still
logged. Events: `AssumeRole`, `ModifyImageAttribute` (add), `DescribeImageAttribute`,
`ModifyImageAttribute` (remove).

**Why the usual reflexes miss it.** There is no egress: flow logs, DLP and S3 access logs see
nothing. The call is an ordinary `Modify*` in a service where `Modify*` is constant, and the
legitimate pattern — a golden-image pipeline sharing to sibling accounts — is identical apart from
the recipient. Block public access for AMIs, now on by default for most accounts, makes people
believe AMIs cannot leak; it refuses only `group: all` and does nothing about a named account. And
the recipient's use of the image produces **no event in this account** unless the AMI's snapshots
are encrypted with a customer-managed key, in which case their `CreateGrant`/`Decrypt` against your
key is the only breadcrumb.

**Detection thesis:** the recipient is the signal. Alert on `ModifyImageAttribute` whose
`launchPermission.add.items[]` names anything other than your own accounts, at Critical for
`group: all` and High otherwise, with no `errorCode` filter. Ignore `launchPermission.remove` —
that is the unshare, and the remediation of this very alert. Capture the full permission list
before revoking, because the revoke destroys it.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- `ModifyImageAttribute`, `DescribeImageAttribute`, `CreateImage`, `CopyImage` are EC2
  **management** events, regional, in Event history for 90 days.
- Request shape: `requestParameters.imageId`, `requestParameters.attributeType`
  (`launchPermission`), `requestParameters.launchPermission.add.items[]` /
  `.remove.items[]`, each item one of `userId`, `group`, `organizationArn`, `organizationalUnitArn`.
- **KMS events in the same trail.** For an AMI backed by snapshots under a customer-managed key, the
  recipient must use your key; that is the only cross-account consumption trace.

**Alerting (must be pre-configured)**
- **`ModifyImageAttribute` adding `group: all` → P0.**
- **`ModifyImageAttribute` adding any recipient not on the allowlist → P1.**
- **`CreateImage`/`CopyImage` then share by one principal within 1h → P1.**

**Response Tooling**
- Break-glass credentials with `ec2:DescribeImages`, `ec2:DescribeImageAttribute`,
  `ec2:ModifyImageAttribute`, `ec2:DescribeSnapshots`, `cloudtrail:LookupEvents`, `iam:PutRolePolicy`.
- The **allowlist of legitimate recipient accounts** (your organization's account IDs and
  organization ARN), kept as data.

**Known IOC Baselines**
- Which principals share AMIs (normally one image-pipeline role) and to whom.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ModifyImageAttribute` with `launchPermission.add.items[].group = all` | CloudTrail (management) | T1537 |
| P1 | `ModifyImageAttribute` adding a `userId` / `organizationArn` / `organizationalUnitArn` not on the allowlist, any outcome | CloudTrail (management) | T1537 |
| P1 | `CreateImage` or `CopyImage` then an unlisted share by the same principal within 1h | CloudTrail, correlation | T1537 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A refused `ModifyImageAttribute` add (block public access, default-key encryption) | CloudTrail (management) | T1537 |
| P2 | `DescribeImages --owners self` / `DescribeImageAttribute` burst from a principal outside the image pipeline | CloudTrail (management) | T1537 |
| P2 | `kms:CreateGrant` / `Decrypt` on an AMI snapshot key from a foreign account | CloudTrail (KMS) | T1537 |

### Detection Rule Quality Notes

| Issue | Impact | Correction |
|-------|--------|-----------|
| The generated rule matched the substring `"launchPermission":{"add"` on the flattened request | Serialisation-dependent; never matched in the in-process evaluator | Match `requestParameters.launchPermission.add` and its `items` directly |
| Public and named-account shares were one rule | Different blast radius and disclosure obligations at one level | `ami_shared_public` (critical) and `ami_shared_cross_account` (high, with allowlist) |
| Nothing distinguished share from unshare | The emulation's revert — and every remediation — would alert | Rules require `launchPermission.add`; the revert carries only `remove` |
| No sequence | Create-then-share, the deliberate shape, was not expressed | `ami_created_bb` plus a `temporal_ordered` correlation |

### Key Investigation Queries

> EC2 is regional: run these in the AMI's Region.

#### Query 1 — Every launch-permission change in the last 30 days

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyImageAttribute \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,Username,CloudTrailEvent]' --output json
```

For each event read `requestParameters.imageId`, `launchPermission.add.items[]` (the share),
`launchPermission.remove.items[]` (the unshare), `userIdentity.arn`, `sourceIPAddress` and
`errorCode`. Record every recipient value as an IOC. For this emulation expect an add and a remove
of `193672423079` 15 seconds apart from session `atomic-t1537-share-ami`.

#### Query 2 — Who can launch the image right now (capture before revoking)

```bash
AMI="<ami_id>"
aws ec2 describe-image-attribute --image-id "$AMI" --attribute launchPermission > launch-permissions-$AMI.json
cat launch-permissions-$AMI.json
```

This is the authoritative recipient list, including grants older than your CloudTrail retention.
Revoking destroys it, so keep the file with the incident record.

#### Query 3 — What is in the image

```bash
AMI="<ami_id>"
aws ec2 describe-images --image-ids "$AMI" \
  --query 'Images[].[Name,CreationDate,Public,BlockDeviceMappings[].Ebs.[SnapshotId,Encrypted,KmsKeyId]]'
```

Find the source instance from the `CreateImage` event that produced the AMI (search Query 1's
window with `AttributeValue=CreateImage`). The instance's role and workload tell you which secrets
the image may contain. `Encrypted: false`, or a customer-managed key the recipient was given access
to, means the recipient can read the volumes.

#### Query 4 — Every image owned by this account that is shared or public

```bash
aws ec2 describe-images --owners self --query 'Images[].[ImageId,Name,Public]' --output table
```

`Public: True` rows are P0. For the rest, run Query 2 on each image ID; any launch permission that
names an account outside the allowlist is in scope.

#### Query 5 — The principal's session

```bash
SESSION="<session-name-or-user-from-Query-1>"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION" \
  --start-time "$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,EventSource,EventName]' --output table
```

`CreateImage` or `CopyImage` before the share is the deliberate path. `ModifySnapshotAttribute` in
the same session is the sibling technique (see the EBS snapshot playbook), and
`kms:CreateGrant` or `PutKeyPolicy` on the snapshot key is the actor making an encrypted image
usable by the recipient.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

> Query 2 must have been captured to disk before Step 1.

#### Step 1 — Revoke every unlisted recipient

```bash
AMI="<ami_id>"; RECIPIENT="<account-id-from-Query-2>"
aws ec2 modify-image-attribute --image-id "$AMI" --launch-permission "Remove=[{UserId=$RECIPIENT}]"
aws ec2 describe-image-attribute --image-id "$AMI" --attribute launchPermission
```

For a public image: `--launch-permission "Remove=[{Group=all}]"`. For an organization or OU grant:
`--launch-permission "Remove=[{OrganizationArn=<arn>}]"`. Repeat for every recipient in the file
from Query 2 that is not on the allowlist, then confirm the list is empty or allowlist-only.

#### Step 2 — Contain the principal

```bash
ROLE="<role-name-from-Query-1>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyDenySharing \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ec2:ModifyImageAttribute","ec2:ModifySnapshotAttribute","ec2:CreateImage","ec2:CopyImage","kms:CreateGrant","kms:PutKeyPolicy"],"Resource":"*"}]}'
```

For an IAM user, deactivate its access keys and attach the same deny as a user policy.

#### Step 3 — Decide about the data

Revoking stops new launches and copies; it does not recall a copy already taken, and you will
not be told whether one was. Deregistering the AMI changes nothing for an existing copy either.
Rotate every credential, key and certificate that the source instance's disk held.

---

## 4. Eradication

### Remove Attacker Access

- Trace the session to its source identity and contain it.
- Remove `ec2:ModifyImageAttribute` from principals that do not run the image pipeline; separate
  `ec2:CreateImage` (backup) from sharing.

### Prevent recurrence

- Keep **Block public access for AMIs** enabled in every Region (`ec2 get-image-block-public-access-state`).
- The guardrail catalogue's **`data_perimeter_governance_scp`** includes
  `ec2:ModifyImageAttribute` in its `PreventExternalResourceShare` statement (conditional; it is a
  data-perimeter control you must adapt). The upstream SCP examples also include
  "Deny users from disabling block public access on AMIs", which protects the public case only.
- Encrypt AMI snapshots with customer-managed keys whose key policy does not trust foreign accounts:
  a shared AMI the recipient cannot decrypt is unusable to them.

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

#### Confirm no image is shared outside the allowlist

```bash
aws ec2 describe-images --owners self --query 'Images[?Public==`true`].[ImageId,Name]' --output table
```

Empty, then Query 2 for each image returns only allowlisted recipients.

#### Confirm the corrected detection fires

```text
MUST fire on:     ModifyImageAttribute with launchPermission.add naming an unlisted account,
                  organization or OU -> high; with group all -> critical; either with or
                  without errorCode.
MUST NOT fire on: launchPermission.remove (the unshare); description or other attribute
                  changes; DescribeImageAttribute; a share to an allowlisted account.
EXPECTED FP:      golden-image pipelines - allowlist the recipient accounts, not the rule.
```

Running this emulation is the test: the add from session `atomic-t1537-share-ami` must fire
`ami_shared_cross_account`; the remove 15 seconds later must not.

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A server image was handed to a foreign account in one call | `ec2:ModifyImageAttribute` held by a principal outside the image pipeline; no data-perimeter SCP |
| Block public access did not help | It applies only to `group: all` |
| Consumption cannot be ruled out | No event exists in this account for a foreign `CopyImage` / `RunInstances` on an unencrypted image |

### Recommended Guardrails

- **Catalogue match:** `data_perimeter_governance_scp` (statement `PreventExternalResourceShare`,
  conditional) lists `ec2:ModifyImageAttribute`.
- **Catalogue gap:** the upstream "Deny users from disabling block public access on AMIs" SCP
  denies `ec2:DisableImageBlockPublicAccess`, which this emulation never calls, and only protects
  the public case; it is not in the catalogue and would not match this attack.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1537 — Transfer Data to Cloud Account |
| Primary API | `ec2:ModifyImageAttribute`, `LaunchPermission.Add` |
| Revert API | `ec2:ModifyImageAttribute`, `LaunchPermission.Remove` |
| Event source | `ec2.amazonaws.com`, management event, image Region |
| Key fields | `requestParameters.imageId`, `requestParameters.launchPermission.add.items[]` (`userId` / `group` / `organizationArn` / `organizationalUnitArn`) |
| Lab identity | Role `stratus-red-team-share-ami-attacker-role`, session `atomic-t1537-share-ami`, recipient `193672423079` |

### Residual Risk

Every revocation closes the window; none recalls a copy. For an unencrypted AMI there is no event,
notification or API that tells you whether the recipient launched or copied it during the window,
so treat every secret on the source volumes as disclosed for any share that was live for more than
a few seconds.
