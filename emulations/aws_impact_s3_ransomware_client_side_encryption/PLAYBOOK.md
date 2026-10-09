# IR Playbook: S3 Objects Replaced by Client-Side Encrypted Copies — Read, Rewrite as `<key>.encrypted`, Delete

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Ransomware / data encrypted for impact (every object is read, re-uploaded encrypted under a key only the attacker holds, and the original deleted) |
| Threat Actor | N/A — single technique, not actor-attributed (Stratus Red Team `aws.impact.s3-ransomware-client-side-encryption`) |
| Platform | aws |
| Severity | **Critical** (matches the emulation manifest). The read phase is exfiltration (assume extortion), and without versioning or a copy the originals are gone and the ciphertext is unrecoverable without the attacker's key |
| MITRE Tactics | Impact |
| MITRE Techniques | T1486 |
| Services in Scope | S3, IAM, STS, CloudTrail (S3 data events), CloudTrail Lake / Athena, GuardDuty S3 Protection, AWS Backup |

**What the technique does:** for each object the actor calls `GetObject`, encrypts the bytes on its
own machine with a key that never touches AWS, `PutObject`s the ciphertext under a new name
(`<key>.encrypted`), and `DeleteObject`s the original. When it finishes, the bucket holds the same
number of objects, all unreadable. Because the encryption is client-side, **no S3 or KMS setting
interferes**: default bucket encryption, SSE-KMS and key policies all apply to the ciphertext and
protect nothing.

**How this emulation runs it.** The stack creates `stratus-red-team-ransomware-encrypt-<account>` with
Block Public Access on, **no versioning**, and 50 synthetic objects under `data/`. The connected role
assumes `stratus-red-team-ransomware-encrypt-attacker-role` (session `atomic-t1486-s3-encrypt`),
allowed `s3:ListBucket` on the bucket and `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` on its
objects. A key is generated in memory (Fernet when `cryptography` is installed, XOR otherwise); for
each object the run does GetObject → PutObject `<key>.encrypted` → DeleteObject `<key>`; the key is
discarded at the end. The lab objects are unrecoverable by design — redeploy the stack. Events:
`AssumeRole` (management); `ListObjects(V2)`, 50 × `GetObject`, 50 × `PutObject`, 50 × `DeleteObject`
(**data events**). It does not upload a ransom note.

> **This port differs from Stratus Red Team's version.** Stratus's technique re-encrypts objects
> *in place* with SSE-C (`CopyObject` with a customer-provided key, after `PutBucketEncryption` to
> unblock SSE-C) and uploads a ransom note. That variant is detected on
> `x-amz-server-side-encryption-customer-algorithm` and is exercised by the **codefinger** emulation.
> This playbook covers the client-side rewrite-and-delete variant the code actually performs.

**Why the usual reflexes miss it.** Every call is an ordinary object operation and a **data event**,
recorded only by a trail that selects S3 data events for the bucket — never in Event history or
`lookup-events`. Delete-volume rules see one delete per object, interleaved with writes, which
looks like churn. And the object count does not drop, so the `NumberOfObjects` metric shows
nothing.

**Detection thesis:** the per-object cycle — *read `K`, write `K` plus a new suffix, delete `K`* — by
one principal on one bucket. A ransomware-style suffix on `PutObject` is the cheap anchor; the
sequence and the volume are the confirmation; the KQL's join of `K.suffix` back to `K` catches
suffixes no list anticipated.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **S3 data events (read and write) for critical buckets**, queryable in Athena / CloudTrail Lake.
  The read phase matters as much as the writes: it is the exfiltration.
- **S3 server access logs** as a second source.
- **GuardDuty S3 Protection**: `Exfiltration:S3/AnomalousBehavior` (read phase),
  `Impact:S3/AnomalousBehavior.Write` and `.Delete`.

**Recoverability (decides the outcome)**
- **Versioning** keeps each deleted original as a non-current version — this variant is fully
  recoverable from it, because the ciphertext is a different key. **Object Lock** stops the
  delete. Replication or AWS Backup keeps an independent copy.

**Alerting (must be pre-configured)**
- **Read → suffix write → delete by one principal in one bucket within 5m → P0.**
- **≥ 10 suffix writes by one principal in one bucket within 10m → P0.**
- **Any `PutObject` with a ransomware-style suffix → P1.**

**Response Tooling**
- Break-glass credentials with `s3:ListBucketVersions`, `s3:GetBucketVersioning`, `s3:GetObject`,
  `s3:PutObject`, `s3:PutBucketPolicy`, `iam:PutRolePolicy`; Athena access to data events.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | GetObject → PutObject `<key>.<suffix>` → DeleteObject `<key>` by one principal within 5m | CloudTrail (S3 data events), correlation | T1486 |
| P0 | ≥ 10 suffix writes (`.encrypted`, `.locked`, `.crypted`) by one principal in one bucket within 10m | CloudTrail (S3 data events), correlation | T1486 |
| P1 | Any `PutObject` with a ransomware-style suffix | CloudTrail (S3 data events) | T1486 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | GuardDuty `Exfiltration:S3/AnomalousBehavior` followed by `Impact:S3/AnomalousBehavior.Write` / `.Delete` for the same principal | GuardDuty | T1486 |
| P2 | A single new object (README, HOW_TO_DECRYPT) in the bucket root after a rewrite burst | CloudTrail (S3 data events) | T1486 |
| P2 | `PutBucketVersioning Suspended` or a lifecycle rule expiring non-current versions, same principal | CloudTrail (management) | T1486 |

### Detection Rule Quality Notes

| Issue | Impact | Correction |
|-------|--------|-----------|
| The generated rule alerted per suffixed object and nothing else | 50 identical alerts, and no expression of the pattern | Kept as the anchor; added the read → write → delete `temporal_ordered` correlation and an `event_count` (≥ 10) correlation, both critical |
| Only `.encrypted` | Trivially renamed | `.locked` and `.crypted` added; `.enc` deliberately excluded (legitimate tools) |
| `<key>.suffix` cannot be joined to `<key>` in Sigma | Unknown suffixes evade the list | KQL joins each suffixed write to the deletion of its original for any dot-suffix |

### Key Investigation Queries

> **`lookup-events` cannot see these calls** (data events). Use Athena / CloudTrail Lake. If the
> bucket was not covered by a data-event selector, the CloudTrail answer is **INCONCLUSIVE**.

#### Query 1 — The rewrite pattern per principal (Athena)

```sql
SELECT useridentity.arn AS principal, eventname,
       count(DISTINCT json_extract_scalar(requestparameters, '$.key')) AS keys,
       min(eventtime) AS first_seen, max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND json_extract_scalar(requestparameters, '$.bucketName') = '<bucket_name>'
  AND eventname IN ('GetObject', 'PutObject', 'DeleteObject', 'ListObjects', 'ListObjectsV2')
  AND eventtime > '<start-of-window>'
GROUP BY 1, 2
ORDER BY principal, first_seen;
```

A principal with roughly equal `GetObject`, `PutObject` and `DeleteObject` key counts is the
pattern. For this emulation: 50 / 50 / 50 from session `atomic-t1486-s3-encrypt`.

#### Query 2 — Which keys were replaced, and with what suffix (Athena)

```sql
SELECT json_extract_scalar(requestparameters, '$.key') AS new_key, eventtime
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com' AND eventname = 'PutObject'
  AND useridentity.arn = '<principal-from-Query-1>'
  AND json_extract_scalar(requestparameters, '$.bucketName') = '<bucket_name>'
ORDER BY eventtime;
```

Strip the suffix to get the list of originals to restore. A non-suffixed new key is likely the
ransom note — preserve it for the record.

#### Query 3 — Can the originals come back?

```bash
BUCKET="<bucket_name>"
aws s3api get-bucket-versioning --bucket "$BUCKET"
```

`Enabled` → each original exists as a non-current version (its delete left a delete marker).
Empty or `Suspended` → originals deleted while unversioned are gone from this bucket; only a replica
or backup restores them. The emulation's bucket is unversioned by design.

#### Query 4 — What the bucket holds now

```bash
BUCKET="<bucket_name>"
aws s3api list-objects-v2 --bucket "$BUCKET" --query 'Contents[].Key' --output text
```

Keys ending in the attacker's suffix are ciphertext. Do **not** delete them yet: if recovery fails,
they are the only remaining form of the data, and a decryptor (law-enforcement or vendor) may exist.

#### Query 5 — The session's management events

```bash
SESSION="<session-name-from-Query-1-arn>"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION" \
  --start-time "$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,EventSource,EventName]' --output table
```

The `AssumeRole` that started the session and any `PutBucketVersioning`, `PutBucketLifecycle` or
`PutBucketEncryption` changes are here.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Step 1 — Stop the principal

```bash
ROLE="<role-name-from-Query-1>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyDenyS3Rewrite \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:DeleteObjectVersion","s3:PutBucketVersioning","s3:PutLifecycleConfiguration"],"Resource":"*"}]}'
```

#### Step 2 — Deny writes and deletes on the bucket to everyone but break-glass

A bucket policy statement denying `s3:PutObject`, `s3:DeleteObject` and `s3:DeleteObjectVersion`
unless `aws:PrincipalArn` is the break-glass role. Other stolen credentials stop at the next object.

#### Step 3 — Freeze recovery sources

Keep versioning on, disable lifecycle expiration of non-current versions, confirm backup recovery
points predate the first rewrite.

---

## 4. Eradication

### Remove Attacker Access

- Trace the session to its source identity and contain it. A principal with read, write and delete
  on the same bucket is the precondition; split those rights.

### Prevent recurrence

- Versioning + Object Lock on critical buckets: this variant cannot destroy a locked original.
- The guardrail catalogue's **`S3-Deny-users-from-deleting-Amazon-S3-Buckets-or-objects`** RCP
  denies `s3:DeleteObject` on named buckets, which leaves the ciphertext next to an intact original.
  The catalogue's `S3-Deny-SSE-C` and `Enforce-encryption-at-rest-for-production-data` match
  `s3:PutObject` but do **not** stop client-side encryption — they govern S3-side encryption headers.

### Remove the emergency policies once clean

```bash
ROLE="<role-name-from-Query-1>"
aws iam delete-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions
aws iam delete-role-policy --role-name "$ROLE" --policy-name EmergencyDenyS3Rewrite
aws iam list-role-policies --role-name "$ROLE"
```

---

## 5. Recovery

### Restore Clean State

#### Versioned bucket: bring back each original

```bash
BUCKET="<bucket_name>"
aws s3api list-object-versions --bucket "$BUCKET" --query 'DeleteMarkers[?IsLatest==`true`].[Key,VersionId]' --output text
```

For each original key, `aws s3api delete-object --bucket <bucket_name> --key <Key> --version-id <VersionId>`
removes the delete marker and restores the plaintext. Verify a sample with `head-object`, then
remove the `*.encrypted` copies.

#### Unversioned bucket

Restore from the replica or AWS Backup. If neither exists, keep the ciphertext, record the key list
from Query 2, and escalate through the disclosure and ransom decision path — the plaintext was also
read, so treat it as disclosed regardless.

#### Confirm the corrected detection fires

```text
MUST fire on:     GetObject -> PutObject <key>.encrypted -> DeleteObject <key> by one principal
                  in one bucket within 5m -> critical; >= 10 suffix writes in 10m -> critical;
                  any PutObject ending .encrypted / .locked / .crypted -> high.
MUST NOT fire on: ordinary PutObject; .enc files from backup tools.
PRECONDITION:     S3 data events (read and write) for the bucket.
```

Running this emulation is the test: 50 cycles from session `atomic-t1486-s3-encrypt`.

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could read, rewrite and delete every object | Read, write and delete granted together on the bucket |
| Originals were not recoverable | No versioning / Object Lock / replica / backup |
| The pattern was not seen | No S3 data events, or rules that counted deletes only |

### Recommended Guardrails

- **Catalogue match:** `S3-Deny-users-from-deleting-Amazon-S3-Buckets-or-objects` (RCP, named
  bucket) denies the `DeleteObject` step. No guardrail prevents the client-side encryption itself.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1486 — Data Encrypted for Impact |
| Per-object calls (eventName) | `GetObject`, `PutObject` (`<key>.encrypted`), `DeleteObject` |
| IAM actions | `s3:ListBucket`, `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` |
| Event category | **Data** — not in Event history, not in `lookup-events` |
| Key fields | `requestParameters.bucketName`, `requestParameters.key` |
| Related variant | SSE-C in-place re-encryption (codefinger emulation; Stratus's own implementation) |
| Lab identity | Role `stratus-red-team-ransomware-encrypt-attacker-role`, session `atomic-t1486-s3-encrypt` |

### Residual Risk

Every object read during the incident is disclosed regardless of recovery. Without versioning or an
independent copy, the plaintext is gone and the only path to it is the attacker's key.
