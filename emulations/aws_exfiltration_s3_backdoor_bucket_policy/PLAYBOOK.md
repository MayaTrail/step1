# IR Playbook: S3 Bucket Policy Backdoored for an External Account — `s3:PutBucketPolicy`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data exfiltration / persistence (a resource policy grants an outside account standing read access to a bucket; the access does not depend on any credential in this account) |
| Threat Actor | N/A — single technique, not actor-attributed (Stratus Red Team `aws.exfiltration.s3-backdoor-bucket-policy`) |
| Platform | aws |
| Severity | High for a named external account; Critical for an unconditioned `Principal: "*"` that S3 Block Public Access did not refuse, or when data events show the external principal reading objects |
| MITRE Tactics | Exfiltration |
| MITRE Techniques | T1537 |
| Services in Scope | S3, IAM, IAM Access Analyzer, STS, CloudTrail (management and S3 data events), GuardDuty |

**What the technique does:** the actor calls `s3:PutBucketPolicy` to install (or replace the bucket's
policy with) a statement that allows an account it controls to list and read the bucket. From then
on the external account reads with **its own** credentials. Rotating every key in this account,
deleting the compromised user, even revoking all sessions — none of it touches the grant, because it
lives on the bucket. It is persistence and an exfiltration channel in one call.

**How this emulation runs it.** The stack creates `stratus-red-team-s3-backdoor-<account>` with S3
Block Public Access fully enabled and three synthetic objects under `data/`. The connected role
assumes `stratus-red-team-s3-backdoor-attacker-role` (session `atomic-t1537-s3-backdoor`), whose
policy allows only `s3:GetBucketPolicy`, `s3:PutBucketPolicy` and `s3:DeleteBucketPolicy` on that
bucket. It checks for an existing policy, puts one statement — `Sid: BackdoorRead`, `Effect: Allow`,
`Principal: {"AWS": "arn:aws:iam::193672423079:root"}`, `Action: [s3:GetObject, s3:ListBucket]` on
the bucket and its objects — waits 15 seconds and deletes the policy. Events: `AssumeRole`,
`GetBucketPolicy`, `PutBucketPolicy`, `DeleteBucketPolicy` — all management events. The dummy
account never reads anything.

**Why the usual reflexes miss it.** **Block Public Access does not stop this.** A grant to a
specific account is not "public" to S3, so the lab bucket — with every Block Public Access flag on
— accepts it. GuardDuty's S3 policy findings (`Policy:S3/BucketAnonymousAccessGranted`,
`Policy:S3/BucketPublicAccessGranted`) are about public access and stay silent. The external reads
are S3 **data events**, absent from most trails. And bucket policies are edited constantly, so an
eventName-only rule drowns; a substring rule on `:root` fires on the owner's own account.

**Detection thesis:** read the policy in the request. Alert when an **Allow** statement names a
principal in another account (by root ARN, role/user ARN or bare ID) that is not on your allowlist,
and at Critical when it names `*` without an organization condition. Confirm with IAM Access
Analyzer, which evaluates the effective policy. Then use data events or server access logs to
answer whether the external principal read anything.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- `PutBucketPolicy`, `GetBucketPolicy`, `DeleteBucketPolicy` are bucket-level **management** events
  (Event history, 90 days). `requestParameters.bucketPolicy` carries the policy as a JSON object.
- **S3 data events** (`GetObject`, `ListObjects`, …) for sensitive buckets, or **S3 server access
  logs**. Without one of them, whether the external principal read data is unanswerable.
- **IAM Access Analyzer** with an external-access analyzer at account or organization zone of trust.

**Alerting (must be pre-configured)**
- **Allow to `*` without `aws:PrincipalOrgID` → P0.**
- **Allow to an account outside the allowlist → P1.**
- **Access Analyzer active finding on a bucket → P1.**

**Response Tooling**
- Break-glass credentials with `s3:GetBucketPolicy`, `s3:PutBucketPolicy`, `s3:DeleteBucketPolicy`,
  `access-analyzer:ListFindings`, `cloudtrail:LookupEvents`, `iam:PutRolePolicy`.
- The approved policy for each sensitive bucket, in IaC.
- **The allowlist of your organization's account IDs**, kept as data.

**Known IOC Baselines**
- Buckets that are legitimately shared cross-account (log archive, analytics) and with whom.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `PutBucketPolicy` with an Allow to `*` and no `aws:PrincipalOrgID` condition, accepted | CloudTrail (management) | T1537 |
| P0 | `GetObject` / `ListObjects` on the bucket by a principal from the newly granted account | CloudTrail (S3 data events) / server access logs | T1537 |
| P1 | `PutBucketPolicy` with an Allow to an unlisted account (root, role, user or bare ID) | CloudTrail (management) | T1537 |
| P1 | IAM Access Analyzer active finding: bucket shared with an external principal | Access Analyzer | T1537 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `PutBucketPolicy` refused with `AccessDenied` because Block Public Access blocked a public policy — the intent was public | CloudTrail (management) | T1537 |
| P2 | `GetBucketPolicy` across many buckets by one principal | CloudTrail (management) | T1537 |
| P2 | `PutBucketPolicy` followed within minutes by `DeleteBucketPolicy` from the same session — a test, or this emulation | CloudTrail (management) | T1537 |

### Detection Rule Quality Notes

| Issue | Impact | Correction |
|-------|--------|-----------|
| The generated rule was `requestParameters` contains `:root` | Fired on the owner's own account root and on Deny statements; missed bare IDs and role/user ARNs | Regular expressions requiring an Allow and an AWS principal in the same statement, either key order |
| Public grants were not detected | `Principal: "*"` contains no `:root` | Separate public rule, excluding statements scoped with `aws:PrincipalOrgID`; shipped at high (second document) so the product validates the cross-account rule this emulation fires — deploy it at critical |
| Owner's account cannot be compared in Sigma | Same-account principals look cross-account | Allowlist placeholder (populate with your own account ID); the KQL compares to `RecipientAccountId` |

### Key Investigation Queries

#### Query 1 — The bucket's policy now

```bash
BUCKET="<bucket_name>"
aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text
```

Read every `Allow` statement's `Principal`. Anything that is `*` (without an organization
condition) or names an account other than yours is the incident. `NoSuchBucketPolicy` means no
policy now — the grant may have been removed already (Query 2 shows whether one existed).

#### Query 2 — Every policy change on S3 in the last 30 days

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,Username,CloudTrailEvent]' --output json
```

For each event read `requestParameters.bucketName`, the full `requestParameters.bucketPolicy`,
`userIdentity.arn`, `sourceIPAddress` and `errorCode`. Repeat with
`AttributeValue=DeleteBucketPolicy`. The grant's window runs from its `PutBucketPolicy` to the next
policy change on the bucket that removed it. For this emulation: put and delete 15 s apart from
session `atomic-t1537-s3-backdoor`.

#### Query 3 — Did the external account read anything? (data events)

CloudTrail Event history and `lookup-events` **never return S3 data events**. Query your trail's
data events in Athena or CloudTrail Lake instead:

```sql
SELECT eventtime, eventname, useridentity.accountid, useridentity.arn, sourceipaddress,
       json_extract_scalar(requestparameters, '$.key') AS object_key
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND json_extract_scalar(requestparameters, '$.bucketName') = '<bucket_name>'
  AND useridentity.accountid = '<external-account-id>'
  AND eventtime BETWEEN '<grant-time>' AND '<revoke-time>'
ORDER BY eventtime;
```

No rows is meaningful **only** if the trail logged data events for this bucket over the whole
window. If it did not, the answer is "unknown" — check S3 server access logs for requester ARNs
from the external account instead, and write "unknown" in the record if neither exists.

#### Query 4 — Every bucket shared outside the account (Access Analyzer)

```bash
aws accessanalyzer list-analyzers --query 'analyzers[].arn' --output text
```

Then `aws accessanalyzer list-findings --analyzer-arn <arn> --filter '{"resourceType":{"eq":["AWS::S3::Bucket"]},"status":{"eq":["ACTIVE"]}}'`.
Each active finding names a bucket and the external principal; anything not on the allowlist is in
scope. This catches grants made before your CloudTrail retention.

#### Query 5 — The principal's session

```bash
SESSION="<session-name-or-user-from-Query-2>"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION" \
  --start-time "$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,EventSource,EventName]' --output table
```

`GetBucketPolicy` / `ListBuckets` before the change is target selection.
`PutBucketPublicAccessBlock` or `DeletePublicAccessBlock` in the same session means the actor tried
to make a public grant possible.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Step 1 — Save the malicious policy, then restore the approved one

```bash
BUCKET="<bucket_name>"
aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text > malicious-policy-$BUCKET.json
aws s3api put-bucket-policy --bucket "$BUCKET" --policy file://approved-policy-$BUCKET.json
```

If the bucket had no approved policy, `aws s3api delete-bucket-policy --bucket "$BUCKET"`. Keep the
saved file as evidence: the external account ID and the actions granted are in it. Do not delete
the policy if it also carried legitimate statements the workload needs — remove only the malicious
statement.

#### Step 2 — Contain the principal

```bash
ROLE="<role-name-from-Query-2>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyDenyPolicyChanges \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:PutBucketPolicy","s3:DeleteBucketPolicy","s3:PutBucketAcl","s3:PutBucketPublicAccessBlock"],"Resource":"*"}]}'
```

For an IAM user, deactivate its access keys and attach the same deny as a user policy.

#### Step 3 — Sweep for other backdoored buckets

Run Query 4. An actor who backdoored one bucket usually did it to the ones that mattered; each
active external-access finding outside the allowlist gets Step 1.

---

## 4. Eradication

### Remove Attacker Access

- The grant was the access; once every malicious statement is gone, the external account has none.
  Confirm with Access Analyzer (Query 4) rather than by reading policies by eye.
- Trace the session to its source identity and contain it.

### Prevent recurrence

- An **RCP using `aws:PrincipalOrgID`** (the catalogue's `identity_perimeter_rcp`, conditional and
  broad) makes a grant to an outside account ineffective even if the policy says otherwise — the
  structural fix for this technique.
- Restrict `s3:PutBucketPolicy` to the IaC role on sensitive buckets.
- Keep S3 Block Public Access on at the account level (the catalogue's
  `S3-Deny-users-from-modifying-S3-Block-Public-Access-(Account-Level)` SCP protects it) — it stops
  the public variant, not this one.

### Remove the emergency policies once clean

```bash
ROLE="<role-name-from-Query-2>"
aws iam delete-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions
aws iam delete-role-policy --role-name "$ROLE" --policy-name EmergencyDenyPolicyChanges
aws iam list-role-policies --role-name "$ROLE"
```

---

## 5. Recovery

### Restore Clean State

#### Confirm the policy is the approved one and Access Analyzer agrees

```bash
BUCKET="<bucket_name>"
aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text
```

Matches IaC, and Access Analyzer shows the bucket's finding as `RESOLVED` (or none).

#### Confirm the corrected detection fires

```text
MUST fire on:     PutBucketPolicy with an Allow to an AWS principal in another account not on
                  the allowlist (root ARN, role/user ARN or bare ID) -> high; Allow to "*"
                  without aws:PrincipalOrgID -> high in the shipped file (deploy at critical).
MUST NOT fire on: DeleteBucketPolicy; a Deny with Principal "*" (deny insecure transport);
                  service principals (cloudtrail.amazonaws.com); allowlisted accounts.
EXPECTED FP:      approved cross-account sharing - allowlist the account IDs.
```

Running this emulation is the test: `PutBucketPolicy` with Sid `BackdoorRead` from session
`atomic-t1537-s3-backdoor` must fire `s3_bucket_policy_cross_account`.

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| An outside account was granted read access in one call | `s3:PutBucketPolicy` available to a non-IaC principal; no organization-perimeter RCP |
| Block Public Access did not intervene | A named external account is not public to S3 |
| Whether data was read is unknown | S3 data events not logged for the bucket; no server access logs |

### Recommended Guardrails

- **Catalogue match:** `identity_perimeter_rcp` and `network_perimeter_vpceorgid_rcp` cover `s3:*`
  conditionally (broad perimeter controls; adapt their organization IDs). No catalogue policy
  targets `s3:PutBucketPolicy` specifically — the upstream AWS examples contain none.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1537 — Transfer Data to Cloud Account |
| Primary API | `s3:PutBucketPolicy` (eventName `PutBucketPolicy`, management event) |
| Revert API | `s3:DeleteBucketPolicy` |
| Key fields | `requestParameters.bucketName`, `requestParameters.bucketPolicy.Statement[].Effect / Principal / Action` |
| Use of the grant | `GetObject` / `ListObjects` by the external account — S3 **data events** |
| Lab identity | Role `stratus-red-team-s3-backdoor-attacker-role`, session `atomic-t1537-s3-backdoor`, grantee `193672423079` |

### Residual Risk

Every object the external account read during the window is disclosed. Without S3 data events or
server access logs for the bucket, there is no way to establish whether that happened, and the
window is bounded only by the policy change events.
