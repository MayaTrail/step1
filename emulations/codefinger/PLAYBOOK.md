# IR Playbook: Codefinger — AWS S3 Ransomware

## Classification
| Field | Value |
|-------|-------|
| Incident Type | Cloud Ransomware / Data Encryption for Extortion |
| Threat Actor | Codefinger |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Initial Access, Collection, Impact |
| MITRE Techniques | T1078.004, T1530, T1486, T1485, T1490 |

---

## 1. Preparation

**Prerequisites that MUST be in place before this incident type occurs:**

- **CloudTrail**: Multi-region trail enabled with S3 data-plane events (GetObject, PutObject, DeleteObject, HeadObject) logging enabled on all sensitive buckets.
- **GuardDuty**: Enabled in all regions with S3 Protection feature active.
- **Amazon Macie**: Enabled for automated sensitive data discovery on S3 buckets containing PII/financial data.
- **Security Hub**: Enabled with AWS Foundational Security Best Practices standard; controls S3.13 and S3.14 active.
- **S3 Versioning**: Enabled on all buckets holding critical data — versioning suspension events become the primary high-signal detection indicator.
- **EventBridge rule**: Alert on `PutBucketVersioning` (suspension) and `PutBucketLifecycleConfiguration` control-plane events.
- **IAM Access Analyzer**: Enabled to detect public S3 bucket policies exposing credentials.
- **Bucket public access block**: `BlockPublicAcls` and `RestrictPublicBuckets` set on all non-intentionally-public buckets.
- **SIEM ingestion**: CloudTrail logs, GuardDuty findings, and Macie findings forwarded to SIEM with correlation rules for SSE-C PutObject chains.
- **IAM key inventory**: Automated audit of long-term access keys; keys unused >90 days auto-disabled.
- **Incident response contacts**: On-call rotation, AWS Support (Business or Enterprise) contact pre-established.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Audit Event | EventSource | Why High-Confidence |
|---|---|---|
| `PutBucketVersioning` (Status=Suspended) | s3.amazonaws.com | Codefinger terminal step; legitimate ops rarely suspend versioning |
| `PutBucketLifecycleConfiguration` with 1-day expiry | s3.amazonaws.com | Ransomware TTL countdown; no legitimate use case applies 1-day deletion on data buckets |
| `PutObject` with `x-amz-server-side-encryption-customer-algorithm: AES256` (SSE-C) on previously non-SSE-C objects | s3.amazonaws.com | In-place re-encryption with attacker-held key — core ransomware mechanism |
| `DeleteObjectVersion` bulk following SSE-C PutObject | s3.amazonaws.com | Eliminates version rollback recovery path |
| `README.txt` PutObject across multiple prefixes simultaneously | s3.amazonaws.com | Ransom note deposit pattern |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Audit Event | EventSource | Why Medium-Confidence |
|---|---|---|
| `GetCallerIdentity` from novel source IP using long-term IAM key | sts.amazonaws.com | Attacker credential validation probe; also used by legitimate tooling |
| `ListBuckets` from IP outside access baseline | s3.amazonaws.com | Reconnaissance; also performed by monitoring tools |
| `ListObjects` + `HeadObject` high-volume burst from single principal | s3.amazonaws.com | Encryption target enumeration; also batch processing jobs |
| Anonymous `GetObject` on bait/IaC state bucket | s3.amazonaws.com | Credential harvesting; legitimate if bucket intentionally public |
| `DeleteObject` bulk following `PutObject` burst (same session) | s3.amazonaws.com | Original object deletion after re-encryption |

### Key Investigation Queries

#### Step 1 — Scope the Compromised IAM Principal

```bash
# Identify all API calls from the suspected IAM access key in the last 24h
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<SUSPECTED_KEY_ID> \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --end-time "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --output json | jq '.Events[] | {time: .EventTime, event: .EventName, resource: .Resources}'
```

```bash
# Who does this key belong to?
aws iam get-access-key-last-used --access-key-id <SUSPECTED_KEY_ID>
```

```bash
# List all access keys for the identified user
aws iam list-access-keys --user-name <VICTIM_IAM_USERNAME>
```

#### Step 2 — Detect Initial Credential Theft from Bait Bucket

```bash
# Check S3 server access logs on the bait bucket for anonymous GetObject
aws s3api get-bucket-logging --bucket <BAIT_BUCKET_NAME>

# Query CloudTrail for GetObject on bait bucket without authenticated principal
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=<BAIT_BUCKET_NAME> \
  --output json | jq '.Events[] | select(.EventName=="GetObject") | {time: .EventTime, user: .Username, ip: (.CloudTrailEvent | fromjson | .sourceIPAddress)}'
```

#### Step 3 — Identify Reconnaissance Activity (T1530)

```bash
# Find ListObjectsV2, HeadObject, GetObject burst from the compromised key
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<COMPROMISED_KEY_ID> \
  --output json | jq '.Events[] | select(.EventName | IN("ListObjects","ListObjectsV2","HeadObject","GetObject")) | {time: .EventTime, bucket: (.CloudTrailEvent | fromjson | .requestParameters.bucketName), key: (.CloudTrailEvent | fromjson | .requestParameters.key)}'
```

#### Step 4 — Detect SSE-C Encryption Activity (T1486)

```bash
# Find PutObject calls with SSE-C headers — look for sseApplied: SSE-C in CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<COMPROMISED_KEY_ID> \
  --output json | jq '.Events[] | select(.EventName=="PutObject") | {time: .EventTime, event: .CloudTrailEvent | fromjson}'
```

```bash
# Check current encryption state of objects in affected bucket (sample)
aws s3api head-object \
  --bucket <TARGET_BUCKET> \
  --key <SAMPLE_OBJECT_KEY>
# Look for: "ServerSideEncryption": "aws:customer" indicating SSE-C
```

```bash
# List all objects in affected prefixes to assess blast radius
aws s3api list-objects-v2 \
  --bucket <TARGET_BUCKET> \
  --prefix finance/ \
  --query 'Contents[*].{Key:Key,Size:Size,LastModified:LastModified}' \
  --output table

aws s3api list-objects-v2 \
  --bucket <TARGET_BUCKET> \
  --prefix hr/ \
  --query 'Contents[*].{Key:Key,Size:Size,LastModified:LastModified}' \
  --output table
```

#### Step 5 — Check Lifecycle Policy (T1485)

```bash
# Inspect current lifecycle policy on affected bucket
aws s3api get-bucket-lifecycle-configuration --bucket <TARGET_BUCKET>
# If rule with 1-day expiry or ID "codefinger-auto-delete" exists: CRITICAL
```

```bash
# Audit CloudTrail for lifecycle modifications
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketLifecycleConfiguration \
  --start-time "$(date -u -d '48 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --output json | jq '.Events[] | {time: .EventTime, user: .Username, bucket: (.CloudTrailEvent | fromjson | .requestParameters.bucketName)}'
```

#### Step 6 — Check Versioning Suspension (T1490)

```bash
# Check current versioning status
aws s3api get-bucket-versioning --bucket <TARGET_BUCKET>
# "Status": "Suspended" = attacker completed terminal step

# Audit CloudTrail for versioning changes
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketVersioning \
  --start-time "$(date -u -d '48 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --output json | jq '.Events[] | {time: .EventTime, user: .Username, bucket: (.CloudTrailEvent | fromjson | .requestParameters.bucketName), status: (.CloudTrailEvent | fromjson | .requestParameters.VersioningConfiguration.Status)}'
```

```bash
# List all remaining object versions (assess if bulk DeleteObjectVersion occurred)
aws s3api list-object-versions \
  --bucket <TARGET_BUCKET> \
  --output json | jq '{versions: [.Versions[]? | {key: .Key, versionId: .VersionId, isLatest: .IsLatest}], deleteMarkers: [.DeleteMarkers[]? | {key: .Key, versionId: .VersionId}]}'
```

#### Step 7 — GuardDuty Finding Review

```bash
# Pull all active GuardDuty findings of severity >= 7 (High/Critical)
aws guardduty list-findings \
  --detector-id <DETECTOR_ID> \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7},"updatedAt":{"Gte":'$(date -u -d '48 hours ago' +%s000)'}}}' \
  --output json

# Get finding detail for relevant finding IDs
aws guardduty get-findings \
  --detector-id <DETECTOR_ID> \
  --finding-ids <FINDING_ID_1> <FINDING_ID_2> \
  --output json | jq '.Findings[] | {type: .Type, severity: .Severity, principal: .Resource.AccessKeyDetails.UserName, ip: .Service.Action.AwsApiCallAction.RemoteIpDetails.IpAddressV4}'
```

```bash
# Get GuardDuty detector ID (if unknown)
aws guardduty list-detectors --output json | jq -r '.DetectorIds[0]'
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### 3.1 — Disable Compromised IAM Access Key

```bash
# IMMEDIATE: Deactivate the stolen long-term access key
aws iam update-access-key \
  --user-name <VICTIM_IAM_USERNAME> \
  --access-key-id <COMPROMISED_KEY_ID> \
  --status Inactive
```

```bash
# Verify deactivation
aws iam list-access-keys --user-name <VICTIM_IAM_USERNAME>
```

#### 3.2 — Attach Explicit Deny Policy to Victim IAM User (Belt-and-Suspenders)

```bash
# Create an explicit deny policy to prevent any further API calls even if key is somehow reactivated
cat > /tmp/deny-all-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF

aws iam put-user-policy \
  --user-name <VICTIM_IAM_USERNAME> \
  --policy-name EmergencyDenyAll \
  --policy-document file:///tmp/deny-all-policy.json
```

#### 3.3 — Remove Active Lifecycle Policy (If Present — Stop Countdown)

```bash
# CRITICAL: Remove attacker-set lifecycle rule to stop automated deletion
aws s3api delete-bucket-lifecycle --bucket <TARGET_BUCKET>

# Verify lifecycle is removed
aws s3api get-bucket-lifecycle-configuration --bucket <TARGET_BUCKET>
# Expected: NoSuchLifecycleConfiguration error = safe
```

#### 3.4 — Re-Enable S3 Object Versioning

```bash
# Re-enable versioning if it was suspended
aws s3api put-bucket-versioning \
  --bucket <TARGET_BUCKET> \
  --versioning-configuration Status=Enabled
```

#### 3.5 — Block Public Access on Bait Bucket (Credential Source)

```bash
# Prevent further anonymous credential downloads from the bait bucket
aws s3api put-public-access-block \
  --bucket <BAIT_BUCKET_NAME> \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

#### 3.6 — Add S3 Bucket Policy Deny for Compromised Principal

```bash
# Deny all S3 access to the compromised IAM user at the resource level
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
VICTIM_ARN="arn:aws:iam::${ACCOUNT_ID}:user/<VICTIM_IAM_USERNAME>"

cat > /tmp/bucket-deny-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCompromisedPrincipal",
      "Effect": "Deny",
      "Principal": {"AWS": "${VICTIM_ARN}"},
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::<TARGET_BUCKET>",
        "arn:aws:s3:::<TARGET_BUCKET>/*"
      ]
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket <TARGET_BUCKET> \
  --policy file:///tmp/bucket-deny-policy.json
```

#### 3.7 — Enable S3 MFA Delete (Prevent Future Version Deletion)

```bash
# Require MFA for version deletion (prevents automated deletion by compromised keys)
# NOTE: Requires root credentials or MFA-authenticated session
aws s3api put-bucket-versioning \
  --bucket <TARGET_BUCKET> \
  --versioning-configuration 'Status=Enabled,MFADelete=Enabled' \
  --mfa "<MFA_SERIAL_NUMBER> <MFA_TOKEN>"
```

---

## 4. Eradication

### Remove Attacker Access

#### 4.1 — Permanently Delete Compromised Access Key

```bash
# After incident is confirmed, delete the key entirely (not just disable)
aws iam delete-access-key \
  --user-name <VICTIM_IAM_USERNAME> \
  --access-key-id <COMPROMISED_KEY_ID>
```

#### 4.2 — Rotate All IAM User Credentials

```bash
# Create a new access key for the legitimate user (for future use after IR)
aws iam create-access-key --user-name <VICTIM_IAM_USERNAME>

# Update login profile password if console access was also active
aws iam update-login-profile \
  --user-name <VICTIM_IAM_USERNAME> \
  --password <NEW_STRONG_PASSWORD> \
  --password-reset-required
```

#### 4.3 — Remove Ransom Notes from Affected Prefixes

```bash
# Remove README.txt ransom notes deposited by attacker
aws s3 rm s3://<TARGET_BUCKET>/finance/README.txt
aws s3 rm s3://<TARGET_BUCKET>/hr/README.txt

# Search for any additional ransom notes across all prefixes
aws s3api list-objects-v2 \
  --bucket <TARGET_BUCKET> \
  --query "Contents[?contains(Key, 'README')]" \
  --output json
```

#### 4.4 — Enumerate and Remove All SSE-C Encrypted Objects

```bash
# List all objects that are currently SSE-C encrypted (check x-amz-server-side-encryption)
# SSE-C objects require the customer key to read — these are inaccessible without attacker key
# Document them for insurance/legal and mark for recovery or permanent removal

aws s3api list-objects-v2 \
  --bucket <TARGET_BUCKET> \
  --output json | jq '.Contents[].Key' -r | while read key; do
    encryption=$(aws s3api head-object --bucket <TARGET_BUCKET> --key "$key" \
      --query 'ServerSideEncryption' --output text 2>/dev/null)
    if [ "$encryption" = "None" ]; then
      echo "POSSIBLY_SSE_C: $key"
    fi
  done
```

#### 4.5 — Remove Emergency Deny Policy After Recovery

```bash
# Only after victim user credentials have been fully rotated and new key issued
aws iam delete-user-policy \
  --user-name <VICTIM_IAM_USERNAME> \
  --policy-name EmergencyDenyAll
```

#### 4.6 — Remediate Bait Bucket — Remove Exposed Credentials Object

```bash
# Delete the terraform.tfvars or equivalent credentials file from the bait bucket
aws s3 rm s3://<BAIT_BUCKET_NAME>/terraform.tfvars

# Audit what else may have been exposed
aws s3api list-objects-v2 --bucket <BAIT_BUCKET_NAME> --output json | jq '.Contents[].Key'
```

#### 4.7 — Check for Lateral IAM Permissions Abuse

```bash
# Review what permissions the victim user has to determine blast radius
aws iam list-user-policies --user-name <VICTIM_IAM_USERNAME>
aws iam list-attached-user-policies --user-name <VICTIM_IAM_USERNAME>
aws iam list-groups-for-user --user-name <VICTIM_IAM_USERNAME>

# Simulate to determine effective permissions
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::<ACCOUNT_ID>:user/<VICTIM_IAM_USERNAME>" \
  --action-names "iam:CreateUser" "iam:AttachRolePolicy" "s3:DeleteBucket" \
  --output json | jq '.EvaluationResults[] | {action: .EvalActionName, decision: .EvalDecision}'
```

---

## 5. Recovery

### Restore Clean State

#### 5.1 — Attempt Version Rollback for Non-SSE-C Objects

```bash
# Identify most recent pre-attack version of each object (before attacker's PutObject timestamp)
ATTACK_TIME="<ISO8601_TIMESTAMP_OF_FIRST_SSE_C_PUTOBJECT>"

aws s3api list-object-versions \
  --bucket <TARGET_BUCKET> \
  --prefix finance/ \
  --output json | jq --arg ts "$ATTACK_TIME" \
  '.Versions[] | select(.LastModified < $ts) | {key: .Key, versionId: .VersionId, modified: .LastModified}' \
  | sort
```

```bash
# Restore a specific pre-attack version by copying it to the current key
aws s3api copy-object \
  --bucket <TARGET_BUCKET> \
  --copy-source "<TARGET_BUCKET>/<OBJECT_KEY>?versionId=<PRE_ATTACK_VERSION_ID>" \
  --key <OBJECT_KEY>
```

```bash
# Bulk restore script: for each prefix, promote the last clean version
aws s3api list-object-versions \
  --bucket <TARGET_BUCKET> \
  --output json | jq -r '.Versions[] | "\(.Key) \(.VersionId) \(.LastModified)"' | \
  while read key version_id modified; do
    if [[ "$modified" < "$ATTACK_TIME" ]]; then
      aws s3api copy-object \
        --bucket <TARGET_BUCKET> \
        --copy-source "${TARGET_BUCKET}/${key}?versionId=${version_id}" \
        --key "$key"
      echo "Restored: $key from version $version_id"
    fi
  done
```

#### 5.2 — Restore from Backup if Versions Deleted

```bash
# If DeleteObjectVersion wiped all clean versions, restore from S3 Cross-Region Replication
# or AWS Backup vault
aws backup list-recovery-points-by-backup-vault \
  --backup-vault-name <VAULT_NAME> \
  --by-resource-arn "arn:aws:s3:::<TARGET_BUCKET>" \
  --output json | jq '.RecoveryPoints[] | {arn: .RecoveryPointArn, creationDate: .CreationDate, status: .Status}'

aws backup start-restore-job \
  --recovery-point-arn <RECOVERY_POINT_ARN> \
  --iam-role-arn "arn:aws:iam::<ACCOUNT_ID>:role/AWSBackupRole" \
  --metadata '{"DestinationBucketName":"<RECOVERY_BUCKET>"}' \
  --resource-type S3
```

#### 5.3 — Re-Verify Security Posture Post-Recovery

```bash
# Verify versioning is re-enabled
aws s3api get-bucket-versioning --bucket <TARGET_BUCKET>
# Expected: {"Status": "Enabled"}

# Verify no lifecycle rules remain
aws s3api get-bucket-lifecycle-configuration --bucket <TARGET_BUCKET>
# Expected: NoSuchLifecycleConfiguration

# Verify no public access on bait bucket
aws s3api get-public-access-block --bucket <BAIT_BUCKET_NAME>

# Verify compromised key is deleted
aws iam list-access-keys --user-name <VICTIM_IAM_USERNAME>
# Confirm COMPROMISED_KEY_ID is absent
```

#### 5.4 — Re-Enable GuardDuty S3 Protection and Verify Macie

```bash
# Confirm GuardDuty S3 protection is active
aws guardduty get-detector \
  --detector-id <DETECTOR_ID> \
  --query 'DataSources.S3Logs.Status' \
  --output text
# Expected: ENABLED

# Re-run Macie classification job on recovered data
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "post-incident-classification-$(date +%Y%m%d)" \
  --s3-job-definition '{"BucketDefinitions":[{"AccountId":"<ACCOUNT_ID>","Buckets":["<TARGET_BUCKET>"]}]}' \
  --output json | jq '.jobId'
```

#### 5.5 — Rotate All IAM Keys in Affected Account (Precautionary)

```bash
# List all IAM users with active access keys
aws iam list-users --output json | jq -r '.Users[].UserName' | while read user; do
  keys=$(aws iam list-access-keys --user-name "$user" \
    --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text)
  if [ -n "$keys" ]; then
    echo "User $user has active keys: $keys"
  fi
done
```

---

## 6. Lessons Learned

### What Would Have Prevented This

| Control Gap | Remediation |
|---|---|
| Long-term IAM access key exposed in public S3 bucket (terraform.tfvars) | Enforce `BlockPublicAcls` on all IaC state buckets; use IAM Access Analyzer to detect public bucket policies; never commit credentials to IaC state files — use Secrets Manager or SSM Parameter Store |
| No detection on anonymous GetObject from credential-bearing bucket | Enable S3 server access logging AND CloudTrail data events on all buckets; alert on anonymous access (no `userIdentity.principalId`) to any non-intentionally-public bucket |
| SSE-C PutObject not detected before full encryption completed | Deploy EventBridge rule on `PutObject` with `requestParameters.x-amz-server-side-encryption-customer-algorithm` present; alert on SIEM for SSE-C writes on buckets with no prior SSE-C history |
| Lifecycle policy modification not automatically blocked | SCPs (Service Control Policies) restricting `s3:PutBucketLifecycleConfiguration` to authorized principals only; EventBridge + Lambda auto-remediation to delete unauthorized lifecycle rules |
| Versioning suspension allowed | SCP denying `s3:PutBucketVersioning` with `Status=Suspended` for all but break-glass roles; Security Hub S3.14 control alert on versioning disable |
| Bulk DeleteObjectVersion not detected | Alert on high-volume `DeleteObjectVersion` (>10 in 60 seconds) from any single principal; require MFA Delete on all versioned buckets holding critical data |
| Long-term IAM keys in use | Enforce IAM policy requiring MFA for sensitive operations; migrate to short-term credentials via IAM Identity Center or instance roles; automated rotation for any key older than 90 days |

### Links to Guardrails

- **SCPs to deploy**: Deny `s3:PutBucketVersioning` (Suspended) and `s3:PutBucketLifecycleConfiguration` from non-admin principals
- **Security Hub controls**: S3.13 (lifecycle), S3.14 (versioning), IAM.3 (root access key), IAM.22 (unused credentials)
- **GuardDuty findings to tune**: `Impact:S3/MaliciousIPCaller.Custom`, `Discovery:IAMUser/AnomalousBehavior`, `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`
- **Kill-chain signature for SIEM**: Correlate `GetCallerIdentity` + `ListBuckets` + `ListObjectsV2` + `PutObject` (SSE-C) + `PutBucketLifecycleConfiguration` + `PutBucketVersioning` (Suspended) within a single `userIdentity.accessKeyId` session window — this 6-event sequence is the complete Codefinger ransomware signature