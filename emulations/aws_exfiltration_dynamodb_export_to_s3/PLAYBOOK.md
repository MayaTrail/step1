# IR Playbook: ATOMIC-dynamodb-export-to-s3 — AWS DynamoDB Bulk Exfiltration

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Cloud Data Exfiltration via Native Export API |
| Threat Actor | ATOMIC-dynamodb-export-to-s3 (technique emulation) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Collection |
| MITRE Techniques | T1530 — Data from Cloud Storage |
| Attack Surface | DynamoDB, S3, STS, IAM |

---

## 1. Preparation

### Prerequisites — Before This Incident Occurs

**Logging & Visibility**
- CloudTrail management events enabled in all regions (must include DynamoDB and STS event sources)
- S3 server access logging enabled on all data-lake and export sink buckets
- CloudTrail data events enabled on high-value S3 buckets (PutObject/GetObject)
- GuardDuty enabled with S3 and IAM threat-detection features active
- Security Hub aggregating GuardDuty, Config, and CloudTrail findings

**Baseline & Alerting**
- Alert rule: `ExportTableToPointInTime` called by any principal outside the approved backup service account
- Alert rule: `AssumeRole` where the requesting principal is an IAM user (not a service) and the assumed role grants DynamoDB read
- Alert rule: `ListTables` or `DescribeTable` from an STS session that was not issued by an approved automation pipeline
- Anomaly baseline for DynamoDB API call rates per IAM principal established in SIEM

**Access Inventory**
- Current map of all IAM roles with `dynamodb:ExportTableToPointInTime` and `dynamodb:DescribeTable` permissions
- Current map of all S3 buckets designated as export sinks (policy grants `dynamodb.amazonaws.com` `s3:PutObject`)
- PITR (Point-in-Time Recovery) status documented for all production tables — tables without PITR cannot be exported and serve as natural canaries

**Response Tooling**
- Responders have `iam:CreateAccessKey`, `iam:DeleteAccessKey`, `iam:AttachUserPolicy`, `iam:DetachRolePolicy`, `sts:GetCallerIdentity`, `dynamodb:DescribeExport`, `s3:GetObject`, `s3:DeleteObject` in their break-glass role
- `aws` CLI v2 installed; `AWS_PROFILE=incident-responder` pre-configured with MFA/break-glass credentials

---

## 2. Identification

### Detection Triggers (Prioritized)

**HIGH-CONFIDENCE — Always indicates suspicious activity**

| CloudTrail eventName | eventSource | Why It Matters |
|---|---|---|
| `ExportTableToPointInTime` | `dynamodb.amazonaws.com` | Bulk DynamoDB export; legitimate backup jobs should be rare and from known service accounts only |
| `AssumeRole` → `ListTables` → `DescribeTable` (within same session) | `sts.amazonaws.com` / `dynamodb.amazonaws.com` | Recon-before-export sequence from a single STS session is a strong exfiltration signal |
| `DescribeTable` on a table whose name contains `key`, `cred`, `secret`, `token`, or `password` | `dynamodb.amazonaws.com` | Attacker interest in credential-named tables (honey table pattern) |
| Repeated `DescribeExport` calls (>3) on same ExportArn within 10 minutes | `dynamodb.amazonaws.com` | Export-completion polling; no legitimate reason to check the same export dozens of times |

**MEDIUM-CONFIDENCE — Investigate further**

| CloudTrail eventName | eventSource | Why It Matters |
|---|---|---|
| `ListTables` from an STS session (userIdentity.type = AssumedRole) | `dynamodb.amazonaws.com` | Table enumeration from a role session; normal for automation, suspicious from interactive sessions |
| `DescribeTable` on a production PII table by a non-ETL principal | `dynamodb.amazonaws.com` | Pre-export target identification |
| `s3:PutObject` where the requester is `dynamodb.amazonaws.com` (service principal) | S3 server access logs | DynamoDB service placing export objects — correlate with a `ExportTableToPointInTime` event within the same time window |

---

### Key Investigation Queries

#### Step 1 — Identify the suspicious AssumeRole event

```bash
# Search last 24h for AssumeRole calls where an IAM user (not a service) is the requester
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)" \
  --query "Events[?contains(CloudTrailEvent, '\"type\":\"IAMUser\"')].{Time:EventTime,User:Username,Event:CloudTrailEvent}" \
  --output json
```

```bash
# Narrow to a specific suspicious role name
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=atomic-dynamodb-export-to-s3-victim-role \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.Events[] | {Time:.EventTime, Principal:.Username, RawEvent:(.CloudTrailEvent | fromjson | .userIdentity)}'
```

#### Step 2 — Trace the STS session used for DynamoDB recon

```bash
# Extract the assumed-role session credentials (AccessKeyId begins with ASIA)
# Replace ASIA... with the AccessKeyId from the AssumeRole response in CloudTrail
SESSION_KEY_ID="ASIAxxxxxxxxxxxxxxxx"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="${SESSION_KEY_ID}" \
  --output json | jq '.Events[] | {Time:.EventTime, Event:.EventName, Source:.EventSource}'
```

#### Step 3 — Enumerate DynamoDB API calls in the suspicious window

```bash
# List all DynamoDB events from the victim-role session
START="2026-01-01T00:00:00Z"   # replace with approximate incident start
END="2026-01-01T01:00:00Z"     # replace with end window

for event in ListTables DescribeTable ExportTableToPointInTime DescribeExport; do
  echo "=== $event ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="${event}" \
    --start-time "${START}" --end-time "${END}" \
    --output json | jq '.Events[] | {Time:.EventTime, User:.Username, Detail:(.CloudTrailEvent | fromjson | .requestParameters)}'
done
```

#### Step 4 — Identify the export ARN and S3 destination

```bash
# Pull ExportTableToPointInTime event details including S3 sink bucket and export ARN
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ExportTableToPointInTime \
  --start-time "${START}" --end-time "${END}" \
  --output json | jq '.Events[] | .CloudTrailEvent | fromjson | {
      TableArn: .requestParameters.tableArn,
      S3Bucket: .requestParameters.s3Bucket,
      S3Prefix: .requestParameters.s3Prefix,
      ExportArn: .responseElements.exportDescription.exportArn,
      Caller: .userIdentity
    }'
```

#### Step 5 — Check current export status

```bash
# Replace with ExportArn from Step 4
EXPORT_ARN="arn:aws:dynamodb:us-east-1:123456789012:table/prod-customers/export/01234567890123"

aws dynamodb describe-export \
  --export-arn "${EXPORT_ARN}" \
  --query 'ExportDescription.{Status:ExportStatus,TableArn:TableArn,S3Bucket:S3Bucket,S3Prefix:S3Prefix,ItemCount:ItemCount,BilledSizeBytes:BilledSizeBytes,StartTime:StartTime,EndTime:EndTime}'
```

#### Step 6 — Enumerate exported objects in the S3 sink

```bash
EXPORT_BUCKET="atomic-dynamodb-export-to-s3-export-bucket"
EXPORT_PREFIX="AWSDynamoDB/"    # DynamoDB default prefix, adjust from DescribeExport output

aws s3 ls "s3://${EXPORT_BUCKET}/${EXPORT_PREFIX}" --recursive --human-readable | sort -k1,2
```

#### Step 7 — Check S3 server access logs for DynamoDB service principal writes

```bash
# If server access logging is enabled, query the access log bucket
# Replace LOG_BUCKET with your server access log destination
LOG_BUCKET="your-s3-access-log-bucket"

aws s3 cp "s3://${LOG_BUCKET}/" . --recursive --include "*.log" \
  --exclude "*" --include "*dynamodb*" 2>/dev/null

# Or grep for DynamoDB service principal in downloaded logs
grep "dynamodb.amazonaws.com" *.log | grep "PUT" | grep "prod-customers"
```

#### Step 8 — Identify honey-table access (internal-api-keys)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeTable \
  --start-time "${START}" --end-time "${END}" \
  --output json | jq '.Events[] | .CloudTrailEvent | fromjson | select(.requestParameters.tableName == "internal-api-keys") | {
      Time: .eventTime,
      Caller: .userIdentity,
      TableName: .requestParameters.tableName
    }'
```

---

## 3. Containment

### Immediate Actions (First 15 Minutes)

#### 3.1 — Identify and disable the attacker's long-lived IAM access key

```bash
# From CloudTrail AssumeRole event, extract the calling IAM user and their access key
# userIdentity.userName and userIdentity.accessKeyId
ATTACKER_USER="attacker-iam-user"       # replace from CloudTrail
ATTACKER_KEY_ID="AKIAxxxxxxxxxxxxxxxx"  # replace from CloudTrail

# Disable the static key immediately (reversible; safer than deletion during IR)
aws iam update-access-key \
  --user-name "${ATTACKER_USER}" \
  --access-key-id "${ATTACKER_KEY_ID}" \
  --status Inactive

echo "Key ${ATTACKER_KEY_ID} for ${ATTACKER_USER} disabled"
```

#### 3.2 — Revoke the active STS session (victim-role)

```bash
# Attach a deny-all inline policy to the victim role to invalidate all active sessions
# This is the fastest way to kill STS sessions without waiting for their 1h expiry
VICTIM_ROLE="atomic-dynamodb-export-to-s3-victim-role"

aws iam put-role-policy \
  --role-name "${VICTIM_ROLE}" \
  --policy-name "INCIDENT-RESPONSE-DENY-ALL-$(date +%Y%m%d%H%M%S)" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {"aws:TokenIssueTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}
      }
    }]
  }'
```

#### 3.3 — Block access to the export sink bucket

```bash
EXPORT_BUCKET="atomic-dynamodb-export-to-s3-export-bucket"

# Option A: Enable S3 Block Public Access (if not already set)
aws s3api put-public-access-block \
  --bucket "${EXPORT_BUCKET}" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Option B: Apply a deny-all bucket policy to prevent any further reads of exported data
aws s3api put-bucket-policy \
  --bucket "${EXPORT_BUCKET}" \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "IR-DenyAllAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::'"${EXPORT_BUCKET}"'",
        "arn:aws:s3:::'"${EXPORT_BUCKET}"'/*"
      ],
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::ACCOUNT_ID:role/incident-responder-role"
        }
      }
    }]
  }'
```

#### 3.4 — Verify no active export jobs are still running

```bash
# List all in-progress exports on the prod-customers table
TABLE_ARN="arn:aws:dynamodb:us-east-1:ACCOUNT_ID:table/prod-customers"

aws dynamodb list-exports \
  --table-arn "${TABLE_ARN}" \
  --query "ExportSummaries[?ExportStatus=='IN_PROGRESS']"
```

#### 3.5 — Tag the incident on all affected resources for audit trail

```bash
INCIDENT_ID="IR-$(date +%Y%m%d)-T1530-DDB-EXPORT"

aws dynamodb tag-resource \
  --resource-arn "${TABLE_ARN}" \
  --tags Key=IncidentId,Value="${INCIDENT_ID}" Key=IncidentStatus,Value=UNDER_INVESTIGATION

aws s3api put-bucket-tagging \
  --bucket "${EXPORT_BUCKET}" \
  --tagging "TagSet=[{Key=IncidentId,Value=${INCIDENT_ID}},{Key=IncidentStatus,Value=UNDER_INVESTIGATION}]"
```

---

## 4. Eradication

### Remove Attacker Access

#### 4.1 — Delete the attacker's access key

```bash
# After IR is complete and key has been inactive long enough to confirm no false positives:
aws iam delete-access-key \
  --user-name "${ATTACKER_USER}" \
  --access-key-id "${ATTACKER_KEY_ID}"

# Audit remaining keys on this user
aws iam list-access-keys --user-name "${ATTACKER_USER}"
```

#### 4.2 — Remove the emergency deny policy and replace with permanent least-privilege

```bash
# Remove the blanket deny-all policy added during containment
DENY_POLICY_NAME="INCIDENT-RESPONSE-DENY-ALL-20260826XXXXXX"  # replace with actual name

aws iam delete-role-policy \
  --role-name "${VICTIM_ROLE}" \
  --policy-name "${DENY_POLICY_NAME}"

# Remove dynamodb:ExportTableToPointInTime from the victim role's policy if not needed
# First, identify the policy attached
aws iam list-attached-role-policies --role-name "${VICTIM_ROLE}"
aws iam list-role-policies --role-name "${VICTIM_ROLE}"

# Review and remove over-permissive policy
# aws iam detach-role-policy --role-name "${VICTIM_ROLE}" --policy-arn "arn:aws:iam::..."
```

#### 4.3 — Remove exported data from S3 sink

```bash
# List all exported objects (review before deleting)
aws s3 ls "s3://${EXPORT_BUCKET}/${EXPORT_PREFIX}" --recursive

# Delete exported data from the incident run
# CAUTION: verify the prefix is isolated to the incident export before running
aws s3 rm "s3://${EXPORT_BUCKET}/${EXPORT_PREFIX}" --recursive \
  --dryrun  # remove --dryrun after confirming correct prefix

# Verify deletion
aws s3 ls "s3://${EXPORT_BUCKET}/${EXPORT_PREFIX}" --recursive
```

#### 4.4 — Audit all IAM principals with ExportTableToPointInTime permission

```bash
# Find all policies that grant the export permission
aws iam list-policies --scope Local --query "Policies[*].Arn" --output text | \
  tr '\t' '\n' | while read -r arn; do
    # Get the default version of each policy
    VERSION=$(aws iam get-policy --policy-arn "$arn" --query 'Policy.DefaultVersionId' --output text)
    MATCHES=$(aws iam get-policy-version --policy-arn "$arn" --version-id "$VERSION" \
      --query "PolicyVersion.Document.Statement[?contains(Action,'dynamodb:ExportTableToPointInTime')]" \
      --output json)
    if [ "$MATCHES" != "[]" ] && [ -n "$MATCHES" ]; then
      echo "Policy: $arn grants ExportTableToPointInTime"
    fi
  done
```

#### 4.5 — Review and restrict trust policy on the victim role

```bash
# Review who can assume the victim role
aws iam get-role --role-name "${VICTIM_ROLE}" \
  --query 'Role.AssumeRolePolicyDocument'

# If the trust policy is overly broad (e.g., allows any IAM user in the account),
# restrict it to only the specific automation principal that legitimately needs it
aws iam update-assume-role-policy \
  --role-name "${VICTIM_ROLE}" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_ID:role/approved-backup-service-role"
      },
      "Action": "sts:AssumeRole"
    }]
  }'
```

---

## 5. Recovery

### Restore Clean State

#### 5.1 — Re-enable bucket access for legitimate services

```bash
# Replace the emergency deny policy with a proper restrictive policy
aws s3api put-bucket-policy \
  --bucket "${EXPORT_BUCKET}" \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AllowDynamoDBExportService",
        "Effect": "Allow",
        "Principal": {"Service": "dynamodb.amazonaws.com"},
        "Action": ["s3:PutObject", "s3:GetBucketLocation"],
        "Resource": [
          "arn:aws:s3:::'"${EXPORT_BUCKET}"'",
          "arn:aws:s3:::'"${EXPORT_BUCKET}"'/*"
        ],
        "Condition": {
          "StringEquals": {"aws:SourceAccount": "ACCOUNT_ID"}
        }
      }
    ]
  }'
```

#### 5.2 — Verify CloudTrail is intact and unmodified

```bash
# Confirm CloudTrail is still logging and log file validation is active
aws cloudtrail describe-trails --query "trailList[*].{Name:Name,IsLogging:IsLogging,LogFileValidation:LogFileValidationEnabled,HomeRegion:HomeRegion}"

aws cloudtrail get-trail-status --name YOUR_TRAIL_NAME \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDigestDeliveryTime:LatestDigestDeliveryTime}'

# Validate a recent log file digest (replace with actual digest ARN from trail status)
aws cloudtrail validate-logs \
  --trail-arn "arn:aws:cloudtrail:us-east-1:ACCOUNT_ID:trail/YOUR_TRAIL_NAME" \
  --start-time "${START}" --end-time "${END}"
```

#### 5.3 — Verify GuardDuty is active and findings were generated

```bash
# Check GuardDuty detector status
aws guardduty list-detectors
DETECTOR_ID="$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)"

aws guardduty get-detector --detector-id "${DETECTOR_ID}" \
  --query '{Status:Status,UpdatedAt:UpdatedAt,Features:Features[*].{Name:Name,Status:Status}}'

# List any GuardDuty findings generated during the incident window
aws guardduty list-findings \
  --detector-id "${DETECTOR_ID}" \
  --finding-criteria '{
    "Criterion": {
      "updatedAt": {
        "Gte": '"$(date -d "${START}" +%s000 2>/dev/null || echo 1700000000000)"',
        "Lte": '"$(date -d "${END}" +%s000 2>/dev/null || echo 1700003600000)"'
      }
    }
  }' \
  --output json
```

#### 5.4 — Confirm the prod-customers table is accessible and intact

```bash
TABLE_NAME="atomic-dynamodb-export-to-s3-prod-customers"

# Confirm table is ACTIVE
aws dynamodb describe-table --table-name "${TABLE_NAME}" \
  --query 'Table.{Status:TableStatus,ItemCount:ItemCount,SizeBytes:TableSizeBytes,PITR:ContinuousBackupsDescription}'

# Confirm PITR is still enabled (ExportTableToPointInTime did not touch the table data)
aws dynamodb describe-continuous-backups --table-name "${TABLE_NAME}" \
  --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription'
```

#### 5.5 — Rotate IAM credentials for any accounts that shared access with the compromised principal

```bash
# List all access keys for the attacker user (there should be none active after IR)
aws iam list-access-keys --user-name "${ATTACKER_USER}"

# If the attacker's session token touched any additional roles, rotate their long-term credentials too
# Identify by searching CloudTrail for the STS session key ID used as the source
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="${SESSION_KEY_ID}" \
  --output json | jq '.Events[] | .CloudTrailEvent | fromjson | select(.eventName == "AssumeRole") | .requestParameters'
```

#### 5.6 — Place a monitoring alert specifically on the honey table

```bash
# Create a CloudWatch metric filter to alert on DescribeTable for the honey table
LOG_GROUP="/aws/cloudtrail/management-events"  # adjust to your CloudTrail log group

aws logs put-metric-filter \
  --log-group-name "${LOG_GROUP}" \
  --filter-name "HoneyTableAccess-internal-api-keys" \
  --filter-pattern '{ ($.eventName = "DescribeTable" || $.eventName = "Scan" || $.eventName = "GetItem") && $.requestParameters.tableName = "internal-api-keys" }' \
  --metric-transformations \
    metricName="HoneyTableAccess",metricNamespace="SecurityAlerts",metricValue=1,defaultValue=0

aws cloudwatch put-metric-alarm \
  --alarm-name "ALERT-HoneyTable-internal-api-keys-Access" \
  --alarm-description "Any access to honey DynamoDB table internal-api-keys" \
  --metric-name "HoneyTableAccess" \
  --namespace "SecurityAlerts" \
  --period 60 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --statistic Sum \
  --alarm-actions "arn:aws:sns:us-east-1:ACCOUNT_ID:security-alerts-topic"
```

---

## 6. Lessons Learned

### What Would Have Prevented or Shortened This Incident

| Gap | Guardrail |
|---|---|
| IAM user had a long-lived static access key with `sts:AssumeRole` into a data-access role | Enforce IAM Identity Center (SSO) for human access; eliminate long-lived IAM user access keys |
| Victim role's trust policy allowed any IAM user in the account to assume it | Restrict trust policies to specific, named service principals only; deny `sts:AssumeRole` to IAM users via SCP |
| No alert fired on `ExportTableToPointInTime` | Create EventBridge rule on `ExportTableToPointInTime` from any non-approved principal; page on-call immediately |
| DynamoDB export bypasses per-item CloudTrail (no `GetItem`/`Scan` visibility) | Treat `ExportTableToPointInTime` as equivalent to full table read; monitor the control-plane call, not data-plane access |
| Export sink bucket accepted writes from any `AssumeRole` session | Restrict `s3:PutObject` on export sink to `dynamodb.amazonaws.com` service principal with `aws:SourceAccount` condition; deny all IAM sessions |
| Honey table (`internal-api-keys`) had no alert configured | All credential-named or honey tables must have a CloudWatch alarm on any `DescribeTable` or data access; treat any access as confirmed compromise |
| PITR status difference between tables not monitored | Alert on `UpdateContinuousBackups` disabling PITR — a pre-export step attacker would take if PITR were not already on |

### Detection Timeline Summary

| T+ | Event | Detection Opportunity |
|---|---|---|
| 0:00 | `AssumeRole` — IAM user → victim-role | GuardDuty IAMUser finding; CloudTrail alert |
| 0:01 | `ListTables` from STS session | Medium-confidence alert on table enumeration |
| 0:02 | `DescribeTable` on `prod-customers` | Pre-export recon signal |
| 0:03 | `DescribeTable` on `internal-api-keys` | HIGH — honey table access; should trigger immediate page |
| 0:04 | `ExportTableToPointInTime` | HIGH — bulk export trigger; EventBridge rule should page |
| 0:04–10:00 | Repeated `DescribeExport` polls | Confirms exfiltration in progress; window to contain before `COMPLETED` |
| ~10:00 | Export `COMPLETED`; data in S3 sink | Full exfiltration; containment shifts to data-at-rest controls |

### Recommended SCP Guardrails (AWS Organizations)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDynamoDBExportFromIAMUsers",
      "Effect": "Deny",
      "Action": "dynamodb:ExportTableToPointInTime",
      "Resource": "*",
      "Condition": {
        "StringEquals": {"aws:PrincipalType": "User"}
      }
    },
    {
      "Sid": "DenyAssumeRoleByIAMUserToDataRoles",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/*data*",
      "Condition": {
        "StringEquals": {"aws:PrincipalType": "User"}
      }
    }
  ]
}
```