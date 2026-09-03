# IR Playbook: ATOMIC-cognito-identity-pool-unauth-creds — AWS

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Unauthenticated Cognito Identity Pool Credential Abuse / Cloud Data Exfiltration |
| Threat Actor | ATOMIC-cognito-identity-pool-unauth-creds (technique emulation) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Initial Access, Discovery, Credential Access, Collection |
| MITRE Technique | T1078.004 — Valid Accounts: Cloud Accounts |
| Primary Detection Surface | CloudTrail: anonymous/unauthenticated principal on Cognito GetId + GetCredentialsForIdentity |

---

## 1. Preparation

### Prerequisites

- **CloudTrail**: Management events enabled in all regions; data events enabled for S3 `GetObject` and `ListObjects` on sensitive buckets.
- **Athena / CloudTrail Lake**: Query capability over CloudTrail logs for the affected account.
- **GuardDuty**: Enabled with Cognito protection feature on (detects `UnauthorizedAccess:IAMUser/AnomalousBehavior` and Cognito-specific findings).
- **IAM Access Analyzer**: Scans for resource-based policies allowing anonymous access.
- **Cognito Monitoring**: CloudWatch metrics enabled for identity pool; alerts on `GetId` and `GetCredentialsForIdentity` error/success spikes from anonymous callers.
- **S3 Data Events**: CloudTrail data events enabled for target sensitive buckets.
- **Incident Response runbook access**: This document available offline.
- **Least-privilege IAM roles** for responders: read-only CloudTrail/CloudWatch role, break-glass remediation role.

### Hardening Checks That Should Be in Place

| Control | Expected State |
|---------|---------------|
| `AllowUnauthenticatedIdentities` on all Cognito pools | `false` unless explicitly required |
| Unauthenticated Cognito IAM role has no S3/data-plane permissions | Policy uses deny-all or minimal read |
| Cognito unauth role trust policy restricts to specific pool via `Condition cognito-identity:amr: unauthenticated` | Present |
| S3 bucket policy denies `s3:GetObject` to `cognito-identity.amazonaws.com` service principal | Present |
| GuardDuty anomaly detection for IAM role assumption from new IP | Enabled |

---

## 2. Identification

### Detection Triggers

#### HIGH-CONFIDENCE — These events together always indicate this attack pattern

| # | Event Name | Event Source | Principal Type | What It Means |
|---|------------|--------------|----------------|---------------|
| 1 | `GetId` | `cognito-identity.amazonaws.com` | **Anonymous / unauthenticated** (no `userIdentity.arn`) | Attacker acquiring Cognito IdentityId without credentials |
| 2 | `GetCredentialsForIdentity` | `cognito-identity.amazonaws.com` | **Anonymous / unauthenticated** | Attacker obtaining STS temp creds from unauthenticated identity pool path |
| 3 | `GetCallerIdentity` | `sts.amazonaws.com` | Unauth Cognito role session | Attacker verifying the acquired credentials work |
| 4 | `GetObject` (sensitive key) | `s3.amazonaws.com` | Unauth Cognito role session | Data exfiltration using the acquired credentials |

#### MEDIUM-CONFIDENCE — Precursor or corroborating events

| # | Event Name | Event Source | Principal Type | What It Means |
|---|------------|--------------|----------------|---------------|
| A | `AssumeRole` | `sts.amazonaws.com` | Long-lived IAM user key | Attacker pivoting from static credentials to role session for enumeration |
| B | `ListIdentityPools` | `cognito-identity.amazonaws.com` | Role session (victim-role) | Attacker enumerating all Cognito identity pools to find misconfigured target |
| C | `DescribeIdentityPool` | `cognito-identity.amazonaws.com` | Role session (victim-role) | Attacker confirming `AllowUnauthenticatedIdentities=true` before exploiting |
| D | `ListObjects` | `s3.amazonaws.com` | Unauth Cognito role session | Attacker enumerating bucket contents before downloading |

---

### Key Investigation Queries

#### Step 1 — Find all anonymous Cognito GetId/GetCredentialsForIdentity calls in time window

```bash
# Search last 24 hours — narrow window after alert fires
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetId \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --end-time "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --query "Events[?contains(CloudTrailEvent, '\"errorCode\"') == \`false\`].{Time:EventTime,Name:EventName,Source:EventSource,ID:EventId}" \
  --output table

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetCredentialsForIdentity \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --end-time "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --output json
```

#### Step 2 — Identify the identity pool exploited and confirm anonymous principal

```bash
# Extract raw CloudTrail event JSON to check userIdentity type (should be "Unknown" or missing arn)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetCredentialsForIdentity \
  --start-time "$(date -u -d '48 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --output json \
  | python3 -c "
import json, sys
events = json.load(sys.stdin)['Events']
for e in events:
    ct = json.loads(e['CloudTrailEvent'])
    uid = ct.get('userIdentity', {})
    print('Time:', ct['eventTime'])
    print('Pool/IdentityId:', ct.get('requestParameters', {}))
    print('UserIdentity type:', uid.get('type'), '| arn:', uid.get('arn', 'NONE - anonymous'))
    print('SourceIP:', ct.get('sourceIPAddress'))
    print('---')
"
```

#### Step 3 — Confirm which identity pool has AllowUnauthenticatedIdentities enabled

```bash
# List all identity pools in the region and check for misconfiguration
aws cognito-identity list-identity-pools \
  --max-results 60 \
  --region us-east-1 \
  --output json \
  | python3 -c "
import json, sys, subprocess
data = json.load(sys.stdin)
for pool in data.get('IdentityPools', []):
    pid = pool['IdentityPoolId']
    name = pool['IdentityPoolName']
    desc = json.loads(subprocess.check_output([
        'aws','cognito-identity','describe-identity-pool',
        '--identity-pool-id', pid,
        '--region','us-east-1','--output','json'
    ]))
    unauth = desc.get('AllowUnauthenticatedIdentities', False)
    print(f'[{\"VULNERABLE\" if unauth else \"ok\"}] {name} ({pid}) - unauthenticated={unauth}')
"
```

#### Step 4 — Find the unauth role ARN and trace all actions it performed

```bash
# First find the unauth role — check pool's role attachment
POOL_ID="us-east-1:REPLACE_WITH_POOL_ID"
aws cognito-identity get-identity-pool-roles \
  --identity-pool-id "$POOL_ID" \
  --region us-east-1 \
  --query "Roles.unauthenticated"

# Then look up CloudTrail events for sessions assuming that role
UNAUTH_ROLE_ARN="arn:aws:iam::ACCOUNT_ID:role/REPLACE_UNAUTH_ROLE_NAME"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$UNAUTH_ROLE_ARN" \
  --start-time "$(date -u -d '48 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --output json
```

#### Step 5 — Identify S3 data exfiltration events from the unauth Cognito session

```bash
# Look for S3 data events (requires S3 data events enabled in CloudTrail)
TARGET_BUCKET="REPLACE_WITH_BUCKET_NAME"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --output json \
  | python3 -c "
import json, sys
events = json.load(sys.stdin)['Events']
for e in events:
    ct = json.loads(e['CloudTrailEvent'])
    resources = ct.get('resources', [])
    for r in resources:
        if '$TARGET_BUCKET' in r.get('ARN',''):
            print('Time:', ct['eventTime'])
            print('Key:', ct.get('requestParameters',{}).get('key','?'))
            print('Principal:', ct.get('userIdentity',{}).get('arn','anonymous'))
            print('SourceIP:', ct.get('sourceIPAddress'))
            print('---')
"

# Also check ListObjects
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListObjects \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --output json
```

#### Step 6 — Find the upstream attacker IAM user (the AssumeRole pivot)

```bash
# Find AssumeRole events that targeted the victim-role
VICTIM_ROLE_NAME="REPLACE_VICTIM_ROLE_NAME"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '48 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --output json \
  | python3 -c "
import json, sys
events = json.load(sys.stdin)['Events']
for e in events:
    ct = json.loads(e['CloudTrailEvent'])
    rp = ct.get('requestParameters', {})
    ra = rp.get('roleArn', '')
    if '$VICTIM_ROLE_NAME' in ra:
        uid = ct.get('userIdentity', {})
        print('Time:', ct['eventTime'])
        print('Attacker principal:', uid.get('arn', uid.get('userName', '?')))
        print('Attacker access key:', uid.get('accessKeyId', '?'))
        print('SourceIP:', ct.get('sourceIPAddress'))
        print('Session name used:', rp.get('roleSessionName','?'))
        print('---')
"
```

#### Step 7 — Check GuardDuty for correlated findings

```bash
# List GuardDuty detectors
DETECTOR_ID=$(aws guardduty list-detectors --region us-east-1 --query 'DetectorIds[0]' --output text)

# Get high/critical severity findings in last 48h
aws guardduty list-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-criteria '{
    "Criterion": {
      "severity": {"Gte": 7},
      "updatedAt": {"Gte": '"$(date -d '48 hours ago' +%s000)"'}
    }
  }' \
  --region us-east-1 \
  --output json

# Get finding details
FINDING_IDS=$(aws guardduty list-findings --detector-id "$DETECTOR_ID" \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' \
  --query 'FindingIds' --output json --region us-east-1)
aws guardduty get-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-ids $FINDING_IDS \
  --region us-east-1
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### 3.1 — Disable the unauthenticated access on the compromised identity pool

```bash
POOL_ID="us-east-1:REPLACE_WITH_POOL_ID"
REGION="us-east-1"

# Get current pool configuration
POOL_CONFIG=$(aws cognito-identity describe-identity-pool \
  --identity-pool-id "$POOL_ID" \
  --region "$REGION" \
  --output json)

# Update pool to disable unauthenticated identities
POOL_NAME=$(echo "$POOL_CONFIG" | python3 -c "import json,sys; print(json.load(sys.stdin)['IdentityPoolName'])")

aws cognito-identity update-identity-pool \
  --identity-pool-id "$POOL_ID" \
  --identity-pool-name "$POOL_NAME" \
  --no-allow-unauthenticated-identities \
  --region "$REGION"

echo "[OK] AllowUnauthenticatedIdentities disabled on $POOL_ID"

# Verify
aws cognito-identity describe-identity-pool \
  --identity-pool-id "$POOL_ID" \
  --region "$REGION" \
  --query "AllowUnauthenticatedIdentities"
```

#### 3.2 — Attach an explicit deny policy to the unauthenticated IAM role

```bash
UNAUTH_ROLE_NAME="REPLACE_UNAUTH_ROLE_NAME"

# Attach a deny-all inline policy as an immediate circuit breaker
aws iam put-role-policy \
  --role-name "$UNAUTH_ROLE_NAME" \
  --policy-name "INCIDENT-RESPONSE-DENY-ALL" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "IncidentResponseDenyAll",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'

echo "[OK] Deny-all inline policy attached to $UNAUTH_ROLE_NAME"
```

#### 3.3 — Revoke all active sessions for the unauth role (invalidate outstanding STS tokens)

```bash
UNAUTH_ROLE_NAME="REPLACE_UNAUTH_ROLE_NAME"

# AWS STS credentials cannot be directly revoked, but adding a
# time-based deny to the role policy invalidates all sessions issued before now
REVOKE_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

aws iam put-role-policy \
  --role-name "$UNAUTH_ROLE_NAME" \
  --policy-name "INCIDENT-RESPONSE-REVOKE-SESSIONS" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Sid\": \"RevokeOldSessions\",
      \"Effect\": \"Deny\",
      \"Action\": \"*\",
      \"Resource\": \"*\",
      \"Condition\": {
        \"DateLessThan\": {
          \"aws:TokenIssueTime\": \"$REVOKE_TIME\"
        }
      }
    }]
  }"

echo "[OK] Session revocation policy applied - all tokens issued before $REVOKE_TIME are now denied"
```

#### 3.4 — Disable attacker IAM user access keys

```bash
ATTACKER_USER="REPLACE_ATTACKER_IAM_USERNAME"

# List their access keys
KEYS=$(aws iam list-access-keys --user-name "$ATTACKER_USER" --output json)
echo "$KEYS"

# Deactivate all keys for that user
echo "$KEYS" | python3 -c "
import json, sys, subprocess
data = json.load(sys.stdin)
for key in data.get('AccessKeyMetadata', []):
    kid = key['AccessKeyId']
    subprocess.run([
        'aws','iam','update-access-key',
        '--user-name','$ATTACKER_USER',
        '--access-key-id', kid,
        '--status','Inactive'
    ], check=True)
    print('[OK] Deactivated key:', kid)
"
```

#### 3.5 — Block S3 bucket access as emergency measure

```bash
TARGET_BUCKET="REPLACE_TARGET_BUCKET_NAME"

# Add a bucket policy deny for the unauth role ARN
UNAUTH_ROLE_ARN="arn:aws:iam::ACCOUNT_ID:role/REPLACE_UNAUTH_ROLE_NAME"

# Get existing policy (if any)
EXISTING=$(aws s3api get-bucket-policy --bucket "$TARGET_BUCKET" --output json 2>/dev/null || echo '{"Policy":"{}"}')

aws s3api put-bucket-policy --bucket "$TARGET_BUCKET" --policy "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [{
    \"Sid\": \"IncidentResponseDenyUnauthCognitoRole\",
    \"Effect\": \"Deny\",
    \"Principal\": {\"AWS\": \"$UNAUTH_ROLE_ARN\"},
    \"Action\": [\"s3:GetObject\",\"s3:ListBucket\"],
    \"Resource\": [
      \"arn:aws:s3:::$TARGET_BUCKET\",
      \"arn:aws:s3:::$TARGET_BUCKET/*\"
    ]
  }]
}"

echo "[OK] Explicit deny applied to bucket $TARGET_BUCKET for $UNAUTH_ROLE_ARN"
```

#### 3.6 — Revoke victim-role sessions (used for pool enumeration)

```bash
VICTIM_ROLE_NAME="REPLACE_VICTIM_ROLE_NAME"
REVOKE_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

aws iam put-role-policy \
  --role-name "$VICTIM_ROLE_NAME" \
  --policy-name "INCIDENT-RESPONSE-REVOKE-SESSIONS" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Sid\": \"RevokeOldSessions\",
      \"Effect\": \"Deny\",
      \"Action\": \"*\",
      \"Resource\": \"*\",
      \"Condition\": {
        \"DateLessThan\": {
          \"aws:TokenIssueTime\": \"$REVOKE_TIME\"
        }
      }
    }]
  }"

echo "[OK] Victim-role sessions revoked before $REVOKE_TIME"
```

---

## 4. Eradication

### 4.1 — Remove attacker IAM user's access keys entirely

```bash
ATTACKER_USER="REPLACE_ATTACKER_IAM_USERNAME"

# Delete all access keys (not just deactivate)
KEYS=$(aws iam list-access-keys --user-name "$ATTACKER_USER" --query 'AccessKeyMetadata[*].AccessKeyId' --output text)
for KEY in $KEYS; do
  aws iam delete-access-key --user-name "$ATTACKER_USER" --access-key-id "$KEY"
  echo "[OK] Deleted access key $KEY for $ATTACKER_USER"
done
```

### 4.2 — Remove or remediate the unauth role's permissive policies

```bash
UNAUTH_ROLE_NAME="REPLACE_UNAUTH_ROLE_NAME"

# List all attached managed policies
aws iam list-attached-role-policies --role-name "$UNAUTH_ROLE_NAME" --output table

# List inline policies
aws iam list-role-policies --role-name "$UNAUTH_ROLE_NAME" --output table

# Review the inline policy granting S3 access and remove it
POLICY_TO_REMOVE="REPLACE_INLINE_POLICY_NAME_GRANTING_S3"
aws iam delete-role-policy \
  --role-name "$UNAUTH_ROLE_NAME" \
  --policy-name "$POLICY_TO_REMOVE"

# If a managed policy grants S3 access, detach it
MANAGED_POLICY_ARN="arn:aws:iam::ACCOUNT_ID:policy/REPLACE_MANAGED_POLICY"
aws iam detach-role-policy \
  --role-name "$UNAUTH_ROLE_NAME" \
  --policy-arn "$MANAGED_POLICY_ARN"

echo "[OK] Over-permissive policies removed from $UNAUTH_ROLE_NAME"
```

### 4.3 — Harden the unauth role trust policy to require pool-specific condition

```bash
UNAUTH_ROLE_NAME="REPLACE_UNAUTH_ROLE_NAME"
POOL_ID="us-east-1:REPLACE_WITH_POOL_ID"

# A properly locked-down trust policy for an unauth role (if role must remain)
aws iam update-assume-role-policy \
  --role-name "$UNAUTH_ROLE_NAME" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Allow\",
      \"Principal\": {\"Federated\": \"cognito-identity.amazonaws.com\"},
      \"Action\": \"sts:AssumeRoleWithWebIdentity\",
      \"Condition\": {
        \"StringEquals\": {
          \"cognito-identity.amazonaws.com:aud\": \"$POOL_ID\"
        },
        \"ForAnyValue:StringLike\": {
          \"cognito-identity.amazonaws.com:amr\": \"unauthenticated\"
        }
      }
    }]
  }"

echo "[OK] Trust policy on $UNAUTH_ROLE_NAME locked to specific pool $POOL_ID"
```

### 4.4 — Remove IR emergency policies after root cause is fixed

```bash
UNAUTH_ROLE_NAME="REPLACE_UNAUTH_ROLE_NAME"
VICTIM_ROLE_NAME="REPLACE_VICTIM_ROLE_NAME"

# Remove the incident-response inline policies added during containment
for ROLE in "$UNAUTH_ROLE_NAME" "$VICTIM_ROLE_NAME"; do
  aws iam delete-role-policy \
    --role-name "$ROLE" \
    --policy-name "INCIDENT-RESPONSE-DENY-ALL" 2>/dev/null && \
    echo "[OK] Removed INCIDENT-RESPONSE-DENY-ALL from $ROLE"
  aws iam delete-role-policy \
    --role-name "$ROLE" \
    --policy-name "INCIDENT-RESPONSE-REVOKE-SESSIONS" 2>/dev/null && \
    echo "[OK] Removed INCIDENT-RESPONSE-REVOKE-SESSIONS from $ROLE"
done
```

### 4.5 — Assess data exposure scope

```bash
TARGET_BUCKET="REPLACE_TARGET_BUCKET_NAME"
INCIDENT_START="REPLACE_YYYY-MM-DDTHH:MM:SSZ"

# Check what objects were accessed during the incident window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time "$INCIDENT_START" \
  --region us-east-1 \
  --output json \
  | python3 -c "
import json, sys
events = json.load(sys.stdin)['Events']
accessed = set()
for e in events:
    ct = json.loads(e['CloudTrailEvent'])
    rp = ct.get('requestParameters', {})
    bucket = rp.get('bucketName','')
    key = rp.get('key','')
    if '$TARGET_BUCKET' in bucket:
        accessed.add(f's3://{bucket}/{key}')
        print('Accessed:', ct['eventTime'], f's3://{bucket}/{key}',
              '| from IP:', ct.get('sourceIPAddress'))
print()
print('Total unique objects accessed:', len(accessed))
for obj in sorted(accessed):
    print(' ', obj)
"
```

---

## 5. Recovery

### 5.1 — Re-enable security services and verify pool is locked down

```bash
POOL_ID="us-east-1:REPLACE_WITH_POOL_ID"
REGION="us-east-1"

# Verify unauthenticated identities are disabled
UNAUTH_ENABLED=$(aws cognito-identity describe-identity-pool \
  --identity-pool-id "$POOL_ID" \
  --region "$REGION" \
  --query "AllowUnauthenticatedIdentities" \
  --output text)

if [ "$UNAUTH_ENABLED" = "False" ]; then
  echo "[OK] Pool $POOL_ID: AllowUnauthenticatedIdentities=false"
else
  echo "[FAIL] Pool $POOL_ID still allows unauthenticated identities - re-run containment step 3.1"
fi
```

### 5.2 — Rotate credentials for any service accounts that had access to the target bucket

```bash
# Identify all IAM principals with GetObject on the target bucket
# (manual review step — use IAM Access Analyzer findings)
aws accessanalyzer list-findings \
  --analyzer-arn "arn:aws:access-analyzer:us-east-1:ACCOUNT_ID:analyzer/REPLACE_ANALYZER_NAME" \
  --filter '{"resourceType":{"eq":["AWS::S3::Bucket"]}}' \
  --region us-east-1 \
  --output table
```

### 5.3 — Verify no Cognito-issued identities with active sessions remain

```bash
POOL_ID="us-east-1:REPLACE_WITH_POOL_ID"
REGION="us-east-1"

# List identities in the pool and look for suspicious unauth entries
aws cognito-identity list-identities \
  --identity-pool-id "$POOL_ID" \
  --max-results 60 \
  --region "$REGION" \
  --output json \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for identity in data.get('Identities', []):
  logins = identity.get('Logins', [])
  if not logins:
    print('[SUSPICIOUS - unauth] IdentityId:', identity['IdentityId'],
          'Created:', identity.get('CreationDate'), 'LastModified:', identity.get('LastModifiedDate'))
  else:
    print('[ok] IdentityId:', identity['IdentityId'], '| Logins:', logins)
"

# Delete suspicious anonymous identity entries
# aws cognito-identity delete-identities \
#   --identity-ids-to-delete "us-east-1:REPLACE_SUSPICIOUS_IDENTITY_ID" \
#   --region "$REGION"
```

### 5.4 — Validate S3 bucket hardening

```bash
TARGET_BUCKET="REPLACE_TARGET_BUCKET_NAME"

# Confirm bucket is not publicly accessible
aws s3api get-bucket-policy-status --bucket "$TARGET_BUCKET" \
  --query "PolicyStatus.IsPublic" --output text

aws s3api get-public-access-block --bucket "$TARGET_BUCKET" --output table

# Confirm bucket encryption is on
aws s3api get-bucket-encryption --bucket "$TARGET_BUCKET" --output table

# Confirm access logging is configured
aws s3api get-bucket-logging --bucket "$TARGET_BUCKET" --output table
```

### 5.5 — Enable detective controls to alert on recurrence

```bash
REGION="us-east-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Create CloudWatch metric filter for future anonymous Cognito GetId calls
LOG_GROUP="/aws/cloudtrail/management-events"  # adjust if using CloudTrail Lake

# Create SNS topic for alerting
SNS_ARN=$(aws sns create-topic --name "cognito-anonymous-access-alert" \
  --region "$REGION" --query TopicArn --output text)
aws sns subscribe --topic-arn "$SNS_ARN" \
  --protocol email --notification-endpoint "REPLACE_SECURITY_TEAM_EMAIL" \
  --region "$REGION"

# Create CloudWatch alarm on Cognito GetId from anonymous principal
# (requires metric filter on CloudTrail log group)
aws cloudwatch put-metric-alarm \
  --alarm-name "Cognito-Anonymous-GetId-Alert" \
  --alarm-description "Anonymous Cognito GetId detected - potential unauth credential abuse" \
  --metric-name "AnonymousCognitoGetId" \
  --namespace "Security/CognitoAbuse" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "$SNS_ARN" \
  --region "$REGION"

echo "[OK] Alert configured: $SNS_ARN"
```

---

## 6. Lessons Learned

### Root Cause

The identity pool was provisioned with `AllowUnauthenticatedIdentities=true` and the automatically created unauthenticated IAM role was granted `s3:GetObject` on a bucket containing sensitive PII and application credentials. Any actor on the internet — with zero AWS credentials — could call `GetId` + `GetCredentialsForIdentity` (both unsigned requests) and obtain valid STS credentials scoped to the overpermissioned unauth role.

### What Would Have Prevented This

| Guardrail | Prevents |
|-----------|---------|
| `AllowUnauthenticatedIdentities=false` by default in IaC | Step 4 (GetId) — no anonymous flow |
| Cognito unauth role has deny-all inline policy unless explicitly required | Step 5-9 — credentials useless even if obtained |
| S3 bucket policy: deny `s3:GetObject` to `cognito-identity.amazonaws.com` service | Steps 7-9 — no data exfiltration even with credentials |
| IAM Access Analyzer scan in CI/CD: fail on public/anonymous resource access | Caught before deployment |
| GuardDuty Cognito Protection enabled: would fire `CredentialAccess:Cognito/AnomalousBehavior` | Faster detection |
| CloudWatch alarm on anonymous `GetId`/`GetCredentialsForIdentity` events | Alert within 5 minutes of Step 4 |
| AWS Config rule: `cognito-identity-pool-no-unauthenticated-identities` | Continuous compliance signal |

### Timeline Reconstruction Queries (Post-Incident)

```bash
# Build full attacker timeline across all sessions
REGION="us-east-1"
INCIDENT_START="REPLACE_YYYY-MM-DDTHH:MM:SSZ"
INCIDENT_END="REPLACE_YYYY-MM-DDTHH:MM:SSZ"

for EVENT in AssumeRole ListIdentityPools DescribeIdentityPool GetId \
             GetCredentialsForIdentity GetCallerIdentity ListObjects GetObject; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVENT" \
    --start-time "$INCIDENT_START" \
    --end-time "$INCIDENT_END" \
    --region "$REGION" \
    --output json \
    | python3 -c "
import json,sys
events=json.load(sys.stdin)['Events']
for e in events:
    ct=json.loads(e['CloudTrailEvent'])
    print(ct['eventTime'],'|','$EVENT','| principal:', ct.get('userIdentity',{}).get('arn','ANONYMOUS'),'| ip:', ct.get('sourceIPAddress'))
" 2>/dev/null
done | sort
```

### MITRE Coverage Map

| Attack Step | MITRE ID | Technique | Detection Event |
|-------------|----------|-----------|-----------------|
| Static key -> AssumeRole pivot | T1078.004 | Valid Accounts: Cloud | `AssumeRole` (attacker user) |
| ListIdentityPools enumeration | T1078.004 | Valid Accounts: Cloud | `ListIdentityPools` (victim-role) |
| DescribeIdentityPool misconfiguration check | T1078.004 | Valid Accounts: Cloud | `DescribeIdentityPool` (victim-role) |
| GetId unsigned (anonymous) | T1078.004 | Valid Accounts: Cloud | `GetId` — **anonymous principal** |
| GetCredentialsForIdentity unsigned | T1078.004 | Valid Accounts: Cloud | `GetCredentialsForIdentity` — **anonymous principal** |
| GetCallerIdentity verification | T1078.004 | Valid Accounts: Cloud | `GetCallerIdentity` (unauth-role session) |
| ListObjects S3 enumeration | T1078.004 | Valid Accounts: Cloud | `ListObjects` (unauth-role session) |
| GetObject config exfiltration | T1530 | Data from Cloud Storage | `GetObject config/app-backend-config.json` |
| GetObject PII export exfiltration | T1530 | Data from Cloud Storage | `GetObject exports/registered-users-2026-07.csv` |