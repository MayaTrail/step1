# IR Playbook: ATOMIC-ses-send-abuse — AWS SES Cloud Service Hijacking

## Classification

| Field | Value |
|-------|-------|
| Incident Type | SES Account Hijacking / Spam Campaign Launch |
| Threat Actor | ATOMIC-ses-send-abuse (T1496.004) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Discovery, Impact, Defense Evasion |
| MITRE Techniques | T1496.004 — Cloud Service Hijacking |
| Detection Sources | CloudTrail, GuardDuty, SES CloudWatch Event Destinations |

---

## 1. Preparation

### Prerequisites
- CloudTrail must be enabled with management events for **sts**, **ses**, **s3**, and **secretsmanager** event sources. Data-plane SES events (SendEmail) are NOT in CloudTrail — ensure a **SES configuration set with a CloudWatch event destination** is attached to sending identities to capture send/bounce/complaint telemetry.
- GuardDuty enabled with `CredentialAccess:SecretsManagerSecret` finding type active.
- SES sending notifications (bounces, complaints) forwarded to SNS → CloudWatch or SIEM.
- S3 server-access logging enabled on campaign buckets (ListObjectsV2 / GetObject data events are not in CloudTrail management trail by default).
- IAM Access Analyzer enabled to alert on anomalous cross-account AssumeRole patterns.
- Baseline: document which IAM principals legitimately call `ses:SendEmail`, `ses:CreateEmailIdentity`, and `secretsmanager:GetSecretValue`.

---

## 2. Identification

### Detection Triggers (prioritized)

**HIGH-CONFIDENCE — these events in combination strongly indicate active SES abuse:**

| Priority | Event | Source | Signal |
|----------|-------|--------|--------|
| 1 | `CreateEmailIdentity` by non-CI/CD principal | CloudTrail / ses.amazonaws.com | Attacker registers sender identity |
| 2 | `DeleteEmailIdentity` within 60 min of `CreateEmailIdentity` | CloudTrail / ses.amazonaws.com | Immediate post-campaign cleanup — strong evasion indicator |
| 3 | `GetSecretValue` on a secret matching `*/ses*` or `*/marketing*` | CloudTrail / secretsmanager.amazonaws.com | Credential harvest for sending infrastructure |
| 4 | `PutAccountDetails` with `errorCode: AccessDenied` | CloudTrail / ses.amazonaws.com | Production-access escalation attempt |
| 5 | `UpdateAccountSendingEnabled` with `errorCode: AccessDenied` | CloudTrail / ses.amazonaws.com | Account-wide sending enablement attempt |
| 6 | `AssumeRole` into an SES-enabled role from unexpected caller | CloudTrail / sts.amazonaws.com | Initial access via role hijacking |

**MEDIUM-CONFIDENCE — individually noisy, high-value in context:**

| Priority | Event | Source | Signal |
|----------|-------|--------|--------|
| 7 | `ListIdentities` + `GetAccount` + `GetSendQuota` in same session | CloudTrail / ses.amazonaws.com | Pre-attack SES recon |
| 8 | `ListSecrets` followed by `GetSecretValue` | CloudTrail / secretsmanager.amazonaws.com | Secrets enumeration pattern |
| 9 | `ListBuckets` from an SES-related role | CloudTrail / s3.amazonaws.com | Lateral discovery of campaign materials |
| 10 | SES bounce/complaint spike from unverified identity | SES CloudWatch Event Destination | Active spam send attempt |
| 11 | GuardDuty: `CredentialAccess:SecretsManagerSecret` | GuardDuty | Automated ML-based detection of secrets access |

---

### Key Investigation Queries

#### Scope the initial AssumeRole event

```bash
# Find the AssumeRole event that kicked off the attacker session
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[?contains(CloudTrailEvent, `ses-send-abuse`) || contains(CloudTrailEvent, `ses_attacker_session`)].{Time:EventTime,User:Username,Event:CloudTrailEvent}' \
  --output table
```

```bash
# Pull the full AssumeRole event detail to get source IP, role ARN, and session name
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output json | \
  python -I -c "
import json, sys
events = json.load(sys.stdin).get('Events', [])
for e in events:
    ct = json.loads(e['CloudTrailEvent'])
    rn = ct.get('requestParameters', {}).get('roleArn', '')
    sn = ct.get('requestParameters', {}).get('roleSessionName', '')
    src = ct.get('sourceIPAddress', '')
    if 'ses' in rn.lower() or 'ses' in sn.lower():
        print(json.dumps({'time': e['EventTime'].isoformat(), 'roleArn': rn, 'sessionName': sn, 'sourceIP': src}, indent=2))
"
```

#### Reconstruct the attacker session timeline

```bash
# All SES events in the last 24 hours — find the attacker session ARN first
ATTACKER_SESSION_ARN="arn:aws:sts::<ACCOUNT_ID>:assumed-role/atomic-ses-send-abuse-attacker-role/ses_attacker_session"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="atomic-ses-send-abuse-attacker-role" \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].{Time:EventTime,Event:EventName,Source:EventSource,Error:ErrorCode}' \
  --output table
```

```bash
# SES-specific recon events: GetAccount, GetSendQuota, ListIdentities
for EVENT in GetAccount GetSendQuota ListIdentities; do
  echo "=== $EVENT ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EVENT \
    --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
    --output json | \
    python -I -c "
import json, sys
data = json.load(sys.stdin)
for e in data.get('Events', []):
    ct = json.loads(e['CloudTrailEvent'])
    print(json.dumps({'time': e['EventTime'].isoformat(), 'user': ct.get('userIdentity', {}).get('arn',''), 'ip': ct.get('sourceIPAddress','')}, indent=2))
"
done
```

```bash
# Detect CreateEmailIdentity + DeleteEmailIdentity pairing (defense evasion fingerprint)
for EVENT in CreateEmailIdentity DeleteEmailIdentity; do
  echo "=== $EVENT ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EVENT \
    --start-time $(date -u -d '48 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
    --query 'Events[*].{Time:EventTime,User:Username,Detail:CloudTrailEvent}' \
    --output json
done
```

```bash
# Find denied SES escalation attempts (do NOT filter on errorCode IS NULL)
for EVENT in PutAccountDetails UpdateAccountSendingEnabled; do
  echo "=== $EVENT (AccessDenied) ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EVENT \
    --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
    --output json | \
    python -I -c "
import json, sys
data = json.load(sys.stdin)
for e in data.get('Events', []):
    ct = json.loads(e['CloudTrailEvent'])
    print(json.dumps({
        'time': e['EventTime'].isoformat(),
        'user': ct.get('userIdentity', {}).get('arn',''),
        'errorCode': ct.get('errorCode',''),
        'errorMessage': ct.get('errorMessage',''),
        'ip': ct.get('sourceIPAddress','')
    }, indent=2))
"
done
```

```bash
# Secrets Manager harvest — list + get in same session
for EVENT in ListSecrets GetSecretValue; do
  echo "=== $EVENT ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EVENT \
    --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
    --query 'Events[*].{Time:EventTime,User:Username,Event:CloudTrailEvent}' \
    --output table
done
```

```bash
# S3 discovery event (management-plane ListBuckets)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].{Time:EventTime,User:Username}' \
  --output table
```

```bash
# Check GuardDuty findings in the last 24 hours for credential-access findings
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-criteria '{
    "Criterion": {
      "updatedAt": {"Gte": '$(date -u -d '24 hours ago' +%s000)'},
      "type": {"Equals": ["CredentialAccess:SecretsManagerSecret"]}
    }
  }' \
  --query 'FindingIds' --output json
```

```bash
# Get current SES account sending status
aws sesv2 get-account --query '{SendingEnabled:SendingEnabled,ProductionAccessEnabled:ProductionAccessEnabled,SendQuota:SendQuota}' --output table
```

```bash
# List all current SES email identities — check for attacker-registered ones
aws sesv2 list-email-identities \
  --query 'EmailIdentities[*].{Identity:IdentityName,Type:IdentityType,Verified:VerifiedForSendingStatus}' \
  --output table
```

```bash
# Check SES configuration set event destinations for CloudWatch delivery of send events
aws sesv2 list-configuration-sets --query 'ConfigurationSets' --output table

# For each config set, list event destinations
CONFIG_SET="<your-config-set-name>"
aws sesv2 get-configuration-set-event-destinations \
  --configuration-set-name $CONFIG_SET \
  --output json
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Step 1 — Identify and revoke the compromised assumed-role session

```bash
# STS-issued sessions cannot be "revoked" directly; you must deny all active sessions
# by attaching a time-based deny policy to the source IAM role

ROLE_NAME="atomic-ses-send-abuse-attacker-role"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Get the session issue time from the AssumeRole CloudTrail event (use exact value)
SESSION_ISSUE_TIME="2026-10-11T00:00:00Z"   # replace with actual from CloudTrail

# Attach deny policy for all sessions issued before now
aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "RevokeActiveSessions" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Deny\",
      \"Action\": \"*\",
      \"Resource\": \"*\",
      \"Condition\": {
        \"DateLessThan\": {
          \"aws:TokenIssueTime\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
        }
      }
    }]
  }"
```

```bash
# Verify the deny policy is attached
aws iam get-role-policy \
  --role-name "atomic-ses-send-abuse-attacker-role" \
  --policy-name "RevokeActiveSessions"
```

#### Step 2 — Disable the IAM role to prevent new sessions

```bash
# Remove all trust relationships from the role to prevent new AssumeRole
aws iam update-assume-role-policy \
  --role-name "atomic-ses-send-abuse-attacker-role" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": []
  }'
```

#### Step 3 — Delete attacker-registered SES email identity

```bash
# Delete the attacker-created identity (noreply@lab.example.com or any unrecognized identity)
# First confirm which identities are attacker-created
aws sesv2 list-email-identities --output json | \
  python -I -c "
import json, sys
data = json.load(sys.stdin)
for i in data.get('EmailIdentities', []):
    if not i.get('VerifiedForSendingStatus', True):
        print('UNVERIFIED (suspect):', i['IdentityName'])
    else:
        print('verified:', i['IdentityName'])
"

# Delete the suspect identity
aws sesv2 delete-email-identity \
  --email-identity "noreply@lab.example.com"
```

#### Step 4 — Restrict SES sending if abuse is confirmed active

```bash
# Pause all SES sending at account level (emergency measure — review before applying)
# NOTE: This affects legitimate sending. Confirm with stakeholders first.
aws sesv2 put-account-details \
  --mail-type MARKETING \
  --website-url "https://example.com" \
  --use-case-description "Emergency pause pending IR review" \
  --additional-contact-email-addresses "ehayushpathak@gmail.com"

# Alternatively: add a sending pause to the specific configuration set used in the attack
aws sesv2 create-configuration-set-event-destination \
  --configuration-set-name "<attack-config-set>" \
  --event-destination-name "EmergencyBlock" \
  --event-destination '{}'
```

#### Step 5 — Block source IP at network level if identified

```bash
# If the attacker's source IP is identified from CloudTrail
ATTACKER_IP="<IP from CloudTrail AssumeRole event>"

# Add a deny rule to the WAF or VPC Network ACL if applicable
# For API Gateway or CloudFront-fronted SES endpoints, use WAF:
aws wafv2 update-ip-set \
  --scope REGIONAL \
  --id "<ip-set-id>" \
  --name "<ip-set-name>" \
  --addresses "$ATTACKER_IP/32" \
  --lock-token $(aws wafv2 get-ip-set --scope REGIONAL --id "<ip-set-id>" --name "<ip-set-name>" --query LockToken --output text)
```

---

## 4. Eradication

### Remove Attacker Access

#### Rotate or delete the source IAM credentials used for initial AssumeRole

```bash
# Identify the calling principal that performed the AssumeRole
# From the CloudTrail event, extract userIdentity.principalId / arn
# If it was an access key:
VICTIM_USER="<username from CloudTrail>"

# List their access keys
aws iam list-access-keys --user-name "$VICTIM_USER"

# Deactivate and delete the compromised key
COMPROMISED_KEY_ID="<key ID from CloudTrail sourceIPAddress correlation>"
aws iam update-access-key \
  --user-name "$VICTIM_USER" \
  --access-key-id "$COMPROMISED_KEY_ID" \
  --status Inactive

aws iam delete-access-key \
  --user-name "$VICTIM_USER" \
  --access-key-id "$COMPROMISED_KEY_ID"
```

#### Remove all inline and managed policies from the compromised role

```bash
ROLE_NAME="atomic-ses-send-abuse-attacker-role"

# List and detach managed policies
aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --query 'AttachedPolicies[*].PolicyArn' --output text | \
  xargs -r -n1 aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn

# List and delete inline policies
for POLICY in $(aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames' --output text); do
  aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY"
done
```

#### Verify no residual attacker-created SES identities

```bash
# Confirm deletion — list all identities and verify expected set
aws sesv2 list-email-identities \
  --query 'EmailIdentities[*].{Identity:IdentityName,Verified:VerifiedForSendingStatus,Type:IdentityType}' \
  --output table
```

#### Rotate the harvested SecretsManager secret

```bash
SECRET_ID="prod/marketing/ses-sending-credentials"

# Force immediate rotation (requires rotation Lambda to be configured)
aws secretsmanager rotate-secret --secret-id "$SECRET_ID"

# If no rotation Lambda: manually put a new secret value
aws secretsmanager put-secret-value \
  --secret-id "$SECRET_ID" \
  --secret-string '{"username":"<new-value>","password":"<new-rotated-value>"}'

# Verify the new version is current
aws secretsmanager describe-secret --secret-id "$SECRET_ID" \
  --query '{Name:Name,LastRotatedDate:LastRotatedDate,VersionIdsToStages:VersionIdsToStages}'
```

#### Check for any SES suppression list additions made by attacker

```bash
# List suppression list entries added in the attack window
aws sesv2 list-suppressed-destinations \
  --start-date $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'SuppressedDestinationSummaries[*].{Email:EmailAddress,Reason:Reason,LastUpdateTime:LastUpdateTime}' \
  --output table
```

#### Verify sending reputation metrics

```bash
# Check account-level reputation metrics post-containment
aws sesv2 get-account \
  --query '{BounceRate:SendingQuota,ReputationMetrics:EnforcementState}' \
  --output json

# Check reputation metrics for specific configuration set
aws sesv2 get-configuration-set \
  --configuration-set-name "<config-set-name>" \
  --query 'ReputationOptions' \
  --output json
```

---

## 5. Recovery

### Restore Clean State

#### Re-enable the IAM role with a clean trust policy (if legitimate use case exists)

```bash
ROLE_NAME="atomic-ses-send-abuse-attacker-role"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Remove the emergency session-revocation deny policy
aws iam delete-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "RevokeActiveSessions"

# Restore a narrowly-scoped trust policy (replace with actual trusted principal)
aws iam update-assume-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Allow\",
      \"Principal\": {\"AWS\": \"arn:aws:iam::${ACCOUNT_ID}:root\"},
      \"Action\": \"sts:AssumeRole\",
      \"Condition\": {
        \"StringEquals\": {\"sts:ExternalId\": \"<known-external-id>\"}
      }
    }]
  }"
```

#### Issue fresh credentials for legitimate SES-sending workloads

```bash
# Create a new access key for the legitimate sending user
LEGITIMATE_USER="<ses-sending-service-account>"
aws iam create-access-key --user-name "$LEGITIMATE_USER"

# Update application configuration / secrets store with new key
aws secretsmanager put-secret-value \
  --secret-id "prod/marketing/ses-sending-credentials" \
  --secret-string '{"AccessKeyId":"<new-key>","SecretAccessKey":"<new-secret>"}'
```

#### Verify SES account sending health

```bash
# Confirm sending is enabled and reputation is clean
aws sesv2 get-account --output json

# Confirm no unexpected email identities remain
aws sesv2 list-email-identities --output table

# Confirm suppression list is clean
aws sesv2 list-suppressed-destinations --output table

# Test a send to the mailbox simulator to verify pipeline is healthy
aws sesv2 send-email \
  --from-email-address "sender@<your-verified-domain>" \
  --destination '{"ToAddresses":["success@simulator.amazonses.com"]}' \
  --content '{"Simple":{"Subject":{"Data":"IR Recovery Test"},"Body":{"Text":{"Data":"Verify SES healthy post-incident."}}}}'
```

#### Re-enable GuardDuty findings review

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Confirm detector is active
aws guardduty get-detector --detector-id "$DETECTOR_ID" \
  --query '{Status:Status,UpdatedAt:UpdatedAt}' --output table

# Archive the IR-related findings after remediation is confirmed
FINDING_IDS=("<finding-id-1>" "<finding-id-2>")
aws guardduty archive-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-ids "${FINDING_IDS[@]}"
```

---

## 6. Lessons Learned

### What Would Have Prevented or Shortened This Incident

| Gap | Guardrail |
|-----|-----------|
| SES data-plane events (SendEmail) are invisible in CloudTrail | Enforce a mandatory SES configuration set with CloudWatch event destination on all sending identities via SCP: `Deny ses:SendEmail` if `ses:ConfigurationSet` condition is absent |
| STS session had no IP or MFA condition | Add `aws:SourceIp` and `aws:MultiFactorAuthPresent` conditions to SES role trust policies |
| SecretsManager secret accessible from the attacker role | Apply resource-based policy on `prod/marketing/ses-sending-credentials` restricting access to the legitimate sending principal only; add GuardDuty anomaly alerting |
| `CreateEmailIdentity` not alerted in real time | Create an EventBridge rule on `ses.amazonaws.com` / `CreateEmailIdentity` that fires a PagerDuty/SNS alert for any identity not matching the approved domain allowlist |
| `DeleteEmailIdentity` immediately after `CreateEmailIdentity` not correlated | Build a correlation rule: `CreateEmailIdentity` followed by `DeleteEmailIdentity` within 60 minutes from the same principal = HIGH severity alert (the deletion itself is the evasion IOC) |
| Denied escalation attempts (`PutAccountDetails`, `UpdateAccountSendingEnabled`) were noise-suppressed | Ensure SIEM rules do **not** filter `errorCode IS NULL` — AccessDenied on SES escalation APIs is a high-signal IOC even when the action fails |
| S3 campaign bucket reachable from attacker role | Apply S3 bucket policy restricting `s3:GetObject` / `s3:ListBucket` to CI/CD roles only; enable S3 server-access logging and alert on cross-principal bucket reads |
| No SES sending budget or rate alert | Configure SES account-level sending quota CloudWatch alarm at 10% of daily quota to catch unexpected volume spikes |

### Post-Incident Actions

```bash
# Verify CloudTrail is logging all required SES management events
aws cloudtrail get-event-selectors \
  --trail-name "<your-trail-name>" \
  --output json

# Confirm GuardDuty is enabled and up to date
aws guardduty get-detector \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --output json

# List all SES configuration sets and confirm event destinations exist
aws sesv2 list-configuration-sets --output json
```