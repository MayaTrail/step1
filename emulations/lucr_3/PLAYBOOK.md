# IR Playbook: LUCR-3 (Scattered Spider) — Multi-Cloud Identity-First Attack

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Identity Compromise / Multi-Cloud Data Exfiltration |
| Threat Actor | LUCR-3 (aka Scattered Spider, Oktapus, UNC3944, STORM-0875) |
| Platform | multi_cloud (Okta, AWS, M365/SharePoint, GitHub) |
| Severity | Critical |
| Motivation | Financial extortion via IP theft; ransom demands in tens of millions USD |
| MITRE Tactics | Initial Access, Credential Access, Persistence, Discovery, Collection, Defense Evasion, Lateral Movement |
| MITRE Techniques | T1078.004, T1621, T1111, T1098.005, T1213.002, T1580, T1619, T1082, T1098, T1136.003, T1098.001, T1555.006, T1578.002, T1550.001, T1562.001, T1562.008, T1021.004, T1072, T1070.008, T1530, T1213.003 |
| Tools Used | S3 Browser 10.9.9, AWS CloudShell, AWS Management Console, SCCM, GitHub |

---

## 1. Preparation

### Required Capabilities (must be in place before incident)

**Okta**
- Okta System Log streaming to SIEM (Splunk/Sentinel) with < 5-minute latency
- Okta ThreatInsight enabled in `Log and Enforce` mode
- MFA enrollment policies require phishing-resistant factors (FIDO2/WebAuthn) — SMS/TOTP as fallback only
- Okta behavior detection rules: new country, new device, impossible travel
- Helpdesk identity verification process (video call + manager approval) for any MFA reset or factor enrollment
- Network Zones defined for corporate IP ranges; alerts on logins from unlisted zones

**AWS**
- CloudTrail multi-region trail enabled and writing to immutable S3 bucket (Object Lock, WORM)
- GuardDuty enabled in all regions; findings forwarded to Security Hub and SIEM
- AWS Security Hub enabled with CIS AWS Foundations Benchmark and AWS Foundational Security Best Practices standards
- S3 server access logging enabled on all buckets (independent of CloudTrail)
- SNS alert on CloudTrail `StopLogging` and `UpdateDetector` events via EventBridge rule
- IAM Access Analyzer enabled; alerting on new cross-account trust policies
- AWS Config rule: `iam-no-inline-policy-check`, `iam-user-mfa-enabled`, `guardduty-enabled-centralized`
- SCPs blocking `guardduty:DeleteDetector`, `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail` from non-admin OUs

**M365 / Azure AD**
- Unified Audit Log enabled and retained for 90+ days
- Microsoft Defender for Cloud Apps (MCAS) connected; impossible travel and mass download policies active
- Conditional Access policies: require compliant device + MFA for all SharePoint access
- Azure AD Identity Protection: risk-based CA policy blocking high-risk sign-ins

**GitHub**
- GitHub Audit Log streaming to SIEM
- GitHub Advanced Security: secret scanning enabled on all repos
- PAT expiration policy enforced (max 90 days); fine-grained PATs required for new tokens
- GitHub `personal_access_token.create` events monitored in SIEM

**General**
- On-call runbook and escalation tree documented and tested
- IR retainer with forensic partner active
- Canary tokens deployed: bait secrets in SecretsManager, bait Terraform state file, bait GitHub PAT — all with alerting on access
- SIEM correlation rule: `CreateUser` + `AttachUserPolicy(AdministratorAccess)` + `CreateAccessKey` within 10 minutes from same principal

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Indicates Active Compromise

| Platform | Event | Why High-Confidence |
|----------|-------|---------------------|
| Okta | `user.mfa.factor.activate` from non-corporate IP | Attacker enrolling their own device (T1098.005) |
| AWS CloudTrail | `StopLogging` on active CloudTrail trail | Almost always attacker pre-exfil action (T1562.008) |
| AWS CloudTrail | `UpdateDetector` disabling GuardDuty | LUCR-3 signature move before bulk exfil (T1562.001) |
| AWS CloudTrail | `CreateUser` + `CreateLoginProfile` + `AttachUserPolicy` within 10 min | Backdoor IAM user creation sequence (T1136.003 + T1098) |
| AWS CloudTrail | `AssumeRoleWithSAML` from anomalous IP | IDP-to-AWS pivot (T1078.004) |
| AWS SecretsManager | `GetSecretValue` on canary/bait secret | Immediate high-fidelity alert (T1555.006) |
| S3 server access logs | Bulk `GetObject` from newly created IAM key | Exfiltration (T1530) — independent of CloudTrail |
| M365 Audit | `HardDelete` of security alert emails | Active attempt to suppress IR (T1070.008) |

#### MEDIUM-CONFIDENCE — Investigate Further

| Platform | Event | Why Medium-Confidence |
|----------|-------|----------------------|
| Okta | Multiple `user.authentication.auth_via_mfa` in short window from same IP | MFA fatigue (T1621); could be user error |
| Okta | `user.session.start` from new geolocation | Could be VPN, travel |
| AWS CloudTrail | Rapid `ListUsers` + `ListRoles` + `DescribeInstances` + `ListTables` | Discovery sweep (T1580); could be legitimate audit tool |
| AWS CloudTrail | `ListBuckets` + `ListObjects` across multiple buckets from federated principal | S3 discovery (T1619); could be data catalog tool |
| AWS CloudTrail | `RunInstances` from newly created IAM user | Attacker EC2 foothold (T1578.002); could be automation |
| M365 Audit | High-volume `FileAccessed` on SharePoint from federated identity | Data collection (T1213.002); could be sync client |
| GitHub Audit | `git.clone` from anomalous IP using PAT | Code repo exfil (T1213.003); could be dev from home |

---

### Key Investigation Queries

#### Okta — Authentication Anomalies

```bash
# List recent authentication events for a specific user
curl -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/logs?filter=actor.alternateId+eq+\"victim@company.com\"&since=2024-01-01T00:00:00Z&limit=100" \
  | jq '.[] | {time: .published, event: .eventType, ip: .client.ipAddress, geo: .client.geographicalContext}'

# Find all MFA challenges in a time window (MFA fatigue detection)
curl -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/logs?filter=eventType+eq+\"user.authentication.auth_via_mfa\"&since=$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')&limit=200" \
  | jq 'group_by(.actor.alternateId)[] | {user: .[0].actor.alternateId, count: length, ips: [.[].client.ipAddress] | unique}'

# Find new MFA factor enrollments (attacker device registration)
curl -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/logs?filter=eventType+eq+\"user.mfa.factor.activate\"&since=$(date -u -d '48 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  | jq '.[] | {time: .published, user: .actor.alternateId, ip: .client.ipAddress, geo: .client.geographicalContext, factor: .target[0].displayName}'

# Check enrolled factors for a specific user
curl -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users/${VICTIM_USER_ID}/factors" \
  | jq '.[] | {id: .id, type: .factorType, provider: .provider, status: .status, created: .created, lastUpdated: .lastUpdated}'

# Get active sessions for a user
curl -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users/${VICTIM_USER_ID}/sessions" \
  | jq '.[] | {id: .id, created: .createdAt, lastActive: .lastFactorVerification, mfaActive: .mfaActive}'
```

#### AWS — CloudTrail Investigation

```bash
# Set time window for investigation (adjust as needed)
START_TIME="2024-01-15T00:00:00Z"
END_TIME="2024-01-16T00:00:00Z"
REGION="us-east-1"

# Find AssumeRoleWithSAML events (IDP-to-AWS pivot)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithSAML \
  --start-time "${START_TIME}" --end-time "${END_TIME}" \
  --region "${REGION}" \
  --query 'Events[*].{Time:EventTime,User:Username,Source:SourceIPAddress,Role:Resources[0].ResourceName}' \
  --output table

# Find backdoor IAM user creation sequence
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time "${START_TIME}" --end-time "${END_TIME}" \
  --region "${REGION}" \
  --query 'Events[*].{Time:EventTime,User:Username,IP:SourceIPAddress,NewUser:Resources[0].ResourceName}' \
  --output table

# Check all events by the attacker IAM user
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=lucr3-attacker-iam-user \
  --start-time "${START_TIME}" --end-time "${END_TIME}" \
  --region "${REGION}" \
  --query 'Events[*].{Time:EventTime,Event:EventName,IP:SourceIPAddress}' \
  --output table

# Find GuardDuty disable event
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateDetector \
  --start-time "${START_TIME}" --end-time "${END_TIME}" \
  --region "${REGION}" \
  --query 'Events[*].{Time:EventTime,User:Username,IP:SourceIPAddress}' \
  --output table

# Find CloudTrail StopLogging
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time "${START_TIME}" --end-time "${END_TIME}" \
  --region "${REGION}" \
  --query 'Events[*].{Time:EventTime,User:Username,IP:SourceIPAddress,Trail:Resources[0].ResourceName}' \
  --output table

# Find all SecretsManager access (harvest detection)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "${START_TIME}" --end-time "${END_TIME}" \
  --region "${REGION}" \
  --query 'Events[*].{Time:EventTime,User:Username,IP:SourceIPAddress,Secret:Resources[0].ResourceName}' \
  --output table

# Enumerate all IAM users created recently
aws iam list-users \
  --query 'Users[?CreateDate>=`'"${START_TIME}"'`].{User:UserName,Created:CreateDate,ARN:Arn}' \
  --output table

# Check policies attached to suspected backdoor user
aws iam list-attached-user-policies \
  --user-name lucr3-attacker-iam-user \
  --output table

# List access keys for backdoor user
aws iam list-access-keys \
  --user-name lucr3-attacker-iam-user \
  --query 'AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status,Created:CreateDate}' \
  --output table

# Check for RunInstances events (attacker EC2 launch)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --start-time "${START_TIME}" --end-time "${END_TIME}" \
  --region "${REGION}" \
  --query 'Events[*].{Time:EventTime,User:Username,IP:SourceIPAddress}' \
  --output table

# Find EC2 instances launched by attacker user
aws ec2 describe-instances \
  --filters "Name=tag:aws:cloudformation:stack-name,Values=*lucr3*" \
  --query 'Reservations[*].Instances[*].{ID:InstanceId,State:State.Name,LaunchTime:LaunchTime,IP:PublicIpAddress}' \
  --output table

# Check SSM session history for lateral movement
aws ssm describe-sessions \
  --state Active \
  --filters "key=Owner,value=arn:aws:iam::*:user/lucr3-attacker-iam-user" \
  --output table

# Query S3 access logs for bulk exfiltration (replace BUCKET and LOG_PREFIX)
aws s3api select-object-content \
  --bucket "${LOG_BUCKET}" \
  --key "${LOG_PREFIX}/$(date +%Y-%m-%d)" \
  --expression "SELECT * FROM S3Object s WHERE s.operation = 'REST.GET.OBJECT' AND s.requester = 'arn:aws:iam::ACCOUNT:user/lucr3-attacker-iam-user'" \
  --expression-type SQL \
  --input-serialization '{"CSV":{"FieldDelimiter":" "}}' \
  --output-serialization '{"CSV":{}}' \
  output.csv

# Get GuardDuty findings
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-criteria '{"Criterion":{"updatedAt":{"Gte":'"$(date -d '24 hours ago' +%s000)"'}}}' \
  --output json \
  | xargs -I{} aws guardduty get-findings \
    --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
    --finding-ids {}
```

#### M365 — SharePoint and Mailbox Investigation

```bash
# Query SharePoint file access events (requires Exchange Online PowerShell or Graph API)
# Via Microsoft Graph API (use access token with AuditLog.Read.All)
ACCESS_TOKEN="<graph_token>"

# Search unified audit log for FileAccessed events
curl -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "https://graph.microsoft.com/v1.0/security/auditLog/queries" \
  -X POST -H "Content-Type: application/json" \
  -d '{
    "displayName": "LUCR3 SharePoint Investigation",
    "filterStartDateTime": "2024-01-15T00:00:00Z",
    "filterEndDateTime": "2024-01-16T00:00:00Z",
    "recordTypeFilters": ["sharePointFileOperation"],
    "operationFilters": ["FileAccessed", "SearchQueryPerformed"]
  }'

# Query bulk file download events via PowerShell (run in Exchange Online PowerShell)
# Search-UnifiedAuditLog -StartDate 2024-01-15 -EndDate 2024-01-16 -Operations FileAccessed,SearchQueryPerformed -ResultSize 1000 | Export-Csv sharepoint_audit.csv

# Check for HardDelete / SoftDelete mailbox events
curl -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "https://graph.microsoft.com/v1.0/security/auditLog/queries" \
  -X POST -H "Content-Type: application/json" \
  -d '{
    "displayName": "LUCR3 Mailbox Deletion Investigation",
    "filterStartDateTime": "2024-01-15T00:00:00Z",
    "filterEndDateTime": "2024-01-16T00:00:00Z",
    "operationFilters": ["HardDelete", "SoftDelete", "MoveToDeletedItems"]
  }'

# Check Azure AD sign-in logs for federated logins
az login
az monitor activity-log list \
  --start-time "2024-01-15T00:00:00Z" \
  --end-time "2024-01-16T00:00:00Z" \
  --query '[?operationName.value==`Microsoft.AAD/signIns/write`].{time:eventTimestamp,user:caller,result:status.value}' \
  --output table

# Get risky sign-ins from Azure AD Identity Protection
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?filter=riskLevel eq 'high'" \
  --headers "Authorization=Bearer ${ACCESS_TOKEN}"
```

#### GitHub — Repository and PAT Investigation

```bash
# List audit log events for organization (requires org owner token)
gh api \
  -H "Accept: application/vnd.github+json" \
  "/orgs/${ORG_NAME}/audit-log?phrase=action:git.clone&include=git&per_page=100" \
  | jq '.[] | {time: .created_at, actor: .actor, repo: .repo, ip: .actor_ip}'

# Check for PAT usage events
gh api \
  -H "Accept: application/vnd.github+json" \
  "/orgs/${ORG_NAME}/audit-log?phrase=action:personal_access_token&per_page=100" \
  | jq '.[] | {time: .created_at, actor: .actor, action: .action, token_id: .token_id}'

# Check repository access logs
gh api \
  -H "Accept: application/vnd.github+json" \
  "/orgs/${ORG_NAME}/audit-log?phrase=repo:${ORG_NAME}/${REPO_NAME}&per_page=200" \
  | jq '.[] | {time: .created_at, actor: .actor, action: .action, ip: .actor_ip}'

# List active fine-grained PATs for the organization
gh api \
  -H "Accept: application/vnd.github+json" \
  "/orgs/${ORG_NAME}/personal-access-tokens?per_page=100" \
  | jq '.[] | {id: .id, owner: .owner.login, name: .name, created: .credential_created_at, last_used: .credential_last_used_at}'
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Okta — Lock Down the Identity Layer First

```bash
# 1. Suspend the compromised Okta user immediately
curl -X POST -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/users/${VICTIM_USER_ID}/lifecycle/suspend"

# 2. Clear ALL active sessions for the victim user
curl -X DELETE -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users/${VICTIM_USER_ID}/sessions"

# 3. Delete the attacker-enrolled TOTP factor
#    First, identify the attacker's factor ID from enrollment investigation
ATTACKER_FACTOR_ID="<factor_id_from_investigation>"
curl -X DELETE -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users/${VICTIM_USER_ID}/factors/${ATTACKER_FACTOR_ID}"

# 4. Block the attacker's source IP (add to Okta Network Zone blocklist)
curl -X POST -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/zones" \
  -d '{
    "type": "IP",
    "name": "LUCR3-BlockedIPs",
    "gateways": [{"type": "CIDR", "value": "<ATTACKER_IP>/32"}],
    "status": "ACTIVE"
  }'

# 5. Set global session policy to require re-authentication (reduce session lifetime to 0)
# Do this in Okta Admin console: Security > Global Session Policy > set max session to 15 min
```

#### AWS — Revoke All Attacker Access

```bash
# 1. Immediately disable the attacker IAM user
aws iam update-login-profile \
  --user-name lucr3-attacker-iam-user \
  --password-reset-required || true

aws iam update-user \
  --user-name lucr3-attacker-iam-user \
  --no-path  # flag to note but actual disable is via access key

# 2. Delete all access keys for attacker IAM user
for key_id in $(aws iam list-access-keys --user-name lucr3-attacker-iam-user \
  --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
  aws iam delete-access-key \
    --user-name lucr3-attacker-iam-user \
    --access-key-id "${key_id}"
  echo "Deleted key: ${key_id}"
done

# 3. Detach all policies from attacker IAM user
for policy_arn in $(aws iam list-attached-user-policies --user-name lucr3-attacker-iam-user \
  --query 'AttachedPolicies[*].PolicyArn' --output text); do
  aws iam detach-user-policy \
    --user-name lucr3-attacker-iam-user \
    --policy-arn "${policy_arn}"
  echo "Detached: ${policy_arn}"
done

# 4. Revoke the federated role session (invalidate all SAML-derived sessions)
#    AWS does not directly revoke active STS sessions, but you can update the role trust policy
#    to block further AssumeRoleWithSAML calls and add a deny condition
FEDERATED_ROLE_NAME="lucr3-privileged-federated-role"
aws iam put-role-policy \
  --role-name "${FEDERATED_ROLE_NAME}" \
  --policy-name "EmergencyDeny-LUCR3-Incident" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "'"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"'"
        }
      }
    }]
  }'

# 5. Re-enable GuardDuty if disabled
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty update-detector \
  --detector-id "${DETECTOR_ID}" \
  --enable

# 6. Re-enable CloudTrail if stopped
TRAIL_ARN=$(aws cloudtrail list-trails --query 'Trails[0].TrailARN' --output text)
aws cloudtrail start-logging --name "${TRAIL_ARN}"

# 7. Isolate attacker-launched EC2 instance (apply quarantine security group)
#    First find the attacker EC2 instance ID
ATTACKER_INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=*lucr3-attacker*" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text)

# Create quarantine security group (no ingress/egress)
QSG_ID=$(aws ec2 create-security-group \
  --group-name "QUARANTINE-LUCR3-Incident" \
  --description "QUARANTINE - LUCR3 IR - blocks all traffic" \
  --vpc-id $(aws ec2 describe-instances --instance-ids "${ATTACKER_INSTANCE_ID}" \
    --query 'Reservations[0].Instances[0].VpcId' --output text) \
  --query 'GroupId' --output text)

# Remove all default egress
aws ec2 revoke-security-group-egress \
  --group-id "${QSG_ID}" \
  --protocol all --port -1 --cidr 0.0.0.0/0

# Apply quarantine SG to attacker instance
aws ec2 modify-instance-attribute \
  --instance-id "${ATTACKER_INSTANCE_ID}" \
  --groups "${QSG_ID}"

echo "Attacker instance ${ATTACKER_INSTANCE_ID} quarantined"

# 8. Terminate attacker EC2 instance (after forensic snapshot if required)
# Take EBS snapshot first for forensics
VOLUME_ID=$(aws ec2 describe-instances \
  --instance-ids "${ATTACKER_INSTANCE_ID}" \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId' --output text)
aws ec2 create-snapshot --volume-id "${VOLUME_ID}" --description "LUCR3-IR-Forensic-Snapshot"

# Then terminate
aws ec2 terminate-instances --instance-ids "${ATTACKER_INSTANCE_ID}"
```

#### M365 — Revoke Federated Session

```bash
# Revoke all refresh tokens for compromised user (requires Azure AD Global Admin)
az ad user update --id "victim@company.com" --account-enabled false

# Revoke all sessions via Microsoft Graph
curl -X POST -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "https://graph.microsoft.com/v1.0/users/victim@company.com/revokeSignInSessions"

# Force sign-out of all active sessions
az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/users/victim@company.com/invalidateAllRefreshTokens"
```

#### GitHub — Revoke Stolen PAT

```bash
# Revoke the stolen PAT (requires org owner token)
# Get token ID from audit log investigation
gh api \
  -X DELETE \
  -H "Accept: application/vnd.github+json" \
  "/orgs/${ORG_NAME}/personal-access-tokens/${TOKEN_ID}"

# If token owner is known, revoke via user endpoint
gh api \
  -X DELETE \
  -H "Accept: application/vnd.github+json" \
  "/applications/${CLIENT_ID}/token" \
  -f access_token="${STOLEN_PAT}"
```

---

## 4. Eradication

### Remove All Attacker Persistence

#### Okta — Remove Attacker Device, Reset Victim

```bash
# 1. Reset victim's MFA — force re-enrollment with verified identity
curl -X POST -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/users/${VICTIM_USER_ID}/lifecycle/reset_factors"

# 2. Force password reset on victim account
curl -X POST -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/users/${VICTIM_USER_ID}/lifecycle/expire_password?tempPassword=false"

# 3. Reactivate user after verified re-enrollment
curl -X POST -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/users/${VICTIM_USER_ID}/lifecycle/unsuspend"

# 4. Audit ALL users for anomalous factor enrollments in the incident window
curl -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/logs?filter=eventType+eq+\"user.mfa.factor.activate\"&since=<INCIDENT_START>&until=<INCIDENT_END>&limit=200" \
  | jq '.[] | {user: .actor.alternateId, ip: .client.ipAddress, factor: .target[0].displayName, time: .published}'

# 5. Delete any other attacker-enrolled factors found in above audit
curl -X DELETE -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users/${OTHER_AFFECTED_USER_ID}/factors/${ATTACKER_FACTOR_ID}"
```

#### AWS — Delete Backdoor User and Clean Up

```bash
# 1. Delete attacker IAM user's login profile
aws iam delete-login-profile --user-name lucr3-attacker-iam-user 2>/dev/null || true

# 2. Remove inline policies
for policy_name in $(aws iam list-user-policies --user-name lucr3-attacker-iam-user \
  --query 'PolicyNames[]' --output text); do
  aws iam delete-user-policy \
    --user-name lucr3-attacker-iam-user \
    --policy-name "${policy_name}"
done

# 3. Remove from any groups
for group in $(aws iam list-groups-for-user --user-name lucr3-attacker-iam-user \
  --query 'Groups[*].GroupName' --output text); do
  aws iam remove-user-from-group \
    --user-name lucr3-attacker-iam-user \
    --group-name "${group}"
done

# 4. Delete the attacker IAM user
aws iam delete-user --user-name lucr3-attacker-iam-user

# 5. Remove the emergency deny inline policy from federated role (added in containment)
aws iam delete-role-policy \
  --role-name "${FEDERATED_ROLE_NAME}" \
  --policy-name "EmergencyDeny-LUCR3-Incident"

# 6. Rotate all SecretsManager secrets that were accessed
#    List all secrets that were GetSecretValue'd during the incident
for secret_id in lucr3-secrets-prod-db lucr3-bait-honey-credentials lucr3-bait-github-pat-secret; do
  aws secretsmanager rotate-secret --secret-id "${secret_id}"
  echo "Rotated: ${secret_id}"
done

# 7. Terminate all attacker-launched EC2 instances (if not done in containment)
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running,stopped" \
  --query 'Reservations[*].Instances[?LaunchTime>=`'"${INCIDENT_START}"'`].{ID:InstanceId,Launch:LaunchTime,Role:IamInstanceProfile.Arn}' \
  --output table

# 8. Audit and remove any IAM instance profiles created by attacker
for profile in $(aws iam list-instance-profiles \
  --query 'InstanceProfiles[?CreateDate>=`'"${INCIDENT_START}"'`].InstanceProfileName' \
  --output text); do
  aws iam delete-instance-profile --instance-profile-name "${profile}"
done

# 9. Rotate victim's IAM credentials if they have programmatic access
aws iam list-access-keys --user-name "${VICTIM_IAM_USER}" \
  --query 'AccessKeyMetadata[*].AccessKeyId' --output text | \
  xargs -I{} aws iam delete-access-key --user-name "${VICTIM_IAM_USER}" --access-key-id {}

aws iam create-access-key --user-name "${VICTIM_IAM_USER}"
```

#### M365 — Restore Mailbox and Revoke Access

```bash
# Recover hard-deleted emails (admin purge recovery — 14-day window)
# Requires Compliance Center PowerShell: New-ComplianceSearchAction -Purge -PurgeType SoftDelete

# Via Graph API — restore soft-deleted items
curl -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -X POST \
  "https://graph.microsoft.com/v1.0/users/victim@company.com/mailFolders/recoverableitemsdeleted/messages/<MESSAGE_ID>/move" \
  -H "Content-Type: application/json" \
  -d '{"destinationId": "inbox"}'

# Re-enable the user account
az ad user update --id "victim@company.com" --account-enabled true

# Require MFA re-registration via Conditional Access
az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/users/victim@company.com/authentication/methods/28c10230-6103-485e-b985-444c60001490/resetPassword" \
  --body '{}'
```

#### GitHub — Rotate Compromised Credentials

```bash
# Generate replacement PAT with minimum required scopes (fine-grained)
gh auth token  # verify current auth

# Notify repository owners to rotate any secrets that may have been in cloned repos
# Run secret scanning on repositories that were accessed
gh api \
  -H "Accept: application/vnd.github+json" \
  "/repos/${ORG_NAME}/${REPO_NAME}/secret-scanning/alerts?state=open" \
  | jq '.[] | {id: .number, secret_type: .secret_type, state: .state, created: .created_at}'
```

---

## 5. Recovery

### Restore Clean State

#### Re-enable Security Services

```bash
# 1. Verify GuardDuty is re-enabled and findings are flowing
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty get-detector --detector-id "${DETECTOR_ID}" \
  --query '{Status:Status,FindingPublishingFrequency:FindingPublishingFrequency}' \
  --output table

# 2. Verify CloudTrail is logging
aws cloudtrail get-trail-status --name "${TRAIL_ARN}" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestNotificationTime:LatestNotificationTime}' \
  --output table

# 3. Verify Security Hub is active
aws securityhub describe-hub --query '{HubArn:HubArn,SubscribedAt:SubscribedAt,AutoEnableControls:AutoEnableControls}'

# 4. Enable GuardDuty features if not already on (S3, Malware Protection, Runtime Monitoring)
aws guardduty update-detector \
  --detector-id "${DETECTOR_ID}" \
  --enable \
  --data-sources '{"S3Logs":{"Enable":true},"Kubernetes":{"AuditLogs":{"Enable":true}},"MalwareProtection":{"ScanEc2InstanceWithFindings":{"EbsVolumes":{"Enable":true}}}}'

# 5. Run an IAM Access Analyzer scan to find any remaining unexpected access
aws accessanalyzer list-analyzers --output table
ANALYZER_ARN=$(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text)
aws accessanalyzer start-resource-scan --analyzer-arn "${ANALYZER_ARN}" \
  --resource-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):root"

# 6. Check for any remaining active EC2 instances not in approved AMI catalog
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].{ID:InstanceId,AMI:ImageId,Launch:LaunchTime,IamRole:IamInstanceProfile.Arn,Tags:Tags}' \
  --output table

# 7. Verify no remaining backdoor IAM users
aws iam list-users \
  --query 'Users[?CreateDate>=`'"${INCIDENT_START}"'`].{User:UserName,Created:CreateDate}' \
  --output table

# 8. Re-rotate S3 KMS keys used for corporate data buckets if key was exposed
aws kms schedule-key-deletion --key-id "${COMPROMISED_KMS_KEY_ID}" --pending-window-in-days 7
aws kms create-key --description "LUCR3-IR-Replacement-Key-$(date +%Y%m%d)"
```

#### Okta — Harden Post-Incident

```bash
# 1. Verify Okta ThreatInsight is in Log and Enforce mode
curl -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/threats/configuration" \
  | jq '.action'
# Should return "BLOCK" not "AUDIT"

# 2. Update Okta enrollment policy to require FIDO2 for all new factor enrollments
# (Do via Admin console: Security > Authenticators > Enrollment > require phishing-resistant)

# 3. Verify SMS/voice call OTP is disabled or restricted to fallback only
curl -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/authenticators" \
  | jq '.[] | {key: .key, name: .name, status: .status}'

# 4. Confirm victim user's new factors are enrolled correctly
curl -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users/${VICTIM_USER_ID}/factors" \
  | jq '.[] | {type: .factorType, provider: .provider, status: .status, enrolled: .lastUpdated}'
```

#### Verify No Persistence Mechanisms Remain

```bash
# Final sweep — check for any unexpected trust relationships in IAM roles
aws iam list-roles \
  --query 'Roles[*].{Role:RoleName,Trust:AssumeRolePolicyDocument}' \
  --output json | python3 -c "
import sys, json
roles = json.load(sys.stdin)
for r in roles:
    trust = r['Trust']
    if isinstance(trust, str):
        trust = json.loads(trust)
    stmts = trust.get('Statement', [])
    for s in stmts:
        principal = s.get('Principal', {})
        if 'Federated' in str(principal) or 'arn:aws:iam' in str(principal):
            print(f\"Role: {r['Role']}, Principal: {principal}\")
"

# Check for any lingering SSM sessions
aws ssm describe-sessions --state Active --output table

# Verify all attacker-created SGs are deleted
aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=*LUCR3*,*attacker*" \
  --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName,Description:Description}' \
  --output table

# Run AWS Trusted Advisor security check
aws support describe-trusted-advisor-checks --language en \
  --query 'checks[?category==`security`].{id:id,name:name}' \
  --output table
```

---

## 6. Lessons Learned

### Post-Incident Review Agenda (within 5 business days)

1. **Timeline reconstruction** — Build minute-by-minute timeline from Okta logs, CloudTrail, S3 server access logs, and M365 UAL. Identify the detection gap between `StopLogging` (Step 17) and S3 exfiltration (Step 21).

2. **Detection gaps identified**

   | Gap | Root Cause | Guardrail |
   |-----|-----------|-----------|
   | MFA fatigue not alerted in time | SMS MFA allowed; no policy blocking rapid re-challenge | Enforce FIDO2/WebAuthn; block SMS MFA for privileged users |
   | Attacker device enrollment went unnoticed | No real-time alert on `user.mfa.factor.activate` from new geolocation | Wire Okta event to PagerDuty via SIEM rule |
   | GuardDuty disabled before exfil | SCP not in place on OU to block `guardduty:UpdateDetector --no-enable` | Add SCP blocking GD disable from non-breakglass principals |
   | CloudTrail stopped successfully | SCP not blocking `cloudtrail:StopLogging`; trail not protected | Enable CloudTrail log file integrity validation; SCP block StopLogging |
   | S3 exfil only detected via server access logs | GuardDuty was disabled; no redundant alert | Ensure S3 server access logs stream to SIEM independently of CloudTrail |
   | Canary secret triggered but delayed response | Alert was email-only, not paged | Wire canary access to PagerDuty/on-call immediately |
   | Mailbox deletion reduced forensic evidence | MCAS policy existed but alert was low-priority | Elevate MCAS `MassMailboxDelete` policy to High; require IR team acknowledgment |

3. **What worked**

   - S3 server access logs were independent of CloudTrail — captured exfil even after logging stopped
   - Canary/bait secrets in SecretsManager provided immediate high-fidelity detection
   - GuardDuty findings prior to disablement provided early warning of discovery phase
   - SAML-to-AWS pivot was visible in CloudTrail as `AssumeRoleWithSAML`

4. **Recommended guardrails to implement**

   ```bash
   # SCP: Block GuardDuty and CloudTrail tampering from non-breakglass OUs
   # Add to SCP JSON:
   cat <<'EOF'
   {
     "Effect": "Deny",
     "Action": [
       "guardduty:DeleteDetector",
       "guardduty:DisassociateFromMasterAccount",
       "cloudtrail:StopLogging",
       "cloudtrail:DeleteTrail",
       "cloudtrail:UpdateTrail"
     ],
     "Resource": "*",
     "Condition": {
       "StringNotLike": {
         "aws:PrincipalARN": "arn:aws:iam::*:role/BreakglassRole"
       }
     }
   }
   EOF

   # EventBridge rule: alert on CloudTrail StopLogging within 60 seconds
   aws events put-rule \
     --name "LUCR3-Guardrail-StopLogging" \
     --event-pattern '{"source":["aws.cloudtrail"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventName":["StopLogging"]}}' \
     --state ENABLED \
     --description "Alert when CloudTrail logging is stopped"

   # Okta: SIEM rule for MFA fatigue
   # Alert: >3 user.authentication.auth_via_mfa events from same source IP within 5 minutes
   # Action: Auto-suspend user, page on-call

   # Okta: SIEM rule for anomalous factor enrollment
   # Alert: user.mfa.factor.activate from IP not in corporate network zone
   # Action: Immediate page, auto-suspend pending verification
   ```

5. **Identity hygiene improvements**
   - Require phishing-resistant MFA (FIDO2) for ALL Okta users — eliminate SMS/TOTP for privileged access
   - Implement Okta Privileged Access Management (PAM) for admin-level Okta actions
   - Enforce helpdesk re-verification via video call + manager confirmation for any MFA reset
   - Quarterly review of SAML-federated role trust policies; remove stale IdP mappings
   - Set AWS STS `MaxSessionDuration` on SAML-federated roles to 1 hour maximum
   - Enable AWS IAM Identity Center instead of direct SAML federation for better session control

6. **Data protection improvements**
   - Enable Amazon Macie on all S3 buckets to classify sensitive data and alert on anomalous access
   - Apply S3 Object Lock (WORM) on all buckets containing terraform state, credentials, or engineering artifacts
   - Enforce VPC endpoints for S3 access; restrict bucket policy to deny non-VPC access for sensitive buckets
   - Deploy GitHub secret scanning push protection to prevent secrets being committed to repos

---

*Playbook Version: 1.0 | Threat Actor: LUCR-3 (Scattered Spider) | Last Updated: 2026-05-16*
*SANS PICERL Framework | MITRE ATT&CK Coverage: 21 techniques across 8 tactics*