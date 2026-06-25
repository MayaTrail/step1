# IR Playbook: DangerDev — AWS Cloud Account Compromise & Resource Hijacking

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Cloud Account Takeover / Cryptomining / SES Abuse / Spearphishing Infrastructure |
| Threat Actor | DangerDev (DangerDev@protonmail.me) |
| Attribution | Indonesia (commercial VPN; confirmed malicious AWS accounts 265857590823 and 671050157472) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Initial Access, Discovery, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement, Impact, Collection, Resource Development |
| MITRE Techniques | T1078.004, T1526, T1087.004, T1136.003, T1098.003, T1580, T1578.002, T1021.001, T1496, T1036.005, T1199, T1098, T1530, T1518.001, T1070, T1583.001, T1566.002 |
| Estimated Dwell Time | Up to 43,200 minutes (30 days) between phases |
| Primary Financial Impact | EC2 GPU compute (p3.16xlarge ~$24/hr x3+), SES quota abuse, Route53 domain registration |

---

## 1. Preparation

### What Should Be in Place Before This Incident

**Detection Coverage**
- CloudTrail enabled in all regions with S3 log delivery to a separate security account; CloudTrail integrity validation enabled
- GuardDuty enabled in all regions with findings forwarded to a SIEM
- AWS Security Hub enabled with CIS AWS Foundations Benchmark and AWS Foundational Security Best Practices standards active
- S3 data events enabled on all buckets containing IAM credentials, Terraform state, or sensitive data
- VPC Flow Logs enabled on all VPCs, forwarded to CloudWatch Logs or S3
- AWS Cost Anomaly Detection configured with alerts on EC2 spend > $50/day and SES send volume anomalies

**Access Baselines**
- IAM Access Analyzer enabled; findings reviewed weekly
- AWS Config rules: `iam-no-inline-policy`, `iam-user-no-policies-check`, `access-keys-rotated`, `iam-root-access-key-check`
- Baseline of all IAM users, roles, access keys, and trust policies exported and versioned
- Known-good list of IAM users with active access keys and their creation dates

**Runbook Prerequisites**
- IR team has break-glass read-only credentials to the security log account
- `aws` CLI installed and configured with IR team profile pointing to security log account
- SIEM query templates for IAM, SES, EC2, GuardDuty, and S3 events pre-built
- Contact list: AWS Support, AWS Trust & Safety (+1-206-266-4064 for abuse)

---

## 2. Identification

### Detection Triggers (Prioritized)

#### HIGH-CONFIDENCE — These events almost always indicate active compromise

| Event | Source | Confidence | Trigger Condition |
|-------|--------|------------|-------------------|
| `GetUser` + `ListAttachedUserPolicies` without preceding `GetCallerIdentity` | CloudTrail / IAM | High | DangerDev's fingerprint: deliberately avoids GetCallerIdentity |
| `CreateUser` with email-format username | CloudTrail / IAM | High | Username contains `@` character |
| `AttachUserPolicy` with `AdministratorAccess` on newly created user | CloudTrail / IAM | High | PolicyArn = `arn:aws:iam::aws:policy/AdministratorAccess` on user created < 24h ago |
| `CreateAccessKey` on an existing user by a different principal | CloudTrail / IAM | High | requestParameters.userName != userIdentity.userName |
| `UpdateLoginProfile` performed by a different principal than the user | CloudTrail / IAM | High | Cross-user password reset |
| IAM username `ses` created | CloudTrail / IAM | High | Single-word name mimicking SES service; check against `ses-smtp-user.*` pattern |
| IAM role named `AWSeservedSSO_*` (lowercase 'e') or `AWSLanding-Zones-*` | CloudTrail / IAM | High | One-character diff from legitimate `AWSReservedSSO_` prefix |
| `AttachRolePolicy` with `AdministratorAccess` on a role with cross-account trust | CloudTrail / IAM | High | Role trust policy principal is external account |
| High-frequency IAM deletion burst: `DeleteUser` + `DeleteAccessKey` + `DetachUserPolicy` within 60 seconds | CloudTrail / IAM | High | DangerDev self-cleanup fingerprint |
| GuardDuty: `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | GuardDuty | High | API calls from known-malicious IP |
| GuardDuty: `Persistence:IAMUser/UserPermissions` | GuardDuty | High | New IAM user or policy attachment from anomalous source |
| GuardDuty: `PrivilegeEscalation:IAMUser/AdministrativePermissions` | GuardDuty | High | AdministratorAccess granted to user or role |

#### MEDIUM-CONFIDENCE — Warrant investigation; may have legitimate explanations

| Event | Source | Confidence | Trigger Condition |
|-------|--------|------------|-------------------|
| `GetSendQuota` + `ListIdentities` from non-ops IAM principal | CloudTrail / SES | Medium | SES enumeration from unexpected user |
| `ListUsers` burst from a non-automation IAM principal | CloudTrail / IAM | Medium | > 3 list calls within 5 minutes from same principal |
| `DescribeInstanceTypes` with GPU filter (`p3.*`, `p4d.*`, `g4dn.*`) | CloudTrail / EC2 | Medium | Mining candidate reconnaissance |
| `RunInstances` from anomalous IAM user with open security group (0.0.0.0/0 on 22 or 3389) | CloudTrail / EC2 | Medium | Paired with Security Hub EC2.19 finding |
| `ListDetectors` + `ListFindings` from non-security-ops principal | CloudTrail / GuardDuty | Medium | Adversary scoping detection coverage |
| `SimulatePrincipalPolicy` targeting `ssm:GetParameter` or `secretsmanager:GetSecretValue` | CloudTrail / IAM | Medium | Probing permissions without touching those services |
| GuardDuty console access with `Amazon Relational Database Service console` user-agent | CloudTrail | Medium | DangerDev's anomalous user-agent fingerprint |
| `ListBuckets` followed by `ListObjectsV2` from anomalous principal | CloudTrail / S3 | Medium | Bucket enumeration + data scoping |
| TCP SYN to port 3389 on EC2 public IP from foreign IP | VPC Flow Logs | Medium | RDP reachability probe |
| CPU spike to 100% at EC2 instance launch | CloudWatch Metrics | Medium | Mining simulation or actual mining binary |
| AWS Cost Anomaly: EC2 GPU spend spike | AWS Cost Explorer | Medium | p3.16xlarge or similar launched unexpectedly |

### Key Investigation Queries

#### Step 0 — Establish Timeline Boundaries

```bash
# Find earliest anomalous IAM event — look for email-format usernames or GetUser-without-GetCallerIdentity
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetUser \
  --start-time "$(date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --end-time "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[?contains(CloudTrailEvent, `\"userIdentity\"`) == `true`].[EventTime,Username,CloudTrailEvent]' \
  --output json | jq '.[] | {time: .[0], user: .[1], event: (.[2] | fromjson | {ip: .sourceIPAddress, ua: .userAgent})}'
```

```bash
# Find when leaked key was first used — query by access key ID
LEAKED_KEY_ID="AKIA..."  # substitute actual key ID
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=${LEAKED_KEY_ID} \
  --start-time "$(date -u -d '60 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[*].[EventTime,EventName,Username]' \
  --output table
```

```bash
# Find the DangerDev backdoor user creation event
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time "$(date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[*].CloudTrailEvent' \
  --output json | jq '.[] | fromjson | select(.requestParameters.userName | test("@|^ses$|^ses-"))' | \
  jq '{time: .eventTime, actor: .userIdentity.arn, ip: .sourceIPAddress, newUser: .requestParameters.userName}'
```

#### Step 1 — Identify All Compromised Principals

```bash
# List all IAM users with email-format names (DangerDev fingerprint)
aws iam list-users \
  --query 'Users[?contains(UserName, `@`)].[UserName,CreateDate,Arn]' \
  --output table
```

```bash
# Find suspicious single-word IAM users that mimic service names
aws iam list-users \
  --query 'Users[?length(UserName) <= `5`].[UserName,CreateDate,Arn]' \
  --output table
```

```bash
# Find all IAM roles with suspicious naming (AWSeservedSSO or AWSLanding-Zones)
aws iam list-roles \
  --query 'Roles[?starts_with(RoleName, `AWSeserved`) || starts_with(RoleName, `AWSLanding-Zones`)].[RoleName,CreateDate,Arn]' \
  --output table
```

```bash
# Check trust policies on suspicious roles for cross-account principals
ROLE_NAME="AWSeservedSSO_AdminAccess"
aws iam get-role \
  --role-name ${ROLE_NAME} \
  --query 'Role.AssumeRolePolicyDocument' \
  --output json
```

```bash
# List all users with more than one active access key (T1098 indicator)
aws iam list-users --query 'Users[*].UserName' --output text | tr '\t' '\n' | while read user; do
  count=$(aws iam list-access-keys --user-name "$user" --query 'length(AccessKeyMetadata)' --output text)
  if [ "$count" -gt "1" ]; then
    echo "ALERT: $user has $count access keys"
    aws iam list-access-keys --user-name "$user" --output table
  fi
done
```

```bash
# Check alice.chen specifically for TA-created keys
aws iam list-access-keys --user-name alice.chen --output table
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=alice.chen \
  --start-time "$(date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[?EventName==`CreateAccessKey` || EventName==`UpdateLoginProfile`].[EventTime,EventName,Username]' \
  --output table
```

#### Step 2 — Enumerate Attack Scope

```bash
# Find all EC2 instances launched by DangerDev principal in last 30 days
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --start-time "$(date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[*].CloudTrailEvent' \
  --output json | jq '.[] | fromjson | select(.userIdentity.userName == "DangerDev@protonmail.me" or .userIdentity.userName == "lab-infra-admin")' | \
  jq '{time: .eventTime, actor: .userIdentity.userName, ip: .sourceIPAddress, instance: .responseElements.instancesSet.items[0].instanceId, type: .requestParameters.instanceType}'
```

```bash
# Enumerate all currently running EC2 instances — look for unexpected GPU types
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,LaunchTime,Tags[?Key==`Name`].Value|[0],PublicIpAddress]' \
  --output table
```

```bash
# Check all regions for GPU instances (DangerDev used multiple regions)
for region in us-east-1 us-west-2 eu-west-1 ap-southeast-1 ap-northeast-1; do
  echo "=== Region: $region ==="
  aws ec2 describe-instances \
    --region $region \
    --filters "Name=instance-state-name,Values=running" \
    --query 'Reservations[*].Instances[?starts_with(InstanceType, `p3`) || starts_with(InstanceType, `p4`) || starts_with(InstanceType, `g4`)].[InstanceId,InstanceType,LaunchTime,PublicIpAddress]' \
    --output table
done
```

```bash
# Find open security groups (0.0.0.0/0 on RDP/SSH)
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`] && (FromPort==`3389` || FromPort==`22`)]].[GroupId,GroupName,Description]' \
  --output table
```

```bash
# Check SES for TA-registered identities and sending activity
aws ses list-identities --output table
aws ses get-send-quota --output json
aws ses get-send-statistics --output json | jq '.SendDataPoints | sort_by(.Timestamp) | .[-7:]'
```

```bash
# Check Route53 for suspicious domain registrations (last 30 days)
aws route53domains list-domains \
  --query 'Domains[*].[DomainName,CreatedDate,ExpiryDate]' \
  --output table
```

```bash
# Look for GuardDuty console access with anomalous user-agent (RDS console fingerprint)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListFindings \
  --start-time "$(date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[*].CloudTrailEvent' \
  --output json | jq '.[] | fromjson | select(.userAgent | test("Relational Database Service|rds")) | {time: .eventTime, actor: .userIdentity.userName, ua: .userAgent, ip: .sourceIPAddress}'
```

```bash
# Find SimulatePrincipalPolicy calls targeting sensitive service actions
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SimulatePrincipalPolicy \
  --start-time "$(date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[*].CloudTrailEvent' \
  --output json | jq '.[] | fromjson | {time: .eventTime, actor: .userIdentity.userName, ip: .sourceIPAddress, actions: .requestParameters.actionNames}'
```

```bash
# Find high-frequency IAM deletion burst (T1070 self-cleanup fingerprint)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteUser \
  --start-time "$(date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[*].[EventTime,Username,CloudTrailEvent]' \
  --output json | jq '.[] | {time: .[0], actor: .[1], event: (.[2] | fromjson | {deletedUser: .requestParameters.userName, ip: .sourceIPAddress})}'
```

```bash
# Check what S3 buckets were accessed and by whom
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets \
  --start-time "$(date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[*].[EventTime,Username]' \
  --output table
```

```bash
# Find access to the leaked credentials bucket (terraform.tfstate access)
BUCKET_NAME="dangerdev-leaked-creds-bucket"  # substitute actual bucket name
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=${BUCKET_NAME} \
  --start-time "$(date -u -d '90 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[*].[EventTime,EventName,Username]' \
  --output table
```

```bash
# Check all GuardDuty findings — sort by severity
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-findings \
  --detector-id ${DETECTOR_ID} \
  --finding-criteria '{"Criterion":{"severity":{"Gte":4}}}' \
  --query 'FindingIds' \
  --output json | jq -r '.[]' | head -50 | xargs -I{} aws guardduty get-findings \
  --detector-id ${DETECTOR_ID} \
  --finding-ids {} \
  --query 'Findings[*].[Severity,Type,UpdatedAt,Resource.AccessKeyDetails.UserName]' \
  --output table
```

```bash
# Check AssumeRole events targeting the backdoor roles
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[*].CloudTrailEvent' \
  --output json | jq '.[] | fromjson | select(.requestParameters.roleArn | test("AWSeservedSSO|AWSLanding-Zones")) | {time: .eventTime, actor: .userIdentity.arn, ip: .sourceIPAddress, role: .requestParameters.roleArn, sessionName: .requestParameters.roleSessionName}'
```

```bash
# Pull all IAM events from the leaked admin key within a time window
LEAKED_KEY_ID="AKIA..."  # substitute actual key ID
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=${LEAKED_KEY_ID} \
  --query 'Events[*].[EventTime,EventName,Username]' \
  --output table | sort
```

---

## 3. Containment

### Immediate Actions — First 15 Minutes

#### 3.1 Disable the Leaked Admin Credential (T1078.004)

```bash
# Identify the leaked access key
VICTIM_USER="lab-infra-admin"
aws iam list-access-keys --user-name ${VICTIM_USER} --output table

# Deactivate immediately — do NOT delete yet (preserves CloudTrail correlation)
LEAKED_KEY_ID="AKIA..."  # substitute
aws iam update-access-key \
  --user-name ${VICTIM_USER} \
  --access-key-id ${LEAKED_KEY_ID} \
  --status Inactive

# Verify deactivation
aws iam list-access-keys --user-name ${VICTIM_USER} --query 'AccessKeyMetadata[*].[AccessKeyId,Status,CreateDate]' --output table
```

```bash
# Revoke any active console sessions for the compromised user (forces re-auth)
aws iam create-login-profile --user-name ${VICTIM_USER} --password "$(openssl rand -base64 24)" --no-password-reset-required 2>/dev/null || \
aws iam update-login-profile --user-name ${VICTIM_USER} --password "$(openssl rand -base64 24)"
```

#### 3.2 Remove DangerDev Backdoor User (T1136.003 / T1098.003)

```bash
# Check if DangerDev@protonmail.me still exists (may have self-deleted via T1070)
aws iam get-user --user-name "DangerDev@protonmail.me" 2>&1 || echo "User already deleted (T1070 self-cleanup executed)"

# If user exists, perform ordered deletion
BACKDOOR_USER="DangerDev@protonmail.me"

# 1. Deactivate and delete all access keys
aws iam list-access-keys --user-name "${BACKDOOR_USER}" --query 'AccessKeyMetadata[*].AccessKeyId' --output text | tr '\t' '\n' | while read key; do
  echo "Deactivating key: $key"
  aws iam update-access-key --user-name "${BACKDOOR_USER}" --access-key-id "$key" --status Inactive
  aws iam delete-access-key --user-name "${BACKDOOR_USER}" --access-key-id "$key"
done

# 2. Detach all managed policies
aws iam list-attached-user-policies --user-name "${BACKDOOR_USER}" --query 'AttachedPolicies[*].PolicyArn' --output text | tr '\t' '\n' | while read arn; do
  echo "Detaching: $arn"
  aws iam detach-user-policy --user-name "${BACKDOOR_USER}" --policy-arn "$arn"
done

# 3. Delete inline policies
aws iam list-user-policies --user-name "${BACKDOOR_USER}" --query 'PolicyNames[*]' --output text | tr '\t' '\n' | while read policy; do
  aws iam delete-user-policy --user-name "${BACKDOOR_USER}" --policy-name "$policy"
done

# 4. Delete login profile
aws iam delete-login-profile --user-name "${BACKDOOR_USER}" 2>/dev/null || echo "No login profile"

# 5. Delete MFA devices if any
aws iam list-mfa-devices --user-name "${BACKDOOR_USER}" --query 'MFADevices[*].SerialNumber' --output text | tr '\t' '\n' | while read serial; do
  aws iam deactivate-mfa-device --user-name "${BACKDOOR_USER}" --serial-number "$serial"
  aws iam delete-virtual-mfa-device --serial-number "$serial" 2>/dev/null || true
done

# 6. Remove from groups
aws iam list-groups-for-user --user-name "${BACKDOOR_USER}" --query 'Groups[*].GroupName' --output text | tr '\t' '\n' | while read grp; do
  aws iam remove-user-from-group --user-name "${BACKDOOR_USER}" --group-name "$grp"
done

# 7. Delete signing certificates
aws iam list-signing-certificates --user-name "${BACKDOOR_USER}" --query 'Certificates[*].CertificateId' --output text | tr '\t' '\n' | while read cert; do
  aws iam delete-signing-certificate --user-name "${BACKDOOR_USER}" --certificate-id "$cert"
done

# 8. Delete the user
aws iam delete-user --user-name "${BACKDOOR_USER}"
echo "Backdoor user deleted"
```

#### 3.3 Remove 'ses' Masquerade User (T1036.005)

```bash
SES_MASQ_USER="ses"
aws iam get-user --user-name ${SES_MASQ_USER} 2>/dev/null && {
  aws iam list-access-keys --user-name ${SES_MASQ_USER} --query 'AccessKeyMetadata[*].AccessKeyId' --output text | tr '\t' '\n' | while read key; do
    aws iam update-access-key --user-name ${SES_MASQ_USER} --access-key-id "$key" --status Inactive
    aws iam delete-access-key --user-name ${SES_MASQ_USER} --access-key-id "$key"
  done
  aws iam delete-login-profile --user-name ${SES_MASQ_USER} 2>/dev/null || true
  aws iam delete-user --user-name ${SES_MASQ_USER}
  echo "Masquerade user 'ses' deleted"
} || echo "User 'ses' does not exist"
```

#### 3.4 Neutralize Cross-Account Backdoor Roles (T1199)

```bash
# Remove AdministratorAccess from both backdoor roles
for ROLE in "AWSeservedSSO_AdminAccess" "AWSLanding-Zones-ConfigRecorderRoles"; do
  echo "Processing role: $ROLE"
  aws iam get-role --role-name "$ROLE" 2>/dev/null && {
    # Detach all managed policies
    aws iam list-attached-role-policies --role-name "$ROLE" --query 'AttachedPolicies[*].PolicyArn' --output text | tr '\t' '\n' | while read arn; do
      echo "  Detaching: $arn"
      aws iam detach-role-policy --role-name "$ROLE" --policy-arn "$arn"
    done
    # Revoke all active sessions for this role by updating trust policy to deny all
    # (Update trust policy to block all principals while preserving for forensics)
    aws iam update-assume-role-policy --role-name "$ROLE" --policy-document '{
      "Version": "2012-10-17",
      "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"}]
    }'
    echo "  Role $ROLE neutralized — trust policy set to Deny-all"
  } || echo "  Role $ROLE does not exist"
done
```

```bash
# After forensic review, delete the backdoor roles entirely
for ROLE in "AWSeservedSSO_AdminAccess" "AWSLanding-Zones-ConfigRecorderRoles"; do
  # Delete inline role policies first
  aws iam list-role-policies --role-name "$ROLE" --query 'PolicyNames[*]' --output text | tr '\t' '\n' | while read pol; do
    aws iam delete-role-policy --role-name "$ROLE" --policy-name "$pol"
  done
  aws iam delete-role --role-name "$ROLE"
  echo "Deleted backdoor role: $ROLE"
done
```

#### 3.5 Revoke alice.chen TA-Created Access Key (T1098)

```bash
# Identify which key was created by the attacker (newer key, created after attack start date)
aws iam list-access-keys --user-name alice.chen --output json | \
  jq '.AccessKeyMetadata | sort_by(.CreateDate) | .[] | {key: .AccessKeyId, created: .CreateDate, status: .Status}'

# Delete the TA-created key (newest key — verify date against attack timeline)
TA_KEY_ID="AKIA..."  # substitute the key ID created during the attack
aws iam update-access-key --user-name alice.chen --access-key-id ${TA_KEY_ID} --status Inactive
aws iam delete-access-key --user-name alice.chen --access-key-id ${TA_KEY_ID}

# Reset alice.chen password to a secure value and force reset on next login
aws iam update-login-profile \
  --user-name alice.chen \
  --password "$(openssl rand -base64 24)" \
  --password-reset-required
echo "alice.chen credentials reset"
```

#### 3.6 Stop Running EC2 Instances (T1578.002 / T1496)

```bash
# Terminate all unexpected EC2 instances across all regions
for region in us-east-1 us-west-2 eu-west-1 ap-southeast-1 ap-northeast-1 ap-northeast-3; do
  echo "=== $region ==="
  INSTANCE_IDS=$(aws ec2 describe-instances \
    --region $region \
    --filters "Name=instance-state-name,Values=running" \
    --filters "Name=tag-key,Values=MayaTrail" \
    --query 'Reservations[*].Instances[*].InstanceId' \
    --output text)
  if [ -n "$INSTANCE_IDS" ]; then
    echo "Terminating in $region: $INSTANCE_IDS"
    aws ec2 terminate-instances --region $region --instance-ids $INSTANCE_IDS
  fi
done

# Also check for GPU instances in all regions (not limited to tagged instances)
for region in us-east-1 us-west-2 eu-west-1 ap-southeast-1; do
  aws ec2 describe-instances --region $region \
    --filters "Name=instance-state-name,Values=running" \
    --query 'Reservations[*].Instances[?starts_with(InstanceType, `p3`) || starts_with(InstanceType, `p4`) || starts_with(InstanceType, `g4`)].{id: InstanceId, type: InstanceType, region: Placement.AvailabilityZone}' \
    --output table
done
```

```bash
# Restrict the open security group to prevent new RDP/SSH connections
OPEN_SG_ID="sg-..."  # substitute actual SG ID
# Revoke 0.0.0.0/0 on port 3389
aws ec2 revoke-security-group-ingress \
  --group-id ${OPEN_SG_ID} \
  --protocol tcp \
  --port 3389 \
  --cidr 0.0.0.0/0
# Revoke 0.0.0.0/0 on port 22
aws ec2 revoke-security-group-ingress \
  --group-id ${OPEN_SG_ID} \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0
echo "Security group $OPEN_SG_ID locked down"
```

#### 3.7 Suspend SES Sending (T1566.002)

```bash
# Disable SES account-level sending immediately
aws ses update-account-sending-enabled --enabled false
echo "SES account sending DISABLED"

# Delete TA-registered email identities
aws ses list-identities --output json | jq -r '.Identities[]' | while read identity; do
  echo "Review identity: $identity"
  # Delete identities that are not in your approved list
  # aws ses delete-identity --identity "$identity"
done

# Delete specific TA-registered identity
aws ses delete-identity --identity "emulation-noreply@emulation-lab-noreply.example.com"
```

#### 3.8 Block Malicious AWS Accounts via SCP (T1199)

```bash
# Apply an SCP to block AssumeRole from confirmed malicious AWS accounts
# Add to the AWS Organizations SCP targeting the affected account's OU
cat > /tmp/block-dangerdev-accounts.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BlockDangerDevExternalAccounts",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "*",
      "Condition": {
        "ArnLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::265857590823:*",
            "arn:aws:iam::671050157472:*"
          ]
        }
      }
    }
  ]
}
EOF

# Apply via Organizations (requires management account credentials)
aws organizations create-policy \
  --name "BlockDangerDevMaliciousAccounts" \
  --description "Block AssumeRole from confirmed DangerDev malicious accounts 265857590823 and 671050157472" \
  --content file:///tmp/block-dangerdev-accounts.json \
  --type SERVICE_CONTROL_POLICY

# Attach to the affected account
aws organizations attach-policy \
  --policy-id "p-..."  \  # substitute returned policy ID
  --target-id "123456789012"  # substitute affected account ID
```

---

## 4. Eradication

### Remove All Attacker Access

#### 4.1 Rotate the Leaked Credential (T1078.004)

```bash
# Delete the leaked access key (after confirming deactivation in step 3.1)
VICTIM_USER="lab-infra-admin"
LEAKED_KEY_ID="AKIA..."

aws iam delete-access-key \
  --user-name ${VICTIM_USER} \
  --access-key-id ${LEAKED_KEY_ID}

# Create a new access key for the legitimate user (if needed)
aws iam create-access-key --user-name ${VICTIM_USER}
# Store new credentials securely in AWS Secrets Manager, NOT in terraform.tfstate
```

```bash
# Remove terraform.tfstate from the exposed S3 bucket (or restrict access)
LEAKED_BUCKET="dangerdev-leaked-creds-bucket"  # substitute actual bucket name
# Option A: Delete the exposed state file
aws s3 rm s3://${LEAKED_BUCKET}/infra/prod/terraform.tfstate

# Option B: Block all public/external access (preferred — preserves for forensics)
aws s3api put-public-access-block \
  --bucket ${LEAKED_BUCKET} \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

#### 4.2 Audit All IAM Access Keys Created in Attack Window

```bash
# Find all access keys created during the attack window
ATTACK_START="2026-03-01T00:00:00Z"  # substitute actual start date
aws iam list-users --query 'Users[*].UserName' --output text | tr '\t' '\n' | while read user; do
  aws iam list-access-keys --user-name "$user" \
    --query "AccessKeyMetadata[?CreateDate >= \`${ATTACK_START}\`].[UserName,AccessKeyId,CreateDate,Status]" \
    --output table
done | grep -v "^$"
```

```bash
# Deactivate any suspicious keys found above — confirm before deleting
SUSPICIOUS_KEY="AKIA..."
SUSPICIOUS_USER="username"
aws iam update-access-key --user-name ${SUSPICIOUS_USER} --access-key-id ${SUSPICIOUS_KEY} --status Inactive
```

#### 4.3 Verify All Backdoor Roles Deleted

```bash
# Confirm no typosquat roles remain in the account
aws iam list-roles --query 'Roles[*].RoleName' --output text | tr '\t' '\n' | grep -E "AWSeserved|AWSLanding-Zones|AWSReseved" | while read role; do
  echo "SUSPICIOUS ROLE FOUND: $role"
  aws iam get-role --role-name "$role" --query 'Role.[RoleName,CreateDate,AssumeRolePolicyDocument]' --output json
done
```

```bash
# Audit all roles with cross-account trust to external accounts
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output text | while read role arn; do
  trust=$(aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)
  if echo "$trust" | grep -qE "265857590823|671050157472"; then
    echo "CRITICAL: $role trusts confirmed malicious account"
  fi
  external=$(echo "$trust" | jq -r '.Statement[].Principal.AWS // empty' | grep -v "$(aws sts get-caller-identity --query Account --output text)" || true)
  if [ -n "$external" ]; then
    echo "Cross-account trust in $role: $external"
  fi
done
```

#### 4.4 Eradicate SES Abuse Infrastructure

```bash
# Re-enable SES only after confirming no TA identities remain
aws ses list-identities --output json | jq -r '.Identities[]'
# For each identity not in your approved allow-list:
# aws ses delete-identity --identity "<identity>"

# After cleanup, re-enable sending
aws ses update-account-sending-enabled --enabled true
```

```bash
# Check for and delete any Route53 domains registered during attack window
aws route53domains list-domains --output json | \
  jq --arg date "$ATTACK_START" '.Domains[] | select(.CreatedDate > $date) | {domain: .DomainName, created: .CreatedDate}'
# For malicious domains: aws route53domains delete-domain --domain-name "<domain>"
```

#### 4.5 Rotate alice.chen Credentials Fully

```bash
# Verify alice.chen has only one access key now (the legitimate one)
aws iam list-access-keys --user-name alice.chen --output table

# Force console password reset on next login
aws iam update-login-profile \
  --user-name alice.chen \
  --password "$(openssl rand -base64 24)" \
  --password-reset-required

# If alice.chen had existing sessions active, revoke them
# (AWS does not have a direct "revoke all sessions for IAM user" API — 
# deactivating the access key is the effective control)
```

---

## 5. Recovery

### Restore Clean State

#### 5.1 Re-enable and Validate Security Services

```bash
# Verify GuardDuty is still enabled and generating findings
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty get-detector --detector-id ${DETECTOR_ID} \
  --query 'Status' --output text
# Expected: ENABLED

# Verify CloudTrail is logging
aws cloudtrail describe-trails --query 'trailList[*].[Name,S3BucketName,IsMultiRegionTrail,LogFileValidationEnabled]' --output table

TRAIL_ARN="arn:aws:cloudtrail:us-east-1:$(aws sts get-caller-identity --query Account --output text):trail/..."
aws cloudtrail get-trail-status --name ${TRAIL_ARN} --query '[IsLogging,LatestDeliveryTime]' --output table
```

```bash
# Check Security Hub for any disabled controls
aws securityhub get-enabled-standards --output json | jq '.StandardsSubscriptions[*].StandardsStatus'

# Run a fresh Security Hub check on IAM controls
aws securityhub describe-standards-controls \
  --standards-subscription-arn "arn:aws:securityhub:us-east-1:$(aws sts get-caller-identity --query Account --output text):subscription/aws-foundational-security-best-practices/v/1.0.0" \
  --query 'Controls[?ControlId==`IAM.1` || ControlId==`IAM.3` || ControlId==`EC2.19`].[ControlId,ControlStatus,Title]' \
  --output table
```

#### 5.2 Verify No Persistence Mechanisms Remain

```bash
# Full IAM audit — users, roles, policies with cross-account access
echo "=== IAM Users with active keys ==="
aws iam list-users --query 'Users[*].UserName' --output text | tr '\t' '\n' | while read user; do
  keys=$(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text)
  [ -n "$keys" ] && echo "  $user: $keys"
done

echo "=== Roles with AdministratorAccess ==="
aws iam list-entities-for-policy \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --entity-filter Role \
  --query 'PolicyRoles[*].RoleName' \
  --output table

echo "=== Users with AdministratorAccess ==="
aws iam list-entities-for-policy \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --entity-filter User \
  --query 'PolicyUsers[*].UserName' \
  --output table
```

```bash
# Check for any unexpected EC2 key pairs (DangerDev created a key pair)
aws ec2 describe-key-pairs --output table
# Delete any unknown key pairs
# aws ec2 delete-key-pair --key-name "dangerdev-lab-key"
```

```bash
# Verify no active EC2 instances remain outside Pulumi/IaC state
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running,pending,stopping,stopped" \
  --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name,LaunchTime,Tags[?Key==`Name`].Value|[0]]' \
  --output table
```

```bash
# Check AWS Cost Anomaly Detection for ongoing unexpected charges
aws ce get-anomalies \
  --date-interval StartDate="$(date -u -d '7 days ago' '+%Y-%m-%d')",EndDate="$(date -u '+%Y-%m-%d')" \
  --query 'Anomalies[*].[AnomalyId,AnomalyStartDate,AnomalyEndDate,Impact.MaxImpact,RootCauses[0].Service]' \
  --output table
```

#### 5.3 Rotate Remaining Credentials

```bash
# Rotate lab-infra-admin key after confirming attacker key deleted
VICTIM_USER="lab-infra-admin"
# Create new key
NEW_KEY=$(aws iam create-access-key --user-name ${VICTIM_USER} --output json)
echo "New key created: $(echo $NEW_KEY | jq -r '.AccessKey.AccessKeyId')"
echo "Update all consumers of this key before proceeding"

# After consumers updated, delete the old key (if it was only deactivated earlier)
OLD_KEY_ID="AKIA..."  # original leaked key
aws iam delete-access-key --user-name ${VICTIM_USER} --access-key-id ${OLD_KEY_ID}
```

```bash
# Store new credentials in Secrets Manager (not S3/terraform.tfstate)
aws secretsmanager create-secret \
  --name "infra/lab-infra-admin/access-key" \
  --description "lab-infra-admin IAM access key - managed post-DangerDev incident" \
  --secret-string "{\"AccessKeyId\":\"$(echo $NEW_KEY | jq -r '.AccessKey.AccessKeyId')\",\"SecretAccessKey\":\"$(echo $NEW_KEY | jq -r '.AccessKey.SecretAccessKey')\"}"
```

#### 5.4 Implement Immediate Guardrails

```bash
# Apply deny-CreateUser SCP to prevent recurrence (apply to affected OU)
cat > /tmp/restrict-iam-user-creation.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireHumanApprovalForNewIAMUsers",
      "Effect": "Deny",
      "Action": ["iam:CreateUser","iam:CreateLoginProfile"],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/Admin*",
            "arn:aws:iam::*:role/Terraform*",
            "arn:aws:iam::*:role/Pulumi*"
          ]
        }
      }
    }
  ]
}
EOF

aws organizations create-policy \
  --name "RestrictIAMUserCreation-DangerDevResponse" \
  --description "Prevent IAM user creation from non-IaC principals - response to DangerDev incident" \
  --content file:///tmp/restrict-iam-user-creation.json \
  --type SERVICE_CONTROL_POLICY
```

---

## 6. Lessons Learned

### What Happened

DangerDev gained initial access via a long-term IAM access key with AdministratorAccess that was inadvertently stored in plaintext in a Terraform state file in an S3 bucket accessible outside the organization. From this foothold the actor conducted multi-phase operations over an extended dwell period: enumerated account services, established persistent backdoor IAM users and cross-account backdoor roles with typosquat names, launched GPU EC2 instances for cryptomining, hijacked existing user accounts (alice.chen), enumerated GuardDuty findings to scope detection exposure, then deleted their primary user account to erase visible footprint — while leaving cross-account backdoor roles and the hijacked alice.chen credentials intact as post-cleanup persistence.

### Root Causes

| Root Cause | Evidence | Fix |
|---|---|---|
| Long-term IAM access key stored in Terraform state in S3 | `infra/prod/terraform.tfstate` in S3 contained `aws_access_key_id` and `aws_secret_access_key` in plaintext | Migrate Terraform state to S3 with encryption; never embed long-term credentials in IaC state; use IAM roles for CI/CD pipelines |
| No IAM Access Analyzer or alert on new email-format IAM users | DangerDev@protonmail.me existed for the full attack duration without alerting | Add SIEM rule: alert on `CreateUser` where `requestParameters.userName` matches `.*@.*` |
| No alert on AdministratorAccess attachment to newly created users | AttachUserPolicy with AdministratorAccess on 24-hour-old user was undetected | CloudWatch Events rule on `AttachUserPolicy` where PolicyArn contains `AdministratorAccess` AND user age < 7 days |
| No alert on cross-account trust roles with AdministratorAccess | AWSeservedSSO_AdminAccess and AWSLanding-Zones-ConfigRecorderRoles persisted | IAM Access Analyzer external access findings; weekly automated role trust policy audit |
| SES sending quota increase granted without anomaly detection | Quota increase enabled large-scale phishing infrastructure | SES sending rate alarm; require change-control approval for SES quota increases |
| No detective control on typosquat IAM role naming | `AWSeservedSSO_` (lowercase 'e') vs `AWSReservedSSO_` (uppercase 'R') | AWS Config custom rule checking IAM role name Levenshtein distance against `AWSReservedSSO_` |
| GuardDuty findings not actioned promptly | DangerDev reviewed GuardDuty findings before cleanup — findings existed but were unactioned | Automate GuardDuty finding response; Critical/High findings require acknowledgement within 1 hour |

### What Would Have Prevented This

1. **IAM roles for all automation — no long-term keys in CI/CD or IaC.** Terraform/Pulumi pipelines should authenticate via EC2 instance profile or OIDC federation, never embedded access keys in state files.
2. **S3 bucket policy denying cross-account and public GetObject on any bucket containing IaC state.**
3. **SCPs preventing `iam:CreateUser` and `iam:CreateLoginProfile` from non-IaC principals in production accounts.**
4. **GuardDuty + Security Hub automated response.** A Lambda-backed EventBridge rule auto-disabling IAM users when `Persistence:IAMUser/UserPermissions` fires would have contained DangerDev before Phase 2.
5. **Mandatory MFA for all console-capable IAM users** combined with a Condition key in all resource policies: `"Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}`.
6. **AWS Cost Anomaly Detection** with alerts on EC2 spend > $100/day would have caught the GPU mining infrastructure within hours.
7. **Centralized CloudTrail in a separate security account** with S3 object lock (WORM) ensures DangerDev's self-cleanup (T1070) does not erase evidence even if the actor gains access to the log bucket.

---

*Playbook authored by MayaTrail | Platform: AWS | Threat Actor: DangerDev | MITRE ATT&CK for Cloud v14 | SANS PICERL | 2026-04-25*