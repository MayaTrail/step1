# IR Playbook: HazyBeacon (CL-STA-1020) — AWS

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Cloud Credential Theft + Serverless C2 + Data Exfiltration |
| Threat Actor | HazyBeacon (alias: CL-STA-1020) |
| Platform | AWS |
| Severity | Critical |
| MITRE Tactics | Reconnaissance, Credential Access, Initial Access, Discovery, Execution, Defense Evasion, Command and Control, Exfiltration |
| MITRE Techniques | T1598.003, T1552.001, T1078.004, T1087.004, T1069.003, T1648, T1564, T1102, T1090, T1041 |
| Tools Used | HazyBeacon backdoor, BackupHandler Lambda relay, AWS CLI, Python/Node.js |

---

## 1. Preparation

### Pre-requisites Before This Incident

**CloudTrail**
- Multi-region CloudTrail trail enabled with management event logging (read + write)
- S3 data events enabled on buckets holding sensitive data (terraform.tfstate, secrets)
- CloudTrail log integrity validation enabled

**GuardDuty**
- GuardDuty enabled in all regions; threat intel feed active
- Findings forwarded to Security Hub and SIEM

**AWS Config**
- Rules in place: `lambda-function-public-access-prohibited`, `required-tags`, `iam-policy-no-statements-with-admin-access`

**Detective**
- AWS Detective enabled and enrolled to the GuardDuty master; provides behavioral baselines for IAM users

**Alerting Baselines Needed**
- Credential use from new IP/geo for developer IAM users
- Lambda function creation with `AuthType: NONE` Function URL
- IAM enumeration burst (>5 IAM read calls in 60 seconds from single principal)
- S3 ListBuckets + ListObjects from IAM users not in automation groups

**Incident Response Tooling**
- Responder has `SecurityAudit` + `ReadOnlyAccess` + targeted remediation permissions
- `aws cloudtrail lookup-events` access or Athena/CloudTrail Lake query access
- `jq` installed locally for CLI output filtering

---

## 2. Identification

### Detection Triggers (Prioritized)

**HIGH-CONFIDENCE — any of these alone indicates active compromise:**

| Event / Signal | Source | Why High-Confidence |
|---|---|---|
| `GetCallerIdentity` from IP not in developer VPN range | CloudTrail (sts.amazonaws.com) | First call with stolen key; rarely from unexpected IPs legitimately |
| `CreateFunction20150331` + `CreateFunctionUrlConfig` in same session by non-automation IAM user | CloudTrail (lambda.amazonaws.com) | Developer users do not deploy Lambda infra manually |
| `AddPermission20150331` with `FunctionUrlAuthType: NONE` | CloudTrail (lambda.amazonaws.com) | Unauthenticated public endpoint is an explicit C2 indicator |
| Lambda `TagResource` within seconds of `CreateFunction` by same non-automation caller | CloudTrail (lambda.amazonaws.com) | Rapid tag application is masking behavior, not IaC |
| GuardDuty: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` | GuardDuty | Key used from IP inconsistent with EC2 source |
| GuardDuty: `Execution:Lambda/NetworkConnectionToThreatIntelFeed` | GuardDuty | C2 beacon matching threat intel |

**MEDIUM-CONFIDENCE — investigate in combination:**

| Event / Signal | Source | Why Medium-Confidence |
|---|---|---|
| `ListUsers` + `ListRoles` + `ListBuckets` burst in single session | CloudTrail | Could be legitimate automation; check principal + timing |
| `ListSecrets` + `DescribeSecret` from developer IAM user | CloudTrail (secretsmanager.amazonaws.com) | Unusual for developer; confirm against normal baseline |
| `GetUserPolicy` + `ListAttachedGroupPolicies` outside business hours | CloudTrail (iam.amazonaws.com) | Permission enumeration before escalation |
| `list_objects_v2` + `head_object` on terraform.tfstate from unexpected principal | S3 server access logs | Credential harvesting reconnaissance pattern |
| `ManagedBy:terraform` tag on Lambda not tracked in IaC state | AWS Config / Terraform state | Impostor tag |
| DNS: repeated resolution of `*.lambda-url.<region>.on.aws` from dev instance | VPC DNS logs / Route53 Resolver logs | C2 beaconing pattern |
| HTTPS egress from EC2 to `*.lambda-url.*.on.aws` at regular intervals | VPC Flow Logs | Periodic beaconing |

---

### Key Investigation Queries

**Scope the Compromised Credential**

```bash
# Identify all API calls made by the suspected compromised IAM user in the last 24h
# Replace USERNAME with the victim IAM username discovered
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=USERNAME \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --end-time "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[*].{Time:EventTime,Event:EventName,Source:EventSource,IP:CloudTrailEvent}' \
  --output table
```

```bash
# Confirm first call with stolen credentials (GetCallerIdentity)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity \
  --start-time "$(date -u -d '48 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[*].{Time:EventTime,User:Username,RawEvent:CloudTrailEvent}' \
  --output json | jq '.[] | {time: .Time, user: .User, sourceIP: (.RawEvent | fromjson | .sourceIPAddress)}'
```

```bash
# Get all source IPs used by the victim IAM user (look for anomalous IPs)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=USERNAME \
  --start-time "$(date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | .sourceIPAddress' | sort | uniq -c | sort -rn
```

**Identify IAM Enumeration Burst**

```bash
# List all IAM read events in the session — look for ListUsers/ListRoles/GetAccountSummary
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=USERNAME \
  --start-time "INCIDENT_START_TIME" \
  --end-time "INCIDENT_END_TIME" \
  --query 'Events[?contains(`["ListUsers","ListRoles","GetAccountSummary","ListGroups","ListGroupsForUser","ListAttachedGroupPolicies","ListUserPolicies","GetUserPolicy","GetPolicy","ListBuckets","ListSecrets","DescribeSecret"]`, EventName)].{Time:EventTime,Event:EventName}' \
  --output table
```

**Identify Rogue Lambda Function**

```bash
# Find Lambda CreateFunction events by non-automation principals
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateFunction20150331 \
  --start-time "INCIDENT_START_TIME" \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | {time: .eventTime, user: .userIdentity.userName, funcName: .requestParameters.functionName, role: .requestParameters.role, sourceIP: .sourceIPAddress}'
```

```bash
# Find Lambda Function URLs created with no auth (AuthType: NONE)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateFunctionUrlConfig \
  --start-time "INCIDENT_START_TIME" \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | select(.requestParameters.authType == "NONE") | {time: .eventTime, user: .userIdentity.userName, funcName: .requestParameters.functionName, authType: .requestParameters.authType, url: .responseElements.functionUrl}'
```

```bash
# List all Lambda functions currently deployed — look for BackupHandler / UpdateWorker / ImageResizer
aws lambda list-functions \
  --query 'Functions[*].{Name:FunctionName,Role:Role,Modified:LastModified,Description:Description}' \
  --output table
```

```bash
# Check function URLs on a suspected function
aws lambda get-function-url-config --function-name BackupHandler 2>/dev/null || \
aws lambda get-function-url-config --function-name UpdateWorker 2>/dev/null || \
aws lambda get-function-url-config --function-name ImageResizer 2>/dev/null
```

```bash
# Get tags on the suspicious function to check ManagedBy:terraform spoofing
aws lambda list-tags --resource arn:aws:lambda:REGION:ACCOUNT_ID:function:BackupHandler
```

**Check SecretsManager and S3 Access**

```bash
# SecretsManager ListSecrets events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListSecrets \
  --start-time "INCIDENT_START_TIME" \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | {time: .eventTime, user: .userIdentity.userName, sourceIP: .sourceIPAddress}'
```

```bash
# S3 ListBuckets events from the victim IAM user
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets \
  --start-time "INCIDENT_START_TIME" \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | {time: .eventTime, user: .userIdentity.userName, sourceIP: .sourceIPAddress}'
```

```bash
# Check S3 server access logs for the exfil bucket (if logging enabled)
# Replace LOGGING_BUCKET and PREFIX with your actual S3 server access log destination
aws s3 ls s3://LOGGING_BUCKET/PREFIX/ --recursive | grep "hazybeacon-exfil-bucket"
```

**Check GuardDuty Findings**

```bash
# List all HIGH/CRITICAL GuardDuty findings in the last 24h
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7},"updatedAt":{"Gt":"EPOCH_24H_AGO"}}}' \
  --query 'FindingIds' --output json | \
xargs -I{} aws guardduty get-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-ids {} \
  --query 'Findings[*].{Type:Type,Severity:Severity,Resource:Resource.ResourceType,Time:UpdatedAt}' \
  --output table
```

**Check VPC Flow Logs for Beaconing**

```bash
# Query VPC Flow Logs via CloudWatch Logs Insights for egress to Lambda URL domains
# Replace LOG_GROUP with your VPC Flow Log group
aws logs start-query \
  --log-group-name VPC_FLOW_LOG_GROUP \
  --start-time $(date -d '24 hours ago' +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, srcAddr, dstAddr, dstPort, bytes
    | filter dstPort = 443 and srcAddr like /10\./ 
    | stats count(*) as connections, sum(bytes) as totalBytes by srcAddr, dstAddr
    | sort totalBytes desc'
```

---

## 3. Containment

### Immediate Actions (First 15 Minutes)

**Step 1 — Disable the Compromised IAM User's Access Keys**

```bash
# List all access keys for the victim user
aws iam list-access-keys --user-name USERNAME

# Deactivate the compromised key (replace KEY_ID)
aws iam update-access-key \
  --user-name USERNAME \
  --access-key-id AKIAXXXXXXXXXXXXXXXXX \
  --status Inactive

# Confirm the key is inactive
aws iam list-access-keys --user-name USERNAME \
  --query 'AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status}'
```

**Step 2 — Attach an Explicit Deny Policy to Stop All API Activity**

```bash
# Create an inline deny-all policy on the compromised user (belt-and-suspenders with key deactivation)
aws iam put-user-policy \
  --user-name USERNAME \
  --policy-name EmergencyDenyAll \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'
```

**Step 3 — Disable the Rogue Lambda Function URL (Cuts C2 Channel)**

```bash
# Delete the Function URL to sever the public C2 endpoint immediately
aws lambda delete-function-url-config --function-name BackupHandler

# If function name differs, also try:
aws lambda delete-function-url-config --function-name UpdateWorker
aws lambda delete-function-url-config --function-name ImageResizer
```

**Step 4 — Throttle the Lambda to Zero (Prevent Any Remaining Invocations)**

```bash
# Set reserved concurrency to 0 — function cannot execute even if URL somehow reappears
aws lambda put-function-concurrency \
  --function-name BackupHandler \
  --reserved-concurrent-executions 0
```

**Step 5 — Revoke the Lambda Execution Role's Permissions (Defense in Depth)**

```bash
# Attach a deny-all inline policy to the Lambda execution role
aws iam put-role-policy \
  --role-name hazybeacon-lambda-exec-role \
  --policy-name EmergencyRoleDenyAll \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'
```

**Step 6 — Isolate the Compromised EC2 Instance**

```bash
# Find the instance ID for hazybeacon-dev-instance (or substitute known instance ID)
INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=hazybeacon-dev-instance" \
  --query 'Reservations[0].Instances[0].InstanceId' \
  --output text)

echo "Isolating instance: $INSTANCE_ID"

# Create an isolation security group (no inbound, no outbound) in the same VPC
VPC_ID=$(aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].VpcId' \
  --output text)

ISOLATION_SG=$(aws ec2 create-security-group \
  --group-name "IR-ISOLATION-$(date +%Y%m%d)" \
  --description "IR isolation - no inbound or outbound traffic allowed" \
  --vpc-id $VPC_ID \
  --query 'GroupId' --output text)

echo "Isolation SG: $ISOLATION_SG"

# Remove all default outbound rules from the isolation SG
aws ec2 revoke-security-group-egress \
  --group-id $ISOLATION_SG \
  --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' 2>/dev/null || true

# Apply isolation SG to the compromised instance
aws ec2 modify-instance-attribute \
  --instance-id $INSTANCE_ID \
  --groups $ISOLATION_SG

echo "Instance $INSTANCE_ID isolated with SG $ISOLATION_SG"
```

**Step 7 — Take a Memory/Disk Snapshot for Forensics Before Any Further Changes**

```bash
# Snapshot the root EBS volume for forensic preservation
ROOT_VOLUME=$(aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId' \
  --output text)

aws ec2 create-snapshot \
  --volume-id $ROOT_VOLUME \
  --description "IR-Forensic-HazyBeacon-$(date +%Y%m%d)-$INSTANCE_ID" \
  --tag-specifications "ResourceType=snapshot,Tags=[{Key=Purpose,Value=ForensicPreservation},{Key=Incident,Value=HazyBeacon}]"
```

**Step 8 — Block S3 Exfil Bucket Access via Bucket Policy**

```bash
# Apply a deny policy to hazybeacon-exfil-bucket blocking all access except from IR team role
# Replace IR_ROLE_ARN with your IR responder role ARN
aws s3api put-bucket-policy \
  --bucket hazybeacon-exfil-bucket \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyAllExceptIR",
      "Effect": "Deny",
      "NotPrincipal": {
        "AWS": ["IR_ROLE_ARN"]
      },
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::hazybeacon-exfil-bucket",
        "arn:aws:s3:::hazybeacon-exfil-bucket/*"
      ]
    }]
  }'
```

---

## 4. Eradication

### Remove Attacker Access and Persistence

**Delete the Rogue Lambda Function**

```bash
# Delete the BackupHandler C2 relay function
aws lambda delete-function --function-name BackupHandler

# Verify deletion
aws lambda get-function --function-name BackupHandler 2>&1 | grep -i "function not found" \
  && echo "BackupHandler successfully deleted" \
  || echo "WARNING: BackupHandler may still exist"
```

**Delete the Rogue Lambda's Resource-Based Policy (Function URL Permission)**

```bash
# List and remove any resource-based policies that allowed public invocation
# (This applies if the function URL / AddPermission created a policy statement)
aws lambda get-policy --function-name BackupHandler 2>/dev/null | \
  jq -r '.Policy | fromjson | .Statement[].Sid' | \
  xargs -I{} aws lambda remove-permission \
    --function-name BackupHandler \
    --statement-id {}
```

**Delete the Compromised IAM Access Key**

```bash
# After deactivation in containment, hard-delete the key
aws iam delete-access-key \
  --user-name USERNAME \
  --access-key-id AKIAXXXXXXXXXXXXXXXXX

# Confirm no remaining keys
aws iam list-access-keys --user-name USERNAME
```

**Remove the Emergency Deny Inline Policy and Lock the Account Properly**

```bash
# Remove the emergency deny (we'll lock the account via console MFA or disable login profile)
aws iam delete-user-policy --user-name USERNAME --policy-name EmergencyDenyAll

# Disable console access (removes login profile = no console login)
aws iam delete-login-profile --user-name USERNAME 2>/dev/null || echo "No login profile existed"

# Force-disable all remaining active keys (run again to catch any we missed)
aws iam list-access-keys --user-name USERNAME \
  --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' \
  --output text | \
  xargs -I{} aws iam update-access-key --user-name USERNAME --access-key-id {} --status Inactive
```

**Rotate SecretsManager Secrets That May Have Been Enumerated**

```bash
# Rotate the hazybeacon-secrets secret immediately
SECRET_ARN=$(aws secretsmanager describe-secret \
  --secret-id hazybeacon-secrets \
  --query 'ARN' --output text)

aws secretsmanager rotate-secret --secret-id $SECRET_ARN

# If no rotation Lambda is attached, force a new version with updated value
aws secretsmanager put-secret-value \
  --secret-id hazybeacon-secrets \
  --secret-string '{"username":"NEW_ROTATED_VALUE","password":"NEW_ROTATED_PASSWORD"}'
```

**Check for and Remove Any Backdoor IAM Users or Roles Created During the Incident**

```bash
# List IAM users created in the incident window (adjust timestamps)
aws iam list-users \
  --query 'Users[?CreateDate>=`INCIDENT_START_ISO`].{User:UserName,Created:CreateDate,ARN:Arn}' \
  --output table

# List IAM roles created in the incident window
aws iam list-roles \
  --query 'Roles[?CreateDate>=`INCIDENT_START_ISO`].{Role:RoleName,Created:CreateDate,ARN:Arn}' \
  --output table

# Delete any rogue user found (replace ROGUE_USER with actual name)
aws iam list-access-keys --user-name ROGUE_USER --query 'AccessKeyMetadata[*].AccessKeyId' --output text | \
  xargs -I{} aws iam delete-access-key --user-name ROGUE_USER --access-key-id {}
aws iam list-attached-user-policies --user-name ROGUE_USER --query 'AttachedPolicies[*].PolicyArn' --output text | \
  xargs -I{} aws iam detach-user-policy --user-name ROGUE_USER --policy-arn {}
aws iam delete-user --user-name ROGUE_USER
```

**Audit the hazybeacon-decoy-admin-user (Honey IAM User)**

```bash
# Check if the honey admin user was accessed — any event from this user is a HIGH-CONFIDENCE indicator
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=hazybeacon-decoy-admin-user \
  --start-time "INCIDENT_START_TIME" \
  --output json | jq '.Events | length'
# Non-zero result means the attacker touched the honey user — escalate incident scope

# Rotate or delete the honey user's access keys regardless
aws iam list-access-keys --user-name hazybeacon-decoy-admin-user \
  --query 'AccessKeyMetadata[*].AccessKeyId' --output text | \
  xargs -I{} aws iam update-access-key \
    --user-name hazybeacon-decoy-admin-user \
    --access-key-id {} --status Inactive
```

**Remove Malicious Lambda Execution Role Policies and Clean Up Role**

```bash
# Remove the emergency deny inline policy from the role (cleanup)
aws iam delete-role-policy \
  --role-name hazybeacon-lambda-exec-role \
  --policy-name EmergencyRoleDenyAll

# Detach all managed policies from the role
aws iam list-attached-role-policies --role-name hazybeacon-lambda-exec-role \
  --query 'AttachedPolicies[*].PolicyArn' --output text | \
  xargs -I{} aws iam detach-role-policy --role-name hazybeacon-lambda-exec-role --policy-arn {}

# Delete the role (after all policies detached and instance profiles removed)
aws iam delete-role --role-name hazybeacon-lambda-exec-role
```

**Check for Any CloudWatch Events or EventBridge Rules That Could Re-invoke the Lambda**

```bash
# List EventBridge rules that targeted the BackupHandler Lambda
aws events list-rules --query 'Rules[*].{Name:Name,State:State,Schedule:ScheduleExpression}' --output table

# Look for rules targeting the BackupHandler ARN
aws events list-targets-by-rule --rule RULE_NAME_IF_FOUND \
  --query 'Targets[?Arn contains `BackupHandler`]'
```

**Terminate (or Stop) the Compromised EC2 Instance**

```bash
# After forensic snapshot is confirmed complete (check snapshot state first)
aws ec2 describe-snapshots \
  --filters "Name=tag:Incident,Values=HazyBeacon" \
  --query 'Snapshots[*].{ID:SnapshotId,State:State,Progress:Progress}' \
  --output table

# Once snapshot state = completed, stop (not terminate) for further forensic analysis
aws ec2 stop-instances --instance-ids $INSTANCE_ID

# To fully terminate after forensic review:
# aws ec2 terminate-instances --instance-ids $INSTANCE_ID
```

---

## 5. Recovery

### Restore Clean State

**Re-provision the Developer Workstation from a Clean AMI**

```bash
# Launch a replacement instance from a known-good, hardened AMI
# Replace SUBNET_ID, SG_ID, KEY_NAME, CLEAN_AMI_ID, INSTANCE_PROFILE with actual values
aws ec2 run-instances \
  --image-id CLEAN_AMI_ID \
  --instance-type t3.medium \
  --subnet-id SUBNET_ID \
  --security-group-ids SG_ID \
  --key-name KEY_NAME \
  --iam-instance-profile Name=INSTANCE_PROFILE \
  --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=hazybeacon-dev-instance-rebuilt},{Key=Purpose,Value=DeveloperWorkstation}]'
```

**Issue New IAM Credentials to the Affected Developer**

```bash
# Create new access key for the legitimate developer (after account is confirmed clean)
aws iam create-access-key --user-name USERNAME \
  --query 'AccessKey.{KeyId:AccessKeyId,Secret:SecretAccessKey}' \
  --output table
# Deliver via secure channel (not Slack/email plaintext)

# Re-enable console login with temporary password requiring reset
aws iam create-login-profile \
  --user-name USERNAME \
  --password "TempPassword-$(openssl rand -hex 8)" \
  --password-reset-required
```

**Verify GuardDuty Is Active and Not Suppressed**

```bash
# Confirm GuardDuty detector is enabled
aws guardduty list-detectors --query 'DetectorIds' --output text | \
  xargs aws guardduty get-detector --detector-id \
  --query '{Status:Status,UpdatedAt:UpdatedAt,Features:Features[*].Name}' --output table

# Check for any suppression rules that might be hiding HazyBeacon-related findings
aws guardduty list-filter \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --query 'FilterNames' --output table
```

**Verify No Lambda Functions with Public URLs Remain**

```bash
# List all Lambda functions in the account and check for Function URLs
aws lambda list-functions --query 'Functions[*].FunctionName' --output text | \
  tr '\t' '\n' | \
  xargs -I{} sh -c 'result=$(aws lambda get-function-url-config --function-name {} 2>/dev/null); \
    [ -n "$result" ] && echo "Function URL found on: {} -> $(echo $result | jq -r .FunctionUrl)"'
```

**Restore S3 Bucket Policy to Pre-Incident State**

```bash
# After confirming no data was exfiltrated and bucket is clean, restore normal policy
# First review bucket access logs for actual data access during incident window
aws s3api get-bucket-logging --bucket hazybeacon-exfil-bucket

# Remove the emergency deny and restore operational policy
aws s3api delete-bucket-policy --bucket hazybeacon-exfil-bucket
# Then re-apply the legitimate policy from your IaC state (Terraform/Pulumi)
```

**Enable S3 Macie on the Exfil Bucket for Ongoing Monitoring**

```bash
# Create a Macie job targeting the exfil bucket
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "IR-HazyBeacon-PostIncident-Scan" \
  --s3-job-definition '{
    "bucketDefinitions": [{
      "accountId": "ACCOUNT_ID",
      "buckets": ["hazybeacon-exfil-bucket"]
    }]
  }'
```

**Confirm CloudTrail Integrity**

```bash
# Validate CloudTrail log file integrity for the incident window
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:REGION:ACCOUNT_ID:trail/TRAIL_NAME \
  --start-time "INCIDENT_START_TIME" \
  --end-time "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --verbose
```

**Verify No Lingering Rogue Resources**

```bash
# Audit all Lambda functions created in the last 7 days
aws lambda list-functions \
  --query 'Functions[?LastModified>=`INCIDENT_MINUS_7_DAYS`].{Name:FunctionName,Role:Role,Modified:LastModified}' \
  --output table

# Audit all IAM users and roles created in the last 7 days
aws iam get-account-authorization-details \
  --filter User \
  --query 'UserDetailList[?CreateDate>=`INCIDENT_MINUS_7_DAYS`].{User:UserName,Created:CreateDate}' \
  --output table

aws iam get-account-authorization-details \
  --filter Role \
  --query 'RoleDetailList[?CreateDate>=`INCIDENT_MINUS_7_DAYS`].{Role:RoleName,Created:CreateDate}' \
  --output table
```

---

## 6. Lessons Learned

### Timeline Reconstruction

| Phase | Technique | Key Evidence |
|---|---|---|
| T+0 | Spearphishing (T1598.003) | Browser history / email gateway logs |
| T+? | HazyBeacon backdoor installed on workstation | EDR: browser -> script -> backdoor process chain |
| T+? | Credential theft from `~/.aws/credentials` (T1552.001) | auditd: file open by unexpected process |
| T+? | First AWS API call with stolen key (T1078.004) | CloudTrail: `GetCallerIdentity` from anomalous IP |
| T+? | IAM + S3 + Secrets enumeration (T1087.004, T1069.003) | CloudTrail: burst of read events in single session |
| T+? | BackupHandler Lambda deployed with public URL (T1648) | CloudTrail: CreateFunction + CreateFunctionUrlConfig |
| T+? | Masking tags applied (T1564) | CloudTrail: TagResource within seconds of CreateFunction |
| T+? | C2 beaconing over Lambda URL (T1102, T1090) | VPC Flow Logs: periodic HTTPS to *.lambda-url.*.on.aws |
| T+? | S3 recon for exfil targets (T1041) | S3 server access logs: ListObjects + HeadObject on terraform.tfstate |

### What Would Have Prevented This

| Gap | Guardrail |
|---|---|
| Static long-lived IAM access keys on developer workstation | Enforce IAM Identity Center (SSO) for all human access; no static keys for developers |
| No MFA on developer IAM user | Require MFA via SCP: `aws:MultiFactorAuthPresent: true` condition on all sensitive actions |
| Lambda Function URL with `AuthType: NONE` not blocked | Implement SCP or AWS Config rule `lambda-function-public-access-prohibited`; deny `lambda:CreateFunctionUrlConfig` with `authType: NONE` via SCP |
| No detection on IAM enumeration burst | GuardDuty + CloudWatch metric filter on IAM read event volume per-user per-hour; alert at threshold |
| `~/.aws/credentials` readable by backdoor process | Use Instance Metadata Service v2 only (`HttpTokens: required`); no static credentials on EC2 filesystem; EDR process-level file access monitoring |
| Lambda created by non-automation IAM user not alerted | SCM: require Lambda deployments from CI/CD role only via SCP; alert on `CreateFunction` from IAM user (not role) principals |
| SecretsManager not alerted on first-time access by dev user | Enable Macie + CloudWatch alarm on `ListSecrets`/`DescribeSecret` from non-automation principals |
| No Terraform state validation against deployed infra | Terraform drift detection (Driftle, Firefly, or native `terraform plan`) catches `ManagedBy:terraform` tag on function absent from state |

### Recommended Follow-On Actions

```bash
# 1. Apply SCP blocking Lambda Function URLs with no auth across the OU
# Add to your Organization SCP:
cat <<'EOF'
{
  "Effect": "Deny",
  "Action": ["lambda:CreateFunctionUrlConfig", "lambda:UpdateFunctionUrlConfig"],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "lambda:FunctionUrlAuthType": "NONE"
    }
  }
}
EOF

# 2. Apply SCP requiring MFA for all IAM key operations
cat <<'EOF'
{
  "Effect": "Deny",
  "Action": ["iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:UpdateAccessKey"],
  "Resource": "*",
  "Condition": {
    "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
  }
}
EOF

# 3. Enable IMDSv2-only on all existing EC2 instances
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[?MetadataOptions.HttpTokens!=`required`].InstanceId' \
  --output text | tr '\t' '\n' | \
  xargs -I{} aws ec2 modify-instance-metadata-options \
    --instance-id {} \
    --http-tokens required \
    --http-endpoint enabled
```