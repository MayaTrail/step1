---
id: aws-cloudtrail-stoplogging
api_call: cloudtrail:StopLogging
required_inputs:
  - INCIDENT_START_TIME
  - CALLER_ARN
  - ACCOUNT_ID
  - TRAIL_NAME
  - REGION
provided_outputs:
  - DISABLED_TRAIL_ARN
  - STOP_LOGGING_TIME
  - BLIND_WINDOW_DURATION
  - SOURCE_IP
---

# Playbook: CloudTrail StopLogging - CRITICAL: Audit Logging Disabled

> **THIS IS A P1 INCIDENT. StopLogging should NEVER occur in production. Re-enable logging IMMEDIATELY before any other action.**

## 1. Governance & Metadata

| Field | Value |
|---|---|
| **Playbook Name** | CloudTrail StopLogging - Audit Logging Disabled |
| **Playbook ID** | PB-AWS-CloudTrail-StopLogging-01 |
| **Version** | 1.0 |
| **Scenario** | An adversary disables CloudTrail logging to blind the organization to subsequent malicious activity. In the SCARLETEEL campaign, the attacker called `StopLogging` at 19:34:37 UTC (same second as `DescribeTrails`) from a compromised EC2 instance role to create an unmonitored window. During this blind window, the attacker exfiltrated S3 data and harvested secrets from SecretsManager. **There is no legitimate reason for StopLogging in production.** |
| **Trigger** | CloudTrail `eventName = StopLogging` |
| **Prerequisites** | CloudTrail logging enabled in target account; Athena table configured over CloudTrail S3 bucket; IAM permissions for incident-response role; AWS CLI v2 installed and configured; Auto-remediation Lambda or EventBridge rule for immediate re-enable |
| **MITRE ATT&CK** | T1562.008 (Impair Defenses: Disable Cloud Logs) |
| **Stakeholders** | Security On-Call (Immediate Page), IR Lead (Incident Commander), Cloud Security Engineering (Containment), CISO (Executive Notification within 1 hour), Legal/Compliance (if blind window > 15 minutes) |
| **SLA** | Re-enable logging within 5 minutes; Triage within 10 minutes; Full containment within 30 minutes; Investigation within 4 hours |
| **Compliance** | SOC 2 CC7.2, NIST 800-53 AU-6 / AU-9 / SI-4, PCI-DSS 10.5.2 / 10.7, HIPAA 164.312(b) |

### Severity Matrix

| Severity | Measurable Conditions |
|---|---|
| **CRITICAL** | ANY `StopLogging` event in ANY account. There is no legitimate production use case. Every occurrence is treated as CRITICAL regardless of caller, source IP, or time of day. |
| **CRITICAL** | `StopLogging` followed by any data-plane activity (S3 GetObject, SecretsManager GetSecretValue, etc.) from the same `CALLER_ARN` within 60 minutes |
| **CRITICAL** | `StopLogging` where the blind window duration exceeds 5 minutes before re-enablement |

### Related Playbooks

Typically preceded by PB-AWS-CloudTrail-DescribeTrails-01. After logging is disabled, expect PB-AWS-S3-GetObject-01 and PB-AWS-STS-GetCallerIdentity-01 activity. See PB-AWS-CAMPAIGN-SCARLETEEL-01.

---

## 2. Triage & Validation

### 2.0 IMMEDIATE ACTION: Re-Enable Logging

> **Do this FIRST. Do not wait for triage. Re-enable logging before anything else.**

```bash
aws cloudtrail start-logging \
  --name <TRAIL_NAME> \
  --region <REGION>
```

**Verify logging is restored:**

```bash
aws cloudtrail get-trail-status \
  --name <TRAIL_NAME> \
  --region <REGION> \
  --query "{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}" \
  --output table
```

**If `start-logging` fails (attacker may have deleted the trail or modified permissions):**

```bash
# Check if trail still exists
aws cloudtrail describe-trails \
  --trail-name-list <TRAIL_NAME> \
  --region <REGION>

# If trail was deleted, recreate it
aws cloudtrail create-trail \
  --name <TRAIL_NAME> \
  --s3-bucket-name <S3_BUCKET_NAME> \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --region <REGION>

aws cloudtrail start-logging --name <TRAIL_NAME> --region <REGION>
```

### 2.1 Automated Enrichment Checks

**Step 1: Retrieve the StopLogging event**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --max-results 10 \
  --output json
```

**Step 2: Extract caller identity, source IP, and user agent**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --output json | jq '
    .Events[] |
    .CloudTrailEvent | fromjson |
    {
      eventTime,
      userIdentity: .userIdentity.arn,
      sourceIPAddress,
      userAgent,
      requestParameters,
      trailARN: .requestParameters.name
    }'
```

**Step 3: Calculate the blind window duration**

```bash
# Get StopLogging time
STOP_TIME=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --output json | jq -r '.Events[0].EventTime')

# Get subsequent StartLogging time (if any)
START_TIME=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StartLogging \
  --start-time "$STOP_TIME" \
  --region <REGION> \
  --output json | jq -r '.Events[0].EventTime // "STILL_DISABLED"')

echo "Blind Window: $STOP_TIME to $START_TIME"
```

**Step 4: Identify the compromised role and instance**

```bash
aws iam get-role \
  --role-name "$(echo <CALLER_ARN> | sed 's|.*/||')" \
  --query "Role.{RoleName:RoleName,AssumeRolePolicyDocument:AssumeRolePolicyDocument,MaxSessionDuration:MaxSessionDuration}" \
  --output json
```

**Step 5: Check for preceding DescribeTrails (SCARLETEEL pattern)**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$(echo <CALLER_ARN> | sed 's|.*/||')" \
  --start-time "$(date -u -d '<INCIDENT_START_TIME> - 5 minutes' +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --output json | jq '[.Events[].CloudTrailEvent | fromjson | select(.eventName == "DescribeTrails")]'
```

**Step 6: Identify activity DURING the blind window (from alternative log sources)**

```bash
# Check VPC Flow Logs for the compromised instance during blind window
aws logs filter-log-events \
  --log-group-name <VPC_FLOW_LOG_GROUP> \
  --start-time $(date -d "<STOP_LOGGING_TIME>" +%s)000 \
  --end-time $(date -d "<START_TIME>" +%s)000 \
  --filter-pattern "<INSTANCE_ENI_ID>" \
  --output json | jq '.events[].message'
```

### 2.2 Decision Gates

| Condition | Action |
|---|---|
| **IF** `StopLogging` event is confirmed | **THEN** ALWAYS escalate to CRITICAL. Page Security On-Call immediately. There are no exceptions. |
| **IF** logging was not already re-enabled by automation | **THEN** re-enable logging immediately (Section 2.0) |
| **IF** `DescribeTrails` precedes `StopLogging` within 300 seconds from the same principal | **THEN** confirm SCARLETEEL attack pattern, activate full IR procedure, cross-reference PB-AWS-CloudTrail-DescribeTrails-01 |
| **IF** blind window exceeds 15 minutes | **THEN** notify Legal/Compliance; assume data exfiltration occurred during the window |
| **IF** any data-access API calls (S3 GetObject, SecretsManager GetSecretValue, etc.) are observed from the same CALLER_ARN after StopLogging | **THEN** activate data breach investigation procedures |
| **IF** caller is an automation/CI account | **THEN** still treat as CRITICAL; investigate how the automation account was compromised or misconfigured |

---

## 3. Containment Strategy

> **WARNING**: Before executing L2 or L3 actions, verify whether the target resource has the tag `Critical-Production-App`. If tagged, obtain explicit approval from the application owner and IR Lead before proceeding. **However, L1 (re-enable logging) must NEVER be delayed for any reason.**

```bash
# Check for Critical-Production-App tag on the EC2 instance (if applicable)
aws ec2 describe-tags \
  --filters "Name=resource-id,Values=<INSTANCE_ID>" "Name=key,Values=Critical-Production-App" \
  --region <REGION> \
  --output json
```

| Level | Action | Command | Rollback |
|---|---|---|---|
| **L1 - Immediate** | Re-enable CloudTrail logging (DO THIS FIRST) | `aws cloudtrail start-logging --name <TRAIL_NAME> --region <REGION>` | N/A - logging must remain enabled |
| **L1 - Immediate** | Verify logging is active and delivering | `aws cloudtrail get-trail-status --name <TRAIL_NAME> --region <REGION> --query "{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}"` | N/A |
| **L2 - Restrict** | Attach inline deny policy blocking CloudTrail modifications on the compromised role | `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name DenyCloudTrailModification --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["cloudtrail:StopLogging","cloudtrail:DeleteTrail","cloudtrail:UpdateTrail","cloudtrail:PutEventSelectors"],"Resource":"*"}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name DenyCloudTrailModification` |
| **L2 - Restrict** | Revoke all active sessions for the compromised role | `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name RevokeOlderSessions --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<INCIDENT_START_TIME>"}}}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name RevokeOlderSessions` |
| **L2 - Restrict** | Deny the compromised principal all actions via inline policy | `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name FullDeny --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name FullDeny` |
| **L3 - Isolate** | Isolate the EC2 instance by replacing its security group | `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <FORENSICS_SG_ID> --region <REGION>` | `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <ORIGINAL_SG_ID> --region <REGION>` |
| **L3 - Isolate** | Detach the instance profile to stop all API access | `aws ec2 disassociate-iam-instance-profile --association-id <IAM_ASSOCIATION_ID> --region <REGION>` | `aws ec2 associate-iam-instance-profile --instance-id <INSTANCE_ID> --iam-instance-profile Name=<ORIGINAL_INSTANCE_PROFILE> --region <REGION>` |
| **L3 - Isolate** | Stop the compromised instance (preserve for forensics, do not terminate) | `aws ec2 stop-instances --instance-ids <INSTANCE_ID> --region <REGION>` | `aws ec2 start-instances --instance-ids <INSTANCE_ID> --region <REGION>` |

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

The primary investigation question is: **What happened during the blind window while logging was disabled?**

1. How long was the blind window (time between StopLogging and StartLogging)?
2. What data-access API calls were made by the attacker during or after StopLogging?
3. Were S3 objects exfiltrated? (Check S3 access logs, VPC Flow Logs)
4. Were secrets harvested from SecretsManager or SSM Parameter Store?
5. Did the attacker create persistence mechanisms (new IAM users, access keys, backdoor roles)?
6. Were other trails in other regions also disabled?
7. Is there evidence of lateral movement to other AWS accounts?
8. What other principals were used from the same source IP? (lateral movement detection)
9. What is the maximum blast radius based on the compromised role's permissions?

### 4.2 Athena Query - StopLogging Events

```sql
SELECT
    eventTime,
    eventName,
    userIdentity.arn AS caller_arn,
    userIdentity.principalId AS principal_id,
    userIdentity.accountId AS account_id,
    sourceIPAddress,
    userAgent,
    awsRegion,
    requestParameters,
    responseElements,
    errorCode,
    errorMessage
FROM cloudtrail_logs
WHERE eventName = 'StopLogging'
  AND userIdentity.arn = '<CALLER_ARN>'
  AND eventTime >= '<INCIDENT_START_TIME>'
  AND awsRegion = '<REGION>'
ORDER BY eventTime ASC;
```

### 4.3 Athena Query - All Activity by Attacker (Before, During, and After Blind Window)

```sql
SELECT
    eventTime,
    eventSource,
    eventName,
    sourceIPAddress,
    userAgent,
    requestParameters,
    responseElements,
    errorCode
FROM cloudtrail_logs
WHERE userIdentity.arn = '<CALLER_ARN>'
  AND eventTime BETWEEN
      date_add('hour', -1, timestamp '<INCIDENT_START_TIME>')
      AND date_add('hour', 6, timestamp '<INCIDENT_START_TIME>')
ORDER BY eventTime ASC;
```

### 4.4 Athena Query - Identify All StopLogging Across All Regions

```sql
SELECT
    eventTime,
    eventName,
    userIdentity.arn AS caller_arn,
    sourceIPAddress,
    awsRegion,
    requestParameters
FROM cloudtrail_logs
WHERE eventName IN ('StopLogging', 'DeleteTrail', 'UpdateTrail')
  AND eventTime >= '<INCIDENT_START_TIME>'
ORDER BY eventTime ASC;
```

### 4.5 Athena Query - Data Access During/After Blind Window (SCARLETEEL Pattern)

```sql
SELECT
    eventTime,
    eventSource,
    eventName,
    sourceIPAddress,
    requestParameters,
    responseElements
FROM cloudtrail_logs
WHERE userIdentity.arn = '<CALLER_ARN>'
  AND eventName IN (
      'GetObject', 'ListObjects', 'ListBuckets',
      'GetSecretValue', 'ListSecrets',
      'GetParameter', 'GetParameters', 'GetParametersByPath',
      'CreateAccessKey', 'CreateUser', 'CreateRole',
      'AssumeRole'
  )
  AND eventTime >= '<INCIDENT_START_TIME>'
ORDER BY eventTime ASC;
```

### 4.6 Source IP Pivot — Detect Lateral Movement

**Why this matters:** Attackers who steal credentials often use multiple identity sets from the same machine. Pivoting on the source IP (not the principal) catches lateral movement that a principal-only query would miss entirely. In SCARLETEEL, this is how the pivot from the EC2 role to `scarleteel-secondary-user` is detected.

**Athena — All principals that called APIs from the attacker's source IP:**

```sql
SELECT
    userIdentity.arn AS principal_arn,
    sourceIPAddress,
    COUNT(*) AS call_count,
    MIN(eventTime) AS first_seen,
    MAX(eventTime) AS last_seen,
    array_agg(DISTINCT eventName) AS api_calls
FROM cloudtrail_logs
WHERE sourceIPAddress = '<SOURCE_IP>'
  AND eventTime BETWEEN
      date_add('hour', -2, timestamp '<INCIDENT_START_TIME>')
      AND date_add('hour', 12, timestamp '<INCIDENT_START_TIME>')
GROUP BY userIdentity.arn, sourceIPAddress
ORDER BY first_seen ASC;
```

**AWS CLI equivalent (if Athena is not configured):**

```bash
aws cloudtrail lookup-events \
  --start-time "$(date -u -d '<INCIDENT_START_TIME> - 2 hours' +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "$(date -u -d '<INCIDENT_START_TIME> + 12 hours' +%Y-%m-%dT%H:%M:%SZ)" \
  --region <REGION> --max-results 50 --output json | jq '
    [.Events[] |
     .CloudTrailEvent | fromjson |
     select(.sourceIPAddress == "<SOURCE_IP>") |
     {eventTime, eventName, principalArn: .userIdentity.arn}]
     | group_by(.principalArn)
     | map({principal: .[0].principalArn, call_count: length, events: [.[].eventName] | unique})'
```

**What to look for:**
- Multiple distinct `userIdentity.arn` values from the same IP = lateral movement confirmed
- A new principal appearing AFTER StopLogging = attacker obtained additional credentials during the blind window
- Calls from the same IP to different AWS accounts = cross-account lateral movement

### 4.7 Blast Radius Scoping — Maximum Possible Damage

**Why this matters:** During the blind window, you cannot see what the attacker did. But you can determine what they COULD have done based on the compromised role's permissions. This defines your worst-case breach scope and drives what credentials/secrets must be rotated.

**Pull all policies attached to the compromised role:**

```bash
# Inline policies
aws iam list-role-policies --role-name <ROLE_NAME> --output json

# For each inline policy
aws iam get-role-policy --role-name <ROLE_NAME> --policy-name <POLICY_NAME> --output json | jq '.PolicyDocument'

# Managed policies
aws iam list-attached-role-policies --role-name <ROLE_NAME> --output json

# For each managed policy
aws iam get-policy-version \
  --policy-arn <POLICY_ARN> \
  --version-id $(aws iam get-policy --policy-arn <POLICY_ARN> --query 'Policy.DefaultVersionId' --output text) \
  --output json | jq '.PolicyVersion.Document'
```

**Athena — Enumerate all services the compromised principal has ever called (historical baseline):**

```sql
SELECT
    eventSource,
    COUNT(*) AS call_count,
    array_agg(DISTINCT eventName) AS api_calls
FROM cloudtrail_logs
WHERE userIdentity.arn = '<CALLER_ARN>'
  AND eventTime >= date_add('day', -30, current_timestamp)
GROUP BY eventSource
ORDER BY call_count DESC;
```

**Document the blast radius:**

| Permission | Resource Scope | Worst-Case During Blind Window |
|------------|---------------|-------------------------------|
| (Fill from policy document) | (ARN or `*`) | (Assume exercised — what data/secrets are at risk?) |

**Decision framework:**
- If the role has `s3:GetObject` on `*` → assume all S3 data in the account was exfiltrated
- If the role has `secretsmanager:GetSecretValue` on `*` → assume all secrets were harvested
- If the role has `iam:Create*` → assume backdoor users/keys were created (check current IAM state)
- If the role has `lambda:GetFunction` on `*` → assume all function source code was stolen

### 4.8 Evidence Preservation

**Snapshot the CloudTrail event log (preserve what was captured BEFORE StopLogging):**

```bash
aws s3 cp s3://<S3_BUCKET_NAME>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<REGION>/ \
  s3://<FORENSICS_BUCKET>/incidents/PB-AWS-CloudTrail-StopLogging-01/<ACCOUNT_ID>/cloudtrail-logs/ \
  --recursive \
  --include "*.json.gz" \
  --region <REGION>
```

**Preserve S3 server access logs (may capture activity during blind window):**

```bash
aws s3 cp s3://<S3_ACCESS_LOG_BUCKET>/ \
  s3://<FORENSICS_BUCKET>/incidents/PB-AWS-CloudTrail-StopLogging-01/<ACCOUNT_ID>/s3-access-logs/ \
  --recursive \
  --region <REGION>
```

**Create EBS snapshot of compromised instance:**

```bash
aws ec2 create-snapshot \
  --volume-id <VOLUME_ID> \
  --description "Forensics snapshot - PB-AWS-CloudTrail-StopLogging-01 - $(date -u +%Y%m%dT%H%M%SZ)" \
  --tag-specifications 'ResourceType=snapshot,Tags=[{Key=Incident,Value=PB-AWS-CloudTrail-StopLogging-01},{Key=PreservedBy,Value=IR-Team},{Key=Classification,Value=Critical}]' \
  --region <REGION>
```

**Capture memory dump (if instance is still running):**

```bash
aws ssm send-command \
  --instance-ids <INSTANCE_ID> \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["dd if=/dev/mem of=/tmp/memory-dump.bin bs=1M count=4096 2>/dev/null; aws s3 cp /tmp/memory-dump.bin s3://<FORENSICS_BUCKET>/incidents/PB-AWS-CloudTrail-StopLogging-01/<ACCOUNT_ID>/memory/"]' \
  --region <REGION>
```

---

## 5. Recovery & Hardening

### 5.1 Sanitize

- Rotate ALL credentials associated with `<CALLER_ARN>`
- Revoke ALL active STS sessions for the compromised role
- Rotate any secrets that may have been accessed during the blind window
- If EC2 instance is compromised, terminate and replace from a known-good AMI

```bash
# Rotate access keys for any IAM user linked to the compromise
aws iam list-access-keys --user-name <COMPROMISED_USER> --output json
aws iam create-access-key --user-name <COMPROMISED_USER>
aws iam delete-access-key --user-name <COMPROMISED_USER> --access-key-id <OLD_ACCESS_KEY_ID>

# Rotate secrets that may have been accessed
aws secretsmanager rotate-secret --secret-id <SECRET_ID> --region <REGION>
```

### 5.2 Restore

- Verify ALL CloudTrail trails across ALL regions are actively logging

```bash
for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "=== $region ==="
  aws cloudtrail describe-trails --region "$region" \
    --query "trailList[].Name" --output text | while read trail; do
    status=$(aws cloudtrail get-trail-status --name "$trail" --region "$region" \
      --query "IsLogging" --output text)
    echo "  $trail: IsLogging=$status"
    if [ "$status" = "False" ]; then
      echo "  WARNING: Re-enabling logging on $trail"
      aws cloudtrail start-logging --name "$trail" --region "$region"
    fi
  done
done
```

- Verify log file validation is enabled

```bash
aws cloudtrail describe-trails --region <REGION> \
  --query "trailList[].{Name:Name,LogFileValidation:LogFileValidationEnabled,IsMultiRegion:IsMultiRegionTrail}" \
  --output table
```

### 5.3 Harden with SCPs

**Deploy an SCP that prevents ANY principal from calling StopLogging or DeleteTrail**, except a break-glass role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyStopLoggingAndDeleteTrail",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/BreakGlassRole"
          ]
        }
      }
    }
  ]
}
```

```bash
aws organizations create-policy \
  --name "DenyCloudTrailDisable" \
  --description "Prevent any principal from disabling or deleting CloudTrail trails" \
  --type SERVICE_CONTROL_POLICY \
  --content file://deny-cloudtrail-disable-scp.json

aws organizations attach-policy \
  --policy-id <POLICY_ID> \
  --target-id <ROOT_OU_ID>
```

**Deploy an EventBridge rule to auto-remediate any StopLogging call:**

```bash
aws events put-rule \
  --name "AutoRemediateStopLogging" \
  --event-pattern '{
    "source": ["aws.cloudtrail"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["StopLogging"]
    }
  }' \
  --region <REGION>

aws events put-targets \
  --rule "AutoRemediateStopLogging" \
  --targets '[{
    "Id": "ReEnableLogging",
    "Arn": "<AUTO_REMEDIATION_LAMBDA_ARN>"
  }]' \
  --region <REGION>
```

### 5.4 Verify

```bash
# Confirm all trails are logging
aws cloudtrail describe-trails --region <REGION> \
  --query "trailList[].{Name:Name,S3BucketName:S3BucketName,IsMultiRegion:IsMultiRegionTrail,LogValidation:LogFileValidationEnabled}" \
  --output table

# Confirm SCP is attached at the root OU
aws organizations list-policies-for-target \
  --target-id <ROOT_OU_ID> \
  --filter SERVICE_CONTROL_POLICY \
  --output table

# Confirm EventBridge auto-remediation rule is active
aws events describe-rule \
  --name "AutoRemediateStopLogging" \
  --region <REGION> \
  --query "{State:State,EventPattern:EventPattern}" \
  --output json

# Test that SCP blocks StopLogging (from a non-break-glass role)
aws cloudtrail stop-logging --name <TRAIL_NAME> --region <REGION>
# Expected: AccessDeniedException
```

### 5.5 Post-Mortem

- Document the full SCARLETEEL-pattern timeline: initial access -> DescribeTrails -> StopLogging -> data exfiltration -> secrets harvesting
- Calculate exact blind window duration and document all activities that occurred during it
- Identify all data that may have been exfiltrated during the blind window
- Determine why the SCP to prevent StopLogging was not already in place
- Determine why auto-remediation did not re-enable logging faster (or why it did not exist)
- Evaluate alternative log sources that provided visibility during the blind window (VPC Flow Logs, S3 access logs, GuardDuty)
- Review all IAM roles with `cloudtrail:StopLogging` permission and remove it where not needed
- Mandate SCP deployment across all organizational units within 7 days
- Schedule red team exercise to validate detection and auto-remediation within 14 days

---

## Detection Rule (Sigma Format)

```yaml
title: CloudTrail StopLogging - Audit Logging Disabled
id: 2f8a6b9c-d4e1-4f3a-8c7d-1e5b9f2a3c6d
status: stable
description: >
  Detects calls to cloudtrail:StopLogging which disables audit logging.
  This is always a critical security event. In the SCARLETEEL campaign,
  StopLogging was used to create a blind window for data exfiltration
  and secrets harvesting. There is no legitimate reason for this API call
  in production environments.
author: MayaTrail IR Team
date: 2026/04/05
references:
  - https://sysdig.com/blog/scarleteel-2-0/
  - https://attack.mitre.org/techniques/T1562/008/
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: StopLogging
    eventSource: cloudtrail.amazonaws.com
  condition: selection
falsepositives:
  - There are no expected false positives in production. Any StopLogging event warrants investigation.
level: critical
tags:
  - attack.defense_evasion
  - attack.t1562.008
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Relevance |
|---|---|---|---|
| Defense Evasion | T1562.008 | Impair Defenses: Disable Cloud Logs | Attacker disables CloudTrail logging to create a blind window for subsequent malicious activity |
| Defense Evasion | T1070 | Indicator Removal | Disabling logging prevents creation of audit evidence for attacker actions during the blind window |
| Persistence | T1098 | Account Manipulation | Attacker may create backdoor IAM users/roles during the blind window when logging is disabled |
| Exfiltration | T1537 | Transfer Data to Cloud Account | SCARLETEEL pattern: S3 data exfiltration performed during the blind window |
| Credential Access | T1528 | Steal Application Access Token | SCARLETEEL pattern: SecretsManager secrets harvested during the blind window |
| Discovery | T1526 | Cloud Service Discovery | Preceding DescribeTrails call used to identify which trails to disable |
