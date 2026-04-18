---
id: aws-cloudtrail-describetrails
api_call: cloudtrail:DescribeTrails
required_inputs:
  - INCIDENT_START_TIME
  - CALLER_ARN
  - ACCOUNT_ID
  - REGION
provided_outputs:
  - TRAIL_NAMES
  - TRAIL_ARNS
  - S3_BUCKET_NAMES
  - SOURCE_IP
---

# Playbook: CloudTrail DescribeTrails Reconnaissance

## 1. Governance & Metadata

| Field | Value |
|---|---|
| **Playbook Name** | CloudTrail DescribeTrails Reconnaissance |
| **Playbook ID** | PB-AWS-CloudTrail-DescribeTrails-01 |
| **Version** | 1.0 |
| **Scenario** | An adversary enumerates CloudTrail trail configurations to identify logging infrastructure before disabling it. In the SCARLETEEL campaign, the attacker called `DescribeTrails` from a compromised EC2 instance role (`i-0aea82a9977cd62a4`) at 19:34:37 UTC, immediately followed by `StopLogging` in the same second, indicating automated tooling designed to discover and disable audit logging. |
| **Trigger** | CloudTrail `eventName = DescribeTrails` |
| **Prerequisites** | CloudTrail logging enabled in target account; Athena table configured over CloudTrail S3 bucket; IAM permissions for incident-response role; AWS CLI v2 installed and configured |
| **MITRE ATT&CK** | T1526 (Cloud Service Discovery), T1580 (Cloud Infrastructure Discovery) |
| **Stakeholders** | Security Operations (Triage), Cloud Security Engineering (Containment), IR Lead (Escalation), CISO (Executive Notification) |
| **SLA** | Triage within 15 minutes of alert; Containment decision within 30 minutes; Full investigation within 4 hours |
| **Compliance** | SOC 2 CC7.2, NIST 800-53 AU-6, PCI-DSS 10.6.1 |

### Severity Matrix

| Severity | Measurable Conditions |
|---|---|
| **CRITICAL** | `DescribeTrails` is followed by `StopLogging`, `DeleteTrail`, or `UpdateTrail` within 300 seconds from the same `CALLER_ARN` |
| **HIGH** | `DescribeTrails` is called from an IP address not in the organization's known CIDR ranges, OR called by an IAM role attached to an EC2 instance that has never made this call before (first-seen principal) |
| **MEDIUM** | `DescribeTrails` is called by a known administrative principal from a known IP, but outside of a scheduled change window |

### Related Playbooks

Frequently followed by PB-AWS-CloudTrail-StopLogging-01 in attack chains (same-second execution in SCARLETEEL). See PB-AWS-CAMPAIGN-SCARLETEEL-01 for full kill chain context.

---

## 2. Triage & Validation

### 2.1 Automated Enrichment Checks

**Step 1: Retrieve the CloudTrail event**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeTrails \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --max-results 20 \
  --output json
```

**Step 2: Identify the caller identity and source IP**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeTrails \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --query "Events[?CloudTrailEvent != null].{EventTime:EventTime,Username:Username,CloudTrailEvent:CloudTrailEvent}" \
  --output json | jq '.[].CloudTrailEvent | fromjson | {userIdentity, sourceIPAddress, userAgent, requestParameters}'
```

**Step 3: Check if the caller ARN is an EC2 instance role**

```bash
aws iam get-role \
  --role-name "$(echo <CALLER_ARN> | sed 's|.*/||')" \
  --query "Role.{RoleName:RoleName,AssumeRolePolicyDocument:AssumeRolePolicyDocument}" \
  --output json
```

**Step 4: Check for subsequent StopLogging or DeleteTrail within 5 minutes**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$(echo <CALLER_ARN> | sed 's|.*/||')" \
  --start-time "<INCIDENT_START_TIME>" \
  --end-time "$(date -u -d '<INCIDENT_START_TIME> + 5 minutes' +%Y-%m-%dT%H:%M:%SZ)" \
  --region <REGION> \
  --output json | jq '[.Events[].CloudTrailEvent | fromjson | .eventName]'
```

**Step 5: Check if this principal has called DescribeTrails before (baseline)**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$(echo <CALLER_ARN> | sed 's|.*/||')" \
  --start-time "$(date -u -d '<INCIDENT_START_TIME> - 90 days' +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --output json | jq '[.Events[].CloudTrailEvent | fromjson | select(.eventName == "DescribeTrails")] | length'
```

### 2.2 Decision Gates

| Condition | Action |
|---|---|
| **IF** `DescribeTrails` is followed by `StopLogging` or `DeleteTrail` within 300s | **THEN** escalate to CRITICAL, trigger PB-AWS-CloudTrail-StopLogging-01, page Security On-Call immediately |
| **IF** source IP is outside known organizational CIDR ranges | **THEN** escalate to HIGH, proceed to Containment L2 |
| **IF** caller is an EC2 instance role AND this is the first-ever `DescribeTrails` call from that role | **THEN** escalate to HIGH, investigate EC2 instance for compromise |
| **IF** caller is a known admin AND source IP is from corporate VPN AND within change window | **THEN** classify as MEDIUM, log and monitor for 24 hours |
| **IF** caller is an automation/CI service account with documented DescribeTrails usage | **THEN** close as informational, update allowlist if needed |

---

## 3. Containment Strategy

> **WARNING**: Before executing L2 or L3 actions, verify whether the target resource has the tag `Critical-Production-App`. If tagged, obtain explicit approval from the application owner and IR Lead before proceeding.

```bash
# Check for Critical-Production-App tag on the EC2 instance (if applicable)
aws ec2 describe-tags \
  --filters "Name=resource-id,Values=<INSTANCE_ID>" "Name=key,Values=Critical-Production-App" \
  --region <REGION> \
  --output json
```

| Level | Action | Command | Rollback |
|---|---|---|---|
| **L1 - Monitor** | Enable enhanced CloudTrail event selectors for management events on all trails | `aws cloudtrail put-event-selectors --trail-name <TRAIL_NAME> --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true}]' --region <REGION>` | `aws cloudtrail put-event-selectors --trail-name <TRAIL_NAME> --event-selectors '[{"ReadWriteType":"WriteOnly","IncludeManagementEvents":true}]' --region <REGION>` |
| **L1 - Monitor** | Create CloudWatch alarm for DescribeTrails + StopLogging pattern | `aws cloudwatch put-metric-alarm --alarm-name "CloudTrail-Recon-<ACCOUNT_ID>" --metric-name DescribeTrailsCount --namespace CloudTrailMetrics --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <SNS_TOPIC_ARN> --region <REGION>` | `aws cloudwatch delete-alarms --alarm-names "CloudTrail-Recon-<ACCOUNT_ID>" --region <REGION>` |
| **L2 - Restrict** | Attach deny policy to the compromised IAM role preventing CloudTrail modifications | `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name DenyCloudTrailModification --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["cloudtrail:StopLogging","cloudtrail:DeleteTrail","cloudtrail:UpdateTrail"],"Resource":"*"}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name DenyCloudTrailModification` |
| **L2 - Restrict** | Revoke all active sessions for the compromised role | `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name RevokeOlderSessions --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<INCIDENT_START_TIME>"}}}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name RevokeOlderSessions` |
| **L3 - Isolate** | Isolate the EC2 instance by replacing its security group with a forensics-only SG | `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <FORENSICS_SG_ID> --region <REGION>` | `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <ORIGINAL_SG_ID> --region <REGION>` |
| **L3 - Isolate** | Detach the instance role to prevent further API calls | `aws ec2 disassociate-iam-instance-profile --association-id <IAM_ASSOCIATION_ID> --region <REGION>` | `aws ec2 associate-iam-instance-profile --instance-id <INSTANCE_ID> --iam-instance-profile Name=<ORIGINAL_INSTANCE_PROFILE> --region <REGION>` |

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

Determine the full scope of the reconnaissance by answering:

1. How many trails exist in the account, and did the attacker enumerate all of them?
2. What other CloudTrail/logging API calls did the same principal make?
3. Did the attacker proceed to disable logging (StopLogging, DeleteTrail)?
4. What other AWS services did the caller interact with in the same session?
5. Is there evidence of lateral movement to other accounts?

### 4.2 Athena Query - DescribeTrails Events

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
WHERE eventName = 'DescribeTrails'
  AND userIdentity.arn = '<CALLER_ARN>'
  AND eventTime >= '<INCIDENT_START_TIME>'
  AND awsRegion = '<REGION>'
ORDER BY eventTime ASC;
```

### 4.3 Athena Query - Full Activity Timeline for Caller

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
  AND eventTime BETWEEN '<INCIDENT_START_TIME>'
      AND date_add('hour', 4, timestamp '<INCIDENT_START_TIME>')
  AND awsRegion = '<REGION>'
ORDER BY eventTime ASC;
```

### 4.4 Evidence Preservation

**Snapshot the CloudTrail event log:**

```bash
aws s3 cp s3://<S3_BUCKET_NAME>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<REGION>/ \
  s3://<FORENSICS_BUCKET>/incidents/PB-AWS-CloudTrail-DescribeTrails-01/<ACCOUNT_ID>/cloudtrail-logs/ \
  --recursive \
  --include "*.json.gz" \
  --region <REGION>
```

**Capture current trail configuration for baseline comparison:**

```bash
aws cloudtrail describe-trails \
  --region <REGION> \
  --output json > /tmp/trail-config-snapshot-$(date -u +%Y%m%dT%H%M%SZ).json

aws s3 cp /tmp/trail-config-snapshot-*.json \
  s3://<FORENSICS_BUCKET>/incidents/PB-AWS-CloudTrail-DescribeTrails-01/<ACCOUNT_ID>/
```

**Create EBS snapshot of compromised instance (if EC2-based):**

```bash
aws ec2 create-snapshot \
  --volume-id <VOLUME_ID> \
  --description "Forensics snapshot - PB-AWS-CloudTrail-DescribeTrails-01 - $(date -u +%Y%m%dT%H%M%SZ)" \
  --tag-specifications 'ResourceType=snapshot,Tags=[{Key=Incident,Value=PB-AWS-CloudTrail-DescribeTrails-01},{Key=PreservedBy,Value=IR-Team}]' \
  --region <REGION>
```

---

## 5. Recovery & Hardening

### 5.1 Sanitize

- Rotate all credentials associated with `<CALLER_ARN>`
- Revoke any temporary STS tokens issued to the compromised role
- If EC2 instance is compromised, terminate and replace from a known-good AMI

```bash
# Rotate access keys (if applicable)
aws iam list-access-keys --user-name <COMPROMISED_USER> --output json
aws iam create-access-key --user-name <COMPROMISED_USER>
aws iam delete-access-key --user-name <COMPROMISED_USER> --access-key-id <OLD_ACCESS_KEY_ID>
```

### 5.2 Restore

- Verify all CloudTrail trails are actively logging

```bash
aws cloudtrail get-trail-status --name <TRAIL_NAME> --region <REGION> \
  --query "{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}" \
  --output table
```

- Verify CloudTrail log file validation is enabled

```bash
aws cloudtrail describe-trails --region <REGION> \
  --query "trailList[].{Name:Name,LogFileValidation:LogFileValidationEnabled}" \
  --output table
```

### 5.3 Harden with SCPs

Apply an SCP to prevent CloudTrail enumeration from non-approved roles:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDescribeTrailsExceptApprovedRoles",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:ListTrails"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/SecurityAuditRole",
            "arn:aws:iam::*:role/OrganizationAccountAccessRole"
          ]
        }
      }
    }
  ]
}
```

```bash
aws organizations create-policy \
  --name "DenyCloudTrailRecon" \
  --description "Prevent non-approved roles from enumerating CloudTrail trails" \
  --type SERVICE_CONTROL_POLICY \
  --content file://deny-cloudtrail-recon-scp.json

aws organizations attach-policy \
  --policy-id <POLICY_ID> \
  --target-id <OU_ID>
```

### 5.4 Verify

```bash
# Confirm trails are logging
aws cloudtrail describe-trails --region <REGION> \
  --query "trailList[].{Name:Name,S3BucketName:S3BucketName,IsMultiRegion:IsMultiRegionTrail}" \
  --output table

# Confirm SCP is attached
aws organizations list-policies-for-target \
  --target-id <OU_ID> \
  --filter SERVICE_CONTROL_POLICY \
  --output table

# Test that blocked role cannot call DescribeTrails
aws sts assume-role --role-arn <TEST_ROLE_ARN> --role-session-name scp-test \
  --query "Credentials" --output json
# Then with assumed creds:
aws cloudtrail describe-trails --region <REGION>
# Expected: AccessDenied
```

### 5.5 Post-Mortem

- Document the full attack timeline (DescribeTrails -> StopLogging -> further actions)
- Identify the initial access vector (e.g., compromised EC2 instance, leaked credentials)
- Evaluate whether existing detection rules caught the activity in time
- Update detection rules to alert on DescribeTrails from non-approved principals
- Review IAM permissions: apply least-privilege to roles that do not need CloudTrail read access
- Schedule tabletop exercise for CloudTrail tampering scenarios within 30 days

---

## Detection Rule (Sigma Format)

```yaml
title: CloudTrail DescribeTrails Reconnaissance
id: 7a3f4c01-e8d2-4b6a-9c1f-3d5e8f2a1b4c
status: experimental
description: >
  Detects calls to cloudtrail:DescribeTrails which may indicate an attacker
  enumerating CloudTrail configuration prior to disabling logging. Observed in
  SCARLETEEL campaign where DescribeTrails was immediately followed by StopLogging.
author: MayaTrail IR Team
date: 2026/04/05
references:
  - https://sysdig.com/blog/scarleteel-2-0/
  - https://attack.mitre.org/techniques/T1526/
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: DescribeTrails
    eventSource: cloudtrail.amazonaws.com
  filter_approved_roles:
    userIdentity.arn|contains:
      - 'SecurityAuditRole'
      - 'OrganizationAccountAccessRole'
  condition: selection and not filter_approved_roles
falsepositives:
  - Legitimate security auditing tools (Prowler, ScoutSuite, AWS Config)
  - Approved administrative roles performing trail inventory
  - AWS Organizations management account operations
level: high
tags:
  - attack.discovery
  - attack.t1526
  - attack.t1580
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Relevance |
|---|---|---|---|
| Discovery | T1526 | Cloud Service Discovery | Attacker enumerates CloudTrail trails to identify logging infrastructure |
| Discovery | T1580 | Cloud Infrastructure Discovery | Attacker maps cloud logging configuration to plan subsequent defense evasion |
| Reconnaissance | T1592.004 | Gather Victim Host Information: Client Configurations | Trail configuration reveals S3 bucket names, multi-region settings, and encryption keys |
| Defense Evasion | T1562.008 | Impair Defenses: Disable Cloud Logs | DescribeTrails is the precursor step enabling targeted StopLogging or DeleteTrail |
