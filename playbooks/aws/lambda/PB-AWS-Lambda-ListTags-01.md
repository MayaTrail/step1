---
id: aws-lambda-listtags
api_call: lambda:ListTags
required_inputs:
  - INCIDENT_START_TIME
  - CALLER_ARN
  - ACCOUNT_ID
  - FUNCTION_ARN
provided_outputs:
  - FUNCTION_TAGS
  - SOURCE_IP
---

# Playbook: Lambda ListTags Reconnaissance

## 1. Governance & Metadata

| Field | Value |
|---|---|
| **Playbook Name** | Lambda ListTags Reconnaissance |
| **Playbook ID** | PB-AWS-Lambda-ListTags-01 |
| **Version** | 1.0 |
| **Scenario** | Attacker enumerates Lambda function tags to discover environment classification (prod/dev/staging), ownership, cost center, and organizational structure. In SCARLETEEL, tag enumeration helped the attacker prioritize high-value targets and understand the deployment topology. |
| **Trigger** | CloudTrail `eventName: ListTags20170331` |
| **MITRE ATT&CK** | T1526 - Cloud Service Discovery |

### Severity Matrix

| Severity | Condition |
|---|---|
| **CRITICAL** | CALLER_ARN is not in the approved IAM roles list AND source IP is outside corporate CIDR blocks AND call targets >= 5 distinct function ARNs within 10 minutes |
| **HIGH** | CALLER_ARN is an EC2 instance profile role AND call targets >= 3 distinct function ARNs within 30 minutes OR call originates from a non-management subnet |
| **MEDIUM** | CALLER_ARN is a known service role but the call occurs outside business hours (00:00-06:00 UTC) OR targets a function tagged `Environment:production` |

### Prerequisites

- CloudTrail logging enabled in target account with management events captured
- Athena table configured for CloudTrail logs
- AWS CLI v2 installed and configured with incident response role
- Access to SecurityHub or equivalent SIEM

### MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Procedure |
|---|---|---|---|
| Discovery | T1526 Cloud Service Discovery | N/A | Enumerate Lambda function tags to reveal environment classification and organizational metadata |

### Stakeholders

| Role | Responsibility |
|---|---|
| SOC Analyst (L1) | Initial triage, severity classification, escalation |
| IR Lead (L2) | Containment decisions, investigation coordination |
| Cloud Security Engineer (L3) | Forensic analysis, hardening, root cause analysis |
| Application Owner | Validate legitimate use, approve containment actions |

### SLA

| Severity | Acknowledge | Contain | Resolve |
|---|---|---|---|
| CRITICAL | 15 minutes | 1 hour | 4 hours |
| HIGH | 30 minutes | 2 hours | 8 hours |
| MEDIUM | 2 hours | 8 hours | 24 hours |

### Compliance

- SOC 2 Type II - CC6.1 (Logical Access Controls)
- NIST 800-53 - IR-4 (Incident Handling), IR-6 (Incident Reporting)
- CIS AWS Benchmark - 3.x (Monitoring)

### Related Playbooks

Part of Lambda enumeration chain. See PB-AWS-Lambda-ListFunctions-01, PB-AWS-Lambda-GetFunction-01, and PB-AWS-CAMPAIGN-SCARLETEEL-01 for full context.

---

## 2. Triage & Validation

### Automated Enrichment

**Step 2.1: Retrieve CloudTrail events for the API call**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListTags20170331 \
  --start-time "<INCIDENT_START_TIME>" \
  --max-results 50 \
  --region us-east-1 \
  --output json
```

**Step 2.2: Identify the caller identity and source IP**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListTags20170331 \
  --start-time "<INCIDENT_START_TIME>" \
  --max-results 20 \
  --region us-east-1 \
  --query 'Events[*].{EventTime:EventTime,Username:Username,SourceIP:CloudTrailEvent}' \
  --output table
```

**Step 2.3: Check if CALLER_ARN is a known/approved role**

```bash
aws iam get-role \
  --role-name "$(echo <CALLER_ARN> | awk -F'/' '{print $NF}')" \
  --query 'Role.{RoleName:RoleName,CreateDate:CreateDate,Description:Description,Tags:Tags}' \
  --output json
```

**Step 2.4: Retrieve current tags on the targeted Lambda function**

```bash
aws lambda list-tags \
  --resource <FUNCTION_ARN> \
  --output json
```

**Step 2.5: Check for other reconnaissance API calls from the same CALLER_ARN in the time window**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$(echo <CALLER_ARN> | awk -F'/' '{print $NF}')" \
  --start-time "<INCIDENT_START_TIME>" \
  --max-results 50 \
  --query 'Events[*].{EventName:EventName,EventTime:EventTime}' \
  --output table
```

**Step 2.6: Determine how many distinct functions were tag-enumerated**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListTags20170331 \
  --start-time "<INCIDENT_START_TIME>" \
  --max-results 50 \
  --query 'Events[*].CloudTrailEvent' \
  --output text | python3 -c "
import sys, json
arns = set()
for line in sys.stdin:
    try:
        evt = json.loads(line.strip())
        resource = evt.get('requestParameters', {}).get('resource', '')
        if resource:
            arns.add(resource)
    except: pass
print(f'Distinct functions targeted: {len(arns)}')
for a in sorted(arns):
    print(f'  {a}')
"
```

### Decision Gates

| Condition | Action |
|---|---|
| IF CALLER_ARN is an approved automation role AND source IP is within corporate CIDR | THEN close as benign, document in ticket |
| IF CALLER_ARN is an EC2 instance profile AND source IP is an EC2 private IP | THEN escalate to L2, proceed to Section 3 |
| IF CALLER_ARN is unknown or recently created (< 24 hours) | THEN escalate to L2 immediately, treat as CRITICAL |
| IF multiple Lambda functions were tag-enumerated (>= 5) within 10 minutes | THEN escalate to L2, treat as CRITICAL |
| IF targeted function has tag `Environment:production` or `DataClassification:confidential` | THEN escalate to L2, treat as HIGH |

---

## 3. Containment Strategy

> **Pre-check**: Before executing L2 or L3 actions, verify the target resource does NOT have the `Critical-Production-App` tag.

```bash
aws lambda list-tags \
  --resource <FUNCTION_ARN> \
  --query 'Tags."Critical-Production-App"' \
  --output text
```

| Level | Action | Command | Rollback |
|---|---|---|---|
| **L1** | Revoke active sessions for the compromised role | `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name DenyAllPolicy --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<INCIDENT_START_TIME>"}}}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name DenyAllPolicy` |
| **L1** | Block source IP in Security Group | `aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port 443 --cidr <SOURCE_IP>/32` | `aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port 443 --cidr <SOURCE_IP>/32` |
| **L2** | Attach explicit deny policy to the IAM role | `aws iam attach-role-policy --role-name <ROLE_NAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/IncidentDenyAll` | `aws iam detach-role-policy --role-name <ROLE_NAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/IncidentDenyAll` |
| **L2** | Disable compromised EC2 instance credentials via IMDS | `aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-endpoint disabled` | `aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-endpoint enabled` |
| **L3** | Isolate EC2 instance to forensic security group | `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <FORENSIC_SG_ID>` | `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <ORIGINAL_SG_ID>` |
| **L3** | Snapshot EBS volume for forensics before termination | `aws ec2 create-snapshot --volume-id <VOLUME_ID> --description "IR-PB-AWS-Lambda-ListTags-01-<INCIDENT_ID>"` | N/A (snapshot is additive) |

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

Determine the blast radius by answering:

1. How many distinct Lambda function ARNs had their tags enumerated?
2. What sensitive tag values were exposed (environment, data classification, cost center, team ownership)?
3. Did the attacker use tag information to pivot to higher-value targets?
4. Were any tag-modification calls (TagResource, UntagResource) made by the same identity?

### 4.2 Athena Query - ListTags Activity

```sql
SELECT
    eventTime,
    userIdentity.arn AS caller_arn,
    userIdentity.principalId AS principal_id,
    sourceIPAddress,
    userAgent,
    requestParameters,
    responseElements,
    errorCode,
    errorMessage,
    awsRegion
FROM cloudtrail_logs
WHERE eventName = 'ListTags20170331'
  AND eventSource = 'lambda.amazonaws.com'
  AND eventTime >= '<INCIDENT_START_TIME>'
  AND recipientAccountId = '<ACCOUNT_ID>'
ORDER BY eventTime ASC;
```

### 4.3 Correlated Activity Query

```sql
SELECT
    eventName,
    eventTime,
    sourceIPAddress,
    userAgent,
    requestParameters
FROM cloudtrail_logs
WHERE userIdentity.arn = '<CALLER_ARN>'
  AND eventTime >= '<INCIDENT_START_TIME>'
  AND eventName IN (
    'ListTags20170331',
    'ListFunctions20150331',
    'GetFunction20150331',
    'GetPolicy20150331',
    'ListEventSourceMappings20150331',
    'ListAliases20150331',
    'TagResource20170331',
    'UntagResource20170331'
  )
ORDER BY eventTime ASC;
```

### 4.4 Evidence Preservation

```bash
# Save CloudTrail events to S3 evidence bucket
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListTags20170331 \
  --start-time "<INCIDENT_START_TIME>" \
  --max-results 50 \
  --output json > /tmp/evidence-listtags-<INCIDENT_ID>.json

aws s3 cp /tmp/evidence-listtags-<INCIDENT_ID>.json \
  s3://<EVIDENCE_BUCKET>/incidents/<INCIDENT_ID>/cloudtrail/listtags.json \
  --sse aws:kms --sse-kms-key-id <EVIDENCE_KMS_KEY_ID>

# Capture current tag state of targeted function
aws lambda list-tags \
  --resource <FUNCTION_ARN> \
  --output json > /tmp/evidence-current-tags-<INCIDENT_ID>.json

aws s3 cp /tmp/evidence-current-tags-<INCIDENT_ID>.json \
  s3://<EVIDENCE_BUCKET>/incidents/<INCIDENT_ID>/lambda/current-tags.json \
  --sse aws:kms --sse-kms-key-id <EVIDENCE_KMS_KEY_ID>
```

---

## 5. Recovery & Hardening

### 5.1 Sanitize

- Rotate all credentials associated with CALLER_ARN
- Delete any inline policies added during containment after confirming new policies are in place
- Remove any temporary security group rules

```bash
# Rotate access keys if applicable
aws iam list-access-keys --user-name <IAM_USER_NAME> --output json
aws iam create-access-key --user-name <IAM_USER_NAME>
aws iam delete-access-key --user-name <IAM_USER_NAME> --access-key-id <OLD_ACCESS_KEY_ID>
```

### 5.2 Restore

- Re-enable IMDS on the EC2 instance if it was disabled (only if instance is confirmed clean)
- Restore original security groups after forensic analysis is complete

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id <INSTANCE_ID> \
  --http-endpoint enabled \
  --http-tokens required

aws ec2 modify-instance-attribute \
  --instance-id <INSTANCE_ID> \
  --groups <ORIGINAL_SG_ID>
```

### 5.3 Harden

- Enforce IMDSv2 on all EC2 instances to prevent SSRF-based credential theft

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id <INSTANCE_ID> \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

- Review and minimize tag content to reduce information leakage. Remove sensitive metadata from tags (cost center IDs, team names, internal project codes).

- Deploy CloudWatch metric filter and alarm for `lambda:ListTags` from compute roles (EC2/Lambda). Do NOT block this API via SCP as it is widely used by legitimate infrastructure tooling (Terraform drift detection, AWS Config rules, cost allocation automation).

```bash
aws logs put-metric-filter \
  --log-group-name <CLOUDTRAIL_LOG_GROUP> \
  --filter-name ListTags-FromComputeRoles \
  --filter-pattern '{ ($.eventName = "ListTags20170331") && ($.eventSource = "lambda.amazonaws.com") && ($.userIdentity.type = "AssumedRole") }' \
  --metric-transformations metricName=ListTagsFromCompute,metricNamespace=MayaTrail/LambdaRecon,metricValue=1

aws cloudwatch put-metric-alarm \
  --alarm-name ListTags-ComputeRole-Alert \
  --metric-name ListTagsFromCompute \
  --namespace MayaTrail/LambdaRecon \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions <SNS_TOPIC_ARN>
```

- Enable GuardDuty Lambda Protection if not already active

```bash
aws guardduty update-detector \
  --detector-id <DETECTOR_ID> \
  --features '[{"Name":"LAMBDA_NETWORK_LOGS","Status":"ENABLED"}]'
```

### 5.4 Verify

```bash
# Confirm compromised role no longer has active sessions
aws iam get-role-policy --role-name <ROLE_NAME> --policy-name DenyAllPolicy 2>&1 | grep -c "NoSuchEntity"

# Confirm IMDSv2 enforcement
aws ec2 describe-instances \
  --instance-ids <INSTANCE_ID> \
  --query 'Reservations[0].Instances[0].MetadataOptions' \
  --output json

# Confirm GuardDuty Lambda feature is enabled
aws guardduty get-detector \
  --detector-id <DETECTOR_ID> \
  --query 'Features[?Name==`LAMBDA_NETWORK_LOGS`].Status' \
  --output text
```

### 5.5 Post-Mortem

- Document timeline from initial compromise to containment
- Record all tag key-value pairs that were exposed (FUNCTION_TAGS)
- Assess organizational metadata leakage risk based on exposed tags
- Identify gaps in monitoring that allowed reconnaissance to proceed
- Evaluate whether tag hygiene policies need revision (remove sensitive values)
- Update detection rules with new IOCs (source IPs, user agents)
- Schedule 30-day review of Lambda tagging policies and tag-based access controls

---

## Detection Rule (Sigma Format)

```yaml
title: AWS Lambda ListTags Reconnaissance
id: f4b2c3d5-6e7f-8901-bcde-fa2345678901
status: experimental
description: Detects enumeration of Lambda function tags, which may indicate reconnaissance of environment classification and organizational structure as seen in SCARLETEEL.
references:
  - https://sysdig.com/blog/scarleteel-2-0/
author: MayaTrail
date: 2026/04/05
tags:
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: lambda.amazonaws.com
    eventName: ListTags20170331
  filter_approved:
    userIdentity.arn|contains:
      - 'APPROVED_ROLE_1'
      - 'APPROVED_ROLE_2'
  condition: selection and not filter_approved
falsepositives:
  - Legitimate CI/CD pipelines reading tags for deployment decisions
  - Infrastructure-as-code tools (Terraform, Pulumi, CloudFormation) performing drift detection
  - Cost allocation and tagging compliance automation
level: medium
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Relevance |
|---|---|---|---|
| Discovery | T1526 | Cloud Service Discovery | Attacker enumerates function tags to discover environment classification and organizational metadata |
| Credential Access | T1552.005 | Cloud Instance Metadata API | Stolen EC2 role credentials used to make the API call |
| Initial Access | T1190 | Exploit Public-Facing Application | SCARLETEEL initial access via vulnerable container |
| Discovery | T1580 | Cloud Infrastructure Discovery | Tags reveal infrastructure topology and asset relationships |
