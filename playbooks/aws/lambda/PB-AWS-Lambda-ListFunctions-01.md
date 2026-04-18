---
id: aws-lambda-listfunctions
api_call: lambda:ListFunctions
required_inputs:
  - INCIDENT_START_TIME
  - CALLER_ARN
  - ACCOUNT_ID
  - REGION
provided_outputs:
  - ENUMERATED_FUNCTION_NAMES
  - FUNCTION_COUNT
  - SOURCE_IP
---

# Playbook: Lambda Function Enumeration via ListFunctions

## 1. Governance & Metadata

| Field | Value |
|---|---|
| **Playbook Name** | Lambda Function Enumeration via ListFunctions |
| **Playbook ID** | PB-AWS-Lambda-ListFunctions-01 |
| **Version** | 1.0 |
| **Scenario** | An adversary enumerates all Lambda functions in an account to discover proprietary code, credentials in environment variables, and potential pivot targets. In SCARLETEEL, the attacker called ListFunctions from stolen EC2 instance role credentials (principal `i-0aea82a9977cd62a4`, IP `122.162.144.65`). EC2 compute roles should rarely need to list all Lambda functions. |
| **Trigger** | CloudTrail `eventName` = `ListFunctions20150331` |

### Severity Matrix

| Severity | Condition |
|---|---|
| **CRITICAL** | ListFunctions called by an EC2 instance role AND followed by GetFunction calls within 10 minutes |
| **HIGH** | ListFunctions called from a non-allowlisted IP or by a principal that has never called this API before |
| **MEDIUM** | ListFunctions called outside business hours or from an unusual region |

### Prerequisites

- CloudTrail logging enabled in `<REGION>` with Lambda data events
- AWS CLI v2 configured with incident response role permissions
- Amazon Athena configured with CloudTrail log table

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Discovery | Cloud Service Discovery | T1526 |

### Stakeholders

| Role | Responsibility |
|---|---|
| SOC Analyst (L1) | Initial triage, severity classification, escalation |
| IR Lead (L2) | Containment decisions, evidence preservation |
| Cloud Security Engineer (L3) | Hardening, SCP deployment, post-mortem |
| Application Owner | Confirm whether the API call is legitimate |

### SLA

| Severity | Acknowledge | Contain | Resolve |
|---|---|---|---|
| CRITICAL | 15 min | 1 hr | 24 hr |
| HIGH | 30 min | 4 hr | 48 hr |
| MEDIUM | 2 hr | 8 hr | 72 hr |

### Compliance

- SOC 2 Type II: CC6.1 (Logical Access Controls)
- PCI DSS: Requirement 10.2 (Audit Trail)
- NIST 800-53: SI-4 (Information System Monitoring)

### Related Playbooks

Typically precedes PB-AWS-Lambda-GetFunction-01 in attack chains. See PB-AWS-CAMPAIGN-SCARLETEEL-01 for full kill chain context.

---

## 2. Triage & Validation

### Automated Enrichment Checks

**Step 1: Confirm the CloudTrail event**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListFunctions20150331 \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --output json
```

**Step 2: Identify the calling principal and source IP**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListFunctions20150331 \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --query 'Events[*].{Time:EventTime,Username:Username,CloudTrailEvent:CloudTrailEvent}' \
  --output json | jq -r '.[].CloudTrailEvent | fromjson | {sourceIPAddress, userIdentity}'
```

**Step 3: Check if the calling role is an EC2 instance profile**

```bash
aws iam get-role \
  --role-name <ROLE_NAME_FROM_CALLER_ARN> \
  --query 'Role.AssumeRolePolicyDocument.Statement[?Principal.Service==`ec2.amazonaws.com`]' \
  --output json
```

**Step 4: Check the number of Lambda functions returned (scope of exposure)**

```bash
aws lambda list-functions \
  --region <REGION> \
  --query 'Functions[*].FunctionName' \
  --output json | jq 'length'
```

**Step 5: Check for subsequent GetFunction calls from the same principal**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --query 'Events[?contains(CloudTrailEvent, `GetFunction`)].{Time:EventTime,Event:CloudTrailEvent}' \
  --output json
```

### Decision Gates

| Condition | Action |
|---|---|
| IF the caller is an EC2 instance role AND GetFunction calls follow within 10 minutes | THEN escalate to CRITICAL; proceed to Section 3, L2 containment |
| IF the caller is a human IAM user calling from a non-corporate IP | THEN escalate to HIGH; proceed to Section 3, L1 containment |
| IF the caller is a known CI/CD role or deployment automation | THEN verify with the application owner; if confirmed legitimate, close as false positive |
| IF the call is from an AWS service (e.g., Config, SecurityHub) | THEN close as informational |

---

## 3. Containment Strategy

> **WARNING**: Before executing L2 or L3 actions, verify the `Critical-Production-App` tag on the affected resource:
> ```bash
> aws ec2 describe-instances \
>   --instance-ids <INSTANCE_ID> \
>   --query 'Reservations[*].Instances[*].Tags[?Key==`Critical-Production-App`].Value' \
>   --output text
> ```
> If tagged, obtain Change Advisory Board (CAB) approval before proceeding.

| Level | Action | Command | Rollback |
|---|---|---|---|
| **L1** | Revoke active sessions for the compromised role | `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name DenyAll-Incident --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_TIME>"}}}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name DenyAll-Incident` |
| **L1** | Block the source IP via NACL | `aws ec2 create-network-acl-entry --network-acl-id <NACL_ID> --rule-number 50 --protocol -1 --rule-action deny --cidr-block <SOURCE_IP>/32 --ingress` | `aws ec2 delete-network-acl-entry --network-acl-id <NACL_ID> --rule-number 50 --ingress` |
| **L2** | Isolate the EC2 instance with a quarantine security group | `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <QUARANTINE_SG_ID>` | `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <ORIGINAL_SG_ID>` |
| **L2** | Detach the instance role to prevent further API calls | `aws ec2 disassociate-iam-instance-profile --association-id <ASSOCIATION_ID>` | `aws ec2 associate-iam-instance-profile --iam-instance-profile Name=<PROFILE_NAME> --instance-id <INSTANCE_ID>` |
| **L3** | Disable the IAM role entirely | `aws iam attach-role-policy --role-name <ROLE_NAME> --policy-arn arn:aws:iam::aws:policy/AWSDenyAll` | `aws iam detach-role-policy --role-name <ROLE_NAME> --policy-arn arn:aws:iam::aws:policy/AWSDenyAll` |
| **L3** | Stop the compromised EC2 instance | `aws ec2 stop-instances --instance-ids <INSTANCE_ID>` | `aws ec2 start-instances --instance-ids <INSTANCE_ID>` |

---

## 4. Investigation & Forensics

### Scope Assessment

**List all API calls made by the compromised principal in the incident window:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
  --start-time "<INCIDENT_START_TIME>" \
  --end-time "<INCIDENT_END_TIME>" \
  --region <REGION> \
  --query 'Events[*].{Time:EventTime,Name:EventName,Source:EventSource}' \
  --output table
```

**Check all regions for lateral movement:**

```bash
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  echo "=== $region ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time "<INCIDENT_START_TIME>" \
    --region "$region" \
    --query 'Events[*].EventName' \
    --output text
done
```

### Athena Query: ListFunctions Events

```sql
SELECT
    eventTime,
    eventName,
    userIdentity.arn AS caller_arn,
    userIdentity.principalId AS principal_id,
    sourceIPAddress,
    awsRegion,
    errorCode,
    errorMessage,
    requestParameters,
    responseElements
FROM cloudtrail_logs
WHERE eventName = 'ListFunctions20150331'
  AND eventTime >= '<INCIDENT_START_TIME>'
  AND awsRegion = '<REGION>'
  AND recipientAccountId = '<ACCOUNT_ID>'
ORDER BY eventTime DESC
LIMIT 100;
```

### Evidence Preservation

**Step 1: Export the relevant CloudTrail events to S3**

```bash
aws s3 cp \
  s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<REGION>/ \
  s3://<EVIDENCE_BUCKET>/incident-<INCIDENT_ID>/cloudtrail/ \
  --recursive \
  --include "*.json.gz" \
  --exclude "*" \
  --source-region <REGION>
```

**Step 2: Snapshot the compromised EC2 instance volumes**

```bash
VOLUME_IDS=$(aws ec2 describe-instances \
  --instance-ids <INSTANCE_ID> \
  --query 'Reservations[*].Instances[*].BlockDeviceMappings[*].Ebs.VolumeId' \
  --output text)

for vol in $VOLUME_IDS; do
  aws ec2 create-snapshot \
    --volume-id "$vol" \
    --description "IR Evidence - Incident <INCIDENT_ID> - $(date -u +%Y%m%dT%H%M%SZ)" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=Incident,Value=<INCIDENT_ID>},{Key=Evidence,Value=true}]"
done
```

**Step 3: Capture the current Lambda function inventory**

```bash
aws lambda list-functions \
  --region <REGION> \
  --output json > /tmp/lambda-functions-inventory-$(date -u +%Y%m%dT%H%M%SZ).json
```

---

## 5. Recovery & Hardening

### Sanitize

- Rotate all credentials associated with the compromised EC2 instance role
- Revoke any temporary security credentials issued before the incident

```bash
aws iam update-role --role-name <ROLE_NAME> --max-session-duration 3600
```

### Restore

- Re-deploy the EC2 instance from a known-good AMI if runtime compromise is suspected
- Re-attach the original (patched) instance profile with least-privilege permissions

### Harden

**Deploy SCP to restrict ListFunctions to authorized roles only:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyListFunctionsUnlessAuthorized",
      "Effect": "Deny",
      "Action": "lambda:ListFunctions",
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::<ACCOUNT_ID>:role/DeploymentRole",
            "arn:aws:iam::<ACCOUNT_ID>:role/SecurityAuditRole"
          ]
        }
      }
    }
  ]
}
```

**Add IAM condition to restrict Lambda read APIs to specific source IPs:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RestrictLambdaReadByIP",
      "Effect": "Deny",
      "Action": [
        "lambda:ListFunctions",
        "lambda:GetFunction"
      ],
      "Resource": "*",
      "Condition": {
        "NotIpAddress": {
          "aws:SourceIp": ["<CORPORATE_CIDR>"]
        },
        "StringNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::<ACCOUNT_ID>:role/AllowedServiceRole"
        }
      }
    }
  ]
}
```

### Verify

```bash
# Confirm the compromised role can no longer call ListFunctions
aws sts assume-role \
  --role-arn <CALLER_ARN> \
  --role-session-name verification-test \
  --query 'Credentials' \
  --output json

# Then attempt:
aws lambda list-functions --region <REGION>
# Expected: AccessDenied
```

### Post-Mortem Detection Gap Analysis

| Gap | Finding | Remediation |
|---|---|---|
| No alert on ListFunctions from EC2 roles | The call was not flagged because no detection rule existed | Deploy the Sigma rule below |
| Overly permissive EC2 instance role | The role had `lambda:*` permissions | Apply least-privilege; remove `lambda:List*` and `lambda:Get*` unless required |
| No VPC endpoint policy for Lambda | API calls routed through public internet | Deploy Lambda VPC endpoint with restrictive policy |

---

## Detection Rule (Sigma Format)

```yaml
title: Lambda ListFunctions Called by EC2 Instance Role
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
  Detects lambda:ListFunctions API calls made by EC2 instance roles,
  which may indicate cloud service discovery as observed in SCARLETEEL.
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
    eventName: ListFunctions20150331
    userIdentity.type: AssumedRole
  filter_known_services:
    userIdentity.invokedBy:
      - config.amazonaws.com
      - securityhub.amazonaws.com
      - access-analyzer.amazonaws.com
  condition: selection and not filter_known_services
falsepositives:
  - Legitimate deployment automation or CI/CD pipelines using EC2-based runners
  - AWS Config or Security Hub service-linked roles
level: high
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Procedure |
|---|---|---|---|
| Discovery | T1526 | Cloud Service Discovery | Attacker enumerates all Lambda functions in the account to identify targets for code theft and credential harvesting |
| Reconnaissance | T1592.004 | Gather Victim Host Information: Client Configurations | ListFunctions response reveals runtimes, memory configurations, and VPC settings |
| Resource Development | T1583.006 | Acquire Infrastructure: Web Services | Knowledge of Lambda function names enables targeted follow-up attacks (GetFunction, Invoke) |
