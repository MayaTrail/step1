---
id: aws-lambda-getpolicy
api_call: lambda:GetPolicy
required_inputs:
  - INCIDENT_START_TIME
  - CALLER_ARN
  - ACCOUNT_ID
  - FUNCTION_NAME
provided_outputs:
  - POLICY_DOCUMENT
  - ALLOWED_PRINCIPALS
  - SOURCE_IP
---

# Playbook: Lambda Permission Reconnaissance via GetPolicy

## 1. Governance & Metadata

| Field | Value |
|---|---|
| **Playbook Name** | Lambda Permission Reconnaissance via GetPolicy |
| **Playbook ID** | PB-AWS-Lambda-GetPolicy-01 |
| **Version** | 1.0 |
| **Scenario** | An adversary calls GetPolicy to retrieve the resource-based policy of a Lambda function, revealing which principals and services can invoke it. In SCARLETEEL, the attacker called GetPolicy to understand invocation permissions and received a `ResourceNotFoundException` (no resource policy existed). Even a negative result is valuable to an attacker -- it confirms the function has no cross-account or service-based invocation permissions, narrowing their attack surface analysis. |
| **Trigger** | CloudTrail `eventName` = `GetPolicy20150331v2` |

### Severity Matrix

| Severity | Condition |
|---|---|
| **CRITICAL** | GetPolicy called by an EC2 instance role AND preceded by GetFunction or ListFunctions within 15 minutes (indicates active reconnaissance chain) |
| **HIGH** | GetPolicy called for more than 5 distinct functions within a 10-minute window by the same principal |
| **MEDIUM** | GetPolicy called by an unfamiliar principal or from an unusual IP, but as an isolated event |

### Prerequisites

- CloudTrail logging enabled with Lambda management event capture
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
- NIST 800-53: SI-4 (Information System Monitoring), AC-6 (Least Privilege)

### Related Playbooks

Part of Lambda enumeration chain with PB-AWS-Lambda-ListFunctions-01, PB-AWS-Lambda-GetFunction-01. See PB-AWS-CAMPAIGN-SCARLETEEL-01.

---

## 2. Triage & Validation

### Automated Enrichment Checks

**Step 1: Confirm the CloudTrail event**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetPolicy20150331v2 \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --output json
```

**Step 2: Identify the calling principal, source IP, and target function**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetPolicy20150331v2 \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --query 'Events[*].CloudTrailEvent' \
  --output text | jq -r 'fromjson | {sourceIPAddress, userIdentity, requestParameters, errorCode}'
```

**Step 3: Check if the calling role is an EC2 instance profile**

```bash
aws iam get-role \
  --role-name <ROLE_NAME_FROM_CALLER_ARN> \
  --query 'Role.AssumeRolePolicyDocument.Statement[?Principal.Service==`ec2.amazonaws.com`]' \
  --output json
```

**Step 4: Retrieve the actual resource-based policy (if it exists)**

```bash
aws lambda get-policy \
  --function-name <FUNCTION_NAME> \
  --region <REGION> \
  --output json 2>&1 || echo "No resource policy found (ResourceNotFoundException)"
```

**Step 5: Check for other Lambda reconnaissance calls from the same principal**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --query 'Events[?contains(CloudTrailEvent, `lambda.amazonaws.com`)].{Time:EventTime,Event:CloudTrailEvent}' \
  --output text | jq -r 'fromjson | {eventName, requestParameters, errorCode}'
```

**Step 6: Count how many distinct functions had their policy queried**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --query 'Events[?contains(CloudTrailEvent, `GetPolicy`)].CloudTrailEvent' \
  --output text | jq -r 'fromjson | .requestParameters.functionName' | sort -u | wc -l
```

### Decision Gates

| Condition | Action |
|---|---|
| IF the caller is an EC2 instance role AND other Lambda recon calls (ListFunctions, GetFunction) precede this within 15 minutes | THEN escalate to CRITICAL; this is part of an active reconnaissance chain; proceed to Section 3, L2/L3 |
| IF more than 5 distinct functions had their policy queried in 10 minutes | THEN escalate to HIGH; systematic policy enumeration indicates methodical reconnaissance |
| IF the call returned ResourceNotFoundException AND no other Lambda calls are observed | THEN classify as MEDIUM; document and monitor for follow-up activity |
| IF the caller is a known deployment or security audit role | THEN verify with the application owner; if confirmed legitimate, close as false positive |

---

## 3. Containment Strategy

> **WARNING**: Before executing L2 or L3 actions, verify the `Critical-Production-App` tag on the affected resource:
> ```bash
> aws lambda get-function \
>   --function-name <FUNCTION_NAME> \
>   --region <REGION> \
>   --query 'Tags.["Critical-Production-App"]' \
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

**Reconstruct the full Lambda reconnaissance chain:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --query 'Events[?contains(CloudTrailEvent, `lambda.amazonaws.com`)].CloudTrailEvent' \
  --output text | jq -r 'fromjson | {eventTime, eventName, requestParameters, errorCode}' | jq -s 'sort_by(.eventTime)'
```

**Check if the attacker discovered any overly permissive resource policies:**

```bash
# For each function the attacker queried, check the current policy
for func in $(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --query 'Events[?contains(CloudTrailEvent, `GetPolicy`)].CloudTrailEvent' \
  --output text | jq -r 'fromjson | .requestParameters.functionName'); do
  echo "=== $func ==="
  aws lambda get-policy --function-name "$func" --region <REGION> 2>&1 | jq -r '.Policy // "No policy"'
done
```

### Athena Query: GetPolicy Events

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
    JSON_EXTRACT_SCALAR(requestParameters, '$.functionName') AS target_function
FROM cloudtrail_logs
WHERE eventName = 'GetPolicy20150331v2'
  AND eventTime >= '<INCIDENT_START_TIME>'
  AND recipientAccountId = '<ACCOUNT_ID>'
ORDER BY eventTime DESC
LIMIT 100;
```

**Athena Query: Full Lambda reconnaissance chain from the same principal:**

```sql
SELECT
    eventTime,
    eventName,
    sourceIPAddress,
    JSON_EXTRACT_SCALAR(requestParameters, '$.functionName') AS target_function,
    errorCode,
    errorMessage
FROM cloudtrail_logs
WHERE userIdentity.arn = '<CALLER_ARN>'
  AND eventSource = 'lambda.amazonaws.com'
  AND eventTime >= '<INCIDENT_START_TIME>'
  AND recipientAccountId = '<ACCOUNT_ID>'
ORDER BY eventTime ASC;
```

### Evidence Preservation

**Step 1: Export the relevant CloudTrail events to S3**

```bash
aws s3 cp \
  s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<REGION>/ \
  s3://<EVIDENCE_BUCKET>/incident-<INCIDENT_ID>/cloudtrail/ \
  --recursive \
  --include "*.json.gz"
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

**Step 3: Preserve current resource-based policies for all targeted functions**

```bash
for func in <FUNCTION_NAME_1> <FUNCTION_NAME_2>; do
  aws lambda get-policy \
    --function-name "$func" \
    --region <REGION> \
    --output json > /tmp/evidence-"$func"-policy-$(date -u +%Y%m%dT%H%M%SZ).json 2>&1
done
```

---

## 5. Recovery & Hardening

### Sanitize

- Rotate all credentials associated with the compromised EC2 instance role
- Revoke any temporary security credentials issued before the incident
- Review and tighten any overly permissive resource-based policies discovered during the incident

```bash
# List resource-based policies for all Lambda functions to identify overly permissive ones
for func in $(aws lambda list-functions --region <REGION> --query 'Functions[*].FunctionName' --output text); do
  echo "=== $func ==="
  aws lambda get-policy --function-name "$func" --region <REGION> 2>&1 | jq -r '.Policy // "No policy"'
done
```

### Restore

- Re-deploy the EC2 instance from a known-good AMI if runtime compromise is suspected
- Re-attach the original (patched) instance profile with least-privilege permissions
- Verify Lambda resource-based policies are correctly scoped

### Harden

**Deploy SCP to restrict Lambda policy read APIs to authorized roles:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyGetPolicyUnlessAuthorized",
      "Effect": "Deny",
      "Action": "lambda:GetPolicy",
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
      "Sid": "RestrictLambdaGetPolicyByIP",
      "Effect": "Deny",
      "Action": [
        "lambda:GetPolicy",
        "lambda:GetFunction",
        "lambda:ListFunctions"
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

**Review and tighten existing Lambda resource-based policies:**

```bash
# Remove overly broad invocation permissions (e.g., Principal: *)
aws lambda remove-permission \
  --function-name <FUNCTION_NAME> \
  --statement-id <OVERLY_BROAD_STATEMENT_ID> \
  --region <REGION>

# Add scoped permission instead
aws lambda add-permission \
  --function-name <FUNCTION_NAME> \
  --statement-id AllowSpecificService \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:<REGION>:<ACCOUNT_ID>:<API_ID>/*" \
  --region <REGION>
```

### Verify

```bash
# Confirm the compromised role can no longer call GetPolicy
aws sts assume-role \
  --role-arn <CALLER_ARN> \
  --role-session-name verification-test \
  --query 'Credentials' \
  --output json

# Then attempt:
aws lambda get-policy --function-name <FUNCTION_NAME> --region <REGION>
# Expected: AccessDenied
```

### Post-Mortem Detection Gap Analysis

| Gap | Finding | Remediation |
|---|---|---|
| No alert on GetPolicy from EC2 roles | Lambda permission reconnaissance was unmonitored | Deploy the Sigma rule below |
| Overly permissive EC2 instance role | The role had broad `lambda:Get*` permissions allowing policy enumeration | Apply least-privilege; restrict `lambda:GetPolicy` to specific function ARNs |
| No correlation rule for Lambda reconnaissance chain | Individual calls (ListFunctions, GetFunction, GetPolicy) were not correlated as a chain | Create a composite detection rule that triggers when 3+ Lambda read APIs are called by the same principal within 15 minutes |
| Lambda resource-based policies not audited | Some functions had overly broad invocation permissions | Implement periodic audit of Lambda resource-based policies via AWS Config rule |

---

## Detection Rule (Sigma Format)

```yaml
title: Lambda GetPolicy Called by EC2 Instance Role - Permission Reconnaissance
id: d4e5f6a7-b8c9-0123-defa-234567890123
status: experimental
description: >
  Detects lambda:GetPolicy API calls made by EC2 instance roles,
  which may indicate permission reconnaissance as observed in SCARLETEEL.
  Attackers use GetPolicy to understand which principals can invoke a function.
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
    eventName: GetPolicy20150331v2
    userIdentity.type: AssumedRole
  filter_known_services:
    userIdentity.invokedBy:
      - config.amazonaws.com
      - securityhub.amazonaws.com
      - access-analyzer.amazonaws.com
  condition: selection and not filter_known_services
falsepositives:
  - Legitimate deployment pipelines checking function permissions during updates
  - AWS Config or IAM Access Analyzer evaluating resource policies
level: medium
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Procedure |
|---|---|---|---|
| Discovery | T1526 | Cloud Service Discovery | Attacker enumerates Lambda resource-based policies to identify which principals and services can invoke functions |
| Discovery | T1069.003 | Permission Groups Discovery: Cloud Groups | GetPolicy reveals cross-account access and service-based invocation permissions |
| Reconnaissance | T1592.004 | Gather Victim Host Information: Client Configurations | Resource policies expose API Gateway integrations, S3 event sources, and other service connections |
