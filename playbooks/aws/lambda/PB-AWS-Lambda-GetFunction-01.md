---
id: aws-lambda-getfunction
api_call: lambda:GetFunction
required_inputs:
  - INCIDENT_START_TIME
  - CALLER_ARN
  - ACCOUNT_ID
  - FUNCTION_NAME
provided_outputs:
  - FUNCTION_CODE_URL
  - FUNCTION_RUNTIME
  - SOURCE_IP
---

# Playbook: Lambda Code Exfiltration via GetFunction

## 1. Governance & Metadata

| Field | Value |
|---|---|
| **Playbook Name** | Lambda Code Exfiltration via GetFunction |
| **Playbook ID** | PB-AWS-Lambda-GetFunction-01 |
| **Version** | 1.0 |
| **Scenario** | An adversary calls GetFunction to obtain a pre-signed S3 URL that allows downloading the Lambda deployment package (source code). This is the most dangerous Lambda enumeration call -- it gives the attacker the actual source code, enabling intellectual property theft, credential harvesting from hardcoded secrets, and discovery of downstream service integrations. In SCARLETEEL, the attacker used stolen EC2 instance role credentials to call GetFunction and download proprietary Lambda code. |
| **Trigger** | CloudTrail `eventName` = `GetFunction20150331v2` |

### Severity Matrix

| Severity | Condition |
|---|---|
| **CRITICAL** | GetFunction called by an EC2 instance role or from a non-corporate IP, especially if preceded by ListFunctions within 10 minutes |
| **HIGH** | GetFunction called for more than 3 distinct functions within a 5-minute window by the same principal |
| **MEDIUM** | GetFunction called by an authorized role but outside business hours or from an unusual region |

### Prerequisites

- CloudTrail logging enabled with Lambda management event capture
- AWS CLI v2 configured with incident response role permissions
- Amazon Athena configured with CloudTrail log table
- Inventory of Lambda functions containing sensitive code or credentials

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Collection | Data from Cloud Storage Object | T1530 |
| Collection | Data from Local System | T1005 |

### Stakeholders

| Role | Responsibility |
|---|---|
| SOC Analyst (L1) | Initial triage, severity classification, escalation |
| IR Lead (L2) | Containment decisions, evidence preservation, pre-signed URL invalidation |
| Cloud Security Engineer (L3) | Hardening, SCP deployment, code rotation |
| Application Owner | Confirm legitimacy, assess IP exposure, rotate embedded secrets |

### SLA

| Severity | Acknowledge | Contain | Resolve |
|---|---|---|---|
| CRITICAL | 15 min | 1 hr | 24 hr |
| HIGH | 30 min | 4 hr | 48 hr |
| MEDIUM | 2 hr | 8 hr | 72 hr |

### Compliance

- SOC 2 Type II: CC6.1 (Logical Access Controls), CC6.7 (Data Classification)
- PCI DSS: Requirement 10.2 (Audit Trail), Requirement 6.5 (Secure Development)
- NIST 800-53: SI-4 (Information System Monitoring), SC-28 (Protection of Information at Rest)

### Related Playbooks

Usually preceded by PB-AWS-Lambda-ListFunctions-01. Often followed by PB-AWS-Lambda-ListVersionsByFunction-01 for env var extraction. See PB-AWS-CAMPAIGN-SCARLETEEL-01.

---

## 2. Triage & Validation

### Automated Enrichment Checks

**Step 1: Confirm the CloudTrail event and extract the pre-signed URL details**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetFunction20150331v2 \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --output json
```

**Step 2: Identify the calling principal, source IP, and target function**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetFunction20150331v2 \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --query 'Events[*].CloudTrailEvent' \
  --output text | jq -r 'fromjson | {sourceIPAddress, userIdentity, requestParameters}'
```

**Step 3: Check if the calling role is an EC2 instance profile**

```bash
aws iam get-role \
  --role-name <ROLE_NAME_FROM_CALLER_ARN> \
  --query 'Role.AssumeRolePolicyDocument.Statement[?Principal.Service==`ec2.amazonaws.com`]' \
  --output json
```

**Step 4: Determine if the targeted function contains sensitive code or environment variables**

```bash
aws lambda get-function-configuration \
  --function-name <FUNCTION_NAME> \
  --region <REGION> \
  --query '{Runtime:Runtime,Handler:Handler,EnvVars:Environment.Variables,VpcConfig:VpcConfig}' \
  --output json
```

**Step 5: Check for preceding ListFunctions calls from the same principal**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --query 'Events[?contains(CloudTrailEvent, `ListFunctions`)].{Time:EventTime,Event:CloudTrailEvent}' \
  --output json
```

**Step 6: Count how many distinct functions were targeted**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --query 'Events[?contains(CloudTrailEvent, `GetFunction`)].CloudTrailEvent' \
  --output text | jq -r 'fromjson | .requestParameters.functionName' | sort -u | wc -l
```

### Decision Gates

| Condition | Action |
|---|---|
| IF the caller is an EC2 instance role AND preceded by ListFunctions | THEN escalate to CRITICAL; proceed to Section 3, L2/L3 containment immediately |
| IF more than 3 distinct functions accessed in 5 minutes | THEN escalate to HIGH; this indicates systematic code exfiltration |
| IF the caller is a known deployment role AND the function is in an active deployment pipeline | THEN verify with the application owner; if confirmed legitimate, close as false positive |
| IF the call resulted in AccessDenied | THEN escalate to HIGH (failed attempt still indicates attacker intent); document and monitor for retry |

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
| **L2** | Deny GetFunction on the targeted Lambda function via resource policy | `aws lambda remove-permission --function-name <FUNCTION_NAME> --statement-id AllowAll 2>/dev/null; aws lambda add-permission --function-name <FUNCTION_NAME> --statement-id DenyCompromisedRole --action lambda:GetFunction --principal <ACCOUNT_ID> --source-account <ACCOUNT_ID> --condition '{"StringEquals":{"aws:PrincipalArn":"<CALLER_ARN>"}}'` | `aws lambda remove-permission --function-name <FUNCTION_NAME> --statement-id DenyCompromisedRole` |
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

**Identify all Lambda functions accessed by the attacker:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --query 'Events[?contains(CloudTrailEvent, `GetFunction`)].CloudTrailEvent' \
  --output text | jq -r 'fromjson | .requestParameters.functionName' | sort -u
```

**Check if the pre-signed S3 URL was accessed (S3 server access logs):**

```bash
aws s3api get-bucket-logging \
  --bucket <LAMBDA_CODE_BUCKET> \
  --output json
```

### Athena Query: GetFunction Events

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
    JSON_EXTRACT_SCALAR(requestParameters, '$.functionName') AS target_function,
    responseElements
FROM cloudtrail_logs
WHERE eventName = 'GetFunction20150331v2'
  AND eventTime >= '<INCIDENT_START_TIME>'
  AND recipientAccountId = '<ACCOUNT_ID>'
ORDER BY eventTime DESC
LIMIT 100;
```

**Athena Query: Correlate with ListFunctions (attack chain detection):**

```sql
SELECT
    eventTime,
    eventName,
    userIdentity.arn AS caller_arn,
    sourceIPAddress,
    JSON_EXTRACT_SCALAR(requestParameters, '$.functionName') AS target_function
FROM cloudtrail_logs
WHERE userIdentity.arn = '<CALLER_ARN>'
  AND eventName IN ('ListFunctions20150331', 'GetFunction20150331v2')
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

**Step 3: Preserve the current Lambda function code as evidence**

```bash
aws lambda get-function \
  --function-name <FUNCTION_NAME> \
  --region <REGION> \
  --query 'Code.Location' \
  --output text | xargs curl -o /tmp/evidence-<FUNCTION_NAME>-$(date -u +%Y%m%dT%H%M%SZ).zip
```

**Step 4: Record the function configuration**

```bash
aws lambda get-function-configuration \
  --function-name <FUNCTION_NAME> \
  --region <REGION> \
  --output json > /tmp/evidence-<FUNCTION_NAME>-config-$(date -u +%Y%m%dT%H%M%SZ).json
```

---

## 5. Recovery & Hardening

### Sanitize

- Rotate ALL credentials and secrets embedded in the Lambda function's source code
- Rotate any environment variables exposed via the function configuration
- Invalidate any API keys, database passwords, or tokens found in the code

```bash
# List environment variables that may need rotation
aws lambda get-function-configuration \
  --function-name <FUNCTION_NAME> \
  --region <REGION> \
  --query 'Environment.Variables' \
  --output json
```

### Restore

- Re-deploy the Lambda function from a verified, clean source repository
- Re-deploy the EC2 instance from a known-good AMI if runtime compromise is suspected
- Re-attach the original (patched) instance profile with least-privilege permissions

### Harden

**Deploy SCP to deny GetFunction for non-authorized roles:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyGetFunctionUnlessAuthorized",
      "Effect": "Deny",
      "Action": "lambda:GetFunction",
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

**Move Lambda secrets to AWS Secrets Manager or Parameter Store:**

```bash
# Create a secret in Secrets Manager
aws secretsmanager create-secret \
  --name "/lambda/<FUNCTION_NAME>/db-password" \
  --secret-string "<NEW_ROTATED_PASSWORD>" \
  --region <REGION>

# Update Lambda to reference Secrets Manager instead of env vars
aws lambda update-function-configuration \
  --function-name <FUNCTION_NAME> \
  --environment '{"Variables":{"DB_PASS_SECRET_ARN":"arn:aws:secretsmanager:<REGION>:<ACCOUNT_ID>:secret:/lambda/<FUNCTION_NAME>/db-password"}}' \
  --region <REGION>
```

**Add IAM condition to restrict Lambda read APIs:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RestrictLambdaGetFunctionByIP",
      "Effect": "Deny",
      "Action": "lambda:GetFunction",
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
# Confirm the compromised role can no longer call GetFunction
aws sts assume-role \
  --role-arn <CALLER_ARN> \
  --role-session-name verification-test \
  --query 'Credentials' \
  --output json

# Then attempt:
aws lambda get-function --function-name <FUNCTION_NAME> --region <REGION>
# Expected: AccessDenied
```

### Post-Mortem Detection Gap Analysis

| Gap | Finding | Remediation |
|---|---|---|
| No alert on GetFunction from EC2 roles | The most dangerous Lambda API call was unmonitored | Deploy the Sigma rule below; add CloudWatch alarm |
| Lambda code stored without encryption | Deployment packages were accessible via pre-signed URL | Enable KMS encryption for Lambda deployment packages |
| Secrets hardcoded in Lambda source code | Credentials were embedded in source, exfiltrated with code | Migrate all secrets to AWS Secrets Manager with automatic rotation |
| No VPC endpoint policy for Lambda | API calls routed through public internet | Deploy Lambda VPC endpoint with restrictive policy |

---

## Detection Rule (Sigma Format)

```yaml
title: Lambda GetFunction Called by EC2 Instance Role - Potential Code Exfiltration
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: >
  Detects lambda:GetFunction API calls made by EC2 instance roles,
  which may indicate Lambda code exfiltration as observed in SCARLETEEL.
  GetFunction returns a pre-signed S3 URL for downloading the deployment package.
references:
  - https://sysdig.com/blog/scarleteel-2-0/
author: MayaTrail
date: 2026/04/05
tags:
  - attack.collection
  - attack.t1530
  - attack.t1005
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: GetFunction20150331v2
    userIdentity.type: AssumedRole
  filter_known_services:
    userIdentity.invokedBy:
      - config.amazonaws.com
      - securityhub.amazonaws.com
  condition: selection and not filter_known_services
falsepositives:
  - Legitimate deployment pipelines that fetch function code for validation
  - AWS CodePipeline or CodeDeploy service roles
level: critical
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Procedure |
|---|---|---|---|
| Collection | T1530 | Data from Cloud Storage Object | Attacker obtains pre-signed S3 URL from GetFunction response to download Lambda deployment package containing proprietary source code |
| Collection | T1005 | Data from Local System | Lambda source code treated as local system data; attacker extracts code and embedded credentials |
| Discovery | T1526 | Cloud Service Discovery | GetFunction used to enumerate function configuration, runtime, VPC settings, and environment variables |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials in Files | Source code may contain hardcoded API keys, database passwords, and service tokens |
