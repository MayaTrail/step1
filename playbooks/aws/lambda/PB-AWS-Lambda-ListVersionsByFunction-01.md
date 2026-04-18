---
id: aws-lambda-listversionsbyfunction
api_call: lambda:ListVersionsByFunction
required_inputs:
  - INCIDENT_START_TIME
  - CALLER_ARN
  - ACCOUNT_ID
  - FUNCTION_NAME
provided_outputs:
  - EXPOSED_ENV_VARS
  - VERSION_COUNT
  - SOURCE_IP
---

# Playbook: Lambda Credential Exposure via ListVersionsByFunction

## 1. Governance & Metadata

| Field | Value |
|---|---|
| **Playbook Name** | Lambda Credential Exposure via ListVersionsByFunction |
| **Playbook ID** | PB-AWS-Lambda-ListVersionsByFunction-01 |
| **Version** | 1.0 |
| **Scenario** | An adversary calls ListVersionsByFunction to enumerate all published versions of a Lambda function. The API response includes the function configuration for each version, which contains environment variables in plaintext. In SCARLETEEL, this call exposed `DB_PASS=SuperSecretCustomerPass123` and other sensitive environment variables. Even if the current version has been patched to use Secrets Manager, older versions may still contain hardcoded credentials. |
| **Trigger** | CloudTrail `eventName` = `ListVersionsByFunction20150331` |

### Severity Matrix

| Severity | Condition |
|---|---|
| **CRITICAL** | ListVersionsByFunction called by an EC2 instance role AND the targeted function has environment variables containing keys matching `PASS`, `SECRET`, `KEY`, `TOKEN`, or `CRED` |
| **HIGH** | ListVersionsByFunction called from a non-allowlisted IP or by a principal with no prior history of this API call |
| **MEDIUM** | ListVersionsByFunction called by a known role but for a function outside its normal operational scope |

### Prerequisites

- CloudTrail logging enabled with Lambda management event capture
- AWS CLI v2 configured with incident response role permissions
- Amazon Athena configured with CloudTrail log table
- Inventory of Lambda functions with environment variables containing secrets

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 |

### Stakeholders

| Role | Responsibility |
|---|---|
| SOC Analyst (L1) | Initial triage, severity classification, escalation |
| IR Lead (L2) | Containment decisions, credential rotation coordination |
| Cloud Security Engineer (L3) | Hardening, SCP deployment, secrets migration |
| Application Owner | Confirm legitimacy, identify all exposed credentials, initiate rotation |

### SLA

| Severity | Acknowledge | Contain | Resolve |
|---|---|---|---|
| CRITICAL | 15 min | 1 hr | 24 hr |
| HIGH | 30 min | 4 hr | 48 hr |
| MEDIUM | 2 hr | 8 hr | 72 hr |

### Compliance

- SOC 2 Type II: CC6.1 (Logical Access Controls), CC6.6 (Security Operations)
- PCI DSS: Requirement 8.2 (Authentication Management), Requirement 10.2 (Audit Trail)
- NIST 800-53: IA-5 (Authenticator Management), SC-28 (Protection of Information at Rest)

### Related Playbooks

Usually preceded by PB-AWS-Lambda-GetFunction-01. Exposes environment variables that may contain credentials. See PB-AWS-CAMPAIGN-SCARLETEEL-01.

---

## 2. Triage & Validation

### Automated Enrichment Checks

**Step 1: Confirm the CloudTrail event**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListVersionsByFunction20150331 \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --output json
```

**Step 2: Identify the calling principal, source IP, and target function**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListVersionsByFunction20150331 \
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

**Step 4: Enumerate environment variables across ALL versions of the targeted function**

```bash
aws lambda list-versions-by-function \
  --function-name <FUNCTION_NAME> \
  --region <REGION> \
  --query 'Versions[*].{Version:Version,EnvVars:Environment.Variables}' \
  --output json
```

**Step 5: Check for sensitive environment variable names**

```bash
aws lambda list-versions-by-function \
  --function-name <FUNCTION_NAME> \
  --region <REGION> \
  --query 'Versions[*].Environment.Variables' \
  --output json | jq -r '.[].keys[]? // empty' | grep -iE '(pass|secret|key|token|cred|api_key|db_)'
```

**Step 6: Count the number of versions exposed**

```bash
aws lambda list-versions-by-function \
  --function-name <FUNCTION_NAME> \
  --region <REGION> \
  --query 'Versions[*].Version' \
  --output json | jq 'length'
```

### Decision Gates

| Condition | Action |
|---|---|
| IF environment variables contain credentials (PASS, SECRET, KEY, TOKEN) AND caller is an EC2 role | THEN escalate to CRITICAL; immediately rotate all exposed credentials; proceed to Section 3, L2/L3 |
| IF the caller is from a non-corporate IP AND has no prior history of this call | THEN escalate to HIGH; proceed to Section 3, L1 containment |
| IF the caller is a known CI/CD or deployment role | THEN verify with the application owner; if confirmed legitimate, close as false positive |
| IF the function has no environment variables or only non-sensitive values | THEN downgrade to MEDIUM; document and monitor |

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
| **L2** | Rotate all exposed credentials immediately | `aws secretsmanager rotate-secret --secret-id <SECRET_ARN> --region <REGION>` | `aws secretsmanager cancel-rotate-secret --secret-id <SECRET_ARN> --region <REGION>` |
| **L2** | Isolate the EC2 instance with a quarantine security group | `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <QUARANTINE_SG_ID>` | `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <ORIGINAL_SG_ID>` |
| **L2** | Detach the instance role to prevent further API calls | `aws ec2 disassociate-iam-instance-profile --association-id <ASSOCIATION_ID>` | `aws ec2 associate-iam-instance-profile --iam-instance-profile Name=<PROFILE_NAME> --instance-id <INSTANCE_ID>` |
| **L3** | Delete old Lambda versions that contain hardcoded credentials | `aws lambda delete-function --function-name <FUNCTION_NAME> --qualifier <VERSION_NUMBER> --region <REGION>` | Re-deploy the version from source control if needed |
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

**Identify all Lambda functions targeted by the attacker:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --query 'Events[?contains(CloudTrailEvent, `lambda.amazonaws.com`)].CloudTrailEvent' \
  --output text | jq -r 'fromjson | {eventName, requestParameters}' | jq -s '.'
```

**Check if exposed credentials were used by the attacker:**

```bash
# For each exposed credential, check CloudTrail for usage
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<EXPOSED_DB_USER> \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> \
  --output json
```

### Athena Query: ListVersionsByFunction Events

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
WHERE eventName = 'ListVersionsByFunction20150331'
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
    errorCode
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

**Step 3: Preserve the full version list with environment variables as evidence**

```bash
aws lambda list-versions-by-function \
  --function-name <FUNCTION_NAME> \
  --region <REGION> \
  --output json > /tmp/evidence-<FUNCTION_NAME>-versions-$(date -u +%Y%m%dT%H%M%SZ).json
```

**Step 4: Record which credentials were exposed**

```bash
aws lambda list-versions-by-function \
  --function-name <FUNCTION_NAME> \
  --region <REGION> \
  --query 'Versions[*].{Version:Version,EnvVars:Environment.Variables}' \
  --output json > /tmp/evidence-<FUNCTION_NAME>-exposed-envvars-$(date -u +%Y%m%dT%H%M%SZ).json
```

---

## 5. Recovery & Hardening

### Sanitize

- Rotate ALL credentials that were present in any Lambda version's environment variables
- Rotate database passwords, API keys, tokens, and any other secrets found
- Invalidate and re-issue any access tokens or session credentials

```bash
# List all unique environment variable keys across all versions
aws lambda list-versions-by-function \
  --function-name <FUNCTION_NAME> \
  --region <REGION> \
  --query 'Versions[*].Environment.Variables' \
  --output json | jq -r '.[].keys[]? // empty' | sort -u
```

### Restore

- Re-deploy the Lambda function from a verified, clean source repository
- Ensure the new deployment uses Secrets Manager or Parameter Store references instead of plaintext env vars
- Delete old versions that contained hardcoded credentials

```bash
# Delete old versions with exposed credentials
for version in $(aws lambda list-versions-by-function \
  --function-name <FUNCTION_NAME> \
  --region <REGION> \
  --query 'Versions[?Version!=`$LATEST`].Version' \
  --output text); do
  aws lambda delete-function \
    --function-name <FUNCTION_NAME> \
    --qualifier "$version" \
    --region <REGION>
done
```

### Harden

**Deploy SCP to deny ListVersionsByFunction for non-authorized roles:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyListVersionsUnlessAuthorized",
      "Effect": "Deny",
      "Action": "lambda:ListVersionsByFunction",
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

**Migrate all Lambda secrets to AWS Secrets Manager:**

```bash
# Create secret in Secrets Manager
aws secretsmanager create-secret \
  --name "/lambda/<FUNCTION_NAME>/db-password" \
  --secret-string "<NEW_ROTATED_PASSWORD>" \
  --region <REGION>

# Update Lambda to remove plaintext env vars and reference Secrets Manager
aws lambda update-function-configuration \
  --function-name <FUNCTION_NAME> \
  --environment '{"Variables":{"DB_PASS_SECRET_ARN":"arn:aws:secretsmanager:<REGION>:<ACCOUNT_ID>:secret:/lambda/<FUNCTION_NAME>/db-password"}}' \
  --region <REGION>
```

**Enable KMS encryption for Lambda environment variables:**

```bash
aws lambda update-function-configuration \
  --function-name <FUNCTION_NAME> \
  --kms-key-arn arn:aws:kms:<REGION>:<ACCOUNT_ID>:key/<KMS_KEY_ID> \
  --region <REGION>
```

### Verify

```bash
# Confirm the compromised role can no longer call ListVersionsByFunction
aws sts assume-role \
  --role-arn <CALLER_ARN> \
  --role-session-name verification-test \
  --query 'Credentials' \
  --output json

# Then attempt:
aws lambda list-versions-by-function --function-name <FUNCTION_NAME> --region <REGION>
# Expected: AccessDenied

# Confirm no old versions with plaintext credentials remain
aws lambda list-versions-by-function \
  --function-name <FUNCTION_NAME> \
  --region <REGION> \
  --query 'Versions[*].{Version:Version,EnvVars:Environment.Variables}' \
  --output json
```

### Post-Mortem Detection Gap Analysis

| Gap | Finding | Remediation |
|---|---|---|
| No alert on ListVersionsByFunction | Credential exposure via environment variables was unmonitored | Deploy the Sigma rule below |
| Plaintext credentials in Lambda environment variables | `DB_PASS`, `API_KEY`, and other secrets stored as plaintext env vars | Migrate all secrets to AWS Secrets Manager with automatic rotation |
| Old Lambda versions retained with hardcoded secrets | Versions from months ago still contained deprecated credentials | Implement version cleanup policy; delete old versions after deployment validation |
| No KMS encryption on Lambda environment variables | Env vars stored without encryption at rest | Enable KMS encryption for all Lambda functions |

---

## Detection Rule (Sigma Format)

```yaml
title: Lambda ListVersionsByFunction Called by EC2 Instance Role - Credential Exposure Risk
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: >
  Detects lambda:ListVersionsByFunction API calls made by EC2 instance roles.
  This API returns environment variables for all function versions, which may
  contain plaintext credentials. In SCARLETEEL, this exposed DB_PASS and other secrets.
references:
  - https://sysdig.com/blog/scarleteel-2-0/
author: MayaTrail
date: 2026/04/05
tags:
  - attack.credential_access
  - attack.t1552.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: ListVersionsByFunction20150331
    userIdentity.type: AssumedRole
  filter_known_services:
    userIdentity.invokedBy:
      - config.amazonaws.com
      - securityhub.amazonaws.com
  condition: selection and not filter_known_services
falsepositives:
  - Legitimate deployment pipelines querying function versions during rollback procedures
  - AWS CodeDeploy traffic-shifting operations
level: high
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Procedure |
|---|---|---|---|
| Credential Access | T1552.001 | Unsecured Credentials: Credentials in Files | Attacker retrieves plaintext credentials (DB_PASS, API keys) from Lambda environment variables exposed in version configurations |
| Discovery | T1526 | Cloud Service Discovery | ListVersionsByFunction reveals function runtime, handler, memory, timeout, and VPC configuration across all versions |
| Collection | T1005 | Data from Local System | Environment variables containing application configuration and secrets are collected from the API response |
| Persistence | T1078.004 | Valid Accounts: Cloud Accounts | Stolen credentials from environment variables may be used to authenticate to databases, APIs, or other cloud services |
