# IR Playbook: ATOMIC-rds-reset-master-password — AWS

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential Access / Data from Information Repositories |
| Threat Actor | ATOMIC-rds-reset-master-password (technique emulation pattern) |
| Platform | aws |
| Severity | High |
| MITRE Tactics | Collection |
| MITRE Techniques | T1213 — Data from Information Repositories |
| Primary Signal | `ModifyDBInstance` with `masterUserPassword HIDDEN_DUE_TO_SECURITY_REASONS` from a non-DBA principal |

---

## 1. Preparation

### Prerequisites

- CloudTrail management events enabled in all regions (multi-region trail recommended).
- GuardDuty enabled with `CredentialAccess:Secrets/SecretsManagerGetSecretValue` finding active.
- AWS Security Hub enabled with CIS/FSBP standards.
- RDS instance tagging policy in place: `Owner`, `Team`, `RotationRole` tags on every instance.
- Least-privilege IAM: only dedicated secrets-rotation roles and DBA roles should hold `rds:ModifyDBInstance` with `masterUserPassword`.
- SCPs or permission boundaries blocking `rds:ModifyDBInstance` from non-DBA/non-rotation principals at the OU level.
- Baseline alerting on `ModifyDBInstance` events via EventBridge → SNS (see below).
- Known-good principal list for `rds:ModifyDBInstance` documented in runbook (DBA role ARNs, secrets-rotation Lambda role ARN).

### Alerting Rule (EventBridge)

```json
{
  "source": ["aws.rds"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["ModifyDBInstance"],
    "requestParameters": {
      "masterUserPassword": ["HIDDEN_DUE_TO_SECURITY_REASONS"]
    }
  }
}
```

---

## 2. Identification

### Detection Triggers (Prioritized)

**HIGH-CONFIDENCE — any of these alone confirms compromise:**

| Event | Source | Signal |
|-------|--------|--------|
| `ModifyDBInstance` with `masterUserPassword HIDDEN_DUE_TO_SECURITY_REASONS` | `rds.amazonaws.com` | Master password reset — primary attack action |
| `ModifyDBInstance` from a principal that is not the DBA or secrets-rotation role ARN | `rds.amazonaws.com` | Unauthorized credential takeover |
| `ModifyDBInstance` with `ApplyImmediately=true` outside a maintenance window | `rds.amazonaws.com` | Forced immediate credential reset |

**MEDIUM-CONFIDENCE — indicators of attacker reconnaissance preceding the reset:**

| Event | Source | Signal |
|-------|--------|--------|
| `AssumeRole` into a DB-management role from an unexpected pipeline/admin principal | `sts.amazonaws.com` | Lateral movement into DB principal |
| `ListSecrets` from a DB-management role (especially `AccessDenied`) | `secretsmanager.amazonaws.com` | Secret enumeration by a principal not expected to list secrets |
| `GetSecretValue` on a prod/database credential secret returning `AccessDenied` | `secretsmanager.amazonaws.com` | Credential harvesting attempt (GuardDuty: `CredentialAccess:Secrets/SecretsManagerGetSecretValue`) |
| `DescribeDBInstances` from a non-DBA principal shortly before `ModifyDBInstance` | `rds.amazonaws.com` | Target scoping before reset |

---

### Key Investigation Queries

**Step 1 — Confirm the `ModifyDBInstance` event and extract the acting principal:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyDBInstance \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --region us-east-1 \
  --query 'Events[*].{Time:EventTime,User:Username,EventId:EventId,Raw:CloudTrailEvent}' \
  --output table
```

**Step 2 — Pull the full raw event to confirm `masterUserPassword` was changed:**

```bash
# Replace EVENT_ID with the EventId from Step 1
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventId,AttributeValue=<EVENT_ID> \
  --region us-east-1 \
  --query 'Events[0].CloudTrailEvent' \
  --output text | python -m json.tool
```

Look for: `requestParameters.masterUserPassword = "HIDDEN_DUE_TO_SECURITY_REASONS"` and `requestParameters.applyImmediately = true`.

**Step 3 — Trace the full session: find the AssumeRole that created the acting identity:**

```bash
# Replace ROLE_ARN with the userIdentity.arn from the ModifyDBInstance event
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --region us-east-1 \
  --query 'Events[?contains(CloudTrailEvent, `<ROLE_ARN>`)].CloudTrailEvent' \
  --output text | python -m json.tool
```

Look for: `requestParameters.roleArn`, `requestParameters.roleSessionName` (e.g., `atomic-rds-reset-master-password-session`), and the `userIdentity` of the caller that assumed the role.

**Step 4 — Check Secrets Manager reconnaissance events from the same session:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListSecrets \
  --start-time $(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --region us-east-1 \
  --output json | python -m json.tool

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time $(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --region us-east-1 \
  --output json | python -m json.tool
```

**Step 5 — Check `DescribeDBInstances` scoping calls from the same principal:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeDBInstances \
  --start-time $(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --region us-east-1 \
  --query 'Events[*].{Time:EventTime,User:Username}' \
  --output table
```

**Step 6 — Confirm the current RDS instance state and pending modifications:**

```bash
aws rds describe-db-instances \
  --db-instance-identifier <DB_INSTANCE_ID> \
  --region us-east-1 \
  --query 'DBInstances[0].{Status:DBInstanceStatus,PendingModifiedValues:PendingModifiedValues,LastModified:LatestRestorableTime}' \
  --output json
```

**Step 7 — Check GuardDuty findings for the time window:**

```bash
DETECTOR_ID=$(aws guardduty list-detectors --region us-east-1 --query 'DetectorIds[0]' --output text)

aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "updatedAt": {
        "GreaterThanOrEqual": '$(date -u -d '4 hours ago' +%s000)'
      }
    }
  }' \
  --region us-east-1 \
  --output json

# Get finding details
aws guardduty get-findings \
  --detector-id $DETECTOR_ID \
  --finding-ids $(aws guardduty list-findings --detector-id $DETECTOR_ID --region us-east-1 --query 'FindingIds[*]' --output text) \
  --region us-east-1 \
  --query 'Findings[*].{Type:Type,Severity:Severity,Title:Title,Principal:Service.Action.AwsApiCallAction.RemoteIpDetails}' \
  --output table
```

**Step 8 — Cross-check IAM role permissions for the acting principal:**

```bash
# Replace ROLE_NAME with the victim role name
aws iam get-role-policy \
  --role-name <VICTIM_ROLE_NAME> \
  --policy-name <POLICY_NAME> \
  --output json

aws iam list-attached-role-policies \
  --role-name <VICTIM_ROLE_NAME> \
  --output table

# Simulate what the role can do against RDS
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<ACCOUNT_ID>:role/<VICTIM_ROLE_NAME> \
  --action-names rds:ModifyDBInstance secretsmanager:GetSecretValue \
  --resource-arns '*' \
  --output table
```

---

## 3. Containment

### Immediate Actions (First 15 Minutes)

**Action 1 — Revoke all active sessions of the compromised role (force credential expiry):**

```bash
# Add an explicit deny policy to the victim role to invalidate all issued STS tokens
aws iam put-role-policy \
  --role-name <VICTIM_ROLE_NAME> \
  --policy-name INCIDENT-RESPONSE-REVOKE-ALL-SESSIONS \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
        }
      }
    }]
  }'
```

**Action 2 — If the source principal (the role/user that performed AssumeRole) is identified, disable it:**

```bash
# If source is an IAM user
aws iam update-login-profile --user-name <SOURCE_USER> --no-password-reset-required 2>/dev/null
aws iam list-access-keys --user-name <SOURCE_USER> --output table
aws iam update-access-key \
  --user-name <SOURCE_USER> \
  --access-key-id <ACCESS_KEY_ID> \
  --status Inactive

# If source is an IAM role, detach its assume-role trust policy
aws iam update-assume-role-policy \
  --role-name <SOURCE_ROLE_NAME> \
  --policy-document '{"Version":"2012-10-17","Statement":[]}'
```

**Action 3 — Immediately rotate the RDS master password back to a known-good credential and store it in Secrets Manager:**

```bash
# Generate a strong replacement password (run locally, do not log)
NEW_PASS=$(python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32)))")

aws rds modify-db-instance \
  --db-instance-identifier <DB_INSTANCE_ID> \
  --master-user-password "$NEW_PASS" \
  --apply-immediately \
  --region us-east-1

# Immediately update the authoritative secret
aws secretsmanager put-secret-value \
  --secret-id prod/database/master_credentials \
  --secret-string "{\"username\":\"admin\",\"password\":\"$NEW_PASS\",\"engine\":\"mysql\",\"host\":\"<RDS_ENDPOINT>\",\"dbname\":\"<DBNAME>\"}" \
  --region us-east-1
```

**Action 4 — Block the victim role from calling `rds:ModifyDBInstance` at the resource policy level:**

```bash
aws iam put-role-policy \
  --role-name <VICTIM_ROLE_NAME> \
  --policy-name INCIDENT-RESPONSE-DENY-RDS-MODIFY \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": ["rds:ModifyDBInstance","rds:ModifyDBCluster"],
      "Resource": "*"
    }]
  }'
```

**Action 5 — Verify the RDS instance returns to `available` state after the recovery rotation:**

```bash
aws rds wait db-instance-available \
  --db-instance-identifier <DB_INSTANCE_ID> \
  --region us-east-1

aws rds describe-db-instances \
  --db-instance-identifier <DB_INSTANCE_ID> \
  --region us-east-1 \
  --query 'DBInstances[0].{Status:DBInstanceStatus,PendingMods:PendingModifiedValues}' \
  --output json
```

---

## 4. Eradication

### Remove Attacker Access

**Step 1 — Delete or restrict the victim role's trust policy to prevent re-assumption:**

```bash
# Inspect current trust policy
aws iam get-role --role-name <VICTIM_ROLE_NAME> \
  --query 'Role.AssumeRolePolicyDocument' --output json

# Replace with a tightly scoped trust (allow only the legitimate rotation Lambda or DBA user)
aws iam update-assume-role-policy \
  --role-name <VICTIM_ROLE_NAME> \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<ACCOUNT_ID>:role/<LEGITIMATE_DBA_ROLE>"
      },
      "Action": "sts:AssumeRole"
    }]
  }'
```

**Step 2 — Remove the incident-response inline policies once the permanent fix is in place:**

```bash
aws iam delete-role-policy \
  --role-name <VICTIM_ROLE_NAME> \
  --policy-name INCIDENT-RESPONSE-REVOKE-ALL-SESSIONS

aws iam delete-role-policy \
  --role-name <VICTIM_ROLE_NAME> \
  --policy-name INCIDENT-RESPONSE-DENY-RDS-MODIFY
```

**Step 3 — Rotate all IAM access keys for the source principal that performed `AssumeRole`:**

```bash
# List and rotate
aws iam list-access-keys --user-name <SOURCE_USER> --output table

aws iam delete-access-key \
  --user-name <SOURCE_USER> \
  --access-key-id <OLD_KEY_ID>

aws iam create-access-key --user-name <SOURCE_USER> --output json
```

**Step 4 — Confirm no additional RDS modifications occurred (look for multi-instance attacks):**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyDBInstance \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --region us-east-1 \
  --query 'Events[*].{Time:EventTime,User:Username,Event:CloudTrailEvent}' \
  --output json | python -m json.tool
```

**Step 5 — Audit all other secrets the compromised principal could have accessed:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --region us-east-1 \
  --query 'Events[?contains(CloudTrailEvent, `<VICTIM_ROLE_NAME>`)].CloudTrailEvent' \
  --output text
```

---

## 5. Recovery

### Restore Clean State

**Step 1 — Verify the rotated RDS password is accepted by the application (health check):**

```bash
aws rds describe-db-instances \
  --db-instance-identifier <DB_INSTANCE_ID> \
  --region us-east-1 \
  --query 'DBInstances[0].{Status:DBInstanceStatus,Engine:Engine,Endpoint:Endpoint}' \
  --output json
```

**Step 2 — Re-enable any suspended application services that lost DB connectivity:**

```bash
# Example: restart an ECS task that uses the DB credential from Secrets Manager
aws ecs update-service \
  --cluster <CLUSTER_NAME> \
  --service <SERVICE_NAME> \
  --force-new-deployment \
  --region us-east-1
```

**Step 3 — Verify GuardDuty is active and findings are not suppressed:**

```bash
DETECTOR_ID=$(aws guardduty list-detectors --region us-east-1 --query 'DetectorIds[0]' --output text)

aws guardduty get-detector \
  --detector-id $DETECTOR_ID \
  --region us-east-1 \
  --query '{Status:Status,UpdatedAt:UpdatedAt,FindingPublishingFrequency:FindingPublishingFrequency}' \
  --output json
```

**Step 4 — Confirm the Secrets Manager secret for the DB has been updated and is accessible only to authorized roles:**

```bash
aws secretsmanager get-secret-value \
  --secret-id prod/database/master_credentials \
  --region us-east-1 \
  --query 'SecretString' \
  --output text | python -m json.tool

aws secretsmanager get-resource-policy \
  --secret-id prod/database/master_credentials \
  --region us-east-1 \
  --output json
```

**Step 5 — Re-validate IAM role permissions with `iam:SimulatePrincipalPolicy` before re-enabling the victim role in production:**

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<ACCOUNT_ID>:role/<VICTIM_ROLE_NAME> \
  --action-names \
    rds:ModifyDBInstance \
    secretsmanager:GetSecretValue \
    secretsmanager:ListSecrets \
  --resource-arns '*' \
  --query 'EvaluationResults[*].{Action:EvalActionName,Decision:EvalDecision}' \
  --output table
```

**Step 6 — Archive CloudTrail event artifacts for legal/compliance hold:**

```bash
# Export relevant events to S3 for evidence preservation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyDBInstance \
  --start-time <INCIDENT_START_TIME> \
  --end-time <INCIDENT_END_TIME> \
  --region us-east-1 \
  --output json > /tmp/incident-rds-modify-evidence.json

aws s3 cp /tmp/incident-rds-modify-evidence.json \
  s3://<EVIDENCE_BUCKET>/incidents/$(date +%Y%m%d)-rds-reset-master-password/evidence.json
```

---

## 6. Lessons Learned

### What Happened

A DB-management IAM role (`victim-role`) with a permissive trust policy (account root) was assumed by a pipeline/admin principal. The actor used that role to reset the RDS master password via `rds:ModifyDBInstance` with `ApplyImmediately=true`, achieving full DB-level credential control without requiring network access to the instance. Secrets Manager reconnaissance (`ListSecrets`, `GetSecretValue`) returned `AccessDenied` — but the denied events are themselves detective signals.

### What Would Have Prevented This

| Guardrail | Implementation |
|-----------|----------------|
| Least-privilege trust policy on victim role | Scope `sts:AssumeRole` to specific role ARNs (DBA/rotation Lambda), never to `arn:aws:iam::<account>:root` |
| SCP blocking `rds:ModifyDBInstance` + `masterUserPassword` from non-rotation principals | `Deny rds:ModifyDBInstance` unless `aws:PrincipalTag/Role = dba-rotation` at the SCP level |
| EventBridge alert on any `ModifyDBInstance` with `masterUserPassword` | Route to PagerDuty/SNS with < 5-minute MTTD |
| RDS IAM authentication instead of master-password auth | Removes the master password as an attack surface for application connectivity |
| Secrets Manager resource policy restricting `GetSecretValue` | `Deny` all except the rotation Lambda ARN and DBA role; `NotPrincipal` list is short and auditable |
| GuardDuty `CredentialAccess:Secrets/SecretsManagerGetSecretValue` | Should have triggered on the `GetSecretValue` AccessDenied pattern if the finding type is active |
| CloudTrail Insights on `ModifyDBInstance` anomalous call rates | Would surface an unexpected spike from a non-baseline principal |

### Relevant MITRE ATT&CK References

- **T1213** — Data from Information Repositories: attacker reads credential metadata from Secrets Manager and resets the DB master password to gain repository-level data access.
- **T1098** — Account Manipulation: `rds:ModifyDBInstance masterUserPassword` is functionally credential manipulation at the DB layer.