# IR Playbook: ATOMIC-rds-modify-public-access — AWS

## Classification
| Field | Value |
|-------|-------|
| Incident Type | Cloud Firewall Impairment / RDS Public Exposure |
| Threat Actor | ATOMIC-rds-modify-public-access (technique emulation) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Defense Evasion |
| MITRE Techniques | T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall |
| Execution Plane | Control Plane (AWS API / CloudTrail management events) |

---

## 1. Preparation

### Prerequisites
- CloudTrail management events enabled in all regions (multi-region trail recommended).
- AWS Security Hub enabled with `RDS.2` control active (RDS DB instances should prohibit public access).
- GuardDuty enabled with `CredentialAccess:Secrets/SecretsManagerGetSecretValue` finding type active.
- AWS Config rule `restricted-common-ports` active and recording.
- Responders have read access to CloudTrail, RDS, EC2, SecretsManager, STS, and IAM APIs.
- Incident response IAM role with least-privilege read + containment permissions pre-created.
- Runbook executed and tested in a lower environment before a live incident.

### Recommended Preventive Controls
| Control | AWS Service |
|---------|-------------|
| SCP blocking `rds:ModifyDBInstance` with `publiclyAccessible=true` | AWS Organizations / SCPs |
| SCP blocking `ec2:AuthorizeSecurityGroupIngress` to `0.0.0.0/0` on port 3306 | AWS Organizations / SCPs |
| GuardDuty Secrets findings alert routed to PagerDuty/Slack | EventBridge -> SNS |
| AWS Config auto-remediation lambda for `RDS.2` | AWS Config Remediation |
| IAM Access Analyzer external access findings for RDS SGs | IAM Access Analyzer |

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — events that almost always indicate active compromise

| Priority | Event Name | Event Source | Key Field | Value |
|----------|-----------|--------------|-----------|-------|
| P1 | `ModifyDBInstance` | `rds.amazonaws.com` | `requestParameters.publiclyAccessible` | `true` |
| P1 | `AuthorizeSecurityGroupIngress` | `ec2.amazonaws.com` | `requestParameters.ipPermissions.items[*].fromPort` | `3306` |
| P2 | `AssumeRole` | `sts.amazonaws.com` | `requestParameters.roleSessionName` | `atomic-rds-public-access-session` (or any unexpected session name on a privileged role) |
| P2 | `GetSecretValue` | `secretsmanager.amazonaws.com` | `responseElements` | `null` (AccessDenied — denied events still logged) |

#### MEDIUM-CONFIDENCE — events that may indicate compromise depending on context

| Priority | Event Name | Event Source | Signal |
|----------|-----------|--------------|--------|
| M1 | `GetSecretValue` | `secretsmanager.amazonaws.com` | Access to a production-named secret from an assumed-role session |
| M2 | `AssumeRole` | `sts.amazonaws.com` | Admin-breadth role assumed from an unexpected principal or outside business hours |
| M3 | `DescribeDBInstances` | `rds.amazonaws.com` | Enumeration of RDS instances immediately before a modification event |
| M4 | `DescribeSecurityGroups` | `ec2.amazonaws.com` | Security group enumeration from the same assumed-role session |

---

### Key Investigation Queries

#### Step 0 — Identify the time window and affected account

```bash
# Get current account ID for use in subsequent queries
aws sts get-caller-identity --query 'Account' --output text
```

#### Step 1 — Find the AssumeRole event for the attacker session

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query "Events[?contains(CloudTrailEvent, 'attacker-role') || contains(CloudTrailEvent, 'atomic-rds-public-access-session')].[EventTime,Username,CloudTrailEvent]" \
  --output table
```

```bash
# Broader: all AssumeRole events in the last 24h — review for suspicious session names
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query "Events[].[EventTime,Username,CloudTrailEvent]" \
  --output json | jq '.[] | {time: .[0], user: .[1], event: (.[2] | fromjson | {roleArn: .requestParameters.roleArn, sessionName: .requestParameters.roleSessionName, sourceIP: .sourceIPAddress, userAgent: .userAgent})}'
```

#### Step 2 — Find GetSecretValue events (including AccessDenied)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query "Events[].[EventTime,Username,CloudTrailEvent]" \
  --output json | jq '.[] | {time: .[0], user: .[1], event: (.[2] | fromjson | {secretId: .requestParameters.secretId, errorCode: .errorCode, errorMessage: .errorMessage, sourceIP: .sourceIPAddress, assumedRole: .userIdentity.arn})}'
```

#### Step 3 — Find ModifyDBInstance with publiclyAccessible=true

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyDBInstance \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query "Events[].[EventTime,Username,CloudTrailEvent]" \
  --output json | jq '.[] | {time: .[0], user: .[1], event: (.[2] | fromjson | {dbInstanceId: .requestParameters.dBInstanceIdentifier, publiclyAccessible: .requestParameters.publiclyAccessible, applyImmediately: .requestParameters.applyImmediately, sourceIP: .sourceIPAddress, assumedRole: .userIdentity.arn})}'
```

#### Step 4 — Find AuthorizeSecurityGroupIngress on MySQL port

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query "Events[].[EventTime,Username,CloudTrailEvent]" \
  --output json | jq '.[] | select((.[2] | fromjson | .requestParameters.ipPermissions.items[].fromPort) == 3306 or (.[2] | fromjson | .requestParameters.ipPermissions.items[].toPort) == 3306) | {time: .[0], user: .[1], event: (.[2] | fromjson | {sgId: .requestParameters.groupId, ipPerms: .requestParameters.ipPermissions, sourceIP: .sourceIPAddress, assumedRole: .userIdentity.arn})}'
```

#### Step 5 — Verify current RDS public access state

```bash
# List all RDS instances and their publiclyAccessible flag
aws rds describe-db-instances \
  --query "DBInstances[].[DBInstanceIdentifier,PubliclyAccessible,DBInstanceStatus,Endpoint.Address,VpcSecurityGroups[*].VpcSecurityGroupId]" \
  --output table
```

#### Step 6 — Inspect security group rules on RDS-attached SGs

```bash
# Replace <sg-id> with the RDS security group ID found in Step 5
aws ec2 describe-security-groups \
  --group-ids <sg-id> \
  --query "SecurityGroups[].IpPermissions[?FromPort==\`3306\` || ToPort==\`3306\`]" \
  --output json
```

#### Step 7 — Enumerate all actions taken by the attacker role session

```bash
# Replace <ACCOUNT_ID> and <ROLE_NAME> with actual values
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="arn:aws:sts::<ACCOUNT_ID>:assumed-role/<ROLE_NAME>/atomic-rds-public-access-session" \
  --start-time "$(date -u -d '48 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query "Events[].[EventTime,EventName,CloudTrailEvent]" \
  --output json | jq '.[] | {time: .[0], event: .[1], sourceIP: (.[2] | fromjson | .sourceIPAddress)}'
```

#### Step 8 — Check GuardDuty findings for corroborating signals

```bash
# List all active GuardDuty detectors
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Query findings related to RDS, SecretsManager, or credential access in the last 24h
aws guardduty list-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-criteria '{
    "Criterion": {
      "updatedAt": {
        "GreaterThanOrEqual": '"$(date -u -d '24 hours ago' +%s000)"'
      },
      "type": {
        "Neq": [""]
      }
    }
  }' \
  --query 'FindingIds' --output json | \
xargs -I{} aws guardduty get-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-ids {} \
  --query "Findings[].[Type,Title,Severity,UpdatedAt,Resource.AccessKeyDetails.UserName]" \
  --output table
```

#### Step 9 — Check AWS Security Hub for RDS.2 findings

```bash
aws securityhub get-findings \
  --filters '{
    "GeneratorId": [{"Value": "security-control/RDS.2", "Comparison": "PREFIX"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
  }' \
  --query "Findings[].[Title,Severity.Label,UpdatedAt,Resources[0].Id]" \
  --output table
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Action 1 — Revoke active sessions for the attacker role (deny all)

```bash
# Attach an inline deny-all policy to the attacker IAM role to invalidate all live sessions
# Replace <ROLE_NAME> with the actual attacker role name
aws iam put-role-policy \
  --role-name <ROLE_NAME> \
  --policy-name INCIDENT-RESPONSE-DENY-ALL \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {
          "DateLessThan": {
            "aws:TokenIssueTime": "'"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"'"
          }
        }
      }
    ]
  }'
```

```bash
# Alternatively — revoke all sessions immediately (simpler, broader)
aws iam put-role-policy \
  --role-name <ROLE_NAME> \
  --policy-name INCIDENT-RESPONSE-DENY-ALL \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
  }'
```

#### Action 2 — Restore RDS instance to non-public

```bash
# Replace <db-instance-id> with the actual RDS instance identifier
aws rds modify-db-instance \
  --db-instance-identifier <db-instance-id> \
  --no-publicly-accessible \
  --apply-immediately

# Confirm the change
aws rds describe-db-instances \
  --db-instance-identifier <db-instance-id> \
  --query "DBInstances[0].[DBInstanceIdentifier,PubliclyAccessible,DBInstanceStatus]" \
  --output table
```

#### Action 3 — Revoke the unauthorized security group ingress rule

```bash
# Replace <sg-id> and <cidr> with actual values found during investigation (e.g., 10.99.254.0/24)
aws ec2 revoke-security-group-ingress \
  --group-id <sg-id> \
  --protocol tcp \
  --port 3306 \
  --cidr <cidr>

# Verify the rule is gone
aws ec2 describe-security-groups \
  --group-ids <sg-id> \
  --query "SecurityGroups[].IpPermissions[?FromPort==\`3306\`]" \
  --output json
```

#### Action 4 — If the compromising principal is an IAM user key, deactivate it

```bash
# Replace <ACCESS_KEY_ID> and <USERNAME> with the compromised principal's credentials
aws iam update-access-key \
  --access-key-id <ACCESS_KEY_ID> \
  --status Inactive \
  --user-name <USERNAME>
```

#### Action 5 — Snapshot the RDS instance for forensics before any further changes

```bash
aws rds create-db-snapshot \
  --db-instance-identifier <db-instance-id> \
  --db-snapshot-identifier ir-forensic-$(date +%Y%m%d%H%M%S)
```

---

## 4. Eradication

### Remove Attacker Access

#### Remove the emergency deny policy and restore role to clean state (or delete role)

```bash
# Option A: delete the role entirely if it was attacker-planted
aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name INCIDENT-RESPONSE-DENY-ALL
aws iam list-role-policies --role-name <ROLE_NAME>    # verify no other attacker policies
aws iam list-attached-role-policies --role-name <ROLE_NAME>

# Detach all policies, then delete role
aws iam detach-role-policy --role-name <ROLE_NAME> --policy-arn <POLICY_ARN>
aws iam delete-role --role-name <ROLE_NAME>
```

#### Audit and rotate any credentials that may have been observed

```bash
# List all access keys for potentially exposed IAM users
aws iam list-users --query "Users[].UserName" --output text | \
  tr '\t' '\n' | \
  xargs -I{} sh -c 'echo "User: {}"; aws iam list-access-keys --user-name {} --query "AccessKeyMetadata[].[AccessKeyId,Status,CreateDate]" --output table'
```

```bash
# Rotate the RDS master password if GetSecretValue was successful
aws rds modify-db-instance \
  --db-instance-identifier <db-instance-id> \
  --master-user-password "$(openssl rand -base64 24)" \
  --apply-immediately

# Update the secret in SecretsManager with the new password
aws secretsmanager put-secret-value \
  --secret-id <secret-id> \
  --secret-string '{"username":"admin","password":"<NEW_PASSWORD>"}'
```

#### Verify no backdoor roles or policies were created during the session

```bash
# Enumerate IAM roles created or modified in the last 24h
aws iam list-roles \
  --query "Roles[?CreateDate>='$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')'].[RoleName,CreateDate,Arn]" \
  --output table

# Check for any inline policies added to existing roles
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutRolePolicy \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --output json | jq '.Events[]'

# Check for any new IAM users
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --output json | jq '.Events[]'
```

#### Verify no additional security group rules were added

```bash
# Find all AuthorizeSecurityGroupIngress events in the window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress \
  --start-time "$(date -u -d '48 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --output json | jq '.Events[] | {time: .EventTime, event: (.CloudTrailEvent | fromjson | {sgId: .requestParameters.groupId, perms: .requestParameters.ipPermissions})}'
```

---

## 5. Recovery

### Restore Clean State

#### Confirm RDS is no longer publicly accessible

```bash
aws rds describe-db-instances \
  --db-instance-identifier <db-instance-id> \
  --query "DBInstances[0].{Id:DBInstanceIdentifier,Public:PubliclyAccessible,Status:DBInstanceStatus}" \
  --output table
# Expected: Public = false
```

#### Confirm Security Hub RDS.2 finding resolves

```bash
# Force Security Hub re-evaluation (may take up to 12h to auto-resolve; trigger manually)
aws securityhub batch-import-findings \
  --findings '[{"SchemaVersion":"2018-10-08","Id":"manual-remediation-check","ProductArn":"arn:aws:securityhub:'$AWS_DEFAULT_REGION':'$ACCOUNT_ID':product/'$ACCOUNT_ID'/default","GeneratorId":"manual","AwsAccountId":"'$ACCOUNT_ID'","Types":["Software and Configuration Checks"],"CreatedAt":"'"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"'","UpdatedAt":"'"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"'","Severity":{"Label":"INFORMATIONAL"},"Title":"Manual remediation verification","Description":"Confirming RDS public access reverted","Resources":[{"Type":"AwsRdsDbInstance","Id":"arn:aws:rds:'$AWS_DEFAULT_REGION':'$ACCOUNT_ID':db:<db-instance-id>"}]}]' 2>/dev/null || echo "Use Security Hub console to re-run RDS.2 check"

# Query for current RDS.2 finding state
aws securityhub get-findings \
  --filters '{"GeneratorId":[{"Value":"security-control/RDS.2","Comparison":"PREFIX"}],"ResourceId":[{"Value":"<db-instance-id>","Comparison":"CONTAINS"}]}' \
  --query "Findings[].[Severity.Label,RecordState,UpdatedAt]" \
  --output table
```

#### Re-enable any security services that were disabled

```bash
# Verify GuardDuty is still active
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty get-detector --detector-id "$DETECTOR_ID" \
  --query "[Status,FindingPublishingFrequency,UpdatedAt]" --output table
# Expected Status: ENABLED

# Verify CloudTrail is still logging
aws cloudtrail describe-trails --query "trailList[].[Name,IsLogging,HomeRegion]" --output table
aws cloudtrail get-trail-status --name <trail-name> --query "IsLogging"
# Expected: true
```

#### Remove the deny-all IR policy from the attacker role if retained for audit

```bash
aws iam delete-role-policy \
  --role-name <ROLE_NAME> \
  --policy-name INCIDENT-RESPONSE-DENY-ALL
```

#### Verify no active sessions remain for the attacker role

```bash
# STS sessions cannot be explicitly listed, but you can verify the deny policy took effect
# by checking CloudTrail for any post-containment API calls from the session
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="arn:aws:sts::<ACCOUNT_ID>:assumed-role/<ROLE_NAME>/atomic-rds-public-access-session" \
  --start-time "<CONTAINMENT_TIMESTAMP>" \
  --output json | jq '.Events | length'
# Expected: 0 (no activity after deny policy applied)
```

---

## 6. Lessons Learned

### What Should Have Prevented This

| Gap | Recommended Guardrail | AWS Control |
|-----|----------------------|-------------|
| Attacker role permitted to call `rds:ModifyDBInstance` without restriction | Add SCP: `Deny rds:ModifyDBInstance` unless `aws:CalledVia = cloudformation.amazonaws.com` or require MFA condition | AWS Organizations SCP |
| Security group modification not restricted to CI/CD principal | SCP: `Deny ec2:AuthorizeSecurityGroupIngress` if `aws:RequestedRegion != approved-regions` or restrict by tag | AWS Organizations SCP |
| RDS publicly accessible by API call alone — no approval gate | Require `aws:MultiFactorAuthPresent = true` for RDS modification in production | IAM condition key |
| Role trust policy allowed account root assumption | Scope trust to specific principal ARN (deployment role), not account root | IAM trust policy |
| No alerting on `ModifyDBInstance` with `publiclyAccessible=true` | EventBridge rule: `source=aws.rds`, `detail-type=AWS API Call via CloudTrail`, `detail.eventName=ModifyDBInstance` + SNS alert | EventBridge + SNS |
| No alerting on port 3306 SG ingress | EventBridge rule on `AuthorizeSecurityGroupIngress` + Lambda checking port range | EventBridge + Lambda |
| Secret access from assumed-role session went undetected | GuardDuty `CredentialAccess:Secrets/SecretsManagerGetSecretValue` finding + PagerDuty routing | GuardDuty + EventBridge |
| No AWS Config rule auto-remediation | Enable auto-remediation for `restricted-common-ports` Config rule with SSM Automation document | AWS Config |

### Detection Timeline Analysis

```
T+0:00  AssumeRole        -> attacker-role (STS)           [CloudTrail: HIGH signal, often missed]
T+0:01  GetSecretValue     -> prod-rds-master-secret        [GuardDuty: should alert within 5 min]
T+0:02  ModifyDBInstance   -> publiclyAccessible=true       [Security Hub: RDS.2 finding, 1-12h delay]
T+0:03  AuthorizeSGIngress -> port 3306 open               [CloudTrail: HIGH signal]
```

**Mean time to alert target:** < 5 minutes via GuardDuty + EventBridge pipeline.  
**Mean time to contain target:** < 15 minutes using the CLI commands in Section 3.

### Post-Incident Actions
1. File a Security Hub finding suppression exception review for any rules that did not trigger.
2. Update the IR role IAM policy to pre-authorize containment actions (RDS modify, SG revoke, IAM deny policy) so responders do not hit permission errors under pressure.
3. Add the `ModifyDBInstance` + `AuthorizeSecurityGroupIngress` event pair to the SIEM correlation rule as a single incident trigger (chained events within 5 minutes from the same source ARN = critical alert).
4. Conduct tabletop exercise using this playbook within 30 days.