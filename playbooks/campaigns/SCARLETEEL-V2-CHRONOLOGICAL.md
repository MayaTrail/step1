---
id: aws-campaign-scarleteel-v2
campaign: SCARLETEEL 2.0
required_inputs:
  - INCIDENT_START_TIME
  - ACCOUNT_ID
  - REGION
  - COMPROMISED_INSTANCE_ID
provided_outputs:
  - ATTACKER_SOURCE_IP
  - ATTACKER_SOURCE_IPV6
  - COMPROMISED_ROLE_ARN
  - LATERAL_USER_ARN
  - EXFILTRATED_ASSETS
  - STOLEN_SECRETS
  - BLIND_WINDOW_START
  - BLIND_WINDOW_END
chained_playbooks:
  - PB-AWS-IAM-ListUsers-01
  - PB-AWS-IAM-ListRoles-01
  - PB-AWS-IAM-CreateUser-01
  - PB-AWS-IAM-DeleteUser-01
  - PB-AWS-IAM-CreateAccessKey-01
  - PB-AWS-S3-ListBuckets-01
  - PB-AWS-S3-ListObjectsV2-01
  - PB-AWS-S3-GetObject-01
  - PB-AWS-Lambda-ListFunctions-01
  - PB-AWS-Lambda-GetFunction-01
  - PB-AWS-Lambda-ListVersionsByFunction-01
  - PB-AWS-Lambda-GetPolicy-01
  - PB-AWS-Lambda-ListAliases-01
  - PB-AWS-Lambda-ListTags-01
  - PB-AWS-Lambda-ListEventSourceMappings-01
  - PB-AWS-CloudTrail-DescribeTrails-01
  - PB-AWS-CloudTrail-StopLogging-01
  - PB-AWS-STS-GetCallerIdentity-01
  - PB-AWS-SecretsManager-ListSecrets-01
  - PB-AWS-SecretsManager-GetSecretValue-01
---

# Playbook: SCARLETEEL 2.0 Campaign Response (Chronological)

**ID:** PB-AWS-CAMPAIGN-SCARLETEEL-V2-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

> This playbook follows the attack in **chronological order** (Phase 1 → 6). For the **alert-driven investigation** that starts from the highest-signal event (`StopLogging`) and pivots outward, see [SCARLETEEL-V2-STOPLOGGING-FIRST](SCARLETEEL-V2-STOPLOGGING-FIRST.md).

---

## 1. Governance & Metadata

| Field | Value |
|-------|-------|
| **Playbook Name** | SCARLETEEL 2.0 Cloud Infrastructure Compromise |
| **Playbook ID** | PB-AWS-CAMPAIGN-SCARLETEEL-V2-01 |
| **Version** | 1.0 |
| **Type** | Campaign-Level (chains per-API-call playbooks) |
| **Scenario** | Multi-phase cloud APT: container RCE → IMDSv1 credential theft → Pacu-style IAM recon → permission boundary bypass → S3/Lambda enumeration and data theft → CloudTrail defense evasion → Terraform state credential theft → lateral movement with stolen IAM user → SecretsManager secret exfiltration. Host-level activity includes iptables flush, Docker container credential sweep, XMRig cryptominer deployment, Pandora (Mirai) DDoS bot, and bash history wiping. |
| **Threat Actor** | SCARLETEEL 2.0 (Sysdig classification) |
| **Trigger** | Any TWO or more of: (1) `StopLogging` event, (2) EC2 role credentials used from non-instance IP, (3) `CreateUser` + `DeleteUser` from compute principal within seconds, (4) `ListFunctions` + `GetFunction` burst from EC2 role, (5) `ListSecrets` + `GetSecretValue` from EC2 role |
| **MITRE ATT&CK Tactics** | Initial Access, Execution, Persistence, Credential Access, Discovery, Collection, Defense Evasion, Lateral Movement, Impact |
| **Source Intelligence** | [Sysdig SCARLETEEL 2.0](https://www.sysdig.com/blog/scarleteel-2-0/) |

### Key Differences from SCARLETEEL v1

| Capability | v1 | v2 |
|---|---|---|
| Initial access | IMDS theft only | Container RCE + IMDS theft |
| IAM recon | None (direct escalation) | Pacu-style ListUsers/ListRoles before escalation |
| Priv esc technique | CreateUser/CreateAccessKey | Create-then-delete probe + AdminJoe naming bypass |
| Evidence destruction | No | CreateUser → immediate DeleteUser to cover tracks |
| Defense evasion | StopLogging | StopLogging + timed secret exfil during blind window |
| Persistence (host) | XMRig miner | XMRig + Pandora/Mirai DDoS bot + iptables flush |
| Secret theft | Lambda env vars only | Lambda env vars + SecretsManager production credentials |
| Lateral movement | Terraform state creds | Terraform state creds + secondary pivot via SecretsManager |
| Anti-forensics | None | bash history -cw after each phase, history wiping |

### SLA

| Severity | Acknowledge | Contain | Resolve |
|---|---|---|---|
| CRITICAL | 5 minutes | 30 minutes | 4 hours |
| HIGH | 15 minutes | 1 hour | 8 hours |
| MEDIUM | 2 hours | 8 hours | 24 hours |

**Campaign-specific SLA overrides:** Re-enable CloudTrail logging within 5 minutes of `StopLogging` detection. Begin secret rotation within 15 minutes of confirmed `GetSecretValue` from compromised principal.

### Severity Matrix

| Level | Condition | Action |
|-------|-----------|--------|
| **CRITICAL** | `StopLogging` observed OR EC2 role creds used from non-instance IP OR `CreateUser` + `DeleteUser` from compute role within seconds OR `GetSecretValue` on production secrets from compute role | Wake CISO & Legal immediately. Page oncall. Begin containment within 5 minutes. |
| **HIGH** | Lambda enumeration burst (5+ Lambda read APIs in 30s from same principal) OR `ListBuckets` from EC2 role followed by `GetObject` on 3+ buckets OR `ListSecrets` from compute role | Immediate IR team response. Begin triage within 15 minutes. |
| **MEDIUM** | Isolated `ListUsers` or `ListBuckets` from EC2 role with no follow-on activity within 10 minutes | Next-business-day triage. Investigate whether role permissions are appropriate. |

### Prerequisites

- **Roles:** `IncidentResponseRole` with read access to CloudTrail, IAM, EC2, S3, Lambda, SecretsManager, CloudWatch
- **Logs:** CloudTrail (management events minimum; S3 data events recommended), VPC Flow Logs
- **Tools:** AWS CLI, Athena, boto3
- **Services:** GuardDuty enabled (detects `InstanceCredentialExfiltration.OutsideAWS`)

### Stakeholders

| Role | When to Notify |
|------|----------------|
| Security Oncall | Immediately on CRITICAL trigger |
| CISO | Within 15 minutes if credential exfiltration confirmed |
| Legal | If PII/customer data in exfiltrated S3 objects, Lambda env vars, or SecretsManager secrets |
| Engineering Lead | If production Lambda functions or secrets compromised |
| DBA Team | If database credentials stolen via SecretsManager |
| PR/Comms | If customer data breach confirmed |

### Compliance

- GDPR 72-hour notification clock starts when credential exfiltration is confirmed
- SOC 2 incident response documentation required
- PCI DSS if payment data in exfiltrated objects or stolen secrets

### Related Playbooks

| Playbook ID | API Call | Kill Chain Phase |
|---|---|---|
| PB-AWS-IAM-ListUsers-01 | `iam:ListUsers` | Phase 2 — Recon, Phase 6 — Lateral |
| PB-AWS-IAM-ListRoles-01 | `iam:ListRoles` | Phase 2 — Recon |
| PB-AWS-IAM-CreateUser-01 | `iam:CreateUser` | Phase 2 — Priv Esc Probe |
| PB-AWS-IAM-DeleteUser-01 | `iam:DeleteUser` | Phase 2 — Evidence Destruction |
| PB-AWS-IAM-CreateAccessKey-01 | `iam:CreateAccessKey` | Phase 2 — Naming Bypass |
| PB-AWS-S3-ListBuckets-01 | `s3:ListBuckets` | Phase 3 — Enumeration |
| PB-AWS-S3-ListObjectsV2-01 | `s3:ListObjectsV2` | Phase 3 — Enumeration |
| PB-AWS-S3-GetObject-01 | `s3:GetObject` | Phase 3, 5 — Exfiltration |
| PB-AWS-Lambda-ListFunctions-01 | `lambda:ListFunctions` | Phase 3 — Enumeration |
| PB-AWS-Lambda-GetFunction-01 | `lambda:GetFunction` | Phase 3 — Source Code Theft |
| PB-AWS-Lambda-ListVersionsByFunction-01 | `lambda:ListVersionsByFunction` | Phase 3 — Secret Exposure |
| PB-AWS-Lambda-GetPolicy-01 | `lambda:GetPolicy` | Phase 3 — Recon |
| PB-AWS-Lambda-ListAliases-01 | `lambda:ListAliases` | Phase 3 — Recon |
| PB-AWS-Lambda-ListTags-01 | `lambda:ListTags` | Phase 3 — Recon |
| PB-AWS-Lambda-ListEventSourceMappings-01 | `lambda:ListEventSourceMappings` | Phase 3 — Recon |
| PB-AWS-CloudTrail-DescribeTrails-01 | `cloudtrail:DescribeTrails` | Phase 4 — Defense Evasion Recon |
| PB-AWS-CloudTrail-StopLogging-01 | `cloudtrail:StopLogging` | Phase 4 — Defense Evasion |
| PB-AWS-STS-GetCallerIdentity-01 | `sts:GetCallerIdentity` | Phase 6 — Lateral Movement |
| PB-AWS-SecretsManager-ListSecrets-01 | `secretsmanager:ListSecrets` | Phase 6 — Secondary Pivot |
| PB-AWS-SecretsManager-GetSecretValue-01 | `secretsmanager:GetSecretValue` | Phase 6 — Secret Theft |

---

## 2. Triage & Validation

### Step 2.0: Immediate Action (Before Triage)

If `cloudtrail:StopLogging` is observed, re-enable logging **BEFORE** any investigation:

```bash
aws cloudtrail start-logging \
  --name <TRAIL_NAME> \
  --region <REGION> \
  --profile <IR_PROFILE>
```

This is non-negotiable. Every second of blind window is unrecoverable evidence.

### Step 2.1: Start From the Trigger Signal

Extract pivot fields (principal, source IP, timestamp) from whichever alert fired first.

**If the trigger is `StopLogging`:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    .Events[] | .CloudTrailEvent | fromjson |
    {eventTime, callerArn: .userIdentity.arn, sourceIP: .sourceIPAddress,
     userAgent, trail: .requestParameters.name}'
```

**If the trigger is CreateUser/DeleteUser rapid pair:**

```bash
aws cloudtrail lookup-events \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.eventName == "CreateUser" or .eventName == "DeleteUser") |
     select(.userIdentity.principalId | contains(":i-"))] |
    sort_by(.eventTime) |
    .[] | {eventTime, eventName, callerArn: .userIdentity.arn,
           sourceIP: .sourceIPAddress, user: .requestParameters.userName}'
```

**If the trigger is SecretsManager access from compute:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=secretsmanager.amazonaws.com \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    .Events[] | .CloudTrailEvent | fromjson |
    select(.userIdentity.principalId | contains(":i-")) |
    {eventTime, eventName, callerArn: .userIdentity.arn,
     sourceIP: .sourceIPAddress, secretId: .requestParameters.secretId}'
```

### Step 2.1b: Source IP Correlation

Check if multiple principals were used from the attacker's source IP:

```bash
aws cloudtrail lookup-events \
  --start-time "<INCIDENT_START_TIME>" \
  --end-time "<INCIDENT_END_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.sourceIPAddress == "<ATTACKER_SOURCE_IP>")] |
    group_by(.userIdentity.arn) |
    map({principal: .[0].userIdentity.arn, count: length,
         first: .[0].eventTime, last: .[-1].eventTime})'
```

**v2-specific:** Check BOTH IPv4 and IPv6 addresses. In the emulation, the attacker used `122.162.145.217` (IPv4) for IAM/Lambda/CloudTrail calls and `2401:4900:1c88:3f9e:551b:c1cb:db2c:a7ad` (IPv6) for SecretsManager calls — same attacker, different IP versions per AWS service endpoint.

### Step 2.2: Confirm IMDSv1 as Attack Vector

```bash
aws ec2 describe-instances \
  --instance-ids <COMPROMISED_INSTANCE_ID> \
  --query "Reservations[0].Instances[0].MetadataOptions" \
  --output json --profile <IR_PROFILE>
```

If `HttpTokens: "optional"` → IMDSv1 enabled, container credential theft possible.
If `HttpPutResponseHopLimit >= 2` → Docker bridge containers can reach IMDS.

**v2-specific:** Also check the `ec2RoleDelivery` field in any CloudTrail event from the compromised role. Value `"1.0"` confirms IMDSv1 was the credential source (IMDSv2 shows `"2.0"`).

### Step 2.3: Confirm Credential Exfiltration via UserAgent

```bash
aws cloudtrail lookup-events \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    .Events[] | .CloudTrailEvent | fromjson |
    select(.userIdentity.arn | contains("<COMPROMISED_ROLE_NAME>")) |
    select(.sourceIPAddress != "AWS Internal") |
    {eventTime, eventName, sourceIP: .sourceIPAddress, userAgent} | limit(5;.)'
```

**v2-specific detection signal:** If `userAgent` contains `os/windows` but the EC2 instance runs Linux (AL2023), credentials are being used from a different machine entirely.

### Step 2.4: Decision Gate

- IF `sourceIPAddress` != instance IP AND `StopLogging` observed AND `GetSecretValue` on production secrets → **CONFIRMED SCARLETEEL 2.0. Containment L3 immediately.**
- IF `sourceIPAddress` != instance IP AND `StopLogging` observed → **CONFIRMED SCARLETEEL. Containment L2, full investigation.**
- IF `sourceIPAddress` != instance IP but no `StopLogging` → **LIKELY compromise. Containment L1, continue investigation.**
- IF calls from expected IPs with MFA → **Likely automation. Verify with team. Mark False Positive if confirmed.**

---

## 3. Containment Strategy (Graduated Response)

### Priority 0: Re-enable CloudTrail (if disabled)

```bash
aws cloudtrail start-logging --name <TRAIL_NAME> --region <REGION> --profile <IR_PROFILE>
```

### Graduated Containment

| Level | Condition | Action | Rollback |
|-------|-----------|--------|----------|
| **L1 (Soft)** | Suspected credential theft | Revoke EC2 role sessions: `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name EmergencyRevokeOldSessions --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<INCIDENT_START_TIME>"}}}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name EmergencyRevokeOldSessions` |
| **L2 (Hard)** | Confirmed exfiltration or `StopLogging` | Deny-all on the role: `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name EmergencyDenyAll --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name EmergencyDenyAll` |
| **L2 (Hard)** | Lateral movement creds identified | Deactivate stolen access keys: `aws iam update-access-key --user-name <LATERAL_USERNAME> --access-key-id <KEY_ID> --status Inactive` | `aws iam update-access-key --user-name <LATERAL_USERNAME> --access-key-id <KEY_ID> --status Active` |
| **L3 (Nuclear)** | Production secrets stolen or active exfiltration | Isolate EC2: `aws ec2 modify-instance-attribute --instance-id <COMPROMISED_INSTANCE_ID> --groups <QUARANTINE_SG_ID>` AND stop instance: `aws ec2 stop-instances --instance-ids <COMPROMISED_INSTANCE_ID>` | Restore SG and restart after investigation |

**CRITICAL CHECK:** Before L2/L3, confirm NOT tagged `Critical-Production-App`:

```bash
aws ec2 describe-tags \
  --filters "Name=resource-id,Values=<COMPROMISED_INSTANCE_ID>" "Name=key,Values=Critical-Production-App" \
  --output text --profile <IR_PROFILE>
```

---

## 4. Investigation & Forensics

### 4.1: Reconstruct the Kill Chain (Chronological)

Execute per-API-call playbooks in attack order:

| Phase | Attack Step | CloudTrail Events | Playbook | Key Evidence |
|-------|------------|-------------------|----------|--------------|
| 1 | Container RCE + IMDSv1 theft | (No CloudTrail — data plane) | N/A | VPC Flow Logs to port 8080, EC2 console output, `ec2RoleDelivery: "1.0"` |
| 1 | Cryptominer + Pandora deployment | (No CloudTrail — host-level) | N/A | EC2 console: systemd `containered.service`, `/root/.configure/containerd`, `/root/.configure/pandora` |
| 2 | Pacu-style IAM recon | `ListUsers`, `ListRoles` | PB-AWS-IAM-ListUsers-01, PB-AWS-IAM-ListRoles-01 | Burst of IAM discovery from EC2 role |
| 2 | Priv esc probe (create+delete) | `CreateUser`, `DeleteUser` | PB-AWS-IAM-CreateUser-01, PB-AWS-IAM-DeleteUser-01 | Same-second create+delete of `ScarleteelBackdoor` |
| 2 | Permission boundary bypass | `CreateAccessKey` (AccessDenied), `CreateAccessKey` (NoSuchEntity) | PB-AWS-IAM-CreateAccessKey-01 | `adminJoe` → AccessDenied, `AdminJoe` → NoSuchEntity (bypass confirmed) |
| 3 | S3 enumeration + data theft | `ListBuckets` (+ `ListObjectsV2`, `GetObject` if data events enabled) | PB-AWS-S3-ListBuckets-01, PB-AWS-S3-ListObjectsV2-01, PB-AWS-S3-GetObject-01 | 16 buckets enumerated |
| 3 | Lambda enumeration + IP theft | `ListFunctions`, `GetFunction`, `ListVersionsByFunction`, `GetPolicy`, `ListAliases`, `ListTags`, `ListEventSourceMappings` | PB-AWS-Lambda-* | 7 Lambda APIs in 2 seconds, env var `DB_PASS` exposed |
| 4 | CloudTrail disabled | `DescribeTrails`, `StopLogging` | PB-AWS-CloudTrail-DescribeTrails-01, PB-AWS-CloudTrail-StopLogging-01 | **BLIND WINDOW STARTS** |
| 5 | Terraform state credential theft | `GetObject` on `terraform.tfstate` | PB-AWS-S3-GetObject-01 | S3 data event (if enabled) — IAM keys extracted from state |
| 6 | Lateral movement (bait user) | `GetCallerIdentity`, `ListUsers` (AccessDenied) | PB-AWS-STS-GetCallerIdentity-01, PB-AWS-IAM-ListUsers-01 | New principal from same attacker IP, zero-permission user |
| 6 | SecretsManager harvest | `ListSecrets`, `GetSecretValue` | PB-AWS-SecretsManager-ListSecrets-01, PB-AWS-SecretsManager-GetSecretValue-01 | `prod/database/master_credentials` stolen **during blind window** |

### 4.2: Full Timeline Query

**CloudTrail LookupEvents:**

```bash
aws cloudtrail lookup-events \
  --start-time "<INCIDENT_START_TIME>" \
  --end-time "<INCIDENT_END_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(
       (.userIdentity.arn // "" | contains("<COMPROMISED_ROLE_NAME>")) or
       (.userIdentity.arn // "" | contains("<LATERAL_USERNAME>")) or
       .sourceIPAddress == "<ATTACKER_SOURCE_IP>" or
       .sourceIPAddress == "<ATTACKER_SOURCE_IPV6>"
     )] |
    sort_by(.eventTime) |
    .[] | {eventTime, eventName, eventSource,
           sourceIP: .sourceIPAddress, errorCode,
           principal: .userIdentity.arn}'
```

**Athena (for full S3 data events if enabled):**

```sql
SELECT
  eventTime, eventName, eventSource, sourceIPAddress, errorCode,
  userIdentity.arn AS principalArn,
  JSON_EXTRACT_SCALAR(requestParameters, '$.bucketName') AS bucket,
  JSON_EXTRACT_SCALAR(requestParameters, '$.key') AS objectKey
FROM cloudtrail_logs
WHERE eventTime BETWEEN '<INCIDENT_START_TIME>' AND '<INCIDENT_END_TIME>'
  AND (
    userIdentity.arn LIKE '%<COMPROMISED_ROLE_NAME>%'
    OR userIdentity.arn LIKE '%<LATERAL_USERNAME>%'
    OR sourceIPAddress IN ('<ATTACKER_SOURCE_IP>', '<ATTACKER_SOURCE_IPV6>')
  )
ORDER BY eventTime ASC;
```

### 4.3: Assess Impact

| Asset Category | Check | Compromised If |
|---|---|---|
| EC2 Role Credentials | Role creds from non-instance IP | Always — IMDSv1 theft confirmed |
| IAM Privilege Boundary | `CreateAccessKey` for `AdminJoe` returned NoSuchEntity (not AccessDenied) | Boundary bypass confirmed — case-sensitive condition is flawed |
| S3 Data | `ListBuckets` succeeded | Assume all enumerated buckets were read (16 buckets in emulation) |
| Lambda Source Code | `GetFunction` returned 200 | Pre-signed download URL generated — code is exfiltrated |
| Lambda Env Vars | `ListVersionsByFunction` returned 200 | `DB_PASS` and other env vars exposed |
| CloudTrail | `StopLogging` returned 200 | Blind window — unknown activity occurred |
| Terraform State | `GetObject` on `*.tfstate` | IAM keys embedded in state are stolen |
| Lateral Movement | `GetCallerIdentity` from different principal at attacker IP | Second credential set confirmed compromised |
| SecretsManager | `GetSecretValue` succeeded | `prod/database/master_credentials` stolen — db_admin credentials compromised |

### 4.4: Blind Window Investigation

After `StopLogging` at 12:12:25, the trail stops delivering to S3. But `LookupEvents` still works:

```bash
aws cloudtrail lookup-events \
  --start-time "<STOP_LOGGING_TIME>" \
  --end-time "<INCIDENT_END_TIME>" \
  --region <REGION> --max-results 50 --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.sourceIPAddress != "AWS Internal")] |
    sort_by(.eventTime) |
    .[] | {eventTime, eventName, sourceIP: .sourceIPAddress,
           principal: .userIdentity.arn, errorCode}'
```

**v2-specific:** In the emulation, the attacker executed `GetCallerIdentity` (lateral movement), `ListUsers` (lateral recon), `ListSecrets`, and `GetSecretValue` AFTER disabling CloudTrail. The SecretsManager theft was deliberately timed for the blind window.

### 4.5: S3 Data Event Gap

**Critical finding from emulation:** S3 `ListObjectsV2` and `GetObject` calls do NOT appear in CloudTrail management event trails. The attacker enumerated 16 buckets and exfiltrated objects from 5 scarleteel-prefixed buckets, but none of these appear as events.

To detect S3 data exfiltration, you need S3 data event logging:

```bash
aws cloudtrail put-event-selectors \
  --trail-name <TRAIL_NAME> \
  --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3"]}]}]' \
  --region <REGION> --profile <IR_PROFILE>
```

Without this, S3 data theft is invisible in CloudTrail. `ListBuckets` is a management event and IS logged — use it as a proxy signal.

### 4.6: Evidence Preservation

```bash
# Forensic bucket
aws s3 mb s3://forensic-scarleteel-v2-<INCIDENT_ID> --region <REGION> --profile <IR_PROFILE>
aws s3api put-public-access-block \
  --bucket forensic-scarleteel-v2-<INCIDENT_ID> \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
  --profile <IR_PROFILE>

# Snapshot the compromised EC2 instance (preserves miner artifacts, bash history)
aws ec2 create-image \
  --instance-id <COMPROMISED_INSTANCE_ID> \
  --name "forensic-scarleteel-v2-<INCIDENT_ID>" \
  --no-reboot --profile <IR_PROFILE>

# Export CloudTrail events
aws cloudtrail lookup-events \
  --start-time "<INCIDENT_START_TIME>" \
  --end-time "<INCIDENT_END_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> > /tmp/scarleteel_v2_cloudtrail.json
aws s3 cp /tmp/scarleteel_v2_cloudtrail.json \
  s3://forensic-scarleteel-v2-<INCIDENT_ID>/cloudtrail/ --profile <IR_PROFILE>
```

---

## 5. Recovery & Hardening

### 5.1: Sanitize (Immediate)

| Action | Command |
|--------|---------|
| Rotate compromised EC2 role | Terminate old instance, launch new with IMDSv2 enforced |
| Delete lateral movement access keys | `aws iam delete-access-key --user-name <LATERAL_USERNAME> --access-key-id <KEY_ID>` |
| Rotate Lambda env var secrets | `aws lambda update-function-configuration --function-name <FUNCTION_NAME> --environment "Variables={DB_PASS=<NEW_PASSWORD>}"` |
| **Rotate SecretsManager secrets** | `aws secretsmanager rotate-secret --secret-id prod/database/master_credentials` + change password at the database |
| Rotate database credentials | Change password at database layer for `db_admin` user |
| Delete Terraform state with embedded keys | Remove plaintext IAM keys from `.tfstate`, re-provision with dynamic credentials |
| **Fix permission boundary** | Change `admin*` deny condition to case-insensitive: `"StringLikeIfExists": {"iam:PassedToService": ...}` or use `ForAnyValue:StringLike` with both cases |

### 5.2: Restore

1. Deploy new EC2 instance with IMDSv2 enforced (`HttpTokens: required`, `HttpPutResponseHopLimit: 1`)
2. Redeploy containerized application with command injection patched
3. Verify CloudTrail is logging to a write-protected S3 bucket
4. Confirm all rotated credentials are functional (Lambda, database, SecretsManager)
5. Verify SecretsManager automatic rotation is enabled

### 5.3: Harden (The "Never Again" Fixes)

| Fix | Implementation | Priority |
|-----|---------------|----------|
| **Enforce IMDSv2 account-wide** | SCP denying `ec2:RunInstances` unless `ec2:MetadataHttpTokens == "required"` | P1 |
| **Prevent CloudTrail disabling** | SCP denying `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail` for all non-SecurityAdmin roles | P1 |
| **Block IAM writes from compute** | SCP denying `iam:Create*`, `iam:Delete*`, `iam:Attach*`, `iam:Put*` when `aws:PrincipalArn` matches EC2/Lambda roles | P1 |
| **Fix permission boundary case sensitivity** | Use `StringLike` with wildcard patterns covering both cases, or use `StringEqualsIgnoreCase` (if available) | P1 |
| **Scope EC2 role permissions** | Remove `s3:ListAllMyBuckets`, `lambda:*`, `cloudtrail:*`, `secretsmanager:*` from compute roles. Use resource-specific ARNs. | P1 |
| **Enable GuardDuty** | Detects `InstanceCredentialExfiltration.OutsideAWS` | P2 |
| **Move Lambda secrets to SecretsManager** | Remove env vars, fetch at runtime with scoped IAM | P2 |
| **Encrypt Terraform state** | SSE-KMS on state bucket, use `sensitive` outputs, dynamic backend credentials | P2 |
| **Enable S3 data event logging** | `aws cloudtrail put-event-selectors` to capture `GetObject`/`PutObject` | P2 |
| **SecretsManager resource policies** | Explicit principal allow-lists on each secret | P2 |
| **Enable automatic secret rotation** | 30-day max rotation interval on all production secrets | P2 |
| **EventBridge auto-remediation** | Rule: on `StopLogging` → Lambda auto-`StartLogging` | P2 |
| **VPC Flow Logs** | Detect C2 communication, mining pool connections, non-standard S3 endpoints | P3 |
| **WAF on public containers** | Block command injection patterns at the network edge | P3 |

### 5.4: Verify

```bash
# Confirm IMDSv2 enforced
aws ec2 describe-instances --instance-ids <NEW_INSTANCE_ID> \
  --query "Reservations[0].Instances[0].MetadataOptions" --output json

# Confirm CloudTrail is logging
aws cloudtrail get-trail-status --name <TRAIL_NAME> --region <REGION>

# Confirm SecretsManager rotation
aws secretsmanager describe-secret --secret-id prod/database/master_credentials \
  --region <REGION> | jq '{LastRotatedDate, RotationEnabled}'

# Confirm SCP is active
aws organizations list-policies --filter SERVICE_CONTROL_POLICY

# Test: attempt StopLogging from non-admin role (should be denied)
aws cloudtrail stop-logging --name <TRAIL_NAME> --profile <TEST_NON_ADMIN_PROFILE>
# Expected: AccessDeniedException
```

### 5.5: Post-Mortem Detection Gap Analysis

| Gap | Impact | Remediation |
|-----|--------|-------------|
| IMDSv1 enabled | Credential theft invisible to CloudTrail | Enforce IMDSv2 via SCP |
| No alert on `StopLogging` | Attacker blinded audit trail for 40+ seconds before secret theft | CloudWatch alarm + EventBridge auto-remediation |
| S3 data events not logged | Cannot prove scope of data exfiltration (16 buckets enumerated, 0 data events captured) | Enable S3 data event logging |
| No GuardDuty | `InstanceCredentialExfiltration` not detected | Enable GuardDuty |
| Over-privileged EC2 role | Single credential gave access to IAM, S3, Lambda, CloudTrail, SecretsManager | Least-privilege role scoped to specific resources |
| Case-sensitive permission boundary | `AdminJoe` bypassed `admin*` deny condition | Case-insensitive condition or broader pattern |
| Plaintext credentials in Terraform state | Lateral movement via `.tfstate` | Encrypt state, use dynamic credentials |
| Lambda secrets in env vars | `DB_PASS` exposed via `ListVersionsByFunction` | Migrate to SecretsManager with scoped access |
| No SecretsManager resource policies | Any role with `secretsmanager:GetSecretValue` can read any secret | Per-secret resource policies |
| No secret rotation | Stolen credentials remain valid indefinitely | Automatic rotation with 30-day max interval |

---

## IOC Reference

| IOC Type | Value | Context |
|----------|-------|---------|
| IPv4 | `<ATTACKER_SOURCE_IP>` | IAM, Lambda, CloudTrail, S3 calls from stolen creds |
| IPv6 | `<ATTACKER_SOURCE_IPV6>` | SecretsManager calls from stolen creds |
| IP | `<INSTANCE_PUBLIC_IP>` | Compromised EC2 host |
| Instance | `<COMPROMISED_INSTANCE_ID>` | Container host with IMDSv1 |
| IAM Role | `<COMPROMISED_ROLE_NAME>` | Over-privileged EC2 instance role |
| IAM User | `ScarleteelBackdoor` | Attacker-created + deleted backdoor user (evidence destruction) |
| IAM User | `<LATERAL_USERNAME>` | Lateral movement target from Terraform state |
| CloudTrail | `<TRAIL_NAME>` | Trail disabled by attacker |
| Secret | `prod/database/master_credentials` | Production DB creds stolen via SecretsManager |
| Systemd | `containered.service` | XMRig miner masquerading as containerd |
| File | `/root/.configure/containerd` | Miner binary path |
| File | `/root/.configure/pandora` | Pandora (Mirai) DDoS bot |
| File | `/tmp/config_background.json` | XMRig pool config |
| Domain | `hb.bizmrg.com` | Russian S3 endpoint for CloudTrail-evading exfil |
| Pool | `pool.c3pool.com:13333` | XMRig mining pool |
| Wallet | `43Lfq18TycJHVR3AMews5C9f...` | Monero mining payout address |
| C2 IP | `45.9.148.221` | Primary C2 server |
| C2 IP | `175.102.182.6` | Secondary C2 server |
| Exfil | `5.39.93.71:9999` | termbin exfiltration endpoint |

---

## Detection Rules (Sigma Format)

### Rule 1: SCARLETEEL 2.0 — CreateUser + DeleteUser Rapid Pair from EC2 Role

```yaml
title: AWS IAM Create-Delete User Pair from EC2 Role (SCARLETEEL 2.0)
id: a1b2c3d4-0001-v2-0001-scarleteel2026
status: experimental
description: >
  Detects the SCARLETEEL 2.0 privilege escalation probe where an EC2 instance
  role creates and immediately deletes an IAM user within seconds. This pattern
  indicates automated tooling testing IAM write permissions before proceeding
  with the attack chain.
references:
  - https://sysdig.com/blog/scarleteel-2-0/
author: MayaTrail
date: 2026/04/11
tags:
  - attack.persistence
  - attack.t1136.003
  - attack.defense_evasion
  - attack.t1070.004
logsource:
  product: aws
  service: cloudtrail
detection:
  create:
    eventSource: iam.amazonaws.com
    eventName: CreateUser
    userIdentity.type: AssumedRole
    userIdentity.principalId|contains: ':i-'
  delete:
    eventSource: iam.amazonaws.com
    eventName: DeleteUser
    userIdentity.type: AssumedRole
    userIdentity.principalId|contains: ':i-'
  condition: create and delete | near create delete
  timeframe: 5m
falsepositives:
  - None expected — EC2 roles should never create or delete IAM users
level: critical
```

### Rule 2: SCARLETEEL 2.0 — SecretsManager Harvest After StopLogging

```yaml
title: AWS SecretsManager Access After CloudTrail Disabled (SCARLETEEL 2.0)
id: a1b2c3d4-0002-v2-0002-scarleteel2026
status: experimental
description: >
  Detects the SCARLETEEL 2.0 pattern where GetSecretValue occurs after
  StopLogging from the same EC2 instance role. The attacker deliberately
  blinds CloudTrail before exfiltrating production secrets.
references:
  - https://sysdig.com/blog/scarleteel-2-0/
author: MayaTrail
date: 2026/04/11
tags:
  - attack.defense_evasion
  - attack.t1562.008
  - attack.credential_access
  - attack.t1528
logsource:
  product: aws
  service: cloudtrail
detection:
  stoplogging:
    eventSource: cloudtrail.amazonaws.com
    eventName: StopLogging
    userIdentity.type: AssumedRole
  secretaccess:
    eventSource: secretsmanager.amazonaws.com
    eventName:
      - GetSecretValue
      - ListSecrets
    userIdentity.type: AssumedRole
  condition: stoplogging and secretaccess | near stoplogging secretaccess
  timeframe: 10m
falsepositives:
  - Scheduled CloudTrail maintenance coinciding with application secret rotation (extremely rare)
level: critical
```

### Rule 3: SCARLETEEL 2.0 — Permission Boundary Bypass via Case Sensitivity

```yaml
title: AWS IAM CreateAccessKey with Mixed-Case Username (Permission Boundary Bypass)
id: a1b2c3d4-0003-v2-0003-scarleteel2026
status: experimental
description: >
  Detects CreateAccessKey attempts where one call is denied and a subsequent
  call for a different-cased username succeeds or returns NoSuchEntity (vs
  AccessDenied). This indicates an attacker probing case-sensitive permission
  boundary conditions. In SCARLETEEL 2.0, 'adminJoe' was denied but 'AdminJoe'
  bypassed the boundary.
references:
  - https://sysdig.com/blog/scarleteel-2-0/
author: MayaTrail
date: 2026/04/11
tags:
  - attack.privilege_escalation
  - attack.t1098.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreateAccessKey
    userIdentity.type: AssumedRole
    userIdentity.principalId|contains: ':i-'
  condition: selection | count() by userIdentity.arn > 1
  timeframe: 5m
falsepositives:
  - Automated key rotation from EC2-hosted tools (should not use instance roles for IAM key management)
level: high
```

---

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic | Kill Chain Phase |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access | Phase 1 |
| T1552.005 | Cloud Instance Metadata API | Credential Access | Phase 1 |
| T1496 | Resource Hijacking (Cryptomining) | Impact | Phase 1 (host) |
| T1036.004 | Masquerade Task or Service | Defense Evasion | Phase 1 (host) |
| T1562.004 | Impair Defenses: Disable System Firewall | Defense Evasion | Phase 1 (host) |
| T1070.003 | Indicator Removal: Clear Command History | Defense Evasion | Phase 1 (host) |
| T1087.004 | Account Discovery: Cloud Account | Discovery | Phase 2, 6 |
| T1136.003 | Create Account: Cloud Account | Persistence | Phase 2 |
| T1070.004 | Indicator Removal: File Deletion | Defense Evasion | Phase 2 (DeleteUser) |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Persistence | Phase 2 |
| T1526 | Cloud Service Discovery | Discovery | Phase 3 |
| T1530 | Data from Cloud Storage Object | Collection | Phase 3 |
| T1005 | Data from Local System | Collection | Phase 3 |
| T1552.001 | Unsecured Credentials: Credentials in Files | Credential Access | Phase 3, 5 |
| T1562.008 | Impair Defenses: Disable Cloud Logs | Defense Evasion | Phase 4 |
| T1078.004 | Valid Accounts: Cloud Accounts | Lateral Movement | Phase 5, 6 |
| T1528 | Steal Application Access Token | Credential Access | Phase 6 |
| T1531 | Account Access Removal | Impact | Phase 2 (DeleteUser) |

---

## Verified Against Emulation Logs

Validated against CloudTrail events from SCARLETEEL 2.0 emulation on 2026-04-11:

| Time (UTC) | Phase | Event | Principal | Source IP | Result |
|---|---|---|---|---|---|
| 12:10:36 | P2 | `ListUsers` | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | OK |
| 12:10:39 | P2 | `ListRoles` | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | OK |
| 12:10:42 | P2 | `CreateUser` (ScarleteelBackdoor) | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | OK |
| 12:10:42 | P2 | `DeleteUser` (ScarleteelBackdoor) | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | OK |
| 12:10:47 | P2 | `CreateAccessKey` (adminJoe) | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | **AccessDenied** |
| 12:10:52 | P2 | `CreateAccessKey` (AdminJoe) | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | **NoSuchEntity** |
| 12:11:00 | P3 | `ListBuckets` | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | OK |
| 12:12:07 | P3 | `ListFunctions` | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | OK |
| 12:12:07 | P3 | `GetFunction` | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | OK |
| 12:12:07 | P3 | `ListVersionsByFunction` | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | OK |
| 12:12:08 | P3 | `ListTags` | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | OK |
| 12:12:08 | P3 | `ListAliases` | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | OK |
| 12:12:08 | P3 | `GetPolicy` | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | ResourceNotFound |
| 12:12:09 | P3 | `ListEventSourceMappings` | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | OK |
| 12:12:25 | P4 | `DescribeTrails` | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | OK |
| 12:12:25 | **P4** | **`StopLogging`** | `vuln-ec2-role/i-0f949...` | 122.162.145.217 | **OK** |
| 12:12:53 | P6 | `GetCallerIdentity` | `bait-user-1d2e775` | 122.162.145.217 | OK |
| 12:13:01 | P6 | `ListUsers` | `bait-user-1d2e775` | 122.162.145.217 | **AccessDenied** |
| 12:13:05 | P6 | `ListSecrets` | `vuln-ec2-role/i-0f949...` | 2401:4900:...a7ad | OK |
| 12:13:05 | P6 | `GetSecretValue` | `vuln-ec2-role/i-0f949...` | 2401:4900:...a7ad | OK |

**Total attack duration:** 2 minutes 29 seconds (12:10:36 → 12:13:05).
**Instance IP:** 13.220.122.208 | **Attacker IPv4:** 122.162.145.217 | **Attacker IPv6:** 2401:4900:1c88:3f9e:551b:c1cb:db2c:a7ad
**Key v2 findings:** CreateUser+DeleteUser same-second pair, AdminJoe case bypass confirmed, SecretsManager theft timed for blind window, dual IPv4/IPv6 source IPs.
