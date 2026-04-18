---
id: aws-campaign-scarleteel
campaign: SCARLETEEL
required_inputs:
  - INCIDENT_START_TIME
  - ACCOUNT_ID
  - REGION
  - COMPROMISED_INSTANCE_ID
provided_outputs:
  - ATTACKER_SOURCE_IP
  - COMPROMISED_ROLE_ARN
  - LATERAL_USER_ARN
  - EXFILTRATED_ASSETS
  - BLIND_WINDOW_START
  - BLIND_WINDOW_END
chained_playbooks:
  - PB-AWS-IAM-CreateUser-01
  - PB-AWS-IAM-CreateAccessKey-01
  - PB-AWS-IAM-ListUsers-01
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
---

# Playbook: SCARLETEEL Campaign Response

**ID:** PB-AWS-CAMPAIGN-SCARLETEEL-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

| Field | Value |
|-------|-------|
| **Playbook Name** | SCARLETEEL Cloud Infrastructure Compromise |
| **Playbook ID** | PB-AWS-CAMPAIGN-SCARLETEEL-01 |
| **Version** | 1.0 |
| **Type** | Campaign-Level (chains per-API-call playbooks) |
| **Scenario** | Multi-phase cloud attack: container RCE, IMDSv1 credential theft, IAM reconnaissance, S3/Lambda data exfiltration, CloudTrail defense evasion, Terraform state credential theft, and lateral movement |
| **Threat Actor** | SCARLETEEL (Sysdig classification) |
| **Trigger** | Any TWO or more of: (1) `StopLogging` event, (2) EC2 role credentials used from non-instance IP, (3) `CreateUser`/`CreateAccessKey` from compute principal, (4) `ListFunctions` + `GetFunction` burst from EC2 role |
| **MITRE ATT&CK Tactics** | Initial Access, Execution, Credential Access, Discovery, Collection, Defense Evasion, Lateral Movement, Impact |
| **Source Intelligence** | [Sysdig SCARLETEEL 2.0](https://www.sysdig.com/blog/scarleteel-2-0/) |

### SLA

| Severity | Acknowledge | Contain | Resolve |
|---|---|---|---|
| CRITICAL | 5 minutes | 30 minutes | 4 hours |
| HIGH | 15 minutes | 1 hour | 8 hours |
| MEDIUM | 2 hours | 8 hours | 24 hours |

**Campaign-specific SLA overrides:** Re-enable CloudTrail logging within 5 minutes of `StopLogging` detection regardless of severity classification.

### Severity Matrix

| Level | Condition | Action |
|-------|-----------|--------|
| **CRITICAL** | `StopLogging` observed OR EC2 role creds used from non-instance IP OR `CreateUser` from compute role | Wake CISO & Legal immediately. Page oncall. Begin containment within 5 minutes. |
| **HIGH** | Lambda enumeration burst (5+ Lambda read APIs in 30s from same principal) OR `ListBuckets` from EC2 role followed by `GetObject` on 3+ buckets | Immediate IR team response. Begin triage within 15 minutes. |
| **MEDIUM** | Isolated `ListUsers` or `ListBuckets` from EC2 role with no follow-on activity within 10 minutes | Next-business-day triage. Investigate whether role permissions are appropriate. |

### Prerequisites

- **Roles:** `IncidentResponseRole` with read access to CloudTrail, IAM, EC2, S3, Lambda, CloudWatch
- **Logs:** CloudTrail (management events minimum; S3 data events recommended), VPC Flow Logs
- **Tools:** AWS CLI, Athena, boto3
- **Services:** GuardDuty enabled (detects `InstanceCredentialExfiltration.OutsideAWS`)

### Stakeholders

| Role | When to Notify |
|------|----------------|
| Security Oncall | Immediately on CRITICAL trigger |
| CISO | Within 15 minutes if credential exfiltration confirmed |
| Legal | If PII/customer data in exfiltrated S3 objects or Lambda env vars |
| Engineering Lead | If production Lambda functions or secrets compromised |
| PR/Comms | If customer data breach confirmed |

### Compliance

- GDPR 72-hour notification clock starts when credential exfiltration is confirmed
- SOC 2 incident response documentation required
- PCI DSS if payment data in exfiltrated objects

### Related Playbooks

| Playbook ID | API Call | Kill Chain Phase |
|---|---|---|
| PB-AWS-IAM-CreateUser-01 | `iam:CreateUser` | Phase 2 — Persistence |
| PB-AWS-IAM-CreateAccessKey-01 | `iam:CreateAccessKey` | Phase 2 — Persistence |
| PB-AWS-IAM-ListUsers-01 | `iam:ListUsers` | Phase 2, 6 — Discovery |
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

The investigation begins from whichever alert fired first. Extract the pivot fields (principal, source IP, timestamp) from the triggering event.

**If the trigger is `StopLogging` (highest confidence):**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    .Events[] | .CloudTrailEvent | fromjson |
    {eventTime, callerArn: .userIdentity.arn, sourceIP: .sourceIPAddress, userAgent, trail: .requestParameters.name}'
```

**If the trigger is `CreateUser`/`CreateAccessKey` from EC2 role:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    .Events[] | .CloudTrailEvent | fromjson |
    select(.userIdentity.principalId | contains(":i-")) |
    {eventTime, callerArn: .userIdentity.arn, sourceIP: .sourceIPAddress, errorCode}'
```

**If the trigger is Lambda enumeration burst:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=lambda.amazonaws.com \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.userIdentity.principalId | contains(":i-"))] |
    group_by(.userIdentity.arn) |
    map(select(length > 5)) |
    .[] | {principal: .[0].userIdentity.arn, sourceIP: .[0].sourceIPAddress, count: length, events: [.[].eventName]}'
```

**From any trigger, extract these three pivot fields:**

| Field | Where to find it | What it tells you |
|-------|-----------------|-------------------|
| `userIdentity.arn` | Triggering event | The compromised principal |
| `sourceIPAddress` | Triggering event | Attacker IP vs. instance IP — confirms credential exfiltration |
| `eventTime` | Triggering event | Anchors the timeline for backward/forward pivots |

**Confirm credential exfiltration by comparing source IP to instance IP:**

```bash
aws ec2 describe-instances \
  --instance-ids <COMPROMISED_INSTANCE_ID> \
  --query "Reservations[0].Instances[0].[PublicIpAddress,PrivateIpAddress]" \
  --output text --profile <IR_PROFILE>
```

**Key Signal:** If the source IP from the alert ≠ the instance's IP, credential exfiltration is confirmed.

### Step 2.1b: Source IP Correlation

Immediately check if other principals were used from the attacker's source IP. This catches lateral movement early in triage.

```bash
aws cloudtrail lookup-events \
  --start-time "<INCIDENT_START_TIME>" \
  --end-time "<INCIDENT_END_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.sourceIPAddress == "<ATTACKER_SOURCE_IP>")] |
    group_by(.userIdentity.arn) |
    map({principal: .[0].userIdentity.arn, count: length, first: .[0].eventTime, last: .[-1].eventTime})'
```

If multiple principals appear from the same IP, the attacker has obtained additional credential sets — likely through credential theft during the attack (e.g., Terraform state files, Lambda environment variables, SecretsManager secrets).

### Step 2.2: Confirm IMDSv1 as Attack Vector

```bash
aws ec2 describe-instances \
  --instance-ids <COMPROMISED_INSTANCE_ID> \
  --query "Reservations[0].Instances[0].MetadataOptions" \
  --output json --profile <IR_PROFILE>
```

If `HttpTokens: "optional"` and `HttpPutResponseHopLimit >= 2`, the container could steal credentials via IMDSv1.

### Step 2.3: Decision Gate

- IF `sourceIPAddress` != instance IP AND `StopLogging` observed → **CONFIRMED SCARLETEEL. Go to Containment.**
- IF `sourceIPAddress` != instance IP but no `StopLogging` → **LIKELY compromise. Go to Containment L1, continue Investigation.**
- IF `sourceIPAddress` == instance IP AND calls are only `ListBuckets`/`ListFunctions` → **Possible misconfigured application. Investigate before containment.**
- IF all calls are from known admin IPs with MFA → **Likely infrastructure automation. Mark False Positive, verify with team.**

---

## 3. Containment Strategy (Graduated Response)

### Priority 0: Re-enable CloudTrail (if disabled)

```bash
aws cloudtrail start-logging --name <TRAIL_NAME> --region <REGION> --profile <IR_PROFILE>
```

**Rollback:** N/A — this is always the correct action.

### Graduated Containment

| Level | Condition | Action | Rollback |
|-------|-----------|--------|----------|
| **L1 (Soft)** | Suspected credential theft, investigation ongoing | Revoke EC2 role sessions issued before incident: `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name EmergencyRevokeOldSessions --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<INCIDENT_START_TIME>"}}}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name EmergencyRevokeOldSessions` |
| **L2 (Hard)** | Confirmed exfiltration or `StopLogging` | Deny-all on the role: `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name EmergencyDenyAll --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name EmergencyDenyAll` |
| **L2 (Hard)** | Lateral movement creds identified | Deactivate stolen access keys: `aws iam update-access-key --user-name <LATERAL_USERNAME> --access-key-id <KEY_ID> --status Inactive` | `aws iam update-access-key --user-name <LATERAL_USERNAME> --access-key-id <KEY_ID> --status Active` |
| **L3 (Nuclear)** | Active data exfiltration or production secrets stolen | Isolate EC2: `aws ec2 modify-instance-attribute --instance-id <COMPROMISED_INSTANCE_ID> --groups <QUARANTINE_SG_ID>` AND Stop instance: `aws ec2 stop-instances --instance-ids <COMPROMISED_INSTANCE_ID>` | `aws ec2 modify-instance-attribute --instance-id <COMPROMISED_INSTANCE_ID> --groups <ORIGINAL_SG_ID>` AND `aws ec2 start-instances --instance-ids <COMPROMISED_INSTANCE_ID>` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:

```bash
aws ec2 describe-tags \
  --filters "Name=resource-id,Values=<COMPROMISED_INSTANCE_ID>" "Name=key,Values=Critical-Production-App" \
  --output text --profile <IR_PROFILE>
```

If tagged, escalate to Engineering Lead before proceeding. Use L1 only until approval.

---

## 4. Investigation & Forensics

### 4.1: Reconstruct the Kill Chain

Execute per-API-call playbooks in attack order. Each playbook provides outputs that feed the next:

| Phase | Attack Step | Playbook | Key Evidence |
|-------|------------|----------|--------------|
| 1 | Container RCE + IMDSv1 theft | (No CloudTrail — data plane) | VPC Flow Logs to port 8080, EC2 console output |
| 2 | IAM recon + priv esc attempt | PB-AWS-IAM-CreateUser-01, PB-AWS-IAM-CreateAccessKey-01, PB-AWS-IAM-ListUsers-01 | `CreateUser`/`CreateAccessKey` from `i-*` principal |
| 3 | S3 enumeration + data theft | PB-AWS-S3-ListBuckets-01, PB-AWS-S3-ListObjectsV2-01, PB-AWS-S3-GetObject-01 | `ListBuckets` from compute role |
| 3 | Lambda source code theft | PB-AWS-Lambda-ListFunctions-01, PB-AWS-Lambda-GetFunction-01, PB-AWS-Lambda-ListVersionsByFunction-01 | `GetFunction` returns pre-signed download URL |
| 3 | Lambda recon | PB-AWS-Lambda-GetPolicy-01, PB-AWS-Lambda-ListAliases-01, PB-AWS-Lambda-ListTags-01, PB-AWS-Lambda-ListEventSourceMappings-01 | Burst of 4+ Lambda read APIs in <5s |
| 4 | CloudTrail disabled | PB-AWS-CloudTrail-DescribeTrails-01, PB-AWS-CloudTrail-StopLogging-01 | `StopLogging` — all evidence after this is from `LookupEvents` only |
| 5 | Terraform state theft | PB-AWS-S3-GetObject-01 (on `terraform.tfstate`) | S3 data event (if enabled) |
| 6 | Lateral movement | PB-AWS-STS-GetCallerIdentity-01, PB-AWS-IAM-ListUsers-01 | New principal appears from same attacker IP |

### 4.2: Full Timeline Query (Athena)

```sql
SELECT
  eventTime,
  eventName,
  eventSource,
  sourceIPAddress,
  errorCode,
  userIdentity.arn AS principalArn,
  requestParameters
FROM cloudtrail_logs
WHERE eventTime BETWEEN '<INCIDENT_START_TIME>' AND '<INCIDENT_END_TIME>'
  AND (
    userIdentity.arn LIKE '%<COMPROMISED_ROLE_NAME>%'
    OR userIdentity.arn LIKE '%<LATERAL_USERNAME>%'
    OR sourceIPAddress = '<ATTACKER_SOURCE_IP>'
  )
ORDER BY eventTime ASC;
```

### 4.3: Assess Impact

| Asset Category | Check Command | Compromised If |
|---|---|---|
| EC2 Role Credentials | Role creds seen from non-instance IP | Always — IMDSv1 theft confirmed |
| S3 Data | `ListBuckets` succeeded from attacker IP | Assume all enumerated buckets were read |
| Lambda Source Code | `GetFunction` returned 200 | Pre-signed URL was generated — code is downloadable |
| Lambda Env Vars | `ListVersionsByFunction` returned 200 | Environment variables (secrets) are exposed |
| CloudTrail | `StopLogging` returned 200 | Blind window — unknown activity occurred |
| Terraform State | `GetObject` on `*.tfstate` | IAM keys embedded in state are stolen |
| Lateral Movement | `GetCallerIdentity` from different principal at attacker IP | Second set of credentials confirmed compromised |
| SecretsManager | `GetSecretValue` from compute role | Production secrets stolen |

### 4.4: Blind Window Investigation

After `StopLogging`, CloudTrail stops delivering events to S3. However, `LookupEvents` API still works (90-day retention).

```bash
# Query the blind window
aws cloudtrail lookup-events \
  --start-time "<STOP_LOGGING_TIME>" \
  --end-time "<INCIDENT_END_TIME>" \
  --region <REGION> --max-results 50 --output json --profile <IR_PROFILE>
```

### 4.5: Evidence Preservation

```bash
# Create forensic bucket
aws s3 mb s3://forensic-evidence-scarleteel-<INCIDENT_ID> --region <REGION> --profile <IR_PROFILE>

# Block public access
aws s3api put-public-access-block \
  --bucket forensic-evidence-scarleteel-<INCIDENT_ID> \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
  --profile <IR_PROFILE>

# Snapshot the compromised EC2 instance
aws ec2 create-image \
  --instance-id <COMPROMISED_INSTANCE_ID> \
  --name "forensic-scarleteel-<INCIDENT_ID>" \
  --no-reboot --profile <IR_PROFILE>

# Export CloudTrail events
aws cloudtrail lookup-events \
  --start-time "<INCIDENT_START_TIME>" \
  --end-time "<INCIDENT_END_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> > /tmp/scarleteel_cloudtrail.json

aws s3 cp /tmp/scarleteel_cloudtrail.json \
  s3://forensic-evidence-scarleteel-<INCIDENT_ID>/cloudtrail/ --profile <IR_PROFILE>
```

---

## 5. Recovery & Hardening

### 5.1: Sanitize (Immediate)

| Action | Command |
|--------|---------|
| Rotate compromised EC2 role (new instance) | Terminate old instance, launch new with IMDSv2 enforced |
| Delete lateral movement access keys | `aws iam delete-access-key --user-name <LATERAL_USERNAME> --access-key-id <KEY_ID>` |
| Rotate Lambda env var secrets | `aws lambda update-function-configuration --function-name <FUNCTION_NAME> --environment "Variables={DB_PASS=<NEW_ROTATED_PASSWORD>}"` |
| Rotate database credentials | Change password at the database layer, update all referencing services |
| Rotate SecretsManager secrets | `aws secretsmanager rotate-secret --secret-id <SECRET_ID>` |
| Delete Terraform state with embedded keys | Remove plaintext IAM keys from `.tfstate`, re-provision with dynamic credentials |

### 5.2: Restore

1. Deploy new EC2 instance with IMDSv2 enforced (`HttpTokens: required`, `HttpPutResponseHopLimit: 1`)
2. Redeploy containerized application with command injection patched
3. Verify CloudTrail is logging to a write-protected S3 bucket
4. Confirm all rotated credentials are functional

### 5.3: Harden (The "Never Again" Fixes)

| Fix | Implementation | Priority |
|-----|---------------|----------|
| **Enforce IMDSv2 account-wide** | SCP denying `ec2:RunInstances` unless `ec2:MetadataHttpTokens == "required"` | P1 |
| **Prevent CloudTrail disabling** | SCP denying `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail` for all non-SecurityAdmin roles | P1 |
| **Block IAM writes from compute** | SCP denying `iam:Create*`, `iam:Attach*`, `iam:Put*` when `aws:PrincipalArn` matches `*:role/*ec2*` | P1 |
| **Scope EC2 role permissions** | Remove `s3:ListAllMyBuckets`, `lambda:*`, `cloudtrail:*` from compute roles. Use resource-specific ARNs. | P1 |
| **Enable GuardDuty** | `aws guardduty create-detector --enable` — detects `InstanceCredentialExfiltration.OutsideAWS` | P2 |
| **Move Lambda secrets to SecretsManager** | Remove env vars, fetch at runtime via `secretsmanager:GetSecretValue` with scoped IAM | P2 |
| **Encrypt Terraform state** | Enable SSE-KMS on state bucket, use `sensitive` outputs, consider remote backend with encryption | P2 |
| **Enable S3 data event logging** | `aws cloudtrail put-event-selectors` to capture `GetObject`/`PutObject` | P2 |
| **EventBridge auto-remediation** | Rule: on `StopLogging` event, trigger Lambda to auto-`StartLogging` | P2 |
| **VPC Flow Logs** | Enable on the VPC to detect C2 communication and non-standard S3 endpoints | P3 |
| **WAF on public containers** | Deploy AWS WAF in front of containerized applications | P3 |

### 5.4: Verify

```bash
# Confirm IMDSv2 enforced on new instance
aws ec2 describe-instances --instance-ids <NEW_INSTANCE_ID> \
  --query "Reservations[0].Instances[0].MetadataOptions" --output json

# Confirm CloudTrail is logging
aws cloudtrail get-trail-status --name <TRAIL_NAME> --region <REGION>

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
| No alert on `StopLogging` | Attacker blinded audit trail | CloudWatch alarm + EventBridge auto-remediation |
| S3 data events not logged | Cannot prove scope of data exfiltration | Enable S3 data event logging |
| No GuardDuty | `InstanceCredentialExfiltration` not detected | Enable GuardDuty |
| Over-privileged EC2 role | Single credential gave access to IAM, S3, Lambda, CloudTrail, SecretsManager | Least-privilege role scoped to specific resources |
| Plaintext credentials in Terraform state | Lateral movement via `.tfstate` | Encrypt state, use dynamic credentials |
| Lambda secrets in env vars | `DB_PASS` exposed via `ListVersionsByFunction` | Migrate to SecretsManager |

---

## IOC Reference

| IOC Type | Value | Context |
|----------|-------|---------|
| IP | `<ATTACKER_SOURCE_IP>` | All malicious API calls from stolen credentials |
| IP | `<INSTANCE_PUBLIC_IP>` | Compromised EC2 host |
| Instance | `<COMPROMISED_INSTANCE_ID>` | Container host with IMDSv1 |
| IAM Role | `<COMPROMISED_ROLE_NAME>` | Over-privileged EC2 instance role |
| IAM User | `ScarleteelBackdoor` | Attacker-created backdoor user (may be deleted) |
| IAM User | `<LATERAL_USERNAME>` | Lateral movement target from Terraform state |
| CloudTrail | `<TRAIL_NAME>` | Trail disabled by attacker |
| Systemd | `containered.service` | XMRig miner masquerading as containerd |
| File | `/root/.configure/containerd` | Miner binary path |
| File | `/root/.configure/pandora` | Pandora (Mirai) DDoS bot |
| File | `/tmp/config_background.json` | XMRig pool config |
| Domain | `hb.bizmrg.com` | Russian S3 endpoint for CloudTrail-evading exfiltration |
| Pool | `pool.c3pool.com:13333` | XMRig mining pool |
| Wallet | `43Lfq18TycJHVR3AMews5C9f...` | Monero mining payout address |

---

## Detection Rule (Sigma Format)

### Rule 1: SCARLETEEL Kill Chain — Lambda Enumeration Burst from EC2 Role

```yaml
title: AWS Lambda Enumeration Burst from EC2 Instance Role
id: a1b2c3d4-5e6f-7890-abcd-ef1234567890
status: experimental
description: >
  Detects a burst of Lambda read API calls (ListFunctions, GetFunction,
  ListVersionsByFunction, GetPolicy, ListAliases, ListTags,
  ListEventSourceMappings) from an EC2 instance role within a short window.
  In SCARLETEEL, the attacker made 7+ Lambda read calls in under 5 seconds
  from stolen EC2 instance credentials.
references:
  - https://sysdig.com/blog/scarleteel-2-0/
author: MayaTrail
date: 2026/04/05
tags:
  - attack.discovery
  - attack.t1526
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: lambda.amazonaws.com
    eventName:
      - ListFunctions20150331
      - GetFunction20150331
      - ListVersionsByFunction20150331
      - GetPolicy20150331
      - ListAliases20150331
      - ListTags20170331
      - ListEventSourceMappings20150331
    userIdentity.type: AssumedRole
  filter_approved:
    userIdentity.arn|contains:
      - 'APPROVED_LAMBDA_ADMIN_ROLE'
      - 'APPROVED_CICD_ROLE'
  condition: selection and not filter_approved | count() by userIdentity.arn > 5
  timeframe: 60s
falsepositives:
  - CI/CD pipelines performing Lambda deployment validation
  - Infrastructure-as-code drift detection (Terraform plan)
level: high
```

### Rule 2: SCARLETEEL Kill Chain — CloudTrail Disabled After Lambda Enumeration

```yaml
title: AWS CloudTrail StopLogging Following Lambda Enumeration
id: b2c3d4e5-6f70-8901-bcde-f12345678901
status: experimental
description: >
  Detects the SCARLETEEL defense evasion pattern where an attacker enumerates
  Lambda functions and then disables CloudTrail logging to cover subsequent
  activity. The correlation window captures the typical SCARLETEEL sequence:
  Lambda recon (Phase 3) followed by StopLogging (Phase 4) within 10 minutes.
references:
  - https://sysdig.com/blog/scarleteel-2-0/
author: MayaTrail
date: 2026/04/05
tags:
  - attack.defense_evasion
  - attack.t1562.008
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: cloudtrail
detection:
  phase3_lambda:
    eventSource: lambda.amazonaws.com
    eventName:
      - ListFunctions20150331
      - GetFunction20150331
    userIdentity.type: AssumedRole
  phase4_stoplogging:
    eventSource: cloudtrail.amazonaws.com
    eventName: StopLogging
  condition: phase3_lambda and phase4_stoplogging | near phase3_lambda phase4_stoplogging
  timeframe: 10m
falsepositives:
  - Scheduled CloudTrail maintenance with coincidental Lambda deployments (extremely rare)
level: critical
```

### Rule 3: SCARLETEEL Kill Chain — EC2 Credential Exfiltration with IAM Persistence

```yaml
title: AWS IAM User Creation from EC2 Instance Role (Credential Exfiltration)
id: c3d4e5f6-7081-9012-cdef-123456789012
status: experimental
description: >
  Detects the SCARLETEEL persistence pattern: an EC2 instance role (identified
  by principal containing ':i-') calls iam:CreateUser or iam:CreateAccessKey.
  EC2 instance roles should never create IAM identities. In SCARLETEEL, the
  attacker used stolen EC2 credentials from IP 122.162.144.65 to attempt
  creation of user "ScarleteelBackdoor".
references:
  - https://sysdig.com/blog/scarleteel-2-0/
author: MayaTrail
date: 2026/04/05
tags:
  - attack.persistence
  - attack.t1136.003
  - attack.credential_access
  - attack.t1552.005
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - CreateUser
      - CreateAccessKey
    userIdentity.type: AssumedRole
    userIdentity.principalId|contains: ':i-'
  condition: selection
falsepositives:
  - None expected — EC2 instance roles should never create IAM users or access keys
level: critical
```

---

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic | Kill Chain Phase |
|-------------|----------------|--------|-----------------|
| T1190 | Exploit Public-Facing Application | Initial Access | Phase 1 |
| T1552.005 | Cloud Instance Metadata API | Credential Access | Phase 1 |
| T1496 | Resource Hijacking (Cryptomining) | Impact | Phase 1 |
| T1036.004 | Masquerade Task or Service | Defense Evasion | Phase 1 (host) |
| T1136.003 | Create Account: Cloud Account | Persistence | Phase 2 |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Persistence | Phase 2 |
| T1087.004 | Account Discovery: Cloud Account | Discovery | Phase 2, 6 |
| T1526 | Cloud Service Discovery | Discovery | Phase 3 |
| T1530 | Data from Cloud Storage Object | Collection | Phase 3 |
| T1005 | Data from Local System | Collection | Phase 3 |
| T1552.001 | Unsecured Credentials: Credentials in Files | Credential Access | Phase 3, 5 |
| T1562.008 | Impair Defenses: Disable Cloud Logs | Defense Evasion | Phase 4 |
| T1078.004 | Valid Accounts: Cloud Accounts | Lateral Movement | Phase 5, 6 |
| T1528 | Steal Application Access Token | Credential Access | Phase 6 |
| T1562.004 | Impair Defenses: Disable System Firewall | Defense Evasion | Host-level |
| T1070.003 | Indicator Removal: Clear Command History | Defense Evasion | Host-level |

---

## Verified Against Emulation Logs

This playbook was validated against CloudTrail events from a live SCARLETEEL emulation run on 2026-04-05:

| Time (UTC) | Event | Principal | Source IP | Result |
|------------|-------|-----------|-----------|--------|
| 19:34:10 | `CreateUser` | `i-0aea82a9977cd62a4` | 122.162.144.65 | AccessDenied |
| 19:34:10 | `CreateAccessKey` | `i-0aea82a9977cd62a4` | 122.162.144.65 | AccessDenied |
| 19:34:11 | `ListBuckets` | `i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:32 | `ListFunctions` | `i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:32 | `GetFunction` | `i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:34 | `ListVersionsByFunction` | `i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:34 | `GetPolicy` | `i-0aea82a9977cd62a4` | 122.162.144.65 | ResourceNotFound |
| 19:34:35 | `ListEventSourceMappings` | `i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:35 | `ListTags` | `i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:35 | `ListAliases` | `i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:37 | `DescribeTrails` | `i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:37 | `StopLogging` | `i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:41 | `GetCallerIdentity` | `scarleteel-secondary-user-d039ffc` | 122.162.144.65 | OK |
| 19:34:42 | `ListUsers` | `scarleteel-secondary-user-d039ffc` | 122.162.144.65 | AccessDenied |

**Total attack duration:** 32 seconds (Phase 2 through Phase 6).
**Instance IP:** 18.206.59.212 | **Attacker IP:** 122.162.144.65 (credential exfiltration confirmed).
