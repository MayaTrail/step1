---
id: aws-iam-simulateprincipalpolicy
api_call: iam:SimulatePrincipalPolicy
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
provided_outputs:
  - ALLOWED_ACTIONS
  - ENUMERATED_SERVICES
  - SOURCE_IP
---

# Playbook: AWS Service & Permission Enumeration via IAM Policy Simulator

**ID:** PB-AWS-IAM-ENUM-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Context Wrapper

- **Scenario:** An attacker with compromised AWS credentials uses the IAM Policy Simulator (`SimulatePrincipalPolicy`) to enumerate allowed services and permissions across IAM, EC2, S3, Lambda, RDS, and KMS without triggering service-specific logs.
- **Trigger:** CloudTrail event spike for `SimulatePrincipalPolicy` calls, GuardDuty finding `Recon:IAMUser/MaliciousIPCaller`, or anomalous `sts:GetCallerIdentity` call from an unfamiliar IP.
- **Severity Matrix:**
  - **CRITICAL:** Enumeration performed by an IAM user with `iam:AttachRolePolicy` or `iam:CreateRole` permissions confirmed allowed. **Action:** Wake CISO & Engineering immediately — privilege escalation is imminent.
  - **HIGH:** Enumeration covers > 3 services AND source IP is external/unknown. **Action:** Immediate IR team response.
  - **MEDIUM:** `SimulatePrincipalPolicy` calls from a known internal IP during business hours. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled), GuardDuty enabled
  - Tools: AWS CLI, Athena, IAM Access Analyzer
- **MITRE ATT&CK Mapping:**
  - T1580: Cloud Infrastructure Discovery
  - T1087.004: Cloud Account Discovery
- **Stakeholders:** CISO, Security Engineering, Cloud Platform Team
- **SLA Target:** Triage: 30 mins
- **Compliance:** Enumeration alone does not trigger GDPR/CCPA clocks, but if followed by data access it may. Monitor for escalation.

---

## 2. Triage & Validation Logic

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who is the caller? Retrieve identity:
  ```bash
  aws sts get-caller-identity
  ```
  Is this a privileged user? Are they on vacation or offboarded?
  ```bash
  aws iam get-user --user-name <USERNAME>
  aws iam list-user-policies --user-name <USERNAME>
  aws iam list-attached-user-policies --user-name <USERNAME>
  ```

- [ ] **Asset Context:** Which services were enumerated? Check CloudTrail for the specific `ActionNames` passed to `SimulatePrincipalPolicy`:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=SimulatePrincipalPolicy \
    --max-results 20
  ```

- [ ] **Threat Intel:** Check the source IP of the `GetCallerIdentity` and `SimulatePrincipalPolicy` calls against GreyNoise/VirusTotal and the corporate VPN list.

- [ ] **Scope of Enumeration:** Did the simulation target `ResourceArns: ["*"]` (all resources) or specific ARNs? Wildcard targeting indicates broad reconnaissance.

### Step 2.2: The "Is It Real?" Decision Gate

- IF `Source_IP == Corporate_VPN` AND `User == Known_DevOps_Admin` AND `Time == Business_Hours`: **Mark False Positive & Close.**
- IF `Source_IP == External` AND `Services_Enumerated >= 3` (IAM, EC2, S3, Lambda, RDS, KMS): **Go to Containment Level 2 (IMMEDIATE).**
- IF `SimulatePrincipalPolicy` returns `Allowed` for `iam:AttachRolePolicy` OR `iam:CreateRole`: **Go to Containment Level 3 — privilege escalation is the next step.**
- IF `Source_IP == Internal` AND `Enumeration_Scope == Limited`: **Go to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | Suspicious enumeration from known user, limited scope | **Restrict Policy Simulator access:** `aws iam put-user-policy --user-name <USERNAME> --policy-name DenySimulatePolicy --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:SimulatePrincipalPolicy","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenySimulatePolicy` |
| **L2 (Hard)** | External IP, broad enumeration across 3+ services | **Deny all IAM actions for the user:** `aws iam put-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll` |
| **L3 (Nuclear)** | Enumeration confirmed `AttachRolePolicy` is allowed — escalation imminent | **Deactivate all access keys:** `aws iam list-access-keys --user-name <USERNAME>` then `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Inactive` | `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Active` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the IAM user is NOT tagged `Critical-Production-App` or a service account tied to production workloads.

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **What was enumerated?** Extract all `ActionNames` passed to `SimulatePrincipalPolicy` from CloudTrail:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=SimulatePrincipalPolicy \
    --start-time <INCIDENT_START_TIME> --end-time <END_TIME> \
    --max-results 50
  ```

- **What came back as Allowed?** Parse the `EvaluationResults` from CloudTrail event `responseElements` — any action with `EvalDecision: allowed` is a confirmed capability the attacker now knows about.

- **Lateral Movement Check:** Did the same identity call any of the services it discovered were allowed?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> --max-results 100
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, eventname, sourceipaddress, useragent,
       json_extract_scalar(requestparameters, '$.policySourceArn') AS enumerated_identity,
       json_extract_scalar(requestparameters, '$.actionNames') AS enumerated_actions
FROM cloudtrail_logs
WHERE eventname IN ('SimulatePrincipalPolicy', 'GetCallerIdentity')
  AND useridentity.arn LIKE '%<USERNAME>%'
ORDER BY eventtime ASC;
```

This maps the full reconnaissance timeline: first the attacker identifies themselves (`GetCallerIdentity`), then probes permissions (`SimulatePrincipalPolicy`) across IAM, EC2, S3, Lambda, RDS, KMS.

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-<INCIDENT_ID>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize Credentials:** Rotate all access keys for the compromised user. Delete the old keys:
   ```bash
   aws iam create-access-key --user-name <USERNAME>
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_KEY_ID>
   ```

2. **Restore:** No data modification occurred during enumeration. No restore needed. If escalation followed, refer to the relevant attack playbook (e.g., PB-AWS-IAM-PRIVESC-01).

3. **Harden (The "Never Again" Fix):**
   - **Restrict `SimulatePrincipalPolicy`** via SCP for non-admin users:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": "iam:SimulatePrincipalPolicy",
         "Resource": "*",
         "Condition": {
           "StringNotLike": { "aws:PrincipalTag/Role": "SecurityAdmin" }
         }
       }]
     }
     ```
   - **Enable GuardDuty Recon findings** to catch `SimulatePrincipalPolicy` abuse.
   - **Apply least-privilege:** Remove `iam:AttachRolePolicy` and `iam:CreateRole` from `<USERNAME>` unless explicitly required.

4. **Verify:** Run the enumeration simulation again with the hardened policy and confirm all `SimulatePrincipalPolicy` calls return `AccessDenied`:
   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::<ACCOUNT_ID>:user/<USERNAME> \
     --action-names iam:AttachRolePolicy s3:GetObject ec2:RunInstances
   ```

5. **Post-Mortem:**
   - Did GuardDuty detect the `SimulatePrincipalPolicy` calls? (Yes/No)
   - Was there an existing SCP blocking policy simulator access for non-admins? (Yes/No)
   - How long between first enumeration call and IR team notification?

---

## Detection Rules

### Rule 1: IAM Policy Simulator Reconnaissance

```yaml
title: AWS IAM Policy Simulator Enumeration Detected
id: 8a3f2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c
status: experimental
level: high
description: Detects use of SimulatePrincipalPolicy to enumerate allowed actions across AWS services. Attackers use this to map permissions before escalation.
author: MayaTrail
date: 2026/02/23
references:
  - https://mayatrail.tech
tags:
  - attack.discovery
  - attack.t1580
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: SimulatePrincipalPolicy
  condition: selection
falsepositives:
  - IAM administrators performing policy audits
  - AWS Config or Access Analyzer automated assessments
```

### Rule 2: Caller Identity Probe Followed by Enumeration

```yaml
title: AWS GetCallerIdentity Followed by Policy Enumeration
id: 9b4f3c2d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
level: medium
description: Detects the reconnaissance pattern where an attacker first identifies themselves via GetCallerIdentity then immediately probes permissions via SimulatePrincipalPolicy.
author: MayaTrail
date: 2026/02/23
references:
  - https://mayatrail.tech
tags:
  - attack.discovery
  - attack.t1087.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection_identity:
    eventSource: sts.amazonaws.com
    eventName: GetCallerIdentity
  selection_enumerate:
    eventSource: iam.amazonaws.com
    eventName: SimulatePrincipalPolicy
  condition: selection_identity or selection_enumerate
  timeframe: 5m
falsepositives:
  - CI/CD pipelines that verify identity before performing actions
  - Automated security scanning tools
```

### Rule 3: Enumeration of Privilege Escalation Actions

```yaml
title: AWS Enumeration of Privilege Escalation Permissions
id: 7c5e4d3f-6a7b-8c9d-0e1f-2a3b4c5d6e7f
status: experimental
level: critical
description: Detects SimulatePrincipalPolicy calls that specifically probe for privilege escalation actions (AttachRolePolicy, CreateRole). This is the precursor to IAM privilege escalation attacks.
author: MayaTrail
date: 2026/02/23
references:
  - https://mayatrail.tech
tags:
  - attack.discovery
  - attack.t1580
  - attack.privilege_escalation
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: SimulatePrincipalPolicy
  filter_actions:
    requestParameters|contains:
      - "iam:AttachRolePolicy"
      - "iam:CreateRole"
      - "iam:PutUserPolicy"
  condition: selection and filter_actions
falsepositives:
  - Security teams auditing IAM permission boundaries
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Simulation Step |
|---|---|---|---|
| T1580 | Cloud Infrastructure Discovery | Discovery | `simulate_principal_policy()` probing IAM, EC2, S3, Lambda, RDS, KMS permissions via `ActionNames` |
| T1087.004 | Account Discovery: Cloud Account | Discovery | `sts.get_caller_identity()` to identify current user ARN before enumeration |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | Simulation assumes compromised credentials are already in use (boto3 default credential chain) |
