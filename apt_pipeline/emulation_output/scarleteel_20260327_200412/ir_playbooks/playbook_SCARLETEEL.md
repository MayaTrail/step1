# SCARLETEEL Incident Response Playbook

## Classification

| Field | Value |
|-------|-------|
| **Incident Type** | Cloud Infrastructure Compromise — Credential Theft, Data Exfiltration, Defense Evasion |
| **Threat Actor** | SCARLETEEL |
| **Severity** | Critical |
| **MITRE ATT&CK Tactics** | Initial Access, Execution, Credential Access, Discovery, Collection, Defense Evasion, Lateral Movement |

---

## 1. Detection — How We Discovered the Attack

### 1.1 Initial Alert Triggers

The following signals should trigger an investigation. Any one of these alone warrants triage; two or more in combination should be treated as a confirmed incident.

**HIGH-CONFIDENCE ALERTS:**

| Signal | CloudTrail Event | Detection Rule |
|--------|-----------------|----------------|
| CloudTrail logging disabled | `StopLogging` | Alert on ANY `cloudtrail:StopLogging` call. This should NEVER happen in normal operations. |
| EC2 instance role used from external IP | Any API call where `Username=i-*` and `sourceIPAddress` != the instance's public/private IP | Compare `sourceIPAddress` in CloudTrail against known EC2 IPs. The stolen credentials were used from `223.233.84.57` while the instance IP was `100.48.22.23`. |
| `iam:CreateUser` or `iam:CreateAccessKey` from EC2 role | `CreateUser`, `CreateAccessKey` with `errorCode=AccessDenied` | EC2 instance roles should never attempt IAM write operations. |
| Mass S3 `ListBuckets` from compute role | `ListBuckets` with `Username=i-*` | EC2 instance roles rarely need to enumerate ALL buckets. |

**MEDIUM-CONFIDENCE ALERTS:**

| Signal | CloudTrail Event | Detection Rule |
|--------|-----------------|----------------|
| Lambda enumeration burst | `ListFunctions`, `GetFunction`, `ListVersionsByFunction`, `ListAliases`, `ListTags` in rapid succession | 5+ Lambda read APIs within 30 seconds from the same principal. |
| `GetCallerIdentity` from an IAM user with no prior activity | `GetCallerIdentity` from `scarleteel-secondary-user` | First-time API call from a dormant IAM user — indicates stolen credentials being tested. |
| S3 object downloads from unusual principals | `GetObject` (data events) from EC2 roles | Requires S3 data event logging to be enabled. |

### 1.2 What We Actually Observed

In this incident, the first detectable signal was:

```
2026-03-27T20:05:50Z | CreateUser (AccessDenied) | srcIP=223.233.84.57 | principal=scarleteel-vuln-ec2-role-c0bcef8/i-0f4e358bd23d5829f
```

**Key observation**: The EC2 instance role credentials (`ASIA5V6I6Y7Q4LSSZ2DO`) were used from IP `223.233.84.57`, which is NOT the instance's public IP (`100.48.22.23`). This confirms the credentials were **exfiltrated and used from an external location**.

---

## 2. Investigation — Step-by-Step Forensic Analysis

### Step 1: Identify the Compromised Principal

**Query:** Find all API calls made by EC2 instance roles from non-EC2 IP addresses.

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=i-0f4e358bd23d5829f \
  --start-time "2026-03-27T19:00:00Z" \
  --end-time "2026-03-28T03:00:00Z" \
  --region us-east-1 --output json
```

**Parse for source IPs:**
```python
for event in events:
    ct = json.loads(event['CloudTrailEvent'])
    print(f"{ct['eventTime']} | {ct['eventName']} | {ct['sourceIPAddress']} | {ct.get('errorCode', 'OK')}")
```

**Finding:** Two distinct source IPs used the same role credentials:
- `100.48.22.23` — legitimate EC2 instance (SSM agent heartbeats)
- `223.233.84.57` — **attacker's IP** (all malicious API calls)

### Step 2: Reconstruct the Attack Timeline

| Time (UTC) | Event | Source IP | Significance |
|------------|-------|-----------|--------------|
| 20:04:12 | EC2 instance launched | - | Instance `i-0f4e358bd23d5829f` created with IMDSv1 |
| 20:04:27 | `RegisterManagedInstance` | 100.48.22.23 | SSM agent registers (legitimate) |
| 20:04:29 | `UpdateInstanceInformation` | 100.48.22.23 | SSM heartbeat (legitimate) |
| 20:05:50 | `CreateUser` (AccessDenied) | **223.233.84.57** | **ATTACKER** — privilege escalation attempt |
| 20:05:51 | `CreateAccessKey` (AccessDenied) | **223.233.84.57** | **ATTACKER** — targets "AdminJoe" user |
| 20:05:53 | `ListBuckets` | **223.233.84.57** | **ATTACKER** — S3 enumeration begins |
| 20:06:29 | `ListFunctions` | **223.233.84.57** | **ATTACKER** — Lambda enumeration |
| 20:06:29 | `GetFunction` | **223.233.84.57** | **ATTACKER** — source code theft |
| 20:06:30 | `ListVersionsByFunction` | **223.233.84.57** | **ATTACKER** — env var extraction |
| 20:06:30 | `Decrypt` (x3) | lambda.amazonaws.com | Lambda decrypts env vars for GetFunction |
| 20:06:31 | `GetPolicy`, `ListAliases`, `ListTags` | **223.233.84.57** | **ATTACKER** — continued enumeration |
| 20:06:32 | `ListEventSourceMappings` | **223.233.84.57** | **ATTACKER** — final Lambda enum |
| 20:06:34 | `DescribeTrails` | **223.233.84.57** | **ATTACKER** — discovers CloudTrail |
| 20:06:35 | **`StopLogging`** | **223.233.84.57** | **ATTACKER** — disables CloudTrail |
| 20:06:40 | `GetCallerIdentity` | **223.233.84.57** | **LATERAL MOVEMENT** — using stolen tfstate creds as `scarleteel-secondary-user-2745ca6` |
| 20:06:42 | `ListUsers` (AccessDenied) | **223.233.84.57** | **LATERAL MOVEMENT** — enumeration attempt fails |

**Total attack duration: ~52 seconds** (from first malicious API call to lateral movement)

### Step 3: Confirm IMDSv1 as the Credential Theft Vector

```bash
aws ec2 describe-instances --instance-ids i-0f4e358bd23d5829f \
  --query "Reservations[0].Instances[0].MetadataOptions"
```

**Finding:**
```json
{
    "HttpTokens": "optional",    ← IMDSv1 ENABLED (no session token required)
    "HttpEndpoint": "enabled",
    "HttpPutResponseHopLimit": 2  ← Allows container access via Docker bridge
}
```

The instance had IMDSv1 enabled with a hop limit of 2, allowing containers on the Docker bridge network to reach `169.254.169.254` and steal the instance role credentials without any authentication.

### Step 4: Identify the Vulnerable Application

```bash
aws ec2 describe-security-groups --group-ids sg-0d44244f7cefd2987
```

**Finding:** Port 8080 open to `0.0.0.0/0` — a containerized web application was publicly exposed. The attacker exploited a command injection vulnerability in this application to achieve code execution inside the container.

### Step 5: Assess Data Exfiltration Scope

**S3 — Management events visible in CloudTrail:**
- `ListBuckets` at 20:05:53 — attacker discovered all 15 buckets in the account
- Individual `ListObjectsV2` calls per bucket (visible with S3 data events only)
- `GetObject` on `terraform.tfstate` — confirmed credential theft

**Lambda — Intellectual property stolen:**
- `GetFunction` returns a **presigned S3 URL** to download the function code
- `ListVersionsByFunction` exposes **environment variables** including `DB_PASS=SuperSecretCustomerPass123`

**Critical gap:** S3 data event logging was NOT enabled, so individual `GetObject` calls are invisible in CloudTrail. We know from the attack script that data was exfiltrated from `scarleteel-dummy-logs`, `scarleteel-dummy-scripts`, and `scarleteel-trail-logs` buckets, but we cannot prove this from logs alone.

### Step 6: Confirm CloudTrail Tampering

```bash
aws cloudtrail get-trail-status --name scarleteel-trail-6d41d4d
```

**Finding:**
```json
{
    "IsLogging": false,
    "StopLoggingTime": "2026-03-28T01:36:35Z"
}
```

CloudTrail was disabled at 20:06:35 UTC. Any API calls made after this time are NOT logged. This is a critical defense evasion technique — the attacker ensured their subsequent S3 data exfiltration and lateral movement would leave no audit trail.

### Step 7: Investigate Lateral Movement

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=scarleteel-secondary-user-2745ca6
```

**Finding:** The attacker obtained permanent IAM credentials (`AKIA5V6I6Y7Q6PVT35NW`) from a `terraform.tfstate` file stored in S3. They used these credentials to:
1. `GetCallerIdentity` (20:06:40) — confirmed access as `scarleteel-secondary-user`
2. `ListUsers` (20:06:42) — attempted further enumeration (denied)

Both calls originated from the same attacker IP: `223.233.84.57`

### Step 8: Assess IAM Role Over-Privilege

```bash
aws iam get-role-policy --role-name scarleteel-vuln-ec2-role-c0bcef8 \
  --policy-name scarleteel-vuln-policy-c228a6f
```

**Finding:** The EC2 instance role had an overly permissive inline policy:
- `s3:ListAllMyBuckets`, `s3:GetObject`, `s3:ListBucket` on `Resource: *`
- 7 Lambda read permissions on `Resource: *`
- `cloudtrail:StopLogging`, `cloudtrail:DescribeTrails` on `Resource: *`

The role had **no business need** for most of these permissions. The `cloudtrail:StopLogging` permission is especially egregious — no EC2 workload should ever have this capability.

---

## 3. Containment — Immediate Response Actions

Execute these in order. Speed is critical — the attacker has your credentials.

### 3.1 Re-enable CloudTrail (Priority 0 — do this FIRST)

```bash
aws cloudtrail start-logging --name scarleteel-trail-6d41d4d --region us-east-1
```

Until logging is restored, you are flying blind. All subsequent containment actions need to be auditable.

### 3.2 Revoke Compromised Credentials

**Revoke the EC2 instance role sessions (invalidates ALL temporary credentials issued before this moment):**

```bash
aws iam put-role-policy \
  --role-name scarleteel-vuln-ec2-role-c0bcef8 \
  --policy-name AWSRevokeOlderSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "2026-03-27T20:10:00Z"
        }
      }
    }]
  }'
```

**Deactivate the stolen IAM user access key:**

```bash
aws iam update-access-key \
  --user-name scarleteel-secondary-user-2745ca6 \
  --access-key-id AKIA5V6I6Y7Q6PVT35NW \
  --status Inactive
```

### 3.3 Isolate the Compromised Instance

**Option A (preferred) — Quarantine via security group:**
```bash
# Create a quarantine SG with no inbound/outbound rules
QUARANTINE_SG=$(aws ec2 create-security-group \
  --group-name quarantine-scarleteel \
  --description "Quarantine - incident response" \
  --output text --query 'GroupId')

# Remove default egress rule
aws ec2 revoke-security-group-egress \
  --group-id $QUARANTINE_SG \
  --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'

# Replace the instance's security group
aws ec2 modify-instance-attribute \
  --instance-id i-0f4e358bd23d5829f \
  --groups $QUARANTINE_SG
```

**Option B — Snapshot and terminate:**
```bash
# Take forensic snapshot first
aws ec2 create-snapshot --volume-id <root-volume-id> --description "Forensic - SCARLETEEL incident"

# Stop the instance (do NOT terminate until forensics complete)
aws ec2 stop-instances --instance-ids i-0f4e358bd23d5829f
```

### 3.4 Rotate All Exposed Secrets

| Secret | Location Found | Action |
|--------|---------------|--------|
| EC2 instance role temp creds (`ASIA5V6I6Y7Q4LSSZ2DO`) | IMDS | Revoked via session policy (Step 3.2) |
| IAM user permanent key (`AKIA5V6I6Y7Q6PVT35NW`) | `terraform.tfstate` in S3 | Deactivate and delete the key, generate new one |
| `DB_PASS=SuperSecretCustomerPass123` | Lambda env vars | Rotate the database password immediately |
| Any secrets in exfiltrated S3 data | S3 buckets | Audit all objects in exfiltrated buckets for secrets |

---

## 4. Eradication — Remove the Vulnerability

### 4.1 Enforce IMDSv2 on All EC2 Instances

```bash
# Fix the compromised instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-0f4e358bd23d5829f \
  --http-tokens required \
  --http-put-response-hop-limit 1

# Audit ALL instances in the account
aws ec2 describe-instances \
  --query "Reservations[*].Instances[*].{ID:InstanceId, HttpTokens:MetadataOptions.HttpTokens, HopLimit:MetadataOptions.HttpPutResponseHopLimit}" \
  --output table
```

Setting `http-tokens required` enforces IMDSv2 (session-based). Setting `hop-limit 1` prevents containers on Docker bridge from reaching the metadata endpoint.

### 4.2 Apply Least-Privilege to the IAM Role

Remove unnecessary permissions. The role should NEVER have:
- `cloudtrail:StopLogging` — no workload needs this
- `s3:*` with `Resource: *` — scope to specific buckets
- `lambda:*` read — scope to specific functions if needed at all

### 4.3 Remove Plaintext Secrets from Terraform State

- Enable S3 server-side encryption (SSE-KMS) on state buckets
- Use Terraform's `sensitive` attribute for credential outputs
- Consider using a remote backend with state encryption (e.g., S3 + DynamoDB with KMS)
- Move secrets to AWS Secrets Manager or SSM Parameter Store (SecureString)

### 4.4 Move Lambda Secrets to Secrets Manager

```bash
# Store in Secrets Manager instead of env vars
aws secretsmanager create-secret --name ProprietaryAlgoFunc/DB_PASS --secret-string "<new-password>"
```

Update the Lambda code to fetch from Secrets Manager at runtime instead of reading `os.environ`.

### 4.5 Enable S3 Data Event Logging

```bash
aws cloudtrail put-event-selectors --trail-name scarleteel-trail-6d41d4d \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3"]
    }]
  }]'
```

This ensures future `GetObject`, `PutObject`, and `DeleteObject` calls are logged.

### 4.6 Protect CloudTrail from Tampering

- Create an SCP (Service Control Policy) at the AWS Organization level to deny `cloudtrail:StopLogging` and `cloudtrail:DeleteTrail` for all accounts:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "cloudtrail:UpdateTrail"
    ],
    "Resource": "*",
    "Condition": {
      "StringNotLike": {
        "aws:PrincipalArn": "arn:aws:iam::*:role/SecurityAdmin"
      }
    }
  }]
}
```

### 4.7 Fix the Vulnerable Web Application

- Patch the command injection vulnerability in the containerized Flask app
- Implement input validation and parameterized command execution
- Deploy a Web Application Firewall (WAF) in front of the application
- Restrict the security group to known client IPs instead of `0.0.0.0/0`

---

## 5. Recovery

1. Deploy a new EC2 instance with IMDSv2 enforced and a least-privilege IAM role
2. Redeploy the containerized application with the vulnerability patched
3. Verify CloudTrail is logging and send logs to a separate, write-only S3 bucket
4. Confirm all rotated credentials are working
5. Run a full IAM Access Analyzer scan to identify remaining over-privileged roles

---

## 6. Lessons Learned — Detection Gap Analysis

| Gap | Impact | Remediation |
|-----|--------|-------------|
| IMDSv1 allowed credential theft from container | Complete account compromise | Enforce IMDSv2 account-wide via SCP or EC2 default settings |
| No alert on `StopLogging` | Attacker disabled audit trail undetected | CloudWatch alarm on `StopLogging` event, SCP to prevent it |
| S3 data events not logged | Cannot prove scope of data exfiltration | Enable S3 data event logging on all sensitive buckets |
| No alert on EC2 role used from external IP | Credential exfiltration went undetected | GuardDuty would catch this (`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`) |
| Terraform state had plaintext creds | Enabled lateral movement | Encrypt state, use Secrets Manager, never store IAM keys in state |
| Over-privileged IAM role | Gave attacker broad read + CloudTrail disable | Implement least-privilege; no workload should have `cloudtrail:StopLogging` |
| No WAF or rate limiting | Command injection exploitable by anyone | Deploy WAF, restrict inbound access, fix the code |
| Lambda env vars had plaintext secrets | Database password stolen | Use Secrets Manager or SSM SecureString |

---

## 7. Detection Rules to Implement

### 7.1 GuardDuty (Enable Immediately)

GuardDuty would have generated these findings for this attack:
- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` — credentials used from non-AWS IP
- `Stealth:IAMUser/CloudTrailLoggingDisabled` — CloudTrail stopped
- `Discovery:IAMUser/AnomalousBehavior` — unusual API patterns

### 7.2 CloudWatch Alerts

```bash
# Alert on CloudTrail being disabled
aws cloudwatch put-metric-alarm \
  --alarm-name "CloudTrail-StopLogging" \
  --metric-name StopLoggingEventCount \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:<account>:security-alerts
```

### 7.3 Custom CloudTrail Metric Filters

```
# Detect credential exfiltration (EC2 role used from non-EC2 IP)
{ ($.userIdentity.type = "AssumedRole") && ($.userIdentity.arn = "*:i-*") && ($.sourceIPAddress != "*.amazonaws.com") && ($.sourceIPAddress != "*.compute.internal") }

# Detect IAM privilege escalation attempts
{ ($.eventName = "CreateUser" || $.eventName = "CreateAccessKey" || $.eventName = "AttachUserPolicy") && ($.errorCode = "AccessDenied") }

# Detect mass S3 enumeration
{ ($.eventName = "ListBuckets") && ($.userIdentity.arn = "*instance-profile*") }
```

---

## 8. IOCs (Indicators of Compromise)

| Type | Value | Context |
|------|-------|---------|
| IP Address | `223.233.84.57` | Attacker source IP for all API calls |
| IP Address | `100.48.22.23` | Compromised EC2 instance public IP |
| Instance ID | `i-0f4e358bd23d5829f` | Compromised container host |
| IAM Role | `scarleteel-vuln-ec2-role-c0bcef8` | Compromised EC2 role |
| Access Key | `ASIA5V6I6Y7Q4LSSZ2DO` | Stolen temporary credentials (expired) |
| Access Key | `AKIA5V6I6Y7Q6PVT35NW` | Stolen permanent credentials from tfstate |
| IAM User | `scarleteel-secondary-user-2745ca6` | Lateral movement target |
| S3 Bucket | `scarleteel-tf-state-6149adc` | Source of stolen credentials |
| CloudTrail | `scarleteel-trail-6d41d4d` | Trail that was disabled |
| User Agent | `Boto3/<version> Python/<version>` | Attacker tooling signature |
| File | `/tmp/miner.sh` | Cryptominer script on compromised host |
| File | `/tmp/config_background.json` | XMRig mining pool configuration |
| File | `/tmp/aws_stolen/raw.json` | Exfiltrated IMDS credentials on disk |

---

## Appendix A: Full CloudTrail Query Commands

```bash
# All activity from compromised instance role
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=i-0f4e358bd23d5829f \
  --start-time "2026-03-27T19:00:00Z" --end-time "2026-03-28T03:00:00Z" \
  --region us-east-1

# Lateral movement activity
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=scarleteel-secondary-user-2745ca6 \
  --start-time "2026-03-27T19:00:00Z" --end-time "2026-03-28T03:00:00Z" \
  --region us-east-1

# CloudTrail tampering events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=cloudtrail.amazonaws.com \
  --start-time "2026-03-27T19:00:00Z" --end-time "2026-03-28T03:00:00Z" \
  --region us-east-1

# Check current CloudTrail status
aws cloudtrail get-trail-status --name <trail-name>

# Verify IMDSv1 exposure on instance
aws ec2 describe-instances --instance-ids i-0f4e358bd23d5829f \
  --query "Reservations[0].Instances[0].MetadataOptions"
```
