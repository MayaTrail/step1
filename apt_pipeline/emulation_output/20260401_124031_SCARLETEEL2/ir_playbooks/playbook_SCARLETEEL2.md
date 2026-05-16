# SCARLETEEL 2.0 — Incident Response Playbook

## Classification

| Field | Value |
|-------|-------|
| **Incident Type** | Cloud Infrastructure Compromise — Credential Theft, IP Exfiltration, Defense Evasion, Lateral Movement |
| **Threat Actor** | SCARLETEEL |
| **Severity** | Critical |
| **Account** | 940482414561 |
| **Region** | us-east-1 |
| **Date** | 2026-04-01 |
| **MITRE ATT&CK Tactics** | Initial Access, Credential Access, Discovery, Collection, Defense Evasion, Lateral Movement, Impact |

---

## 1. Detection — How We Discovered the Attack

### 1.1 Initial Alert Triggers

The following signals should trigger an investigation. Any one of these alone warrants triage; two or more in combination should be treated as a confirmed incident.

**HIGH-CONFIDENCE ALERTS:**

| Signal | CloudTrail Event | Detection Rule |
|--------|-----------------|----------------|
| CloudTrail logging disabled | `StopLogging` | Alert on ANY `cloudtrail:StopLogging` call. This should **NEVER** happen in normal operations. |
| EC2 instance role used from external IP | Any API call where `Username=i-*` and `sourceIPAddress` is not the instance's known IP | Compare `sourceIPAddress` against known EC2 IPs. In this incident, stolen creds were used from `223.233.87.167` while the instance IP was `100.56.9.155`. |
| `iam:CreateUser` from EC2 role | `CreateUser` with principal `i-044bfaf60db1a6f47` | EC2 instance roles should **never** attempt IAM user creation. |
| `iam:CreateAccessKey` with `AccessDenied` | `CreateAccessKey` with `errorCode=AccessDenied` | Failed privilege escalation attempt — attacker testing IAM boundaries. |

**MEDIUM-CONFIDENCE ALERTS:**

| Signal | CloudTrail Event | Detection Rule |
|--------|-----------------|----------------|
| Lambda enumeration burst | `ListFunctions` → `GetFunction` → `ListVersionsByFunction` → `ListAliases` → `ListTags` in <10s | 5+ Lambda read APIs within 30 seconds from the same principal. |
| Mass S3 bucket enumeration | `ListBuckets` from EC2 instance role | EC2 roles rarely need to enumerate ALL buckets in the account. |
| SecretsManager harvest | `ListSecrets` + `GetSecretValue` from compute role | EC2 roles accessing SecretsManager is unusual in most architectures. |
| `GetCallerIdentity` from dormant IAM user | `GetCallerIdentity` from `scarleteel-bait-user` | First-time API call from a user with no prior activity — indicates stolen/new credentials being tested. |

### 1.2 What We Actually Observed

In this incident, the first detectable attack signal was:

```
2026-04-01 12:44:51 IST | ListUsers | srcIP=223.233.87.167 | principal=i-044bfaf60db1a6f47 | OK
```

**Key observation**: The EC2 instance role credentials for `i-044bfaf60db1a6f47` were used from IP `223.233.87.167`, which is **NOT** the instance's public IP (`100.56.9.155`). This confirms the credentials were **exfiltrated from the instance metadata service and used from an external location**.

The instance's own IP (`100.56.9.155`) only appears in SSM agent heartbeat events (`UpdateInstanceInformation`, `ListInstanceAssociations`, `RegisterManagedInstance`) — all legitimate.

---

## 2. Investigation — Step-by-Step Forensic Analysis

### Step 1: Identify the Compromised Principal

**Query:** Find all API calls made by the EC2 instance role from non-EC2 IP addresses.

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=i-044bfaf60db1a6f47 \
  --start-time "2026-04-01T07:00:00Z" \
  --end-time "2026-04-01T09:00:00Z" \
  --region us-east-1 --output json --profile apt
```

**Finding:** Two distinct source IPs used the same role credentials:

| Source IP | Activity | Classification |
|-----------|----------|---------------|
| `100.56.9.155` | `UpdateInstanceInformation`, `RegisterManagedInstance`, `ListInstanceAssociations` | **Legitimate** — SSM agent heartbeats from the EC2 instance |
| `223.233.87.167` | `ListUsers`, `ListRoles`, `CreateUser`, `CreateAccessKey`, `ListBuckets`, `ListFunctions`, `GetFunction`, `DescribeTrails`, `StopLogging`, `ListSecrets`, `GetSecretValue` | **Malicious** — Stolen credentials used from attacker's IP |
| `2401:4900:1c7e:d239:*` (IPv6) | `ListSecrets`, `GetSecretValue` | **Malicious** — Same attacker, IPv6 address |

### Step 2: Reconstruct the Attack Timeline

#### Phase 0: Infrastructure Provisioning (Legitimate — 12:40:31 to 12:44:18 IST)

| Time (IST) | Event | Source IP | Significance |
|------------|-------|-----------|--------------|
| 12:40:31 | Various `Create*` events | 223.233.87.167 | Pulumi deploying infrastructure (legitimate admin `ayush`) |
| 12:40:32 | `CreateUser` (scarleteel-bait-user) | 223.233.87.167 | Bait IAM user created |
| 12:40:33 | `CreateBucket` (x4) | 223.233.87.167 | S3 buckets provisioned |
| 12:40:36 | `PutRolePolicy` | 223.233.87.167 | Over-privileged inline policy attached to EC2 role |
| 12:40:38 | `AttachRolePolicy` | 223.233.87.167 | Permission boundary attached |
| 12:40:41 | `CreateFunction` (ProprietaryAlgoFunc) | 223.233.87.167 | Lambda with DB_PASS env var |
| 12:40:49 | `RunInstances` | 223.233.87.167 | EC2 instance `i-044bfaf60db1a6f47` launched |
| 12:40:50 | `CreateTrail` + `StartLogging` | 223.233.87.167 | CloudTrail trail activated |
| 12:44:13 | `CreateSecret` (prod/database/master_credentials) | IPv6 | SecretsManager bait secret created |
| 12:44:17 | `PutSecretValue` | IPv6 | Secret value populated |

#### Phase 1: Initial Compromise (~12:41 to 12:44 IST — NOT visible in CloudTrail)

The initial container exploitation and IMDSv1 credential theft happen entirely on the **data plane**:
- HTTP POST to `http://100.56.9.155:8080/cmd` — command injection into Flask app
- `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/...` — credential theft from inside container

**These actions generate ZERO CloudTrail events.** The only evidence would be:
- EC2 instance console output / cloud-init logs
- VPC Flow Logs showing HTTP traffic to port 8080
- Container-level logging (if configured)

This is why IMDSv1 is so dangerous — credential theft is completely invisible to CloudTrail.

#### Phase 2: Pacu Recon + Privilege Escalation (12:44:51 to 12:45:06 IST)

| Time (IST) | Event | Source IP | Error | Target | Significance |
|------------|-------|-----------|-------|--------|--------------|
| **12:44:51** | `ListUsers` | 223.233.87.167 | OK | - | **FIRST MALICIOUS EVENT** — Pacu-style IAM recon |
| **12:44:55** | `ListRoles` | 223.233.87.167 | OK | - | Enumerating IAM roles for escalation targets |
| **12:44:58** | `CreateUser` | 223.233.87.167 | OK | ScarleteelBackdoor | **Backdoor user created!** |
| **12:44:58** | `DeleteUser` | 223.233.87.167 | OK | ScarleteelBackdoor | Immediate cleanup (attacker testing permissions) |
| **12:45:01** | `CreateAccessKey` | 223.233.87.167 | **AccessDenied** | - | Privilege escalation blocked by permission boundary |
| **12:45:06** | `CreateAccessKey` | 223.233.87.167 | NoSuchEntity | AdminJoe | **Naming-convention bypass attempt** — capital A bypasses `admin*` deny, but user doesn't exist |

**Analysis:**
- The attacker first enumerated IAM to understand the environment (Pacu recon pattern)
- Successfully created a backdoor user `ScarleteelBackdoor` — confirms the role has `iam:CreateUser`
- Tested the naming-convention bypass: `adminJoe` → AccessDenied, `AdminJoe` → NoSuchEntityException (NOT AccessDenied — bypass works, user just doesn't exist)
- The 4-second gap between `ListUsers` and `CreateUser` suggests automated tooling with built-in delays

#### Phase 3: S3 + Lambda Enumeration (12:45:22 to 12:46:44 IST)

| Time (IST) | Event | Source IP | Target | Significance |
|------------|-------|-----------|--------|--------------|
| **12:45:22** | `ListBuckets` | 223.233.87.167 | - | Full account bucket enumeration |
| **12:46:41** | `ListFunctions` | 223.233.87.167 | - | Lambda function discovery |
| **12:46:42** | `GetFunction` | 223.233.87.167 | ProprietaryAlgoFunc | **Source code download URL obtained** |
| **12:46:42** | `ListVersionsByFunction` | 223.233.87.167 | ProprietaryAlgoFunc | **Environment variables (DB_PASS) exposed** |
| **12:46:43** | `GetPolicy` | 223.233.87.167 | ProprietaryAlgoFunc | ResourceNotFoundException (no resource policy) |
| **12:46:43** | `ListAliases` | 223.233.87.167 | ProprietaryAlgoFunc | Alias enumeration |
| **12:46:43** | `ListTags` | 223.233.87.167 | ProprietaryAlgoFunc | Tag enumeration |
| **12:46:44** | `ListEventSourceMappings` | 223.233.87.167 | ProprietaryAlgoFunc | Trigger enumeration |

**Analysis:**
- 82-second gap between `ListBuckets` and `ListFunctions` — attacker was downloading S3 objects (data events not captured without S3 data event logging)
- Lambda enumeration burst: 7 API calls in 3 seconds — classic automated tool fingerprint
- `GetFunction` returns a pre-signed URL to download the Lambda deployment package — **intellectual property stolen**
- `ListVersionsByFunction` exposes environment variables including `DB_PASS=SuperSecretCustomerPass123`

**Missing evidence:** S3 `GetObject` calls (downloading bucket contents, terraform.tfstate) are **data events** and only appear if S3 data event logging was enabled on the trail. In this emulation, they were not captured in CloudTrail management events.

#### Phase 4: Defense Evasion (12:47:02 IST)

| Time (IST) | Event | Source IP | Target | Significance |
|------------|-------|-----------|--------|--------------|
| **12:47:02** | `DescribeTrails` | 223.233.87.167 | - | Attacker discovering audit trails |
| **12:47:02** | `StopLogging` | 223.233.87.167 | scarleteel-trail-* | **CLOUDTRAIL DISABLED — AUDIT TRAIL DESTROYED** |

**Analysis:**
- Same-second execution of `DescribeTrails` → `StopLogging` — fully automated
- **After this point, no further CloudTrail events are recorded for the attack**
- This is the most critical detection event — `StopLogging` should trigger an immediate P1 incident

#### Phase 5: Terraform State Credential Theft (~12:47:05 IST — NOT in CloudTrail)

- `s3:GetObject` on `terraform.tfstate` — data event, not captured
- The attacker extracted IAM access keys for `scarleteel-bait-user` from the Terraform state file
- This would only be visible in S3 data event logs or S3 access logs

#### Phase 6: Lateral Movement + Secondary Pivot (12:47:23 to 12:47:38 IST)

| Time (IST) | Event | Source IP | Error | Principal | Significance |
|------------|-------|-----------|-------|-----------|--------------|
| **12:47:23** | `GetCallerIdentity` | 223.233.87.167 | OK | `scarleteel-bait-user` | **NEW IDENTITY** — lateral movement confirmed |
| **12:47:31** | `ListUsers` | 223.233.87.167 | **AccessDenied** | `scarleteel-bait-user` | Lateral user has zero permissions (expected) |
| **12:47:38** | `ListSecrets` | IPv6 | OK | `i-044bfaf60db1a6f47` | Back to EC2 role — SecretsManager harvest |
| **12:47:38** | `GetSecretValue` | IPv6 | OK | `prod/database/master_credentials` | **PRODUCTION SECRET STOLEN** |

**Analysis:**
- Principal changes from `i-044bfaf60db1a6f47` to `scarleteel-bait-user` — proves the Terraform state credentials were successfully extracted and used
- `GetCallerIdentity` is the first API call any attacker makes with new credentials to verify they work
- After confirming the lateral user has no permissions, the attacker pivots back to the EC2 role for SecretsManager harvest
- `ListSecrets` + `GetSecretValue` in the same second — automated exfiltration

**Note:** These Phase 6 events occurred AFTER CloudTrail was disabled in Phase 4. They appear in our forensic data because we queried CloudTrail `LookupEvents` which searches the CloudTrail service's internal event history (retained for 90 days), not the trail's S3 delivery. The `StopLogging` only stopped delivery to S3 — the CloudTrail service still records events internally.

### Step 3: Identify the Attack Vector

**How were the credentials stolen?**

The EC2 instance `i-044bfaf60db1a6f47` was configured with:
- **IMDSv1 enabled** (`HttpTokens: optional`) — allows unauthenticated credential theft via `curl`
- **HTTP PUT Response Hop Limit: 2** — allows containers (behind Docker bridge) to reach IMDS
- A Docker container running a Flask web application with a command injection vulnerability on port 8080

The attacker exploited the web application via HTTP POST to `/cmd`, then used `curl` from inside the container to steal temporary IAM credentials from the Instance Metadata Service at `169.254.169.254`.

**Evidence supporting this theory:**
1. The EC2 role credentials appeared at a non-instance IP (`223.233.87.167`) — confirms credential exfiltration
2. The instance has a security group allowing inbound port 8080 from `0.0.0.0/0`
3. IMDSv1 was explicitly enabled on the instance
4. The `http_put_response_hop_limit=2` setting confirms Docker containers could reach IMDS

### Step 4: Assess Impact

| Asset | Compromised? | Evidence |
|-------|-------------|----------|
| EC2 Instance Role | **YES** | Role credentials used from external IP for 20+ API calls |
| IAM User Enumeration | **YES** | `ListUsers` returned all IAM users in account |
| IAM Role Enumeration | **YES** | `ListRoles` returned all IAM roles |
| Backdoor User Creation | **YES (temporary)** | `ScarleteelBackdoor` created and immediately deleted |
| S3 Bucket Contents | **LIKELY** | `ListBuckets` succeeded; `GetObject` not captured (data events) |
| Lambda Source Code | **YES** | `GetFunction` returned pre-signed download URL |
| Lambda Environment Variables | **YES** | `DB_PASS=SuperSecretCustomerPass123` exposed via `ListVersionsByFunction` |
| CloudTrail Audit Trail | **DISABLED** | `StopLogging` succeeded — no further audit trail |
| Terraform State (IAM Keys) | **LIKELY** | S3 GetObject not captured, but lateral movement confirms extraction |
| Lateral IAM User | **YES** | `GetCallerIdentity` confirmed from `scarleteel-bait-user` |
| SecretsManager Secrets | **YES** | `GetSecretValue` on `prod/database/master_credentials` succeeded |
| Database Credentials | **YES** | `db_admin` / `Pr0d-M4st3r-P@ss!2026` for `prod-db.internal.corp.com:5432` stolen |

---

## 3. Indicators of Compromise (IOCs)

### Network IOCs

| IOC | Type | Description |
|-----|------|-------------|
| `223.233.87.167` | IPv4 | Attacker source IP (stolen credential usage) |
| `2401:4900:1c7e:d239:21af:4010:dcb2:59a` | IPv6 | Attacker source IP (SecretsManager harvest) |
| `100.56.9.155` | IPv4 | Compromised EC2 instance public IP |
| `45.9.148.221` | IPv4 | SCARLETEEL primary C2 server (from threat intel) |
| `175.102.182.6` | IPv4 | SCARLETEEL secondary C2 / script hosting (from threat intel) |
| `hb.bizmrg.com` | Domain | Russian S3 endpoint used for CloudTrail-evading exfiltration |
| `pool.c3pool.com:13333` | Host:Port | XMRig mining pool |

### AWS IOCs

| IOC | Type | Description |
|-----|------|-------------|
| `i-044bfaf60db1a6f47` | EC2 Instance ID | Compromised container host |
| `scarleteel-vuln-ec2-role-*` | IAM Role | Compromised over-privileged role |
| `ScarleteelBackdoor` | IAM User | Attacker-created backdoor user (deleted) |
| `scarleteel-bait-user-*` | IAM User | Lateral movement target (credentials extracted from Terraform state) |
| `scarleteel-trail-*` | CloudTrail Trail | Trail disabled by attacker |

### Host IOCs

| IOC | Path/Name | Description |
|-----|-----------|-------------|
| `containered.service` | systemd service | XMRig miner masquerading as `containerd` (note the extra 'e') |
| `/root/.configure/containerd` | File path | Miner binary disguised as containerd |
| `/root/.configure/pandora` | File path | Pandora (Mirai variant) DDoS bot |
| `/tmp/config_background.json` | File path | XMRig pool configuration |
| `43Lfq18TycJHVR3AMews5C9f...` | Monero wallet | Mining payout address |

---

## 4. Containment

### Immediate Actions (First 15 minutes)

1. **Re-enable CloudTrail logging** — highest priority:
   ```bash
   aws cloudtrail start-logging --name scarleteel-trail-d88a157 --profile apt
   ```

2. **Isolate the compromised EC2 instance** — replace security group with deny-all:
   ```bash
   aws ec2 create-security-group --group-name quarantine-sg --description "Quarantine - no traffic" --profile apt
   aws ec2 modify-instance-attribute --instance-id i-044bfaf60db1a6f47 \
     --groups <quarantine-sg-id> --profile apt
   ```

3. **Revoke the compromised role's temporary credentials** — add inline deny policy:
   ```bash
   aws iam put-role-policy --role-name scarleteel-vuln-ec2-role-* \
     --policy-name emergency-deny-all \
     --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}' \
     --profile apt
   ```

4. **Deactivate the lateral movement IAM user's access keys**:
   ```bash
   aws iam list-access-keys --user-name scarleteel-bait-user-* --profile apt
   aws iam update-access-key --user-name scarleteel-bait-user-* \
     --access-key-id <key_id> --status Inactive --profile apt
   ```

5. **Rotate the stolen Lambda environment variable**:
   - Change `DB_PASS` in Lambda configuration
   - Rotate the actual database password referenced by `DB_PASS`

6. **Rotate the stolen SecretsManager secret**:
   ```bash
   aws secretsmanager rotate-secret --secret-id prod/database/master_credentials --profile apt
   ```
   - Also rotate the actual database credentials at `prod-db.internal.corp.com:5432`

### Secondary Actions (First hour)

7. **Snapshot the EC2 instance for forensic analysis** before termination:
   ```bash
   aws ec2 create-image --instance-id i-044bfaf60db1a6f47 \
     --name "forensic-snapshot-scarleteel-$(date +%Y%m%d)" --no-reboot --profile apt
   ```

8. **Review all IAM users** for unauthorized access keys or recently created users:
   ```bash
   aws iam list-users --profile apt
   aws iam list-access-keys --user-name <each_user> --profile apt
   ```

9. **Check for unauthorized EC2 SSH key pairs**:
   ```bash
   aws ec2 describe-key-pairs --profile apt
   ```

10. **Enable S3 data event logging** on the CloudTrail trail to capture future `GetObject` calls.

---

## 5. Eradication

1. **Terminate the compromised EC2 instance**:
   ```bash
   aws ec2 terminate-instances --instance-ids i-044bfaf60db1a6f47 --profile apt
   ```

2. **Delete the bait/compromised IAM user and access keys**:
   ```bash
   aws iam delete-access-key --user-name scarleteel-bait-user-* --access-key-id <key> --profile apt
   aws iam delete-user --user-name scarleteel-bait-user-* --profile apt
   ```

3. **Remove the over-privileged IAM role** and all attached policies:
   ```bash
   aws iam delete-role-policy --role-name scarleteel-vuln-ec2-role-* --policy-name scarleteel-vuln-policy --profile apt
   aws iam remove-role-from-instance-profile --instance-profile-name <profile> --role-name <role> --profile apt
   aws iam delete-role --role-name scarleteel-vuln-ec2-role-* --profile apt
   ```

4. **Delete the attacker's S3 buckets and trail**:
   ```bash
   aws s3 rb s3://scarleteel-dummy-logs-* --force --profile apt
   aws s3 rb s3://scarleteel-dummy-scripts-* --force --profile apt
   aws s3 rb s3://scarleteel-tf-state-* --force --profile apt
   aws s3 rb s3://scarleteel-trail-logs-* --force --profile apt
   aws cloudtrail delete-trail --name scarleteel-trail-* --profile apt
   ```

5. **Full infrastructure teardown** (via Pulumi if still available):
   ```bash
   cd scarleteel_emulation && AWS_PROFILE=apt pulumi destroy -y
   ```

---

## 6. Recovery & Hardening

### Immediate Hardening

| Action | Priority | Rationale |
|--------|----------|-----------|
| **Enforce IMDSv2** on all EC2 instances | P1 | Prevents unauthenticated IMDS credential theft. Set `HttpTokens: required` account-wide via SCP. |
| **Enable CloudTrail Organization trail** with delete protection | P1 | Prevents attacker from disabling logging. Use SCP to deny `cloudtrail:StopLogging` from non-admin roles. |
| **Implement least-privilege IAM** | P1 | EC2 roles should never have `iam:CreateUser`, `iam:CreateAccessKey`, `cloudtrail:StopLogging`. |
| **Enable S3 data event logging** | P2 | Captures `GetObject` calls — critical for detecting data exfiltration. |
| **Enable GuardDuty** | P2 | Would have detected: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` |
| **Restrict SecretsManager access** | P2 | EC2 compute roles should not have blanket `secretsmanager:GetSecretValue`. |
| **Case-sensitive IAM policies** | P2 | Use `aws:PrincipalTag` or exact ARN matching instead of `admin*` pattern. |
| **VPC Flow Logs** | P3 | Detects C2 communication and non-standard S3 endpoint usage (`hb.bizmrg.com`). |
| **Container security** | P3 | No exposed command injection endpoints. Use WAF for public-facing containers. |

### Detection Rules to Implement

```yaml
# Rule 1: CloudTrail StopLogging (CRITICAL — P1)
- name: cloudtrail_disabled
  condition: eventName == "StopLogging"
  severity: CRITICAL
  action: page_oncall_immediately

# Rule 2: EC2 Role Used from External IP (HIGH — P1)
- name: ec2_credential_exfiltration
  condition: |
    principalId matches "i-*" AND
    sourceIPAddress NOT IN known_ec2_ips
  severity: HIGH
  action: page_oncall + isolate_instance

# Rule 3: IAM Write from Compute Role (HIGH — P1)
- name: iam_write_from_compute
  condition: |
    principalId matches "i-*" AND
    eventName IN ["CreateUser", "CreateAccessKey", "AttachUserPolicy"]
  severity: HIGH
  action: alert_security_team

# Rule 4: Mass Lambda Enumeration (MEDIUM — P2)
- name: lambda_enumeration_burst
  condition: |
    COUNT(eventName IN ["ListFunctions", "GetFunction", "ListVersionsByFunction"])
    FROM same principal WITHIN 30 seconds >= 5
  severity: MEDIUM
  action: alert_security_team

# Rule 5: SecretsManager Access from Compute (MEDIUM — P2)
- name: secrets_harvest_from_compute
  condition: |
    principalId matches "i-*" AND
    eventName IN ["ListSecrets", "GetSecretValue"]
  severity: MEDIUM
  action: alert_security_team

# Rule 6: First API Call from Dormant User (MEDIUM — P2)
- name: dormant_user_activation
  condition: |
    principalType == "IAMUser" AND
    eventName == "GetCallerIdentity" AND
    user has no API activity in last 90 days
  severity: MEDIUM
  action: alert_security_team

# Rule 7: Naming Convention Bypass (LOW — P3)
- name: iam_naming_bypass
  condition: |
    eventName == "CreateAccessKey" AND
    requestParameters.userName matches regex "^[A-Z].*admin.*" (case-insensitive)
  severity: LOW
  action: log_for_review
```

---

## 7. Attack Timeline Summary

```
12:40:31 ─── INFRASTRUCTURE PROVISIONED (Pulumi) ─────────────────────
         │  EC2 + Docker + Flask RCE + IMDSv1 enabled
         │  S3 buckets, Lambda, CloudTrail, SecretsManager
         │  Over-privileged EC2 role with IAM/S3/Lambda/CT/SM permissions
12:40:49 ─── EC2 INSTANCE LAUNCHED ────────────────────────────────────
         │  i-044bfaf60db1a6f47 at 100.56.9.155
         │  UserData: iptables flush, Docker build, miner deploy
12:41:05 ─── SSM AGENT REGISTERS (legitimate) ─────────────────────────
         │
         │  ~~~ Container boots, Flask app starts on :8080 ~~~
         │  ~~~ Attacker exploits /cmd endpoint ~~~
         │  ~~~ IMDSv1 credential theft (INVISIBLE to CloudTrail) ~~~
         │
12:44:51 ─── PHASE 2: PACU RECON ─────────────────────────────────────
         │  ListUsers, ListRoles (from 223.233.87.167)
12:44:58 │  CreateUser "ScarleteelBackdoor" → OK (then deleted)
12:45:01 │  CreateAccessKey "adminJoe" → AccessDenied ✗
12:45:06 │  CreateAccessKey "AdminJoe" → NoSuchEntity (bypass works!)
         │
12:45:22 ─── PHASE 3: S3 + LAMBDA ENUMERATION ────────────────────────
         │  ListBuckets → 4+ buckets discovered
         │  [~80s of S3 GetObject — NOT in CloudTrail]
12:46:41 │  ListFunctions → ProprietaryAlgoFunc
12:46:42 │  GetFunction → source code URL stolen
12:46:42 │  ListVersionsByFunction → DB_PASS exposed
12:46:43 │  GetPolicy, ListAliases, ListTags, ListEventSourceMappings
         │
12:47:02 ─── PHASE 4: DEFENSE EVASION ────────────────────────────────
         │  DescribeTrails → found scarleteel-trail
         │  StopLogging → CLOUDTRAIL DISABLED ⚠️
         │
         │  ~~~ NO FURTHER TRAIL DELIVERY ~~~
         │  (but CloudTrail service still records internally)
         │
12:47:23 ─── PHASE 6: LATERAL MOVEMENT ───────────────────────────────
         │  GetCallerIdentity → confirmed as scarleteel-bait-user
12:47:31 │  ListUsers → AccessDenied (zero-permission, expected)
12:47:38 │  ListSecrets → prod/database/master_credentials
12:47:38 │  GetSecretValue → DATABASE CREDENTIALS STOLEN ⚠️
         │
12:47:38 ─── ATTACK COMPLETE ─────────────────────────────────────────
         │  Total attack duration: ~3 minutes (Phase 2-6)
         │  Total API calls by attacker: ~20 management events
         │  Data stolen: Lambda source code, DB_PASS, lateral IAM keys,
         │               production database credentials
```

---

## 8. Lessons Learned

1. **IMDSv1 is the root cause.** If IMDSv2 had been enforced, the container exploitation would not have yielded IAM credentials. This single configuration change would have prevented the entire attack chain.

2. **CloudTrail `StopLogging` must be prevented, not just detected.** Use an SCP to deny `cloudtrail:StopLogging` from all non-admin principals. Detection alone allows the attacker to blind you before the alert fires.

3. **EC2 roles with `iam:CreateUser` are a critical finding.** No compute workload should ever need IAM write permissions. This is a privilege escalation vector.

4. **Terraform state files containing credentials are time bombs.** Use dynamic credentials (IAM roles, OIDC federation) instead of static access keys in Terraform. If static keys must exist, encrypt the state file and restrict S3 access.

5. **SecretsManager access from EC2 roles should be scoped.** Use resource-based policies or IAM conditions to restrict which secrets a role can access, not blanket `secretsmanager:*`.

6. **S3 data event logging is essential for incident response.** Without it, we cannot confirm what objects the attacker downloaded. In this incident, the S3 enumeration and Terraform state theft are only inferred from subsequent lateral movement.

7. **The naming-convention bypass is a real vulnerability.** IAM policies using `admin*` patterns are case-sensitive by default. Always use `StringEqualsIgnoreCase` or exact ARN matching.

8. **GuardDuty would have caught this.** The `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` finding fires when EC2 role credentials are used from outside AWS or from a different IP. This is a solved detection problem — enable GuardDuty.
