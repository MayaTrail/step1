# SCARLETEEL 2.0 Incident Response — Alert-Driven Investigation

> **Start here when you get paged.** This playbook begins from the highest-signal alert (`StopLogging`) and works backward and forward to reconstruct the full attack. For the chronological kill-chain walkthrough, see [SCARLETEEL-V2-CHRONOLOGICAL](SCARLETEEL-V2-CHRONOLOGICAL.md).

## How This Playbook Works

In SCARLETEEL 2.0, `StopLogging` happens at Phase 4 — after IAM recon, privilege escalation probes, and S3/Lambda enumeration. But it's the **loudest alert** and the one most likely to page you. From this single event, you extract three pivot fields (principal, source IP, timestamp) and use them to unravel everything the attacker did before, during, and after they blinded you.

**v2 upgrade over v1:** The attacker now deliberately times their most sensitive operations (SecretsManager theft, lateral movement) for the blind window AFTER `StopLogging`. Your investigation must cover both sides of the blind window.

```
                 ATTACK ORDER                              INVESTIGATION ORDER
                 ───────────                               ────────────────────
Phase 1: Container RCE + IMDS theft     ◄──── Step 7: Confirm initial access vector
Phase 1: Cryptominer + Pandora (host)   ◄──── Step 7: EC2 forensic image analysis
Phase 2: Pacu IAM recon                 ◄──── Step 3: Backward pivot on principal
Phase 2: CreateUser+DeleteUser probe    ◄──── Step 3: Backward pivot on principal
Phase 2: AdminJoe naming bypass         ◄──── Step 3: Backward pivot on principal
Phase 3: S3 + Lambda enumeration        ◄──── Step 3: Backward pivot on principal
Phase 4: StopLogging ◀━━━━━━━━━━━━━━━━━━━━━━━ Step 1: START HERE
Phase 5: Terraform state cred theft     ◄──── Step 4: Blind window analysis
Phase 6: Lateral movement (bait user)   ◄──── Step 5: Source IP pivot (new principals)
Phase 6: SecretsManager harvest         ◄──── Step 4: Blind window analysis (both IPs!)
```

---

## Classification

| Field | Value |
|-------|-------|
| **Incident Type** | Cloud Infrastructure Compromise — Credential Theft, Data Exfiltration, Defense Evasion, Secret Theft |
| **Threat Actor** | SCARLETEEL 2.0 |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1190, T1552.005, T1136.003, T1070.004, T1098.001, T1526, T1530, T1562.008, T1078.004, T1528 |
| **Primary Alert** | `cloudtrail:StopLogging` — zero false positive rate in production |
| **Source Intelligence** | [Sysdig SCARLETEEL 2.0](https://www.sysdig.com/blog/scarleteel-2-0/) |

---

## Step 0: Re-Enable CloudTrail (Before Everything Else)

> **Do this NOW. Do not read further until logging is restored.**

```bash
aws cloudtrail start-logging \
  --name <TRAIL_NAME> \
  --region <REGION> \
  --profile <IR_PROFILE>
```

Verify:

```bash
aws cloudtrail get-trail-status \
  --name <TRAIL_NAME> \
  --region <REGION> \
  --query "{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}" \
  --profile <IR_PROFILE>
```

If `start-logging` fails (trail may have been deleted):

```bash
aws cloudtrail describe-trails --trail-name-list <TRAIL_NAME> --region <REGION> --profile <IR_PROFILE>
# If empty: trail was deleted. Recreate it.
aws cloudtrail create-trail \
  --name <TRAIL_NAME> \
  --s3-bucket-name <TRAIL_BUCKET> \
  --region <REGION> --profile <IR_PROFILE>
aws cloudtrail start-logging --name <TRAIL_NAME> --region <REGION> --profile <IR_PROFILE>
```

**Record the blind window:**
- `BLIND_WINDOW_START` = `StopLogging` event timestamp
- `BLIND_WINDOW_END` = now (when you re-enabled logging)

---

## Step 1: Extract Pivot Fields from StopLogging

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    .Events[] | .CloudTrailEvent | fromjson |
    {eventTime, callerArn: .userIdentity.arn, sourceIP: .sourceIPAddress,
     userAgent, trail: .requestParameters.name,
     ec2RoleDelivery: .userIdentity.sessionContext.ec2RoleDelivery,
     instanceId: .userIdentity.inScopeOf.credentialsIssuedTo}'
```

You now have three pivot fields:

| Field | From Emulation | What It Tells You |
|-------|---------------|-------------------|
| **Principal** | `arn:aws:sts::940482414561:assumed-role/scarleteel-vuln-ec2-role-dea0778/i-0f94960b20ea0f589` | Compromised EC2 instance role — the `:i-` suffix confirms EC2 origin |
| **Source IP** | `122.162.145.217` | Attacker IP — compare to instance IP to confirm credential theft |
| **Timestamp** | `2026-04-11T12:12:25Z` | Everything before = pre-exfil recon. Everything after = blind window operations. |

**v2 bonus fields:**
- `ec2RoleDelivery: "1.0"` → confirms IMDSv1 (not IMDSv2)
- `userAgent: os/windows` → credentials used from Windows machine, EC2 runs Linux
- `inScopeOf.credentialsIssuedTo` → exact instance ARN

### Confirm Credential Exfiltration

```bash
aws ec2 describe-instances \
  --instance-ids <INSTANCE_ID_FROM_PRINCIPAL> \
  --query "Reservations[0].Instances[0].[PublicIpAddress,PrivateIpAddress]" \
  --output text --profile <IR_PROFILE>
```

If `sourceIPAddress` (122.162.145.217) ≠ instance IP (13.220.122.208) → **credential exfiltration confirmed**.

---

## Step 2: Immediate Containment

Based on confirmed credential exfiltration + StopLogging, go directly to **L2 containment**:

```bash
# Deny-all on the compromised role
aws iam put-role-policy \
  --role-name <COMPROMISED_ROLE_NAME> \
  --policy-name EmergencyDenyAll \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}' \
  --profile <IR_PROFILE>
```

**Rollback (after investigation):**
```bash
aws iam delete-role-policy --role-name <COMPROMISED_ROLE_NAME> --policy-name EmergencyDenyAll
```

---

## Step 3: Backward Pivot — What Did This Principal Do BEFORE StopLogging?

```bash
aws cloudtrail lookup-events \
  --start-time "<INCIDENT_START_TIME>" \
  --end-time "<STOP_LOGGING_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.userIdentity.arn == "<COMPROMISED_PRINCIPAL_ARN>")] |
    sort_by(.eventTime) |
    .[] | {eventTime, eventName, eventSource,
           sourceIP: .sourceIPAddress, errorCode,
           params: .requestParameters}'
```

**What you'll find (from emulation):**

### Phase 2 — IAM Recon + Priv Esc (12:10:36 → 12:10:52)

| Time | Event | Significance |
|------|-------|--------------|
| 12:10:36 | `ListUsers` (OK) | Pacu-style recon — enumerated 7 IAM users |
| 12:10:39 | `ListRoles` (OK) | Discovered 19 IAM roles |
| 12:10:42 | `CreateUser` "ScarleteelBackdoor" (OK) | Priv esc probe succeeded |
| 12:10:42 | `DeleteUser` "ScarleteelBackdoor" (OK) | **Evidence destruction — same second!** |
| 12:10:47 | `CreateAccessKey` for "adminJoe" (**AccessDenied**) | Permission boundary blocked lowercase `admin*` |
| 12:10:52 | `CreateAccessKey` for "AdminJoe" (**NoSuchEntity**) | **Boundary bypass confirmed!** Capital `A` evaded the deny condition. Error is NoSuchEntity (user doesn't exist), not AccessDenied. |

**Investigation action:** Check the permission boundary for case-sensitivity bugs:
```bash
aws iam get-role \
  --role-name <COMPROMISED_ROLE_NAME> \
  --query "Role.PermissionsBoundary" \
  --profile <IR_PROFILE>

# Then inspect the boundary policy:
aws iam get-policy-version \
  --policy-arn <BOUNDARY_POLICY_ARN> \
  --version-id v1 --profile <IR_PROFILE>
```

### Phase 3 — S3 + Lambda Enumeration (12:11:00 → 12:12:09)

| Time | Event | Significance |
|------|-------|--------------|
| 12:11:00 | `ListBuckets` (OK) | 16 buckets discovered |
| 12:12:07 | `ListFunctions` (OK) | Lambda function enumeration |
| 12:12:07 | `GetFunction` (OK) | **Source code URL generated** — code is downloadable |
| 12:12:07 | `ListVersionsByFunction` (OK) | **Env vars exposed** — `DB_PASS: SuperSecretCustomerPass123` |
| 12:12:08 | `ListTags`, `ListAliases`, `GetPolicy`, `ListEventSourceMappings` | Full Lambda deep-dive in 2 seconds |

**Critical gap:** S3 `ListObjectsV2` and `GetObject` are NOT in CloudTrail — these are data-plane events. The attacker enumerated objects in all 16 buckets and exfiltrated from 5 scarleteel-prefixed buckets, but you can't see this without S3 data event logging.

**Investigation action:** Check if S3 data events are enabled:
```bash
aws cloudtrail get-event-selectors --trail-name <TRAIL_NAME> --region <REGION> --profile <IR_PROFILE>
```

---

## Step 4: Blind Window Analysis — What Happened AFTER StopLogging?

`StopLogging` stops event delivery to S3, but `LookupEvents` API still records events (90-day retention):

```bash
aws cloudtrail lookup-events \
  --start-time "<STOP_LOGGING_TIME>" \
  --end-time "<BLIND_WINDOW_END>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(
       (.userIdentity.arn // "" | contains("<COMPROMISED_ROLE_NAME>")) or
       (.userIdentity.arn // "" | contains("<LATERAL_USERNAME>")) or
       .sourceIPAddress == "<ATTACKER_SOURCE_IP>" or
       .sourceIPAddress == "<ATTACKER_SOURCE_IPV6>"
     )] |
    sort_by(.eventTime) |
    .[] | {eventTime, eventName, sourceIP: .sourceIPAddress,
           principal: .userIdentity.arn, errorCode}'
```

**What you'll find (from emulation):**

| Time | Event | Principal | Source IP | Significance |
|------|-------|-----------|-----------|--------------|
| 12:12:53 | `GetCallerIdentity` | `bait-user-1d2e775` | 122.162.145.217 | **NEW PRINCIPAL!** Lateral movement with stolen Terraform state creds |
| 12:13:01 | `ListUsers` (AccessDenied) | `bait-user-1d2e775` | 122.162.145.217 | Lateral recon failed — zero-permission user |
| 12:13:05 | `ListSecrets` | `vuln-ec2-role/i-0f949...` | **2401:4900:...a7ad** | Secret enumeration — **NOTE: different IP (IPv6!)** |
| 12:13:05 | `GetSecretValue` | `vuln-ec2-role/i-0f949...` | **2401:4900:...a7ad** | **Production DB credentials stolen!** |

**v2-specific insight:** The attacker switches between IPv4 and IPv6 across AWS service endpoints. Your IP-based correlation MUST include both `<ATTACKER_SOURCE_IP>` AND `<ATTACKER_SOURCE_IPV6>`.

**Investigation action for lateral movement:** Where did the bait user creds come from?

```bash
# Check if Terraform state was accessed (S3 data event, if enabled)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    .Events[] | .CloudTrailEvent | fromjson |
    select(.requestParameters.key | contains("tfstate"))'
```

If no S3 data events, look for `ListObjectsV2` on any bucket containing `tf-state` or `terraform`:
```bash
# Proxy signal: ListBuckets shows the attacker discovered terraform state buckets
# In emulation: scarleteel-tf-state-4655237 was enumerated
```

---

## Step 5: Source IP Pivot — Find ALL Principals Used from Attacker IPs

```bash
# Check BOTH IPv4 and IPv6
for ip in "<ATTACKER_SOURCE_IP>" "<ATTACKER_SOURCE_IPV6>"; do
  echo "=== Principals from $ip ==="
  aws cloudtrail lookup-events \
    --start-time "<INCIDENT_START_TIME>" \
    --end-time "<INCIDENT_END_TIME>" \
    --region <REGION> --output json --profile <IR_PROFILE> | jq --arg ip "$ip" '
      [.Events[] | .CloudTrailEvent | fromjson |
       select(.sourceIPAddress == $ip)] |
      group_by(.userIdentity.arn) |
      map({principal: .[0].userIdentity.arn, count: length,
           events: [.[].eventName] | unique})'
done
```

**From emulation, you'll find three principals from the attacker IPs:**

1. `scarleteel-vuln-ec2-role-dea0778/i-0f94960b20ea0f589` — Stolen EC2 instance role (Phases 2-4, 6)
2. `scarleteel-bait-user-1d2e775` — Stolen from Terraform state (Phase 6)
3. `AWSReservedSSO_AdministratorAccess.../abhi` — Your admin account (Pulumi deployment — expected, filter out)

The first two are attack principals. Investigate both fully.

---

## Step 6: Containment — Stolen Credentials

Now that you've identified all compromised principals:

### Lateral Movement User (from Terraform state)

```bash
# Deactivate all access keys for the lateral user
aws iam list-access-keys --user-name <LATERAL_USERNAME> --profile <IR_PROFILE>
aws iam update-access-key \
  --user-name <LATERAL_USERNAME> \
  --access-key-id <KEY_ID> \
  --status Inactive --profile <IR_PROFILE>
```

### Emergency Secret Rotation

```bash
# Rotate the stolen secret immediately
aws secretsmanager rotate-secret \
  --secret-id prod/database/master_credentials \
  --region <REGION> --profile <IR_PROFILE>

# ALSO change the actual database password — rotating the secret
# without changing the DB password is insufficient!
```

---

## Step 7: Confirm Initial Access Vector

The EC2 instance was compromised via container RCE + IMDSv1. Verify:

```bash
# Check IMDS configuration
aws ec2 describe-instances \
  --instance-ids <COMPROMISED_INSTANCE_ID> \
  --query "Reservations[0].Instances[0].MetadataOptions" \
  --output json --profile <IR_PROFILE>
```

Expected finding: `HttpTokens: "optional"` (IMDSv1 enabled), `HttpPutResponseHopLimit: 2` (container IMDS access enabled).

### Host-Level Forensics

Create a forensic image before terminating:

```bash
aws ec2 create-image \
  --instance-id <COMPROMISED_INSTANCE_ID> \
  --name "forensic-scarleteel-v2-$(date +%Y%m%d)" \
  --no-reboot --profile <IR_PROFILE>
```

On the forensic image, look for:
- `/root/.configure/containerd` — XMRig miner masquerading as containerd
- `/root/.configure/pandora` — Pandora (Mirai) DDoS bot
- `/etc/systemd/system/containered.service` — Persistent miner service
- `/opt/vuln-app/` — Vulnerable Flask webapp with RCE endpoint
- `iptables -L` — Rules will be flushed (empty)
- `history` — Will be empty (attacker ran `history -cw` after each phase)

---

## Step 8: Full Evidence Export

```bash
# Export all attack events
aws cloudtrail lookup-events \
  --start-time "<INCIDENT_START_TIME>" \
  --end-time "<INCIDENT_END_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> > /tmp/scarleteel_v2_full.json

# Filter to attack-only events
cat /tmp/scarleteel_v2_full.json | jq '
  [.Events[] | .CloudTrailEvent | fromjson |
   select(
     (.userIdentity.arn // "" | contains("<COMPROMISED_ROLE_NAME>")) or
     (.userIdentity.arn // "" | contains("<LATERAL_USERNAME>"))
   ) |
   select(.eventName != "UpdateInstanceInformation" and
          .eventName != "ListInstanceAssociations")] |
  sort_by(.eventTime)' > /tmp/scarleteel_v2_attack_only.json

# Upload to forensic bucket
aws s3 cp /tmp/scarleteel_v2_full.json s3://forensic-scarleteel-v2-<INCIDENT_ID>/cloudtrail/ --profile <IR_PROFILE>
aws s3 cp /tmp/scarleteel_v2_attack_only.json s3://forensic-scarleteel-v2-<INCIDENT_ID>/cloudtrail/ --profile <IR_PROFILE>
```

---

## Step 9: Recovery & Hardening

See [SCARLETEEL-V2-CHRONOLOGICAL, Section 5](SCARLETEEL-V2-CHRONOLOGICAL.md#5-recovery--hardening) for the full recovery checklist.

**Priority 1 (do today):**
1. Enforce IMDSv2 account-wide (SCP)
2. SCP preventing `StopLogging` from non-SecurityAdmin roles
3. SCP blocking IAM writes from compute roles
4. Fix the case-sensitive permission boundary
5. Rotate ALL compromised credentials (EC2 role, Lambda env vars, SecretsManager secrets, Terraform state keys)

**Priority 2 (this week):**
1. Enable GuardDuty
2. Enable S3 data event logging
3. SecretsManager resource policies
4. EventBridge auto-remediation for StopLogging
5. Automatic secret rotation (30-day max)

---

## Investigation Checklist Summary

- [ ] **Step 0:** Re-enable CloudTrail logging
- [ ] **Step 1:** Extract principal, source IP, timestamp from `StopLogging`
- [ ] **Step 2:** Contain — deny-all on compromised role
- [ ] **Step 3:** Backward pivot — reconstruct Phases 2-3 (IAM recon, S3/Lambda enum)
- [ ] **Step 4:** Blind window — find Phases 5-6 (lateral movement, secret theft)
- [ ] **Step 5:** Source IP pivot — find ALL principals (check both IPv4 and IPv6!)
- [ ] **Step 6:** Contain stolen creds — deactivate lateral keys, rotate secrets
- [ ] **Step 7:** Confirm initial access — IMDSv1 + container RCE
- [ ] **Step 8:** Export evidence to forensic bucket
- [ ] **Step 9:** Harden — IMDSv2 SCP, StopLogging SCP, IAM write SCP, fix boundary, rotate everything
