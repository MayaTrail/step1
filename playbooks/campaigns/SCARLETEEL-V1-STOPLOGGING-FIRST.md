# SCARLETEEL Incident Response — Alert-Driven Investigation

> **Start here when you get paged.** This playbook begins from the highest-signal alert (`StopLogging`) and works backward and forward to reconstruct the full attack. For the chronological kill-chain walkthrough, see [SCARLETEEL-V1-CHRONOLOGICAL](SCARLETEEL-V1-CHRONOLOGICAL.md). For the SCARLETEEL 2.0 variant with SecretsManager theft and permission boundary bypass, see [SCARLETEEL-V2-STOPLOGGING-FIRST](SCARLETEEL-V2-STOPLOGGING-FIRST.md).

## How This Playbook Works

In the SCARLETEEL attack chain, `StopLogging` happens at Phase 4 — after initial access, privilege escalation, and data enumeration. But it's the **loudest alert** and the one most likely to page you. From this single event, you extract three pivot fields (principal, source IP, timestamp) and use them to unravel everything the attacker did before, during, and after they blinded you.

```
                 ATTACK ORDER                              INVESTIGATION ORDER
                 ───────────                               ────────────────────
Phase 1: Container RCE + IMDS theft     ◄──── Step 6: Confirm initial access vector
Phase 2: IAM recon + priv esc           ◄──── Step 2: Backward pivot on principal
Phase 3: S3 + Lambda enumeration        ◄──── Step 2: Backward pivot on principal
Phase 4: StopLogging ◀━━━━━━━━━━━━━━━━━━━━━━━ Step 1: START HERE
Phase 5: Terraform state cred theft     ◄──── Step 4: Blackout window analysis
Phase 6: Lateral movement               ◄──── Step 3: Source IP pivot
```

---

## Classification

| Field | Value |
|-------|-------|
| **Incident Type** | Cloud Infrastructure Compromise — Credential Theft, Data Exfiltration, Defense Evasion |
| **Threat Actor** | SCARLETEEL |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1190, T1552.005, T1098.001, T1526, T1530, T1562.008, T1078.004 |
| **Primary Alert** | `cloudtrail:StopLogging` — zero false positive rate in production |
| **Source Intelligence** | [Sysdig SCARLETEEL](https://www.sysdig.com/blog/cloud-breach-terraform-data-theft/) |

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
  --s3-bucket-name <LOG_BUCKET> \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --region <REGION> --profile <IR_PROFILE>
aws cloudtrail start-logging --name <TRAIL_NAME> --region <REGION> --profile <IR_PROFILE>
```

---

## Step 1: Anchor on the StopLogging Event

Pull the full event and extract every field that drives the investigation.

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time "<INCIDENT_START_TIME>" \
  --region <REGION> --max-results 5 --output json --profile <IR_PROFILE> | jq '
    .Events[] |
    .CloudTrailEvent | fromjson |
    {
      eventTime,
      callerArn: .userIdentity.arn,
      principalId: .userIdentity.principalId,
      sourceIP: .sourceIPAddress,
      userAgent,
      trailARN: .requestParameters.name,
      errorCode
    }'
```

You now have three pivot fields:

| Field | What It Tells You |
|-------|-------------------|
| `callerArn` | Compromised principal — the `:i-` suffix confirms EC2 origin |
| `sourceIP` | Attacker IP — compare to instance IP to confirm credential exfiltration |
| `eventTime` | The exact moment visibility ended. Everything after = blind window. |

### Confirm credential exfiltration:

```bash
aws ec2 describe-instances \
  --instance-ids <INSTANCE_ID_FROM_PRINCIPAL> \
  --query "Reservations[0].Instances[0].[PublicIpAddress,PrivateIpAddress]" \
  --output text --profile <IR_PROFILE>
```

If `sourceIPAddress` != instance IP → **credential exfiltration confirmed**.

### Check all trails across all regions:

```bash
for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  trails=$(aws cloudtrail describe-trails --region "$region" --query "trailList[].Name" --output text 2>/dev/null)
  for trail in $trails; do
    status=$(aws cloudtrail get-trail-status --name "$trail" --region "$region" --query "IsLogging" --output text 2>/dev/null)
    echo "$region | $trail | IsLogging=$status"
  done
done
```

---

## Step 2: Backward Pivot on Principal

Everything the attacker did **before** `StopLogging` is recorded in CloudTrail.

```bash
aws cloudtrail lookup-events \
  --start-time "<INCIDENT_START_TIME>" \
  --end-time "<STOP_LOGGING_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.userIdentity.arn == "<COMPROMISED_PRINCIPAL_ARN>")] |
    sort_by(.eventTime) |
    .[] | {eventTime, eventName, sourceIP: .sourceIPAddress, errorCode}'
```

### What the backward pivot reveals:

| Attack Phase | Events | Significance |
|---|---|---|
| **Phase 2 — Priv Esc** | `CreateUser` (AccessDenied), `CreateAccessKey` (AccessDenied) | Privilege escalation blocked by insufficient permissions |
| **Phase 3 — S3 Enum** | `ListBuckets` | Full bucket inventory — all buckets now known to attacker |
| **Phase 3 — Lambda Theft** | `ListFunctions`, `GetFunction`, `ListVersionsByFunction` | Source code URL generated + env vars exposed |
| **Phase 3 — Lambda Recon** | `GetPolicy`, `ListAliases`, `ListTags`, `ListEventSourceMappings` | Full Lambda deep-dive in seconds |
| **Phase 4 — Recon** | `DescribeTrails` | Identified the trail to disable |

---

## Step 3: Source IP Pivot — Detect Lateral Movement

Query all API calls from the attacker's IP regardless of principal. This catches credential pivots.

```bash
aws cloudtrail lookup-events \
  --start-time "<INCIDENT_START_TIME>" \
  --end-time "<INCIDENT_END_TIME>" \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] |
     .CloudTrailEvent | fromjson |
     select(.sourceIPAddress == "<ATTACKER_SOURCE_IP>")] |
    group_by(.userIdentity.arn) |
    map({principal: .[0].userIdentity.arn, count: length,
         events: [.[].eventName] | unique})'
```

If a second principal appears from the same attacker IP, the attacker obtained additional credentials — likely from Terraform state files, Lambda environment variables, or other credential stores accessed during the attack.

---

## Step 4: Blackout Window Analysis

`StopLogging` stops event delivery to S3, but `LookupEvents` still works (90-day retention):

```bash
aws cloudtrail lookup-events \
  --start-time "<STOP_LOGGING_TIME>" \
  --end-time "<INCIDENT_END_TIME>" \
  --region <REGION> --max-results 50 --output json --profile <IR_PROFILE> | jq '
    [.Events[] |
     .CloudTrailEvent | fromjson |
     select(.sourceIPAddress == "<ATTACKER_SOURCE_IP>")] |
    sort_by(.eventTime) |
    .[] | {eventTime, eventName, principal: .userIdentity.arn, errorCode}'
```

### What's visible vs. invisible during the blind window:

| Log Source | Available? | What it captures |
|---|---|---|
| CloudTrail S3 delivery | **NO** | Nothing — this is the point of the attack |
| CloudTrail `LookupEvents` API | **YES** (90-day retention) | Management events only |
| S3 Server Access Logs | **YES** (if enabled) | Per-request `GetObject`/`PutObject` |
| VPC Flow Logs | **YES** (if enabled) | Network connections to/from the instance |
| GuardDuty | **YES** (independent) | `InstanceCredentialExfiltration.OutsideAWS` |

---

## Step 5: Blast Radius Scoping

Determine the maximum possible damage by examining the compromised role's permissions:

```bash
# Inline policies
aws iam list-role-policies --role-name <COMPROMISED_ROLE_NAME> --profile <IR_PROFILE>
aws iam get-role-policy \
  --role-name <COMPROMISED_ROLE_NAME> \
  --policy-name <POLICY_NAME> \
  --output json --profile <IR_PROFILE> | jq '.PolicyDocument'

# Attached managed policies
aws iam list-attached-role-policies --role-name <COMPROMISED_ROLE_NAME> --profile <IR_PROFILE>
```

For each allowed action with `Resource: *`, assume the attacker exercised it during the blind window.

---

## Step 6: Confirm Initial Access Vector

```bash
aws ec2 describe-instances \
  --instance-ids <COMPROMISED_INSTANCE_ID> \
  --query "Reservations[0].Instances[0].MetadataOptions" \
  --output json --profile <IR_PROFILE>
```

If `HttpTokens: "optional"` → IMDSv1 enabled.
If `HttpPutResponseHopLimit >= 2` → Containers can reach IMDS via Docker bridge.

**No CloudTrail evidence exists for Phase 1.** Container RCE and IMDS credential theft are data-plane operations. Detection requires VPC Flow Logs or host-level monitoring.

---

## Step 7: Containment

### L1 — Soft (Immediate)

```bash
# Revoke all sessions issued before incident
aws iam put-role-policy \
  --role-name <COMPROMISED_ROLE_NAME> \
  --policy-name EmergencyRevokeOldSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<INCIDENT_START_TIME>"}}}]}' \
  --profile <IR_PROFILE>

# Deactivate lateral movement access keys
aws iam update-access-key \
  --user-name <LATERAL_USERNAME> \
  --access-key-id <KEY_ID> \
  --status Inactive --profile <IR_PROFILE>
```

**Rollback:** `aws iam delete-role-policy --role-name <COMPROMISED_ROLE_NAME> --policy-name EmergencyRevokeOldSessions`

### L2 — Hard (Confirmed Compromise)

> Before L2, check: `aws ec2 describe-tags --filters "Name=resource-id,Values=<INSTANCE_ID>" "Name=key,Values=Critical-Production-App"`

```bash
# Deny-all on compromised role
aws iam put-role-policy \
  --role-name <COMPROMISED_ROLE_NAME> \
  --policy-name EmergencyDenyAll \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}' \
  --profile <IR_PROFILE>
```

### L3 — Nuclear (Active Exfiltration)

```bash
# Isolate instance
aws ec2 modify-instance-attribute \
  --instance-id <COMPROMISED_INSTANCE_ID> \
  --groups <QUARANTINE_SG_ID> --profile <IR_PROFILE>

# Snapshot for forensics and stop
aws ec2 create-image \
  --instance-id <COMPROMISED_INSTANCE_ID> \
  --name "forensic-scarleteel-$(date +%Y%m%d)" \
  --no-reboot --profile <IR_PROFILE>
aws ec2 stop-instances --instance-ids <COMPROMISED_INSTANCE_ID> --profile <IR_PROFILE>
```

---

## Step 8: Rotate All Exposed Secrets

| Secret | Where Exposed | Action |
|--------|---------------|--------|
| EC2 instance role temp creds | IMDS → attacker IP | Revoked via session policy (Step 7 L1) |
| IAM user permanent key | `terraform.tfstate` in S3 | Deactivate + delete, generate new |
| Lambda `DB_PASS` | `ListVersionsByFunction` | Rotate database password immediately |
| S3 bucket contents | `GetObject` on multiple buckets | Audit all objects for secrets/PII |

---

## Step 9: Hardening (Never Again)

| Fix | Priority | Implementation |
|-----|----------|----------------|
| Enforce IMDSv2 account-wide | P1 | SCP denying `ec2:RunInstances` unless `ec2:MetadataHttpTokens == "required"` |
| Prevent CloudTrail disable | P1 | SCP denying `cloudtrail:StopLogging`/`DeleteTrail` for non-SecurityAdmin roles |
| Auto-remediate StopLogging | P1 | EventBridge rule → Lambda that calls `start-logging` |
| Scope EC2 role permissions | P1 | Remove `Resource: *`, scope to specific bucket/function ARNs |
| Enable S3 data event logging | P2 | `put-event-selectors` to capture `GetObject`/`PutObject` |
| Enable GuardDuty | P2 | Detects `InstanceCredentialExfiltration.OutsideAWS` independently |
| Move secrets to SecretsManager | P2 | Remove `DB_PASS` from Lambda env vars, fetch at runtime |
| Encrypt Terraform state | P2 | SSE-KMS on state bucket, never embed IAM keys in state |

---

## Investigation Checklist Summary

- [ ] **Step 0:** Re-enable CloudTrail logging
- [ ] **Step 1:** Extract principal, source IP, timestamp from `StopLogging`
- [ ] **Step 2:** Backward pivot — reconstruct Phases 2-3 (IAM recon, S3/Lambda enum)
- [ ] **Step 3:** Source IP pivot — find lateral movement principals
- [ ] **Step 4:** Blind window — find Phases 5-6 via LookupEvents
- [ ] **Step 5:** Blast radius — audit compromised role's permissions
- [ ] **Step 6:** Confirm initial access — IMDSv1 + container RCE
- [ ] **Step 7:** Contain — revoke sessions, deny-all, quarantine instance
- [ ] **Step 8:** Rotate all exposed secrets
- [ ] **Step 9:** Harden — IMDSv2 SCP, StopLogging SCP, least-privilege roles

---

## IOCs

| Type | Value | Context |
|------|-------|---------|
| IP | `<ATTACKER_SOURCE_IP>` | All malicious API calls from stolen credentials |
| IP | `<INSTANCE_PUBLIC_IP>` | Compromised EC2 host |
| Instance | `<COMPROMISED_INSTANCE_ID>` | Container host with IMDSv1 |
| IAM Role | `<COMPROMISED_ROLE_NAME>` | Over-privileged EC2 instance role |
| IAM User | `<LATERAL_USERNAME>` | Lateral movement target from Terraform state |
| CloudTrail | `<TRAIL_NAME>` | Disabled trail |
| Systemd | `containered.service` | XMRig miner masquerading as containerd |
| File | `/root/.configure/containerd` | Miner binary path |
| File | `/tmp/config_background.json` | XMRig pool config |
| Domain | `hb.bizmrg.com` | Russian S3 endpoint for CloudTrail-evading exfil |
| Pool | `pool.c3pool.com:13333` | XMRig mining pool |

---

## MITRE ATT&CK Coverage

| Technique | Name | Where in This Playbook |
|-----------|------|----------------------|
| T1190 | Exploit Public-Facing Application | Step 6 — Initial access via container RCE |
| T1552.005 | Cloud Instance Metadata API | Step 6 — IMDSv1 credential theft |
| T1098.001 | Additional Cloud Credentials | Step 2 — CreateUser/CreateAccessKey attempts |
| T1526 | Cloud Service Discovery | Step 2 — ListBuckets, ListFunctions |
| T1530 | Data from Cloud Storage Object | Step 2, 4 — S3 + Lambda exfiltration |
| T1552.001 | Credentials in Files | Step 4 — terraform.tfstate credential theft |
| T1562.008 | Disable Cloud Logs | Step 1 — StopLogging (the anchor event) |
| T1078.004 | Valid Accounts: Cloud Accounts | Step 3 — Lateral movement with stolen creds |

---

## Verified Against Emulation Logs

Validated against CloudTrail events from SCARLETEEL v1 emulation on 2026-04-05:

| Time (UTC) | Event | Principal | Source IP | Result |
|---|---|---|---|---|
| 19:34:10 | `CreateUser` | `vuln-ec2-role/i-0aea82a9977cd62a4` | 122.162.144.65 | AccessDenied |
| 19:34:10 | `CreateAccessKey` | `vuln-ec2-role/i-0aea82a9977cd62a4` | 122.162.144.65 | AccessDenied |
| 19:34:11 | `ListBuckets` | `vuln-ec2-role/i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:32 | `ListFunctions` | `vuln-ec2-role/i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:32 | `GetFunction` | `vuln-ec2-role/i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:34 | `ListVersionsByFunction` | `vuln-ec2-role/i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:35 | `DescribeTrails` | `vuln-ec2-role/i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:37 | `StopLogging` | `vuln-ec2-role/i-0aea82a9977cd62a4` | 122.162.144.65 | OK |
| 19:34:41 | `GetCallerIdentity` | `scarleteel-secondary-user-d039ffc` | 122.162.144.65 | OK |
| 19:34:42 | `ListUsers` | `scarleteel-secondary-user-d039ffc` | 122.162.144.65 | AccessDenied |

**Total attack duration:** 32 seconds. **Instance IP:** 18.206.59.212 | **Attacker IP:** 122.162.144.65.
