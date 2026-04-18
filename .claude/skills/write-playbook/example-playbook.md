# Playbook: S3 Data Exfiltration & Compromise Response

**ID:** PB-AWS-S3-DATA-01 | **Version:** 2.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Context Wrapper

- **Scenario:** Unauthorized access, mass download, or public exposure of private S3 data.
- **Trigger:** GuardDuty Findings (e.g., `S3:CompromisedData`), Spike in `GetObject` API calls, or User Report.
- **Severity Matrix:**
  - **CRITICAL:** Public Bucket + PII/Financial Data identified via Macie. **Action:** Wake CISO & Legal immediately.
  - **HIGH:** Confirmed Exfiltration (Volume > 10GB) but Internal/VPN Source.
  - **MEDIUM:** Suspicious calls, no data movement confirmed.
- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (S3 Data Events), S3 Server Access Logs, GuardDuty enabled
  - Tools: AWS CLI, Athena, Macie (optional)
- **MITRE ATT&CK Mapping:**
  - T1537: Cloud Data Transfer
  - T1098: Account Manipulation

---

## 2. Triage & Validation Logic

### Step 2.1: Automated Enrichment (Tool Actions)

1. **Verify Public Status:** Run `aws s3api get-public-access-block` and `get-bucket-policy` to confirm if the bucket is actually exposed.
2. **IP Reputation:** Check Source IP against Threat Intel (GreyNoise/VirusTotal) and Corporate VPN list.
3. **User Context:** Is the user `dev-ops-admin` accessing this during their normal hours?

### Step 2.2: The "Is It Real?" Decision Gate

- IF `PublicAccess == True` AND `Data == Sensitive`: **Go to Containment Level 2 (IMMEDIATE).**
- IF `Source_IP == Known_Vendor` AND `Volume < 1GB`: **Mark False Positive & Close.**
- IF `Finding == GuardDuty` AND `User == Anomalous`: **Go to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action (Command) | Rollback (Safety Net) |
|---|---|---|---|
| **L1 (Soft)** | Suspicious IP, Low Volume | **Block IP:** Apply Bucket Policy `bucket-policy-ip.json` restricting specific Source IPs. | `aws s3api delete-bucket-policy --bucket <name>` |
| **L2 (Hard)** | Confirmed Data Exfil | **Lockdown:** Apply `bucket-policy-ir.json` (Deny All except IR Role). | `aws s3api delete-bucket-policy --bucket <name>` |
| **L3 (User)** | Compromised Creds | **Revoke:** Deactivate Access Keys: `aws iam update-access-key --status Inactive`. | `aws iam update-access-key --status Active` |
| **L3 (Role)** | Compromised Role | **Deny:** Attach Inline Deny Policy to Role/User. | `aws iam delete-user-policy --policy-name EmergencyDenyAll` |

---

## 4. Investigation & Forensics (Deep Dive)

### 4.1 Scope Assessment

- **List Affected Objects:** Run `aws s3 ls s3://<bucket>/ --recursive` to see what files are at risk.
- **Check Lateral Movement:** Query CloudTrail to see if the same User accessed other buckets.
- **Volume Analysis:** Count GET requests by IP to quantify data loss:
  ```
  grep "REST.GET.OBJECT" ./s3-logs/* | awk '{print $8}' | sort | uniq -c
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, eventsource, eventname, sourceipaddress, useragent
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('GetObject', 'PutObject', 'DeleteObject')
  AND requestparameters LIKE '%<bucket-name>%'
ORDER BY eventtime DESC;
```

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:** `aws s3 mb s3://forensic-evidence-<id>`
2. **Secure It:** Enable Encryption & Block Public Access immediately.
3. **Copy Logs:** Sync CloudTrail/S3 Logs to this new forensic bucket.

---

## 5. Recovery & Eradication

1. **Sanitize Credentials:** Rotate all keys for the affected user. Delete the old keys.
2. **Restore Data:** If data was deleted/ransomwared, restore from Versioning.
3. **Hardening (The "Never Again" Fix):**
   - Enable **MFA Delete** on critical buckets.
   - Implement **S3 Object Lock** for compliance data.
4. **Verification:** Attempt to access the bucket from a non-whitelisted IP. Ensure it fails (Access Denied).

---

## 6. Post-Incident Review

- **Timeline:** Detection Time vs. Containment Time.
- **Gap Analysis:** Did GuardDuty detect this? If not, why?
- **Policy Update:** Do we need a new SCP (Service Control Policy) to prevent public buckets globally?
