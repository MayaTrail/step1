# IR Playbook: ATOMIC-guardduty-impair — AWS GuardDuty Impairment

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense Evasion — Security Tool Tampering |
| Threat Actor | ATOMIC-guardduty-impair (technique emulation) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Defense Evasion (TA0005) |
| MITRE Techniques | T1685 — Disable or Modify Tools |
| Attack Surface | AWS GuardDuty, STS, IAM, S3 |

---

## 1. Preparation

### Prerequisites Before This Incident

- **CloudTrail** enabled in all regions with management events logging (read + write). Multi-region trail strongly recommended.
- **GuardDuty** enabled with findings delivered to EventBridge and/or SNS for real-time alerting.
- **AWS Config** recording IAM, GuardDuty, and S3 resource changes.
- **Security Hub** aggregating GuardDuty findings centrally.
- **SCPs or IAM permission boundaries** blocking `guardduty:DeleteDetector`, `guardduty:DisassociateFromMasterAccount`, and `guardduty:UpdateDetector` for non-security principals (the deny guard in this lab emulates this).
- **Least-privilege posture** for IAM roles: roles outside the security team should not hold `guardduty:CreateIPSet`, `guardduty:CreateFilter`, or `guardduty:UpdateDetector`.
- **Alerting rule** on CloudTrail for GuardDuty-modifying API calls from any non-security-team principal — including `errorCode=AccessDenied` events (denial does NOT mean safe; see Steps 7–8).
- **Baseline** of all existing GuardDuty IPSets and suppression filters documented and stored in a CMDB or version control.
- **Runbook tested** for detector restore: know your detector ID and baseline `findingPublishingFrequency` before an incident.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Events that always indicate compromise or attempted tampering

| Event Name | Source | Why High-Confidence |
|---|---|---|
| `CreateIPSet` | guardduty.amazonaws.com | No legitimate automation creates GuardDuty IPSets outside change windows; any external-principal creation is suspect |
| `CreateFilter` with `action=ARCHIVE` | guardduty.amazonaws.com | Suppression filters from non-security principals are almost always attacker behavior |
| `UpdateDetector` reducing `findingPublishingFrequency` | guardduty.amazonaws.com | Legitimate changes only increase frequency; decrease indicates deliberate blinding |
| `DeleteDetector` (even `AccessDenied`) | guardduty.amazonaws.com | Intent to destroy the detector is high-confidence IOC regardless of success |
| `DeletePublishingDestination` (even `AccessDenied`) | guardduty.amazonaws.com | Intent to blind log export; `AccessDenied` on this call must NOT be filtered |

#### MEDIUM-CONFIDENCE — Events that warrant investigation

| Event Name | Source | Context |
|---|---|---|
| `AssumeRole` into a broad-GuardDuty-scope role | sts.amazonaws.com | Normal for automated pipelines; investigate if role is assumed outside business hours or from unexpected source IP |
| `ListDetectors` + `GetDetector` in rapid succession | guardduty.amazonaws.com | Reconnaissance pattern; benign if from security tooling, suspicious from generic compute or CI roles |
| `PutObject` to a bucket with a security-team-like name | s3.amazonaws.com | Staging a trusted-IP list; check bucket name, key name, and calling principal |
| `GetCallerIdentity` immediately after `AssumeRole` | sts.amazonaws.com | Common attacker confirmation step; alone it is weak, but combined with subsequent GD calls it corroborates a chain |
| `DeleteFilter` / `DeleteIPSet` from the same session as `CreateFilter` / `CreateIPSet` | guardduty.amazonaws.com | Cleanup after attack; session coherence confirms the full chain |

---

### Key Investigation Queries

#### 1. Find all GuardDuty-modifying events in the last 24 hours (including denied calls)

```bash
# List all GuardDuty events — include AccessDenied (do NOT add --query filtering on errorCode)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=guardduty.amazonaws.com \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].{Time:EventTime,Name:EventName,User:Username,Error:CloudTrailEvent}' \
  --output table
```

#### 2. Isolate the high-risk write events specifically

```bash
for EVENT in CreateIPSet CreateFilter UpdateDetector DeleteDetector \
             DeletePublishingDestination DeleteFilter DeleteIPSet; do
  echo "=== $EVENT ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EVENT \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --query 'Events[*].CloudTrailEvent' \
    --output text | python3 -m json.tool 2>/dev/null || echo "(none)"
done
```

#### 3. Find all AssumeRole calls from the suspected attacker role

```bash
# Replace ACCOUNT_ID and ROLE_NAME with values from your environment
ROLE_ARN="arn:aws:iam::ACCOUNT_ID:role/atomic-guardduty-impair-attacker-role"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query "Events[?contains(CloudTrailEvent, 'atomic-guardduty-impair-attacker-role')].CloudTrailEvent" \
  --output text | python3 -m json.tool
```

#### 4. Enumerate all current GuardDuty IPSets (look for unauthorized entries)

```bash
REGION=us-east-1   # adjust to your region
DETECTOR_ID=$(aws guardduty list-detectors --region $REGION \
  --query 'DetectorIds[0]' --output text)

echo "Detector: $DETECTOR_ID"

# List all IPSets
aws guardduty list-ip-sets \
  --detector-id $DETECTOR_ID \
  --region $REGION

# Describe each IPSet for S3 location and status
for IPSET_ID in $(aws guardduty list-ip-sets --detector-id $DETECTOR_ID \
  --region $REGION --query 'IpSetIds[]' --output text); do
  echo "--- IPSet $IPSET_ID ---"
  aws guardduty get-ip-set \
    --detector-id $DETECTOR_ID \
    --ip-set-id $IPSET_ID \
    --region $REGION
done
```

#### 5. Enumerate all suppression filters and check for ARCHIVE actions

```bash
aws guardduty list-filters \
  --detector-id $DETECTOR_ID \
  --region $REGION

for FILTER_NAME in $(aws guardduty list-filters \
  --detector-id $DETECTOR_ID --region $REGION \
  --query 'FilterNames[]' --output text); do
  echo "--- Filter: $FILTER_NAME ---"
  aws guardduty get-filter \
    --detector-id $DETECTOR_ID \
    --filter-name $FILTER_NAME \
    --region $REGION
done
```

#### 6. Check current detector publishing frequency (look for SIX_HOURS)

```bash
aws guardduty get-detector \
  --detector-id $DETECTOR_ID \
  --region $REGION \
  --query '{Status:Status,FrequencyMinutes:FindingPublishingFrequency,CreatedAt:CreatedAt}'
```

#### 7. Check S3 for staged trusted-IP files

```bash
# Scan buckets with security-sounding names for suspicious objects
for BUCKET in $(aws s3api list-buckets \
  --query 'Buckets[?contains(Name,`guardduty`) || contains(Name,`trusted`) || contains(Name,`security`)].Name' \
  --output text); do
  echo "=== Bucket: $BUCKET ==="
  aws s3api list-object-versions --bucket $BUCKET \
    --query 'Versions[*].{Key:Key,LastModified:LastModified,ETag:ETag}' \
    --output table 2>/dev/null
done
```

#### 8. Correlate full session activity from the attacker role

```bash
# Pull all events from the attacker assumed-role session
SESSION_NAME="AtomicT1685GuardDutyImpair"   # from attack plan RoleSessionName

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="assumed-role/atomic-guardduty-impair-attacker-role/$SESSION_NAME" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].{Time:EventTime,Name:EventName,Source:EventSource}' \
  --output table
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Step 1 — Deactivate and delete unauthorized IPSet(s)

```bash
# Get the IPSet ID from the investigation query above, then:
SUSPECT_IPSET_ID="<ipset-id-from-investigation>"

# Deactivate first (INACTIVE state)
aws guardduty update-ip-set \
  --detector-id $DETECTOR_ID \
  --ip-set-id $SUSPECT_IPSET_ID \
  --activate false \
  --region $REGION

# Then delete
aws guardduty delete-ip-set \
  --detector-id $DETECTOR_ID \
  --ip-set-id $SUSPECT_IPSET_ID \
  --region $REGION

echo "[OK] IPSet $SUSPECT_IPSET_ID removed"
```

#### Step 2 — Delete unauthorized suppression filter(s)

```bash
SUSPECT_FILTER_NAME="<filter-name-from-investigation>"

aws guardduty delete-filter \
  --detector-id $DETECTOR_ID \
  --filter-name $SUSPECT_FILTER_NAME \
  --region $REGION

echo "[OK] Filter $SUSPECT_FILTER_NAME deleted"
```

#### Step 3 — Restore detector publishing frequency

```bash
# Restore to ONE_HOUR (or your baseline value captured in Preparation)
aws guardduty update-detector \
  --detector-id $DETECTOR_ID \
  --finding-publishing-frequency ONE_HOUR \
  --region $REGION

# Verify
aws guardduty get-detector \
  --detector-id $DETECTOR_ID \
  --region $REGION \
  --query 'FindingPublishingFrequency'
```

#### Step 4 — Revoke the attacker IAM role's active sessions

```bash
# Attach a deny-all inline policy to the attacker role to immediately invalidate
# all active sessions (STS sessions ignore the original role policy once revoked)
ATTACKER_ROLE="atomic-guardduty-impair-attacker-role"

aws iam put-role-policy \
  --role-name $ATTACKER_ROLE \
  --policy-name RevokeAllSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
        }
      }
    }]
  }'

echo "[OK] All sessions issued before $(date -u) for $ATTACKER_ROLE are now denied"
```

#### Step 5 — Remove staged S3 objects (trusted-IP file)

```bash
SUSPECT_BUCKET="<bucket-name-from-investigation>"

# Delete the specific object (and all versions if versioning is enabled)
aws s3api delete-object \
  --bucket $SUSPECT_BUCKET \
  --key trusted_ip_list.txt

# If bucket versioning is on, remove all versions of the key:
for VERSION_ID in $(aws s3api list-object-versions \
  --bucket $SUSPECT_BUCKET --prefix trusted_ip_list.txt \
  --query 'Versions[*].VersionId' --output text); do
  aws s3api delete-object \
    --bucket $SUSPECT_BUCKET \
    --key trusted_ip_list.txt \
    --version-id $VERSION_ID
done

echo "[OK] Staged trusted-IP artifact removed"
```

#### Step 6 — Block further API calls by detaching the attacker role's permission policies

```bash
# List attached managed policies
aws iam list-attached-role-policies --role-name $ATTACKER_ROLE

# Detach each (repeat for all listed policies)
aws iam detach-role-policy \
  --role-name $ATTACKER_ROLE \
  --policy-arn <PolicyArn>

echo "[OK] Attacker role stripped of managed policies"
```

---

## 4. Eradication

### Remove Attacker Access

#### 1. Audit and remove the attacker IAM role entirely (after forensic preservation)

```bash
# First, capture the role's trust policy and inline policies for forensics
aws iam get-role --role-name $ATTACKER_ROLE > /tmp/attacker_role_forensics.json
aws iam list-role-policies --role-name $ATTACKER_ROLE >> /tmp/attacker_role_forensics.json

# Delete inline policies
for POLICY_NAME in $(aws iam list-role-policies \
  --role-name $ATTACKER_ROLE \
  --query 'PolicyNames[]' --output text); do
  aws iam delete-role-policy \
    --role-name $ATTACKER_ROLE \
    --policy-name $POLICY_NAME
done

# Delete the role
aws iam delete-role --role-name $ATTACKER_ROLE

echo "[OK] Attacker role $ATTACKER_ROLE deleted"
```

#### 2. Verify no residual IPSets or filters remain

```bash
echo "--- Remaining IPSets ---"
aws guardduty list-ip-sets \
  --detector-id $DETECTOR_ID \
  --region $REGION

echo "--- Remaining Filters ---"
aws guardduty list-filters \
  --detector-id $DETECTOR_ID \
  --region $REGION
```

#### 3. Audit all other IAM roles for overly broad GuardDuty permissions

```bash
# Find all roles/policies allowing guardduty:CreateIPSet, CreateFilter, UpdateDetector
aws iam get-account-authorization-details \
  --filter Role \
  --query 'RolePolicyList[*].[RoleName,PolicyName]' \
  --output table

# For a targeted scan (requires aws-policy-validator or manual review):
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::ACCOUNT_ID:role/ROLE_TO_TEST" \
  --action-names "guardduty:CreateIPSet" "guardduty:CreateFilter" "guardduty:UpdateDetector" \
  --resource-arns "*"
```

#### 4. Rotate any access keys held by principals that granted AssumeRole to the attacker role

```bash
# Find the role's trust policy principal
aws iam get-role \
  --role-name $ATTACKER_ROLE \
  --query 'Role.AssumeRolePolicyDocument'

# For each trusted principal IAM user, rotate keys
aws iam list-access-keys --user-name <TrustedPrincipalUser>
aws iam update-access-key \
  --user-name <TrustedPrincipalUser> \
  --access-key-id <OldKeyId> \
  --status Inactive
aws iam create-access-key --user-name <TrustedPrincipalUser>
```

---

## 5. Recovery

### Restore Clean State

#### 1. Confirm GuardDuty detector is healthy and enabled

```bash
aws guardduty get-detector \
  --detector-id $DETECTOR_ID \
  --region $REGION \
  --query '{Status:Status,FrequencyMinutes:FindingPublishingFrequency,UpdatedAt:UpdatedAt}'
# Expected: Status=ENABLED, FindingPublishingFrequency=ONE_HOUR (or your baseline)
```

#### 2. Re-enable any GuardDuty data sources that may have been altered

```bash
# Check Kubernetes, Malware Protection, S3 data source statuses
aws guardduty get-detector \
  --detector-id $DETECTOR_ID \
  --region $REGION \
  --query 'DataSources'

# Re-enable S3 protection if found disabled
aws guardduty update-detector \
  --detector-id $DETECTOR_ID \
  --region $REGION \
  --data-sources '{"S3Logs":{"Enable":true}}'
```

#### 3. Verify publishing destination is intact

```bash
aws guardduty list-publishing-destinations \
  --detector-id $DETECTOR_ID \
  --region $REGION

for DEST_ID in $(aws guardduty list-publishing-destinations \
  --detector-id $DETECTOR_ID --region $REGION \
  --query 'Destinations[*].DestinationId' --output text); do
  aws guardduty get-publishing-destination \
    --detector-id $DETECTOR_ID \
    --destination-id $DEST_ID \
    --region $REGION
done
# Expected Status: PUBLISHING (not UNABLE_TO_PUBLISH_FIXABLE or PENDING_VERIFICATION)
```

#### 4. Run a GuardDuty findings sample to confirm the pipeline is operational

```bash
aws guardduty create-sample-findings \
  --detector-id $DETECTOR_ID \
  --finding-types "Recon:IAMUser/MaliciousIPCaller" \
  --region $REGION

# Wait ~2 minutes, then verify findings appear
aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --region $REGION \
  --finding-criteria '{"Criterion":{"type":{"Eq":["Recon:IAMUser/MaliciousIPCaller"]}}}' \
  --query 'FindingIds' \
  --output table
```

#### 5. Remove the emergency session-revocation inline policy from any surviving roles

```bash
# If the attacker role was preserved rather than deleted for forensics:
aws iam delete-role-policy \
  --role-name $ATTACKER_ROLE \
  --policy-name RevokeAllSessions
```

#### 6. Force CloudTrail integrity validation to confirm log completeness during the incident window

```bash
TRAIL_ARN=$(aws cloudtrail describe-trails \
  --query 'trailList[0].TrailARN' --output text)
LOG_BUCKET=$(aws cloudtrail describe-trails \
  --query 'trailList[0].S3BucketName' --output text)

aws cloudtrail validate-logs \
  --trail-arn $TRAIL_ARN \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --verbose
```

---

## 6. Lessons Learned

### What This Attack Demonstrated

| Gap | Mitigation |
|-----|------------|
| IAM roles with broad GuardDuty write permissions existed outside the security team | Apply SCP: deny `guardduty:CreateIPSet`, `guardduty:CreateFilter`, `guardduty:UpdateDetector` for all OUs except the security OU |
| No alert fired on `CreateIPSet` or `CreateFilter` from a non-security principal | Create a CloudWatch Metric Filter + EventBridge rule on these exact API calls; wake on-call immediately |
| Detection rules that filter `errorCode IS NOT NULL` silently dropped the `DeleteDetector` and `DeletePublishingDestination` denied attempts | Review all detection rules: `AccessDenied` on destructive GuardDuty calls is a **high-confidence IOC**, not noise |
| No change-management gate existed for GuardDuty suppression filters | Require PR approval + security team co-sign for any new GuardDuty filter in Terraform/CDK/Pulumi |
| Attacker role had `s3:PutObject` on a security-named bucket | Enforce naming conventions with SCPs; block `s3:PutObject` to buckets matching `*guardduty*` / `*trusted-ip*` from non-security principals |
| Detector publishing frequency could be degraded via API | Monitor `UpdateDetector` events; alert on any decrease in `findingPublishingFrequency`; consider SCP deny on this call outside the security OU |

### Preventive Guardrails

```bash
# SCP snippet — deny all GuardDuty impairment outside security OU
# Attach to root or non-security OUs; exempt security OU via Condition

{
  "Sid": "DenyGuardDutyImpairment",
  "Effect": "Deny",
  "Action": [
    "guardduty:CreateIPSet",
    "guardduty:UpdateIPSet",
    "guardduty:DeleteIPSet",
    "guardduty:CreateFilter",
    "guardduty:UpdateFilter",
    "guardduty:DeleteFilter",
    "guardduty:UpdateDetector",
    "guardduty:DeleteDetector",
    "guardduty:DisassociateFromMasterAccount",
    "guardduty:DeletePublishingDestination",
    "guardduty:StopMonitoringMembers"
  ],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {
      "aws:PrincipalArn": [
        "arn:aws:iam::ACCOUNT_ID:role/SecurityTeamRole",
        "arn:aws:iam::ACCOUNT_ID:role/SecurityAutomationRole"
      ]
    }
  }
}
```

### Detection Rule References

- **Rule: GuardDuty IPSet or Filter Created Outside Change Window** — alert on `CreateIPSet` / `CreateFilter` from any principal not in the security role allowlist, any time.
- **Rule: GuardDuty Detector Frequency Degraded** — alert on `UpdateDetector` where the event detail shows `findingPublishingFrequency` changes to `SIX_HOURS` or `FIFTEEN_MINUTES` (decreasing sensitivity).
- **Rule: Denied Attempt to Destroy GuardDuty** — alert on `DeleteDetector` or `DeletePublishingDestination` with `errorCode=AccessDenied`. This is a **must-not-suppress** rule.
- **Rule: GuardDuty Enumeration from Non-Security Principal** — alert on `ListDetectors` + `GetDetector` within 60 seconds from the same principal outside the security team.