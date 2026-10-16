# IR Playbook: ATOMIC-rds-data-api-query — AWS RDS Data API Credential Exfiltration

## Classification
| Field | Value |
|-------|-------|
| Incident Type | Data Exfiltration via RDS Data API |
| Threat Actor | ATOMIC-rds-data-api-query (technique emulation) |
| Platform | aws |
| Severity | High |
| MITRE Tactics | Collection (T1213 — Data from Information Repositories) |
| MITRE Techniques | T1213 — SecretsManager credential retrieval + RDS Data API PII dump |

---

## 1. Preparation

### Prerequisites to have in place before this incident type

**CloudTrail data events** (off by default — the entire RDS Data API access path is invisible without them):
```bash
# Verify data events are capturing RDS cluster activity
aws cloudtrail get-event-selectors --trail-name <your-trail-name> \
  --query 'EventSelectors[].DataResources'

# If missing, add them (requires management events trail already active)
aws cloudtrail put-event-selectors \
  --trail-name <your-trail-name> \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [
      {"Type": "AWS::RDS::DBCluster", "Values": ["arn:aws:rds:*:*:cluster:*"]},
      {"Type": "AWS::SecretsManager::Secret", "Values": ["arn:aws:secretsmanager:*:*:secret:*"]}
    ]
  }]'
```

**GuardDuty** with RDS Protection enabled:
```bash
# Check GuardDuty detector status
aws guardduty list-detectors
aws guardduty get-detector --detector-id <detector-id> \
  --query 'Features[?Name==`RDS_LOGIN_EVENTS`]'

# Enable RDS Protection if missing
aws guardduty update-detector --detector-id <detector-id> \
  --features '[{"Name": "RDS_LOGIN_EVENTS", "Status": "ENABLED"}]'
```

**Establish a known-good application principal baseline** for RDS Data API calls. Document which IAM role/user legitimately calls `rds-data:ExecuteStatement` and `secretsmanager:GetSecretValue` for each Aurora cluster. This is the detection signal for anomalous-caller alerts.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Events that always indicate compromise

| Audit Event | Service | Source | Notes |
|---|---|---|---|
| `GetSecretValue` on a DB-credential secret from a non-application IAM principal | CloudTrail (management) | secretsmanager.amazonaws.com | Always logged; no data event required |
| `CredentialAccess:Secrets/AnomalousBehavior` | GuardDuty | — | Fires when caller deviates from established baseline |
| `CredentialAccess:RDS/AnomalousBehavior` | GuardDuty | — | Fires on RDS Data API calls from anomalous principals (requires baseline) |

#### MEDIUM-CONFIDENCE — Events that may indicate compromise (require data events)

| Audit Event | Service | Source | Notes |
|---|---|---|---|
| `ExecuteStatement` on `AWS::RDS::DBCluster` from non-application principal | CloudTrail (data event) | rds-data.amazonaws.com | Off by default — only visible if data events enabled |
| `ExecuteStatement` with SHOW TABLES or SELECT * pattern | CloudTrail (data event) | rds-data.amazonaws.com | SQL text not in CloudTrail, but caller identity + timing is |

---

### Key Investigation Queries

#### Step 1 — Find all GetSecretValue calls on DB-credential secrets (last 7 days)

```bash
# Search by event name and source
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-7d +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].{Time:EventTime,User:Username,Source:EventSource,Resources:Resources}' \
  --output table
```

```bash
# Filter to DB-credential secrets specifically (CloudTrail Insights / S3 logs via Athena)
SELECT eventtime, useridentity.arn, requestparameters.secretid, sourceipaddress
FROM cloudtrail_logs
WHERE eventsource = 'secretsmanager.amazonaws.com'
  AND eventname = 'GetSecretValue'
  AND requestparameters.secretid LIKE '%db%'
  AND eventtime > CURRENT_TIMESTAMP - INTERVAL '7' DAY
ORDER BY eventtime DESC;
```

#### Step 2 — Identify rds-data ExecuteStatement calls (requires data events)

```bash
# Lookup by event source
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=rds-data.amazonaws.com \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-7d +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].{Time:EventTime,EventName:EventName,User:Username,Source:EventSource}' \
  --output table
```

```bash
# Athena: find all RDS Data API callers and frequency
SELECT useridentity.arn, COUNT(*) as call_count, MIN(eventtime) as first_seen, MAX(eventtime) as last_seen
FROM cloudtrail_logs
WHERE eventsource = 'rds-data.amazonaws.com'
  AND eventname = 'ExecuteStatement'
  AND eventtime > CURRENT_TIMESTAMP - INTERVAL '7' DAY
GROUP BY useridentity.arn
ORDER BY call_count DESC;
```

#### Step 3 — Correlate the access key used across both calls

```bash
# Find all events by a specific access key (substitute actual key ID found in step 1)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<VICTIM_ACCESS_KEY_ID> \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-1d +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].{Time:EventTime,EventName:EventName,Source:EventSource,IP:CloudTrailEvent}' \
  --output json | jq '.[].{Time,EventName,Source}'
```

#### Step 4 — Determine the calling IAM identity

```bash
# Identify what principal the key belongs to
aws iam get-access-key-last-used --access-key-id <VICTIM_ACCESS_KEY_ID>

# List all keys for that user and their status
aws iam list-access-keys --user-name <victim-user>
```

#### Step 5 — Check GuardDuty findings

```bash
# List all findings from last 7 days, filter to CredentialAccess family
aws guardduty list-findings \
  --detector-id <detector-id> \
  --finding-criteria '{
    "Criterion": {
      "type": {"Eq": ["CredentialAccess:Secrets/AnomalousBehavior", "CredentialAccess:RDS/AnomalousBehavior"]},
      "updatedAt": {"Gte": 1735948800000}
    }
  }' \
  --query 'FindingIds'

# Get details on specific finding
aws guardduty get-findings \
  --detector-id <detector-id> \
  --finding-ids <finding-id> \
  --query 'Findings[].{Title:Title,Severity:Severity,Principal:Resource.AccessKeyDetails.PrincipalId,Key:Resource.AccessKeyDetails.AccessKeyId,IP:Service.Action.AwsApiCallAction.RemoteIpDetails.IpAddressV4}'
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### 3a — Disable the compromised IAM access key

```bash
# Immediately disable the static key used by the attacker
aws iam update-access-key \
  --user-name <victim-user> \
  --access-key-id <VICTIM_ACCESS_KEY_ID> \
  --status Inactive

# Confirm it is inactive
aws iam list-access-keys --user-name <victim-user> \
  --query 'AccessKeyMetadata[].{KeyId:AccessKeyId,Status:Status,Created:CreateDate}'
```

#### 3b — Attach an explicit Deny policy to the IAM user to kill all in-flight sessions

```bash
# Create an emergency deny-all inline policy
aws iam put-user-policy \
  --user-name <victim-user> \
  --policy-name INCIDENT-RESPONSE-DENY-ALL \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'
```

#### 3c — Restrict the Aurora cluster's Data API to application role only (SCP or resource policy)

```bash
# Tag the cluster for tracking
aws rds add-tags-to-resource \
  --resource-name arn:aws:rds:<region>:<account-id>:cluster:<cluster-id> \
  --tags Key=SecurityStatus,Value=UNDER-INVESTIGATION

# Disable RDS Data API on the cluster if no legitimate application currently requires it
aws rds modify-db-cluster \
  --db-cluster-identifier <cluster-id> \
  --no-enable-http-endpoint \
  --apply-immediately
```

#### 3d — Rotate the DB-credential secret immediately

```bash
# Trigger rotation on the compromised secret
aws secretsmanager rotate-secret \
  --secret-id <db-credentials-secret-arn> \
  --rotation-lambda-arn <rotation-lambda-arn>

# If no rotation Lambda: force update the secret value manually
aws secretsmanager put-secret-value \
  --secret-id <db-credentials-secret-arn> \
  --secret-string '{"username":"<db-user>","password":"<NEW-STRONG-PASSWORD>"}'
```

#### 3e — Force an Aurora master password rotation

```bash
# Rotate the Aurora master credentials out-of-band from Secrets Manager
aws rds modify-db-cluster \
  --db-cluster-identifier <cluster-id> \
  --master-user-password '<NEW-STRONG-PASSWORD>' \
  --apply-immediately
```

---

## 4. Eradication

### Remove Attacker Access

#### 4a — Delete the compromised access key permanently

```bash
# After validating no legitimate workload depends on this key
aws iam delete-access-key \
  --user-name <victim-user> \
  --access-key-id <VICTIM_ACCESS_KEY_ID>
```

#### 4b — Remove the emergency deny policy and re-evaluate least privilege

```bash
# Remove the blast-radius deny (after issuing replacement credentials to legitimate owner)
aws iam delete-user-policy \
  --user-name <victim-user> \
  --policy-name INCIDENT-RESPONSE-DENY-ALL
```

#### 4c — Audit all IAM principals with rds-data permissions

```bash
# Find all policies granting rds-data:ExecuteStatement
aws iam list-policies --scope Local --query 'Policies[].Arn' --output text | \
  xargs -I{} aws iam get-policy-version \
    --policy-arn {} \
    --version-id $(aws iam get-policy --policy-arn {} --query 'Policy.DefaultVersionId' --output text) \
    --query 'PolicyVersion.Document' 2>/dev/null | grep -l "ExecuteStatement"

# For each IAM role/user with this permission, verify it is legitimate
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<account-id>:user/<victim-user> \
  --action-names rds-data:ExecuteStatement secretsmanager:GetSecretValue \
  --query 'EvaluationResults[].EvalDecision'
```

#### 4d — Audit SecretsManager access policy on DB-credential secret

```bash
# Check resource-based policy on the secret
aws secretsmanager get-resource-policy \
  --secret-id <db-credentials-secret-arn>

# Restrict to only the application role (replace placeholder ARN)
aws secretsmanager put-resource-policy \
  --secret-id <db-credentials-secret-arn> \
  --resource-policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Principal": "*",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::<account-id>:role/<legitimate-app-role>"
        }
      }
    }]
  }'
```

#### 4e — Verify no new IAM entities were created during the incident window

```bash
# List users created after the first GetSecretValue event
aws iam list-users \
  --query 'Users[?CreateDate>=`<incident-start-time>`].{User:UserName,Created:CreateDate}' \
  --output table

# List roles created in same window
aws iam list-roles \
  --query 'Roles[?CreateDate>=`<incident-start-time>`].{Role:RoleName,Created:CreateDate}' \
  --output table
```

---

## 5. Recovery

### Restore Clean State

#### 5a — Re-enable RDS Data API for legitimate applications (if it was disabled)

```bash
# Re-enable only after confirming the application role is scoped correctly
aws rds modify-db-cluster \
  --db-cluster-identifier <cluster-id> \
  --enable-http-endpoint \
  --apply-immediately
```

#### 5b — Issue new access key for the legitimate owner of the victim account

```bash
# Create a fresh key pair for the legitimate user
aws iam create-access-key --user-name <victim-user> \
  --query 'AccessKey.{KeyId:AccessKeyId,Secret:SecretAccessKey}'

# Deliver securely out of band — never log or commit the secret value
```

#### 5c — Verify GuardDuty findings are resolved

```bash
# Archive resolved findings
aws guardduty archive-findings \
  --detector-id <detector-id> \
  --finding-ids <finding-id-1> <finding-id-2>

# Confirm no new CredentialAccess findings remain open
aws guardduty list-findings \
  --detector-id <detector-id> \
  --finding-criteria '{
    "Criterion": {
      "type": {"Prefix": ["CredentialAccess"]},
      "service.archived": {"Eq": ["false"]}
    }
  }'
```

#### 5d — Confirm data events are now active (prevent detection gap recurrence)

```bash
# Verify trail has RDS and SecretsManager data events
aws cloudtrail get-event-selectors --trail-name <your-trail-name> \
  --query 'EventSelectors[].DataResources[].{Type:Type,Values:Values}'
```

#### 5e — Validate PII data scope — determine what was exposed

```bash
# From CloudTrail data events (if enabled): identify which cluster + database received the query
# If not enabled, use RDS performance insights or enhanced monitoring
aws rds describe-db-cluster-endpoints \
  --db-cluster-identifier <cluster-id> \
  --query 'DBClusterEndpoints[].{Endpoint:Endpoint,Type:EndpointType}'

# Check RDS Performance Insights for query history (if enabled)
aws pi get-resource-metrics \
  --service-type RDS \
  --identifier db:<cluster-id> \
  --metric-queries '[{"Metric": "db.load.avg"}]' \
  --start-time <incident-start-time> \
  --end-time <incident-end-time> \
  --period-in-seconds 60
```

---

## 6. Lessons Learned

### What this attack exploited

| Gap | Root Cause | Guardrail |
|---|---|---|
| Static IAM key with `rds-data:*` and `secretsmanager:GetSecretValue` | Overly broad IAM permissions; long-lived static credentials | Replace static keys with IAM roles + instance profiles; scope permissions to specific secret ARNs and cluster ARNs |
| RDS Data API accessible from any IAM principal over HTTPS | No network perimeter around the Data API; no resource policy on the cluster | Restrict Data API calls via IAM conditions (`aws:PrincipalArn`) or SCP; consider disabling the HTTP endpoint if unused |
| DB-credential secret lacked a resource policy | Secret was readable by any principal with `secretsmanager:GetSecretValue` | Add a Deny-unless-application-role resource policy on every DB-credential secret |
| CloudTrail data events not enabled | `ExecuteStatement` calls are invisible without explicit data event configuration | Enable data events for `AWS::RDS::DBCluster` and `AWS::SecretsManager::Secret` in all production trails — this attack leaves only `GetSecretValue` in management logs by default |
| No GuardDuty RDS query baseline | `CredentialAccess:RDS/AnomalousBehavior` requires an established baseline period | Enable GuardDuty RDS Protection in advance; allow 2–4 weeks of application traffic to build the baseline before depending on anomaly alerts |

### Recommended preventive controls

```bash
# SCP to require all rds-data callers to use a specific role tag (attach to target OU)
# Example condition in an SCP:
# "Condition": {"StringNotLike": {"aws:PrincipalTag/Application": "rds-data-authorized"}}

# Enable S3-backed CloudTrail with data events org-wide
aws organizations list-delegated-administrators \
  --service-principal cloudtrail.amazonaws.com

# Enable Macie on buckets where query results may be written downstream
aws macie2 enable-macie
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --s3-job-definition '{"bucketDefinitions": [{"accountId": "<account-id>", "buckets": ["<target-bucket>"]}]}'
```

---

*Playbook generated for ATOMIC-rds-data-api-query — T1213 (Collection) emulation. Last updated: 2026-10-11.*