# IR Playbook: ATOMIC-console-federation-signin — AWS

## Classification
| Field | Value |
|-------|-------|
| Incident Type | Unauthorized Console Access via IAM Federation |
| Threat Actor | ATOMIC-console-federation-signin |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Discovery (T1538 - Cloud Service Dashboard) |
| Key Techniques | GetFederationToken abuse, Console federation sign-in, SecretsManager enumeration, S3 enumeration |

---

## 1. Preparation

### Prerequisites
- **CloudTrail Management Events** enabled in all regions (multi-region trail recommended)
- **CloudTrail signin.amazonaws.com events** enabled — these are Management Events but require the trail to capture `signin.amazonaws.com` as an event source
- S3 Server Access Logging enabled on sensitive buckets (S3 data events are off by default and will miss Step 4)
- CloudTrail S3 Data Events enabled on high-value buckets if Step 4 visibility is required
- GuardDuty enabled (detects `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess` and federation anomalies)
- AWS Config rules tracking IAM user access key age
- SIEM ingestion of CloudTrail logs with alerting on `ConsoleLogin` where `userIdentity.type = FederatedUser`
- Runbook access to IAM for key deletion, user disabling, and session revocation

### Detection Pre-wiring
Alert rule to create before this incident occurs:
```
eventName = "ConsoleLogin"
AND userIdentity.type = "FederatedUser"
AND NOT sourceIPAddress IN [approved_corporate_egress_ranges]
```

---

## 2. Identification

### Detection Triggers (prioritized)

**HIGH-CONFIDENCE — any of these alone warrants immediate investigation:**

| Event | Source | Field | Value | Why High-Confidence |
|-------|--------|-------|-------|---------------------|
| `ConsoleLogin` | `signin.amazonaws.com` | `userIdentity.type` | `FederatedUser` | Programmatic IAM users rarely federate to console; this is the primary signal |
| `ConsoleLogin` | `signin.amazonaws.com` | `userAgent` | Python `requests` library | Browser absent — programmatic console login is almost always abuse |
| `GetFederationToken` | `sts.amazonaws.com` | caller | non-CI IAM user principal | Non-service-account principals calling GetFederationToken is atypical |
| `GetSigninToken` | `signin.amazonaws.com` | `userAgent` | non-browser | Automated sign-in token retrieval |

**MEDIUM-CONFIDENCE — correlate with above before escalating:**

| Event | Source | Anomaly |
|-------|--------|---------|
| `ListSecrets` | `secretsmanager.amazonaws.com` | Principal type `FederatedUser` — rare in production |
| `DescribeSecret` | `secretsmanager.amazonaws.com` | `FederatedUser` accessing prod-named secret |
| `ListObjectsV2` | `s3.amazonaws.com` (S3 data events) | Called by `FederatedUser` ARN — atypical accessor type |
| `GetFederationToken` | `sts.amazonaws.com` | `DurationSeconds=900` — short window suggesting automation |

---

### Key Investigation Queries

#### Step 1 — Find the GetFederationToken event

```bash
# Look back 24 hours; adjust --start-time as needed
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetFederationToken \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].{Time:EventTime,User:Username,Event:CloudTrailEvent}' \
  --output json | jq '.[] | {time: .Time, user: .User, raw: (.Event | fromjson | {sourceIPAddress, userAgent, requestParameters})}'
```

#### Step 2 — Find the GetSigninToken event (signin.amazonaws.com source)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSigninToken \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.[] | .CloudTrailEvent | fromjson | {eventTime, sourceIPAddress, userAgent, userIdentity}'
```

#### Step 3 — Find the ConsoleLogin event and confirm FederatedUser type

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.[] | .CloudTrailEvent | fromjson | select(.userIdentity.type == "FederatedUser") | {eventTime, sourceIPAddress, userAgent, userIdentity, responseElements}'
```

#### Step 4 — Identify the victim IAM user from the federation chain

```bash
# Extract the ARN of the user who called GetFederationToken
VICTIM_ARN=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetFederationToken \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq -r '.[0].CloudTrailEvent | fromjson | .userIdentity.arn')
echo "Victim ARN: $VICTIM_ARN"

# Extract the username
VICTIM_USER=$(echo "$VICTIM_ARN" | awk -F'/' '{print $NF}')
echo "Victim IAM User: $VICTIM_USER"
```

#### Step 5 — Enumerate all events by the victim user's static key in the last 24h

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$VICTIM_USER" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.[] | .CloudTrailEvent | fromjson | {eventTime, eventName, eventSource, sourceIPAddress, userAgent}'
```

#### Step 6 — Find SecretsManager enumeration by FederatedUser session

```bash
for EVENT in ListSecrets DescribeSecret GetSecretValue; do
  echo "=== $EVENT ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVENT" \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --output json | jq '.[] | .CloudTrailEvent | fromjson | select(.userIdentity.type == "FederatedUser") | {eventTime, eventName, sourceIPAddress, userIdentity, requestParameters}'
done
```

#### Step 7 — Check for S3 access via the federation session (requires data events)

```bash
# If S3 data events are enabled; otherwise check S3 server access logs
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListObjectsV2 \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.[] | .CloudTrailEvent | fromjson | select(.userIdentity.type == "FederatedUser") | {eventTime, sourceIPAddress, requestParameters}'
```

#### Step 8 — Check if the victim user's access keys were already known-compromised

```bash
aws iam list-access-keys --user-name "$VICTIM_USER" \
  --query 'AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status,Created:CreateDate}' \
  --output table
```

#### Step 9 — Check GuardDuty findings for correlated detections

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-criteria '{"Criterion":{"type":{"Eq":["UnauthorizedAccess:IAMUser/ConsoleLoginSuccess"]}}}' \
  --output json | jq '.FindingIds[]'

# Get finding details
aws guardduty get-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-ids $(aws guardduty list-findings --detector-id "$DETECTOR_ID" --output text --query 'FindingIds[*]' | tr '\t' ' ') \
  --output json | jq '.Findings[] | {title: .Title, severity: .Severity, time: .UpdatedAt, resource: .Resource}'
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Action 1 — Disable the victim user's static access key (stops GetFederationToken re-abuse)

```bash
# List all keys first to get the key ID
aws iam list-access-keys --user-name "$VICTIM_USER"

# Disable the compromised key (replace AKIAXXXXXXXXXXXXXXXX with actual key ID)
COMPROMISED_KEY_ID="AKIAXXXXXXXXXXXXXXXX"
aws iam update-access-key \
  --user-name "$VICTIM_USER" \
  --access-key-id "$COMPROMISED_KEY_ID" \
  --status Inactive

echo "Key $COMPROMISED_KEY_ID set to Inactive for user $VICTIM_USER"
```

#### Action 2 — Revoke all active sessions for the FederatedUser

```bash
# Federation tokens cannot be directly revoked via IAM; they expire after DurationSeconds (900s by default).
# However, attaching a deny-all inline policy to the source IAM user immediately invalidates
# ALL derived sessions (including STS federation tokens) because AWS evaluates the source user's
# policy at each API call, not just at token issuance.

aws iam put-user-policy \
  --user-name "$VICTIM_USER" \
  --policy-name "EmergencyDenyAll" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'

echo "Emergency Deny-All attached to $VICTIM_USER — all derived sessions are now denied"
```

> **Note:** The deny-all inline policy overrides any permission grants in the user's attached policies. This is the fastest way to kill active federation sessions without waiting for the 15-minute STS expiry.

#### Action 3 — Block the attacker source IP at the account boundary (if IP is known)

```bash
# Get the source IP from the ConsoleLogin event
ATTACKER_IP=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq -r '.[0].CloudTrailEvent | fromjson | select(.userIdentity.type == "FederatedUser") | .sourceIPAddress')
echo "Attacker source IP: $ATTACKER_IP"

# Create a Service Control Policy (SCP) deny for the IP (requires AWS Organizations)
# OR add an explicit deny condition to the victim user's policy:
aws iam put-user-policy \
  --user-name "$VICTIM_USER" \
  --policy-name "DenyAttackerIP" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Deny\",
      \"Action\": \"*\",
      \"Resource\": \"*\",
      \"Condition\": {\"IpAddress\": {\"aws:SourceIp\": \"$ATTACKER_IP\"}}
    }]
  }"
```

#### Action 4 — Snapshot current IAM user state for forensics before any changes

```bash
aws iam get-user --user-name "$VICTIM_USER" > /tmp/victim_user_snapshot.json
aws iam list-attached-user-policies --user-name "$VICTIM_USER" >> /tmp/victim_user_snapshot.json
aws iam list-user-policies --user-name "$VICTIM_USER" >> /tmp/victim_user_snapshot.json
aws iam list-groups-for-user --user-name "$VICTIM_USER" >> /tmp/victim_user_snapshot.json
echo "Snapshot saved to /tmp/victim_user_snapshot.json"
```

#### Action 5 — Scope the blast radius: what resources did the FederatedUser touch?

```bash
# Pull all CloudTrail events from the federation session principal
FEDERATED_ARN=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq -r '.[0].CloudTrailEvent | fromjson | select(.userIdentity.type == "FederatedUser") | .userIdentity.arn')

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="console-federator" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.[] | .CloudTrailEvent | fromjson | {eventTime, eventName, eventSource, requestParameters}'
```

---

## 4. Eradication

### Remove Attacker Access

#### Step 1 — Delete the compromised static access key

```bash
# Only after disabling in containment and confirming no legitimate services depend on it
aws iam delete-access-key \
  --user-name "$VICTIM_USER" \
  --access-key-id "$COMPROMISED_KEY_ID"
echo "Key $COMPROMISED_KEY_ID deleted"
```

#### Step 2 — Issue a new access key for the victim user (if the user is legitimate)

```bash
NEW_KEY=$(aws iam create-access-key --user-name "$VICTIM_USER")
echo "New KeyId: $(echo $NEW_KEY | jq -r '.AccessKey.AccessKeyId')"
# Distribute new key through approved secret management channel (NOT via plaintext)
```

#### Step 3 — Remove the emergency deny-all policy added during containment

```bash
# Only after new key is distributed and tested
aws iam delete-user-policy \
  --user-name "$VICTIM_USER" \
  --policy-name "EmergencyDenyAll"

aws iam delete-user-policy \
  --user-name "$VICTIM_USER" \
  --policy-name "DenyAttackerIP" 2>/dev/null || true
```

#### Step 4 — Review and tighten the victim user's permissions

```bash
# Check if GetFederationToken permission should be on this user at all
aws iam simulate-principal-policy \
  --policy-source-arn "$VICTIM_ARN" \
  --action-names "sts:GetFederationToken" \
  --query 'EvaluationResults[*].{Action:EvalActionName,Decision:EvalDecision}' \
  --output table

# If GetFederationToken is not required for this user's legitimate function, add an explicit deny:
aws iam put-user-policy \
  --user-name "$VICTIM_USER" \
  --policy-name "DenyFederationAbuse" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyConsoleFederation",
      "Effect": "Deny",
      "Action": ["sts:GetFederationToken", "sts:GetSessionToken"],
      "Resource": "*"
    }]
  }'
```

#### Step 5 — Verify no backdoor resources were created during the federation session

```bash
# Check if any new IAM users, roles, or policies were created
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="console-federator" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.[] | .CloudTrailEvent | fromjson | select(.eventName | test("Create|Attach|Put|Add")) | {eventTime, eventName, requestParameters}'

# Check for new IAM users created in the window
aws iam list-users \
  --query 'Users[?CreateDate>=`'"$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)"'`]' \
  --output table

# Check for secrets that were accessed (GetSecretValue) — if data exfiltration is suspected
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.[] | .CloudTrailEvent | fromjson | select(.userIdentity.type == "FederatedUser") | {eventTime, requestParameters}'
```

#### Step 6 — Rotate any secrets that were enumerated (ListSecrets / DescribeSecret)

```bash
# List secrets that were described during the attack window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeSecret \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.[] | .CloudTrailEvent | fromjson | select(.userIdentity.type == "FederatedUser") | .requestParameters.secretId'

# For each identified secret, rotate its value:
# aws secretsmanager rotate-secret --secret-id <SECRET_ID>
# (or update the secret value manually if auto-rotation is not configured)
```

---

## 5. Recovery

### Restore Clean State

#### Step 1 — Verify the user's new credentials work correctly

```bash
# Using the new key
aws sts get-caller-identity \
  --profile <new-key-profile>
```

#### Step 2 — Confirm GuardDuty is active and has the latest intel

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty get-detector --detector-id "$DETECTOR_ID" \
  --query '{Status: Status, UpdatedAt: UpdatedAt, FindingPublishFrequency: FindingPublishFrequency}'
```

#### Step 3 — Verify CloudTrail is still capturing signin.amazonaws.com events post-incident

```bash
aws cloudtrail get-trail-status --name <YOUR_TRAIL_NAME> \
  --query '{IsLogging: IsLogging, LatestDeliveryTime: LatestDeliveryTime, LatestDeliveryError: LatestDeliveryError}'

# Confirm the trail covers global/management events
aws cloudtrail get-event-selectors --trail-name <YOUR_TRAIL_NAME> \
  --query 'EventSelectors[*].{ReadWriteType:ReadWriteType,IncludeManagement:IncludeManagementEvents}'
```

#### Step 4 — Enable MFA for the victim user (prevent future static-key-only access)

```bash
# Check current MFA status
aws iam list-mfa-devices --user-name "$VICTIM_USER"

# If no MFA is configured, force MFA via IAM policy condition:
aws iam put-user-policy \
  --user-name "$VICTIM_USER" \
  --policy-name "RequireMFA" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyWithoutMFA",
      "Effect": "Deny",
      "NotAction": ["iam:CreateVirtualMFADevice","iam:EnableMFADevice","iam:GetUser","iam:ListMFADevices","iam:ListVirtualMFADevices","iam:ResyncMFADevice","sts:GetSessionToken"],
      "Resource": "*",
      "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}
    }]
  }'
```

#### Step 5 — Confirm no active federation sessions remain (wait for STS expiry + verify)

```bash
# Federation tokens expire within 15 minutes (DurationSeconds=900).
# Confirm no new GetFederationToken events since containment:
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetFederationToken \
  --start-time "$(date -u +%Y-%m-%dT%H:%M:%SZ -d '-15 minutes')" \
  --output json | jq '. | length'
# Expected: 0
```

#### Step 6 — Add SCP or permission boundary to prevent GetFederationToken account-wide (if policy allows)

```bash
# Check if AWS Organizations is in use
aws organizations describe-organization 2>/dev/null | jq '.Organization.Id'

# If organizations is available, create an SCP to restrict federation token creation
# to approved service roles only (requires Organizations management account access):
# aws organizations create-policy \
#   --name "RestrictGetFederationToken" \
#   --type SERVICE_CONTROL_POLICY \
#   --description "Restrict GetFederationToken to approved federation roles only" \
#   --content '{"Version":"2012-10-17","Statement":[{"Sid":"DenyGetFederationToken","Effect":"Deny","Action":"sts:GetFederationToken","Resource":"*","Condition":{"StringNotLike":{"aws:PrincipalARN":"arn:aws:iam::*:role/ApprovedFederationRole*"}}}]}'
```

---

## 6. Lessons Learned

### What Would Have Prevented This

| Gap | Guardrail |
|-----|-----------|
| IAM user with `sts:GetFederationToken` permission | Remove `GetFederationToken` from all non-federation-service IAM users; assign it only to dedicated federation roles |
| Static long-lived access key as sole credential | Enforce key rotation policy via AWS Config rule `access-keys-rotated`; enforce MFA requirement via IAM condition |
| No alert on `ConsoleLogin` with `FederatedUser` type | Add high-priority SIEM rule: `ConsoleLogin AND userIdentity.type=FederatedUser` — this is a near-zero false-positive signal |
| No alert on `GetFederationToken` from non-service principals | Alert on any IAM user (not role) calling `GetFederationToken` |
| No alert on non-browser `userAgent` at `signin.amazonaws.com` | Alert on `GetSigninToken` with Python / curl user agent |
| S3 data events disabled (Step 4 not visible in CloudTrail) | Enable S3 data events on sensitive buckets via CloudTrail; cost-optimize by scoping to specific bucket prefixes |
| SecretsManager access not gated by VPC endpoint or IP condition | Add resource policy on sensitive secrets: deny access outside corporate IP ranges or VPC endpoints |
| GuardDuty `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess` finding not actioned | Wire GuardDuty findings to PagerDuty / SNS with <5 minute SLA for Critical severity |

### MITRE ATT&CK Coverage Summary

| Step | Technique | Tactic | Primary Detection |
|------|-----------|--------|-------------------|
| 1 | T1538 | Discovery | `GetFederationToken` from non-service IAM user |
| 2 | T1538 | Discovery | `GetSigninToken` with non-browser user-agent |
| 3 | T1538 | Discovery | `ConsoleLogin` with `userIdentity.type=FederatedUser` (highest fidelity) |
| 4 | T1538 | Discovery | S3 `ListObjectsV2` from `FederatedUser` (requires data events) |
| 5 | T1538 | Discovery | `ListSecrets` / `DescribeSecret` from `FederatedUser` |

### Post-Incident Metric Targets

- **MTTD** (Mean Time to Detect): Target <5 minutes via `ConsoleLogin FederatedUser` alert
- **MTTC** (Mean Time to Contain): Target <15 minutes (static key disable + deny-all policy)
- **MTTR** (Mean Time to Recover): Target <2 hours (key rotation, policy tightening, MFA enrollment)