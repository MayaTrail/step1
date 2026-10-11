# IR Playbook: ATOMIC-cognito-refresh-token-reuse — AWS Cognito Refresh Token Abuse

## Classification
| Field | Value |
|-------|-------|
| Incident Type | Application Access Token Abuse / Session Hijacking |
| Threat Actor | ATOMIC-cognito-refresh-token-reuse (technique emulation) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Credential Access |
| MITRE Techniques | T1550.001 — Use Alternate Authentication Material: Application Access Token |
| Data Sources | CloudTrail management events, Cognito user-pool data plane logs, Cognito advanced security logging |

---

## 1. Preparation

### What must be in place before this incident type is detectable

**Logging prerequisites (without these, core attacker actions are invisible):**
- Cognito **advanced security mode** enabled on every user pool (`EnhancedFlowType` or at minimum `AUDIT` mode) — this is the only way `InitiateAuth` data-plane events appear in logs
- Cognito **user-pool data events** delivered to CloudTrail (requires enabling via the Cognito console or API: `SetUserPoolMfaConfig` / Data event logging config)
- CloudTrail management events enabled in all regions (captures `AssumeRole`, `GetParameters`, `AdminUserGlobalSignOut`)
- CloudWatch Logs subscription or SIEM ingestion for Cognito advanced security findings

**IAM / config prerequisites:**
- SCP or IAM guardrail restricting `cognito-idp:UpdateUserPool` — prevents attacker disabling token revocation mid-incident
- AWS Config rule alerting on `cognito-idp:UpdateUserPool` changes (MFA config, token revocation flag)
- Baseline for expected `AssumeRole` sessions per IAM role (detect anomalous role assumption patterns)
- SSM Parameter Store path-level access logging (CloudTrail `GetParameters` events)

**Response runbooks:**
- Token revocation procedure (AdminUserGlobalSignOut, AdminDisableUser) pre-approved for on-call
- Cognito user-pool ID inventory (pool IDs per service/environment) maintained in CMDB

---

## 2. Identification

### Detection Triggers (prioritized)

**HIGH-CONFIDENCE — Events that always indicate compromise when correlated:**

| Audit Event | Source | Why High-Confidence |
|---|---|---|
| `AssumeRole` for an unexpected or unknown role | `sts.amazonaws.com` (CloudTrail) | Attacker's first action; role name `atomic-cognito-refresh-token-reuse-attacker-role` or equivalent prefixed pattern |
| `GetParameters` on `/atomic-cognito-refresh-token-reuse/*` or any `*/cognito/*` SSM path | `ssm.amazonaws.com` (CloudTrail) | Credential/config exfiltration from parameter store |
| `AdminUserGlobalSignOut` followed immediately by new `InitiateAuth` for the same user | `cognito-idp.amazonaws.com` (CloudTrail + data plane) | Sign-out-then-reauth pattern is a sign of attacker testing revocation boundaries |
| `InitiateAuth` with `AuthFlow=REFRESH_TOKEN_AUTH` from a new IP/device fingerprint | Cognito advanced security | Core T1550.001 signal — token reuse without password |

**MEDIUM-CONFIDENCE — Events that may indicate compromise:**

| Audit Event | Source | Why Medium-Confidence |
|---|---|---|
| `InitiateAuth` with `AuthFlow=USER_PASSWORD_AUTH` for a service account (`prod.svc.account` pattern) | Cognito data plane | Service accounts should not authenticate interactively; may be legitimate automation |
| Multiple `GetUser` calls for the same sub/username within a short time window | Cognito data plane | Session verification after token reuse; could be aggressive health-checking |
| `AssumeRole` from an IAM user that does not normally assume this role | `sts.amazonaws.com` (CloudTrail) | Lateral movement; requires baseline to distinguish |
| Cognito advanced security `ImpersonationRisk` or `UnusualSignIn` finding | Cognito advanced security / EventBridge | Device or IP context anomaly on REFRESH_TOKEN_AUTH |

---

### Key Investigation Queries

**Step 1 — Find the initial role assumption**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query "Events[?contains(CloudTrailEvent, 'cognito-refresh-token-reuse') || contains(CloudTrailEvent, 'attacker-role')].{Time:EventTime,User:Username,Detail:CloudTrailEvent}" \
  --output table
```

**Step 2 — Find SSM parameter reads on Cognito-related paths**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetParameters \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query "Events[?contains(CloudTrailEvent, 'cognito')].{Time:EventTime,User:Username,Detail:CloudTrailEvent}" \
  --output json | python -m json.tool
```

**Step 3 — Enumerate all CloudTrail events from the suspected attacker role session**

Replace `ATTACKER_ROLE_ARN` and `SESSION_NAME` with values from Step 1 output.
```bash
ATTACKER_ROLE_ARN="arn:aws:iam::<ACCOUNT_ID>:role/atomic-cognito-refresh-token-reuse-attacker-role"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="${ATTACKER_ROLE_ARN}" \
  --start-time "$(date -u -d '48 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | python -m json.tool
```

**Step 4 — Find AdminUserGlobalSignOut events**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AdminUserGlobalSignOut \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query "Events[*].{Time:EventTime,User:Username,Detail:CloudTrailEvent}" \
  --output table
```

**Step 5 — Check Cognito advanced security findings for the affected pool**

Replace `<USER_POOL_ID>` with the pool identified from SSM reads.
```bash
USER_POOL_ID="<USER_POOL_ID>"

aws cognito-idp describe-risk-configuration \
  --user-pool-id "${USER_POOL_ID}"

aws cognito-idp admin-list-user-auth-events \
  --user-pool-id "${USER_POOL_ID}" \
  --username "prod.svc.account" \
  --max-results 50 \
  --output json | python -m json.tool
```

**Step 6 — Identify all active sessions for the victim user**
```bash
aws cognito-idp admin-get-user \
  --user-pool-id "${USER_POOL_ID}" \
  --username "prod.svc.account" \
  --query "{Status:UserStatus,Enabled:Enabled,Created:UserCreateDate,Modified:UserLastModifiedDate,Attributes:UserAttributes}"
```

**Step 7 — Check whether token revocation is disabled (permissive pool config)**
```bash
aws cognito-idp describe-user-pool-client \
  --user-pool-id "${USER_POOL_ID}" \
  --client-id "<APP_CLIENT_ID>" \
  --query "UserPoolClient.{TokenRevocation:EnableTokenRevocation,ExplicitAuthFlows:ExplicitAuthFlows,RefreshTokenValidity:RefreshTokenValidity,MFAConfig:AllowedOAuthFlowsUserPool}" \
  --output table
```

**Step 8 — Scan CloudWatch Logs for Cognito data-plane events (if advanced security enabled)**
```bash
LOG_GROUP="/aws/cognito/userpools/${USER_POOL_ID}/RefreshTokenAuth"

aws logs filter-log-events \
  --log-group-name "${LOG_GROUP}" \
  --start-time $(date -d '24 hours ago' +%s)000 \
  --filter-pattern '{ $.eventType = "Authentication" && $.authenticationDetails.authenticationFlow = "REFRESH_TOKEN_AUTH" }' \
  --output json | python -m json.tool
```

**Step 9 — Identify all roles/users that can assume the attacker role**
```bash
aws iam get-role \
  --role-name "atomic-cognito-refresh-token-reuse-attacker-role" \
  --query "Role.AssumeRolePolicyDocument"

aws iam simulate-principal-policy \
  --policy-source-arn "${ATTACKER_ROLE_ARN}" \
  --action-names "cognito-idp:InitiateAuth" "ssm:GetParameters" \
  --output table
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**3.1 — Invalidate all sessions for the compromised Cognito user**
```bash
aws cognito-idp admin-user-global-sign-out \
  --user-pool-id "${USER_POOL_ID}" \
  --username "prod.svc.account"
```

**3.2 — Disable the victim account until password reset is confirmed**
```bash
aws cognito-idp admin-disable-user \
  --user-pool-id "${USER_POOL_ID}" \
  --username "prod.svc.account"
```

**3.3 — Revoke the attacker IAM role's STS session (deny all new calls)**

Create an inline deny policy on the attacker role to invalidate the active session:
```bash
aws iam put-role-policy \
  --role-name "atomic-cognito-refresh-token-reuse-attacker-role" \
  --policy-name "EmergencyDenyAll" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {
          "DateLessThan": {
            "aws:TokenIssueTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
          }
        }
      }
    ]
  }'
```

**3.4 — Revoke any IAM access keys if the attacker assumed from an IAM user**

Identify the caller identity from the CloudTrail AssumeRole event and revoke:
```bash
# Replace ACCESS_KEY_ID with the key found in the AssumeRole event
COMPROMISED_KEY="AKIA..."

aws iam update-access-key \
  --access-key-id "${COMPROMISED_KEY}" \
  --status Inactive

# Identify which user owns it
aws iam get-access-key-last-used --access-key-id "${COMPROMISED_KEY}"
```

**3.5 — Lock down SSM parameters to prevent further reads**
```bash
# Add a resource-based policy denying GetParameters except from known roles
PARAM_PATH="/atomic-cognito-refresh-token-reuse"

aws ssm add-tags-to-resource \
  --resource-type "Parameter" \
  --resource-id "${PARAM_PATH}/pool-id" \
  --tags Key=Quarantine,Value=true Key=IncidentDate,Value="$(date +%Y-%m-%d)"
```

**3.6 — Enable token revocation on the app client immediately**
```bash
APP_CLIENT_ID="<APP_CLIENT_ID>"

aws cognito-idp update-user-pool-client \
  --user-pool-id "${USER_POOL_ID}" \
  --client-id "${APP_CLIENT_ID}" \
  --enable-token-revocation
```

---

## 4. Eradication

### Remove Attacker Access

**4.1 — Force password reset for the compromised Cognito user**
```bash
aws cognito-idp admin-set-user-password \
  --user-pool-id "${USER_POOL_ID}" \
  --username "prod.svc.account" \
  --password "$(openssl rand -base64 24 | tr -d '/+=' | head -c 20)Aa1!" \
  --permanent

# Require password change on next login
aws cognito-idp admin-reset-user-password \
  --user-pool-id "${USER_POOL_ID}" \
  --username "prod.svc.account"
```

**4.2 — Rotate all SSM parameters that were exfiltrated**
```bash
# List all parameters under the affected path
aws ssm get-parameters-by-path \
  --path "/atomic-cognito-refresh-token-reuse" \
  --with-decryption \
  --query "Parameters[*].Name" \
  --output text

# Rotate the app client secret (generates a new client secret)
aws cognito-idp describe-user-pool-client \
  --user-pool-id "${USER_POOL_ID}" \
  --client-id "${APP_CLIENT_ID}" \
  --query "UserPoolClient.ClientSecret"
```

**4.3 — Delete or update the attacker IAM role to close the lateral movement path**
```bash
# Remove all inline policies first
aws iam list-role-policies \
  --role-name "atomic-cognito-refresh-token-reuse-attacker-role" \
  --output text

# Then restrict the trust policy to deny external assumption
aws iam update-assume-role-policy \
  --role-name "atomic-cognito-refresh-token-reuse-attacker-role" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Principal": {"AWS": "*"},
        "Action": "sts:AssumeRole"
      }
    ]
  }'
```

**4.4 — Verify no additional Cognito users were enumerated or modified**
```bash
aws cognito-idp list-users \
  --user-pool-id "${USER_POOL_ID}" \
  --filter "status = \"COMPROMISED\"" \
  --output table

# Check for any recently enabled users (attacker may have created a backdoor account)
aws cognito-idp list-users \
  --user-pool-id "${USER_POOL_ID}" \
  --query "Users[?UserStatus!='CONFIRMED'].{Username:Username,Status:UserStatus,Created:UserCreateDate}" \
  --output table
```

**4.5 — Audit all app client configurations for permissive refresh token settings**
```bash
aws cognito-idp list-user-pool-clients \
  --user-pool-id "${USER_POOL_ID}" \
  --query "UserPoolClients[*].ClientId" \
  --output text | tr '\t' '\n' | while read CLIENT_ID; do
    echo "=== Client: ${CLIENT_ID} ==="
    aws cognito-idp describe-user-pool-client \
      --user-pool-id "${USER_POOL_ID}" \
      --client-id "${CLIENT_ID}" \
      --query "UserPoolClient.{TokenRevocation:EnableTokenRevocation,RefreshValidity:RefreshTokenValidity,ExplicitFlows:ExplicitAuthFlows}"
  done
```

---

## 5. Recovery

### Restore Clean State

**5.1 — Re-enable the victim user after password rotation is confirmed**
```bash
aws cognito-idp admin-enable-user \
  --user-pool-id "${USER_POOL_ID}" \
  --username "prod.svc.account"
```

**5.2 — Enable Cognito advanced security mode if not already on**
```bash
aws cognito-idp update-user-pool \
  --user-pool-id "${USER_POOL_ID}" \
  --user-pool-add-ons AdvancedSecurityMode=ENFORCED
```

**5.3 — Enable MFA for all service accounts (prevent password-only auth in USER_PASSWORD_AUTH flow)**
```bash
aws cognito-idp admin-set-user-mfa-preference \
  --user-pool-id "${USER_POOL_ID}" \
  --username "prod.svc.account" \
  --software-token-mfa-settings Enabled=true,PreferredMfa=true
```

**5.4 — Shorten refresh token validity to reduce the re-use window**
```bash
# Reduce from 30 days to 1 day for service accounts
aws cognito-idp update-user-pool-client \
  --user-pool-id "${USER_POOL_ID}" \
  --client-id "${APP_CLIENT_ID}" \
  --refresh-token-validity 1 \
  --token-validity-units RefreshToken=days \
  --enable-token-revocation
```

**5.5 — Remove the emergency deny policy from the attacker role once rotated**
```bash
aws iam delete-role-policy \
  --role-name "atomic-cognito-refresh-token-reuse-attacker-role" \
  --policy-name "EmergencyDenyAll"
```

**5.6 — Verify no active sessions remain for the compromised identity**
```bash
aws cognito-idp admin-list-user-auth-events \
  --user-pool-id "${USER_POOL_ID}" \
  --username "prod.svc.account" \
  --max-results 10 \
  --output json | python -m json.tool

# Confirm GetUser no longer returns data for old tokens (should 401)
# Run from isolated test environment after old tokens are revoked
```

**5.7 — Verify CloudTrail integrity (confirm no log tampering)**
```bash
aws cloudtrail get-trail-status \
  --name <YOUR_TRAIL_NAME> \
  --query "{IsLogging:IsLogging,LatestDelivery:LatestDeliveryTime,LatestDigest:LatestDigestDeliveryTime}"

aws cloudtrail validate-logs \
  --trail-arn "arn:aws:cloudtrail:<REGION>:<ACCOUNT_ID>:trail/<TRAIL_NAME>" \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"
```

---

## 6. Lessons Learned

### What would have prevented or accelerated detection

| Gap | Recommendation | Priority |
|---|---|---|
| Cognito `InitiateAuth` is invisible in CloudTrail without advanced security mode | Enable `AdvancedSecurityMode=ENFORCED` on all user pools; steps 3-5 of this attack chain produce zero CloudTrail management events without it | Critical |
| Token revocation was disabled (`enableTokenRevocation=false`) | Enforce `enableTokenRevocation=true` via AWS Config rule: `cognito-idp-token-revocation-enabled` | High |
| 30-day refresh token validity gives attacker a month of access | Reduce to 1 day for service accounts; 7 days maximum for user-facing apps | High |
| SSM parameters storing Cognito credentials in plaintext paths | Migrate to AWS Secrets Manager with rotation; audit SSM GetParameters events for credential paths | High |
| No MFA on the victim Cognito user | Require MFA for all identities capable of authenticating via `USER_PASSWORD_AUTH`; prefer `ALLOW_USER_SRP_AUTH` over `USER_PASSWORD_AUTH` to avoid password traveling in plaintext | High |
| No alerting on `AssumeRole` for attacker-prefixed role names | Create EventBridge rule on CloudTrail `AssumeRole` events matching unusual role naming patterns | Medium |
| No baseline for `GetParameters` on Cognito config paths | Alert on first-time callers reading SSM paths containing `cognito`, `pool-id`, or `client-id` | Medium |
| Cognito advanced security findings not ingested into SIEM | Route Cognito EventBridge findings (source: `aws.cognito-idp`) to SIEM for `ImpersonationRisk` and `UnusualSignIn` events | Medium |

### Key detection equation for this technique

> `REFRESH_TOKEN_AUTH InitiateAuth` (data plane) with no preceding `USER_PASSWORD_AUTH` in the same device fingerprint window, OR from a novel IP/ASN, **and** `AdminUserGlobalSignOut` within 60 minutes of the first refresh event = high-confidence T1550.001 indicator.

CloudTrail management events alone are insufficient to detect the core attacker action (steps 3-5). This incident should drive Cognito advanced security enablement as a mandatory baseline control.