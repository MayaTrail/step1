# IR Playbook: ATOMIC-iam-oidc-provider-backdoor — AWS IAM OIDC Trust Modification

## Classification

| Field | Value |
|-------|-------|
| Incident Type | IAM Trust Policy Backdoor via OIDC Federation |
| Threat Actor | ATOMIC-iam-oidc-provider-backdoor (technique emulation) |
| Platform | aws |
| Severity | Critical |
| MITRE Techniques | T1484.002 — Domain or Tenant Policy Modification: Trust Modification |
| MITRE Tactics | Defense Evasion, Privilege Escalation |
| Attack Surface | AWS IAM (OIDC Providers, Roles), AWS STS |
| Audit Source | CloudTrail management events |

---

## 1. Preparation

### What must be in place before this incident

**Logging & Visibility**
- CloudTrail multi-region trail enabled, delivering to a protected S3 bucket with object-level integrity validation
- CloudTrail logs ingested into a SIEM or queryable store (Athena, CloudWatch Logs Insights, Splunk, etc.)
- CloudWatch metric filter and alarm on `CreateOpenIDConnectProvider` and `CreateRole` with `Federated` principal events
- GuardDuty enabled (detects some unusual IAM activity as a secondary signal)
- AWS Config rules: `iam-no-inline-policy`, `iam-role-managed-policy`, `iam-root-access-key-check`

**Access Controls**
- SCPs on the OU/account restricting `iam:CreateOpenIDConnectProvider` and `iam:CreateRole` to approved pipeline roles only
- IAM Access Analyzer enabled to surface external-principal trust relationships automatically
- Least-privilege exec role — no IAM write permissions unless explicitly required
- Break-glass admin role protected by MFA with separate credential store

**Runbook Prerequisites**
- Responder has `SecurityAudit` + `IAMReadOnlyAccess` at minimum, or assume `SecurityResponseRole`
- AWS CLI v2 configured with responder credentials and target account profile (`--profile <account>`)
- `jq` installed for JSON parsing
- Account ID noted: `ACCOUNT_ID=<12-digit-account-id>`

---

## 2. Identification

### Detection Triggers (prioritized)

**HIGH-CONFIDENCE — these events always indicate the attack pattern**

| Event | Source | Why High Confidence |
|-------|--------|---------------------|
| `CreateOpenIDConnectProvider` | `iam.amazonaws.com` | Legitimate GitHub OIDC providers are created once during pipeline bootstrap; any new creation from a non-pipeline principal is anomalous |
| `CreateRole` with `Federated` principal containing `token.actions.githubusercontent.com` | `iam.amazonaws.com` | Shadow federated roles are the core persistence artifact — any role with this trust anchor from non-IaC principals is suspicious |
| `AssumeRoleWithWebIdentity` with `errorCode: InvalidIdentityToken` | `sts.amazonaws.com` | Attacker probing with a fake/invalid JWT; legitimate CI/CD never produces this error |
| `DeleteOpenIDConnectProvider` outside maintenance windows | `iam.amazonaws.com` | Cleanup step — attacker removing forensic evidence |
| `DeleteRole` for roles with OIDC trust, outside IaC lifecycle | `iam.amazonaws.com` | Cleanup step — attacker removing backdoor role |

**MEDIUM-CONFIDENCE — may indicate compromise or require correlation**

| Event | Source | Why Medium Confidence |
|-------|--------|----------------------|
| `ListOpenIDConnectProviders` from non-IaC principals | `iam.amazonaws.com` | Reconnaissance step — alone not conclusive, but precedes attack |
| `GetCallerIdentity` from an unexpected role/key | `sts.amazonaws.com` | Attacker confirming identity post-credential acquisition |
| `CreateRole` from exec/runtime role (not IaC deployer) | `iam.amazonaws.com` | Roles should only be created by IaC deployers (Pulumi/Terraform runner role) |

---

### Key Investigation Queries

**Step 0 — Set environment variables**
```bash
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export REGION=us-east-1
export PROFILE="--profile incident-response"
# Adjust time window to the suspected incident window
export START_TIME="2024-01-01T00:00:00Z"
export END_TIME="2024-12-31T23:59:59Z"
```

**Query 1 — Find all OIDC provider create/delete events**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateOpenIDConnectProvider \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --query 'Events[*].{Time:EventTime,User:Username,Event:CloudTrailEvent}' \
  --output json $PROFILE | jq '.[] | {Time: .Time, User: .User, Detail: (.Event | fromjson | {userIdentity, requestParameters, responseElements, sourceIPAddress})}'
```

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteOpenIDConnectProvider \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --output json $PROFILE | jq '.[] | {Time: .Time, User: .User, Detail: (.Event | fromjson | {userIdentity, requestParameters, sourceIPAddress})}'
```

**Query 2 — Find all IAM role creations in the window (look for Federated trust)**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --output json $PROFILE | jq '.[] | {
    Time: .EventTime,
    User: .Username,
    RoleName: (.CloudTrailEvent | fromjson | .requestParameters.roleName),
    TrustPolicy: (.CloudTrailEvent | fromjson | .requestParameters.assumeRolePolicyDocument | fromjson),
    SourceIP: (.CloudTrailEvent | fromjson | .sourceIPAddress),
    UserAgent: (.CloudTrailEvent | fromjson | .userAgent)
  }'
```

**Query 3 — Filter specifically for OIDC-federated role creations (GitHub Actions trust anchor)**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --output json $PROFILE | jq '.[] | select(
    (.CloudTrailEvent | fromjson | .requestParameters.assumeRolePolicyDocument) |
    contains("token.actions.githubusercontent.com") or contains("Federated")
  ) | {
    Time: .EventTime,
    RoleName: (.CloudTrailEvent | fromjson | .requestParameters.roleName),
    TrustPolicy: (.CloudTrailEvent | fromjson | .requestParameters.assumeRolePolicyDocument | fromjson),
    Principal: (.CloudTrailEvent | fromjson | .userIdentity)
  }'
```

**Query 4 — Find failed AssumeRoleWithWebIdentity calls (attacker probing)**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithWebIdentity \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --output json $PROFILE | jq '.[] | select(
    (.CloudTrailEvent | fromjson | .errorCode) == "InvalidIdentityToken" or
    (.CloudTrailEvent | fromjson | .errorCode) != null
  ) | {
    Time: .EventTime,
    ErrorCode: (.CloudTrailEvent | fromjson | .errorCode),
    ErrorMessage: (.CloudTrailEvent | fromjson | .errorMessage),
    RoleArn: (.CloudTrailEvent | fromjson | .requestParameters.roleArn),
    SourceIP: (.CloudTrailEvent | fromjson | .sourceIPAddress)
  }'
```

**Query 5 — Enumerate all current OIDC providers in the account**
```bash
aws iam list-open-id-connect-providers $PROFILE --output json | jq '.OpenIDConnectProviderList[].Arn'
```

```bash
# Inspect each provider for unexpected thumbprints or audiences
for PROVIDER_ARN in $(aws iam list-open-id-connect-providers $PROFILE --query 'OpenIDConnectProviderList[*].Arn' --output text); do
  echo "=== Provider: $PROVIDER_ARN ==="
  aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$PROVIDER_ARN" $PROFILE
done
```

**Query 6 — Find all roles with OIDC/Federated trust (identify backdoor candidates)**
```bash
aws iam list-roles $PROFILE --output json | jq '.Roles[] | select(
  .AssumeRolePolicyDocument.Statement[].Principal.Federated? |
  type == "string" and contains("oidc")
) | {
  RoleName: .RoleName,
  RoleArn: .Arn,
  CreateDate: .CreateDate,
  TrustPolicy: .AssumeRolePolicyDocument
}'
```

**Query 7 — Look for the backdoor role by name pattern**
```bash
aws iam get-role --role-name "backdoor-oidc-federated-role" $PROFILE 2>/dev/null || echo "Role not found (already cleaned up or not created)"
aws iam get-role --role-name "acme-prod-deploy-github" $PROFILE 2>/dev/null || echo "Role not found"
```

**Query 8 — Reconstruct the full timeline for the exec-role principal**
```bash
# Get the exec role ARN first
EXEC_ROLE_ARN=$(aws iam get-role --role-name "exec-role" $PROFILE --query Role.Arn --output text 2>/dev/null)
echo "Exec role ARN: $EXEC_ROLE_ARN"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$EXEC_ROLE_ARN" \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --output json $PROFILE | jq '.Events[] | {Time: .EventTime, Event: .EventName, Source: (.CloudTrailEvent | fromjson | .eventSource)}'
```

**Query 9 — Check IAM Access Analyzer findings for external trust**
```bash
# List all analyzers
aws accessanalyzer list-analyzers $PROFILE --output json | jq '.analyzers[] | {Name: .name, Arn: .arn, Type: .type}'

# Get current findings (look for OIDC or external Federated principals)
ANALYZER_ARN=$(aws accessanalyzer list-analyzers $PROFILE --query 'analyzers[0].arn' --output text)
aws accessanalyzer list-findings --analyzer-arn "$ANALYZER_ARN" $PROFILE \
  --filter '{"resourceType": {"eq": ["AWS::IAM::Role"]}}' \
  --output json | jq '.findings[] | {
    Resource: .resource,
    Principal: .principal,
    Condition: .condition,
    Status: .status,
    UpdatedAt: .updatedAt
  }'
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**Action 1 — Identify and revoke the compromised exec-role static key**
```bash
# List all access keys for exec-role's attached user or role
# If exec-role is an IAM user with static keys:
aws iam list-access-keys --user-name exec-role-user $PROFILE --output json

# Disable the key immediately (disable before delete — preserves forensic record)
aws iam update-access-key \
  --user-name exec-role-user \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive \
  $PROFILE

# If exec-role is a role with instance profile, revoke all active sessions:
aws iam create-policy-version \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/DenyAllForExecRole \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}' \
  --set-as-default \
  $PROFILE
```

**Action 2 — Delete the backdoor OIDC federated role (if it still exists)**
```bash
# Check if backdoor role still exists
BACKDOOR_ROLE="backdoor-oidc-federated-role"

# First detach any managed policies
for POLICY_ARN in $(aws iam list-attached-role-policies --role-name "$BACKDOOR_ROLE" $PROFILE --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null); do
  echo "Detaching policy: $POLICY_ARN"
  aws iam detach-role-policy --role-name "$BACKDOOR_ROLE" --policy-arn "$POLICY_ARN" $PROFILE
done

# Delete inline policies
for POLICY_NAME in $(aws iam list-role-policies --role-name "$BACKDOOR_ROLE" $PROFILE --query 'PolicyNames[*]' --output text 2>/dev/null); do
  echo "Deleting inline policy: $POLICY_NAME"
  aws iam delete-role-policy --role-name "$BACKDOOR_ROLE" --policy-name "$POLICY_NAME" $PROFILE
done

# Delete the role
aws iam delete-role --role-name "$BACKDOOR_ROLE" $PROFILE && echo "Backdoor role deleted"
```

**Action 3 — Audit and contain the backdoor OIDC provider**
```bash
# List all OIDC providers and flag unexpected ones
aws iam list-open-id-connect-providers $PROFILE

# For any provider with token.actions.githubusercontent.com — inspect it
SUSPECT_PROVIDER_ARN="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"

aws iam get-open-id-connect-provider \
  --open-id-connect-provider-arn "$SUSPECT_PROVIDER_ARN" \
  $PROFILE

# CAUTION: Only delete if confirmed attacker-created and NOT used by legitimate CI/CD.
# Check if any legitimate roles trust this provider before deletion.
aws iam list-roles $PROFILE | jq --arg provider "$SUSPECT_PROVIDER_ARN" \
  '.Roles[] | select(.AssumeRolePolicyDocument | tostring | contains($provider)) | .RoleName'
```

**Action 4 — Apply an SCP or inline deny to block further OIDC manipulation**
```bash
# Apply emergency IAM deny SCP (requires Organizations access) — or attach inline policy:
cat > /tmp/emergency-iam-deny.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOIDCManipulation",
      "Effect": "Deny",
      "Action": [
        "iam:CreateOpenIDConnectProvider",
        "iam:DeleteOpenIDConnectProvider",
        "iam:UpdateOpenIDConnectProviderThumbprint",
        "iam:AddClientIDToOpenIDConnectProvider",
        "iam:RemoveClientIDFromOpenIDConnectProvider",
        "iam:CreateRole",
        "iam:UpdateAssumeRolePolicy"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::${ACCOUNT_ID}:role/PulumiDeployRole",
            "arn:aws:iam::${ACCOUNT_ID}:role/TerraformDeployRole",
            "arn:aws:iam::${ACCOUNT_ID}:role/SecurityResponseRole"
          ]
        }
      }
    }
  ]
}
EOF

# Attach as an inline permissions boundary or SCP via AWS Organizations console
# (SCP API requires Organizations master account credentials)
```

**Action 5 — Isolate the exec-role from further API access**
```bash
# Attach a deny-all permissions boundary to the exec role
aws iam put-role-permissions-boundary \
  --role-name exec-role \
  --permissions-boundary arn:aws:iam::aws:policy/AWSDenyAll \
  $PROFILE
```

---

## 4. Eradication

### Remove Attacker Access

**Step 1 — Complete inventory of backdoor artifacts**
```bash
# Find all roles created during the attack window with OIDC/Federated trust
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --output json $PROFILE | jq -r '
    .Events[] |
    (.CloudTrailEvent | fromjson) |
    select(.requestParameters.assumeRolePolicyDocument | contains("Federated")) |
    .requestParameters.roleName
  '

# Find any OIDC providers created during the window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateOpenIDConnectProvider \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --output json $PROFILE | jq '.Events[] | {
    Time: .EventTime,
    Provider: (.CloudTrailEvent | fromjson | .responseElements.openIDConnectProviderArn),
    CreatedBy: (.CloudTrailEvent | fromjson | .userIdentity.arn)
  }'
```

**Step 2 — Delete attacker-created OIDC provider (only if confirmed not legitimate)**
```bash
# CONFIRM first: is this provider used by legitimate CI/CD pipelines?
# If attacker-created and no legitimate roles depend on it:
ATTACKER_PROVIDER_ARN="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"

aws iam delete-open-id-connect-provider \
  --open-id-connect-provider-arn "$ATTACKER_PROVIDER_ARN" \
  $PROFILE && echo "OIDC provider deleted"
```

**Step 3 — Permanently delete compromised static access key**
```bash
# After disabling in containment, now permanently delete
aws iam delete-access-key \
  --user-name exec-role-user \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  $PROFILE

# Verify no remaining keys
aws iam list-access-keys --user-name exec-role-user $PROFILE
```

**Step 4 — Remove emergency deny policies applied during containment**
```bash
# After validated clean state, remove the permissions boundary
aws iam delete-role-permissions-boundary --role-name exec-role $PROFILE
```

**Step 5 — Audit all roles with OIDC trust for legitimacy**
```bash
# Generate full list of federated roles and their trust conditions
aws iam list-roles $PROFILE --output json | jq '[
  .Roles[] |
  select(.AssumeRolePolicyDocument.Statement[].Principal.Federated? | type == "string") |
  {
    RoleName: .RoleName,
    CreateDate: .CreateDate,
    TrustStatements: .AssumeRolePolicyDocument.Statement
  }
]'

# Cross-reference against IaC state (Pulumi stack / Terraform state) to confirm legitimacy
# Any role NOT in IaC state and created during the incident window should be deleted
```

**Step 6 — Rotate exec-role credentials**
```bash
# Issue new access key for exec-role (if static key model is retained)
aws iam create-access-key --user-name exec-role-user $PROFILE

# Store new credentials in secrets manager immediately
aws secretsmanager put-secret-value \
  --secret-id "exec-role/access-key" \
  --secret-string '{"access_key_id":"NEW_KEY","secret_access_key":"NEW_SECRET"}' \
  $PROFILE

# Invalidate old session tokens derived from the compromised key
# (Active STS sessions from static key expire naturally; max 12h for assumed-role sessions)
```

---

## 5. Recovery

### Restore Clean State

**Step 1 — Re-establish legitimate OIDC provider (if deleted)**
```bash
# Retrieve the expected thumbprint from GitHub's OIDC endpoint
# (use your IaC state or documented thumbprint — do NOT re-fetch from an untrusted source)
EXPECTED_THUMBPRINT="6938fd4d98bab03faadb97b34396831e3780aea1"

aws iam create-open-id-connect-provider \
  --url "https://token.actions.githubusercontent.com" \
  --client-id-list "sts.amazonaws.com" \
  --thumbprint-list "$EXPECTED_THUMBPRINT" \
  $PROFILE

# Verify
aws iam list-open-id-connect-providers $PROFILE
```

**Step 2 — Re-deploy IaC stack to restore known-good role configuration**
```bash
# Use Pulumi to reconcile IAM state back to declared state
pulumi up --stack prod --yes --diff

# Or Terraform:
terraform plan -out=recovery.tfplan && terraform apply recovery.tfplan
```

**Step 3 — Verify no residual backdoor roles remain**
```bash
# Re-scan for OIDC-federated roles and confirm all match IaC declarations
aws iam list-roles $PROFILE --output json | jq '[
  .Roles[] |
  select(.AssumeRolePolicyDocument.Statement[].Principal.Federated? | strings | contains("oidc"))
  | .RoleName
]'
```

**Step 4 — Re-enable access for the exec-role with new credentials**
```bash
# Remove permissions boundary applied during containment
aws iam delete-role-permissions-boundary --role-name exec-role $PROFILE

# Confirm execution with new credentials
aws sts get-caller-identity $PROFILE
```

**Step 5 — Verify CloudTrail and GuardDuty are healthy**
```bash
# Confirm CloudTrail trail is active
aws cloudtrail get-trail-status --name cloudtrail-trail $PROFILE \
  --query '{IsLogging: IsLogging, LatestDeliveryTime: LatestDeliveryTime}'

# Confirm GuardDuty detector is enabled
aws guardduty list-detectors $PROFILE --output json

DETECTOR_ID=$(aws guardduty list-detectors $PROFILE --query DetectorIds[0] --output text)
aws guardduty get-detector --detector-id "$DETECTOR_ID" $PROFILE \
  --query '{Status: Status, UpdatedAt: UpdatedAt}'
```

**Step 6 — Run IAM Access Analyzer to confirm no remaining external access**
```bash
ANALYZER_ARN=$(aws accessanalyzer list-analyzers $PROFILE --query 'analyzers[0].arn' --output text)

# Start a new archive/re-scan
aws accessanalyzer start-resource-scan \
  --analyzer-arn "$ANALYZER_ARN" \
  --resource-arn "arn:aws:iam::${ACCOUNT_ID}:root" \
  $PROFILE

# Check for active findings
aws accessanalyzer list-findings \
  --analyzer-arn "$ANALYZER_ARN" \
  --filter '{"status": {"eq": ["ACTIVE"]}}' \
  $PROFILE | jq '.findings[] | {Resource: .resource, Principal: .principal, Status: .status}'
```

---

## 6. Lessons Learned

### What Would Have Prevented This

| Control Gap | Recommended Guardrail |
|-------------|----------------------|
| Exec-role with IAM write permissions | Restrict `iam:CreateRole`, `iam:CreateOpenIDConnectProvider` to IaC deployer role only via SCP |
| No alerting on `CreateOpenIDConnectProvider` | Add CloudWatch metric filter + SNS alarm on this specific event |
| Static long-lived access keys | Replace exec-role static keys with instance profile, ECS task role, or short-lived STS tokens |
| No IAM Access Analyzer in continuous mode | Enable IAM Access Analyzer with real-time findings alerts to Security Hub |
| No baseline of expected OIDC providers | Tag known-good providers (`Environment=prod`, `ManagedBy=IaC`) and alert on untagged creation |
| No restriction on trusted GitHub org/repo in OIDC conditions | Enforce SCP requiring `token.actions.githubusercontent.com:sub` condition on all GitHub-federated roles |

### Key Detection Signatures to Add

**CloudWatch Metric Filter — OIDC Provider Creation**
```json
{
  "filterPattern": "{ ($.eventName = CreateOpenIDConnectProvider) }",
  "metricName": "OIDCProviderCreation",
  "metricNamespace": "SecurityEvents",
  "metricValue": "1"
}
```

**CloudWatch Metric Filter — Federated Role Creation**
```json
{
  "filterPattern": "{ ($.eventName = CreateRole) && ($.requestParameters.assumeRolePolicyDocument = \"*Federated*\") }",
  "metricName": "FederatedRoleCreation",
  "metricNamespace": "SecurityEvents",
  "metricValue": "1"
}
```

**CloudWatch Metric Filter — Failed AssumeRoleWithWebIdentity**
```json
{
  "filterPattern": "{ ($.eventName = AssumeRoleWithWebIdentity) && ($.errorCode = InvalidIdentityToken) }",
  "metricName": "FailedOIDCFederation",
  "metricNamespace": "SecurityEvents",
  "metricValue": "1"
}
```

### Post-Incident Hardening SCP

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RestrictOIDCProviderManagement",
      "Effect": "Deny",
      "Action": [
        "iam:CreateOpenIDConnectProvider",
        "iam:DeleteOpenIDConnectProvider",
        "iam:UpdateOpenIDConnectProviderThumbprint"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/PulumiDeployRole",
            "arn:aws:iam::*:role/TerraformApplyRole"
          ]
        }
      }
    },
    {
      "Sid": "RequireOIDCSubConditionOnFederatedRoles",
      "Effect": "Deny",
      "Action": "iam:CreateRole",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "iam:PolicyDocument": "*token.actions.githubusercontent.com*"
        },
        "Null": {
          "iam:PolicyDocument/Statement/Condition/StringLike/token.actions.githubusercontent.com:sub": "true"
        }
      }
    }
  ]
}
```

### Timeline Summary Template

| Phase | Event | Detection Method |
|-------|-------|-----------------|
| T+0 | `GetCallerIdentity` from exec-role static key | CloudTrail baseline deviation |
| T+1m | `ListOpenIDConnectProviders` enumeration | CloudTrail + SIEM correlation |
| T+2m | `CreateOpenIDConnectProvider` (or EntityAlreadyExists) | CloudWatch alarm fires |
| T+3m | `CreateRole` with `Federated: token.actions.githubusercontent.com` | CloudWatch alarm fires, IAM Access Analyzer finding |
| T+4m | `AssumeRoleWithWebIdentity` with `InvalidIdentityToken` | CloudWatch alarm fires |
| T+5m | `DeleteRole` + `DeleteOpenIDConnectProvider` (attacker cleanup) | CloudTrail — attacker removing evidence |