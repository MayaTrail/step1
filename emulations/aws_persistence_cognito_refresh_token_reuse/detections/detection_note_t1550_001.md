# Detection Note: T1550.001 - Cognito Data Plane Operations

## Techniques Covered

- Step 3: `InitiateAuth` (USER_PASSWORD_AUTH) - initial credential theft to obtain refresh token
- Step 4: `InitiateAuth` (REFRESH_TOKEN_AUTH) - core T1550.001 action: refresh token reuse
- Step 5: `GetUser` - attacker verifying refreshed identity

## Why These Generate No Standard CloudTrail Events

All three operations are **Cognito user pool data plane calls** (`cognito-idp.amazonaws.com`
`InitiateAuth` and `GetUser`). AWS CloudTrail management events do **not** include
Cognito user pool data plane activity by default. These calls are invisible to standard
CloudTrail unless one of the following is enabled:

- **Cognito Advanced Security Features (ASF)** — adds anomaly detection and user pool
  event logging to CloudWatch Logs
- **CloudTrail data events for Cognito** — requires explicit enablement per user pool;
  logs `InitiateAuth`, `GetUser`, `RespondToAuthChallenge`, etc. to a CloudTrail trail

## Detection Alternatives

### 1. Cognito Advanced Security Features (Recommended)
Enable ASF on the user pool to gain:
- **User pool event log** in CloudWatch Logs: streams all `InitiateAuth` calls with
  `AuthFlow`, `ClientId`, `UserPoolId`, source IP, and device fingerprint.
- **Risk scores** for authentication events — a REFRESH_TOKEN_AUTH from a new IP or
  device that differs from the initial USER_PASSWORD_AUTH session gets a medium-high
  risk score, which is the primary signal for T1550.001 refresh token reuse.
- Configurable actions: notify, MFA challenge, or block based on risk level.

Key CloudWatch Logs fields (Cognito User Pool Event Log):
```
eventType       -> "Authentication"
authFlowType    -> "REFRESH_TOKEN_AUTH" or "USER_PASSWORD_AUTH"
riskDecision    -> "AccountTakeover", "Block", or "NoRisk"
compromisedCredentialsDetected -> true/false
deviceFingerprint -> (present if device tracking enabled)
```

### 2. CloudTrail Data Events for Cognito
If data events are enabled on the user pool trail:
```
eventName:  InitiateAuth
eventSource: cognito-idp.amazonaws.com
requestParameters.authFlow: REFRESH_TOKEN_AUTH
```
Correlate source IP of the REFRESH_TOKEN_AUTH call against the source IP of the
preceding USER_PASSWORD_AUTH for the same user. IP mismatch is the core T1550.001
indicator.

### 3. GuardDuty - Cognito Finding Types
AWS GuardDuty (with Runtime Monitoring) may generate findings for:
- `CognitoUserPool:NewGeolocationAnomaly` - token reuse from unusual geography
- `CredentialAccess:CognitoUserPool/AnomalousBehavior` - abnormal auth patterns

These are available without manual log configuration if GuardDuty is enabled.

### 4. Application-Layer Detection (If You Control the App)
If the relying application validates tokens server-side:
- Log every `GetUser` / `GetId` call with the IP and User-Agent
- Flag token reuse across differing device context (IP subnet, UA string) within
  a single refresh token lifetime
- Alert when a refresh token issued during USER_PASSWORD_AUTH is later used via
  REFRESH_TOKEN_AUTH from a different IP block

### 5. Network / WAF Signals
- WAF logs: repeated `InitiateAuth` calls from a single IP targeting multiple user accounts
- VPC Flow Logs: unusual volume of HTTPS traffic to `cognito-idp.<region>.amazonaws.com`
  from a single source (bulk token refresh)

## Correlation Strategy for T1550.001 Refresh Token Reuse

The highest-fidelity detection joins audit-visible and data-plane signals:

```
1. CloudTrail: AssumeRole targeting attacker-staged role
   -> within 60s ->
2. CloudTrail: SSM GetParameters on Cognito config path
   -> within 120s ->
3. Cognito ASF / data events: InitiateAuth USER_PASSWORD_AUTH
   -> within 5s ->
4. Cognito ASF / data events: InitiateAuth REFRESH_TOKEN_AUTH
   (source IP differs from step 3 OR device fingerprint mismatch)
   -> within 30s ->
5. Cognito data events: GetUser with access token from step 4
   -> within 300s ->
6. CloudTrail: AdminUserGlobalSignOut for the same username
```

A chain matching steps 1+2+6 (all CloudTrail-visible) with any of 3-5
(Cognito data plane) constitutes a confirmed T1550.001 refresh token reuse incident.
Steps 1+2+6 alone without data-plane visibility still warrant investigation.

## References
- https://attack.mitre.org/techniques/T1550/001/
- https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-advanced-security.html
- https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html
- https://docs.aws.amazon.com/guardduty/latest/ug/findings-cognito.html
