# Detection Note: T1648 Data-Plane Steps -- Lambda Invocation and Credential Exfiltration

## Affected Steps

- **Step 6 (Collection):** Attacker invokes their Lambda function (`atomic-passrole-exfil`),
  which runs as the privileged target role and calls `secretsmanager:GetSecretValue` against
  the canary secret. The function returns the secret string in its response payload.

## Why No Audit Log Events by Default

Lambda `InvokeFunction` and the downstream `GetSecretValue` call made *inside* the Lambda
execution are **data-plane operations**. CloudTrail management events (the default tier) do
not record them. They are invisible without explicit data event configuration.

The `GetSecretValue` CloudTrail event is attributed to the **Lambda execution role's
assumed-role session** (e.g., `assumed-role/atomic-lambda-passrole-invoke-target-role/...`),
not to the attacker's victim-role credentials -- making it appear as a routine service call
unless the analyst knows to look for the execution role as the caller.

## Detection Alternatives

### 1. CloudTrail Data Events (Recommended)

Enable data events for:

- **Lambda:** `InvokeFunction` -- logs every function invocation with caller identity,
  function ARN, and invocation type. In CloudTrail, enable under Lambda data event selectors.
- **Secrets Manager:** `GetSecretValue` -- logs every secret read with the caller ARN.
  Enable under management+data events for `secretsmanager.amazonaws.com`.

**KQL query once data events are enabled:**

```kql
// GetSecretValue by a Lambda execution role assumed-role session
AWSCloudTrail
| where EventName == "GetSecretValue"
| where EventSource == "secretsmanager.amazonaws.com"
| where UserIdentityType == "AssumedRole"
| where UserIdentityArn contains ":assumed-role/"
// Flag when the caller session name matches a Lambda execution pattern
| where UserIdentityPrincipalid contains ":lambda:"
      or UserAgent has "lambda"
| extend
    SecretId     = tostring(parse_json(RequestParameters).secretId),
    CallerSession = UserIdentityArn
| project TimeGenerated, SecretId, CallerSession, SourceIpAddress, AWSRegion
| sort by TimeGenerated desc
```

### 2. CloudWatch Logs -- Lambda Execution Log Group

Every Lambda invocation writes to its CloudWatch log group (`/aws/lambda/<function-name>`).
The function's output (including any error messages or explicit print statements) is logged.
If the function prints the secret value or an error accessing it, it will appear in the logs.

**Detection:** Alert on any log group named `/aws/lambda/atomic-passrole-exfil` or any
function not in your approved inventory appearing in CloudWatch Logs Lambda log groups.

### 3. GuardDuty Findings

GuardDuty monitors Secrets Manager access patterns and may generate:

- `UnauthorizedAccess:IAMUser/AnomalousBehavior` if the execution role accesses secrets
  it has not historically accessed.
- `CredentialAccess:Secrets/UnusualAccess` for unusual secret access patterns.

GuardDuty does not require data events to be separately enabled for Secrets Manager.

### 4. Short-Lived Assumed-Role Session Correlation

The Lambda execution role's assumed-role session is created at invocation time and expires
after the function returns. Correlate:

1. `AssumeRole` event for the target execution role (principal: `lambda.amazonaws.com`)
2. Followed immediately by `GetSecretValue` from that session
3. Session duration matching Lambda execution window (typically < 15 minutes)

This correlation catches the data exfiltration even without Secrets Manager data events,
because the `AssumeRole` is a management event recorded by default.
