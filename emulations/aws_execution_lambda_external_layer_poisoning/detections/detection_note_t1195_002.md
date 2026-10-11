# Detection Note: Lambda Invocation After Layer Poisoning (T1195.002 - Data Plane)

## Why No SIGMA/KQL Rule

Step 4 of this attack (invoking the victim Lambda to trigger poisoned layer code) operates
on the **data plane**. Lambda Invoke calls do NOT appear in CloudTrail management events by
default. No standard audit log row is written unless the account has explicitly opted into
CloudTrail **data events** for `lambda.amazonaws.com`.

---

## Detection Alternatives

### 1. CloudWatch Logs - Poisoned Marker String (Recommended)
The emulation injects a `LAYER_POISONED` marker into the Lambda log group at invocation time.
Search for this string directly in the function's log group:

**Log Group:** `/aws/lambda/atomic-lambda-external-layer-poisoning-victim`

**CloudWatch Logs Insights query:**
```
fields @timestamp, @message
| filter @message like /LAYER_POISONED/
| sort @timestamp desc
| limit 50
```

In Sentinel (if CWL is forwarded via the AWS connector):
```kql
AWSCloudWatch
| where LogGroupName == "/aws/lambda/atomic-lambda-external-layer-poisoning-victim"
| where Message contains "LAYER_POISONED"
| project TimeGenerated, LogGroupName, LogStreamName, Message
| sort by TimeGenerated desc
```

### 2. CloudTrail Data Events (Requires Explicit Enablement)
Enable Lambda data events on the trail or via EventBridge:

```json
{
  "DataResources": [
    {
      "Type": "AWS::Lambda::Function",
      "Values": ["arn:aws:lambda:*:*:function:*"]
    }
  ]
}
```

Once enabled, `Invoke` events appear in CloudTrail with `userIdentity.arn` of the caller.
A SIGMA rule on `eventName: Invoke` attributed to the attacker role would then fire.

### 3. GuardDuty - Lambda Protection
If GuardDuty Lambda Protection is enabled, the finding
**Lambda:Execution/SuspiciousCode** may fire when the poisoned module runs, based on
behavioral analysis of the Lambda execution environment.

Check for active findings:
- Finding type: `Lambda:Execution/SuspiciousCode`
- Resource: the victim function ARN

### 4. AWS Security Hub - Lambda.1 Control
Security Hub Lambda.1 control flags functions where the attached layer was not published
by the same account or a known trusted account. Check Security Hub findings with:
- Standard: `AWS Foundational Security Best Practices`
- Control: `Lambda.1`

### 5. ENV_KEYS Exfiltration Pattern in Logs
The poisoned module also prints `ENV_KEYS` (env var names, not values) at import time.
Searching for `ENV_KEYS` alongside `LAYER_POISONED` in CloudWatch Logs confirms the module
executed and accessed the execution environment.

---

## Correlation Recommendation

Pair any of the above data-plane signals with the control-plane chain:
1. `PublishLayerVersion20181031` from attacker role (SIGMA: sigma_T1195_002_publish_layer_version.yml)
2. `UpdateFunctionConfiguration20150331v2` with Layers modified (SIGMA: sigma_T1195_002_layer_injection.yml)
3. `LAYER_POISONED` in CloudWatch Logs within minutes of the UpdateFunctionConfiguration event

All three together give high-confidence, low-FP confirmation of an end-to-end supply-chain injection.
