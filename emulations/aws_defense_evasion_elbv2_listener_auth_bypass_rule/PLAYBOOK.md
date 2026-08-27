# IR Playbook: ATOMIC-elbv2-listener-auth-bypass-rule — AWS

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Authentication Bypass via ALB Listener Rule Injection |
| Threat Actor | ATOMIC-elbv2-listener-auth-bypass-rule |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Defense Evasion |
| MITRE Techniques | T1556 — Modify Authentication Process |
| Primary Detection Source | CloudTrail (elasticloadbalancing.amazonaws.com CreateRule) |
| Secondary Detection Sources | ALB Access Logs, VPC Flow Logs, GuardDuty |

---

## 1. Preparation

### Prerequisites

The following controls and tooling must be in place before this incident can be effectively detected and investigated:

**Logging & Visibility**
- CloudTrail multi-region trail enabled with management events (Read + Write) and S3 data events
- ALB access logging enabled and shipping to S3 (check `x-amzn-oidc-*` header fields in log schema)
- VPC Flow Logs enabled for all subnets fronted by the ALB
- GuardDuty enabled in all regions with threat intel feeds active
- CloudTrail Insights enabled to detect anomalous API call rates

**IAM Hygiene**
- Least-privilege IAM policies: `elbv2-bypass-victim-user` (or analogues) should NOT hold `elasticloadbalancing:CreateRule` or `elasticloadbalancing:ModifyRule`
- Service Control Policies (SCPs) restricting ALB rule mutations to known automation roles
- IAM Access Analyzer enabled to surface over-permissive policies

**Alerting**
- CloudWatch Metric Filter + Alarm on `CreateRule` events from non-automation principals
- CloudWatch Metric Filter + Alarm on burst of `Describe*` calls against ELBv2 from a single principal within a 5-minute window
- SIEM ingesting CloudTrail and ALB access logs with correlation rules for rule injection patterns

**Runbook Access**
- Responder must have read access to CloudTrail (via `AWSCloudTrailReadOnlyAccess` or equivalent) and `elasticloadbalancing:Describe*` / `elasticloadbalancing:DeleteRule`
- AWS CLI configured with incident-responder profile: `aws configure --profile ir-responder`

---

## 2. Identification

### Detection Triggers (Prioritized)

#### HIGH-CONFIDENCE — Events that ALWAYS indicate active compromise or targeted reconnaissance

| Priority | Event Name | Event Source | Why High-Confidence |
|----------|-----------|--------------|---------------------|
| 1 | `CreateRule` | `elasticloadbalancing.amazonaws.com` | A new listener rule with an HTTP header condition and NO `authenticate-cognito` action on a Cognito-protected listener is a direct backdoor injection — no legitimate use case |
| 2 | Burst of `DescribeLoadBalancers` + `DescribeListeners` + `DescribeTargetGroups` + `DescribeRules` within 60s from single principal | `elasticloadbalancing.amazonaws.com` | Automated enumeration pattern; legitimate users do not burst all four Describe* calls in sequence |

#### MEDIUM-CONFIDENCE — Events that MIGHT indicate compromise (require correlation)

| Priority | Event Name | Event Source | Why Medium / What to Correlate |
|----------|-----------|--------------|-------------------------------|
| 3 | `GuardDuty: UnauthorizedAccess:IAMUser/MaliciousIPCaller` | GuardDuty | Attacker's egress IP in threat feed; requires IP overlap with CloudTrail source IP |
| 4 | ALB access log entry: HTTP 200 with `X-Bypass-Auth` header present and `x-amzn-oidc-identity` absent | ALB Access Logs | Proves bypass is being exercised, but requires ALB log review; not a real-time control-plane signal |
| 5 | VPC Flow Log: inbound TCP 443 connection from external IP returning 200 without prior OAuth redirect sequence | VPC Flow Logs | Indirect — requires correlation with ALB 302 OAuth patterns for same source IP |

---

### Key Investigation Queries

#### Step 1: Identify the compromised principal and enumeration burst

```bash
# Find all ELB Describe* events in the last 24 hours — narrow to suspicious principals
aws cloudtrail lookup-events \
  --profile ir-responder \
  --region us-east-1 \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=elasticloadbalancing.amazonaws.com \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[?contains(`["DescribeLoadBalancers","DescribeListeners","DescribeTargetGroups","DescribeRules"]`, eventName)].[eventTime,eventName,userIdentity.arn,sourceIPAddress]' \
  --output table
```

```bash
# Isolate events specifically from the victim IAM user (substitute actual username)
aws cloudtrail lookup-events \
  --profile ir-responder \
  --region us-east-1 \
  --lookup-attributes AttributeKey=Username,AttributeValue=elbv2-bypass-victim-user \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.Events[] | {time:.EventTime, event:.CloudTrailEvent | fromjson | {eventName,sourceIPAddress,userAgent,requestParameters}}'
```

#### Step 2: Find the injected CreateRule event

```bash
# Search for all CreateRule calls across all principals in last 72 hours
aws cloudtrail lookup-events \
  --profile ir-responder \
  --region us-east-1 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRule \
  --start-time "$(date -u -d '72 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.Events[].CloudTrailEvent | fromjson | {
    time: .eventTime,
    principal: .userIdentity.arn,
    sourceIP: .sourceIPAddress,
    listenerArn: .requestParameters.listenerArn,
    priority: .requestParameters.priority,
    conditions: .requestParameters.conditions,
    actions: .requestParameters.actions
  }'
```

```bash
# Specifically hunt for rules with http-header conditions (magic-header backdoor pattern)
aws cloudtrail lookup-events \
  --profile ir-responder \
  --region us-east-1 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRule \
  --start-time "$(date -u -d '72 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.Events[].CloudTrailEvent | fromjson | select(.requestParameters.conditions[]?.field == "http-header") | {
    time: .eventTime,
    principal: .userIdentity.arn,
    sourceIP: .sourceIPAddress,
    priority: .requestParameters.priority,
    headerName: .requestParameters.conditions[].httpHeaderConfig.httpHeaderName,
    headerValues: .requestParameters.conditions[].httpHeaderConfig.values,
    actions: .requestParameters.actions
  }'
```

#### Step 3: Enumerate all current listener rules on affected ALBs to find the backdoor

```bash
# List all ALBs in the region
aws elbv2 describe-load-balancers \
  --profile ir-responder \
  --region us-east-1 \
  --query 'LoadBalancers[*].[LoadBalancerArn,DNSName,State.Code]' \
  --output table
```

```bash
# Get listeners for the affected ALB (substitute actual ARN)
ALB_ARN="arn:aws:elasticloadbalancing:us-east-1:ACCOUNT_ID:loadbalancer/app/ALBNAME/ALBID"

aws elbv2 describe-listeners \
  --profile ir-responder \
  --region us-east-1 \
  --load-balancer-arn "$ALB_ARN" \
  --query 'Listeners[*].[ListenerArn,Port,Protocol,DefaultActions[0].Type]' \
  --output table
```

```bash
# Dump ALL rules on the HTTPS listener — look for low-priority rules with http-header conditions
LISTENER_ARN="arn:aws:elasticloadbalancing:us-east-1:ACCOUNT_ID:listener/app/ALBNAME/ALBID/LISTENERID"

aws elbv2 describe-rules \
  --profile ir-responder \
  --region us-east-1 \
  --listener-arn "$LISTENER_ARN" \
  --output json | jq '.Rules[] | {
    priority: .Priority,
    ruleArn: .RuleArn,
    conditions: .Conditions,
    actions: .Actions,
    isDefault: .IsDefault
  }' | jq 'select(.priority != "default")' | sort_by(.priority | tonumber)
```

```bash
# Specifically find rules with http-header conditions missing authenticate-cognito in actions
aws elbv2 describe-rules \
  --profile ir-responder \
  --region us-east-1 \
  --listener-arn "$LISTENER_ARN" \
  --output json | jq '.Rules[] | select(
    any(.Conditions[]; .Field == "http-header") and
    (all(.Actions[]; .Type != "authenticate-cognito"))
  ) | {priority: .Priority, ruleArn: .RuleArn, conditions: .Conditions, actions: .Actions}'
```

#### Step 4: Check ALB access logs for active exploitation

```bash
# Query ALB access logs in S3 for requests that got HTTP 200 with X-Bypass-Auth header
# (requires Athena table over ALB access log S3 prefix, or direct S3 grep)
# Athena query — run via aws athena start-query-execution:

aws athena start-query-execution \
  --profile ir-responder \
  --region us-east-1 \
  --query-string "
    SELECT request_creation_time, client_ip, target_status_code,
           request_url, user_agent
    FROM alb_access_logs
    WHERE date >= date '2026-08-20'
      AND target_status_code = '200'
      AND request_url LIKE 'https://%'
      AND ssl_protocol IS NOT NULL
      /* ALB logs do not echo custom request headers directly; correlate 200s
         that lack x-amzn-oidc-identity in response headers against rule creation time */
    ORDER BY request_creation_time DESC
    LIMIT 500
  " \
  --result-configuration OutputLocation=s3://YOUR-IR-RESULTS-BUCKET/athena/ \
  --work-group primary
```

```bash
# GuardDuty findings in last 72 hours
aws guardduty list-detectors \
  --profile ir-responder \
  --region us-east-1 \
  --output json | jq -r '.DetectorIds[]' | while read DID; do
    aws guardduty list-findings \
      --profile ir-responder \
      --region us-east-1 \
      --detector-id "$DID" \
      --finding-criteria '{"Criterion":{"updatedAt":{"Gt":'"$(date -u -d '72 hours ago' +%s000)"'},"type":{"Eq":["UnauthorizedAccess:IAMUser/MaliciousIPCaller"]}}}' \
      --output json | jq ".FindingIds[] | {detectorId: \"$DID\", findingId: .}"
done
```

#### Step 5: Attribute — confirm source IP and key used

```bash
# Pull full CloudTrail event detail for the CreateRule event to get source IP, user agent, and key ID
aws cloudtrail lookup-events \
  --profile ir-responder \
  --region us-east-1 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRule \
  --start-time "$(date -u -d '72 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.Events[].CloudTrailEvent | fromjson | {
    eventTime,
    accessKeyId: .userIdentity.accessKeyId,
    principalArn: .userIdentity.arn,
    sourceIPAddress,
    userAgent
  }'
```

```bash
# List all access keys for the compromised user and identify which key was used
aws iam list-access-keys \
  --profile ir-responder \
  --user-name elbv2-bypass-victim-user \
  --output json | jq '.AccessKeyMetadata[] | {AccessKeyId, Status, CreateDate}'
```

---

## 3. Containment

### Immediate Actions (First 15 Minutes)

#### 3.1 Disable the compromised IAM access key

```bash
# IMMEDIATELY disable the victim key — do NOT delete yet (preserve for forensics)
VICTIM_KEY_ID="AKIAIOSFODNN7EXAMPLE"  # From CloudTrail accessKeyId field

aws iam update-access-key \
  --profile ir-responder \
  --user-name elbv2-bypass-victim-user \
  --access-key-id "$VICTIM_KEY_ID" \
  --status Inactive

# Verify
aws iam list-access-keys \
  --profile ir-responder \
  --user-name elbv2-bypass-victim-user \
  --output json | jq '.AccessKeyMetadata[] | {AccessKeyId, Status}'
```

#### 3.2 Delete the injected backdoor listener rule

```bash
# Get the injected rule ARN (from investigation Step 3 above)
BACKDOOR_RULE_ARN="arn:aws:elasticloadbalancing:us-east-1:ACCOUNT_ID:listener-rule/app/ALBNAME/ALBID/LISTENERID/RULEID"

# Delete it
aws elbv2 delete-rule \
  --profile ir-responder \
  --region us-east-1 \
  --rule-arn "$BACKDOOR_RULE_ARN"

# Verify it is gone — rule should no longer appear
aws elbv2 describe-rules \
  --profile ir-responder \
  --region us-east-1 \
  --listener-arn "$LISTENER_ARN" \
  --output json | jq '.Rules[] | {priority: .Priority, ruleArn: .RuleArn, conditions: .Conditions}'
```

#### 3.3 Verify default Cognito authentication is still intact on the listener

```bash
# Confirm the default action on the HTTPS listener remains authenticate-cognito
aws elbv2 describe-listeners \
  --profile ir-responder \
  --region us-east-1 \
  --listener-arns "$LISTENER_ARN" \
  --output json | jq '.Listeners[].DefaultActions[] | {Type, AuthenticateCognitoConfig}'
```

#### 3.4 Attach an explicit IAM deny policy to the victim user (belt-and-suspenders)

```bash
# Inline deny policy blocks all ELB mutations even if key is somehow re-enabled
aws iam put-user-policy \
  --profile ir-responder \
  --user-name elbv2-bypass-victim-user \
  --policy-name IR-EmergencyDenyELBWrite \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Deny",
      "Action":["elasticloadbalancing:CreateRule","elasticloadbalancing:ModifyRule",
                "elasticloadbalancing:DeleteRule","elasticloadbalancing:ModifyListener",
                "elasticloadbalancing:CreateListener"],
      "Resource":"*"
    }]
  }'
```

#### 3.5 Block attacker source IP at the ALB WAF (if WAF is associated)

```bash
# Get WAF ACL associated with the ALB
aws wafv2 list-web-acls \
  --profile ir-responder \
  --region us-east-1 \
  --scope REGIONAL \
  --output json | jq '.WebACLs[] | {Name, ARN}'

# Create an IP set for the attacker IP and block it
ATTACKER_IP="x.x.x.x/32"  # From CloudTrail sourceIPAddress

aws wafv2 create-ip-set \
  --profile ir-responder \
  --region us-east-1 \
  --name IR-Attacker-Block \
  --scope REGIONAL \
  --ip-address-version IPV4 \
  --addresses "$ATTACKER_IP"
# Then associate a block rule to the web ACL via update-web-acl (manual step — ACL structure varies)
```

---

## 4. Eradication

### Remove Attacker Access and Persistence

#### 4.1 Delete the compromised access key (after forensic copy)

```bash
# Record the key metadata before deletion
aws iam list-access-keys \
  --profile ir-responder \
  --user-name elbv2-bypass-victim-user \
  --output json > /tmp/ir-victim-user-keys-$(date +%Y%m%d).json

# Delete the compromised key
aws iam delete-access-key \
  --profile ir-responder \
  --user-name elbv2-bypass-victim-user \
  --access-key-id "$VICTIM_KEY_ID"
```

#### 4.2 Issue new access key for victim user (if it is a legitimate service account)

```bash
# Only if the victim user must continue operating — rotate to a new key
aws iam create-access-key \
  --profile ir-responder \
  --user-name elbv2-bypass-victim-user \
  --output json | jq '{AccessKeyId: .AccessKey.AccessKeyId, SecretAccessKey: .AccessKey.SecretAccessKey}'
# Store in AWS Secrets Manager immediately; never in plaintext
```

#### 4.3 Audit all listener rules across all ALBs for additional backdoors

```bash
# Enumerate every listener in the account, dump all non-default rules
aws elbv2 describe-load-balancers \
  --profile ir-responder \
  --region us-east-1 \
  --output json | jq -r '.LoadBalancers[].LoadBalancerArn' | while read ALB; do
    aws elbv2 describe-listeners \
      --region us-east-1 \
      --load-balancer-arn "$ALB" \
      --output json | jq -r '.Listeners[].ListenerArn' | while read LIS; do
        echo "=== Listener: $LIS ===" >&2
        aws elbv2 describe-rules \
          --region us-east-1 \
          --listener-arn "$LIS" \
          --output json | jq --arg l "$LIS" '
            .Rules[] | select(.IsDefault == false) | {
              listener: $l,
              priority: .Priority,
              ruleArn: .RuleArn,
              conditions: .Conditions,
              actions: .Actions
            }'
      done
done
```

#### 4.4 Review IAM policy for victim user — remove over-privileged ELB permissions

```bash
# Review attached managed policies
aws iam list-attached-user-policies \
  --profile ir-responder \
  --user-name elbv2-bypass-victim-user \
  --output table

# Review inline policies
aws iam list-user-policies \
  --profile ir-responder \
  --user-name elbv2-bypass-victim-user \
  --output table

# Pull the specific policy document and identify elasticloadbalancing:CreateRule / ModifyRule
# (substitute actual policy name)
aws iam get-user-policy \
  --profile ir-responder \
  --user-name elbv2-bypass-victim-user \
  --policy-name POLICY_NAME \
  --output json | jq '.PolicyDocument.Statement[] | select(.Action | if type == "array" then any(startswith("elasticloadbalancing:")) else startswith("elasticloadbalancing:") end)'
```

#### 4.5 Remove the emergency deny policy once permanent policy is scoped correctly

```bash
aws iam delete-user-policy \
  --profile ir-responder \
  --user-name elbv2-bypass-victim-user \
  --policy-name IR-EmergencyDenyELBWrite
```

---

## 5. Recovery

### Restore Clean State

#### 5.1 Verify the Cognito default action is active and no stray rules remain

```bash
# Full listener rule audit — expect ONLY the default rule (priority: default)
aws elbv2 describe-rules \
  --profile ir-responder \
  --region us-east-1 \
  --listener-arn "$LISTENER_ARN" \
  --output json | jq '.Rules[] | {priority: .Priority, isDefault: .IsDefault, actions: [.Actions[].Type], conditions: .Conditions}'

# Expected output: only one rule, IsDefault: true, actions: ["authenticate-cognito","forward"]
```

#### 5.2 Re-test authentication enforcement (A/B proof of restored protection)

```bash
# With magic header — should now get 302 to Cognito (no longer 200)
curl -v -k -H "X-Bypass-Auth: ATTACKER_SECRET_VALUE" "https://ALB_DNS_NAME/" 2>&1 | grep "< HTTP"

# Without magic header — should also get 302 to Cognito
curl -v -k "https://ALB_DNS_NAME/" 2>&1 | grep "< HTTP"

# Both should return: < HTTP/1.1 302 Found  (redirect to Cognito hosted UI)
# If either returns 200, the rule was not fully removed — re-run Step 4.2
```

#### 5.3 Confirm GuardDuty is active and threat feed is current

```bash
aws guardduty get-detector \
  --profile ir-responder \
  --region us-east-1 \
  --detector-id "$DETECTOR_ID" \
  --output json | jq '{Status: .Status, UpdatedAt: .UpdatedAt, FindingPublishingFrequency: .FindingPublishingFrequency}'

# List threat intel sets — confirm active
aws guardduty list-threat-intel-sets \
  --profile ir-responder \
  --region us-east-1 \
  --detector-id "$DETECTOR_ID" \
  --output table
```

#### 5.4 Enable CloudTrail Insights for anomalous API call volume detection (if not already on)

```bash
aws cloudtrail put-insight-selectors \
  --profile ir-responder \
  --region us-east-1 \
  --trail-name YOUR-TRAIL-NAME \
  --insight-selectors '[{"InsightType":"ApiCallRateInsight"},{"InsightType":"ApiErrorRateInsight"}]'
```

#### 5.5 Deploy preventive SCP to block non-automation principals from mutating ALB rules

```json
// SCP to attach via Organizations — attach at OU or account level
// Block elasticloadbalancing write actions except from deployment role
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyALBRuleMutationByNonAutomation",
      "Effect": "Deny",
      "Action": [
        "elasticloadbalancing:CreateRule",
        "elasticloadbalancing:ModifyRule",
        "elasticloadbalancing:DeleteRule",
        "elasticloadbalancing:ModifyListener"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/infra-deploy-*",
            "arn:aws:iam::*:role/AWSControlTowerExecution"
          ]
        }
      }
    }
  ]
}
```

```bash
# Apply SCP (requires Organizations management account access)
aws organizations create-policy \
  --profile organizations-admin \
  --content file://scp-deny-alb-mutation.json \
  --name DenyALBRuleMutationByNonAutomation \
  --type SERVICE_CONTROL_POLICY \
  --description "Prevent non-automation principals from mutating ALB listener rules"
```

---

## 6. Lessons Learned

### What Would Have Prevented or Caught This Earlier

| Gap | Finding | Recommended Control |
|-----|---------|---------------------|
| **Overprivileged IAM policy** | `elbv2-bypass-victim-user` held `elasticloadbalancing:CreateRule` — a write permission no data-plane service account needs | Enforce least-privilege: application service accounts should have zero ELB write permissions; infrastructure changes go through IaC pipeline roles only |
| **No real-time alert on CreateRule** | The backdoor existed for an undetermined window before detection | CloudWatch Metric Filter on CloudTrail: `{ $.eventName = "CreateRule" && $.eventSource = "elasticloadbalancing.amazonaws.com" }` with SNS alarm; threshold = 1 |
| **No alert on Describe* burst** | Pre-compromise enumeration was invisible | CloudWatch Metric Filter counting ELB Describe* calls per principal per 5-minute window; alarm at >= 4 distinct Describe* EventNames in one window |
| **ALB access logs not parsed for auth header anomalies** | Active exploitation was not detected in near-real-time | SIEM rule: ALB log 200 response on Cognito-protected listener with no `x-amzn-oidc-identity` forwarded header — indicates unauthenticated successful access |
| **No SCP guarding ALB mutations** | Any compromised IAM principal with the right policy could inject rules | Attach SCP restricting `elasticloadbalancing:CreateRule/ModifyRule/DeleteRule` to known IaC roles only |
| **No GuardDuty custom threat list** | Attacker IP not in default threat feed would not generate a finding | Add egress IPs of attacker infrastructure to a GuardDuty custom threat list via `upload-ip-set` to catch reconnaissance and exploitation from known-bad IPs |
| **No change-management baseline for listener rules** | No automated drift detection on listener rule count/structure | Use AWS Config custom rule or Conformance Pack: detect when a new listener rule lacks `authenticate-cognito` on a listener whose default action is `authenticate-cognito`; trigger Lambda remediation |

### Post-Incident Actions Checklist

- [ ] File incident report with root cause: overprivileged IAM key, no real-time write-API alerting
- [ ] Rotate all other IAM access keys in the same account that hold `elasticloadbalancing:CreateRule`
- [ ] Review IAM Access Analyzer findings for all user principals — scope down write permissions
- [ ] Deploy CloudWatch alarms for `CreateRule`, `ModifyRule`, `DeleteRule` on all ELB listeners
- [ ] Enable ALB access log parsing in SIEM with Cognito auth-bypass correlation rule
- [ ] Deploy SCP to block direct ALB mutation by non-automation principals
- [ ] Schedule quarterly red-team exercise targeting ALB listener rule injection (T1556) to validate controls

---

*Playbook generated: 2026-08-27 | Technique: T1556 — Modify Authentication Process | Platform: AWS ELBv2 | SANS PICERL framework*