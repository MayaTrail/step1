# IR Playbook: ATOMIC-wafv2-disable-web-acl — AWS WAFv2 Firewall Impairment

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Cloud Firewall Impairment / Defense Evasion |
| Threat Actor | ATOMIC-wafv2-disable-web-acl (technique emulation) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Defense Evasion |
| MITRE Techniques | T1686.001 — Disable or Modify System Firewall: Cloud Firewall |
| Affected Services | AWS WAFv2, AWS STS, AWS IAM |
| Attack Surface | Control Plane (API) |

---

## 1. Preparation

### What should be in place before this incident

**Logging & Monitoring**
- CloudTrail management events enabled in all regions with S3 + CloudWatch Logs delivery
- WAFv2 logging enabled on all Web ACLs (separate from CloudTrail; captures sampled requests)
- CloudWatch Metric Alarms or EventBridge rules alerting on `UpdateWebACL` events from non-pipeline IAM principals
- AWS Config rule `waf-regional-webacl-not-empty` or custom rule verifying rule counts haven't dropped
- GuardDuty enabled (detects anomalous IAM role assumptions)

**Access Controls**
- WAF operator roles scoped with condition keys (`aws:RequestedRegion`, `aws:SourceIp`, `sts:ExternalId`) to limit AssumeRole blast radius
- IAM Access Analyzer monitoring for cross-account or overly permissive WAF policies
- SCPs denying `wafv2:UpdateWebACL` except from known deployment pipeline principals

**Baseline Documentation**
- Exported snapshot of all Web ACL rule sets stored in S3 or SSM Parameter Store (used for diff-based recovery)
- CMDB entry mapping each Web ACL ARN to owning team and protected application

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Events that ALWAYS indicate compromise or require immediate investigation

| Audit Event | eventSource | Why High Confidence |
|-------------|-------------|---------------------|
| `UpdateWebACL` | `wafv2.amazonaws.com` | Legitimate rule changes go through change-management pipelines; ad-hoc calls are anomalous |
| `UpdateWebACL` with `rules[0].action.allow` prepended at priority 0 | `wafv2.amazonaws.com` | Injecting a permissive Allow rule ahead of managed rule groups is an attacker TTL signature |
| `UpdateWebACL` referencing `ByteMatchStatement` on a custom `SingleHeader` | `wafv2.amazonaws.com` | Magic-header bypass pattern — `X-Bypass` or similar header not in approved ACL spec |
| `AssumeRole` to a WAF operator role from a non-CI/CD principal | `sts.amazonaws.com` | Lateral movement into WAF operator identity |

#### MEDIUM-CONFIDENCE: Events that MIGHT indicate compromise (investigate in context)

| Audit Event | eventSource | Why Medium Confidence |
|-------------|-------------|----------------------|
| `ListWebACLs` | `wafv2.amazonaws.com` | Could be legitimate auditing; suspicious if from new principal or at unusual hour |
| `GetWebACL` | `wafv2.amazonaws.com` | Read-only, but consecutive GetWebACL → UpdateWebACL sequence is a LockToken harvest pattern |
| `AssumeRole` with `roleSessionName` matching an ad-hoc pattern (e.g. `atomic-t1686001-session`) | `sts.amazonaws.com` | Non-standard session names from automation tools |
| Spike in `4xx` WAF block decisions dropping in CloudWatch (`BlockedRequests` metric falls) | CloudWatch WAF metrics | Could indicate rules were softened |

---

### Key Investigation Queries

#### 2.1 — Find all WAFv2 UpdateWebACL events in the last 24 hours

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateWebACL \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --end-time "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --query 'Events[*].{Time:EventTime,User:Username,EventId:EventId}' \
  --output table
```

#### 2.2 — Extract full CloudTrail event detail for a specific UpdateWebACL event

```bash
# Replace EVENT_ID with the EventId from query above
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventId,AttributeValue=EVENT_ID \
  --region us-east-1 \
  --query 'Events[0].CloudTrailEvent' \
  --output text | python -m json.tool
```

#### 2.3 — Find all AssumeRole calls to WAF operator roles in the last 7 days

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --query 'Events[*].{Time:EventTime,User:Username,Detail:CloudTrailEvent}' \
  --output json | python -c "
import json,sys
events = json.load(sys.stdin)
for e in events:
    detail = json.loads(e['Detail'])
    role = detail.get('requestParameters',{}).get('roleArn','')
    if 'waf' in role.lower() or 'wafv2' in role.lower():
        print(e['Time'], e['User'], role, detail.get('requestParameters',{}).get('roleSessionName',''))
"
```

#### 2.4 — Find GetWebACL calls immediately preceding UpdateWebACL (LockToken harvest pattern)

```bash
# Get all WAFv2 events by a specific principal
PRINCIPAL="arn:aws:sts::123456789012:assumed-role/atomic-wafv2-disable-web-acl-attacker-role/atomic-t1686001-session"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=atomic-t1686001-session \
  --start-time "$(date -u -d '48 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --query 'Events[*].{Time:EventTime,Event:EventName,Detail:CloudTrailEvent}' \
  --output json | python -c "
import json,sys
events = json.load(sys.stdin)
for e in sorted(events, key=lambda x: x['Time']):
    print(e['Time'], e['Event'])
"
```

#### 2.5 — Inspect the injected rule in the UpdateWebACL CloudTrail event

```bash
# Get the UpdateWebACL event and parse requestParameters to see injected rules
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateWebACL \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --output json \
  --query 'Events[*].CloudTrailEvent' \
  | python -c "
import json,sys
raw = json.load(sys.stdin)
for ct_str in raw:
    ct = json.loads(ct_str)
    rules = ct.get('requestParameters',{}).get('rules',[])
    for r in rules:
        stmt = r.get('statement',{})
        bm = stmt.get('byteMatchStatement',{})
        if bm:
            print('INJECTED ByteMatch rule found:')
            print('  ruleName:', r.get('name'))
            print('  priority:', r.get('priority'))
            print('  action:', r.get('action'))
            print('  header:', bm.get('fieldToMatch',{}).get('singleHeader',{}).get('name'))
            print('  searchString:', bm.get('searchString'))
            print('  positionalConstraint:', bm.get('positionalConstraint'))
"
```

#### 2.6 — Get current Web ACL rule configuration to assess live state

```bash
# Retrieve the current rules for the affected Web ACL
WEB_ACL_NAME="atomic-wafv2-disable-web-acl-victim-web-acl"
WEB_ACL_ID="<id-from-list-web-acls>"

aws wafv2 get-web-acl \
  --name "$WEB_ACL_NAME" \
  --scope REGIONAL \
  --id "$WEB_ACL_ID" \
  --region us-east-1 \
  --query 'WebACL.Rules[*].{Priority:Priority,Name:Name,Action:Action}' \
  --output table
```

#### 2.7 — List all regional Web ACLs (scope the blast radius)

```bash
aws wafv2 list-web-acls \
  --scope REGIONAL \
  --region us-east-1 \
  --query 'WebACLs[*].{Name:Name,Id:Id,ARN:ARN}' \
  --output table
```

#### 2.8 — Check WAFv2 logging to look for requests using the magic header

```bash
# Get logging configuration for the ACL
aws wafv2 get-logging-configuration \
  --resource-arn "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/${WEB_ACL_NAME}/${WEB_ACL_ID}" \
  --region us-east-1

# If logging to CloudWatch Logs, query for requests matching the magic header
aws logs filter-log-events \
  --log-group-name "aws-waf-logs-<your-group>" \
  --filter-pattern '{ $.httpRequest.headers[*].name = "x-bypass" }' \
  --start-time $(date -d '24 hours ago' +%s000) \
  --region us-east-1
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### 3.1 — Revoke the compromised attacker role session immediately

```bash
# Deny all permissions to the attacker role by attaching an inline deny-all policy
aws iam put-role-policy \
  --role-name "atomic-wafv2-disable-web-acl-attacker-role" \
  --policy-name "INCIDENT-RESPONSE-SESSION-REVOKE" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "'"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"'"
        }
      }
    }]
  }'
```

#### 3.2 — Immediately restore Web ACL to known-good state

```bash
# Step 1: Get current ACL config and fresh LockToken
WEB_ACL_NAME="atomic-wafv2-disable-web-acl-victim-web-acl"
WEB_ACL_ID="<id>"

CURRENT=$(aws wafv2 get-web-acl \
  --name "$WEB_ACL_NAME" \
  --scope REGIONAL \
  --id "$WEB_ACL_ID" \
  --region us-east-1)

LOCK_TOKEN=$(echo "$CURRENT" | python -c "import json,sys; d=json.load(sys.stdin); print(d['LockToken'])")

# Step 2: Identify and remove the injected ByteMatch Allow rule (priority 0)
# Build the clean rules list excluding any ByteMatch rules at priority 0
CLEAN_RULES=$(echo "$CURRENT" | python -c "
import json,sys
d = json.load(sys.stdin)
rules = d['WebACL']['Rules']
clean = [r for r in rules if not (
    r.get('priority') == 0 and
    'byteMatchStatement' in r.get('statement', {})
)]
print(json.dumps(clean))
")

# Step 3: Issue UpdateWebACL with the cleaned rules
aws wafv2 update-web-acl \
  --name "$WEB_ACL_NAME" \
  --scope REGIONAL \
  --id "$WEB_ACL_ID" \
  --lock-token "$LOCK_TOKEN" \
  --default-action '{"Block":{}}' \
  --visibility-config "$(echo "$CURRENT" | python -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d['WebACL']['VisibilityConfig']))")" \
  --rules "$CLEAN_RULES" \
  --region us-east-1
```

#### 3.3 — Block the attacker role from making further WAF API calls

```bash
# Remove wafv2 permissions from the attacker role immediately
aws iam put-role-policy \
  --role-name "atomic-wafv2-disable-web-acl-attacker-role" \
  --policy-name "INCIDENT-WAF-DENY" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": ["wafv2:*", "waf:*", "waf-regional:*"],
      "Resource": "*"
    }]
  }'
```

#### 3.4 — Update Web ACL trust policy to restrict who can assume the attacker role

```bash
# Tighten the role trust policy to prevent further AssumeRole by unauthorized principals
aws iam update-assume-role-policy \
  --role-name "atomic-wafv2-disable-web-acl-attacker-role" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole"
    }]
  }'
```

#### 3.5 — Verify Web ACL restoration succeeded

```bash
aws wafv2 get-web-acl \
  --name "$WEB_ACL_NAME" \
  --scope REGIONAL \
  --id "$WEB_ACL_ID" \
  --region us-east-1 \
  --query 'WebACL.Rules[*].{Priority:Priority,Name:Name,Action:Action,Statement:Statement}' \
  --output json | python -m json.tool
```

---

## 4. Eradication

### Remove Attacker Access

#### 4.1 — Delete the attacker IAM role entirely

```bash
# List and detach all managed policies
aws iam list-attached-role-policies \
  --role-name "atomic-wafv2-disable-web-acl-attacker-role" \
  --query 'AttachedPolicies[*].PolicyArn' \
  --output text | tr '\t' '\n' | while read ARN; do
    aws iam detach-role-policy \
      --role-name "atomic-wafv2-disable-web-acl-attacker-role" \
      --policy-arn "$ARN"
done

# Delete all inline policies
aws iam list-role-policies \
  --role-name "atomic-wafv2-disable-web-acl-attacker-role" \
  --query 'PolicyNames' \
  --output text | tr '\t' '\n' | while read PNAME; do
    aws iam delete-role-policy \
      --role-name "atomic-wafv2-disable-web-acl-attacker-role" \
      --policy-name "$PNAME"
done

# Delete the role
aws iam delete-role \
  --role-name "atomic-wafv2-disable-web-acl-attacker-role"
```

#### 4.2 — Audit all Web ACLs for similar injected ByteMatch Allow rules across all regions

```bash
for REGION in us-east-1 us-west-2 eu-west-1 ap-southeast-1; do
  echo "=== Checking region: $REGION ==="
  aws wafv2 list-web-acls \
    --scope REGIONAL \
    --region "$REGION" \
    --query 'WebACLs[*].{Name:Name,Id:Id}' \
    --output json | python -c "
import json, sys, subprocess
acls = json.load(sys.stdin)
for acl in acls:
    result = subprocess.run([
        'aws', 'wafv2', 'get-web-acl',
        '--name', acl['Name'],
        '--scope', 'REGIONAL',
        '--id', acl['Id'],
        '--region', '$REGION',
        '--output', 'json'
    ], capture_output=True, text=True)
    d = json.loads(result.stdout)
    for r in d.get('WebACL', {}).get('Rules', []):
        bm = r.get('statement', {}).get('byteMatchStatement', {})
        if bm and r.get('action', {}).get('allow') is not None:
            print(f'SUSPECT RULE in {acl[\"Name\"]} ({\"$REGION\"}): {r[\"name\"]} priority={r[\"priority\"]} header={bm.get(\"fieldToMatch\",{}).get(\"singleHeader\",{}).get(\"name\")}')
"
done
```

#### 4.3 — Search CloudTrail for the same session name across all regions and all WAFv2 calls

```bash
for REGION in us-east-1 us-west-2 eu-west-1; do
  echo "=== Region: $REGION ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=atomic-t1686001-session \
    --start-time "$(date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
    --region "$REGION" \
    --query 'Events[*].{Time:EventTime,Event:EventName,Region:EventSource}' \
    --output table
done
```

#### 4.4 — Rotate credentials for any IAM user that assumed the attacker role

```bash
# Find who issued the AssumeRole call
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '48 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --query 'Events[*].CloudTrailEvent' \
  --output json | python -c "
import json,sys
events = json.load(sys.stdin)
for e_str in events:
    e = json.loads(e_str)
    role = e.get('requestParameters',{}).get('roleArn','')
    if 'attacker' in role:
        caller = e.get('userIdentity',{})
        print('Caller type:', caller.get('type'))
        print('Caller ARN:', caller.get('arn'))
        print('Caller account:', caller.get('accountId'))
"

# If a specific user is identified, rotate their access keys
# aws iam create-access-key --user-name <caller-user>
# aws iam delete-access-key --user-name <caller-user> --access-key-id <old-key-id>
```

---

## 5. Recovery

### Restore Clean State

#### 5.1 — Verify the Web ACL rule set matches the approved baseline

```bash
# Export current state for comparison with baseline
aws wafv2 get-web-acl \
  --name "$WEB_ACL_NAME" \
  --scope REGIONAL \
  --id "$WEB_ACL_ID" \
  --region us-east-1 \
  --output json > /tmp/current_web_acl.json

echo "Rules in recovered ACL:"
cat /tmp/current_web_acl.json | python -c "
import json,sys
d = json.load(sys.stdin)
for r in d['WebACL']['Rules']:
    print(f\"  Priority {r['priority']}: {r['name']} -> {list(r['action'].keys())[0]}\")
"
```

#### 5.2 — Re-enable WAFv2 logging if it was tampered with

```bash
# Check logging config
aws wafv2 get-logging-configuration \
  --resource-arn "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/${WEB_ACL_NAME}/${WEB_ACL_ID}" \
  --region us-east-1

# Re-enable if missing or modified
aws wafv2 put-logging-configuration \
  --logging-configuration '{
    "ResourceArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/'"$WEB_ACL_NAME"'/'"$WEB_ACL_ID"'",
    "LogDestinationConfigs": ["arn:aws:firehose:us-east-1:123456789012:deliverystream/aws-waf-logs-<your-stream>"],
    "LoggingFilter": {
      "DefaultBehavior": "KEEP",
      "Filters": []
    }
  }' \
  --region us-east-1
```

#### 5.3 — Confirm no anomalous rules remain across all CLOUDFRONT-scope ACLs (us-east-1 only)

```bash
aws wafv2 list-web-acls \
  --scope CLOUDFRONT \
  --region us-east-1 \
  --query 'WebACLs[*].{Name:Name,Id:Id}' \
  --output table
```

#### 5.4 — Verify CloudTrail is still logging WAFv2 API calls normally

```bash
aws cloudtrail get-trail-status \
  --name <your-trail-name> \
  --region us-east-1 \
  --query '{IsLogging:IsLogging,LatestDelivery:LatestDeliveryTime,LatestError:LatestDeliveryError}' \
  --output table
```

#### 5.5 — Add a CloudWatch EventBridge rule to alert on future UpdateWebACL calls

```bash
aws events put-rule \
  --name "ALERT-WAFv2-UpdateWebACL-Anomaly" \
  --event-pattern '{
    "source": ["aws.wafv2"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["wafv2.amazonaws.com"],
      "eventName": ["UpdateWebACL"]
    }
  }' \
  --state ENABLED \
  --description "Alert on any WAFv2 UpdateWebACL call for incident response" \
  --region us-east-1
```

#### 5.6 — Run AWS Config evaluation to verify WAF compliance posture

```bash
aws configservice start-config-rules-evaluation \
  --config-rule-names waf-regional-webacl-not-empty \
  --region us-east-1

aws configservice describe-compliance-by-config-rule \
  --config-rule-names waf-regional-webacl-not-empty \
  --region us-east-1 \
  --query 'ComplianceByConfigRules[*].{Rule:ConfigRuleName,Compliance:Compliance.ComplianceType}' \
  --output table
```

---

## 6. Lessons Learned

### What Would Have Prevented This

| Control Gap | Recommended Guardrail |
|-------------|----------------------|
| WAF operator role trusted entire account root (`arn:aws:iam::ACCOUNT:root`) | Scope trust policy to specific deployment pipeline role ARN + require `sts:ExternalId` condition |
| No alert on `UpdateWebACL` outside of change windows | EventBridge rule → SNS → PagerDuty on any `wafv2:UpdateWebACL` call |
| No Web ACL rule baseline snapshot for diff-based alerting | Schedule daily `aws wafv2 get-web-acl` export to S3; Lambda diffs on each `UpdateWebACL` CloudTrail event |
| `ListWebACLs` + `GetWebACL` + `UpdateWebACL` all granted to same role | Split read (auditor) and write (deployer) WAF roles; require MFA for write role assumption |
| No detection for ByteMatch Allow rules at priority 0 | AWS Config custom rule or Lambda that rejects any ACL with a priority-0 `action.allow` rule not in approved list |
| WAFv2 sampled request logs not correlated with CloudTrail | Ingest WAF sampled request logs into SIEM; correlate `X-Bypass` header appearance with `UpdateWebACL` event timestamps |
| Magic-header bypass lived undetected until manual investigation | Set CloudWatch Alarm on `AllowedRequests` metric spike alongside `BlockedRequests` drop for anomaly detection |

### Key Forensic Artifacts to Preserve

```bash
# Preserve the raw CloudTrail events for the attack chain before they age out
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=atomic-t1686001-session \
  --start-time "$(date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --output json > forensic_wafv2_attack_chain_$(date +%Y%m%d).json

# Capture the GuardDuty findings if any fired
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text --region us-east-1) \
  --finding-criteria '{"Criterion":{"service.action.awsApiCallAction.serviceName":{"Eq":["wafv2.amazonaws.com"]}}}' \
  --region us-east-1
```

### MITRE D3FEND Countermeasures

| Attack Step | D3FEND Countermeasure |
|-------------|----------------------|
| T1686.001 — AssumeRole to WAF operator | `D3-LAM` — Least-Privilege Access Management; `D3-MFA` — Multi-factor Authentication |
| T1686.001 — ListWebACLs enumeration | `D3-PWID` — Per-User Identity Isolation (scoped role per service, not shared) |
| T1686.001 — GetWebACL LockToken harvest | `D3-PA` — Privileged Account Management; read/write separation |
| T1686.001 — UpdateWebACL rule injection | `D3-CCE` — Configuration Change Enforcement (enforce ACL baseline via Config rules) |