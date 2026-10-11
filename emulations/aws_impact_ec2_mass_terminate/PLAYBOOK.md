# IR Playbook: ATOMIC-ec2-mass-terminate — AWS EC2 Mass Instance Termination

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Cloud Instance Destruction / Infrastructure Sabotage |
| Threat Actor | ATOMIC-ec2-mass-terminate (technique emulation) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Impact |
| MITRE Techniques | T1578.003 — Delete Cloud Instance |
| Attack Surface | EC2 control plane via compromised IAM automation credentials |

---

## 1. Preparation

### Prerequisites

**Logging and Visibility**
- CloudTrail must be enabled in all regions with management event logging (read + write). Multi-region trail strongly recommended.
- CloudTrail logs must be delivered to a protected S3 bucket (or CloudWatch Logs / Security Lake) — not accessible to ops automation roles.
- AWS Config must be enabled with the `ec2-instance-managed-by-ssm` and EC2 state-change rules active.
- AWS Security Hub EC2.8 control ("EC2 instances should use Instance Metadata Service Version 2") enabled — raises FAILED findings when `disableApiTermination` is modified.
- Amazon EventBridge rule on `EC2 Instance State-change Notification` → SNS/PagerDuty for `terminated` state transitions.
- GuardDuty enabled (detects anomalous credential use from unexpected source IPs).

**Access Controls**
- Termination protection enabled by default on all production-tagged EC2 instances via SCP or AWS Config auto-remediation.
- `MayaTrailScenario` (or equivalent environment tag) enforced via SCP: deny `ec2:TerminateInstances` on resources **without** the tag from automation roles, and deny `ec2:ModifyInstanceAttribute` (disableApiTermination) outside a change-window.
- IAM ops automation roles scoped to minimum necessary actions; no `ec2:ModifyInstanceAttribute` unless business-justified.
- Separate, MFA-protected break-glass credentials for incident response.

**Runbooks and Contacts**
- On-call schedule for cloud infrastructure team loaded in PagerDuty.
- Snapshot/backup policy verified: EBS snapshots or AMI backups taken within last 24h for all production instances.

---

## 2. Identification

### Detection Triggers

**HIGH-CONFIDENCE — these events in sequence almost always indicate active compromise:**

| Priority | Event | Source | Why High-Confidence |
|----------|-------|--------|---------------------|
| 1 | `TerminateInstances` on 2+ instances in a single API call | CloudTrail ec2.amazonaws.com | Legitimate operations almost never terminate multiple prod instances simultaneously |
| 2 | `ModifyInstanceAttribute` (disableApiTermination=false) on 3+ instances within 5 min | CloudTrail ec2.amazonaws.com | Bulk protection removal is a precursor signature with no benign explanation |
| 3 | `ModifyInstanceAttribute` immediately followed by `TerminateInstances` on the same instance IDs | CloudTrail ec2.amazonaws.com | Sequential disable-then-terminate is the canonical destruction pattern |
| 4 | `TerminateInstances` from a source IP not in the ops automation IP allowlist | CloudTrail sourceIPAddress | Credential theft indicator — automation should run from known CIDRs |

**MEDIUM-CONFIDENCE — investigate but may have benign explanations:**

| Priority | Event | Source | Notes |
|----------|-------|--------|-------|
| 5 | `GetCallerIdentity` from the ops automation principal from an unexpected IP | CloudTrail sts.amazonaws.com | Could be key rotation test; correlate with subsequent EC2 events |
| 6 | `DescribeInstances` with no subsequent EC2 changes (reconnaissance only) | CloudTrail ec2.amazonaws.com | Enumeration without follow-up action; watch for recurrence |
| 7 | `TerminateInstances` returning `UnauthorizedOperation` on an untagged instance | CloudTrail ec2.amazonaws.com (errorCode) | Attacker testing scope of credentials; no damage yet but attack in progress |
| 8 | EC2.8 Security Hub finding: termination protection disabled | AWS Security Hub | Could be legitimate maintenance; confirm with change record |
| 9 | EC2 instance state-change to `terminated` for production-tagged instances | EventBridge / AWS Health | Could be scheduled decommission; cross-check with change management |

---

### Key Investigation Queries

**Step 1 — Identify the timeframe and principal involved**

```bash
# Find all TerminateInstances events in the last 24 hours
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=TerminateInstances \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].{Time:EventTime,User:Username,Source:CloudTrailEvent}' \
  --output json
```

```bash
# Find ModifyInstanceAttribute (termination protection changes) in last 24 hours
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyInstanceAttribute \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].{Time:EventTime,User:Username,RawEvent:CloudTrailEvent}' \
  --output json | \
  python3 -c "
import json, sys
events = json.load(sys.stdin)
for e in events:
    raw = json.loads(e['RawEvent'])
    req = raw.get('requestParameters', {})
    if 'disableApiTermination' in str(req):
        print(json.dumps({'time': e['Time'], 'user': e['User'], 'params': req}, indent=2))
"
```

```bash
# Find GetCallerIdentity calls from the ops automation principal
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[?contains(Username, `prod-ops`)]' \
  --output json
```

**Step 2 — Scope the affected instances**

```bash
# Check current state of all instances in the VPC (substitute your VPC ID)
aws ec2 describe-instances \
  --filters "Name=vpc-id,Values=vpc-XXXXXXXX" \
  --query 'Reservations[].Instances[].{ID:InstanceId,State:State.Name,Name:Tags[?Key==`Name`]|[0].Value,Scenario:Tags[?Key==`MayaTrailScenario`]|[0].Value}' \
  --output table
```

```bash
# List instances that transitioned to 'terminated' in the last hour
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=terminated" \
  --query 'Reservations[].Instances[?StateTransitionReason!=`null`].{ID:InstanceId,Reason:StateTransitionReason,LaunchTime:LaunchTime}' \
  --output table
```

```bash
# Check termination protection status on surviving instances
aws ec2 describe-instance-attribute \
  --instance-id i-XXXXXXXXXXXXXXXXX \
  --attribute disableApiTermination \
  --query 'DisableApiTermination.Value'
```

**Step 3 — Identify source IP and determine if credential theft occurred**

```bash
# Extract source IP from the TerminateInstances CloudTrail event
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=TerminateInstances \
  --start-time $(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].CloudTrailEvent' \
  --output text | \
  python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        print('sourceIPAddress:', e.get('sourceIPAddress'))
        print('userAgent:', e.get('userAgent'))
        print('userIdentity:', json.dumps(e.get('userIdentity'), indent=2))
        print('requestParameters:', json.dumps(e.get('requestParameters'), indent=2))
    except: pass
"
```

```bash
# Find all events by the compromised principal in the attack window (broaden scope)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=prod-ops-role \
  --start-time $(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].{Time:EventTime,Event:EventName,Source:EventSource}' \
  --output table
```

**Step 4 — Check for denied termination attempts (attacker scope testing)**

```bash
# Find UnauthorizedOperation errors from EC2 in recent window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=TerminateInstances \
  --start-time $(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].CloudTrailEvent' \
  --output text | \
  python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        if e.get('errorCode') == 'Client.UnauthorizedOperation':
            print('DENIED attempt at:', e['eventTime'])
            print('Source IP:', e.get('sourceIPAddress'))
            print('Target:', json.dumps(e.get('requestParameters'), indent=2))
    except: pass
"
```

**Step 5 — Check Access Advisor and recent key usage for the ops role**

```bash
# Check when the ops role's credentials were last used
aws iam get-role \
  --role-name prod-ops-role \
  --query 'Role.RoleLastUsed'

# If static IAM user credentials were used instead:
aws iam list-access-keys \
  --user-name prod-ops-user \
  --query 'AccessKeyMetadata[].{KeyId:AccessKeyId,Status:Status,Created:CreateDate}'

aws iam get-access-key-last-used \
  --access-key-id AKIAXXXXXXXXXXXXXXXX \
  --query 'AccessKeyLastUsed'
```

**Step 6 — Check GuardDuty findings for credential anomaly**

```bash
# List active GuardDuty findings filtered by EC2 or IAM anomaly types
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "updatedAt": {"GreaterThanOrEqual": '$(date -d '24 hours ago' +%s000)'},
      "severity": {"GreaterThanOrEqual": 4}
    }
  }' \
  --query 'FindingIds' \
  --output json | \
  xargs -I{} aws guardduty get-findings \
    --detector-id $DETECTOR_ID \
    --finding-ids {} \
    --query 'Findings[].{Type:Type,Severity:Severity,Resource:Resource.ResourceType,Detail:Description}' \
    --output table
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**ACTION 1 — Deactivate the compromised access key (do this first)**

```bash
# If static IAM user key was compromised:
aws iam update-access-key \
  --user-name prod-ops-user \
  --access-key-id AKIAXXXXXXXXXXXXXXXX \
  --status Inactive

# Verify deactivation
aws iam list-access-keys \
  --user-name prod-ops-user \
  --query 'AccessKeyMetadata[?Status==`Active`]'
```

```bash
# If role credentials were leaked via assume-role, revoke all active sessions:
# Add a deny-all inline policy with a date condition to invalidate existing tokens
aws iam put-role-policy \
  --role-name prod-ops-role \
  --policy-name EmergencyRevocation \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
        }
      }
    }]
  }'
```

**ACTION 2 — Protect remaining instances immediately**

```bash
# Re-enable termination protection on all surviving production instances
for INSTANCE_ID in i-XXXXXXX1 i-XXXXXXX2 i-XXXXXXX3; do
  echo "Re-enabling termination protection on $INSTANCE_ID"
  aws ec2 modify-instance-attribute \
    --instance-id $INSTANCE_ID \
    --disable-api-termination
done
```

```bash
# Verify termination protection is now active
for INSTANCE_ID in i-XXXXXXX1 i-XXXXXXX2; do
  aws ec2 describe-instance-attribute \
    --instance-id $INSTANCE_ID \
    --attribute disableApiTermination \
    --query '{Instance:InstanceId,TerminationProtected:DisableApiTermination.Value}'
done
```

**ACTION 3 — Isolate attacker source IP if identified**

```bash
# Add a deny rule to the ops automation security group blocking the attacker's IP
# Replace sg-XXXXXXXXX with the relevant SG and X.X.X.X with attacker IP
aws ec2 revoke-security-group-ingress \
  --group-id sg-XXXXXXXXX \
  --protocol tcp \
  --port 443 \
  --cidr X.X.X.X/32

# If attacker IP is hitting NAT Gateway or VPC endpoints, add a network ACL block:
aws ec2 create-network-acl-entry \
  --network-acl-id acl-XXXXXXXXX \
  --ingress \
  --rule-number 1 \
  --protocol -1 \
  --cidr-block X.X.X.X/32 \
  --rule-action deny
```

**ACTION 4 — Snapshot surviving instances for forensics**

```bash
# Create EBS snapshots of all running production instances before any further action
for INSTANCE_ID in i-XXXXXXX1 i-XXXXXXX2; do
  # Get the root volume ID
  VOL_ID=$(aws ec2 describe-instances \
    --instance-ids $INSTANCE_ID \
    --query 'Reservations[0].Instances[0].BlockDeviceMappings[?DeviceName==`/dev/xvda`].Ebs.VolumeId' \
    --output text)
  
  aws ec2 create-snapshot \
    --volume-id $VOL_ID \
    --description "IR-forensic-snapshot-$(date +%Y%m%d-%H%M)-$INSTANCE_ID" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=Purpose,Value=IRForensics},{Key=InstanceId,Value=$INSTANCE_ID}]"
  
  echo "Snapshot initiated for $INSTANCE_ID (volume $VOL_ID)"
done
```

**ACTION 5 — Notify stakeholders and open incident**

```bash
# Send SNS notification to the on-call engineering team
aws sns publish \
  --topic-arn arn:aws:sns:us-east-1:ACCOUNT_ID:on-call-critical \
  --subject "CRITICAL: EC2 Mass Termination Detected" \
  --message "Production EC2 instances terminated via compromised prod-ops-role credentials. Incident in progress. Key deactivated. Time: $(date -u). Investigate CloudTrail for TerminateInstances and ModifyInstanceAttribute events."
```

---

## 4. Eradication

### Remove Attacker Access

**Delete the compromised access key (after rotating dependent systems)**

```bash
# First confirm which systems use this key (check Parameter Store / Secrets Manager)
aws secretsmanager list-secrets \
  --query 'SecretList[?contains(Name, `ops`) || contains(Name, `automation`)].{Name:Name,ARN:ARN}' \
  --output table

aws ssm describe-parameters \
  --parameter-filters "Key=Name,Option=Contains,Values=ops,key,automation" \
  --query 'Parameters[].{Name:Name,LastModified:LastModifiedDate}' \
  --output table
```

```bash
# Create a replacement key for legitimate use before deleting the compromised one
aws iam create-access-key \
  --user-name prod-ops-user \
  --query 'AccessKey.{KeyId:AccessKeyId,Secret:SecretAccessKey}'

# Update the secret in Secrets Manager with the new key
aws secretsmanager update-secret \
  --secret-id arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:prod-ops-credentials \
  --secret-string '{"access_key_id":"AKIANEWKEY","secret_access_key":"newSecretValue"}'

# Now delete the compromised key
aws iam delete-access-key \
  --user-name prod-ops-user \
  --access-key-id AKIACOMPROMISEDKEY
```

**Remove the emergency revocation policy and restore normal ops**

```bash
# Only after new key is deployed and verified working
aws iam delete-role-policy \
  --role-name prod-ops-role \
  --policy-name EmergencyRevocation
```

**Audit and tighten the prod-ops-role IAM policy**

```bash
# Review current attached policies
aws iam list-attached-role-policies --role-name prod-ops-role
aws iam list-role-policies --role-name prod-ops-role

# Check if ec2:ModifyInstanceAttribute should be in the policy at all
aws iam get-role-policy \
  --role-name prod-ops-role \
  --policy-name prod-ops-role-policy \
  --query 'PolicyDocument' | python3 -m json.tool
```

```bash
# If ModifyInstanceAttribute is not needed, remove it:
# Pull current policy, edit to remove the action, then put the updated version
aws iam get-role-policy \
  --role-name prod-ops-role \
  --policy-name prod-ops-role-policy \
  --query 'PolicyDocument' > /tmp/policy_backup.json

# After editing /tmp/policy_updated.json to remove ec2:ModifyInstanceAttribute:
aws iam put-role-policy \
  --role-name prod-ops-role \
  --policy-name prod-ops-role-policy \
  --policy-document file:///tmp/policy_updated.json
```

**Check for any backdoors created during the attack window**

```bash
# Check for new IAM users, roles, or access keys created during the attack window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time $(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --start-time $(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time $(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)

# Check for new security group rules or VPC changes that could establish persistence
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress \
  --start-time $(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)
```

```bash
# Check if any Lambda functions or SSM automation docs were modified (alternate persistence)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionCode \
  --start-time $(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateDocument \
  --start-time $(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)
```

---

## 5. Recovery

### Restore Clean State

**Step 1 — Verify terminated instances cannot be recovered (EC2 termination is irreversible)**

```bash
# Confirm instance state
aws ec2 describe-instances \
  --instance-ids i-TERMINATED1 i-TERMINATED2 i-TERMINATED3 \
  --query 'Reservations[].Instances[].{ID:InstanceId,State:State.Name,Reason:StateTransitionReason}'

# Note: terminated instances are removed from the API after ~1 hour
# EBS root volumes are also deleted unless DeleteOnTermination was false
```

**Step 2 — Restore instances from the most recent snapshots or AMIs**

```bash
# Find the most recent production AMIs
aws ec2 describe-images \
  --owners self \
  --filters "Name=tag:Environment,Values=production" \
  --query 'sort_by(Images, &CreationDate)[-3:].{ID:ImageId,Name:Name,Created:CreationDate}' \
  --output table

# Launch replacement web server from AMI
aws ec2 run-instances \
  --image-id ami-XXXXXXXXXXXXXXXXX \
  --instance-type t3.medium \
  --key-name prod-keypair \
  --subnet-id subnet-XXXXXXXXX \
  --security-group-ids sg-XXXXXXXXX \
  --disable-api-termination \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=target-web-01},{Key=MayaTrailScenario,Value=ec2-mass-terminate},{Key=Environment,Value=production}]'
```

**Step 3 — Re-enable termination protection on all newly launched instances**

```bash
# Verify all new production instances have termination protection enabled
aws ec2 describe-instances \
  --filters "Name=tag:Environment,Values=production" "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].InstanceId' \
  --output text | \
  xargs -n1 -I{} aws ec2 describe-instance-attribute \
    --instance-id {} \
    --attribute disableApiTermination \
    --query '{ID:InstanceId,Protected:DisableApiTermination.Value}'
```

**Step 4 — Verify Security Hub EC2.8 control returns to PASSED**

```bash
# Check Security Hub findings for EC2.8 (termination protection)
aws securityhub get-findings \
  --filters '{
    "ComplianceSecurityControlId": [{"Value": "EC2.8", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
  }' \
  --query 'Findings[].{Title:Title,Status:Compliance.Status,Resource:Resources[0].Id}' \
  --output table
```

**Step 5 — Confirm GuardDuty is active and no new anomalies are firing**

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

aws guardduty get-detector \
  --detector-id $DETECTOR_ID \
  --query '{Status:Status,UpdatedAt:UpdatedAt,FindingPublishingFrequency:FindingPublishingFrequency}'
```

**Step 6 — Rotate any other credentials the prod-ops-role may have accessed**

```bash
# Check what Secrets Manager secrets the ops role accessed during the attack window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time $(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[?contains(Username, `prod-ops`)].{Time:EventTime,Event:EventName,Secret:Resources[0].ARN}' \
  --output table

# Rotate any exposed secrets
aws secretsmanager rotate-secret \
  --secret-id arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:possibly-accessed-secret
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Category | Finding |
|----------|---------|
| Initial Access | Static IAM access key for ops automation role leaked or exfiltrated |
| Enablement | `ec2:ModifyInstanceAttribute` granted to ops role, permitting termination protection bypass |
| Impact Amplification | Mass single-call `TerminateInstances` destroyed three instances simultaneously |
| Detection Gap | No real-time alert on `disableApiTermination=false` for production-tagged instances |
| Audit Trail | All actions visible in CloudTrail; detection was possible but relied on log polling |

### Guardrails That Would Have Prevented This

**1. Prevent static long-lived credentials for ops automation**
Replace IAM user access keys with:
- EC2 instance profiles (if automation runs on EC2)
- OIDC-federated short-lived credentials (if running in CI/CD)
- AWS Systems Manager Run Command (eliminates key distribution entirely)

**2. Add SCP to deny `ModifyInstanceAttribute` on production-tagged resources outside change windows**
```json
{
  "Sid": "DenyTerminationProtectionRemoval",
  "Effect": "Deny",
  "Action": "ec2:ModifyInstanceAttribute",
  "Resource": "*",
  "Condition": {
    "StringEquals": {"ec2:ResourceTag/Environment": "production"},
    "StringNotEquals": {"aws:PrincipalTag/ChangeWindow": "active"}
  }
}
```

**3. Real-time EventBridge alert on `disableApiTermination` changes**
```bash
aws events put-rule \
  --name "TerminationProtectionDisabled" \
  --event-pattern '{
    "source": ["aws.cloudtrail"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["ec2.amazonaws.com"],
      "eventName": ["ModifyInstanceAttribute"],
      "requestParameters": {"disableApiTermination": {"value": [false]}}
    }
  }' \
  --state ENABLED
```

**4. Automated Config rule to re-enable termination protection on production instances**
```bash
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "ec2-termination-protection-enabled",
    "Source": {"Owner": "AWS", "SourceIdentifier": "EC2_INSTANCE_TERMINATION_PROTECTION_ENABLED"},
    "Scope": {"ComplianceResourceTypes": ["AWS::EC2::Instance"]}
  }'
```

**5. Restrict `TerminateInstances` to approved change management pipeline only**
- Require `aws:RequestedRegion` to match an approved region
- Require caller to have `aws:PrincipalTag/ApprovedDestructor=true` (set only on break-glass roles)
- Use an SCP deny on `ec2:TerminateInstances` from all principals except the decommission automation role, which requires MFA

**6. VPC endpoint policy to restrict `TerminateInstances` from inside the VPC**
```json
{
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "ec2:TerminateInstances",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {"aws:PrincipalArn": "arn:aws:iam::ACCOUNT_ID:role/approved-decommission-role"}
    }
  }]
}
```

### Post-Incident Actions (30-day window)

- [ ] Rotate all ops automation credentials project-wide; audit for other static keys
- [ ] Review all IAM roles with `ec2:ModifyInstanceAttribute` and scope them down
- [ ] Enable CloudWatch Logs Insights alert on the `ModifyInstanceAttribute → TerminateInstances` sequence pattern
- [ ] Verify EBS snapshot / AMI backup cadence meets RTO/RPO for all production instances
- [ ] Conduct tabletop exercise with cloud ops team using this playbook
- [ ] Add GuardDuty threat intelligence feed for ops automation role credential anomaly detection
- [ ] Review and tighten tag enforcement: no `ec2:RunInstances` without required `Environment` and `MayaTrailScenario` tags