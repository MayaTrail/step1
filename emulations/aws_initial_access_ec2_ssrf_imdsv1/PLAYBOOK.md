# IR Playbook: ATOMIC-ec2-ssrf-imdsv1 — AWS EC2 SSRF + IMDSv1 Credential Exfiltration

## Classification
| Field | Value |
|-------|-------|
| Incident Type | SSRF-driven IMDSv1 credential exfiltration and external credential use |
| Threat Actor | ATOMIC-ec2-ssrf-imdsv1 (technique emulation) |
| Platform | aws |
| Severity | High |
| MITRE Tactics | Initial Access (T1190 — Exploit Public-Facing Application) |
| MITRE Techniques | T1190 x4 steps: SSRF role probe, SSRF credential harvest, STS GetCallerIdentity from foreign IP, S3 ListBuckets from foreign IP |

---

## 1. Preparation

### Prerequisites
- CloudTrail data events enabled for S3 and management events for STS, IAM — verify with:
  ```bash
  aws cloudtrail get-event-selectors --trail-name <TRAIL_NAME>
  ```
- VPC Flow Logs enabled on the VPC containing EC2 instances, published to S3 (`flowlog-bucket`) or CloudWatch:
  ```bash
  aws ec2 describe-flow-logs --filter Name=resource-id,Values=<VPC_ID>
  ```
- GuardDuty enabled in every region:
  ```bash
  aws guardduty list-detectors
  ```
- IMDSv2 enforcement policy (`http-tokens=required`) applied to all EC2 instances via SCP or instance metadata options. Verify:
  ```bash
  aws ec2 describe-instances \
    --query "Reservations[].Instances[].{ID:InstanceId,IMDSv2:MetadataOptions.HttpTokens}" \
    --output table
  ```
- Instance profile least-privilege review — instance roles should not have `s3:ListAllMyBuckets` unless explicitly required.
- SIEM alert on GuardDuty finding type `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`.

---

## 2. Identification

### Detection Triggers (prioritized)

**HIGH-CONFIDENCE — these events always indicate active compromise**

| Source | Signal | Why it fires |
|--------|--------|--------------|
| GuardDuty | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | EC2 instance role credentials used from a source IP outside the EC2 IP space |
| CloudTrail | `sts:GetCallerIdentity` with `userIdentity.type=AssumedRole`, `sessionContext.sessionIssuer.type=Role`, `sourceIPAddress != EC2 IP range` | IMDS-sourced role session used from attacker IP |
| CloudTrail | `s3:ListBuckets` under the same instance role session from foreign IP | Attacker enumerating account-level S3 assets |

**MEDIUM-CONFIDENCE — corroborating signals that may indicate compromise**

| Source | Signal | Why it fires |
|--------|--------|--------------|
| VPC Flow Logs | EC2 instance making outbound TCP to `169.254.169.254:80` | Any web process (including via SSRF) triggering metadata API access |
| EC2 App Logs | `/fetch` handler log entries with `169.254.169.254` as the proxied URL | SSRF proxy endpoint being abused |
| CloudTrail | `AssumedRole` event for the instance role from `ec2.amazonaws.com` followed immediately by API calls from a different source IP | Temporal correlation: IMDS-issued credentials then used externally |

---

### Key Investigation Queries

#### 1. Find GuardDuty findings for credential exfiltration
```bash
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query "DetectorIds[0]" --output text) \
  --finding-criteria '{"Criterion":{"type":{"Eq":["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"]}}}' \
  --query "FindingIds" --output json

# Get full detail for each finding ID returned above:
aws guardduty get-findings \
  --detector-id $(aws guardduty list-detectors --query "DetectorIds[0]" --output text) \
  --finding-ids <FINDING_ID>
```

#### 2. Find CloudTrail events from the suspected instance role session
```bash
# Identify the instance role ARN first (substitute instance ID)
INSTANCE_ID="i-0xxxxxxxxxxxx"
ROLE_ARN=$(aws ec2 describe-iam-instance-profile-associations \
  --filters Name=instance-id,Values=$INSTANCE_ID \
  --query "IamInstanceProfileAssociations[0].IamInstanceProfile.Arn" \
  --output text)

# Search CloudTrail for API calls made with the role's session credentials
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=$ROLE_ARN \
  --start-time $(date -u -d "24 hours ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[].CloudTrailEvent | fromjson | {time:.eventTime, event:.eventName, source:.eventSource, srcIP:.sourceIPAddress, user:.userIdentity.arn}'
```

#### 3. Search specifically for GetCallerIdentity and ListBuckets from non-EC2 IPs
```bash
# GetCallerIdentity events in last 24h
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity \
  --start-time $(date -u -d "24 hours ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[].CloudTrailEvent | fromjson | select(.userIdentity.sessionContext.ec2RoleDelivery == "true") | {time:.eventTime, srcIP:.sourceIPAddress, roleArn:.userIdentity.arn, sessionName:.userIdentity.sessionContext.sessionIssuer.arn}'

# ListBuckets events from an AssumedRole identity
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets \
  --start-time $(date -u -d "24 hours ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[].CloudTrailEvent | fromjson | select(.userIdentity.type == "AssumedRole") | {time:.eventTime, srcIP:.sourceIPAddress, roleArn:.userIdentity.arn}'
```

#### 4. Query VPC Flow Logs for link-local (IMDS) access from the EC2 instance
```bash
# If flow logs are in CloudWatch Logs:
aws logs filter-log-events \
  --log-group-name /aws/vpc/flowlogs \
  --filter-pattern "169.254.169.254" \
  --start-time $(date -d "24 hours ago" +%s000 2>/dev/null || date -v-24H +%s000) \
  --output json | jq '.events[].message'

# If flow logs are in S3, query with Athena:
# SELECT srcaddr, dstaddr, dstport, action, protocol, start
# FROM vpc_flow_logs
# WHERE dstaddr = '169.254.169.254'
#   AND start > (CURRENT_TIMESTAMP - INTERVAL '24' HOUR)
# ORDER BY start DESC;
```

#### 5. Identify attacker's source IP from CloudTrail events
```bash
# Extract all unique source IPs used by the compromised role session
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=<ROLE_NAME_OR_ARN> \
  --start-time <INCIDENT_START_TIME> \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | .sourceIPAddress' | sort | uniq -c | sort -rn
```

#### 6. Enumerate all API actions taken by the compromised session
```bash
# Full event list for the suspected role session access key (ASIA prefix)
STALE_KEY_ID="ASIAxxxxxxxxxxxxxxxxxx"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=$STALE_KEY_ID \
  --output json | jq '.Events[].CloudTrailEvent | fromjson | {time:.eventTime, event:.eventName, source:.eventSource, srcIP:.sourceIPAddress, errorCode:.errorCode}'
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Step 1 — Disable the compromised EC2 instance role's active session
Since EC2 instance role credentials are temporary (STS), the fastest revocation is a deny-all policy on the role:

```bash
ROLE_NAME="<ec2-instance-role-name>"

# Attach an inline deny-all policy to immediately invalidate all active sessions
aws iam put-role-policy \
  --role-name $ROLE_NAME \
  --policy-name "INCIDENT-RESPONSE-DENY-ALL" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {"aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}
      }
    }]
  }'
```

#### Step 2 — Block the attacker source IP at the Security Group level
```bash
# Identify the emulation/attacker IP from CloudTrail (see Investigation step 5 above)
ATTACKER_IP="x.x.x.x/32"
EC2_INSTANCE_ID="i-0xxxxxxxxxxxx"

# Get the security group attached to the victim EC2
SG_ID=$(aws ec2 describe-instances \
  --instance-ids $EC2_INSTANCE_ID \
  --query "Reservations[0].Instances[0].SecurityGroups[0].GroupId" \
  --output text)

# Revoke inbound HTTP access from attacker IP (port 8080 - Flask SSRF proxy)
aws ec2 revoke-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 8080 \
  --cidr $ATTACKER_IP
```

#### Step 3 — Enforce IMDSv2 on the victim EC2 instance immediately
```bash
aws ec2 modify-instance-metadata-options \
  --instance-id $EC2_INSTANCE_ID \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --http-endpoint enabled
```

This kills IMDSv1 access — any new SSRF attempts against `169.254.169.254` from the Flask proxy will now receive HTTP 401 because the PUT preflight token step cannot be completed via a naive SSRF GET.

#### Step 4 — Isolate the EC2 instance (if full compromise is suspected)
```bash
# Create an isolation security group that allows only SSM access for forensics
ISOLATION_SG=$(aws ec2 create-security-group \
  --group-name "ISOLATION-IR-$(date +%Y%m%d)" \
  --description "IR isolation SG - no inbound, SSM egress only" \
  --vpc-id <VPC_ID> \
  --query "GroupId" --output text)

# Allow SSM egress (443 to 0.0.0.0/0 for SSM endpoint)
aws ec2 authorize-security-group-egress \
  --group-id $ISOLATION_SG \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# Replace instance SG with isolation SG
aws ec2 modify-instance-attribute \
  --instance-id $EC2_INSTANCE_ID \
  --groups $ISOLATION_SG
```

---

## 4. Eradication

### Remove Attacker Access

#### Step 1 — Detach and replace the compromised instance role
```bash
# Detach the current instance profile
ASSOCIATION_ID=$(aws ec2 describe-iam-instance-profile-associations \
  --filters Name=instance-id,Values=$EC2_INSTANCE_ID \
  --query "IamInstanceProfileAssociations[0].AssociationId" --output text)

aws ec2 disassociate-iam-instance-profile --association-id $ASSOCIATION_ID

# Create a new role with restricted permissions (no s3:ListAllMyBuckets, etc.)
# ... then associate new clean profile:
aws ec2 associate-iam-instance-profile \
  --instance-id $EC2_INSTANCE_ID \
  --iam-instance-profile Name=<NEW-CLEAN-PROFILE-NAME>
```

#### Step 2 — Remove the incident-response deny policy (after new role is confirmed working)
```bash
aws iam delete-role-policy \
  --role-name $ROLE_NAME \
  --policy-name "INCIDENT-RESPONSE-DENY-ALL"
```

#### Step 3 — Audit and scope all API calls made with the compromised key
```bash
# Full audit of actions taken by compromised access key
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=$STALE_KEY_ID \
  --output json | \
  jq '.Events[].CloudTrailEvent | fromjson | {time:.eventTime, event:.eventName, source:.eventSource, region:.awsRegion, resources:.resources}' \
  > compromised_session_audit.json

cat compromised_session_audit.json
```

#### Step 4 — Remediate the SSRF vulnerability in the Flask application
Patch the `/fetch` proxy handler to:
- Block requests to link-local ranges (`169.254.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Validate and allowlist permitted destination hostnames/IPs
- Apply IMDSv2 as backup enforcement (already done in Containment Step 3)

Verify the fix is deployed and the old application version is no longer running:
```bash
aws ssm send-command \
  --instance-ids $EC2_INSTANCE_ID \
  --document-name AWS-RunShellScript \
  --parameters commands=["curl -s 'http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/' || echo BLOCKED"] \
  --output text
```

---

## 5. Recovery

### Restore Clean State

#### Step 1 — Verify GuardDuty findings are resolved / no new findings
```bash
# List open findings for the detector; confirm no new InstanceCredentialExfiltration findings
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query "DetectorIds[0]" --output text) \
  --finding-criteria '{"Criterion":{"type":{"Eq":["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"]},"updatedAt":{"Gte":'$(date -d "1 hour ago" +%s000 2>/dev/null || date -v-1H +%s000)'}}}' \
  --query "FindingIds"
```

#### Step 2 — Confirm IMDSv2 enforcement is active on all instances in the account
```bash
aws ec2 describe-instances \
  --query "Reservations[].Instances[?MetadataOptions.HttpTokens!='required'].{ID:InstanceId,State:State.Name,IMDSv2:MetadataOptions.HttpTokens}" \
  --output table
```

Any instance with `HttpTokens != required` is a remaining risk — apply Step 3 from Containment to each.

#### Step 3 — Enforce IMDSv2 account-wide via SCP (prevent regression)
```bash
# Create an SCP that denies IMDSv1 (requires AWS Organizations)
aws organizations create-policy \
  --name "Enforce-IMDSv2" \
  --type SERVICE_CONTROL_POLICY \
  --description "Deny EC2 RunInstances with IMDSv1 http-tokens=optional" \
  --content '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyIMDSv1",
      "Effect": "Deny",
      "Action": "ec2:ModifyInstanceMetadataOptions",
      "Resource": "*",
      "Condition": {
        "StringEquals": {"ec2:MetadataHttpTokens": "optional"}
      }
    }]
  }'
```

#### Step 4 — Re-enable normal Security Group rules and remove isolation
```bash
# Restore original SG (replace isolation SG with pre-incident SG)
aws ec2 modify-instance-attribute \
  --instance-id $EC2_INSTANCE_ID \
  --groups $ORIGINAL_SG_ID

# Delete the isolation SG
aws ec2 delete-security-group --group-id $ISOLATION_SG
```

#### Step 5 — Verify clean CloudTrail — no API calls from attacker IP in last hour
```bash
aws cloudtrail lookup-events \
  --start-time $(date -u -d "1 hour ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-1H +%Y-%m-%dT%H:%M:%SZ) \
  --output json | \
  jq --arg ip "$ATTACKER_IP" '.Events[].CloudTrailEvent | fromjson | select(.sourceIPAddress == ($ip | rtrimstr("/32"))) | {time:.eventTime, event:.eventName, src:.sourceIPAddress}'
```

Expected result: empty set.

---

## 6. Lessons Learned

### Root Causes
| Root Cause | Guardrail |
|------------|-----------|
| Flask `/fetch` proxy did not block link-local SSRF targets | SSRF input validation: reject `169.254.0.0/16`, private RFC-1918 ranges, and loopback at the application layer |
| IMDSv1 was enabled (`http-tokens=optional`) on victim EC2 | Enforce `http-tokens=required` via SCP and EC2 launch template defaults; scan for non-compliant instances with AWS Config rule `ec2-imdsv2-check` |
| Instance role had over-broad permissions (`s3:ListAllMyBuckets`) | Apply least-privilege to all instance profiles; use AWS IAM Access Analyzer to identify unused permissions |
| No alerting on IMDS access patterns | Enable VPC Flow Logs with link-local destination alerts; consider enabling EC2 instance metadata access logging via CloudWatch agent |

### What would have prevented this
1. **IMDSv2 enforcement** — the IMDSv1 credential harvest (Steps 1-2) requires only a GET request. IMDSv2 requires a PUT preflight to obtain a session token, which cannot be forged via a naive SSRF GET proxy. A single SCP policy or EC2 instance metadata option blocks the entire attack chain before any credential is issued.
2. **SSRF input validation** — blocking requests to `169.254.0.0/16` in the `/fetch` handler prevents the proxy from ever reaching the metadata service.
3. **GuardDuty alerting SLA** — `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` fires the moment Step 3 (GetCallerIdentity from foreign IP) occurs. A 15-minute SIEM-to-oncall SLA would have contained this before S3 enumeration completed.
4. **Least-privilege instance roles** — even with credentials exfiltrated, an instance role with no permissions beyond its narrow application function limits the attacker's lateral movement surface.

### AWS Config Rules to Enable
```bash
aws configservice put-config-rule \
  --config-rule '{"ConfigRuleName":"ec2-imdsv2-check","Source":{"Owner":"AWS","SourceIdentifier":"EC2_IMDSV2_CHECK"}}'

aws configservice put-config-rule \
  --config-rule '{"ConfigRuleName":"guardduty-enabled-centralized","Source":{"Owner":"AWS","SourceIdentifier":"GUARDDUTY_ENABLED_CENTRALIZED"}}'
```