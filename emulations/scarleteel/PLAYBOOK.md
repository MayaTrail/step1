# IR Playbook: SCARLETEEL - AWS Credential Theft & Intellectual Property Exfiltration

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Cloud Credential Theft / IP Exfiltration / Cryptomining |
| Threat Actor | SCARLETEEL |
| Attribution | Unattributed (financially motivated; IP theft prioritised alongside cryptojacking) |
| Platform | aws |
| Severity | Critical |
| First Reported | Sysdig Threat Research Team - 28 February 2023 (v1), 11 July 2023 (v2) |
| MITRE Tactics | Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact |
| MITRE Techniques | T1190, T1552.005, T1552.001, T1555.006, T1580, T1526, T1619, T1613, T1685.002, T1136.003, T1098.001, T1078.004, T1530, T1537, T1648, T1496, T1498 |

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail enabled, delivering to S3 with MFA delete and object versioning
- CloudTrail log file validation enabled
- **CloudTrail S3 data events enabled on sensitive buckets** - in the original incident, object-level events were NOT enabled, which made it impossible to determine which objects the attacker read from the 1 TB they accessed
- GuardDuty enabled in all regions with EKS Protection, S3 Protection, and Lambda Protection enabled
- GuardDuty EKS Runtime Monitoring or equivalent container runtime sensor - the initial container exploitation and IMDS call happen entirely at the data plane and never appear in CloudTrail
- VPC Flow Logs enabled on all VPCs, delivered to CloudWatch Logs or S3
- Kubernetes audit logging enabled and shipped off-cluster
- AWS Config enabled with conformance pack for CIS AWS Foundations Benchmark
- Security Hub enabled with AWS Foundational Security Best Practices standard

**Alerting (must be pre-configured)**
- CloudWatch alarm on `cloudtrail:StopLogging` / `cloudtrail:DeleteTrail` metric filter
- EventBridge rule on `iam:CreateUser` + `iam:CreateAccessKey` + `iam:AttachUserPolicy` with `AdministratorAccess`
- EventBridge rule on `lambda:GetFunction` / `lambda:ListFunctions` burst from a compute-plane role
- EventBridge rule on `s3:GetObject` where key matches `*.tfstate`
- AWS Budgets anomaly alert for EC2 spend spike (>200% of baseline) - the v2 campaign launched 42 large instances
- GuardDuty findings SNS -> PagerDuty/Slack integration

**Response Tooling**
- AWS CLI v2 configured with break-glass responder credentials, separate from any potentially compromised principal
- `jq` installed for JSON parsing in response scripts
- `kubectl` access to the affected cluster with a break-glass kubeconfig
- Documented procedure for role session revocation via `aws:TokenIssueTime` - temporary credentials harvested from IMDS **cannot** be deleted like access keys
- CloudTrail log S3 bucket with S3 Object Lock (WORM) on at least 30-day retention

**Known IOC Baselines**
- Inventory legitimate IAM users - flag any user named `aws_support` or similar support-impersonating name not in baseline
- Inventory legitimate Lambda functions and confirm none carry credentials in environment variables
- Baseline expected `--endpoint-url` usage - any AWS CLI call to a non-AWS endpoint is anomalous
- Inventory which EC2 instances and node groups still permit IMDSv1 (`HttpTokens=optional`)
- Inventory legitimate Lambda functions and their execution roles, so an attacker-created function is identifiable by exception rather than by name

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE - Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `cloudtrail:StopLogging` or `cloudtrail:DeleteTrail` from any non-break-glass principal | CloudTrail / CloudWatch Alarm | T1685.002 |
| P0 | GuardDuty: `Stealth:IAMUser/CloudTrailLoggingDisabled` | GuardDuty | T1685.002 |
| P0 | `iam:CreateUser` creating `aws_support` (or comparable support-impersonating name) | CloudTrail | T1136.003 |
| P0 | `iam:CreateAccessKey` issued for multiple existing IAM users in a short window | CloudTrail | T1098.001 |
| P0 | Container process reading `169.254.169.254/latest/meta-data/iam/security-credentials/` | Runtime sensor / Falco | T1552.005 |
| P0 | AWS API call from a node/cluster role originating from an IP outside the VPC CIDR | CloudTrail | T1552.005 |
| P0 | `lambda:CreateFunction` from a compute-plane or non-CI/CD principal | CloudTrail | T1648 |
| P0 | `secretsmanager:GetSecretValue` from an EC2/node role that has no application reason to read secrets | CloudTrail | T1555.006 |
| P1 | `s3:GetObject` on a `*.tfstate` key from a non-pipeline principal | CloudTrail (data events) | T1552.001 |
| P1 | `lambda:GetFunction` on multiple functions in sequence from a compute-plane role | CloudTrail | T1530 |
| P1 | AWS CLI invoked with `--endpoint-url` pointing to a non-AWS domain | Runtime sensor / process args | T1537 |
| P1 | `ec2:RunInstances` for `c5.metal`, `r5a.4xlarge`, or comparable high-core types in unusual regions | CloudTrail | T1496 |
| P1 | `iam:AttachUserPolicy` / `iam:AttachRolePolicy` with `arn:aws:iam::aws:policy/AdministratorAccess` | CloudTrail | T1098.001 |

#### MEDIUM-CONFIDENCE - May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Burst of `iam:ListUsers` + `iam:ListRoles` + `iam:GetAccountSummary` + `sts:GetCallerIdentity` within 60 seconds | CloudTrail | T1580 |
| P2 | `s3:ListBuckets` followed by `s3:ListObjectsV2` across many buckets from one session | CloudTrail | T1619 |
| P2 | `secretsmanager:ListSecrets` followed by `GetSecretValue` in the same session | CloudTrail | T1555.006 |
| P2 | `cloudtrail:DescribeTrails` immediately preceding `StopLogging` - the attacker locating the trail to disable | CloudTrail | T1685.002 |
| P2 | `secretsmanager:GetSecretValue` on a secret the calling role has never read before | CloudTrail | T1555.006 |
| P2 | `lambda:ListFunctions` followed by `lambda:GetFunction` from a role whose intended scope is a single bucket | CloudTrail | T1526 |
| P2 | Denied `iam:CreateUser` / `iam:CreateGroup` / `iam:CreateAccessKey` - failed persistence attempts precede successful ones | CloudTrail (`errorCode`) | T1136.003 |
| P2 | `kubectl get secrets` / `get pods` / `get namespaces` from an unexpected service account (Peirates behaviour) | K8s audit log | T1613, T1552.007 |
| P2 | XMRig or SRBMiner process launch inside a container | Runtime sensor | T1496 |
| P2 | Outbound connections to `temp.sh`, `termbin.com` (port 9999), or `hb.bizmrg.com` | VPC Flow Logs / DNS logs | T1537 |
| P2 | AWS Budget anomaly: >300% EC2 spend spike | AWS Budgets | T1496 |
| P3 | GuardDuty: `CryptoCurrency:EC2/BitcoinTool.B!DNS` or `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | GuardDuty | T1552.005, T1496 |
| P3 | GuardDuty: `Discovery:IAMUser/AnomalousBehavior` | GuardDuty | T1580 |
| P3 | Mirai/Pandora binary execution or SYN flood egress from a workload | Runtime sensor / VPC Flow Logs | T1498 |

#### EMULATION COVERAGE - which triggers fire during a MayaTrail SCARLETEEL run

Mapping to the `attack.py` emulation module, for validating that these
detections are live before relying on them.

| Emulation phase | Action generated | Trigger that fires |
|-----------------|------------------|--------------------|
| 1 - Initial access | `POST /cmd` on port 8080; `id; uname -a` | Runtime P0 - shell spawned from web process |
| 1 - Miner decoy | writes `/tmp/miner.sh`, `/tmp/config_background.json`, executes | Runtime P2 - XMRig process launch |
| 2 - Credential access | `curl 169.254.169.254/.../security-credentials/` | P0 runtime IMDS rule; P0 out-of-VPC `sourceIPAddress` |
| 3 - Discovery | `sts:GetCallerIdentity`, `s3:ListBuckets`, `s3:ListObjectsV2`, `secretsmanager:ListSecrets` | P2 enumeration burst; P2 bucket listing; P2 `ListSecrets` |
| 4 - Defense evasion | `cloudtrail:StopLogging` | P0 + Query 1 |
| 5 - Lateral movement | `secretsmanager:GetSecretValue` | P0 + P2 |
| 6 - Persistence | `lambda:CreateFunction` -> `mayatrail-scarleteel-backdoor` | P0 + Query 7 |

**Triggers that will NOT fire during an emulation run.** These exist because the
real campaign performed them. Silence here is expected and is not a detection
failure - validate them by other means.

| Trigger | Why it does not fire |
|---------|----------------------|
| `s3:GetObject` on `*.tfstate` | Phase 3 lists the target bucket but never reads the state object. Also requires CloudTrail S3 data events, which are a separate prerequisite |
| `lambda:GetFunction` / `GetFunctionConfiguration` | Phase 6 creates a function rather than exfiltrating existing code. This is a deliberate divergence from the real campaign |
| `iam:CreateUser` / `CreateAccessKey` / `aws_support` | No IAM persistence phase in the emulation |
| `iam:GetRole` / `ListAttachedRolePolicies` | Phase 3 performs no IAM principal enumeration, despite the module's completion summary listing these |
| `ec2:RunInstances` for large instance types | No mining-compute phase; the miner is a decoy script only |
| `--endpoint-url` egress to non-AWS storage | Not implemented |
| Peirates / Kubernetes pivoting, Pandora DDoS | Not implemented; the stack is EC2-only with no cluster |
| Second-account pivot | Single-account stack |

`cloudtrail:DescribeTrails` fires only when the stack omits `cloudtrail_arn` from
its outputs, so treat it as non-deterministic across runs rather than a reliable
sequencing signal.

**Two timing caveats when validating against the stack's own trail.**
- The Phase 3 discovery is deliberately light - four calls (`GetCallerIdentity`,
  `ListBuckets`, `ListObjectsV2`, `ListSecrets`) across three services. It
  demonstrates the enumeration *pattern* but does not reach the volume threshold
  of a burst detector tuned for the real campaign, so a count-based enumeration
  rule will not trip on an emulation run. Validate the individual read signals
  (bucket listing, `ListSecrets`) instead.
- Phase 4 stops the stack's **single-region** trail. Every event after it -
  Phase 5 `GetSecretValue` and Phase 6 `CreateFunction` - is therefore **not
  captured by that trail**. In the emulation these are visible only if a separate
  org/management-account trail is still logging, or via GuardDuty. This is
  faithful to the real campaign, where `StopLogging` preceded the most sensitive
  actions precisely so they would leave no trail record - which is the reason the
  P0 `StopLogging` alert must route through a pipeline that does not depend on the
  same trail it is protecting.

**MITRE cross-reference.** Where the emulation's own labels differ from the
techniques used above, the emulation reports: Phase 3 `T1087.004`, Phase 5
`T1550.001`, Phase 6 `T1098`. This playbook uses `T1619`/`T1526`, `T1555.006`,
and `T1648` respectively, which map more precisely to the observed API calls.
Correlate on the phase, not the technique ID.

---

> **Detection gap to acknowledge explicitly.** Data exfiltration performed with
> `aws s3 cp --endpoint-url <attacker-endpoint>` does **not** appear in the
> victim's CloudTrail, because the request never reaches an AWS API endpoint.
> This is only catchable at the runtime or network layer. Do not treat a clean
> CloudTrail as evidence that no data left.

---

### Key Investigation Queries

#### Query 1 - Confirm CloudTrail StopLogging / DeleteTrail

```bash
for EVENT in StopLogging DeleteTrail UpdateTrail PutEventSelectors; do
  echo "=== $EVENT ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVENT" \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region us-east-1 \
    --query 'Events[*].CloudTrailEvent' \
    --output text | jq -r '{time: .eventTime, caller: .userIdentity.arn, sourceIP: .sourceIPAddress, trail: .requestParameters.name, error: .errorCode}'
done
```

#### Query 2 - Identify the compromised node/cluster role and its session

```bash
# IMDS-derived sessions surface as AssumedRole with the instance ID as session name.
# An AWS API call from a node role with a sourceIPAddress outside your VPC CIDR
# is the clearest single indicator of IMDS credential theft.

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --query 'Events[*].CloudTrailEvent' \
  --output text | \
  jq -r 'select(.userIdentity.type == "AssumedRole") | {time: .eventTime, role: .userIdentity.sessionContext.sessionIssuer.userName, session: .userIdentity.arn, sourceIP: .sourceIPAddress, ua: .userAgent}'
```

#### Query 3 - Reconstruct the enumeration sequence for one session

```bash
# Substitute the session ARN identified in Query 2.
SESSION_ARN="<arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION>"

aws cloudtrail lookup-events \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --max-results 1000 \
  --query 'Events[*].CloudTrailEvent' \
  --output text | \
  jq -r --arg arn "$SESSION_ARN" \
    'select(.userIdentity.arn == $arn) | [.eventTime, .eventSource, .eventName, (.errorCode // "OK")] | @tsv' | sort
```

#### Query 4 - Lambda code and environment variable access (IP theft)

```bash
# GetFunction returns a presigned download URL for the deployment package, and
# GetFunctionConfiguration returns environment variables. Either against several
# functions from a compute-plane role indicates source code / credential theft.

for EVENT in ListFunctions GetFunction GetFunctionConfiguration; do
  echo "=== $EVENT ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVENT" \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region us-east-1 \
    --query 'Events[*].CloudTrailEvent' \
    --output text | jq -r '{time: .eventTime, caller: .userIdentity.arn, function: .requestParameters.functionName, sourceIP: .sourceIPAddress}'
done

# Which Lambda functions currently expose credentials in environment variables?
for FN in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  VARS=$(aws lambda get-function-configuration --function-name "$FN" \
    --query 'Environment.Variables' --output json 2>/dev/null)
  echo "$VARS" | grep -qiE 'AWS_ACCESS_KEY|AWS_SECRET|SECRET|PASSWORD|TOKEN|KEY' && \
    echo "[!] $FN exposes credential-like environment variables"
done
```

#### Query 5 - Terraform state file access (the pivot to a second account)

```bash
# Two layers. ListObjectsV2 is a MANAGEMENT event and is always logged, so it
# catches the reconnaissance step even when data events are off. GetObject is a
# DATA event and only appears if data events were explicitly enabled.

# Layer 1 - bucket listing (always available)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListObjects \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --query 'Events[*].CloudTrailEvent' \
  --output text | jq -r '{time: .eventTime, caller: .userIdentity.arn, bucket: .requestParameters.bucketName, sourceIP: .sourceIPAddress}'

# Layer 2 - object reads (requires data events)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --query 'Events[*].CloudTrailEvent' \
  --output text | \
  jq -r 'select(.requestParameters.key // "" | test("tfstate")) | {time: .eventTime, caller: .userIdentity.arn, bucket: .requestParameters.bucketName, key: .requestParameters.key, sourceIP: .sourceIPAddress}'

# Independently: which state files in your buckets actually contain secrets?
for BUCKET in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  aws s3api list-objects-v2 --bucket "$BUCKET" \
    --query 'Contents[?ends_with(Key, `.tfstate`)].Key' --output text 2>/dev/null | \
    while read -r KEY; do
      [ -n "$KEY" ] && echo "[!] State file: s3://$BUCKET/$KEY"
    done
done
```

#### Query 6 - Persistence: user and access key creation

```bash
for EVENT in CreateUser CreateAccessKey CreateLoginProfile AttachUserPolicy PutUserPolicy CreateGroup UpdateSSHPublicKey; do
  echo "=== $EVENT ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVENT" \
    --start-time "$(date -u -d '48 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region us-east-1 \
    --query 'Events[*].CloudTrailEvent' \
    --output text | jq -r '{time: .eventTime, caller: .userIdentity.arn, target: (.requestParameters.userName // .requestParameters.groupName), policy: .requestParameters.policyArn, error: (.errorCode // "SUCCESS")}'
done

# Denied attempts matter as much as successful ones - in the original incident the
# attacker's first persistence attempts failed, then succeeded after privilege escalation.
```

#### Query 7 - Lambda functions created for persistence

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)

# Control-plane record of function creation, with caller attribution
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateFunction20150331 \
  --start-time "$(date -u -d '48 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --query 'Events[*].CloudTrailEvent' \
  --output text | jq -r '{time: .eventTime, caller: .userIdentity.arn, function: .requestParameters.functionName, role: .requestParameters.role, sourceIP: .sourceIPAddress}'

# NOTE: the CloudTrail eventName for lambda:CreateFunction is CreateFunction20150331
# (the API version is part of the event name). Filtering on "CreateFunction" alone
# returns nothing - a common reason this detection silently fails.

# Current-state sweep: any function whose execution role is not a known CI/CD role
for REGION in $REGIONS; do
  aws lambda list-functions --region "$REGION" \
    --query 'Functions[*].[FunctionName,Role,LastModified]' --output text 2>/dev/null | \
    while read -r FN ROLE MODIFIED; do
      [ -n "$FN" ] && echo "$REGION | $FN | $ROLE | $MODIFIED"
    done
done
```

#### Query 8 - Cryptomining compute across all regions

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)

for REGION in $REGIONS; do
  COUNT=$(aws ec2 describe-instances --region "$REGION" \
    --filters "Name=instance-state-name,Values=running" \
    --query 'length(Reservations[].Instances[?contains(InstanceType, `metal`) || contains(InstanceType, `4xlarge`) || contains(InstanceType, `8xlarge`)][])' \
    --output text 2>/dev/null)
  [ -n "$COUNT" ] && [ "$COUNT" != "0" ] && echo "[!] $REGION: $COUNT large instances running"
done

# RunInstances events in the last 24h with caller attribution
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --query 'Events[*].CloudTrailEvent' \
  --output text | jq -r '{time: .eventTime, caller: .userIdentity.arn, type: .requestParameters.instanceType, count: .requestParameters.maxCount, sourceIP: .sourceIPAddress}'
```

#### Query 9 - Which instances and node groups still allow IMDSv1

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)

for REGION in $REGIONS; do
  aws ec2 describe-instances --region "$REGION" \
    --query 'Reservations[].Instances[?MetadataOptions.HttpTokens==`optional`].[InstanceId,PrivateIpAddress]' \
    --output text 2>/dev/null | while read -r ID IP; do
      [ -n "$ID" ] && echo "[!] $REGION $ID ($IP) permits IMDSv1"
    done
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Step 1 - Re-enable CloudTrail if disabled (DO THIS FIRST)

```bash
TRAIL_NAME="<trail-name-or-arn>"
REGION="us-east-1"

aws cloudtrail start-logging --name "$TRAIL_NAME" --region "$REGION"

aws cloudtrail get-trail-status --name "$TRAIL_NAME" --region "$REGION" \
  --query '{IsLogging:IsLogging, LatestDeliveryTime:LatestDeliveryTime, LatestDeliveryError:LatestDeliveryError}'

# Enumerate every trail in the account and confirm all are logging
for T in $(aws cloudtrail describe-trails --query 'trailList[*].Name' --output text); do
  STATUS=$(aws cloudtrail get-trail-status --name "$T" --query IsLogging --output text)
  echo "$T : $STATUS"
  [ "$STATUS" != "True" ] && aws cloudtrail start-logging --name "$T"
done
```

#### Step 2 - Revoke the stolen IMDS role session

```bash
# CRITICAL: credentials harvested from IMDS belong to a ROLE SESSION, not an IAM
# user. There is no access key to delete. The only way to invalidate a live
# session is a deny policy conditioned on aws:TokenIssueTime attached to the ROLE.

COMPROMISED_ROLE="<node-or-cluster-role-name>"   # from Query 2
REVOKE_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

aws iam put-role-policy \
  --role-name "$COMPROMISED_ROLE" \
  --policy-name "AWSRevokeOlderSessions" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {"aws:TokenIssueTime": "'"$REVOKE_TIME"'"}
      }
    }]
  }'

echo "[OK] Sessions issued before $REVOKE_TIME revoked for $COMPROMISED_ROLE"
```

#### Step 3 - Isolate the compromised container and node

```bash
NAMESPACE="<namespace>"
POD="<compromised-pod>"
NODE="<node-name>"

# Capture evidence BEFORE killing anything
kubectl describe pod "$POD" -n "$NAMESPACE" > "/tmp/${POD}-describe.txt"
kubectl logs "$POD" -n "$NAMESPACE" --all-containers > "/tmp/${POD}-logs.txt" 2>&1

# Cut network reachability without destroying the workload
kubectl label pod "$POD" -n "$NAMESPACE" quarantine=true --overwrite
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine-deny-all
spec:
  podSelector:
    matchLabels:
      quarantine: "true"
  policyTypes: [Ingress, Egress]
EOF

# Cordon the node so nothing new schedules onto it
kubectl cordon "$NODE"
```

#### Step 4 - Enforce IMDSv2 on the affected instances

```bash
REGION="us-east-1"

# Immediate: require tokens on the compromised instance(s)
INSTANCE_ID="<instance-id>"
aws ec2 modify-instance-metadata-options \
  --instance-id "$INSTANCE_ID" \
  --http-tokens required \
  --http-endpoint enabled \
  --region "$REGION"

# Also reduce the hop limit so containers cannot reach IMDS through the host
aws ec2 modify-instance-metadata-options \
  --instance-id "$INSTANCE_ID" \
  --http-put-response-hop-limit 1 \
  --region "$REGION"
```

#### Step 5 - Disable attacker-created IAM users and keys

```bash
# Substitute names found in Query 6
for USER in "aws_support"; do
  aws iam get-user --user-name "$USER" >/dev/null 2>&1 || { echo "  $USER not found"; continue; }

  # Deactivate keys (do NOT delete yet - preserve forensic evidence)
  for KEY in $(aws iam list-access-keys --user-name "$USER" \
      --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$USER" --access-key-id "$KEY" --status Inactive
    echo "  [OK] Deactivated $KEY on $USER"
  done

  # Kill console access
  aws iam delete-login-profile --user-name "$USER" 2>/dev/null

  # Deny-all to neutralise any live session
  aws iam put-user-policy --user-name "$USER" \
    --policy-name "EmergencyDenyAll" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
done
```

#### Step 6 - Rotate credentials exposed in Terraform state and Lambda env vars

```bash
# Every IAM user access key found in a .tfstate file or Lambda environment
# variable must be treated as compromised, including in OTHER accounts.

EXPOSED_USER="<iam-user-from-tfstate>"
EXPOSED_ACCOUNT="<second-account-id>"

echo "[!] Rotate in account $EXPOSED_ACCOUNT: $EXPOSED_USER"

aws iam list-access-keys --user-name "$EXPOSED_USER" \
  --query 'AccessKeyMetadata[*].{Key:AccessKeyId,Status:Status,Created:CreateDate}'

# Deactivate, then apply session revocation
for KEY in $(aws iam list-access-keys --user-name "$EXPOSED_USER" \
    --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
  aws iam update-access-key --user-name "$EXPOSED_USER" --access-key-id "$KEY" --status Inactive
done

aws iam put-user-policy --user-name "$EXPOSED_USER" \
  --policy-name "EmergencyRevokeSessions" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny", "Action": "*", "Resource": "*",
      "Condition": {"DateLessThan": {"aws:TokenIssueTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}}
    }]
  }'
```

#### Step 7 - Neutralise the backdoor Lambda function

```bash
REGION="us-east-1"
FUNCTION_NAME="<attacker-created-function>"   # from Query 7

# Deny invocation immediately without destroying evidence: set reserved
# concurrency to 0, which throttles every invocation including any existing
# event source, alias, or scheduled rule.
aws lambda put-function-concurrency \
  --function-name "$FUNCTION_NAME" \
  --reserved-concurrent-executions 0 \
  --region "$REGION"

# Capture the deployment package before deletion
CODE_URL=$(aws lambda get-function --function-name "$FUNCTION_NAME" \
  --region "$REGION" --query 'Code.Location' --output text)
curl -s "$CODE_URL" -o "/tmp/${FUNCTION_NAME}-evidence.zip"

aws lambda get-function-configuration --function-name "$FUNCTION_NAME" \
  --region "$REGION" > "/tmp/${FUNCTION_NAME}-config.json"

# Enumerate anything that could re-invoke it
aws lambda list-event-source-mappings --function-name "$FUNCTION_NAME" --region "$REGION"
aws lambda list-aliases --function-name "$FUNCTION_NAME" --region "$REGION"
aws lambda get-policy --function-name "$FUNCTION_NAME" --region "$REGION" 2>/dev/null
aws lambda list-function-url-configs --function-name "$FUNCTION_NAME" --region "$REGION" 2>/dev/null
```

#### Step 8 - Terminate cryptomining compute

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)

for REGION in $REGIONS; do
  # Instances launched by the compromised principal in the incident window
  IDS=$(aws ec2 describe-instances --region "$REGION" \
    --filters "Name=instance-state-name,Values=running,pending" \
    --query 'Reservations[].Instances[?contains(InstanceType, `metal`) || contains(InstanceType, `4xlarge`)].InstanceId' \
    --output text 2>/dev/null)

  for ID in $IDS; do
    echo "[!] $REGION: terminating $ID"
    # Snapshot the root volume first if forensics are required
    aws ec2 terminate-instances --instance-ids "$ID" --region "$REGION"
  done
done
```

---

## 4. Eradication

### Remove Attacker Access

#### Delete attacker-created IAM users

```bash
for USER in "aws_support"; do
  aws iam get-user --user-name "$USER" >/dev/null 2>&1 || { echo "  $USER not found"; continue; }
  echo "=== Cleaning up user: $USER ==="

  for POLICY in $(aws iam list-user-policies --user-name "$USER" --query 'PolicyNames[]' --output text); do
    aws iam delete-user-policy --user-name "$USER" --policy-name "$POLICY"
    echo "  [OK] Deleted inline policy: $POLICY"
  done

  for ARN in $(aws iam list-attached-user-policies --user-name "$USER" --query 'AttachedPolicies[*].PolicyArn' --output text); do
    aws iam detach-user-policy --user-name "$USER" --policy-arn "$ARN"
    echo "  [OK] Detached: $ARN"
  done

  for GROUP in $(aws iam list-groups-for-user --user-name "$USER" --query 'Groups[*].GroupName' --output text); do
    aws iam remove-user-from-group --user-name "$USER" --group-name "$GROUP"
  done

  for KEY in $(aws iam list-access-keys --user-name "$USER" --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
    aws iam delete-access-key --user-name "$USER" --access-key-id "$KEY"
  done

  aws iam delete-login-profile --user-name "$USER" 2>/dev/null
  aws iam delete-user --user-name "$USER"
  echo "  [OK] Deleted user: $USER"
done
```

#### Remove unauthorised access keys created on legitimate users

```bash
# The v2 campaign created access keys for every user in the account once it had
# admin. Any key created inside the incident window is suspect.

INCIDENT_START="2023-01-01T00:00:00Z"   # substitute your incident window

for USER in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  aws iam list-access-keys --user-name "$USER" \
    --query "AccessKeyMetadata[?CreateDate>='$INCIDENT_START'].[AccessKeyId,CreateDate]" \
    --output text | while read -r KEY CREATED; do
      [ -n "$KEY" ] && echo "[!] $USER: key $KEY created $CREATED - verify and delete"
    done
done
```

#### Re-scope the over-permissive compute-plane role

```bash
# Root cause in the original incident: the cluster role was intended to read one
# S3 bucket but was granted account-wide read, which exposed Lambda code.

COMPROMISED_ROLE="<node-or-cluster-role-name>"

# Record current state for the RCA
aws iam list-attached-role-policies --role-name "$COMPROMISED_ROLE"
aws iam list-role-policies --role-name "$COMPROMISED_ROLE"

# Replace with a least-privilege policy scoped to the intended bucket only
aws iam put-role-policy \
  --role-name "$COMPROMISED_ROLE" \
  --policy-name "ScopedS3ReadOnly" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::<intended-bucket>",
        "arn:aws:s3:::<intended-bucket>/*"
      ]
    }]
  }'

# Detach the broad managed policies that permitted Lambda and account-wide reads
for ARN in $(aws iam list-attached-role-policies --role-name "$COMPROMISED_ROLE" \
    --query 'AttachedPolicies[?contains(PolicyArn, `ReadOnlyAccess`) || contains(PolicyArn, `AmazonS3ReadOnlyAccess`)].PolicyArn' \
    --output text); do
  aws iam detach-role-policy --role-name "$COMPROMISED_ROLE" --policy-arn "$ARN"
  echo "[OK] Detached over-broad policy: $ARN"
done

# Remove the emergency deny once the scoped policy is verified
# aws iam delete-role-policy --role-name "$COMPROMISED_ROLE" --policy-name "AWSRevokeOlderSessions"
```

#### Purge secrets from Terraform state and migrate to a secure backend

```bash
# Terraform state is plaintext by design. Any secret that entered state must be
# rotated - removing it from the file does not un-leak it.

STATE_BUCKET="<state-bucket>"

# Enable encryption and block public access on the state bucket
aws s3api put-bucket-encryption --bucket "$STATE_BUCKET" \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "<kms-key-arn>"
      },
      "BucketKeyEnabled": true
    }]
  }'

aws s3api put-public-access-block --bucket "$STATE_BUCKET" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

aws s3api put-bucket-versioning --bucket "$STATE_BUCKET" \
  --versioning-configuration Status=Enabled

# Restrict the bucket policy to the CI/CD principal only
aws s3api put-bucket-policy --bucket "$STATE_BUCKET" --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyAllExceptPipeline",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::'"$STATE_BUCKET"'", "arn:aws:s3:::'"$STATE_BUCKET"'/*"],
    "Condition": {
      "StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/TerraformPipelineRole"}
    }
  }]
}'

# NOTE: also purge historical versions of state files that contain the leaked keys
aws s3api list-object-versions --bucket "$STATE_BUCKET" \
  --prefix "<state-prefix>" \
  --query 'Versions[*].[Key,VersionId]' --output table
```

#### Remove credentials from Lambda environment variables

```bash
# Move every credential-bearing env var to Secrets Manager and grant the function
# read access to the secret instead.

FN="<function-name>"

aws lambda get-function-configuration --function-name "$FN" \
  --query 'Environment.Variables' --output json > "/tmp/${FN}-env-backup.json"

# After creating the secret and updating function code to fetch it:
aws lambda update-function-configuration \
  --function-name "$FN" \
  --environment "Variables={SECRET_ARN=<secret-arn>}"
```

#### Delete the backdoor Lambda and its triggers

```bash
REGION="us-east-1"
FUNCTION_NAME="<attacker-created-function>"

# Remove triggers first, or deletion can leave orphaned rules that error loudly
for UUID in $(aws lambda list-event-source-mappings --function-name "$FUNCTION_NAME" \
    --region "$REGION" --query 'EventSourceMappings[*].UUID' --output text 2>/dev/null); do
  aws lambda delete-event-source-mapping --uuid "$UUID" --region "$REGION"
  echo "  [OK] Deleted event source mapping: $UUID"
done

for URL_CONFIG in $(aws lambda list-function-url-configs --function-name "$FUNCTION_NAME" \
    --region "$REGION" --query 'FunctionUrlConfigs[*].FunctionArn' --output text 2>/dev/null); do
  aws lambda delete-function-url-config --function-name "$FUNCTION_NAME" --region "$REGION"
  echo "  [OK] Deleted function URL config"
done

# EventBridge rules that target the function
for RULE in $(aws events list-rules --region "$REGION" --query 'Rules[*].Name' --output text); do
  aws events list-targets-by-rule --rule "$RULE" --region "$REGION" \
    --query 'Targets[*].Arn' --output text 2>/dev/null | grep -q "$FUNCTION_NAME" && \
    echo "  [!] Rule $RULE targets $FUNCTION_NAME - remove targets then delete rule"
done

aws lambda delete-function --function-name "$FUNCTION_NAME" --region "$REGION"
echo "  [OK] Deleted function: $FUNCTION_NAME"
```

#### Re-scope the over-privileged Lambda execution role

```bash
# The backdoor is only useful because the execution role it was handed is
# over-privileged. Deleting the function without fixing the role leaves the
# capability intact for the next intrusion.

LAMBDA_ROLE="<lambda-execution-role-name>"

aws iam list-attached-role-policies --role-name "$LAMBDA_ROLE"
aws iam list-role-policies --role-name "$LAMBDA_ROLE"

# Any AWS-managed broad policy on a Lambda execution role is a finding
for ARN in $(aws iam list-attached-role-policies --role-name "$LAMBDA_ROLE" \
    --query 'AttachedPolicies[?contains(PolicyArn, `AdministratorAccess`) || contains(PolicyArn, `PowerUserAccess`) || contains(PolicyArn, `ReadOnlyAccess`)].PolicyArn' \
    --output text); do
  echo "[!] Over-broad policy on Lambda role: $ARN"
done

# Also verify the trust policy is scoped to lambda.amazonaws.com only
aws iam get-role --role-name "$LAMBDA_ROLE" --query 'Role.AssumeRolePolicyDocument'
```

#### Remove miner and DDoS malware artefacts from the cluster

```bash
# Rebuild rather than clean. Any node that ran an unknown binary should be replaced.
NODE="<node-name>"

kubectl drain "$NODE" --ignore-daemonsets --delete-emptydir-data
# Then terminate the underlying instance so the ASG/node group replaces it from a
# known-good AMI:
aws ec2 terminate-instances --instance-ids "<instance-id>" --region us-east-1

# Verify no residual workloads reference attacker images
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | \
  grep -viE '<your-registry>|gcr.io/your-project'
```

---

## 5. Recovery

### Restore Clean State

#### Verify CloudTrail is healthy and logs are intact

```bash
TRAIL_NAME="<trail-name>"

aws cloudtrail get-trail-status --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging, LatestDeliveryError:LatestDeliveryError, LatestCloudWatchLogsDeliveryError:LatestCloudWatchLogsDeliveryError}'

aws cloudtrail validate-logs \
  --trail-arn "$(aws cloudtrail describe-trails --query "trailList[?Name=='$TRAIL_NAME'].TrailARN" --output text)" \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"

# Confirm S3 data events are now enabled on sensitive buckets
aws cloudtrail get-event-selectors --trail-name "$TRAIL_NAME" \
  --query 'AdvancedEventSelectors'
```

#### Verify IMDSv2 is enforced everywhere

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)
FAIL=0

for REGION in $REGIONS; do
  OPTIONAL=$(aws ec2 describe-instances --region "$REGION" \
    --query 'Reservations[].Instances[?MetadataOptions.HttpTokens==`optional`].InstanceId' \
    --output text 2>/dev/null)
  if [ -n "$OPTIONAL" ]; then
    echo "[FAIL] $REGION still permits IMDSv1: $OPTIONAL"
    FAIL=1
  fi
done

[ "$FAIL" -eq 0 ] && echo "[OK] IMDSv2 enforced in all regions"

# Also verify launch templates so new instances inherit the setting
for REGION in $REGIONS; do
  for LT in $(aws ec2 describe-launch-templates --region "$REGION" \
      --query 'LaunchTemplates[*].LaunchTemplateId' --output text 2>/dev/null); do
    TOKENS=$(aws ec2 describe-launch-template-versions --region "$REGION" \
      --launch-template-id "$LT" --versions '$Latest' \
      --query 'LaunchTemplateVersions[0].LaunchTemplateData.MetadataOptions.HttpTokens' \
      --output text 2>/dev/null)
    [ "$TOKENS" != "required" ] && echo "[!] $REGION launch template $LT: HttpTokens=$TOKENS"
  done
done
```

#### Verify no attacker identities remain

```bash
for USER in "aws_support"; do
  RESULT=$(aws iam get-user --user-name "$USER" 2>&1)
  if echo "$RESULT" | grep -q "NoSuchEntity"; then
    echo "[OK] User $USER confirmed deleted"
  else
    echo "[FAIL] User $USER still exists"
  fi
done

# No access keys older than the rotation date should remain active
aws iam generate-credential-report >/dev/null
sleep 5
aws iam get-credential-report --query Content --output text | base64 -d | \
  awk -F, 'NR==1 || ($9=="true" || $14=="true")' | cut -d, -f1,9,11,14,16
```

#### Verify no unexpected Lambda functions remain

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)
KNOWN_ROLE_PREFIX="arn:aws:iam::<account-id>:role/<your-ci-role-prefix>"

for REGION in $REGIONS; do
  aws lambda list-functions --region "$REGION" \
    --query 'Functions[*].[FunctionName,Role]' --output text 2>/dev/null | \
    while read -r FN ROLE; do
      case "$ROLE" in
        "$KNOWN_ROLE_PREFIX"*) ;;
        *) [ -n "$FN" ] && echo "[!] $REGION: $FN uses unreviewed role $ROLE" ;;
      esac
    done
done
```

#### Verify no residual mining compute

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)

for REGION in $REGIONS; do
  COUNT=$(aws ec2 describe-instances --region "$REGION" \
    --filters "Name=instance-state-name,Values=running" \
    --query 'length(Reservations[].Instances[])' --output text 2>/dev/null)
  echo "$REGION: $COUNT running instances"
done

echo "Compare against your known baseline instance count per region."
```

#### Verify GuardDuty coverage including Lambda and EKS protection

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)

for REGION in $REGIONS; do
  DET=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text 2>/dev/null)
  if [ -z "$DET" ] || [ "$DET" == "None" ]; then
    echo "[!] GuardDuty NOT enabled in $REGION"
  else
    aws guardduty get-detector --detector-id "$DET" --region "$REGION" \
      --query 'Features[?Status==`DISABLED`].Name' --output text | \
      while read -r F; do
        [ -n "$F" ] && echo "[!] $REGION: GuardDuty feature disabled - $F"
      done
  fi
done
```

#### Confirm no data left via non-AWS endpoints

```bash
# CloudTrail cannot answer this. Query your runtime sensor or VPC Flow Logs for
# egress to the IOC list, and your DNS logs for the C2 domains.

LOG_GROUP="/vpc-flow-logs"
START=$(date -u -d '7 days ago' +%s)000

for IP in 80.239.140.66 45.9.148.221 45.9.148.121 45.9.249.58; do
  echo "=== $IP ==="
  aws logs filter-log-events \
    --log-group-name "$LOG_GROUP" \
    --start-time "$START" \
    --filter-pattern "\"$IP\"" \
    --query 'events[*].message' --output text 2>/dev/null | head -20
done
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| Container exploited via internet-exposed service in a self-managed Kubernetes cluster | No vulnerability management cycle on public-facing workloads; no admission control restricting exposure |
| Node role credentials stolen from IMDS | IMDSv1 permitted (`HttpTokens=optional`) and hop limit >1, so any process in any container could reach the metadata endpoint. No IRSA / Pod Identity, so pods inherited the node role |
| Attacker read Lambda code and all S3 buckets with a role intended for one bucket | Over-permissive IAM: intent was read on a single bucket, grant was account-wide read. Read-only access was treated as low risk despite exposing source code and credentials |
| Credentials found in Lambda environment variables | Secrets stored as plaintext env vars instead of Secrets Manager / Parameter Store |
| Second AWS account compromised via keys in `terraform.tfstate` | Terraform state stored in S3 without restrictive bucket policy; long-lived IAM user keys committed to state, which is plaintext by design |
| CloudTrail logging successfully disabled | No SCP denying `cloudtrail:StopLogging` for non-break-glass principals; no pre-configured alarm on the API call |
| Object-level access to 1 TB of data unknowable after the fact | CloudTrail S3 data events not enabled, so the specific objects read could never be determined |
| Exfiltration invisible to CloudTrail | Attacker used `aws --endpoint-url` against non-AWS S3-compatible storage; no egress filtering and no runtime process monitoring |
| Privilege escalation to `AdministratorAccess` (v2) | A single-character typo in a customer IAM policy allowed a guardrail to be bypassed. No automated policy validation (Access Analyzer / IAM policy linting) in the deployment pipeline |
| Application secrets readable by a compute-plane role | Secrets Manager resource policy did not restrict which principals may call `GetSecretValue`; the node role's grant was not scoped to the secrets its workload actually needs |
| Backdoor function created with an over-privileged execution role | Any principal able to call `lambda:CreateFunction` plus `iam:PassRole` on a privileged role can mint arbitrary execution capability. `iam:PassRole` was not constrained by `iam:PassedToService` or a role-path condition |

### Recommended Guardrails

**Service Control Policies (SCPs) - apply at OU level**

```json
// SCP 1: Block CloudTrail tampering
{
  "Effect": "Deny",
  "Action": [
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "cloudtrail:UpdateTrail",
    "cloudtrail:PutEventSelectors"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/BreakGlassAdmin",
        "arn:aws:iam::*:role/SecurityResponseRole"
      ]
    }
  }
}

// SCP 2: Require IMDSv2 on all instance launches
{
  "Effect": "Deny",
  "Action": "ec2:RunInstances",
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringNotEquals": {"ec2:MetadataHttpTokens": "required"}
  }
}

// SCP 3: Deny AdministratorAccess attachment by non-approved principals
{
  "Effect": "Deny",
  "Action": ["iam:AttachUserPolicy", "iam:AttachRolePolicy"],
  "Resource": "*",
  "Condition": {
    "ArnEquals": {
      "iam:PolicyARN": "arn:aws:iam::aws:policy/AdministratorAccess"
    },
    "StringNotEquals": {
      "aws:PrincipalArn": "arn:aws:iam::*:role/IdentityAdminRole"
    }
  }
}

// SCP 4: Constrain iam:PassRole so CreateFunction cannot mint privileged compute
{
  "Effect": "Deny",
  "Action": "iam:PassRole",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {"iam:PassedToService": ["lambda.amazonaws.com", "ecs-tasks.amazonaws.com"]}
  }
}

// SCP 5: Deny IAM user access key creation entirely (force federation / roles)
{
  "Effect": "Deny",
  "Action": "iam:CreateAccessKey",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalArn": "arn:aws:iam::*:role/IdentityAdminRole"
    }
  }
}
```

**Eliminate the IMDS attack path**
- Enforce `HttpTokens=required` and `HttpPutResponseHopLimit=1` in every launch template and EKS node group
- Adopt IAM Roles for Service Accounts (IRSA) or EKS Pod Identity so pods receive scoped credentials and never need the node role
- Where IMDS is not required by the workload at all, disable the endpoint (`HttpEndpoint=disabled`)

**Treat read-only as a data exfiltration primitive**
- `lambda:GetFunction` returns a downloadable deployment package - scope it, do not grant it broadly via `ReadOnlyAccess`
- `lambda:GetFunctionConfiguration` returns environment variables in plaintext
- Audit every use of the AWS-managed `ReadOnlyAccess` and `AmazonS3ReadOnlyAccess` policies on compute-plane roles

**Secrets handling**
- No credentials in Lambda environment variables - use Secrets Manager or Parameter Store with scoped read
- No long-lived IAM user keys referenced in Terraform; use OIDC federation for the pipeline
- Terraform state in S3 with KMS encryption, versioning, public access block, and a bucket policy limited to the pipeline role
- Run a secret scanner (TruffleHog or equivalent) against state files and buckets on a schedule - the responders found the leaked keys this way, and so did the attacker

**Detection improvements**
- EventBridge rule: `cloudtrail:StopLogging` -> SNS -> PagerDuty (P0)
- EventBridge rule: `iam:CreateUser` or `iam:CreateAccessKey` -> SNS (P0)
- EventBridge rule: `s3:GetObject` on `*.tfstate` from a non-pipeline principal (P1, requires data events)
- Detection on AWS API calls from a node role where `sourceIPAddress` falls outside the VPC CIDR - the single highest-fidelity signal for IMDS credential theft
- Enable GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`, which fires specifically on instance credentials used from outside AWS
- Runtime rule: process reading `169.254.169.254` from inside a container
- Runtime rule: AWS CLI invoked with `--endpoint-url` - this is the only place exfiltration to non-AWS storage is visible
- Egress filtering or a NAT allowlist, so `hb.bizmrg.com`, `temp.sh`, and `termbin.com` are unreachable from workloads
- AWS Budgets anomaly alert on EC2 spend, sized to catch a 42-instance launch within minutes

### Known SCARLETEEL IOCs for Threat Intel Feeds

Sourced from the Sysdig Threat Research Team reports:
[SCARLETEEL v1](https://sysdig.com/blog/cloud-breach-terraform-data-theft/) (28 Feb 2023),
[SCARLETEEL 2.0](https://sysdig.com/blog/scarleteel-2-0/) (11 Jul 2023), and
[SCARLETEEL 2.0 and MITRE ATT&CK](https://sysdig.com/blog/scarleteel-mitre-attack/).
Full and current IOC lists live at `https://github.com/sysdig/STRT/tree/main/iocs`.

| Type | Value | Campaign |
|------|-------|----------|
| IP address | `80.239.140.66` | v1 (Feb 2023) |
| IP address | `45.9.148.221` | v1 |
| IP address | `45.9.148.121` | v1 |
| IP address | `45.9.249.58` | v1 |
| Exfil / C2 domain | `hb.bizmrg.com` (redirects to `mcs.mail.ru/storage`, S3-compatible) | v2 (Jul 2023) |
| Exfil endpoint | `temp.sh` | v2 |
| Exfil endpoint | `termbin.com` (port 9999) | v2 |
| IAM user name | `aws_support` | v2 |
| Miner | XMRig, launched via `miner.sh` with `config_background.json` | v1 |
| DDoS malware | Pandora (Mirai family) | v2 |
| Offensive tooling | Pacu (AWS exploitation framework) | v1 IR analysis, v2 attacker use |
| Offensive tooling | Peirates (Kubernetes privilege escalation / pivoting) | v2 |
| Offensive tooling | TruffleHog (secret discovery in S3 / state files) | v1 |
| Instance types abused | `c5.metal`, `r5a.4xlarge` (42 instances launched) | v2 |
| Technique marker | `aws` CLI invoked with `--endpoint-url` to non-AWS storage | v2 |

