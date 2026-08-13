# IR Playbook - Steal EC2 Instance Credentials via IMDS - Role Credential Exfiltration through `ssm:SendCommand`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential Access / Instance Credential Theft |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, yields live, usable IAM role credentials (note: `MANIFEST.py` currently rates this MEDIUM; the IR view is High because a successful run hands the attacker working role credentials, not just a log signal) |
| MITRE Tactics | Credential Access |
| MITRE Techniques | T1552.005 |
| Services in Scope | SSM, EC2, STS, IAM, GuardDuty, CloudTrail, VPC Flow Logs |
| Infrastructure Created | 1 EC2 instance + IAM role/instance profile + VPC/subnet/IGW (via `infra/`) |

**What the emulation does:** waits for the target EC2 instance to register with SSM, then calls `ssm:SendCommand` with the `AWS-RunShellScript` document to run a two-line `curl` against the Instance Metadata Service (IMDS), first listing the attached role, then fetching its temporary credentials from `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`. It retrieves the command output with `ssm:GetCommandInvocation`, builds a new boto3 session from the stolen `AccessKeyId`/`SecretAccessKey`/`Token`, and calls `sts:GetCallerIdentity` to prove the credentials work.

**Why this is high severity, unlike a failed enumeration:** this technique does not probe, it *succeeds*. At the end of a run the operator holds working credentials for the instance's IAM role. Everything that role can do, the attacker can now do, from anywhere, until the token expires (max ~6 hours for instance-profile credentials, but silently renewable by re-reading IMDS on the host).

**The two-stage signature.** The theft (`ssm:SendCommand` → IMDS) and the *use* of the stolen credentials are separate, differently-observed events:
- The **theft** is visible in CloudTrail as SSM API calls from the attacker's principal.
- The **use** is visible only when the role credentials appear from an IP that is not the instance, this is what GuardDuty's `InstanceCredentialExfiltration` findings detect, and it is the single most reliable signal for this technique.

A defender who watches only the SSM side misses exfiltration when the attacker steals credentials by other means (SSRF, a web shell, `GetConsoleOutput`); a defender who watches only credential use misses the theft when the attacker uses the credentials from inside AWS. Both are required.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to CloudWatch Logs / a log platform for rate queries
- **GuardDuty enabled in all regions**, this technique's highest-value detection (`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` and `.OutsideAWS`) is GuardDuty-only; no CloudTrail rule reproduces it
- VPC Flow Logs on all VPCs, needed to see the instance's own egress to mining/C2 or the absence of expected traffic
- **Know where `ssm:SendCommand` command text lives.** For the standard `AWS-RunShellScript` / `AWS-RunPowerShellScript` documents used by this technique, the `commands` payload is plaintext and normally **does** appear in CloudTrail under `requestParameters.parameters.commands`, so grepping CloudTrail for `169.254.169.254` usually works here. It can be absent when a *custom* document marks parameters `NoEcho`, or where an org has restricted parameter logging. Validate against a sample event in your own account rather than assuming, and enable SSM RunCommand output logging to S3/CloudWatch as an authoritative fallback for command bodies
- Enable SSM Run Command output logging to an S3 bucket or CloudWatch Logs group, account-wide, so command *content* is recoverable even when CloudTrail omits it

**Alerting (must be pre-configured)**
- GuardDuty `InstanceCredentialExfiltration.*` findings → SNS → on-call, at P0. This is the alert that catches the actual compromise
- `ssm:SendCommand` targeting an instance, where the calling principal is **not** on the SSM-operations allowlist, medium confidence, high value as an early signal
- Correlation: role-session credentials (`userIdentity.type = AssumedRole`, ARN matching an *instance* role) seen with a `sourceIPAddress` that is **not** the instance's private IP or its NAT/EIP → this is credential exfiltration and should page
- `ssm:SendCommand` with `DocumentName = AWS-RunShellScript` or `AWS-RunPowerShellScript` from an interactive user principal (as opposed to a CI/patch-automation role)

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any instance role
- `jq` installed
- An inventory mapping each EC2 instance → its instance profile/role → that role's private IP and NAT egress IP, so "is this credential being used off-instance?" is answerable in minutes
- The instance-role trust and permission policies on hand, to scope blast radius the moment a role is implicated

**Known IOC Baselines**
- Baseline which principals legitimately call `ssm:SendCommand`, normally a small set of patch/automation roles, never interactive users
- Baseline each instance role's normal `sourceIPAddress` set (its private IP, the VPC NAT). Anything else using those credentials is theft
- **Enforce IMDSv2** (`HttpTokens: required`, `HttpPutResponseHopLimit: 1`) as the baseline. The emulation's plain `curl` succeeds only against IMDSv1; on an IMDSv2-only instance the token-less GET returns 401 and the theft fails. A fleet that is IMDSv2-only converts this High-severity technique into a non-event

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | GuardDuty | T1552.005 |
| P0 | GuardDuty `...InstanceCredentialExfiltration.InsideAWS` (stolen creds used from another AWS account) | GuardDuty | T1552.005 |
| P0 | Instance-role credentials (`assumed-role/<instance-role>`) used from a `sourceIPAddress` that is not the instance's private IP or its NAT/EIP | CloudTrail | T1552.005 |
| P1 | `ssm:SendCommand` whose recovered command body references `169.254.169.254`, `iam/security-credentials`, or `latest/meta-data` | SSM output logs / CloudTrail (if not redacted) | T1552.005 |
| P1 | `ssm:SendCommand` (RunShellScript/RunPowerShellScript) from an interactive user principal not on the SSM-operations allowlist | CloudTrail | T1552.005 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `ssm:SendCommand` → `ssm:GetCommandInvocation` pair from a principal with no prior SSM history | CloudTrail | T1552.005 |
| P2 | Sudden `ssm:DescribeInstanceInformation` sweep followed by `SendCommand` to a returned instance | CloudTrail | T1552.005 |
| P2 | Instance-role credentials performing actions the workload never performs (e.g. `iam:*`, `s3:ListAllMyBuckets`) even from the instance IP | CloudTrail | T1552.005 |
| P3 | `sts:GetCallerIdentity` immediately after credential retrieval, attacker validating the loot (weak alone; `GetCallerIdentity` is extremely high-volume) | CloudTrail | T1552.005 |

### Detection Rule Quality Notes

The rules in `detections/` are **too noisy to deploy as written.** These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma and KQL both match `eventName IN (DescribeInstanceInformation, SendCommand, GetCommandInvocation, GetCallerIdentity)` with `condition: selection` and no further qualifier | Unusable. `sts:GetCallerIdentity` is one of the highest-volume API calls in AWS, every SDK/CLI init, every CI job, every credential probe emits it. `ssm:SendCommand`/`GetCommandInvocation` are routine patch operations. This rule alerts thousands of times a day on entirely benign activity and will be muted immediately | Split into two targeted rules (below). Drop `GetCallerIdentity` and `GetCommandInvocation` as *primary* selectors, they are corroborating context, not triggers |
| No use of `userIdentity.type`, principal allowlist, or `sourceIPAddress` | The rule cannot distinguish the patch-automation role (benign) from an interactive attacker, nor theft from normal role use | Filter `SendCommand` to interactive/non-allowlisted principals; add the off-instance-IP correlation as its own rule |
| Neither rule inspects the command body for the IMDS string | The most specific single-event signal (`169.254.169.254` / `iam/security-credentials` in the `commands`) is unused | Add a `requestParameters.parameters.commands|contains` selection. For standard RunShellScript/RunPowerShellScript documents this is present in CloudTrail; where a custom `NoEcho` document hides it, source the body from SSM output logging |
| GuardDuty `InstanceCredentialExfiltration`, the definitive signal, is not referenced by either rule | The best detection for this technique is absent from its own detection set | Add a GuardDuty finding-type detection at P0 |
| Header TODO "verify acronym casing" unresolved | Event-name casing is correct; stale TODO implies the rule is unvalidated | Resolve or remove |
| `level: medium` on a rule dominated by benign `GetCallerIdentity` | Guarantees alert fatigue | See per-rule levels below |

**Rule A, suspicious `SendCommand` (early signal, medium).** Deploy as Sigma with a maintained principal allowlist:

```yaml
title: SSM SendCommand shell document from non-automation principal
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'SendCommand'
    requestParameters.documentName:
      - 'AWS-RunShellScript'
      - 'AWS-RunPowerShellScript'
  automation_principals:
    userIdentity.arn|contains:
      - ':role/patch-automation'
      - ':role/ssm-runner'
  condition: selection and not automation_principals
level: medium
```

Companion high-severity rule keying on the IMDS string in the command body
(deploy alongside Rule A wherever command text reaches the log source):

```yaml
title: SSM SendCommand body targets the instance metadata service
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'SendCommand'
    requestParameters.parameters.commands|contains:
      - '169.254.169.254'
      - 'iam/security-credentials'
      - 'latest/meta-data'
  condition: selection
level: high
```

**Rule B, credential exfiltration (the real detection, high/critical).** This is a **correlation over `sourceIPAddress`**, not a single-event match, and is best expressed in a log platform (see Query 5). Where GuardDuty is available, prefer its finding directly:

```yaml
title: GuardDuty EC2 instance credential exfiltration
status: stable
logsource:
  product: aws
  service: guardduty
detection:
  selection:
    type|startswith: 'UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration'
  condition: selection
level: critical
```

**On the `Client.` error-prefix rule learned elsewhere:** it does not bite here, the emulation's SSM/STS calls succeed, so there is no `errorCode` to key on. If you build a variant detecting *failed* IMDS theft against IMDSv2-hardened hosts, that failure appears in the instance's own logs (HTTP 401 from IMDS), not in CloudTrail.

---

### Key Investigation Queries

> All CloudTrail extraction below uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`, which is robust; piping `--output text` into `jq` relies on undocumented tab-delimiting and breaks on fields containing tabs/newlines.

#### Query 1: Find the `SendCommand` that drove the theft

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-4H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendCommand \
  --start-time "$START" \
  --region "$REGION" \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime,
     caller: .userIdentity.arn,
     type: .userIdentity.type,
     document: .requestParameters.documentName,
     targets: (.requestParameters.instanceIds // .requestParameters.targets),
     # commands may be absent/redacted: do not rely on this being populated
     commands: (.requestParameters.parameters.commands // "REDACTED_OR_ABSENT"),
     sourceIP: .sourceIPAddress,
     error: (.errorCode // "SUCCESS")}'
```

If `commands` shows `REDACTED_OR_ABSENT`, pull the command body from SSM instead:

```bash
COMMAND_ID="<command-id-from-above>"
aws ssm list-command-invocations --command-id "$COMMAND_ID" --details \
  --region "$REGION" \
  --query 'CommandInvocations[].CommandPlugins[].{Name:Name,Output:Output,Status:Status}'
```

#### Query 2: Identify the instance and the role that was on it

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"

aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].{
    PrivateIp:PrivateIpAddress,
    PublicIp:PublicIpAddress,
    Profile:IamInstanceProfile.Arn,
    IMDSv2:MetadataOptions.HttpTokens,
    HopLimit:MetadataOptions.HttpPutResponseHopLimit,
    State:State.Name}' \
  --output json

# Resolve the instance profile to its role name: this is the credential that leaked
PROFILE_NAME=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn' --output text | awk -F'/' '{print $NF}')

aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME" \
  --query 'InstanceProfile.Roles[0].RoleName' --output text
```

Note `IMDSv2`: if `HttpTokens = required`, the plain-`curl` theft should have **failed**, investigate how credentials were obtained, because it was not this path.

#### Query 3 - The decisive query: did the role's credentials appear off-instance?

This distinguishes theft from normal use. Compare every `sourceIPAddress` that used the role against the instance's known IPs.

**Lookup-attribute caveat, read before running.** `AttributeKey=Username` in
`lookup-events` matches the CloudTrail *username*, which for an `AssumedRole`
session is the **role session name**, not the role name. For EC2
instance-profile credentials AWS sets the session name to the **instance ID**
(the ARN is `assumed-role/<role>/<instance-id>`). So the lookup key is the
instance ID, and the role name is matched by post-filtering on
`.userIdentity.sessionContext.sessionIssuer.userName`. Keying the lookup on the
role name returns **zero events**, do not do it.

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
ROLE_NAME="<instance-role-name-from-Query-2>"
INSTANCE_ID="<i-xxxxxxxxxxxx>"            # this is the session name for instance creds
INSTANCE_PRIVATE_IP="<from-Query-2>"
INSTANCE_NAT_IP="<the-NAT/EIP-the-instance-egresses-through>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$INSTANCE_ID" \
  --start-time "$START" \
  --region "$REGION" \
  --output json | \
  jq -r --arg role "$ROLE_NAME" --arg priv "$INSTANCE_PRIVATE_IP" --arg nat "$INSTANCE_NAT_IP" '
    .Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.type == "AssumedRole") |
    select((.userIdentity.sessionContext.sessionIssuer.userName // "") == $role) |
    select(.sourceIPAddress != $priv and .sourceIPAddress != $nat) |
    select(.sourceIPAddress | endswith("amazonaws.com") | not) |
    {time: .eventTime, event: .eventName, ip: .sourceIPAddress,
     agent: .userAgent, error: (.errorCode // "SUCCESS")}' | \
  jq -s 'sort_by(.time)'
```

The session name equals the instance ID whether the credentials are used on the
host or exfiltrated, because it is fixed at issuance, so this lookup catches
off-instance use too. If you do not know the instance ID, drop
`--lookup-attributes` for a broad time-bounded lookup and rely on the
`sessionIssuer.userName` filter alone (heavier, but complete).

**A row here is a high-confidence exfiltration indicator, not automatic proof.**
AWS-service-internal calls surface as `*.amazonaws.com` source values (filtered
out above). Before declaring theft, rule out other legitimate holders of the
same role session name / IP, a sibling instance in an HA group sharing the
profile, or your own responders reusing the role during investigation. A genuine
external IP or another account's traffic is the finding. Record every
`sourceIPAddress`, these are IOCs.

#### Query 4: Everything the stolen credentials did

Enumerate the full blast radius of the role session so eradication is scoped correctly.

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
ROLE_NAME="<instance-role-name>"
INSTANCE_ID="<i-xxxxxxxxxxxx>"            # session name for instance-profile creds

# Key on the instance ID (= session name); post-filter on the role name to be safe
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$INSTANCE_ID" \
  --start-time "$START" \
  --region "$REGION" \
  --output json | \
  jq -r --arg role "$ROLE_NAME" '.Events[].CloudTrailEvent | fromjson |
    select((.userIdentity.sessionContext.sessionIssuer.userName // "") == $role) |
    {time: .eventTime, event: .eventName, source: .eventSource,
     ip: .sourceIPAddress, error: (.errorCode // "SUCCESS")}' | \
  jq -s 'group_by(.event) | map({event: .[0].event, count: length,
         first: (min_by(.time).time), last: (max_by(.time).time),
         ips: (map(.ip) | unique)}) | sort_by(-.count)'
```

Flag anything outside the workload's normal behaviour: `iam:*`, `sts:AssumeRole` to other roles (pivot), `s3:GetObject`/`ListBucket` on sensitive buckets, `secretsmanager:GetSecretValue`, `ec2:RunInstances`.

#### Query 5: Deployable off-instance-use detection (log platform)

**Dialect: Sentinel / Azure Log Analytics KQL**, not CloudWatch Logs Insights. This is Rule B expressed against stored logs; maintain a watchlist named `InstanceRoleIPs` (columns `RoleName`, `AllowedPrivateIp`, `AllowedNatIp`) mapping each instance role → its legitimate IPs. Reference it via `_GetWatchlist()`; a bare `_InstanceRoleIPs` identifier does not resolve.

```kql
let InstanceRoleIPs = _GetWatchlist('InstanceRoleIPs');   // columns: RoleName, AllowedPrivateIp, AllowedNatIp
AWSCloudTrail
| where TimeGenerated > ago(6h)
| where UserIdentityType == "AssumedRole"
| where UserIdentityArn has "assumed-role/"
| extend RoleName = tostring(split(UserIdentityArn, "/")[1])
| where SourceIpAddress !endswith "amazonaws.com"            // drop AWS-internal
| join kind=inner (InstanceRoleIPs) on RoleName              // instance roles only
| where SourceIpAddress != AllowedPrivateIp and SourceIpAddress != AllowedNatIp
| summarize Calls = count(), Events = make_set(EventName, 20),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by RoleName, SourceIpAddress
| extend Verdict = "INSTANCE CREDENTIAL USED OFF-HOST, exfiltration"
| order by Calls desc
```

CloudWatch Logs Insights has no join-to-watchlist; there, filter to instance roles and exclude known IPs inline:

```
fields @timestamp, userIdentity.arn, sourceIPAddress, eventName
| filter userIdentity.type = "AssumedRole"
| filter userIdentity.arn like /assumed-role\/(app|web|worker)-instance-role/
| filter sourceIPAddress not like /amazonaws\.com$/
| filter sourceIPAddress != "10.10.1.23" and sourceIPAddress != "203.0.113.10"
| stats count(*) as calls by userIdentity.arn, sourceIPAddress
```

#### Query 6: GuardDuty findings for this instance/role

```bash
REGION="us-east-1"
DETECTOR_ID=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text)

aws guardduty list-findings --detector-id "$DETECTOR_ID" --region "$REGION" \
  --finding-criteria '{"Criterion":{"type":{"Eq":["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS","UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS"]}}}' \
  --query 'FindingIds' --output text | \
  xargs -r aws guardduty get-findings --detector-id "$DETECTOR_ID" --region "$REGION" --finding-ids
```

#### Query 7: Multi-region SSM sweep

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  COUNT=$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=SendCommand \
    --start-time "$START" \
    --region "$REGION" --query 'length(Events)' --output text 2>/dev/null)
  [ -n "$COUNT" ] && [ "$COUNT" != "0" ] && [ "$COUNT" != "None" ] && \
    echo "[!] $REGION, $COUNT SendCommand events"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The stolen credentials are the emergency, not the instance. Instance-profile
tokens keep working from anywhere until they expire, **revoking them is the
first priority**, ahead of touching the host.

#### Step 1: Revoke the leaked role's active sessions

`aws:TokenIssueTime` invalidates every credential **issued before** the cutoff,
which includes the stolen tokens as they exist right now, without deleting the
role or breaking its legitimate use once the host is clean.

**Understand exactly what this does and does not stop.** This policy kills only
the tokens that already exist at the moment you apply it. It does **not** stop
new theft: if the attacker still has code execution on the host, their next IMDS
read returns a *fresh* token with a later `TokenIssueTime`, which the Deny
condition does not match, so that credential works normally. This step buys
time by killing the currently-exfiltrated tokens; it is **not** containment on
its own. Continued theft is stopped by severing SSM (Step 3) and isolating the
network (Step 4), which cut the attacker's ability to reach the host and mint
new tokens. Do all four steps.

```bash
ROLE_NAME="<instance-role-name-from-Query-2>"

aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "EmergencyRevokeSessions" \
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

echo "[OK] All pre-existing sessions for $ROLE_NAME revoked (stolen tokens now dead)"
```

This also kills the *legitimate* workload's current credentials on the instance;
that is acceptable and expected during containment. The instance will obtain a
fresh token on its next IMDS read, and because that token is issued *after* the
cutoff, it is **not** blocked by this policy (the workload keeps functioning, and
so would an attacker still on the host). The role stays broadly usable; the
`aws:TokenIssueTime` deny is a scalpel for the already-leaked tokens, not a gate
on the role.

#### Step 2: Disable the attacker's own principal

The role credentials were stolen *by* some principal via `ssm:SendCommand`
(Query 1). Contain that principal too, or the theft simply repeats.

```bash
ATTACKER_ARN="<caller-arn-from-Query-1>"

if echo "$ATTACKER_ARN" | grep -q ":user/"; then
  ATTACKER_USER=$(echo "$ATTACKER_ARN" | awk -F'/' '{print $NF}')
  for KEY in $(aws iam list-access-keys --user-name "$ATTACKER_USER" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$ATTACKER_USER" --access-key-id "$KEY" --status Inactive
    echo "[OK] Disabled key $KEY for $ATTACKER_USER"
  done
elif echo "$ATTACKER_ARN" | grep -q ":assumed-role/"; then
  ATTACKER_ROLE=$(echo "$ATTACKER_ARN" | awk -F'/' '{print $2}')
  aws iam put-role-policy --role-name "$ATTACKER_ROLE" \
    --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]}'
  echo "[OK] Revoked sessions for attacker role $ATTACKER_ROLE"
fi
```

#### Step 3: Cut the instance's ability to receive more commands

Deny SSM on the instance role so no further RunCommand can execute, without yet
destroying forensic state on the host.

```bash
REGION="us-east-1"
ROLE_NAME="<instance-role-name>"

aws iam put-role-policy --role-name "$ROLE_NAME" \
  --policy-name "EmergencyDenySSM" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect":"Deny","Action":["ssm:*","ssmmessages:*","ec2messages:*"],"Resource":"*"}]
  }'
echo "[OK] SSM denied for $ROLE_NAME, no further SendCommand can execute on the host"
```

#### Step 4: Snapshot, then isolate the instance

Preserve evidence before network isolation. Step 3 has already severed command
execution, so a strict zero-egress quarantine is safe here - SSM-based on-host
forensics is already off the table.

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"

# Snapshot every attached volume first
for VOL in $(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId' --output text); do
  aws ec2 create-snapshot --volume-id "$VOL" --region "$REGION" \
    --description "IR-T1552.005-$INSTANCE_ID-$(date -u +%Y%m%dT%H%M%SZ)" \
    --query 'SnapshotId' --output text
  echo "[OK] Snapshot started for $VOL"
done

# Record original SGs (per ENI) so §5 can restore
aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].NetworkInterfaces[*].{ENI:NetworkInterfaceId,SGs:Groups[*].GroupId}' \
  --output json | tee "./ir-original-sgs-$INSTANCE_ID.json"

VPC_ID=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].VpcId' --output text)

QSG=$(aws ec2 create-security-group --group-name "ir-quarantine-$INSTANCE_ID" \
  --description "IR isolation" --vpc-id "$VPC_ID" --region "$REGION" \
  --query 'GroupId' --output text) || { echo "[FAIL] SG create"; exit 1; }

if aws ec2 revoke-security-group-egress --group-id "$QSG" --region "$REGION" \
     --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'; then
  echo "[OK] Egress stripped from $QSG"
else
  echo "[FAIL] Egress not stripped, $QSG is not a quarantine SG"; exit 1
fi

# Apply per-ENI (modify-instance-attribute --groups rejects multi-ENI instances)
for ENI in $(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].NetworkInterfaces[*].NetworkInterfaceId' --output text); do
  aws ec2 modify-network-interface-attribute --network-interface-id "$ENI" \
    --groups "$QSG" --region "$REGION" && echo "[OK] $ENI quarantined"
done
```

---

## 4. Eradication

### Remove Attacker Access

#### Scope down the instance role

Revoking sessions (Step 1) stopped the stolen tokens. Eradication ensures the
role cannot be re-harvested into the same blast radius.

```bash
ROLE_NAME="<instance-role-name>"

# Review what the role can do: this bounded the attacker's reach
aws iam list-attached-role-policies --role-name "$ROLE_NAME" --output table
aws iam list-role-policies --role-name "$ROLE_NAME" --output table

# If the role was over-privileged (it usually is: that is why this is High),
# scope it down NOW, before removing the emergency deny. Derive the minimal
# policy from Query 4 / IAM Access Advisor.
```

#### Terminate and rebuild the instance from a known-good image

An instance that ran attacker shell commands is untrusted. IMDS credential theft
implies arbitrary code execution on the host, so do not clean in place, replace
it.

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"

# Snapshots from Step 4 preserve forensic state; now terminate the compromised host
aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'TerminatingInstances[0].{Id:InstanceId,State:CurrentState.Name}'

# Relaunch from the pipeline/golden AMI with IMDSv2 ENFORCED (see Guardrails)
```

#### Remove attacker-created persistence

The role session (Query 4) may have created backdoors. Check for and remove:

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
aws cloudtrail lookup-events \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventName | test("^(CreateUser|CreateAccessKey|CreateLoginProfile|CreateRole|PutUserPolicy|AttachRolePolicy|CreateFunction|ImportKeyPair)$")) |
    {time: .eventTime, actor: .userIdentity.arn, event: .eventName,
     target: (.requestParameters | tostring)}'
```

Remediate each hit with the relevant persistence playbook (backdoor user/role,
login profile, etc.).

#### Remove emergency policies once clean

```bash
ROLE_NAME="<instance-role-name>"
# Only after: sessions revoked, host rebuilt, role scoped down, persistence removed
aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "EmergencyDenySSM" 2>/dev/null
aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed from $ROLE_NAME"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the stolen credentials are dead

```bash
REGION="us-east-1"
ROLE_NAME="<instance-role-name>"
INSTANCE_ID="<i-xxxxxxxxxxxx>"            # session name for instance-profile creds
CONTAINED_AT="<iso8601-containment-timestamp>"

# NOTE: key on the instance ID (the session name), NOT the role name - a role-name
# Username lookup returns zero events and would make this check ALWAYS print [OK].
LEAKS=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$INSTANCE_ID" \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg role "$ROLE_NAME" --arg priv "<instance-private-ip>" --arg nat "<instance-nat-ip>" '
    .Events[].CloudTrailEvent | fromjson |
    select((.userIdentity.sessionContext.sessionIssuer.userName // "") == $role) |
    select(.errorCode == null) |
    select(.sourceIPAddress != $priv and .sourceIPAddress != $nat) |
    select(.sourceIPAddress | endswith("amazonaws.com") | not) | .eventTime' | grep -c .)

[ "$LEAKS" -eq 0 ] && echo "[OK] No successful off-instance role activity since containment" \
                   || echo "[FAIL] $LEAKS off-instance calls succeeded after containment, attacker still active or new tokens minted"
```

#### Verify the attacker principal is contained

```bash
ATTACKER_ARN="<caller-arn-from-Query-1>"
if echo "$ATTACKER_ARN" | grep -q ":user/"; then
  U=$(echo "$ATTACKER_ARN" | awk -F'/' '{print $NF}')
  ACTIVE=$(aws iam list-access-keys --user-name "$U" \
    --query 'AccessKeyMetadata[?Status==`Active`]' --output text)
  [ -z "$ACTIVE" ] && echo "[OK] No active keys for $U" || echo "[FAIL] $U still has active keys"
fi
```

#### Verify the replacement instance enforces IMDSv2

```bash
REGION="us-east-1"
NEW_INSTANCE="<new-i-xxxxxxxxxxxx>"

OPTS=$(aws ec2 describe-instances --instance-ids "$NEW_INSTANCE" --region "$REGION" \
  --query 'Reservations[0].Instances[0].MetadataOptions.{Tokens:HttpTokens,Hop:HttpPutResponseHopLimit}' \
  --output json)
echo "$OPTS"
echo "$OPTS" | jq -e '.Tokens == "required" and .Hop <= 1' >/dev/null \
  && echo "[OK] IMDSv2 enforced, hop limit <= 1" \
  || echo "[FAIL] Replacement still allows IMDSv1 or a hop limit > 1"
```

#### Verify GuardDuty is enabled everywhere

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  D=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text 2>/dev/null)
  { [ -z "$D" ] || [ "$D" = "None" ]; } && echo "[!] GuardDuty NOT enabled in $REGION"
done
echo "[OK] GuardDuty sweep complete"
```

#### Restore the instance's original SGs (if cleaned rather than rebuilt)

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"
SG_BACKUP="./ir-original-sgs-$INSTANCE_ID.json"

[ -f "$SG_BACKUP" ] || { echo "[FAIL] No SG backup at $SG_BACKUP"; exit 1; }
jq -c '.[]' "$SG_BACKUP" | while read -r ROW; do
  ENI=$(echo "$ROW" | jq -r '.ENI'); SGS=$(echo "$ROW" | jq -r '.SGs | join(" ")')
  aws ec2 modify-network-interface-attribute --network-interface-id "$ENI" \
    --groups $SGS --region "$REGION" && echo "[OK] $ENI restored to: $SGS"
done
```

#### Confirm the corrected detections work

```bash
# Re-run the emulation against an IMDSv2-only test instance and assert the theft FAILS,
# then against an IMDSv1 test instance and assert Rule B / GuardDuty fires.
echo "IMDSv2 host: expect the IMDS curl to return 401 and NO credentials in SendCommand output."
echo "IMDSv1 host: expect exactly ONE Rule-B alert on off-instance credential use, not one per API call."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could `ssm:SendCommand` arbitrary shell to the instance | SSM RunCommand not restricted to automation principals / approved documents; interactive users held `ssm:SendCommand` |
| Plain `curl` to IMDS returned credentials | IMDSv1 still enabled; no `HttpTokens: required`, hop limit > 1 |
| Stolen credentials usable from off-host | No detection correlating instance-role credentials with off-instance source IPs; GuardDuty findings not alerted at P0 |
| Instance role was worth stealing | Instance profile over-privileged beyond the workload's actual needs |
| Command body invisible in CloudTrail | SSM Run Command output logging to S3/CloudWatch not enabled, so the IMDS string could not be confirmed from logs |

### Recommended Guardrails

**Service Control Policies (SCPs), apply at OU level**

```json
// SCP 1: Deny launching/modifying instances that permit IMDSv1
{
  "Effect": "Deny",
  "Action": ["ec2:RunInstances", "ec2:ModifyInstanceMetadataOptions"],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": { "ec2:MetadataHttpTokens": "required" }
  }
}
```

```json
// SCP 2: Restrict SendCommand to approved automation roles
{
  "Effect": "Deny",
  "Action": "ssm:SendCommand",
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/patch-automation",
        "arn:aws:iam::*:role/BreakGlassAdmin"
      ]
    }
  }
}
```

**Enforce IMDSv2 fleet-wide**
- Set `HttpTokens: required` and `HttpPutResponseHopLimit: 1` on all instances and in all launch templates. The hop limit of 1 stops containerised workloads from reaching IMDS through the host, which is the common SSRF-to-credential path
- Audit existing instances: `aws ec2 describe-instances --query 'Reservations[].Instances[?MetadataOptions.HttpTokens==\`optional\`].InstanceId'`

**Least-privilege instance roles**
- Scope each instance profile to exactly the actions the workload performs (derive from CloudTrail / Access Advisor). A stolen credential is only as dangerous as the role behind it
- Never attach `AdministratorAccess` or broad `iam:*`/`sts:AssumeRole` to an instance role

**Detection improvements**
- Alert GuardDuty `InstanceCredentialExfiltration.*` at P0 (the definitive signal)
- Deploy Rule B (off-instance credential-use correlation) with a maintained instance-role → IP watchlist
- Restrict + alert `ssm:SendCommand` from non-automation principals (Rule A)
- Enable SSM Run Command output logging so command bodies are always recoverable

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1552.005 - Unsecured Credentials: Cloud Instance Metadata API |
| MITRE tactic | Credential Access (TA0006) |
| Primary API path | `ssm:SendCommand` (AWS-RunShellScript) → IMDS `curl` → `ssm:GetCommandInvocation` → `sts:GetCallerIdentity` |
| Event sources | `ssm.amazonaws.com`, `sts.amazonaws.com` |
| Definitive detection | GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` / `.InsideAWS` |
| Prerequisite for success | IMDSv1 reachable (`HttpTokens: optional`); fails against enforced IMDSv2 |
| Resources created | 1 EC2 instance + IAM role/instance profile + VPC scaffolding |
| Follow-on to watch for | `sts:AssumeRole` (pivot), `iam:Create*`, `secretsmanager:GetSecretValue`, `s3:GetObject` on sensitive buckets |

### Revert

`pulumi destroy` in `infra/` removes the EC2 instance, IAM role/instance
profile, and VPC scaffolding. Nothing else is created by the emulation, the
stolen credentials expire on their own and are not persisted. After a real
incident (as opposed to an emulation), do **not** rely on `pulumi destroy`
alone: the instance must be treated as compromised and rebuilt, and the role
scoped down, per §4, the Pulumi teardown does not undo attacker persistence
created with the stolen credentials.
