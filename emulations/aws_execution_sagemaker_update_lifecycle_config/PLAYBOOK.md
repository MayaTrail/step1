# IR Playbook - Malicious Script Execution via SageMaker Lifecycle Config - Code Execution via `sagemaker:UpdateNotebookInstanceLifecycleConfig`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Execution / Command & Scripting Interpreter (persistent notebook code execution) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, the injected script executes with the notebook instance's execution-role privileges on every start/restart; it is code execution plus a persistence trigger (`MANIFEST.py` rates MEDIUM; the IR view is High because it yields recurring code execution under an IAM role, not just a config edit) |
| MITRE Tactics | Execution (with a Persistence characteristic, see §6) |
| MITRE Techniques | T1059 |
| Services in Scope | SageMaker, CloudTrail, IAM, VPC Flow Logs |
| Infrastructure Created | 1 SageMaker Notebook Instance Lifecycle Configuration (via `infra/`) |

**What the emulation does:** calls `sagemaker:UpdateNotebookInstanceLifecycleConfig` to overwrite the config's **OnStart** script with a malicious base64-encoded shell script (a download-and-execute payload). Any notebook instance attached to this lifecycle config runs that script, as the notebook's execution role, on every start or restart. The emulation's revert restores the original benign OnStart script.

**Why this is a persistence-flavored execution technique.** Unlike a one-shot command, the OnStart script re-runs **every time the notebook starts**. Once the config is backdoored, the attacker gets code execution repeatedly without touching the account again, closer to an event-triggered persistence mechanism than a single execution. Remediation therefore has to restore the config *and* treat any notebook that already started under it as compromised.

**Why `UpdateNotebookInstanceLifecycleConfig` is the signal.** Lifecycle configs are set up once during provisioning and rarely changed afterward, almost never by an interactive/non-provisioning principal. So the Update call is inherently high-signal, the opposite of a noisy event like `RunInstances`. The shipped rule (§2) matches it but also bundles in the benign `Describe` call and applies no principal filter or content inspection.

**The payload is usually recoverable from the log itself.** SageMaker records the request parameters for the Update, and the OnStart `content` (base64) is typically present in CloudTrail, so you can often decode the malicious script directly from the event, and always from the config via `DescribeNotebookInstanceLifecycleConfig`. Confirm which against a sample event in your account.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to a log platform. `UpdateNotebookInstanceLifecycleConfig` is a management event, so `lookup-events` works
- Confirm whether CloudTrail captures the OnStart `content` in `requestParameters` for this call (it typically does; if truncated/redacted for size, the config itself is the source of truth via `DescribeNotebookInstanceLifecycleConfig`)
- An inventory mapping each lifecycle config → the notebook instances that use it and the execution role those notebooks assume, so blast radius is answerable immediately
- VPC Flow Logs on the notebook subnets, to catch the OnStart script's C2 callback

**Alerting (must be pre-configured)**
- **`sagemaker:UpdateNotebookInstanceLifecycleConfig` from any principal not on the provisioning/IaC allowlist → alert.** This is the primary control, the call is rare and the write is the whole attack
- Content alert: an Update whose decoded OnStart/OnCreate script contains `curl`/`wget`/`base64 -d`/`/dev/tcp`/`bash -i`/an IP literal → high severity
- `sagemaker:CreateNotebookInstanceLifecycleConfig` creating a config with a suspicious OnStart from a non-provisioning principal (the create-new variant of the same abuse)
- Notebook start events (`sagemaker:StartNotebookInstance`) shortly after a lifecycle-config change, the moment the payload executes

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` and `base64` for decoding OnStart scripts
- The known-good OnStart content for each lifecycle config, saved (e.g. `known-good-onstart.txt`), so restoration is a command not a reconstruction
- The notebook execution-role policies on hand, to scope what the script could do

**Known IOC Baselines**
- Baseline which principals modify lifecycle configs, normally only provisioning
- Baseline the expected OnStart content per config, so an injected script is a diff

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `sagemaker:UpdateNotebookInstanceLifecycleConfig` whose decoded OnStart/OnCreate contains download-and-execute content (`curl`/`wget`/`/dev/tcp`/`base64 -d`) | CloudTrail | T1059 |
| P0 | `UpdateNotebookInstanceLifecycleConfig` from a principal not on the provisioning allowlist | CloudTrail | T1059 |
| P1 | `CreateNotebookInstanceLifecycleConfig` with a suspicious OnStart from a non-provisioning principal | CloudTrail | T1059 |
| P1 | Lifecycle-config change followed by `StartNotebookInstance` on a notebook using that config | CloudTrail | T1059 |
| P1 | Notebook C2 callback (outbound to an unrecognised host) shortly after a start | VPC Flow Logs | T1059 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `UpdateNotebookInstanceLifecycleConfig` outside a known deployment window | CloudTrail | T1059 |
| P2 | Update where the OnStart content changed length/hash significantly from baseline | CloudTrail / config diff | T1059 |
| P2 | `UpdateNotebookInstanceLifecycleConfig` denied (`errorCode = AccessDenied`) at volume, permission probing | CloudTrail | T1059 |
| P3 | Provisioning-pipeline principal updating a lifecycle config **outside** a known deployment window | CloudTrail | T1059 |

### Detection Rule Quality Notes

The rules in `detections/` are too coarse. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `UpdateNotebookInstanceLifecycleConfig` **and** `DescribeNotebookInstanceLifecycleConfig` with `condition: selection` | The `Describe` is a benign read that dilutes the alert; bundling it as an OR means a routine describe fires the same rule as a malicious update | Drop `Describe` as a trigger; alert on `Update` (and `Create`) only |
| No principal allowlist | Cannot separate provisioning from an attacker; the whole signal is "who changed the config" | Filter to non-provisioning principals |
| No content inspection | The strongest signal, a download-and-execute OnStart script, is ignored, and the base64 content is right there in the event | Decode `requestParameters.onStart[].content` and match on suspicious tokens |
| `Create*` variant absent | An attacker can create a *new* malicious config and attach it, evading an Update-only rule | Include `CreateNotebookInstanceLifecycleConfig` |
| Header TODO "verify acronym casing"; `level: medium` | Stale marker; and content-matched malice deserves higher severity | Resolve TODO; principal rule → `level: high`; content-matched rule → `level: critical` |

**Recommended detection, the config write, with content inspection.**

```yaml
title: SageMaker notebook lifecycle config modified with suspicious OnStart
id: 5d2a7f18-6b34-4c90-a2e1-8f0c3b9d4a67
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sagemaker.amazonaws.com'
    eventName:
      - 'UpdateNotebookInstanceLifecycleConfig'
      - 'CreateNotebookInstanceLifecycleConfig'
  allowlisted:
    userIdentity.arn|contains:
      - ':role/provisioning'
      - ':role/ci-'
  condition: selection and not allowlisted
level: high
```

Content-matched companion (higher severity where the log platform can decode
base64, the OnStart `content` field is base64 in the event):

```yaml
detection:
  selection:
    eventSource: 'sagemaker.amazonaws.com'
    eventName: ['UpdateNotebookInstanceLifecycleConfig', 'CreateNotebookInstanceLifecycleConfig']
  suspicious_decoded:
    # after base64-decoding requestParameters.onStart[].content / onCreate[].content
    DecodedOnStart|contains:
      - 'curl'
      - 'wget'
      - '/dev/tcp'
      - 'base64 -d'
      - 'bash -i'
  condition: selection and suspicious_decoded
level: critical
```

**On error strings:** SageMaker denials surface as `AccessDenied` / `AccessDeniedException` (not `Client.`-prefixed like EC2). Match both if you add a permission-probing rule, and confirm against a sample event.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`, robust, unlike `--output text | jq`.

#### Query 1: Find the lifecycle-config modification and who made it

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

for EV in UpdateNotebookInstanceLifecycleConfig CreateNotebookInstanceLifecycleConfig; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$START" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime,
     event: .eventName,
     caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,            # feeds ACCESS_KEY_ID in Query 5
     config: .requestParameters.notebookInstanceLifecycleConfigName,
     error: (.errorCode // "SUCCESS"),
     ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

#### Query 2: Decode the injected OnStart script (get the C2 IOCs)

Try the CloudTrail event first; if the content isn't present there, read it from
the config.

```bash
# GNU base64 decodes with -d, older BSD/macOS with -D. Probe, then decode.
b64d() { if base64 -d </dev/null >/dev/null 2>&1; then base64 -d; else base64 -D; fi; }

# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
CONFIG_NAME="<lifecycle-config-name-from-Query-1>"

# Option A: decode straight from the CloudTrail request parameters (if present)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateNotebookInstanceLifecycleConfig \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg c "$CONFIG_NAME" '.Events[].CloudTrailEvent | fromjson |
    select(.requestParameters.notebookInstanceLifecycleConfigName == $c) |
    (.requestParameters.onStart // [])[].content' | \
  while read -r B64; do [ -n "$B64" ] && echo "$B64" | b64d; done | tee ./ir-onstart.txt

# Option B - authoritative: read the live config (works even if CloudTrail omits content)
aws sagemaker describe-notebook-instance-lifecycle-config \
  --notebook-instance-lifecycle-config-name "$CONFIG_NAME" --region "$REGION" \
  --query 'OnStart[0].Content' --output text | b64d | tee -a ./ir-onstart.txt

echo "=== IOC scan ==="
grep -Ein 'curl|wget|nc |/dev/tcp|bash -i|http[s]?://|[0-9]{1,3}(\.[0-9]{1,3}){3}|AKIA[0-9A-Z]{16}' ./ir-onstart.txt
```

#### Query 3 - Blast radius: which notebooks use this config, and did any start?

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
CONFIG_NAME="<lifecycle-config-name>"

# Notebooks attached to the backdoored config: these run the script on next start
aws sagemaker list-notebook-instances --region "$REGION" \
  --query "NotebookInstances[?NotebookInstanceLifecycleConfigName=='$CONFIG_NAME'].
           {Name:NotebookInstanceName,Status:NotebookInstanceStatus}" --output table

# Any StartNotebookInstance after the config change = the payload likely executed
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StartNotebookInstance \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, caller: .userIdentity.arn,
     notebook: .requestParameters.notebookInstanceName}'
```

A notebook in `InService` that started after the config change should be treated
as having executed the payload under its execution role.

#### Query 4: Deployable detection (log platform, with content decode)

**Dialect: Sentinel / Azure Log Analytics KQL**, not CloudWatch Logs Insights.

```kql
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventSource == "sagemaker.amazonaws.com"
| where EventName in ("UpdateNotebookInstanceLifecycleConfig", "CreateNotebookInstanceLifecycleConfig")
| extend Req = parse_json(RequestParameters)
| extend OnStartB64 = tostring(Req.onStart[0].content)
| extend OnStart = base64_decode_tostring(OnStartB64)
| extend Config = tostring(Req.notebookInstanceLifecycleConfigName)
// Use `contains` (substring), NOT `has_any` (whole-term), has_any won't reliably
// match "/dev/tcp" or "base64 -d" (slash/space-delimited), the exact payloads here.
| extend Suspicious = OnStart contains "curl" or OnStart contains "wget"
                      or OnStart contains "/dev/tcp" or OnStart contains "base64 -d"
                      or OnStart contains "bash -i"
| project TimeGenerated, UserIdentityArn, EventName, Config, SourceIpAddress, Suspicious, OnStart
| where Suspicious
       or UserIdentityArn !has "role/provisioning"      // tune to your allowlist
| order by TimeGenerated desc
```

CloudWatch Logs Insights cannot base64-decode inline; there, alert on the Update
by non-provisioning principals and pivot to Query 2 for content:

```
fields @timestamp, userIdentity.arn, eventName, requestParameters.notebookInstanceLifecycleConfigName
| filter eventSource = "sagemaker.amazonaws.com"
| filter eventName in ["UpdateNotebookInstanceLifecycleConfig","CreateNotebookInstanceLifecycleConfig"]
| filter userIdentity.arn not like /role\/(provisioning|ci-)/
```

#### Query 5: Full session reconstruction of the modifying principal

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

ACCESS_KEY_ID="<access-key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$START" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

#### Query 6: Multi-region sweep

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  N=$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateNotebookInstanceLifecycleConfig \
    --start-time "$START" \
    --region "$REGION" --query 'length(Events)' --output text 2>/dev/null)
  [ -n "$N" ] && [ "$N" != "0" ] && [ "$N" != "None" ] && \
    echo "[!] $REGION, $N lifecycle-config updates"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The backdoor executes on every notebook start. Stop it re-executing: restore the
config, prevent affected notebooks from restarting into the payload, and contain
the principal.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1: Restore the lifecycle config to a benign OnStart

Neutralises the backdoor immediately so no future notebook start runs it.

```bash
REGION="us-east-1"
CONFIG_NAME="<lifecycle-config-name>"

# Restore known-good OnStart. The Content field is a plain (already-base64) STRING,
# so we pre-encode it ourselves here: the CLI does not base64 it for us.
GOOD_B64=$(base64 < ./known-good-onstart.txt) | tr -d '\n'
aws sagemaker update-notebook-instance-lifecycle-config \
  --notebook-instance-lifecycle-config-name "$CONFIG_NAME" --region "$REGION" \
  --on-start "Content=$GOOD_B64"
echo "[OK] Restored benign OnStart on $CONFIG_NAME"

# If there is no known-good baseline, clear OnStart entirely rather than leave it malicious:
# aws sagemaker update-notebook-instance-lifecycle-config \
#   --notebook-instance-lifecycle-config-name "$CONFIG_NAME" --region "$REGION" --on-start '[]'
```

#### Step 2: Contain the modifying principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')          # user ARN: name = last segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] Disabled key $K for $U"
  done
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')           # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]}'
  echo "[OK] Revoked sessions for role $R"
fi
```

#### Step 3: Stop notebooks that ran (or would run) the payload

For each notebook from Query 3 that used the config: stop it to sever any running
C2 and prevent a restart from re-executing until the config is confirmed clean.

```bash
REGION="us-east-1"
NOTEBOOK="<notebook-instance-name>"

STATUS=$(aws sagemaker describe-notebook-instance --notebook-instance-name "$NOTEBOOK" \
  --region "$REGION" --query 'NotebookInstanceStatus' --output text 2>/dev/null)
if [ "$STATUS" = "InService" ]; then
  aws sagemaker stop-notebook-instance --notebook-instance-name "$NOTEBOOK" --region "$REGION" && \
    echo "[OK] Stopping $NOTEBOOK (ran under the backdoored config)"
fi
```

#### Step 4: Deny further lifecycle-config changes by the principal

```bash
SUSPECT_ROLE="<role-name>"
aws iam put-role-policy --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenySageMakerLifecycle" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":["sagemaker:UpdateNotebookInstanceLifecycleConfig","sagemaker:CreateNotebookInstanceLifecycleConfig"],"Resource":"*"}]
  }'
echo "[OK] Lifecycle-config modification denied for $SUSPECT_ROLE"
```

---

## 4. Eradication

### Remove Attacker Access

#### Confirm the config is clean and check for other tampered configs

```bash
# GNU base64 decodes with -d, older BSD/macOS with -D. Probe, then decode.
b64d() { if base64 -d </dev/null >/dev/null 2>&1; then base64 -d; else base64 -D; fi; }

REGION="us-east-1"
CONFIG_NAME="<lifecycle-config-name>"

# Verify the restored OnStart no longer contains the payload
aws sagemaker describe-notebook-instance-lifecycle-config \
  --notebook-instance-lifecycle-config-name "$CONFIG_NAME" --region "$REGION" \
  --query 'OnStart[0].Content' --output text | b64d

# Sweep ALL lifecycle configs for suspicious OnStart/OnCreate content: the
# attacker may have touched more than one
for C in $(aws sagemaker list-notebook-instance-lifecycle-configs --region "$REGION" \
    --query 'NotebookInstanceLifecycleConfigs[].NotebookInstanceLifecycleConfigName' --output text); do
  BODY=$(aws sagemaker describe-notebook-instance-lifecycle-config \
    --notebook-instance-lifecycle-config-name "$C" --region "$REGION" \
    --query 'OnStart[0].Content' --output text 2>/dev/null | b64d 2>/dev/null)
  echo "$BODY" | grep -qEi 'curl|wget|/dev/tcp|bash -i|http[s]?://' && echo "[!] Suspicious OnStart in config: $C"
done
echo "[OK] Lifecycle-config sweep complete"
```

#### Treat any notebook that executed the payload as compromised

A notebook that started under the backdoored config ran attacker code as its
execution role. Enumerate that role's activity, and rebuild the notebook rather
than trusting it.

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
NOTEBOOK="<notebook-instance-name>"

# The notebook's execution role
ROLE_ARN=$(aws sagemaker describe-notebook-instance --notebook-instance-name "$NOTEBOOK" \
  --region "$REGION" --query 'RoleArn' --output text)
ROLE_NAME=$(echo "$ROLE_ARN" | awk -F'/' '{print $NF}')
echo "Notebook execution role: $ROLE_NAME"

# What that role did (look for off-notebook use / IAM / data access driven by the script).
# NOTE: do NOT key `--lookup-attributes Username` on the role name - for
# AssumedRole sessions the CloudTrail Username is the SESSION name, not the role
# name, so a role-name lookup silently returns nothing. Pull the window and
# jq-filter on the role name inside sessionContext.sessionIssuer.userName instead.
aws cloudtrail lookup-events \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg role "$ROLE_NAME" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.type == "AssumedRole") |
    select((.userIdentity.sessionContext.sessionIssuer.userName // "") == $role) |
    {time: .eventTime, event: .eventName, source: .eventSource, ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

(A bare `lookup-events` window pull can be large; narrow `--start-time`, or if
your log platform is available, filter on `sessionIssuer.userName == "<role>"`
there instead.)

If the execution role was abused, revoke its sessions and pivot to the relevant
playbook. Delete and recreate the notebook instance from a clean definition.
Block the Query 2 C2 IOCs at the edge and hunt for them.

#### Right-size lifecycle-config permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove sagemaker:Update/CreateNotebookInstanceLifecycleConfig from principals
# that are not the provisioning pipeline.
```

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenySageMakerLifecycle" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the config's OnStart is benign

```bash
# GNU base64 decodes with -d, older BSD/macOS with -D. Probe, then decode.
b64d() { if base64 -d </dev/null >/dev/null 2>&1; then base64 -d; else base64 -D; fi; }

REGION="us-east-1"
CONFIG_NAME="<lifecycle-config-name>"

BODY=$(aws sagemaker describe-notebook-instance-lifecycle-config \
  --notebook-instance-lifecycle-config-name "$CONFIG_NAME" --region "$REGION" \
  --query 'OnStart[0].Content' --output text 2>/dev/null | b64d 2>/dev/null)
if echo "$BODY" | grep -qEi 'curl|wget|/dev/tcp|bash -i|http[s]?://|AKIA[0-9A-Z]{16}'; then
  echo "[FAIL] $CONFIG_NAME OnStart still contains suspicious content"
else
  echo "[OK] $CONFIG_NAME OnStart is clean"
fi
```

#### Verify no further lifecycle-config changes since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(for EV in UpdateNotebookInstanceLifecycleConfig CreateNotebookInstanceLifecycleConfig; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$CONTAINED_AT" --region "$REGION" --output json 2>/dev/null
done | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | select(.errorCode == null) | .eventTime' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No further lifecycle-config changes from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further changes, containment did not hold"
```

#### Verify the credential is dead

```bash
SUSPECT_ARN="<principal-arn>"
if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  ACTIVE=$(aws iam list-access-keys --user-name "$U" \
    --query 'AccessKeyMetadata[?Status==`Active`]' --output text)
  [ -z "$ACTIVE" ] && echo "[OK] No active keys for $U" || echo "[FAIL] $U still has active keys"
fi
```

#### Verify the C2 IOCs are blocked and absent

```bash
echo "Confirm each Query 2 IOC (URL/IP/domain) is blocked at the edge and does not"
echo "appear in any notebook subnet's egress after remediation."
```

#### Confirm the corrected detection fires

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
CONFIG_NAME="<lifecycle-config-name>"

# Re-run the emulation and assert the Update event with OnStart content is captured
HIT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateNotebookInstanceLifecycleConfig \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg c "$CONFIG_NAME" '[.Events[].CloudTrailEvent | fromjson |
    select(.requestParameters.notebookInstanceLifecycleConfigName == $c)] | length')

[ -n "$HIT" ] && [ "$HIT" -gt 0 ] && echo "[OK] Update captured, the rule has data to fire on" \
                                  || echo "[FAIL] No Update captured, check trail / event name"
echo "Confirm the content-matched rule flagged the OnStart as suspicious (Suspicious=true)."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could rewrite a lifecycle config's OnStart | `sagemaker:UpdateNotebookInstanceLifecycleConfig` granted to a principal outside provisioning; no alerting on lifecycle-config writes |
| Malicious script ran on notebook start | OnStart scripts execute automatically with the notebook execution role; no review/pin of lifecycle-config content |
| Attack undetected | Shipped rule bundled the benign Describe, applied no principal filter, and never inspected the OnStart content that was sitting in the event |
| Notebook execution role over-permissioned | The injected script inherited whatever the notebook role could do |
| Config change untied to notebook starts | No correlation between a lifecycle-config change and subsequent `StartNotebookInstance` |

### Recommended Guardrails

**Restrict lifecycle-config modification to provisioning**

```json
// SCP: only provisioning/CI roles may create/modify notebook lifecycle configs
{
  "Effect": "Deny",
  "Action": [
    "sagemaker:UpdateNotebookInstanceLifecycleConfig",
    "sagemaker:CreateNotebookInstanceLifecycleConfig"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "aws:PrincipalArn": ["arn:aws:iam::*:role/provisioning", "arn:aws:iam::*:role/ci-*", "arn:aws:iam::*:role/BreakGlassAdmin"]
    }
  }
}
```

**Least-privilege notebook execution roles**
- The notebook execution role bounds what an injected OnStart script can do. Scope it to the notebook's actual needs, never `AdministratorAccess` or broad data access, so a backdoored config yields a limited foothold
- Manage lifecycle configs through IaC and treat any out-of-band `Update`/`Create` as an incident

**Detection improvements**
- Deploy the write rule (Update/Create by non-provisioning principal) and the content-matched rule (decoded OnStart contains download-and-execute tokens), never the shipped Update+Describe match
- Correlate a lifecycle-config change with a subsequent `StartNotebookInstance`
- Baseline expected OnStart content per config so an injected script is a diff

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1059 - Command and Scripting Interpreter |
| MITRE tactic | Execution (TA0002); also has a Persistence character (event-triggered re-execution on every notebook start, akin to T1546) |
| Primary API | `sagemaker:UpdateNotebookInstanceLifecycleConfig` (and `CreateNotebookInstanceLifecycleConfig`) |
| Event source | `sagemaker.amazonaws.com` |
| Key discriminator | The Update/Create write by a non-provisioning principal, and a decoded OnStart/OnCreate containing download-and-execute content, not the benign Describe |
| Payload recovery | Decode `requestParameters.onStart[].content` from CloudTrail (usually present), or `describe-notebook-instance-lifecycle-config … OnStart[0].Content | base64 -d` |
| Execution context | Runs as the **notebook instance's execution role** on every notebook start/restart |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException` |
| Resources created | 1 SageMaker Notebook Instance Lifecycle Configuration |
| Follow-on to watch for | C2 callback from the notebook, notebook-execution-role abuse, data access from the notebook |

### Revert

`pulumi destroy` in `infra/` removes the lifecycle configuration. The emulation's
own revert restores the benign OnStart script, so a normal run leaves the config
clean. After a **real** incident, restore the config's OnStart per §3, rebuild any
notebook that executed the payload, right-size the notebook execution role, and
block the C2 IOCs, `pulumi destroy` does not undo code that already ran on a
notebook or credentials that code may have used.
