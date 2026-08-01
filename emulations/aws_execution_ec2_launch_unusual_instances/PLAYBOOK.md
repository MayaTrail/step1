# IR Playbook: Launch Unusual EC2 Instance Types for Cryptomining — Resource Hijacking via `ec2:RunInstances`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Execution / Resource Hijacking (cryptomining) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A — single-technique emulation (the AMBERSQUID campaign playbook covers a full actor version of this) |
| Platform | aws |
| Severity | Medium–High — Medium as the atomic launch signal; High once mining is confirmed or the launch is at scale/across regions, given direct billing loss and reputational risk |
| MITRE Tactics | Execution |
| MITRE Techniques | T1204.003 (as mapped by Stratus — a poor fit; T1496 Resource Hijacking is closer, see §6) |
| Services in Scope | EC2, GuardDuty, CloudTrail, Cost Explorer / Budgets, Auto Scaling, EC2 Fleet/Spot |
| Infrastructure Created | None — the emulation launches and then terminates its own instance in a `finally` block |

**What the emulation does:** calls `ec2:RunInstances` trying a list of GPU / compute-dense instance types (p2/p3/g4 families) associated with mining, falling back to a small instance if those are unavailable, then terminates whatever it launched. Even when the GPU launches fail (quota/availability), the *attempt* is recorded in CloudTrail — which is itself the detection signal.

**Why the instance TYPE is the signal, not the `RunInstances` call.** `ec2:RunInstances` is one of the most frequent management calls in any active account — autoscaling, CI, deployments, batch jobs all launch instances constantly. Matching the call is useless. What marks this technique is `requestParameters.instanceType` landing in a **GPU / accelerated / expensive-compute family** that the account does not normally run:

- **GPU (`p2/p3/p4/p5`, `g3/g4/g4ad/g5/g6`) and FPGA (`f1/f2`)** — the families actually useful for cryptomining hash-work, and the highest-value signal.
- **ML-accelerator families (`inf1/inf2` Inferentia, `trn1` Trainium, `dl1` Habana Gaudi)** — these are ASIC ML accelerators, **not effective for classic proof-of-work mining**. Include them as an *expensive-compute abuse / cost* signal, but do not label their presence as cryptomining specifically; the likely abuse there is cost-theft, not mining.

The shipped rule matches every `RunInstances` (§2) and is unusable.

**Why failed launches matter.** The emulation tries several GPU types before falling back. Those attempts fail with `Client.VcpuLimitExceeded` / `Client.InstanceLimitExceeded` / an unsupported-type error — and a burst of *failed* `RunInstances` across large instance types from one principal is an attacker probing what they can spin up. A detection keyed only on successful launches misses the probing phase.

**Three detection layers, because one is not enough.** Control-plane (`RunInstances` + unusual type — immediate, but evadable by using a permitted family), runtime (GuardDuty `CryptoCurrency:EC2/BitcoinTool.B` — confirms actual mining traffic), and billing (Cost Anomaly Detection — lagging, but catches mining on *normal-looking* instance types that the first two miss). A mature program runs all three.

**The relaunch trap.** Terminating the miner instance is not containment. Real cryptomining intrusions launch miners via an **Auto Scaling group, EC2 Fleet, or Spot Fleet** so that terminated instances are automatically replaced. Containment must remove the *launch mechanism* first, or the miners respawn faster than you can kill them (the AMBERSQUID pattern).

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to CloudWatch Logs / a log platform. `RunInstances`/`TerminateInstances` are management events, so `lookup-events` works for them
- **GuardDuty enabled in all regions** — `CryptoCurrency:EC2/BitcoinTool.B` and `!DNS` variants are the runtime confirmation and are GuardDuty-only
- **AWS Cost Anomaly Detection** (or a Budgets anomaly alert) configured on EC2 spend — the billing layer that catches mining the control-plane and GuardDuty rules miss
- A baseline of instance-type families the account legitimately runs, per region, so "unusual" is a concrete list rather than a guess
- VPC Flow Logs, to see outbound mining-pool connections from a suspect instance

**Alerting (must be pre-configured)**
- `ec2:RunInstances` with an `instanceType` in a GPU/accelerated family not in the account baseline → alert (control-plane, immediate). This is the primary control
- A burst of **failed** `RunInstances` across large instance types from one principal → alert (the probing signal). Match the full failure set the attack produces — `VcpuLimitExceeded`, `InstanceLimitExceeded`, `InsufficientInstanceCapacity`, `Unsupported`, `InvalidParameterValue` — not just `*LimitExceeded`
- GuardDuty `CryptoCurrency:EC2/*` → SNS → on-call at P0
- Cost Anomaly Detection: >X% day-over-day EC2 spend increase → alert
- `ec2:CreateFleet` / `ec2:RequestSpotFleet` / `autoscaling:CreateAutoScalingGroup` launching GPU/compute types from a non-CI principal → alert (the relaunch mechanism)

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` installed
- The account's Service Quotas for GPU families on hand — low quotas are both a control and a triage aid
- A current inventory of legitimate Auto Scaling groups / fleets, so an attacker-created one is distinguishable

**Known IOC Baselines**
- Baseline the instance-type families and per-region footprint. A `p3.2xlarge` in a region that normally runs only `t3`/`m5` is anomalous on its own
- Baseline which principals call `RunInstances` and at what scale
- Mining-pool ports and known pool domains for the Flow Logs / GuardDuty correlation (see the AMBERSQUID playbook's IOC table)

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | GuardDuty `CryptoCurrency:EC2/BitcoinTool.B` or `...BitcoinTool.B!DNS` on any instance | GuardDuty | T1204.003 |
| P0 | `ec2:RunInstances` succeeding with a GPU/accelerated type (`p*`,`g*`,`inf*`,`trn*`,`dl*`) not in the account baseline, from a non-CI principal | CloudTrail | T1204.003 |
| P1 | Burst of failed `RunInstances` (`Client.VcpuLimitExceeded`/`InstanceLimitExceeded`) across large types from one principal — capability probing | CloudTrail | T1204.003 |
| P1 | Attacker-created Auto Scaling group / EC2 Fleet / Spot Fleet launching GPU/compute types | CloudTrail | T1204.003 |
| P1 | EC2 cost anomaly (Cost Anomaly Detection) not explained by a known deployment | Cost Explorer | T1204.003 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `RunInstances` of an unusual type in a region with no normal workload | CloudTrail | T1204.003 |
| P2 | Instances launched then a same-principal spike in outbound traffic to non-standard ports (mining pools) | VPC Flow Logs | T1204.003 |
| P2 | `RunInstances` with `imageId` referencing a public/community AMI not on the approved list | CloudTrail | T1204.003 |
| P3 | Single GPU instance launched by an allowlisted ML/CI principal, terminated normally | CloudTrail | T1204.003 |

### Detection Rule Quality Notes

The rules in `detections/` are unusable as written. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (DescribeImages, RunInstances, TerminateInstances)` with `condition: selection`, no `instanceType` filter | Catastrophically noisy. `RunInstances` fires on every autoscale/CI/deploy; `DescribeImages`/`TerminateInstances` are pure noise. The rule cannot distinguish a mining launch from normal capacity | Drop `DescribeImages`/`TerminateInstances` as triggers; filter `RunInstances` to unusual `instanceType` families |
| No instance-type discriminator | The defining signal (GPU/accelerated family) is exactly what an event-name match ignores | Match `requestParameters.instanceType` against the GPU/accelerated family patterns |
| No `errorCode` handling | Loses the capability-probing signal (failed large-type launches) and cannot separate a successful hijack from a blocked attempt | Add both a success rule and a failed-attempt rule |
| GuardDuty `CryptoCurrency` finding — the definitive runtime signal — not referenced | The best confirmation of *actual* mining is absent from the detection set | Add a GuardDuty finding rule at P0 |
| Header TODO "verify acronym casing"; `level: medium` on a rule matching all `RunInstances` | Stale marker; alert fatigue | Resolve TODO; unusual-type rule → `level: high`; GuardDuty rule → `level: critical` |

**Recommended detection — `RunInstances` with an unusual instance type.**

```yaml
title: EC2 RunInstances with GPU/accelerated instance type
id: 7a3e1c62-9b40-4d8f-a1e5-6c2b7f0d9a34
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'RunInstances'
  unusual_type:
    # GPU / accelerated-compute families — tune to your account baseline
    requestParameters.instanceType|re: '^(p[0-9]|g[0-9]|f[0-9]|inf[0-9]|trn[0-9]|dl[0-9])'
  allowlisted:
    userIdentity.arn|contains:
      - ':role/ml-training'
      - ':role/ci-'
  condition: selection and unusual_type and not allowlisted
level: high
```

Companion GuardDuty rule (the runtime confirmation):

```yaml
title: GuardDuty EC2 cryptomining finding
status: stable
logsource:
  product: aws
  service: guardduty
detection:
  selection:
    type|startswith: 'CryptoCurrency:EC2/'
  condition: selection
level: critical
```

Add a third rule for failed capability probing: same `selection` plus a match on
the full set of `RunInstances` failure codes the attack actually produces —
`errorCode|contains` any of `VcpuLimitExceeded`, `InstanceLimitExceeded`,
`InsufficientInstanceCapacity`, `Unsupported`, `InvalidParameterValue` (a
`LimitExceeded`-only substring match misses the capacity/unsupported/invalid-param
failures, which are equally strong "probing what I can launch" signals) —
grouped/counted per principal, at `level: medium`.

**On error strings:** EC2 CloudTrail errors carry a `Client.` prefix —
`Client.VcpuLimitExceeded`, `Client.InstanceLimitExceeded`,
`Client.UnauthorizedOperation`. Match the prefixed form (or `contains`) and
confirm against a sample event.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'` — robust, unlike `--output text | jq`.

#### Query 1 — Find the unusual `RunInstances` calls and who made them

```bash
REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --start-time "$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime,
     caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,          # feeds ACCESS_KEY_ID in Query 5
     type: .requestParameters.instanceType,
     image: .requestParameters.imageId,
     instances: ([.responseElements.instancesSet.items[]?.instanceId] // []),
     error: (.errorCode // "SUCCESS"),
     ip: .sourceIPAddress}' | \
  jq -s 'map(select(.type | test("^(p[0-9]|g[0-9]|f[0-9]|inf[0-9]|trn[0-9]|dl[0-9])"))) |
         sort_by(.time)'
```

Rows with a GPU/accelerated `type` are the hits. `SUCCESS` + a real
`instances` id = a live miner to kill; a `Client.*LimitExceeded` error =
a blocked probe (still investigate the principal).

#### Query 2 — Locate the running miner instances to terminate

```bash
REGION="us-east-1"

# Live GPU/accelerated instances (the ones costing money right now)
aws ec2 describe-instances --region "$REGION" \
  --filters "Name=instance-state-name,Values=running,pending" \
  --query 'Reservations[].Instances[?starts_with(InstanceType, `p`) ||
             starts_with(InstanceType, `g`) || starts_with(InstanceType, `inf`) ||
             starts_with(InstanceType, `trn`) || starts_with(InstanceType, `dl`) || starts_with(InstanceType, `f`)].
             {Id:InstanceId,Type:InstanceType,Launched:LaunchTime,AZ:Placement.AvailabilityZone}' \
  --output table
```

#### Query 3 — Find the relaunch mechanism (before killing instances)

Kill the launcher first, or terminated miners respawn.

```bash
REGION="us-east-1"

# Auto Scaling groups launching GPU/compute types
aws autoscaling describe-auto-scaling-groups --region "$REGION" \
  --query 'AutoScalingGroups[].{Name:AutoScalingGroupName,Desired:DesiredCapacity,LT:LaunchTemplate.LaunchTemplateName}' \
  --output table

# EC2 Fleet / Spot Fleet requests
aws ec2 describe-fleets --region "$REGION" \
  --query 'Fleets[?FleetState==`active`].{Id:FleetId,Capacity:TargetCapacitySpecification.TotalTargetCapacity}' \
  --output table 2>/dev/null
aws ec2 describe-spot-fleet-requests --region "$REGION" \
  --query 'SpotFleetRequestConfigs[?SpotFleetRequestState==`active`].SpotFleetRequestId' \
  --output text 2>/dev/null

# Recently created ASGs (attacker infra)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAutoScalingGroup \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, caller: .userIdentity.arn, asg: .requestParameters.autoScalingGroupName}'

# Recently created launch templates (surfaces the ID and NAME for §4 deletion)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateLaunchTemplate \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, caller: .userIdentity.arn,
     lt_id: .responseElements.CreateLaunchTemplateResponse.launchTemplate.launchTemplateId,
     lt_name: .requestParameters.CreateLaunchTemplateRequest.launchTemplateName}'
```

#### Query 4 — GuardDuty cryptomining findings

```bash
REGION="us-east-1"
DETECTOR_ID=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text)

aws guardduty list-findings --detector-id "$DETECTOR_ID" --region "$REGION" \
  --finding-criteria '{"Criterion":{"type":{"Eq":["CryptoCurrency:EC2/BitcoinTool.B","CryptoCurrency:EC2/BitcoinTool.B!DNS"]}}}' \
  --query 'FindingIds' --output text | \
  xargs -r aws guardduty get-findings --detector-id "$DETECTOR_ID" --region "$REGION" --finding-ids
```

#### Query 5 — Full session reconstruction of the launching principal

```bash
ACCESS_KEY_ID="<access-key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

#### Query 6 — Multi-region sweep (miners spread across regions)

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  N=$(aws ec2 describe-instances --region "$REGION" \
    --filters "Name=instance-state-name,Values=running,pending" \
    --query 'length(Reservations[].Instances[?starts_with(InstanceType, `p`) ||
               starts_with(InstanceType, `g`) || starts_with(InstanceType, `inf`) ||
               starts_with(InstanceType, `trn`) || starts_with(InstanceType, `dl`) || starts_with(InstanceType, `f`)][])' \
    --output text 2>/dev/null)
  [ -n "$N" ] && [ "$N" != "0" ] && echo "[!] $REGION — $N GPU/accelerated instances running"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Order matters: **kill the relaunch mechanism, then the instances, then the
principal.** Terminating instances first just triggers auto-replacement.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1 — Remove the relaunch mechanism (from Query 3)

```bash
REGION="us-east-1"

# Set attacker ASG desired/min to 0 and delete it (force-detaches instances)
ASG="<attacker-asg-name>"
aws autoscaling update-auto-scaling-group --auto-scaling-group-name "$ASG" \
  --min-size 0 --desired-capacity 0 --region "$REGION"
aws autoscaling delete-auto-scaling-group --auto-scaling-group-name "$ASG" \
  --force-delete --region "$REGION" && echo "[OK] Deleted attacker ASG $ASG"

# Cancel Spot Fleet / EC2 Fleet requests (terminate their instances)
SFR="<spot-fleet-request-id>"
aws ec2 cancel-spot-fleet-requests --spot-fleet-request-ids "$SFR" \
  --terminate-instances --region "$REGION" 2>/dev/null && echo "[OK] Cancelled spot fleet $SFR"
```

#### Step 2 — Terminate the miner instances (from Query 2 / Query 6, per region)

```bash
REGION="us-east-1"

MINERS=$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=instance-state-name,Values=running,pending" \
  --query 'Reservations[].Instances[?starts_with(InstanceType, `p`) ||
             starts_with(InstanceType, `g`) || starts_with(InstanceType, `inf`) ||
             starts_with(InstanceType, `trn`) || starts_with(InstanceType, `dl`) || starts_with(InstanceType, `f`)].InstanceId' \
  --output text)

# Optional: snapshot a miner's volume for forensics before terminating (malware sample)
for IID in $MINERS; do
  echo "  Terminating miner: $IID"
  aws ec2 terminate-instances --instance-ids "$IID" --region "$REGION" \
    --query 'TerminatingInstances[0].{Id:InstanceId,State:CurrentState.Name}'
done
[ -z "$MINERS" ] && echo "[OK] No running miners in $REGION" || echo "[OK] Termination issued in $REGION"
```

#### Step 3 — Contain the launching principal

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

#### Step 4 — Block further large-instance launches immediately

```bash
SUSPECT_ROLE="<role-name>"
aws iam put-role-policy --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenyRunInstances" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":["ec2:RunInstances","ec2:CreateFleet","ec2:RequestSpotFleet","autoscaling:CreateAutoScalingGroup"],"Resource":"*"}]
  }'
echo "[OK] Launch actions denied for $SUSPECT_ROLE"
```

---

## 4. Eradication

### Remove Attacker Access

#### Confirm every miner and launcher is gone (all regions)

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  # Any GPU/accelerated instance still not terminated
  N=$(aws ec2 describe-instances --region "$REGION" \
    --filters "Name=instance-state-name,Values=running,pending" \
    --query 'length(Reservations[].Instances[?starts_with(InstanceType, `p`) ||
               starts_with(InstanceType, `g`) || starts_with(InstanceType, `inf`) ||
               starts_with(InstanceType, `trn`) || starts_with(InstanceType, `dl`) || starts_with(InstanceType, `f`)][])' \
    --output text 2>/dev/null)
  [ -n "$N" ] && [ "$N" != "0" ] && echo "[!] $REGION still has $N GPU instances — terminate"
  # Any active ASG/fleet that could relaunch
  aws autoscaling describe-auto-scaling-groups --region "$REGION" \
    --query 'AutoScalingGroups[?DesiredCapacity>`0`].AutoScalingGroupName' --output text 2>/dev/null
done
echo "[OK] Cross-region miner/launcher sweep complete"
```

#### Remove attacker launch templates and AMIs

```bash
REGION="us-east-1"
# Delete attacker-created launch templates (IDs/names from Query 3's
# CreateLaunchTemplate lookup). Use --launch-template-id OR --launch-template-name.
LT="<attacker-launch-template-id>"
aws ec2 delete-launch-template --launch-template-id "$LT" --region "$REGION" 2>/dev/null && \
  echo "[OK] Deleted launch template $LT"
```

#### Right-size the principal's launch permissions

```bash
SUSPECT_ROLE="<role-name>"
# Review and scope RunInstances — most principals should be limited to an
# allowlist of instance types via the ec2:InstanceType condition key (see Guardrails).
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
```

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenyRunInstances" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify no GPU/accelerated instances remain running

```bash
FAIL=0
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  N=$(aws ec2 describe-instances --region "$REGION" \
    --filters "Name=instance-state-name,Values=running,pending" \
    --query 'length(Reservations[].Instances[?starts_with(InstanceType, `p`) ||
               starts_with(InstanceType, `g`) || starts_with(InstanceType, `inf`) ||
               starts_with(InstanceType, `trn`) || starts_with(InstanceType, `dl`) || starts_with(InstanceType, `f`)][])' \
    --output text 2>/dev/null)
  [ -n "$N" ] && [ "$N" != "0" ] && { echo "[FAIL] $REGION still runs $N GPU instances"; FAIL=1; }
done
[ "$FAIL" -eq 0 ] && echo "[OK] No GPU/accelerated instances running in any region"
```

#### Verify no relaunch mechanism survives

```bash
FAIL=0
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  ASGS=$(aws autoscaling describe-auto-scaling-groups --region "$REGION" \
    --query 'AutoScalingGroups[?DesiredCapacity>`0`].AutoScalingGroupName' --output text 2>/dev/null)
  # Cross-check any survivors against the known-good ASG inventory from §1
  [ -n "$ASGS" ] && echo "[i] $REGION active ASGs (verify against inventory): $ASGS"
done
echo "[OK] Relaunch-mechanism review complete"
```

#### Verify no further unusual launches since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    select(.requestParameters.instanceType | test("^(p[0-9]|g[0-9]|f[0-9]|inf[0-9]|trn[0-9]|dl[0-9])")) |
    select(.errorCode == null) | .eventTime' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No further unusual launches from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further GPU launches — containment did not hold"
```

#### Verify billing has returned to baseline

```bash
# EC2 daily unblended cost — confirm the spike is over
aws ce get-cost-and-usage --granularity DAILY \
  --time-period Start=$(date -u -d '7 days ago' +%Y-%m-%d),End=$(date -u +%Y-%m-%d) \
  --metrics UnblendedCost \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Elastic Compute Cloud - Compute"]}}' \
  --query 'ResultsByTime[].{Date:TimePeriod.Start,Cost:Total.UnblendedCost.Amount}' \
  --output table
echo "Confirm the daily EC2 cost has dropped back to baseline after termination."
```

#### Verify GuardDuty is enabled everywhere

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  D=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text 2>/dev/null)
  { [ -z "$D" ] || [ "$D" = "None" ]; } && echo "[!] GuardDuty NOT enabled in $REGION"
done
echo "[OK] GuardDuty sweep complete"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could launch GPU/accelerated instances | No `ec2:InstanceType` restriction on `RunInstances`; the principal could launch any type |
| Mining launch undetected | Shipped rule matched all `RunInstances` (no type filter) and was muted; GuardDuty crypto findings not alerted at P0 |
| Cost impact noticed late | No Cost Anomaly Detection on EC2 spend |
| Miners could respawn | No detection/restriction on attacker-created Auto Scaling groups / fleets |
| High GPU quotas available | Service Quotas for GPU families left at high defaults with no business need |

### Recommended Guardrails

**Service Control Policies (SCPs) — apply at OU level**

```json
// SCP 1: Allow RunInstances only for approved instance types.
// NOTE: ec2:InstanceType is a SINGLE-valued condition key — use plain
// StringNotLike, NOT the ForAnyValue:/ForAllValues: set-operator prefix
// (applying a set operator to a single-valued key evaluates inconsistently and
// can fail open).
{
  "Effect": "Deny",
  "Action": "ec2:RunInstances",
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringNotLike": {
      "ec2:InstanceType": ["t3.*", "m5.*", "c5.*", "r5.*"]
    }
  }
}
```

```json
// SCP 2: Restrict fleet/ASG creation to CI principals
{
  "Effect": "Deny",
  "Action": ["ec2:CreateFleet", "ec2:RequestSpotFleet", "autoscaling:CreateAutoScalingGroup"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/ci-*", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

**Keep GPU quotas at zero unless needed**
- Set Service Quotas for GPU/accelerated families (`p`, `g`, `inf`, `trn`, `dl`) to 0 in accounts/regions with no ML workload — an attacker's launch then fails at the quota, and the failed attempt is itself an alert

**Detection improvements**
- Deploy the unusual-`instanceType` `RunInstances` rule and the GuardDuty `CryptoCurrency:EC2/*` rule as separate detections (high / critical)
- Add the failed-launch probing rule (`*LimitExceeded` at volume)
- Enable Cost Anomaly Detection on EC2 as the billing backstop
- Alert on attacker-shaped fleet/ASG creation

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1204.003 (as mapped by Stratus) — see caveat below |
| MITRE tactic | Execution (TA0002) |
| Primary API | `ec2:RunInstances` with a GPU/accelerated `instanceType`; `TerminateInstances` on cleanup |
| Event source | `ec2.amazonaws.com` |
| Key discriminator | `requestParameters.instanceType` in a GPU/accelerated family (`p*`,`g*`,`inf*`,`trn*`,`dl*`) not in the account baseline — the call alone is not a signal |
| Runtime confirmation | GuardDuty `CryptoCurrency:EC2/BitcoinTool.B` / `!DNS` |
| Billing backstop | Cost Anomaly Detection on EC2 compute spend |
| Error strings (`Client.`-prefixed) | `Client.VcpuLimitExceeded`, `Client.InstanceLimitExceeded`, `Client.UnauthorizedOperation` |
| Relaunch mechanisms | Auto Scaling group, EC2 Fleet, Spot Fleet — kill these BEFORE terminating instances |
| Resources created | None — the emulation launches then self-terminates |
| Related | The AMBERSQUID campaign playbook is the full multi-service actor version of cryptomining |

**MITRE mapping caveat:** the MANIFEST maps this to **T1204.003**, whose canonical
MITRE name is *User Execution: Malicious Image* — which describes a user deploying
a malicious container/VM image, not launching stock instances of an expensive
type to mine. The behaviour is squarely **T1496 (Resource Hijacking)** under the
Impact tactic. The mapping is inherited from Stratus Red Team; treat the
behaviour (resource hijacking for mining) as authoritative and the technique ID
as approximate. Recorded for the end-of-run MITRE-mapping finding.

### Revert

The emulation launches an instance and terminates it in a `finally` block, so a
normal run leaves nothing; `pulumi destroy` is a no-op (no infra). **Verify the
self-termination actually succeeded** — if the GPU launch happened to succeed and
the terminate call failed, a genuinely expensive instance could be left running.
Run Query 2 after any emulation to confirm no GPU/accelerated instance survives.
After a **real** incident, `pulumi destroy` is irrelevant — terminate the miners
and remove the relaunch mechanism per §3–§4.
