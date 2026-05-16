# Detection Note: T1204.003 - User Execution: Malicious Image
# AMBERSQUID: ECS Fargate task runs attacker-staged Docker image with injected IAM credentials

## Execution Plane
Data plane — ECS container execution generates NO CloudTrail management events.
The malicious container runtime is invisible to CloudTrail. Credential harvest from
injected environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) is
entirely a container-internal operation.

## First CloudTrail-Visible Event
The container's FIRST external action is T1078.004 GetCallerIdentity (STS).
This is the earliest point in the kill chain where defenders have a CloudTrail signal.
See: sigma_t1078.004.yml / kql_t1078.004.kql

## Detection Alternatives (in priority order)

### 1. ECS Task Launch (Management Plane — CloudTrail)
The RunTask or CreateService call that starts the malicious container IS in CloudTrail.
Detect: ECS RunTask with ubuntu:22.04 (or unknown public image) + launchType FARGATE
from a non-console session. See sigma_t1608.001.yml for RegisterTaskDefinition.

```
AWSCloudTrail
| where EventSource == "ecs.amazonaws.com"
| where EventName == "RunTask"
| where RequestParameters contains "ubuntu" or RequestParameters contains "docker.io"
| where UserAgent !contains "console.aws.amazon.com"
```

### 2. Container Environment Variable Audit (ECS Task Definition Inspection)
ECS task definitions that inject AWS credentials as plaintext environment variables
are detectable at definition creation time (RegisterTaskDefinition CloudTrail event).

```
AWSCloudTrail
| where EventSource == "ecs.amazonaws.com"
| where EventName == "RegisterTaskDefinition"
| where RequestParameters has_any ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
```

AMBERSQUID IOC: ambersquid-task-definition contains AWS credentials as plaintext
container environment variables. This is a security misconfiguration indicator
regardless of attacker presence — should be detected and alerted unconditionally.

### 3. Amazon Inspector - Container Image Vulnerability / Malware Scanning
Amazon Inspector (ECR integration) scans images pushed to ECR for:
  - UPX-packed ELF binaries (SRBMiner-MULTI is UPX-packed)
  - Known malware signatures (SRBMiner, XMRig, NBMiner)
  - CVE findings in image layers
AMBERSQUID uses public Docker Hub images, not ECR — Inspector does not scan these
at pull time unless ECR pull-through cache is configured with inspection enabled.

### 4. GuardDuty - ECS Runtime Monitoring (if enabled)
GuardDuty ECS runtime monitoring (requires GuardDuty agent sidecar or ECS integration):
  - Finding: Execution:Runtime/NewBinaryExecuted — detects SRBMiner binary execution
  - Finding: CryptoCurrency:Runtime/BitcoinTool.B — detects mining pool connections
  - Finding: UnauthorizedAccess:Runtime/TorRelay — if miner uses Tor exit node pools
Note: GuardDuty ECS runtime monitoring requires explicit opt-in and agent deployment.

### 5. VPC Flow Logs - Mining Pool Outbound Connections
Mining pool ports blocked by ambersquid-task-sg in this lab (3333, 4444, 5555,
7777, 8888, 9999, 14444, 45560). In production without this block:
  - VPC Flow Logs REJECT entries on known mining pool ports from ECS task ENI
  - DNS query logs for mining pool domains: 2miners.com, c3pool.com, nanopool.org
  - Network firewall rules blocking these domains/IPs with alert on match

### 6. ECS Container Insights - Process-Level Anomaly
ECS Container Insights with performance monitoring enabled can detect:
  - CPU utilization spike to ~100% sustained (mining workload pattern)
  - Network throughput to external IPs on non-standard ports
  - Process name "SRBMiner-MULTI" or "srbminer" in container process list

## AMBERSQUID-Specific IOCs for This Technique
- Container image: ubuntu:22.04 (stand-in), real image contains SRBMiner-MULTI (UPX-packed)
- ECS task family: ambersquid-task-definition
- Injected env vars: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (plaintext — critical finding)
- Container command: sleep infinity (benign stand-in) / SRBMiner-MULTI (real attack)
- Mining pools: 2miners, c3pool, nanopool
- Mining wallets: ZEPHYR2vyrpcg2e2sJaA88EM6aGaLCBdiYfiHffrs5b3Fa4p1qpoEPH4UabmhJr5YYF7CxJykLTJmESQWaB9ARNuhb6jvptapVq3v (ZEPHYR), TFrQ7u9spKk8MBgX6Bze3oxPbs3Yh1tAsq (TRX)
