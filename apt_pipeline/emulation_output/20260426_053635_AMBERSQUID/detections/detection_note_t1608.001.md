# Detection Note: T1608.001 - Stage Capabilities: Upload Malware
# AMBERSQUID: SRBMiner-MULTI (UPX-packed) staged on external Docker registry

## Execution Plane
Control plane (external) - generates NO CloudTrail events in the victim account.
AMBERSQUID pushes a malicious Docker image to an attacker-controlled or public
container registry (Docker Hub or similar) BEFORE targeting victim AWS accounts.
The staging happens entirely outside the victim's AWS environment. CloudTrail only
captures downstream events when the staged image is pulled by an ECS task or
referenced in a task definition.

## First Observable Event
The earliest victim-account proxy for this technique is:
- `ecs:RegisterTaskDefinition` referencing `ubuntu:22.04` or another public base image
  (CloudTrail visible at T1059.009 / T1610 phases)
- The ambersquid-task-definition created by the victim themselves (before compromise)
  may already contain the public image reference that AMBERSQUID exploits

See: sigma_t1608.001.yml / kql_t1608.001.kql

## Detection Alternatives (in priority order)

### 1. ECS Task Definition Inspection - Public Image Reference
RegisterTaskDefinition CloudTrail events referencing images from public registries
(docker.io, ubuntu, public.ecr.aws) from non-console, non-CDK sessions:

```kql
AWSCloudTrail
| where EventSource == "ecs.amazonaws.com"
| where EventName == "RegisterTaskDefinition"
| where RequestParameters has_any ("\"image\":\"ubuntu", "\"image\":\"docker.io")
| where UserAgent !contains "console.aws.amazon.com"
| extend TaskFamily = tostring(parse_json(RequestParameters).family)
| project TimeGenerated, TaskFamily, UserIdentityArn, SourceIpAddress
```

### 2. AWS Credential Injection Detection (Highest Priority)
AMBERSQUID's staged image works by reading injected AWS credentials from container
environment variables. The RegisterTaskDefinition call that injects these credentials
is the highest-fidelity single event:

```kql
AWSCloudTrail
| where EventSource == "ecs.amazonaws.com"
| where EventName == "RegisterTaskDefinition"
| where RequestParameters has_any ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
```

This is a security misconfiguration indicator independent of AMBERSQUID — any task
definition with plaintext AWS credentials in environment variables should be alerted
unconditionally. Use AWS Secrets Manager or IAM task roles instead.

### 3. Amazon Inspector - Container Image Scanning
Amazon Inspector (with ECR integration) scans images for:
  - UPX-packed ELF binaries (SRBMiner-MULTI is UPX-packed — Inspector detects this)
  - Known malware signatures: SRBMiner, XMRig, NBMiner, T-Rex
  - CVE findings in image layers (ubuntu base layer vulnerabilities)

Limitation: Inspector scans ECR-hosted images. AMBERSQUID uses Docker Hub images
pulled directly by ECS — Inspector does NOT scan at pull time unless ECR pull-through
cache is configured with inspection enabled (ECR pull-through cache + Inspector).

To detect at pull time:
  1. Configure ECR pull-through cache for docker.io
  2. Enable Amazon Inspector on ECR
  3. Any pull of `ubuntu:22.04` or other public images goes through ECR first,
     triggering Inspector scan before the container runs

### 4. VirusTotal / Threat Intel - Image Digest Lookup
Container image digests (SHA256) are available in:
  - ECR PutImage responseElements (if image is pulled into ECR)
  - ECS task metadata endpoint (from within the container at runtime)

Submit image digest to VirusTotal or Malware Bazaar to check for UPX-packed
SRBMiner-MULTI signatures. AMBERSQUID's specific image may be indexed from
prior campaign incident reports.

### 5. GuardDuty - Runtime Monitoring for Container Execution
GuardDuty ECS Runtime Monitoring (requires opt-in):
  - Finding: `Execution:Runtime/NewBinaryExecuted` — detects SRBMiner binary executed
    inside the container at runtime (even from ubuntu base image)
  - Finding: `CryptoCurrency:Runtime/BitcoinTool.B` — detects mining pool connections
  - Requires GuardDuty agent deployment alongside ECS tasks

GuardDuty Runtime Monitoring catches the staged image at execution time, not at
pull time — but it closes the detection gap left by Inspector for Docker Hub images.

### 6. AWS Security Hub Controls
Security Hub provides automated checks relevant to this technique:
  - ECS.1: ECS task definitions should not have elevated privilege
  - ECS.2: ECS services should not have public IP addresses automatically assigned
  - ECS.10: ECS Fargate services should run on the latest platform version

### 7. EDR / CNAPP - Container Runtime Security
Container runtime security tools (Falco, Sysdig, Aqua, Prisma) detect:
  - UPX unpacking behavior (mprotect + write to executable memory)
  - Outbound TCP to known mining pool IP ranges
  - Process name matching SRBMiner-MULTI or srbminer binary signature
  - Anomalous CPU consumption combined with network activity

## AMBERSQUID-Specific IOCs for This Technique
- Malicious image stand-in: `ubuntu:22.04` (real attack uses custom image)
- Real image content:
  - SRBMiner-MULTI (UPX-packed ELF binary)
  - entrypoint.sh (credential reader + script dispatcher)
  - amplify-role.sh, repo.sh, code.sh, jalan.sh, sup0.sh, ecs.sh, ulang.sh,
    note.sh, salah.sh, delete.sh, stoptrigger.sh, scale.sh, restart.sh
  - amplify.yml, index.py, amplify-role.json, sugo.json, ecsTaskExecutionRole.json
- Tool used for packing: UPX (Universal Packer for eXecutables)
- Mining algorithms: ZEPHYR, TRX, RVN, XMR
- Image behavior: reads AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY from env, then
  executes deployment scripts that replicate AMBERSQUID infrastructure across
  Amplify, CodeCommit, CodeBuild, SageMaker, and ECS
