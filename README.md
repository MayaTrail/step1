# MayaTrail/step1 - AWS Security Simulation Lab
A Pulumi-based infrastructure-as-code project that provisions intentionally misconfigured AWS resources for security testing and attack simulation.

### Overview
MayaTrail/step1 sets up a controlled AWS environment to simulate privilege escalation scenarios, including:
* IAM User/Role creation with overly permissive policies
* Role assumption attacks (user can assume role with iam:AttachRolePolicy)
* S3 bucket provisioning for data exfiltration simulations
* Prerequisites
  - Python 3.1x
  - Pulumi CLI with state configured (either local or remote)
  - AWS credentials configured (aws configure or aws login)

### Quick Start
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pulumi up
```
**NOTE:** Currently, I have not included simulations as a part post deploying pulumi infra. Simulations can be run separately.

### Project Structure
```shell
src/
├── __main__.py          # Core infrastructure (IAM, S3)
├── simulations/
│   ├── attach_role_policy.py     # Privilege escalation simulation
│   ├── enumeration.py            # AWS service enumeration
│   ├── s3_initial_access.py      # S3 access simulation
│   ├── s3_kms_encryption.py      # S3 KMS encryption simulation
|   └── eventual_consistency.py   # Eventual Consistency attack simulation 
└── Pulumi.yaml
```

### Simulations
|  Module | Attack Technique |
|:---------:|:---------:|
| simulations/attach_role_policy | Attach AdministratorAccess to role |
| simulations/enumeration  | IAM policy simulator for permission discovery |
| simulations/s3_initial_access | perform a very basic N common attack on found s3 bucket | 
| simulations/s3_kms_encryption | perform KMS Ransomware attack scenario on s3 bucket |
| simulations/eventual_consistency.py | perform eventual consistency attack using compromised user creds |

---

### Docker-Based Backend Deployment

The entire Pulumi & Simulations script setup is packaged as a Docker image so any team member can deploy or destroy infrastructure with a single command, without installing Pulumi or Python locally.

#### Prerequisites
- Docker installed on your machine or EC2 instance.
- AWS credentials available (via EC2 Instance Role or local `~/.aws` config).

#### One-Time Setup: Create the State Bucket

One team member needs to create the shared S3 bucket that stores Pulumi state. This only needs to be done once.    
<b>NOTE:</b> I have already created the pre-requisites for this. So, we can directly jump to "running on EC2" part. <i> Bucket versioning configuration is optional, even we don't have it as of now.</i>

```bash
aws s3 mb s3://mayatrail-pulumi-state --region ap-south-1
aws s3api put-bucket-versioning \
  --bucket mayatrail-pulumi-state \
  --versioning-configuration Status=Enabled
``` 

#### Build the Image

```bash
cd src/
docker build -t mayatrail-emulator .
```

#### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ACTION` | `preview` | Pulumi action: `up`, `destroy`, `preview`, or `refresh` |
| `STACK` | `dev-default` | Your personal stack name (e.g., `dev-himan10`) |
| `STATE_BUCKET` | `mayatrail-pulumi-state` | S3 bucket for Pulumi state |
| `AWS_REGION` | `ap-south-1` | AWS region for resource deployment |

#### Running on EC2 (with Instance Role)

No AWS credentials need to be passed. The container picks them up from the instance metadata service.

```bash
# Preview changes
docker run --rm -e ACTION=preview -e STACK=dev-<your-name> mayatrail-emulator

# Deploy infrastructure
docker run --rm -e ACTION=up -e STACK=dev-<your-name> mayatrail-emulator

# Tear down infrastructure
docker run --rm -e ACTION=destroy -e STACK=dev-<your-name> mayatrail-emulator

# Sync state with actual AWS resources
docker run --rm -e ACTION=refresh -e STACK=dev-<your-name> mayatrail-emulator
```

#### Running Locally

Mount your local AWS credentials into the container:

```bash
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -e ACTION=up \
  -e STACK=dev-<your-name> \
  mayatrail-emulator
```

#### Stack Isolation

Each team member uses their own stack name, which creates an independent set of resources:

```bash
docker run --rm -e ACTION=up -e STACK=dev-himan10 mayatrail-emulator
docker run --rm -e ACTION=up -e STACK=dev-ayush mayatrail-emulator
```

This produces isolated resources per stack (e.g., `mayatrail-user-dev-himan10`, `mayatrail-role-dev-himan10`, `mayatrail-step1-bucket-dev-himan10`).

---

***IMP NOTE:*** *This project creates intentionally vulnerable AWS resources. Use only in isolated test accounts.*  
*Destroy resources after testing:* `pulumi destroy` or `docker run --rm -e ACTION=destroy -e STACK=dev-<your-name> mayatrail-emulator`
