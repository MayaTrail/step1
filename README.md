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
│   ├── attach_role_policy.py  # Privilege escalation simulation
│   ├── enumeration.py         # AWS service enumeration
│   ├── s3_initial_access.py   # S3 access simulation
│   └── s3_kms_encryption.py   # S3 KMS encryption simulation
└── Pulumi.yaml
```

### Simulations
|  Module | Attack Technique |
|:---------:|:---------:|
| simulations/attach_role_policy | Attach AdministratorAccess to role |
| simulations/enumeration  | IAM policy simulator for permission discovery |
| simulations/s3_initial_access | perform a very basic N common attack on found s3 bucket | 
| simulations/s3_kms_encryption | perform KMS Ransomware attack scenario on s3 bucket |

---

***IMP NOTE:*** *This project creates intentionally vulnerable AWS resources. Use only in isolated test accounts.*  
*Destroy resources after testing:* `pulumi destroy`
