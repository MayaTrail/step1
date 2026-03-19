# MayaTrail/step1 - AWS Security Simulation Platform
A full-stack web application for provisioning intentionally misconfigured AWS resources (via Pulumi IaC), executing attack simulations (via boto3), and viewing results through a dashboard.

### Overview
MayaTrail/step1 sets up a controlled AWS environment to simulate privilege escalation scenarios, including:
* IAM User/Role creation with overly permissive policies
* Role assumption attacks (user can assume role with iam:AttachRolePolicy)
* S3 bucket provisioning for data exfiltration simulations
* IAM eventual consistency exploitation
* KMS ransomware simulation

The platform consists of a **Django REST API** backend, a **React + TypeScript** frontend dashboard, and **Docker Compose** orchestration that ties everything together.

### Prerequisites
- Docker and Docker Compose
- AWS credentials (via environment variables or EC2 Instance Role)

For local development without Docker:
- Python 3.12+
- Node.js 20+
- Pulumi CLI (for standalone IaC operations)

### Quick Start (Docker Compose)
```bash
# 1. Configure environment
cp backend/.env.example backend/.env
# Fill in SECRET_KEY and AWS credentials in backend/.env

# 2. Build the Pulumi image (one-time)
docker-compose build pulumi

# 3. Start the full stack
docker-compose up --build
```
The application is available at `http://localhost`.

### Quick Start (CLI / Standalone Pulumi)
```bash
cd src && python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python runner.py --deploy --emulate    # deploy infra + run simulations
python runner.py --destroy             # tear down
```

### Architecture Documentation
For detailed technical documentation, see the `architectures/` directory:
- [Backend Architecture](architectures/backend.md) — Django REST API, Celery async tasks, Pulumi IaC, simulation plugin system
- [Frontend Architecture](architectures/frontend.md) — React + TypeScript SPA, state management, Tailwind design system
- [Docker Architecture](architectures/docker.md) — Docker Compose services, networking, credential flow

### Project Structure
```shell
step1/
├── backend/                    # Django REST API
│   ├── apps/
│   │   ├── users/              # Auth: registration, login (JWT), profile
│   │   ├── infrastructure/     # Stack CRUD + deploy/destroy/refresh/preview
│   │   ├── simulations/        # Simulation run trigger + status + output
│   │   └── logs/               # Read-only audit log
│   ├── config/                 # Django settings (base/dev/prod), Celery, URLs
│   ├── Dockerfile              # Backend container image
│   └── requirements.txt
├── frontend/UI/                # React + TypeScript SPA
│   ├── src/
│   │   ├── components/         # Page and UI components
│   │   ├── context/            # Auth, Theme, Platform contexts
│   │   ├── services/           # API service layer (Axios)
│   │   └── types/              # TypeScript type definitions
│   ├── Dockerfile              # Multi-stage: Node build -> Nginx
│   └── nginx.conf              # Hardened SPA serving config
├── simulations/                # Standalone boto3 attack modules
│   ├── attach_role_policy.py   # Privilege escalation simulation
│   ├── enumeration.py          # AWS service enumeration
│   ├── s3_initial_access.py    # S3 access simulation
│   ├── s3_kms_encryption.py    # S3 KMS encryption simulation
│   ├── eventual_consistency.py # Eventual consistency attack
│   └── registry.py             # Auto-discovers simulation modules
├── src/                        # Pulumi IaC project
│   ├── __main__.py             # Core infrastructure (IAM, S3)
│   ├── Dockerfile              # Pulumi container image
│   ├── entrypoint.sh           # Container entrypoint
│   └── Pulumi.yaml
├── architectures/              # Technical documentation
├── docker-compose.yml          # Full stack orchestration (7 services)
└── nginx.conf                  # Edge reverse proxy config
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

### Docker Compose Stack

The full platform runs as a Docker Compose stack with 7 services:

| Service | Purpose |
|---|---|
| `db` | PostgreSQL 16 database |
| `redis` | Celery message broker + result backend |
| `backend` | Django REST API (Gunicorn) |
| `worker` | Celery worker (spawns ephemeral Pulumi containers) |
| `pulumi` | Build-only Pulumi IaC image |
| `ui` | React SPA (Nginx, non-root) |
| `nginx` | Edge reverse proxy (routes `/api/` to backend, `/*` to UI) |

See [Docker Architecture](architectures/docker.md) for full details.

---

### Standalone Pulumi Container

The Pulumi IaC setup is also available as a standalone Docker image for direct infrastructure operations without the full stack:

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

---

### Contributing

For a comprehensive understanding of the codebase, start with the architecture documentation:
1. [Backend Architecture](architectures/backend.md) — Django apps, Celery tasks, Pulumi IaC, simulation plugin system
2. [Frontend Architecture](architectures/frontend.md) — React components, state management, API integration
3. [Docker Architecture](architectures/docker.md) — Service topology, credential flow, networking

The `CLAUDE.md` file at the project root provides quick-reference commands and coding conventions.
