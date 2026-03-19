# Docker Architecture

## Overview

MayaTrail uses Docker Compose to orchestrate a six-service local development stack. All services are defined in a single `docker-compose.yml` at the project root. The stack provides a fully self-contained environment where a developer can run `docker-compose up --build` and have the entire platform running — database, cache, backend API, async workers, frontend UI, and edge proxy.

```
                                   Port 80
                                     |
                              +-----------+
                              |   nginx   |  Edge reverse proxy
                              +-----------+
                               /          \
                         /api/*            /*
                          /                  \
                  +-----------+        +-----------+
                  |  backend  |        |    ui     |
                  |  :8000    |        |  :8080    |
                  +-----------+        +-----------+
                    |       |
              +-----+   +-------+
              |  db  |   | redis |
              | :5432|   | :6379 |
              +------+   +-------+
                            |
                  +-----------+
                  |  worker   |       Celery worker
                  +-----------+       (spawns pulumi containers)
                         |
                  +-----------+
                  |  pulumi   |       Build-only image
                  +-----------+       (ephemeral containers)
```

---

## Service Summary

| Service | Image | Purpose | Port | Long-Running? |
|---|---|---|---|---|
| `db` | postgres:16-alpine | PostgreSQL database | 5432 | Yes |
| `redis` | redis:7-alpine | Celery broker + result backend | 6379 | Yes |
| `backend` | Custom (python:3.12-slim) | Django REST API (Gunicorn) | 8000 | Yes |
| `worker` | Same image as backend | Celery worker (async tasks) | — | Yes |
| `pulumi` | Custom (pulumi/pulumi-python:3.207.0) | Pulumi IaC runner | — | No (build-only) |
| `ui` | Custom (node:20-alpine + nginx:1.27-alpine) | React SPA (Nginx) | 8080 | Yes |
| `nginx` | nginx:1.27-alpine | Edge reverse proxy | 80 | Yes |

---

## docker-compose.yml Walkthrough

### Getting Started

```bash
# 1. Set up environment
cp backend/.env.example backend/.env
# Fill in SECRET_KEY and AWS credentials in backend/.env

# 2. Build the Pulumi image first (it's a tools-profile service)
docker-compose build pulumi

# 3. Start the full stack
docker-compose up --build
```

The application is then available at `http://localhost:80` (or just `http://localhost`).

---

### Service: `db` (PostgreSQL)

```yaml
db:
  image: postgres:16-alpine
  environment:
    POSTGRES_DB: mayatrail
    POSTGRES_USER: mayatrail
    POSTGRES_PASSWORD: mayatrail
  volumes:
    - postgres_data:/var/lib/postgresql/data
  ports:
    - "5432:5432"
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U mayatrail"]
    interval: 5s
    timeout: 5s
    retries: 10
```

**Why PostgreSQL 16 Alpine:**
- Alpine variant for smaller image size
- PostgreSQL 16 for latest features and performance
- Used by both Django (ORM) and the Celery result backend (via Django models)

**Data Persistence:**
Uses a named Docker volume (`postgres_data`) so data survives container restarts. If you `docker-compose down -v`, the data is permanently deleted.

**Design Decision — Simple Credentials:**
Development uses static credentials (`mayatrail/mayatrail`). In production, these would be replaced with AWS RDS credentials from environment variables or secrets manager.

---

### Service: `redis` (Message Broker)

```yaml
redis:
  image: redis:7-alpine
  ports:
    - "6379:6379"
  healthcheck:
    test: ["CMD", "redis-cli", "ping"]
    interval: 5s
    timeout: 5s
    retries: 10
```

Redis serves two roles:
1. **Celery Broker** — receives task messages from the Django API and delivers them to workers
2. **Celery Result Backend** — stores task results (status, return value)

No persistence is configured — Redis data is lost on container restart. This is acceptable because:
- Task results are also stored in PostgreSQL (on the Stack/SimulationRun models)
- Pending tasks are retried by Django when the user polls status

---

### Service: `backend` (Django API)

```yaml
backend:
  build:
    context: ./backend
    dockerfile: Dockerfile
  env_file:
    - ./backend/.env
  environment:
    DJANGO_SETTINGS_MODULE: config.settings.dev
    POSTGRES_HOST: db
    POSTGRES_PORT: "5432"
    POSTGRES_DB: mayatrail
    POSTGRES_USER: mayatrail
    POSTGRES_PASSWORD: mayatrail
    REDIS_URL: redis://redis:6379/0
    SIMULATIONS_PATH: /opt
  ports:
    - "8000:8000"
  volumes:
    - ./simulations:/opt/simulations:ro
  depends_on:
    db:
      condition: service_healthy
    redis:
      condition: service_healthy
  command: >
    sh -c "python manage.py makemigrations users infrastructure simulations logs &&
           python manage.py migrate --noinput &&
           gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 2 --timeout 120"
```

**Key Design Decisions:**

1. **Healthcheck Dependencies:** The backend waits for both `db` and `redis` to be healthy before starting. This prevents Django from crashing on startup because the database isn't ready.

2. **Auto-Migration on Startup:** The command runs `makemigrations` and `migrate` before starting Gunicorn. This is convenient for development — any model changes are automatically applied. In production, migrations should be run explicitly (not auto-applied).

3. **Simulation Volume Mount:** The `simulations/` directory is mounted read-only at `/opt/simulations`. The `SIMULATIONS_PATH=/opt` env var tells the Django simulation tasks where to find the package. This means simulation files are shared between the host and container without needing a rebuild.

4. **Healthcheck:** Uses a Python socket connection test (not curl or wget, which aren't in the slim image).

**Dockerfile (`backend/Dockerfile`):**

```dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies for psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc && rm -rf /var/lib/apt/lists/*

# Install Python deps (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Collect static files (admin CSS)
RUN python manage.py collectstatic --noinput --settings=config.settings.prod || true

EXPOSE 8000

CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "120"]
```

**Layer Ordering:**
1. System dependencies first (rarely change)
2. `requirements.txt` copy + install (cached until deps change)
3. Application source last (changes frequently)

The `collectstatic` command is run at build time with `|| true` to avoid failure if settings aren't fully configured. This collects Django admin CSS into `staticfiles/`.

---

### Service: `worker` (Celery Worker)

```yaml
worker:
  build:
    context: ./backend
    dockerfile: Dockerfile
  env_file:
    - ./backend/.env
  environment:
    # Same as backend, plus:
    PULUMI_IMAGE: step1-pulumi
    STATE_BUCKET: mayatrail-pulumi-state
    SIMULATIONS_PATH: /opt
  volumes:
    # Docker socket for spawning Pulumi containers
    - /var/run/docker.sock:/var/run/docker.sock
    # Simulations package
    - ./simulations:/opt/simulations:ro
  command: celery -A config worker --loglevel=info --concurrency=2
```

**Critical Design Decision — Docker Socket Mount:**
The worker mounts `/var/run/docker.sock` from the host. This allows the Celery worker to use the Docker SDK (Python `docker` library) to spawn sibling containers — specifically, ephemeral Pulumi containers for stack operations.

This is the "Docker-in-Docker" pattern (specifically, "Docker-outside-of-Docker" or DooD). The worker doesn't run Docker inside its own container; instead, it talks to the host's Docker daemon to create new containers at the same level.

**Security Implications:** Mounting the Docker socket gives the worker container root-equivalent access to the host. This is acceptable in a development environment but should be replaced with a more secure mechanism in production (e.g., a dedicated Docker API proxy or Kubernetes Job-based runner).

**Concurrency:** Set to 2 workers. This means at most 2 async tasks can run simultaneously (e.g. two stack deploys, or one deploy + one simulation).

**Environment Variables:**
- `PULUMI_IMAGE=step1-pulumi` — the Docker image to use for ephemeral Pulumi containers
- `STATE_BUCKET=mayatrail-pulumi-state` — S3 bucket for Pulumi state
- `SIMULATIONS_PATH=/opt` — where the simulations package is mounted

---

### Service: `pulumi` (Build-Only Image)

```yaml
pulumi:
  build:
    context: ./src
    dockerfile: Dockerfile
  image: step1-pulumi
  profiles:
    - tools
```

**Design Decision — Build-Only Service with Tools Profile:**
The `pulumi` service is tagged with `profiles: [tools]`, which means it does **not** start when you run `docker-compose up`. It exists solely to build the `step1-pulumi` image that the Celery worker spawns as ephemeral containers.

You must build it explicitly:
```bash
docker-compose build pulumi
```

**Dockerfile (`src/Dockerfile`):**

```dockerfile
FROM pulumi/pulumi-python:3.207.0

WORKDIR /app

# Python dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pulumi project config
COPY Pulumi.yaml .

# Application source
COPY __main__.py .
COPY simulations/ ./simulations/

# Entrypoint
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Default environment
ENV ACTION=preview
ENV STACK=dev-default
ENV STATE_BUCKET=mayatrail-pulumi-state
ENV AWS_REGION=ap-south-1

ENTRYPOINT ["./entrypoint.sh"]
```

**Entrypoint Script (`src/entrypoint.sh`):**

```
1. Read env vars: ACTION, STACK, STATE_BUCKET, AWS_REGION
2. Print configuration banner
3. Login to Pulumi S3 state backend: pulumi login s3://<STATE_BUCKET>
4. Select or create the stack: pulumi stack select <STACK>
5. Set AWS region in stack config: pulumi config set aws:region <AWS_REGION>
6. Execute the action: pulumi <ACTION> --yes --non-interactive
7. If ACTION=up, print stack outputs as JSON
```

Uses `set -euo pipefail` for strict error handling.

**What Gets Excluded (`.dockerignore`):**

| Excluded | Reason |
|---|---|
| `.venv/`, `venv/` | Local virtual environments |
| `__pycache__/`, `*.pyc` | Python bytecode |
| `.git/`, `.gitignore`, `README.md` | Repository metadata |
| `cleanup.py` | Manual utility |
| `runner.py` | CLI orchestration (container uses entrypoint.sh) |

---

### Service: `ui` (React Frontend)

```yaml
ui:
  build:
    context: ./frontend/UI
    dockerfile: Dockerfile
  healthcheck:
    test: ["CMD-SHELL", "kill -0 $$(cat /tmp/nginx.pid 2>/dev/null) 2>/dev/null || exit 1"]
    interval: 10s
    timeout: 3s
    retries: 5
    start_period: 10s
```

**Multi-Stage Dockerfile (`frontend/UI/Dockerfile`):**

```
Stage 1 (node:20-alpine):
  - npm ci (install deps)
  - npm run build (tsc + vite build → dist/)

Stage 2 (nginx:1.27-alpine):
  - Create non-root user (nginxuser:1001)
  - Remove default nginx config
  - Copy custom nginx.conf
  - Prepare writable temp directories
  - Copy dist/ from build stage
  - Switch to non-root user
  - Expose port 8080
  - Start nginx
```

**Design Decision — Non-Root Nginx:**
The production image runs as `nginxuser` (UID 1001). Nginx listens on port 8080 (unprivileged) instead of 80. All temp/log/PID directories are pre-created and owned by the non-root user. This follows the principle of least privilege.

**Nginx Configuration (`frontend/UI/nginx.conf`):**
- Serves the SPA from `/usr/share/nginx/html`
- `try_files $uri $uri/ /index.html` for client-side routing (React Router)
- Security headers: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, Content-Security-Policy
- Static asset caching: CSS/JS = 1h, images/fonts = 7d
- Health endpoint at `/health`
- Blocks hidden files (`.git`, `.env`, etc.)
- Returns 502 JSON for `/api/` when running standalone

---

### Service: `nginx` (Edge Reverse Proxy)

```yaml
nginx:
  image: nginx:1.27-alpine
  ports:
    - "${HTTP_PORT:-80}:80"
  volumes:
    - ./nginx.conf:/etc/nginx/nginx.conf:ro
  depends_on:
    ui:
      condition: service_started
    backend:
      condition: service_healthy
```

**Routing Rules (root `nginx.conf`):**

| Pattern | Upstream | Purpose |
|---|---|---|
| `/api/*` | `http://backend:8000` | Django REST API |
| `/admin/*` | `http://backend:8000` | Django admin panel |
| `/*` (everything else) | `http://ui:8080` | React SPA |

**Design Decision — Variable-Based Upstream Resolution:**
The nginx.conf uses `set $upstream` variables for proxy targets:
```nginx
location /api/ {
    set $backend_upstream http://backend:8000;
    proxy_pass $backend_upstream;
}
```
This forces nginx to re-resolve DNS on every request using Docker's embedded DNS (`127.0.0.11`). Without this pattern, nginx would cache the IP at startup and break when containers restart (getting new IPs).

**Security Headers:**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `server_tokens off` (hides nginx version)

**Proxy Headers:**
All proxied requests forward `Host`, `X-Real-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto` to the upstream services.

**Configurable Port:**
The host port defaults to 80 but can be overridden via the `HTTP_PORT` environment variable.

---

## Container Dependency Graph

```
                   ┌──────────────┐
                   │   nginx:80   │
                   └──────┬───────┘
                     depends_on
              ┌───────────┴───────────┐
              │                       │
     ┌────────┴─────────┐   ┌────────┴──────┐
     │  backend:8000    │   │   ui:8080     │
     │  (service_healthy)│   │  (service_    │
     │                   │   │   started)    │
     └────────┬──────────┘   └──────────────┘
              │ depends_on
       ┌──────┴──────┐
       │             │
  ┌────┴───┐  ┌──────┴──────┐
  │ db:5432│  │ redis:6379  │
  │(healthy)│  │ (healthy)   │
  └────────┘  └──────┬──────┘
                     │ depends_on
              ┌──────┴──────┐
              │   worker    │
              │  (Celery)   │
              └──────┬──────┘
                     │ spawns
              ┌──────┴──────┐
              │   pulumi    │
              │ (ephemeral) │
              └─────────────┘
```

**Startup Order:**
1. `db` and `redis` start first (no dependencies)
2. `backend` starts after `db` and `redis` are healthy
3. `worker` starts after `db` and `redis` are healthy
4. `ui` starts independently (no backend dependency)
5. `nginx` starts after `ui` is started and `backend` is healthy
6. `pulumi` never starts automatically (tools profile)

---

## AWS Credentials

### Local Development

AWS credentials are passed via `backend/.env`:
```
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
```

These flow through:
1. `backend/.env` → loaded by docker-compose `env_file`
2. Available in both `backend` and `worker` containers
3. The worker passes them to ephemeral Pulumi containers via environment variables

### On EC2 (Recommended for Production)

When running on EC2 with an IAM Instance Role:
- No credentials need to be passed
- Both Pulumi and boto3 discover credentials from IMDS
- IMDSv2 hop limit must be 2 for Docker containers:
  ```bash
  aws ec2 modify-instance-metadata-options \
    --instance-id <id> \
    --http-put-response-hop-limit 2 \
    --http-endpoint enabled
  ```

### Credential Precedence

Both Pulumi and boto3 follow the AWS SDK credential chain:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credentials file (`~/.aws/credentials`)
3. EC2 Instance Metadata Service (IMDS)
4. ECS Container Credentials

---

## Pulumi State Management

### S3 Backend

Pulumi state is stored in a shared S3 bucket (`mayatrail-pulumi-state`). The entrypoint script runs `pulumi login s3://<bucket>` on every container start.

**Multi-User Isolation:**
Each team member uses a unique stack name → separate state file → separate AWS resources:

```
Stack: dev-himan10
  → mayatrail-user-dev-himan10
  → mayatrail-role-dev-himan10
  → mayatrail-step1-bucket-dev-himan10

Stack: dev-ayush
  → mayatrail-user-dev-ayush
  → mayatrail-role-dev-ayush
  → mayatrail-step1-bucket-dev-ayush
```

### State Bucket Setup (One-Time)

```bash
aws s3 mb s3://mayatrail-pulumi-state --region ap-south-1
aws s3api put-bucket-versioning \
  --bucket mayatrail-pulumi-state \
  --versioning-configuration Status=Enabled
```

---

## Volume Summary

| Volume | Type | Container(s) | Purpose |
|---|---|---|---|
| `postgres_data` | Named volume | db | PostgreSQL data persistence |
| `./simulations` | Bind mount (ro) | backend, worker | Simulation Python modules |
| `./nginx.conf` | Bind mount (ro) | nginx | Edge proxy configuration |
| `./backend/.env` | env_file | backend, worker | Environment variables |
| `/var/run/docker.sock` | Bind mount | worker | Docker API for spawning Pulumi containers |

---

## Network

All services communicate over Docker Compose's default bridge network. Service names (`db`, `redis`, `backend`, `worker`, `ui`) are resolvable as hostnames within the network.

No custom networks are defined — the default network is sufficient for this architecture. If services needed isolation (e.g. preventing the UI from accessing the database directly), custom networks would be added.

---

## Image Registry

For team distribution, push built images to a container registry:

```bash
# Backend + Worker
docker tag step1-backend <registry>/mayatrail-backend:latest
docker push <registry>/mayatrail-backend:latest

# Frontend
docker tag step1-ui <registry>/mayatrail-ui:latest
docker push <registry>/mayatrail-ui:latest

# Pulumi runner
docker tag step1-pulumi <registry>/mayatrail-pulumi:latest
docker push <registry>/mayatrail-pulumi:latest
```

---

## Key Design Decisions Summary

| Decision | Rationale |
|---|---|
| Docker Compose (not Kubernetes) | Simplicity for local development; K8s would add complexity without benefit at this stage |
| Shared backend image for API + worker | Reduces build time and ensures API and worker always have matching code |
| Docker socket mount for Pulumi | Enables spawning ephemeral containers without Docker-in-Docker overhead |
| Tools profile for Pulumi service | Prevents Pulumi from running perpetually; it's only needed as a build target |
| Healthchecks on all services | Prevents cascading startup failures (Django doesn't crash because Postgres isn't ready) |
| Named volume for Postgres only | Only database state needs persistence; Redis, frontend, and backend are stateless |
| Read-only simulation mount | Prevents the backend/worker from accidentally modifying simulation source files |
| Non-root nginx for UI | Security best practice — limits blast radius if container is compromised |
| Edge proxy pattern | Single entry point for all traffic; clean URL routing without CORS issues |
