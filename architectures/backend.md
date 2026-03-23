# Backend Architecture

## Overview

MayaTrail's backend is a three-layer system:

1. **Django REST API** — The web service layer that exposes HTTP/JSON endpoints for authentication, stack management, simulation execution, and audit logging.
2. **Infrastructure Layer (Pulumi IaC)** — A standalone Pulumi program that provisions intentionally misconfigured AWS resources for attack simulation.
3. **Simulation Layer** — Standalone Python/boto3 modules that execute attack techniques against the provisioned infrastructure.

The Django API sits between the React frontend and the AWS layers, driving Pulumi and simulation modules through Celery async tasks. The Pulumi IaC and simulation scripts are not modified — the Django layer orchestrates them.

---

## Technology Stack

| Component | Technology | Version | Notes |
|---|---|---|---|
| Framework | Django | 5.0.6 | Core web framework |
| REST API | Django REST Framework (DRF) | 3.15.2 | ViewSets, Routers, Serializers |
| Authentication | djangorestframework-simplejwt | 5.3.1 | Stateless JWT auth |
| Task Queue | Celery | 5.4.0 | Async execution of Pulumi + simulations |
| Message Broker | Redis | 5.0.7 | Celery broker and result backend |
| Database | PostgreSQL 16 | psycopg2-binary 2.9.9 | Docker locally, AWS RDS in production |
| CORS | django-cors-headers | 4.4.0 | Allow requests from the React container |
| WSGI Server | Gunicorn | 22.0.0 | 2 workers, 120s timeout |
| Config | python-decouple | 3.8 | Secrets via environment variables |
| Docker SDK | docker (Python) | 7.1.0 | Spawning ephemeral Pulumi containers |
| AWS SDK | boto3 | 1.41.2 | Simulation modules |
| IaC Framework | Pulumi | 3.207.0 | Infrastructure provisioning |
| Language | Python | 3.12 | Backend container uses python:3.12-slim |

---

## Directory Structure

```
backend/
  manage.py                    -- Django management entry point
  requirements.txt             -- Python dependencies (pinned versions)
  Dockerfile                   -- Backend container image (python:3.12-slim)
  .env                         -- Local environment variables (git-ignored)
  .env.example                 -- Template for .env
  openapi.yaml                 -- OpenAPI 3.0.3 specification (818 lines)
  config/
    __init__.py                -- Celery app auto-load on Django startup
    celery.py                  -- Celery app instance, autodiscovers tasks
    urls.py                    -- Root URL conf, mounts each app under /api/
    wsgi.py                    -- WSGI entry point for Gunicorn
    asgi.py                    -- ASGI entry point (future WebSocket support)
    settings/
      __init__.py
      base.py                  -- Shared settings (apps, middleware, DRF, JWT, Celery)
      dev.py                   -- DEBUG=True, local Postgres, CORS allow all
      prod.py                  -- DEBUG=False, RDS, restricted CORS + ALLOWED_HOSTS
  apps/
    __init__.py
    users/                     -- Auth: registration, login, profile
    infrastructure/            -- Stack CRUD + deploy/destroy/refresh/preview
    simulations/               -- Simulation run trigger + status + output
    logs/                      -- Read-only audit log
  tests/                       -- (placeholder, no test suite yet)

simulations/                   -- Top-level simulation package (outside backend/)
  __init__.py                  -- Empty init
  registry.py                  -- Auto-discovers simulation modules
  logger.py                    -- Shared coloured logging via colorama
  attach_role_policy.py        -- Privilege escalation simulation
  enumeration.py               -- IAM Policy Simulator enumeration
  s3_initial_access.py         -- S3 data exfiltration
  s3_kms_encryption.py         -- KMS ransomware simulation
  eventual_consistency.py      -- IAM eventual consistency attack

src/                           -- Original Pulumi IaC project
  __main__.py                  -- Pulumi program (MayaTrailInfra class)
  Pulumi.yaml                  -- Pulumi project configuration
  requirements.txt             -- Pulumi Python dependencies
  runner.py                    -- CLI tool for local deploy/emulate/destroy
  cleanup.py                   -- IAM login profile cleanup utility
  Dockerfile                   -- Pulumi container image
  entrypoint.sh                -- Pulumi container entrypoint script
  .dockerignore                -- Excludes .venv, runner.py, cleanup.py
```

---

## Django Apps — Detailed Breakdown

### 1. users

Handles registration, login (JWT), and authenticated user identity.

**Model: `User`** (extends `AbstractUser`)

| Field | Type | Notes |
|---|---|---|
| `id` | AutoField (int) | Django default PK |
| `username` | CharField(150) | Unique, required |
| `email` | EmailField | **unique=True** (overridden from AbstractUser) |
| `password` | CharField | Stored as PBKDF2 hash |
| `first_name` | CharField(150) | Optional |
| `last_name` | CharField(150) | Optional |
| `is_staff` | BooleanField | Admin access |
| `is_active` | BooleanField | Login gate |
| `date_joined` | DateTimeField | Auto-set |

Registered as the custom user model via `AUTH_USER_MODEL = "users.User"` in `base.py`.

**Design Decision — Custom User From Day One:**
Using `AbstractUser` from the start avoids the painful `auth.User` swap migration later. Even though no extra fields are needed now, this is the Django-recommended pattern for any project that expects to grow.

**Endpoints:**

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/register/` | None | Create account (username, email, password, invite_code) |
| POST | `/api/auth/login/` | None | Return JWT access + refresh tokens |
| POST | `/api/auth/refresh/` | None | Refresh an expired access token |
| GET | `/api/auth/me/` | JWT | Return current user's profile |

**Registration Gate:**
The `RegisterSerializer` includes an `invite_code` field. When `REGISTRATION_INVITE_CODE` is set in the environment, every registration request must include the matching code. When empty, open registration is allowed. This provides a simple access-control mechanism without building a full invitation system.

**Serializers:**
- `UserSerializer` — read-only, exposes safe subset of fields, never includes password.
- `RegisterSerializer` — write-only password field with `min_length=8`, email normalisation to lowercase, duplicate email rejection, invite code validation. Uses `User.objects.create_user()` (not `.create()`) to ensure password hashing.

**Login/Refresh:**
Uses SimpleJWT's built-in `TokenObtainPairView` and `TokenRefreshView` directly — no custom login logic. Token lifetimes: access = 1 hour, refresh = 7 days.

---

### 2. infrastructure

Manages Pulumi stack lifecycle. Each `Stack` record tracks a named Pulumi stack and its deployment state.

**Model: `Stack`**

| Field | Type | Description |
|---|---|---|
| `id` | UUIDField | Primary key (auto-generated) |
| `name` | CharField(128) | Unique stack name, e.g. `dev-himan10` |
| `region` | CharField(32) | AWS region, default `us-east-1` |
| `status` | CharField(16) | `pending`, `deploying`, `ready`, `destroying`, `refreshing`, `failed` |
| `outputs` | JSONField | Pulumi stack outputs after successful deploy |
| `owner` | ForeignKey(User) | User who created the stack |
| `created_at` | DateTimeField | Auto timestamp |
| `updated_at` | DateTimeField | Auto timestamp |

**Endpoints:**

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/stacks/` | JWT | List stacks owned by current user |
| POST | `/api/stacks/` | JWT | Create a new stack record |
| GET | `/api/stacks/{id}/` | JWT | Retrieve a single stack + outputs |
| DELETE | `/api/stacks/{id}/` | JWT | Delete the stack DB record |
| POST | `/api/stacks/{id}/deploy/` | JWT | Enqueue `pulumi up` via Celery |
| POST | `/api/stacks/{id}/destroy/` | JWT | Enqueue `pulumi destroy` via Celery |
| POST | `/api/stacks/{id}/refresh/` | JWT | Enqueue `pulumi refresh` via Celery |
| POST | `/api/stacks/{id}/preview/` | JWT | Enqueue `pulumi preview` via Celery |

**Design Decision — 409 Conflict Guard:**
All action endpoints check if the stack is in a "busy" status (`deploying`, `destroying`, `refreshing`) before enqueuing a new task. This prevents race conditions where two Pulumi operations could run simultaneously against the same stack, which would corrupt the state file.

**Celery Tasks (infrastructure/tasks.py):**

Each task spawns an **ephemeral Docker container** from the pre-built `step1-pulumi` image. This is a critical architectural choice:

1. **Isolation** — Each Pulumi operation runs in its own container with its own process space. A crash or hang in one operation does not affect the Django process.
2. **Dependency isolation** — The Pulumi Python SDK and its dependencies are only in the Pulumi image, not in the Django container.
3. **Security** — AWS credentials are passed as environment variables to the ephemeral container, not stored on disk.

```
Django View → Celery Task → Docker SDK → Ephemeral Pulumi Container → AWS
                                   ↑
                           Uses docker.from_env()
                           Mount: /var/run/docker.sock
```

The worker container mounts `/var/run/docker.sock` so it can spawn sibling containers via the Docker SDK. The Pulumi image name defaults to `step1-pulumi` (matching the `docker-compose.yml` service name).

**Output Parsing:**
After a successful `pulumi up`, the `_parse_stack_outputs()` function looks for a `"Stack outputs:"` marker in stdout and attempts to parse the JSON block that follows. Falls back to storing the raw output string.

**Error Handling:**
- `docker.errors.ContainerError` — container exited non-zero → stack marked FAILED
- `docker.errors.ImageNotFound` — Pulumi image not built → returns error message
- `docker.errors.APIError` — Docker daemon issues → returns error message
- All tasks use `bind=True` with `max_retries=0` to re-raise exceptions after marking the stack as FAILED

---

### 3. simulations

Triggers boto3 attack modules and tracks each run's status and output.

**Model: `SimulationRun`**

| Field | Type | Description |
|---|---|---|
| `id` | UUIDField | Primary key |
| `stack` | ForeignKey(Stack) | Target AWS environment |
| `module` | CharField(128) | Module name (e.g. `s3_initial_access`) |
| `status` | CharField(16) | `pending`, `running`, `completed`, `failed` |
| `stdout` | TextField | Captured stdout from the simulation |
| `stderr` | TextField | Captured stderr (errors, tracebacks) |
| `triggered_by` | ForeignKey(User) | User who triggered the run |
| `started_at` | DateTimeField | Task start time |
| `completed_at` | DateTimeField | Task finish time |
| `created_at` | DateTimeField | Auto timestamp |

**Dynamic Module Discovery:**
The `SimulationRun` model has a class-level `get_modules()` method that calls `simulations.registry.discover()`. This scans `simulations/*.py`, imports each module, and looks for a `MANIFEST` dict and a `run()` function. Modules missing either are silently skipped. The result is cached on the class to avoid re-importing on every request.

The `SIMULATIONS_PATH` environment variable controls where the simulations package is found. In docker-compose, the `simulations/` directory is mounted at `/opt/simulations` and `SIMULATIONS_PATH=/opt`.

**Design Decision — Plug-and-Play Simulations:**
Previously, the module catalogue was hardcoded. Now, adding a new simulation is as simple as creating a `.py` file in `simulations/` with a `MANIFEST` dict and a `run()` function. No backend code changes needed. IDs are assigned deterministically by alphabetical order of the module name.

**Endpoints:**

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/simulations/` | JWT | List all runs by the authenticated user |
| GET | `/api/simulations/{id}/` | JWT | Retrieve run status + output (for polling) |
| GET | `/api/simulations/modules/` | JWT | List all available simulation modules |
| POST | `/api/simulations/run/` | JWT | Trigger a new simulation run |

**Trigger Flow:**
```
POST /api/simulations/run/  { "stack_id": "<uuid>", "module_id": 3 }
    |
    v
1. Validate input (TriggerSimulationSerializer)
2. Resolve module_id → module name via get_module_by_id()
3. Verify stack belongs to user and is in READY state
4. Create SimulationRun record (status=pending)
5. Enqueue run_simulation.delay(run_id)
6. Return 201 with run data + Celery task_id
```

**Celery Task (simulations/tasks.py):**

Unlike infrastructure tasks which spawn Docker containers, simulation tasks run **in-process** inside the Celery worker. The task:

1. Sets the run status to RUNNING
2. Adds the simulations path to `sys.path`
3. Uses `importlib.import_module()` to dynamically load the module
4. Wraps execution in `redirect_stdout()` / `redirect_stderr()` to capture all output
5. Calls `mod.run()` if the module exposes a `run()` entry point
6. Stores stdout/stderr on the SimulationRun record

**Design Decision — In-Process vs Container:**
Simulations run in-process (not in separate containers) because they are lightweight Python/boto3 scripts that don't need Pulumi's complex environment. This avoids the overhead of spinning up a container for each simulation and makes stdout/stderr capture trivial.

---

### 4. logs

Read-only audit log. Each significant event writes a `LogEntry`.

**Model: `LogEntry`**

| Field | Type | Description |
|---|---|---|
| `id` | UUIDField | Primary key |
| `level` | CharField(16) | `info`, `warning`, `error` |
| `event` | CharField(64) | Machine-readable: `stack.deployed`, `simulation.started`, etc. |
| `message` | TextField | Human-readable description |
| `actor` | ForeignKey(User) | Nullable — user who caused the event |
| `stack` | ForeignKey(Stack) | Nullable — related stack |
| `run` | ForeignKey(SimulationRun) | Nullable — related simulation run |
| `timestamp` | DateTimeField | Auto timestamp |

**Design Decision — Nullable Foreign Keys:**
All FKs use `on_delete=models.SET_NULL` with `null=True`. This ensures log entries survive the deletion of their referenced objects (stacks, runs, users). The audit trail is never broken.

**Endpoints:**

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/logs/` | JWT | List log entries relevant to the user |
| GET | `/api/logs/{id}/` | JWT | Retrieve a single log entry |

**QuerySet Filtering:**
The `get_queryset()` method uses a complex `Q` filter to return entries where:
- The actor is the current user, OR
- The entry references a stack owned by the current user, OR
- The entry references a simulation run triggered by the current user

This means users only see audit events related to their own activity — multi-tenant isolation by design.

---

## Authentication Flow

```
Client                          Django                        SimpleJWT
  |                                |                               |
  |-- POST /api/auth/login ------> |                               |
  |   { username, password }       |-- validate credentials -----> |
  |                                |<-- access_token, refresh_token|
  |<-- 200 { access, refresh } ----|                               |
  |                                |                               |
  |-- GET /api/stacks/ ----------> |                               |
  |   Authorization: Bearer <jwt>  |-- verify token -------------> |
  |                                |<-- user identity -------------|
  |<-- 200 [ ...stacks ] ---------|                               |
```

**Global Defaults (base.py):**
- `DEFAULT_AUTHENTICATION_CLASSES` = JWTAuthentication (all requests checked)
- `DEFAULT_PERMISSION_CLASSES` = IsAuthenticated (all endpoints require auth)
- `DEFAULT_RENDERER_CLASSES` = JSONRenderer only (no HTML browsable API)
- Public endpoints (register, login, refresh) override with `AllowAny`

**Token Lifetimes:**
- Access token: 1 hour
- Refresh token: 7 days

**Frontend Token Handling:**
The React frontend stores the JWT in `localStorage` under the key `mayatrail_token`. An Axios interceptor attaches `Authorization: Bearer <token>` to every request. A 401 response interceptor clears the token and redirects to `/login`.

---

## Async Task Architecture

```
Django API                    Redis               Celery Worker           Docker / AWS
    |                            |                      |                   |
    |-- enqueue deploy_stack --> |                      |                   |
    |   Stack.status = deploying |-- pick up task ----> |                   |
    |                            |                      |-- spawn Pulumi    |
    |                            |                      |   container ----> |
    |                            |                      |<-- exit + output  |
    |                            |                      |                   |
    |                            | Stack.status = ready |                   |
    |                            | Stack.outputs = {...}|                   |
```

The same pattern applies to `destroy_stack`, `refresh_stack`, `preview_stack`, and `run_simulation`.

**Celery Configuration (base.py):**
- Broker: Redis (from `REDIS_URL` env var)
- Result backend: Redis (same URL)
- Serialization: JSON only
- Timezone: UTC
- Task autodiscovery: enabled for all installed apps

**Celery App (config/celery.py):**
- Named `"mayatrail"`
- Reads config from Django settings using `CELERY_` namespace prefix
- Uses `autodiscover_tasks()` to find `tasks.py` in each installed app

**Worker Command:**
```bash
celery -A config worker --loglevel=info --concurrency=2
```

---

## Settings Architecture

```
config/settings/
  base.py     -- Shared: INSTALLED_APPS, MIDDLEWARE, DRF, JWT, Celery, AUTH_USER_MODEL
  dev.py      -- DEBUG=True, local Postgres (via env), CORS_ALLOW_ALL_ORIGINS=True
  prod.py     -- DEBUG=False, RDS, ALLOWED_HOSTS from env, restricted CORS, security headers
```

The active settings module is selected via the `DJANGO_SETTINGS_MODULE` environment variable (default: `config.settings.dev`).

**Environment Variables:**

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | (required) | Django secret key for token signing |
| `DJANGO_SETTINGS_MODULE` | `config.settings.dev` | Active settings file |
| `POSTGRES_DB` | `mayatrail` | Database name |
| `POSTGRES_USER` | `mayatrail` | Database user |
| `POSTGRES_PASSWORD` | `mayatrail` | Database password |
| `POSTGRES_HOST` | `db` | Docker service name / hostname |
| `POSTGRES_PORT` | `5432` | Database port |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `AWS_ACCESS_KEY_ID` | (empty) | AWS credentials for Celery workers |
| `AWS_SECRET_ACCESS_KEY` | (empty) | AWS credentials for Celery workers |
| `AWS_DEFAULT_REGION` | `us-east-1` | Default AWS region |
| `PULUMI_IMAGE` | `step1-pulumi` | Docker image for Pulumi runner |
| `STATE_BUCKET` | `mayatrail-pulumi-state` | S3 bucket for Pulumi state |
| `SIMULATIONS_PATH` | (project root) | Directory containing the `simulations/` package |
| `REGISTRATION_INVITE_CODE` | (empty) | When set, required for registration |

---

## Infrastructure Layer (Pulumi IaC)

### Entry Point: `src/__main__.py`

The Pulumi program is built around the `MayaTrailInfra` class. Pulumi executes this file when running `pulumi up`.

### MayaTrailInfra Class

```
MayaTrailInfra
  __init__()           -- Sets resource names (suffixed with stack name), account ID, region
  create_dummies()     -- Creates IAM User or IAM Role based on type parameter
  attach_policies()    -- Creates IAM policy from statements and attaches to user or role
  create_s3_bucket()   -- Creates S3 bucket and uploads a sample object
  _create_user_access_key()  -- Creates access key pair for the IAM user
```

### AWS Resources Created

| Pulumi Resource | AWS Resource | Naming Pattern |
|---|---|---|
| `aws.iam.User` | IAM User | `mayatrail-user-{stack_name}` |
| `aws.iam.AccessKey` | IAM Access Key | `mayatrail-dummy-access-key` |
| `aws.iam.Role` | IAM Role | `mayatrail-role-{stack_name}` |
| `aws.s3.Bucket` | S3 Bucket | `mayatrail-step1-bucket-{stack_name}` |
| `aws.s3.BucketObjectv2` | S3 Object | `mayatrail-s3-bucket-object` |
| `LoginProfileCleanup` | Dynamic Resource | Deletes IAM login profile on `pulumi destroy` |

The `{stack_name}` suffix comes from `pulumi.get_stack()`, ensuring multiple team members can deploy isolated environments on the same AWS account.

### Resource Dependencies

```
IAM User
  |-- AccessKey (depends_on: User)
  |-- LoginProfileCleanup (depends_on: User)

IAM Role
  |-- Trust policy references the IAM User ARN

S3 Bucket
  |-- BucketObjectv2 (references bucket ID)
```

### LoginProfileCleanup (Dynamic Resource)

A custom Pulumi dynamic resource that handles a specific edge case: if a simulation creates an IAM login profile for the user (via the AWS Console or boto3), `pulumi destroy` will fail because the login profile is not managed by Pulumi. The `LoginProfileCleanup` resource calls `iam.delete_login_profile()` during the destroy phase, catching `NoSuchEntity` errors gracefully.

### Stack Outputs

| Output | Value |
|---|---|
| `username` | The IAM access key ID |
| `role_arn` | The IAM role ARN |
| `object_url` | The S3 object URL |

### Pulumi State

State is stored in a shared S3 bucket (`mayatrail-pulumi-state`). The entrypoint script runs `pulumi login s3://<bucket>` on every container start. Each team member uses their own stack name, so state files do not collide.

---

## Simulation Layer

### Design Pattern

Each simulation is an independent Python module with:
- A `MANIFEST` dict containing `name` and `description`
- A `run()` function as the entry point

The `simulations/registry.py` module auto-discovers all valid simulation modules by scanning `simulations/*.py`, importing each, and checking for the `MANIFEST` + `run()` contract. Files in the `_SKIP` set (`__init__`, `logger`, `registry`) are excluded.

### Simulation Modules

| Module | Attack Technique | MITRE Mapping |
|---|---|---|
| `attach_role_policy.py` | Assume role via STS, attach AdministratorAccess policy | Privilege Escalation |
| `enumeration.py` | IAM Policy Simulator-based permission discovery | Discovery |
| `s3_initial_access.py` | List buckets, read/delete objects, upload ransom note | Initial Access / Exfiltration |
| `s3_kms_encryption.py` | KMS ransomware: re-encrypt S3 objects, delete key material | Impact |
| `eventual_consistency.py` | Exploit IAM eventual consistency propagation window | Execution |

### Adding a New Simulation

1. Create a new `.py` file in `simulations/` (e.g. `my_simulation.py`)
2. Define `MANIFEST = {"name": "my_simulation", "description": "What it does"}`
3. Define `def run(): ...` as the entry point
4. No code changes needed in the backend — it will be auto-discovered

### Shared Logger (`logger.py`)

Provides coloured console logging via `colorama`. All simulation modules call `get_logger(name)` to get a configured logger instance.

### Runner (`runner.py`) — CLI Only

```bash
python runner.py --deploy              # Deploy infrastructure
python runner.py --emulate             # Interactive simulation menu
python runner.py --destroy             # Tear down infrastructure
python runner.py --deploy --emulate    # Deploy then run simulations
python runner.py --stack dev-himan10   # Specify Pulumi stack name
```

The runner is a standalone CLI tool for local development. It is excluded from the Docker images. In production, the Django API + Celery worker replaces the runner.

---

## URL Routing

```
config/urls.py (Root)
  |-- admin/                   -> Django admin
  |-- api/auth/                -> apps.users.urls
  |   |-- register/            POST   -> RegisterView
  |   |-- login/               POST   -> TokenObtainPairView
  |   |-- refresh/             POST   -> TokenRefreshView
  |   |-- me/                  GET    -> MeView
  |-- api/stacks/              -> apps.infrastructure.urls (DefaultRouter)
  |   |-- /                    GET    -> list
  |   |-- /                    POST   -> create
  |   |-- {id}/                GET    -> retrieve
  |   |-- {id}/                DELETE -> destroy
  |   |-- {id}/deploy/         POST   -> deploy (custom action)
  |   |-- {id}/destroy/        POST   -> destroy_stack (custom action)
  |   |-- {id}/refresh/        POST   -> refresh (custom action)
  |   |-- {id}/preview/        POST   -> preview (custom action)
  |-- api/simulations/         -> apps.simulations.urls (DefaultRouter)
  |   |-- /                    GET    -> list
  |   |-- {id}/                GET    -> retrieve
  |   |-- modules/             GET    -> modules (custom action)
  |   |-- run/                 POST   -> run (custom action)
  |-- api/logs/                -> apps.logs.urls (DefaultRouter)
  |   |-- /                    GET    -> list
  |   |-- {id}/                GET    -> retrieve
```

---

## OpenAPI Specification

A comprehensive `openapi.yaml` (818 lines, OpenAPI 3.0.3) is maintained at `backend/openapi.yaml`. It documents all endpoints, request/response schemas, auth requirements, and example payloads. This can be imported into Swagger UI, Postman, or used for client code generation.

---

## Integration with Frontend

The React frontend communicates with the backend exclusively through the `/api/` prefix. In development:
- Vite's dev server proxies `/api` requests to `http://localhost:8000`
- In docker-compose, the edge Nginx proxy routes `/api/` to the `backend:8000` service

The frontend stores JWTs in `localStorage`, attaches them via Axios interceptors, and polls simulation/stack status endpoints for real-time updates.

---

## Integration with Docker

- The backend runs as the `backend` service in docker-compose, exposed on port 8000.
- The Celery worker runs as the `worker` service using the same Docker image but with a different command (`celery -A config worker`).
- The worker mounts `/var/run/docker.sock` to spawn ephemeral Pulumi containers.
- The `simulations/` directory is mounted at `/opt/simulations:ro` into both the backend and worker containers.
- Database migrations run automatically on container startup via the backend command.

---

## Key Conventions

- All models use UUID primary keys (`models.UUIDField(default=uuid.uuid4)`) except `User` (Django's default int PK).
- Resource naming in Pulumi follows `mayatrail-*-{stack_name}` pattern.
- Simulation tasks import modules in-process; infrastructure tasks spawn Docker containers.
- No test suite exists yet — validation is manual.
- All Pulumi commands must run from the `src/` directory where `Pulumi.yaml` lives.
- `Pulumi.Output` values are async — use `.apply()` or `pulumi.Output.all()` to unwrap.
- The `simulations/__init__.py` is empty — simulation modules are not imported by Pulumi.
- `DJANGO_SETTINGS_MODULE` controls which settings file is active (dev vs prod).
