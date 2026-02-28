# Django Backend Architecture

## Overview

This document describes the proposed Django REST API backend for MayaTrail. The backend
sits between the React frontend and the existing AWS simulation layer, exposing a clean
HTTP/JSON interface for managing Pulumi stacks, triggering attack simulations, and
retrieving results.

The existing Pulumi IaC (`src/__main__.py`) and boto3 simulation modules
(`src/simulations/`) are not modified — the Django layer drives them as subprocesses
via Celery workers.

---

## Technology Stack

| Component         | Technology                        | Notes                                      |
|-------------------|-----------------------------------|--------------------------------------------|
| Framework         | Django 5.x                        | Core web framework                         |
| REST API          | Django REST Framework (DRF)       | ViewSets, Routers, Serializers             |
| Authentication    | djangorestframework-simplejwt     | Stateless JWT — fits React + Django split  |
| Task Queue        | Celery                            | Async execution of Pulumi + simulations    |
| Message Broker    | Redis                             | Celery broker and result backend           |
| Database          | PostgreSQL                        | AWS RDS in production, Docker locally      |
| CORS              | django-cors-headers               | Allow requests from the React container    |
| Language          | Python 3.x                        | Matches existing src/ venv                 |

---

## Directory Structure

```
backend/
  manage.py                    -- Django management entry point
  requirements.txt             -- Python dependencies
  Dockerfile                   -- Backend container image
  config/
    __init__.py
    settings/
      base.py                  -- Shared settings (installed apps, middleware, DRF config)
      dev.py                   -- Development overrides (DEBUG=True, SQLite fallback)
      prod.py                  -- Production overrides (RDS, allowed hosts, logging)
    urls.py                    -- Root URL conf, mounts each app's router
    wsgi.py                    -- WSGI entry point
    asgi.py                    -- ASGI entry point (optional, for future WebSocket support)
  apps/
    users/
      models.py                -- Extends Django's AbstractUser (no extra fields required initially)
      serializers.py           -- UserSerializer, LoginSerializer
      views.py                 -- RegisterView, LoginView, MeView (JWT-protected)
      urls.py                  -- /api/auth/* routes
    infrastructure/
      models.py                -- Stack model
      serializers.py           -- StackSerializer
      views.py                 -- StackViewSet (CRUD + deploy/destroy actions)
      urls.py                  -- /api/stacks/* routes
      tasks.py                 -- Celery tasks: deploy_stack, destroy_stack
    simulations/
      models.py                -- SimulationRun model
      serializers.py           -- SimulationRunSerializer
      views.py                 -- SimulationRunViewSet (trigger + status + results)
      urls.py                  -- /api/simulations/* routes
      tasks.py                 -- Celery tasks: run_simulation
    logs/
      models.py                -- LogEntry model
      serializers.py           -- LogEntrySerializer
      views.py                 -- LogEntryViewSet (read-only)
      urls.py                  -- /api/logs/* routes
```

---

## Django Apps

### users

Handles registration, login, and authenticated user identity.

**Model:** Extends Django's built-in `AbstractUser`. No extra fields required in v1.

**Endpoints:**

| Method | Path                  | Auth     | Description                  |
|--------|-----------------------|----------|------------------------------|
| POST   | `/api/auth/register`  | None     | Create a new user account    |
| POST   | `/api/auth/login`     | None     | Return JWT access + refresh  |
| POST   | `/api/auth/refresh`   | None     | Refresh an access token      |
| GET    | `/api/auth/me`        | JWT      | Return current user profile  |

---

### infrastructure

Manages Pulumi stack lifecycle. Each `Stack` record tracks a named Pulumi stack and its
current deployment state.

**Model: `Stack`**

| Field        | Type         | Description                                      |
|--------------|--------------|--------------------------------------------------|
| `id`         | UUID         | Primary key                                      |
| `name`       | CharField    | Stack name, e.g. `dev-himan10`                   |
| `status`     | CharField    | `pending`, `deploying`, `ready`, `destroying`, `error` |
| `region`     | CharField    | AWS region, default `ap-south-1`                 |
| `outputs`    | JSONField    | Pulumi stack outputs (username, role_arn, etc.)  |
| `owner`      | ForeignKey   | User who created the stack                       |
| `created_at` | DateTimeField| Auto timestamp                                   |
| `updated_at` | DateTimeField| Auto timestamp                                   |

**Endpoints:**

| Method | Path                       | Auth | Description                          |
|--------|----------------------------|------|--------------------------------------|
| GET    | `/api/stacks`              | JWT  | List stacks owned by current user    |
| POST   | `/api/stacks`              | JWT  | Create a stack record + trigger deploy |
| GET    | `/api/stacks/{id}`         | JWT  | Retrieve a single stack + outputs    |
| DELETE | `/api/stacks/{id}`         | JWT  | Trigger `pulumi destroy` + delete record |
| POST   | `/api/stacks/{id}/deploy`  | JWT  | Re-deploy an existing stack          |

**Celery Tasks (`tasks.py`):**

```python
@shared_task
def deploy_stack(stack_id: str) -> None:
    """
    Run `pulumi up --yes` for the given stack inside src/.
    Updates Stack.status and Stack.outputs on completion.
    """

@shared_task
def destroy_stack(stack_id: str) -> None:
    """
    Run `pulumi destroy --yes` for the given stack inside src/.
    Updates Stack.status on completion.
    """
```

---

### simulations

Triggers boto3 attack modules and tracks each run's status and output.

**Model: `SimulationRun`**

| Field        | Type          | Description                                              |
|--------------|---------------|----------------------------------------------------------|
| `id`         | UUID          | Primary key                                              |
| `stack`      | ForeignKey    | The Stack this run targets                               |
| `module`     | CharField     | Module name: `s3_initial_access`, `enumeration`, etc.    |
| `status`     | CharField     | `pending`, `running`, `completed`, `failed`              |
| `stdout`     | TextField     | Captured stdout from the simulation module               |
| `stderr`     | TextField     | Captured stderr (errors, tracebacks)                     |
| `started_at` | DateTimeField | Task start time                                          |
| `finished_at`| DateTimeField | Task finish time (null while running)                    |
| `triggered_by`| ForeignKey   | User who triggered the run                               |

**Available Modules (maps to `src/simulations/`):**

| Module Name           | Description                                               |
|-----------------------|-----------------------------------------------------------|
| `enumeration`         | IAM Policy Simulator — discover permitted actions         |
| `attach_role_policy`  | Assume role via STS, attach AdministratorAccess           |
| `s3_initial_access`   | List buckets, read/delete objects, upload ransom note     |
| `s3_kms_encryption`   | KMS ransomware — re-encrypt S3 objects, delete key material |
| `eventual_consistency`| Exploit IAM eventual consistency propagation window       |

**Endpoints:**

| Method | Path                            | Auth | Description                           |
|--------|---------------------------------|------|---------------------------------------|
| GET    | `/api/simulations`              | JWT  | List all simulation runs              |
| POST   | `/api/simulations/run`          | JWT  | Trigger a simulation module on a stack |
| GET    | `/api/simulations/{id}`         | JWT  | Retrieve run status + output          |
| GET    | `/api/simulations/{id}/logs`    | JWT  | Stream or fetch stdout/stderr         |

**Request body for `POST /api/simulations/run`:**

```json
{
  "stack_id": "uuid-of-target-stack",
  "module": "s3_initial_access"
}
```

**Celery Task (`tasks.py`):**

```python
@shared_task
def run_simulation(run_id: str) -> None:
    """
    Import and call the main function of the target simulation module.
    Captures stdout/stderr. Updates SimulationRun.status on completion.
    """
```

---

### logs

Read-only audit log. Each significant event (stack deployed, simulation triggered,
simulation completed) writes a `LogEntry`. Used by the frontend to show an activity feed.

**Model: `LogEntry`**

| Field       | Type          | Description                                      |
|-------------|---------------|--------------------------------------------------|
| `id`        | UUID          | Primary key                                      |
| `level`     | CharField     | `INFO`, `WARNING`, `ERROR`                       |
| `event`     | CharField     | Machine-readable event name, e.g. `stack.deployed` |
| `message`   | TextField     | Human-readable description                       |
| `actor`     | ForeignKey    | User who triggered the event (nullable)          |
| `stack`     | ForeignKey    | Related stack (nullable)                         |
| `run`       | ForeignKey    | Related simulation run (nullable)                |
| `created_at`| DateTimeField | Auto timestamp                                   |

**Endpoints:**

| Method | Path                   | Auth | Description                         |
|--------|------------------------|------|-------------------------------------|
| GET    | `/api/logs`            | JWT  | List log entries, newest first      |
| GET    | `/api/logs/{id}`       | JWT  | Retrieve a single log entry         |

---

## Authentication Flow

```
Client                          Django                        simplejwt
  |                                |                               |
  |-- POST /api/auth/login ------> |                               |
  |   { username, password }       |-- validate credentials -----> |
  |                                |<-- access_token, refresh_token|
  |<-- 200 { access, refresh } ----|                               |
  |                                |                               |
  |-- GET /api/stacks -----------> |                               |
  |   Authorization: Bearer <jwt>  |-- verify token -------------> |
  |                                |<-- user identity -------------|
  |<-- 200 [ ...stacks ] ---------|                               |
```

Token lifetime (recommended):
- Access token: 15 minutes
- Refresh token: 7 days

---

## Async Task Flow

```
Django API                    Redis               Celery Worker           AWS
    |                            |                      |                   |
    |-- enqueue deploy_stack --> |                      |                   |
    |   Stack.status = deploying |-- pick up task ----> |                   |
    |                            |                      |-- pulumi up ----> |
    |                            |                      |<-- outputs -------|
    |                            |                      |                   |
    |                            | Stack.status = ready |                   |
    |                            | Stack.outputs = {...} |                  |
```

The same pattern applies to `destroy_stack` and `run_simulation`.

---

## Settings Split

```
config/settings/
  base.py     -- INSTALLED_APPS, MIDDLEWARE, DRF config, JWT config, Celery config
  dev.py      -- DEBUG=True, SQLite or local Postgres, CORS allow all origins
  prod.py     -- DEBUG=False, RDS connection via env vars, ALLOWED_HOSTS, logging
```

Environment variables (managed via `python-decouple` or `django-environ`):

| Variable              | Description                            |
|-----------------------|----------------------------------------|
| `SECRET_KEY`          | Django secret key                      |
| `DATABASE_URL`        | PostgreSQL connection string           |
| `REDIS_URL`           | Redis connection string                |
| `AWS_ACCESS_KEY_ID`   | AWS credentials for Celery workers     |
| `AWS_SECRET_ACCESS_KEY` | AWS credentials for Celery workers   |
| `AWS_DEFAULT_REGION`  | Default region (`ap-south-1`)          |
| `PULUMI_ACCESS_TOKEN` | Pulumi Cloud token (if using state backend) |
| `DJANGO_SETTINGS_MODULE` | e.g. `config.settings.prod`        |

---

## Key Dependencies (`requirements.txt`)

```
django>=5.0
djangorestframework>=3.15
djangorestframework-simplejwt>=5.3
django-cors-headers>=4.3
celery>=5.3
redis>=5.0
psycopg2-binary>=2.9
python-decouple>=3.8
```

---

## Key Conventions

- All models use UUID primary keys (`models.UUIDField(default=uuid.uuid4)`).
- Resource naming inside Celery tasks mirrors the existing `mayatrail-*-{stack_name}` pattern.
- Simulation tasks import modules from `src/simulations/` directly — they do not shell out
  to `runner.py`. This keeps stdout/stderr capturable and avoids a subprocess wrapper.
- `pulumi up` and `pulumi destroy` are still invoked via `subprocess.run()` inside Celery
  tasks (same as `runner.py`), with `cwd=src/` so `Pulumi.yaml` is found correctly.
- No test suite exists yet — validation is manual (deploy stack, trigger simulation, check
  results via API).
