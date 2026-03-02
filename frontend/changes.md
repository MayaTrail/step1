# Docker & Backend Deployment Fixes

All changes made to get the MayaTrail stack running in Docker (`docker compose up`).

---

## 1. Missing Django Migration Files

**Problem:** All 4 Django apps had no initial migration files. `manage.py migrate` created no tables → backend crashed with `relation "users" does not exist`.

**Files created:**

| File | Creates Table |
|---|---|
| `backend/apps/users/migrations/__init__.py` | *(package marker)* |
| `backend/apps/users/migrations/0001_initial.py` | `users` |
| `backend/apps/logs/migrations/__init__.py` | *(package marker)* |
| `backend/apps/logs/migrations/0001_initial.py` | `log_entries` |
| `backend/apps/infrastructure/migrations/0001_initial.py` | `stacks` |
| `backend/apps/simulations/migrations/0001_initial.py` | `simulation_runs` |

---

## 2. UI Healthcheck — BusyBox wget Incompatibility

**Problem:** `nginx:1.27-alpine` uses BusyBox `wget` which doesn't support `--no-verbose` or `--spider`. Every healthcheck failed instantly, marking the UI container as unhealthy.

**Changes:**

- **`docker-compose.yml`** — Replaced wget-based healthcheck with a process-based check:
  ```diff
  - test: ["CMD-SHELL", "wget --no-verbose --spider http://localhost:8080/health || exit 1"]
  + test: ["CMD-SHELL", "kill -0 $(cat /tmp/nginx.pid 2>/dev/null) 2>/dev/null || exit 1"]
  ```
  Added `start_period: 15s`.

- **`docker-compose.yml`** — Changed edge nginx dependency on UI:
  ```diff
  - condition: service_healthy
  + condition: service_started
  ```

- **`UI/Dockerfile`** — Same wget flag fix for standalone usage.

---

## 3. Missing AWS Credentials for Celery

**Problem:** Celery container had `AWS_REGION` but was missing `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`. Pulumi login to S3 backend failed with `NoCredentialProviders`.

**Change in `docker-compose.yml`** — Added to celery environment:
```yaml
AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:?Set AWS_ACCESS_KEY_ID in .env}
AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY:?Set AWS_SECRET_ACCESS_KEY in .env}
AWS_SESSION_TOKEN: ${AWS_SESSION_TOKEN:-}
```

---

## 4. Missing Pulumi Config Passphrase

**Problem:** Pulumi S3 backend requires `PULUMI_CONFIG_PASSPHRASE` to encrypt stack secrets. `pulumi stack init` failed silently without it.

**Change in `docker-compose.yml`** — Added to celery environment:
```yaml
PULUMI_CONFIG_PASSPHRASE: ${PULUMI_CONFIG_PASSPHRASE:-}
```

---

## 5. Pulumi Stack Not Initialized

**Problem:** `pulumi up --stack dev-name` failed because the stack didn't exist in the S3 state backend yet. Needed `pulumi stack init` first.

**Change in `backend/apps/infrastructure/tasks.py`** — Added `pulumi stack init` call inside `_run_pulumi()` before the main command:
```python
subprocess.run(
    ["pulumi", "stack", "init", stack_name, "--non-interactive"],
    cwd=SRC_DIR,
    capture_output=True,
    text=True,
    env=env,
)
```

---

## 6. Read-Only Volume Mount

**Problem:** `src/` was mounted as `:ro` (read-only), but Pulumi needs to write stack config files (`Pulumi.<stack-name>.yaml`) into the project directory.

**Change in `docker-compose.yml`:**
```diff
- - ./src:/src:ro
+ - ./src:/src
```
