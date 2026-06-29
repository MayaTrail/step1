# MayaTrail Step1 — Agent Orientation

AWS security simulation platform: Django REST API + React/TypeScript SPA + Celery workers + Pulumi IaC.
**This platform creates intentionally vulnerable AWS resources. Only run in isolated test accounts.**

## Repository Layout

```
backend/          Django REST API (Gunicorn/Celery)
frontend/UI/      React + TypeScript SPA (Vite → Nginx)
emulations/       Attack emulation plugin packages
src/              Legacy standalone Pulumi IaC
simulations/      Legacy standalone boto3 scripts (not active)
docker-compose.yml
```

## Commands

```bash
# Full stack
docker-compose up --build

# Backend only
cd backend && pip install -r requirements.txt
python manage.py makemigrations users infrastructure emulations logs && python manage.py migrate
python manage.py runserver

# Frontend only
cd frontend/UI && npm install && npm run dev

# Celery worker
cd backend && celery -A config worker --queues=enterprise --loglevel=info
```

## Code Style

- Backend: Python 3.12, Django 5, DRF. Follow existing patterns in `backend/apps/`.
- Frontend: TypeScript strict mode, React functional components, Tailwind CSS.
- No `type: ignore` or `any` in new TypeScript code without a comment explaining why.
- New Django apps go in `backend/apps/<name>/` with the standard structure (models, views, serializers, urls, tasks).

## Key Files

- `emulations/registry.py` — plugin auto-discovery logic
- `emulations/<name>/MANIFEST.py` — emulation metadata schema
- `backend/config/settings/base.py` — Django settings (all secrets via `python-decouple`)
- `backend/apps/emulations/tasks.py` — Celery tasks that drive deploy/attack/destroy lifecycle
- `docker-compose.yml` — authoritative service topology

## Environment

Copy `backend/.env.example` to `backend/.env`. Critical vars:
- `PULUMI_CONFIG_PASSPHRASE` — never change after stacks are created
- `EMULATIONS_BASE_DIR` — set to `/opt/emulations` in Docker, absolute path to `emulations/` locally
- `STATE_BUCKET` — S3 bucket for Pulumi state (`mayatrail-state-bucket`, region `ap-south-1`)

## Testing

No automated test suite currently. Validate changes by running the stack locally and exercising the affected API endpoints or UI flows.
