<!-- PLACEHOLDER: replace with MayaTrail logo -->
<!-- <p align="center"><img src="docs/assets/logo.svg" alt="MayaTrail" width="240"/></p> -->

<h1 align="center">MayaTrail</h1>

<p align="center">
  <strong>Rehearse real cloud attacks safely - in your own AWS account, before attackers do.</strong>
</p>

<p align="center">
  MayaTrail connects to your AWS account, provisions a realistic, intentionally vulnerable
  environment, runs a real adversary emulation against it, and shows you exactly what an
  attacker could reach, then tears it all down automatically. Every emulation ships with
  MITRE ATT&CK mappings and ready-to-deploy detection rules.
</p>

<div align="center">
  
  [![Backend tests](https://github.com/MayaTrail/step1/actions/workflows/backend-tests.yml/badge.svg)](https://github.com/MayaTrail/step1/actions/workflows/backend-tests.yml)
  [![Detections](https://github.com/MayaTrail/step1/actions/workflows/detections.yml/badge.svg?branch=main)](https://github.com/MayaTrail/step1/actions/workflows/detections.yml)
  [![Dependency Graph](https://github.com/MayaTrail/step1/actions/workflows/dependabot/update-graph/badge.svg?branch=main)](https://github.com/MayaTrail/step1/actions/workflows/dependabot/update-graph)
</div>
<!-- PLACEHOLDER: badges — add once CI / license / release are public -->
<p align="center">
  <!-- <img src="https://img.shields.io/badge/license-TBD-blue" alt="License"/> -->
  <!-- <img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build"/> -->
  <!-- <img src="https://img.shields.io/badge/stack-Django%20%7C%20React%20%7C%20Pulumi-111111" alt="Stack"/> -->
</p>

---

## The problem

Cloud and Kubernetes misconfiguration is the leading cause of modern breaches, a single over-permissive IAM role, an EC2 instance with IMDSv1 enabled, or a pod with a writable hostPath mount is enough to lose an account or a cluster. Yet security teams have almost no safe way to rehearse these attacks against infrastructure that looks like their own:

Production is too risky to attack. You can't run a credential-theft-to-persistence chain, or a pod-to-node escape, against live infrastructure just to see if it works.
Pentests are expensive and infrequent. A point-in-time engagement once or twice a year doesn't keep pace with infrastructure that changes daily.    

Knowing about a misconfiguration isn't the same as knowing your blast radius. Most tools flag that IMDSv1 is on or that a pod can mount hostPath; they don't show you the full kill chain it unlocks or whether your detections would catch it.
The result: teams discover whether their cloud or cluster is exploitable only when a real attacker shows them.

## The solution

MayaTrail closes the loop — **connect → deploy → attack → observe → auto-destroy** — running
real adversary emulations inside an isolated, disposable environment in *your own* AWS account.

1. **Connect** your AWS account by granting a scoped, cross-account IAM role (no long-lived keys to hand over. MayaTrail assumes the role via STS at run time), or target a MayaTrail-provisioned Kubernetes host for cluster-level emulations.
2. **Deploy** a realistic, intentionally vulnerable environment from code (Pulumi).
3. **Attack** it with a real adversary emulation modelled on a documented campaign or a known CVE/misconfiguration class.
4. **Observe** the outcome in a dashboard: the kill chain, MITRE ATT&CK coverage, blast
   radius, and an immutable audit log - plus detection rules you can take straight to your SIEM.
5. **Auto-destroy** every environment has a TTL, so nothing lingers and costs stay bounded.

Spin it up, run the breach, learn from it, and let it clean itself up. Repeat as often as your
infrastructure changes.

<p align="center">
  <img width="1915" height="995" alt="image" src="https://github.com/user-attachments/assets/431b63ab-a990-47f1-ba9a-805dec35f402" />
</p>

## Who it's for

MayaTrail is built for the people responsible for cloud and cluster security posture:

| Persona | What they get from MayaTrail |
|---|---|
| **Detection Engineer** | Real attacker telemetry plus shipped Sigma + KQL rules to validate and tune detections against. |
| **Security Engineer** | A safe range to validate whether a misconfiguration is actually exploitable end-to-end. |
| **Cloud Security Engineer** | Realistic, documented attack scenarios run safely inside their own AWS account. |
| **Platform / Kubernetes Engineer** | Hands-on proof of cluster-level attack paths without touching production clusters. |
| **DevSecOps Engineer** | Disposable, IaC-defined environments that fit into existing pipelines. |
| **SOC Analyst** | A controlled environment to study real attack patterns and response. |
| **Security Architect** | Evidence of blast radius to inform guardrails and policy decisions. |

## Key capabilities

- **Multi-platform** — AWS today, with native Kubernetes attack emulations and the plugin model built to extend to Azure and GCP.
- **Runs against your own infrastructure** — AWS connection is via a scoped, cross-account IAM role that MayaTrail assumes at run time; no long-lived credentials are stored.
- **Real-world adversary emulations** — modelled on documented campaigns, not toy scenarios.
- **Mapped to MITRE ATT&CK** — every phase is tied to a technique, with coverage surfaced on the dashboard.
- **Ships detection rules** — each emulation includes Sigma and KQL rules and an incident-response playbook, ready for your SIEM.
- **Ephemeral and cost-aware** — environments carry a TTL and are auto-destroyed on a schedule; cost estimates are shown up front.
- **Plugin-based emulation packages** — drop in a new emulation package and it's auto-discovered, infra and detections included.
- **Auditable** — an immutable log records every connect, deploy, attack, and destroy.

## Why now

Cloud and Kubernetes footprints are growing faster than the teams defending them, and the discipline is
shifting from point-in-time pentests toward **continuous threat exposure management** — always
knowing whether your environment is exploitable today, not last quarter. MayaTrail makes that
rehearsal loop cheap, safe, and repeatable enough to run continuously.

## Roadmap

`step1` is the first phase of a deliberately staged platform. Direction ahead:

- A growing library of adversary emulations across more documented campaigns
- Deeper Kubernetes coverage: multi-node clusters, managed control planes (EKS/GKE/AKS), and container-runtime-level attack paths
- Multi-cloud support (Azure, GCP, Kubernetes) — the platform model already accounts for it
- Deeper detection-engineering workflows built on emulation telemetry
- CI/CD integration to rehearse attacks on every infrastructure change

---

> The sections below are technical reference for running and contributing to MayaTrail.

## How it works

MayaTrail runs as a full-stack web application. The flow for a single emulation:

1. **Connect** —  for AWS emulations, a user grants a cross-account IAM role scoped to the permissions each emulation needs; the connectors app verifies it and MayaTrail assumes it via STS at run       time (no long-lived keys are stored). Kubernetes emulations target a MayaTrail-provisioned host running a lightweight, isolated control plane.
2. **Deploy** — the enterprise Celery worker provisions the emulation's infrastructure into the
   user's account using the **Pulumi Automation API, in-process** (no Docker socket, no
   ephemeral Pulumi containers). Pulumi state lives in a dedicated S3 state bucket.
3. **Attack** — the emulation package's `attack.py` executes the kill chain against the
   freshly provisioned infrastructure.
4. **Observe** — results, MITRE ATT&CK mappings, and detection rules surface in the dashboard;
   the `logs` app records an immutable audit trail.
5. **Auto-destroy** — each stack carries a TTL (SCARLETEEL defaults to 4 hours, most Kubernetes emulations default to 2 hours); Celery Beat runs an auto-destroy task every 15 minutes so expired environments are cleaned up and costs stay bounded.

## Connecting your AWS account

AWS emulations run against **your own account** via a cross-account IAM role — MayaTrail never
asks for or stores long-lived AWS access keys. To connect:

1. **Create an IAM role** in your AWS account (e.g. `MayaTrailRole`).
2. **Attach a trust policy** allowing the MayaTrail platform account to assume it (see below).
3. **Attach a permissions policy** scoped to what emulations need — the connector page in the app
   shows the exact policy required, grouped by emulation category, plus the full JSON to
   copy/paste.
4. **Submit the role's ARN** on the connector page
   (`arn:aws:iam::<your-account-id>:role/<role-name>`). MayaTrail verifies it live via
   `sts:AssumeRole` before marking the connection verified — nothing is provisioned until you
   actually run an emulation.

<p align="center">
  <img width="1909" height="987" alt="image" src="https://github.com/user-attachments/assets/0e8d2535-24ca-498e-b8fc-a110db8997eb" />
</p>

### Using the hosted app (app.mayatrail.tech)

If you're using the hosted instance at [app.mayatrail.tech](https://app.mayatrail.tech), trust
MayaTrail's platform AWS account, `940482414561`, in your role's trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::940482414561:root" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Self-hosting

If you're running your own instance (see [Quick start](#quick-start-docker-compose) below), the
trust policy must instead reference **your own platform account** — the AWS account behind the
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` credentials configured in `backend/.env`, since
that's the identity the `connectors` app assumes the role as.

## Quick start (Docker Compose)

```bash
# 1. Configure environment
cp backend/.env.example backend/.env
# Fill in SECRET_KEY, AWS credentials, and STATE_BUCKET in backend/.env

# 2. Start the full stack
docker-compose up --build
```

The application is available at `http://localhost`. Migrations run automatically on backend
startup.

**Prerequisites:** Docker and Docker Compose, plus AWS credentials for the platform account (used to AssumeRole into target accounts, provision Kubernetes hosts, and store Pulumi state).

### Key environment variables (`backend/.env`)

| Variable | Description |
|---|---|
| `SECRET_KEY` | Django secret key |
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Celery broker + result backend |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Platform AWS credentials (STS AssumeRole + state bucket) |
| `AWS_DEFAULT_REGION` | Default AWS region (e.g. `ap-south-1`) |
| `STATE_BUCKET` | S3 bucket for Pulumi state (e.g. `mayatrail-state-bucket`) |
| `PULUMI_CONFIG_PASSPHRASE` | Passphrase for Pulumi stack secrets |
| `EMULATIONS_BASE_DIR` | Where emulation packages are mounted (`/opt/emulations`) |
| `REGISTRATION_INVITE_CODE` | Invite code gating self-registration |
| `GOOGLE_CLIENT_ID` | Google SSO client ID |

### Frontend development

```bash
cd frontend/UI
npm install
npm run dev    # Vite dev server on http://localhost:3000
```

## Emulations

The point of MayaTrail isn't the module list — it's letting your team run a real APT chain end-to-end and find out, concretely, whether your detections fire, your SOC catches it in time, and your playbooks and guardrails hold up under an actual (contained) compromise. Use it to:

- **Test detections** — run the real technique and confirm your Sigma/KQL rules actually fire, not just that they parse.
- **Grade SOC response** — trigger a live-looking incident and time how fast the team detects, triages, and escalates.
- **Validate playbooks** — walk the shipped incident-response playbook against a real, contained compromise instead of a tabletop hypothetical.
- **Prove guardrails** — confirm IAM boundaries, network policies, and Kubernetes admission controls actually stop the attack where you think they do.
- **Run drills on demand** — spin up a fresh, disposable environment for a red/blue/purple team exercise whenever you need one, then let it auto-destroy.
Each emulation packages a documented threat-actor campaign or a disclosed CVE/misconfiguration class as a self-contained, auto-discovered plugin: Pulumi infra to stand up the vulnerable environment, an attack script that executes the real kill chain, MITRE ATT&CK mappings per phase, Sigma/KQL detection rules, and an incident-response playbook. Today, it spans multi-phase AWS campaigns (including SCARLETEEL, AMBERSQUID, Codefinger, and DangerDev), a library of narrower single-technique AWS emulations for isolating one detection at a time, and Kubernetes emulations covering RBAC abuse, adversary-in-the-middle, Pod Security Admission bypass, and host escape. The full, current catalogue — MITRE coverage, severity, cost and TTL per module — is browsable live in the dashboard, since new packages are auto-discovered as soon as they land in emulations/


- `MANIFEST.py` — identity, kill-chain phases, MITRE ATT&CK mappings, cost and TTL metadata
- `attack.py` — a `run(outputs)` function that executes the kill chain
- `infra/` — a Pulumi program that provisions the vulnerable environment
- `detections/` — Sigma and KQL detection rules, one set per technique
- `PLAYBOOK.md` — an incident-response playbook for the campaign

> [!IMPORTANT]
> **Writing or migrating an emulation? Start with the authoring knowledge base.**
> The authoring guide, the copy-paste package template, and the per-emulation migration records live in a
> **private submodule** at `emulations/_kb/` (repo `MayaTrail/emulations-authoring` — access required). It is the
> source of truth for the contracts every emulation must satisfy (MANIFEST/dashboard, readiness, naming,
> secrets), the validation gates, and the gotchas — follow it and a new package "lights up" the platform with
> no backend changes.
>
> ```bash
> git submodule update --init emulations/_kb     # populate it (needs access to the private repo)
> #  then read   emulations/_kb/AUTHORING.md
> #  start new   cp -r emulations/_kb/_TEMPLATE emulations/<name>
> #  migration   emulations/_kb/migrations/<name>.md  (from MIGRATION_TEMPLATE.md)
> ```
>
> Without submodule access `emulations/_kb/` stays empty — the public emulation packages still build and run;
> only the authoring methodology is gated.

<p align="center">
  <img width="1915" height="995" alt="image" src="https://github.com/user-attachments/assets/332e1c22-4edd-48a1-8f9e-fd12da46bc0f" />
</p>

## Docker Compose stack

The full platform runs as a Docker Compose stack with 7 services:

| Service | Purpose |
|---|---|
| `db` | PostgreSQL 16 database |
| `redis` | Celery message broker + result backend |
| `backend` | Django REST API (Gunicorn) |
| `worker_enterprise` | Celery worker — deploys, attacks, and destroys emulations in the user's AWS account via STS AssumeRole (Pulumi Automation API, in-process) |
| `beat` | Celery Beat scheduler — auto-destroys expired stacks every 15 minutes |
| `ui` | React SPA (Nginx, non-root) |
| `nginx` | Edge reverse proxy (routes `/` to UI, `/api/` + `/admin/` to backend) |

## Contributing

Good entry points for understanding the codebase:

**NOTE:** Contributors are required to have access to the emulations' knowledge base,
in case you want to contribute, show us some of your emulations sample and if everythign aligns perfectly, we will allow
you to access our knowledge base directory so you can start contributing to Mayatrail. 

- `docker-compose.yml` — the full service topology and how the pieces connect
- `emulations/scarleteel/` — a complete AWS emulation package (manifest, attack, infra, detections, playbook)
- `emulations/k8s_rbac_impersonation/` — a complete Kubernetes emulation package, and
  `emulations/k8s_attack_readme.md` for how all five Kubernetes attacks work end to end
- `emulations/_kb/AUTHORING.md` — **the authoring/migration knowledge base (private submodule); read it before
  writing or migrating an emulation** (see the [Emulations](#emulations) callout to initialise it)
- `frontend/UI/DESIGN.md` — the frontend design system; read it before any UI change
- Adding or migrating an emulation is the most common contribution. **Read `emulations/_kb/AUTHORING.md` first**, then copy `emulations/_kb/_TEMPLATE/` to a new `emulations/<name>/`, fill in the `MANIFEST.py` and an `attack.py`
- exposing `run(outputs, region)` — the registry discovers it automatically — and record the work in `emulations/_kb/migrations/<name>.md`.

The KB defines the contracts CI enforces, so following it keeps your package from failing the build.

---

$`\textcolor{red}{\text{Safety note: MayaTrail provisions intentionally vulnerable AWS resources inside the connected account. Use only a dedicated, isolated test account.}}`$
