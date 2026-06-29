# DANGERDEV Emulation Migration — Design Spec

- **Date:** 2026-06-14
- **Status:** Implemented + live-validated TWICE on 2026-06-15: (1) standalone (deploy 65 → 17-step attack exit 0 → destroy, zero orphans), and (2) through the **full Celery backend path** (deploy → readiness routed straight to READY_FOR_ATTACK → run_emulation_attack completed → destroy, zero orphans) on the worker's pinned pulumi-aws 7.11.1 + pulumi-tls 5.3.1. Uncommitted on `feat/dangerdev-emulation` pending integration.
- **Author:** Ayush Pathak (with Claude)
- **Repo target:** `MayaTrail/step1` branch `main` (`C:\Users\Ayush\Documents\mayatrail\step1`)
- **This file is gitignored** — it is a working spec/playbook and must NOT be pushed to GitHub.

---

## 1. Objective

Port the raw pipeline-generated **DANGERDEV** emulation
(`apt_pipeline` branch, `emulation_output/20260422_111749_DANGERDEV/`) into a
backend-compatible package at `step1/emulations/dangerdev/`, **faithful to the
real DangerDev threat actor's TTPs**, and prove compatibility with a real
deploy → attack → destroy run through the MayaTrail backend.

This is the **first** of several emulation migrations. Its second purpose is to
establish (a) the repeatable migration recipe and (b) the minimal backend
generalization that future non-web emulations require.

### In scope
- New package `emulations/dangerdev/` (MANIFEST, attack, infra, playbook, detections).
- One backend change: manifest-driven readiness gating in `apps/emulations/tasks.py`.
- One worker-image change: add `pulumi-tls`.
- Static validation + a paired live run.

### Out of scope (for this first migration)
- Migrating AMBERSQUID / CODEFINGER / LUCR-3 (follow-on work, reuses this recipe).
- Automating the migration in the pipeline (separate effort; this spec feeds it).
- Any change to scarleteel's runtime behavior.

---

## 2. Locked decisions

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | First emulation | **DANGERDEV** | User selection. |
| 2 | Fidelity | **Faithful port + compat fixes; fidelity to the real APT is the tie-breaker** | Emulation/detection value lives in the real names + real TTP footprint. |
| 3 | Gap B — readiness gating | **Manifest-driven backend change** | Generalizes for all future non-web emulations; back-compatible. |
| 4 | Gap A — `pulumi_tls` keypair | **Keep keypair, add `pulumi-tls` to worker image** | Real DangerDev created EC2 key pairs + used RDP (T1021.001); preserve the footprint. |
| 5 | Resource naming | **Keep real/masquerade names static** | Backend deploys per-user-account + enforces one active stack per user, so the multi-tenant collision the suffix-rule defends against cannot occur here. Preserves masquerade fidelity + detection matches. |
| 6 | Verification | **Full live deploy + attack + destroy** | Highest confidence; requires gaps A+B resolved for real. |
| 7 | Live-run ownership | **Pair live: Claude drives commands, user approves each AWS-touching step** | |
| 8 | Spec location | `step1/docs/superpowers/specs/…` **gitignored** | Working artifact, not product code. |

---

## 3. Backend contracts this package must satisfy

From `step1/backend/apps/emulations/`:

1. **Registry** (`registry.py`): scans `emulations/*/MANIFEST.py`, imports
   `emulations.<name>.MANIFEST.MANIFEST` (a dict). Required keys:
   `name, display_name, description, tier`. Recommends `schema_version`. Passes
   **all** manifest fields through to the catalogue (so new fields like
   `readiness` are surfaced automatically). Enumerates `detections/`.

2. **Attack entry point** (`tasks.py::run_emulation_attack`):
   `mod.run(stack.outputs, region=stack.region)` — `outputs` is a flat
   `dict[str, value]` (secret outputs included, plaintext via `.value`).
   stdout/stderr are captured and streamed to `EmulationRun`. No return contract.

3. **Deploy → readiness → attack flow:**
   - `deploy_emulation_stack` runs `pulumi up`, saves `stack.outputs`, then
     **unconditionally** enqueues `poll_ec2_readiness`.
   - `poll_ec2_readiness` currently hardcodes `stack.outputs["vuln_instance_ip"]`
     + `GET http://ip:8080/health`; success is the **only** path to
     `READY_FOR_ATTACK`. Missing IP → immediate `FAILED`.
   - `EmulationAttackView` only triggers the attack when status is
     `READY_FOR_ATTACK`.

4. **Pulumi program packaging** (`tasks.py::_prepare_work_dir`): only
   `Pulumi.yaml` + `__main__.py` are copied into the work dir. **`requirements.txt`
   is never installed** — every third-party import in `__main__.py` must already
   exist in the worker image.

5. **Credentials/region:** `_assume_user_role(stack.owner)` → deploy runs in the
   **enterprise user's own AWS account**; `aws:region` config = `stack.region`.

6. **Concurrency:** `EmulationDeployView` returns 409 if the user already has a
   non-terminal stack → **one active stack per user**.

---

## 4. Compatibility findings & resolutions

### Gap A — `pulumi_tls` not in the worker image (would crash `pulumi up`)
`infra/__main__.py` does `import pulumi_tls as tls` for the RSA keypair, but the
worker installs `pulumi-aws` only and never installs the emulation's
`requirements.txt` (see contract 4).
**Resolution:** add `pulumi-tls` to the worker image (work area 3). Keypair kept
for fidelity (decision 4).

### Gap B — readiness gating mismatch (headline; would auto-FAIL DangerDev)
DangerDev is an IAM/credential-abuse scenario on a **Windows** host with no
`:8080/health` web app, and exports `ec2_public_ip` (not `vuln_instance_ip`).
Under the current flow it can never reach `READY_FOR_ATTACK`.
**Resolution:** make readiness manifest-driven (work area 2). DangerDev declares
`readiness: {"type": "none"}` → deploy goes straight to `READY_FOR_ATTACK`.

### Gap C — runtime is pulumi-aws v7 (infra needs a v7 port)
The worker installs `backend/requirements.txt` = `pulumi==3.207.0`,
`pulumi-aws==7.11.1`, `pulumi-std==2.2.0` (no `pulumi-tls`). Because the
emulation's own `requirements.txt` is never installed (contract 4), **v7.11.1 is
the real runtime.** scarleteel's `>=6,<7` pin is documentary only — it runs on v7
because it avoids deprecated args (uses `BucketV2` + separate resources).
DangerDev's infra uses the classic `aws.s3.Bucket` with inline
`server_side_encryption_configuration` / `versioning` / `lifecycle_rules` /
`logging` plus `aws.s3.BucketObject` — removed/deprecated on v7.
**Resolution:** port the S3 layer to v7 — `BucketV2` +
`BucketServerSideEncryptionConfigurationV2` + `BucketVersioningV2` +
`BucketLifecycleConfigurationV2` + `BucketLoggingV2` + `BucketObjectv2`; verify
`aws.guardduty.Detector(datasources=...)` on v7. Drive and confirm with
`pulumi preview` against 7.11.1 before the live run.

### Gap D — hardcoded `us-east-1a` availability zone
`public_subnet` uses `availability_zone="us-east-1a"`, which breaks if
`stack.region != us-east-1`.
**Resolution:** region-derive it (`availability_zone=f"{region}a"`, matching
scarleteel). Natural live-run region is `us-east-1` regardless.

### Gap E — env-var credential handoff + `subprocess` auto-trigger
Pipeline infra hands creds to the attack via `subprocess.Popen` + env vars
(`LEAKED_KEY_ID`, `LAB_OPERATOR_KEY_ID`, …). Backend uses `run(outputs, region)`.
**Resolution:** remove the auto-trigger; read the leaked-admin key from
`outputs`; use the leaked-admin session (not an env operator key) for the
self-cleanup steps (see §5.2).

### Gap F — placeholder `adversaryAccountId` breaks real deploys (found in live run)
The infra defaulted the cross-account backdoor-role trust principal to
`config.get("adversaryAccountId") or "111111111111"`. AWS rejects a trust to a
non-existent account (`MalformedPolicyDocument: Invalid principal`), so
`pulumi up` fails on the two backdoor roles — and the backend deploy path would
hit the same error (it sets no such config). Pointing the trust at the real
documented adversary accounts would be *worse*: it creates a genuine admin
backdoor into a real malicious account.
**Resolution:** default `adversary_account_id` to the current account
(`account_id`) — a deployable, safe self-trust that preserves the masquerade
names + admin footprint. Side effect: the attack's Step 11 `AssumeRole` now
*succeeds* (self-admin) instead of the scripted AccessDenied — cosmetic, handled
gracefully. **Recipe note:** any future emulation with cross-account trust needs
a deployable, safe trust default (self-account), never a fake or real-malicious
placeholder.

---

## 5. Work area 1 — `emulations/dangerdev/` package

Directory: `20260422_111749_DANGERDEV/` → `emulations/dangerdev/` (clean slug).

### 5.1 `MANIFEST.py` (synthesized)
Source: `phase0b_metadata.json` + `attack_plan.json`. Mirror scarleteel's
structure. Required + key fields:

- `schema_version: 1`, `name: "dangerdev"`, `display_name` (e.g. "DangerDev"),
  `description` (3-phase / 17-step AWS IAM-abuse + cryptomining + phishing-infra
  campaign), `tier: "enterprise"`.
- UI metadata: `origin`, `tags`, `technique_count: 17`, `severity`, `aliases`
  ("DangerDev@protonmail.me"), `attribution` (Indonesia, financially motivated),
  `targets`, `incidents`/source (Invictus-IR DangerDev report).
- `attack_path`: 3 phases mapping the 17 steps:
  - **Phase 1 — Initial Access & Persistence:** T1078.004, T1526, T1087.004, T1136.003, T1098.003
  - **Phase 2 — Discovery & Compute:** T1580, T1578.002, T1021.001, T1496
  - **Phase 3 — Persistence/Collection/Evasion/Phishing-infra:** T1036.005, T1199, T1098, T1530, T1518.001, T1070, T1583.001, T1566.002
- `mitre_mappings`: one entry per technique (id, name, tactic, platform,
  description) — author from `attack_plan.json` step descriptions + the inline
  step comments in `attack.py`.
- `references`: Invictus-IR report + relevant MITRE technique pages.
- `phase_count: 3`, `estimated_duration_minutes`, `default_ttl_hours`,
  `total_resources` (count actual Pulumi resources for the progress bar —
  ~30+; finalize during implementation), `resources`, `resource_costs`
  (static estimates: EC2 t2.micro, GuardDuty, CloudTrail, S3, Secrets Manager,
  SNS, KMS).
- **`readiness: {"type": "none"}`** — the compatibility-critical field.

### 5.2 `attack.py` (from `emulation_scripts/attack.py`)
Keep all 17 steps, the `CredentialStore`, the audit `_events` log, the masquerade
behaviors, and the static resource-name lookups **verbatim** (decision 5 keeps
names static, so lookups stay valid). Changes only at the boundary:

1. Replace `main(target_info)` + `if __name__ == "__main__"` with:
   ```python
   def run(outputs: dict, region: str = "us-east-1") -> None:
   ```
2. Read the leaked-admin credentials from `outputs`:
   `outputs["admin_access_key_id"]`, `outputs["admin_access_key_secret"]`
   (replaces `LEAKED_KEY_ID` / `LEAKED_SECRET_KEY`). Raise `RuntimeError` if
   absent (replaces `sys.exit(1)`).
3. Thread `region` through `make_session` / `boto_client` defaults and every
   explicit `region_name="us-east-1"`.
4. **Self-cleanup (Step 15 + post-17):** replace the
   `os.environ["LAB_OPERATOR_KEY_ID/SECRET"]` operator session with
   `creds.get("leaked_admin_session")` — `lab-infra-admin` (Administrator, a
   different principal than `DangerDev@protonmail.me`) can perform the deletions.
   Removes all `os.environ` usage. Faithful: an external admin credential still
   performs the cleanup.
5. Drop `import sys`/`import os` if unused; keep `print(...)` (Celery streams it);
   optionally add `logger = logging.getLogger(__name__)` like scarleteel.
6. Account ID stays resolved from the IAM `get_user` ARN (no new output needed).

Only `admin_access_key_id` + `admin_access_key_secret` are consumed from
`outputs`. (alice's key is created at runtime in Step 12, so the exported alice
creds are unused by the attack.)

### 5.3 `infra/__main__.py` (from `infra/__main__.py`)
- Remove the `_trigger_attack` function, the `subprocess.Popen` block, the
  commented auto-trigger, and the `import os` / `import subprocess` lines.
- **Keep** `pulumi_tls` keypair (decision 4) and **all** static names (decision 5).
- `TAGS["MayaTrail"] = "dangerdev"` (was `"true"`).
- Region-derive the subnet AZ (Gap D): `availability_zone=f"{region}a"`.
- **Port the S3 layer to pulumi-aws v7 (Gap C):** convert the three classic
  `aws.s3.Bucket(...)` (with inline SSE/versioning/lifecycle/logging) to
  `aws.s3.BucketV2` + `BucketServerSideEncryptionConfigurationV2` +
  `BucketVersioningV2` + `BucketLifecycleConfigurationV2` + `BucketLoggingV2`,
  and `aws.s3.BucketObject` → `aws.s3.BucketObjectv2`. Validate with
  `pulumi preview` against 7.11.1; fix any further v7 deltas it surfaces.
- Keep all existing `pulumi.export(...)`s (the attack needs
  `admin_access_key_id` + `admin_access_key_secret`; the rest are useful
  catalogue/telemetry outputs).
- Confirm program imports reduce to: `json` (stdlib), `pulumi`, `pulumi_aws`,
  `pulumi_tls` — all present in the worker after work area 3.

### 5.4 `infra/Pulumi.yaml`
```yaml
name: mayatrail-dangerdev
runtime: python
description: DangerDev APT emulation — AWS IAM abuse, cryptomining, phishing infra.
```
(Drop the `runtime.options.virtualenv: venv` form.)

### 5.5 `infra/requirements.txt` (dev reference only; worker uses `backend/requirements.txt`)
Match the runtime so local dev mirrors the worker:
```
pulumi>=3.0.0,<4.0.0
pulumi-aws>=7.0.0,<8.0.0
pulumi-tls>=5.0.0,<6.0.0
```

### 5.6 `PLAYBOOK.md`
From `ir_playbooks/playbook_DANGERDEV.md` → package root. Sanitize/generalize
run-specific IPs, instance IDs, timestamps, and access-key IDs so it reads as a
reusable IR guide (per the report's playbook-content requirement).

### 5.7 `detections/`
Copy the pipeline `detections/` directory as-is (15 KQL + matching Sigma +
detection notes). Confirm rules match the static names kept in decision 5.

### 5.8 `__init__.py` and `infra/__init__.py`
Empty files (mirrors scarleteel).

---

## 6. Work area 2 — backend readiness change (`apps/emulations/tasks.py`)

Back-compatible, manifest-driven. Default (field absent) = today's exact behavior.

- Helper to resolve readiness from the manifest with the legacy default:
  ```python
  DEFAULT_READINESS = {"type": "ec2_http", "ip_output": "vuln_instance_ip",
                       "port": 8080, "path": "/health"}
  readiness = manifest.get("readiness") or DEFAULT_READINESS
  ```
- `deploy_emulation_stack`: after saving `stack.outputs`, branch:
  - `type == "none"` → set `READY_FOR_ATTACK`, **do not** enqueue the poll.
  - else → set `EC2_BOOTING`, enqueue `poll_ec2_readiness` (current behavior).
- `poll_ec2_readiness`: read `ip_output` / `port` / `path` from the manifest's
  readiness block instead of the hardcoded `vuln_instance_ip` + `:8080/health`.
- scarleteel `MANIFEST.py`: add an explicit `readiness` block equal to
  `DEFAULT_READINESS` (documentation only; no behavior change).
- `registry.py`: no change required (passes the field through).

---

## 7. Work area 3 — worker image

Add `pulumi-tls` to **`backend/requirements.txt`** (which already pins
`pulumi-aws==7.11.1`; the worker image installs from this file). Pin a
pulumi-3-compatible release (`pulumi-tls>=5.0.0,<6.0.0`, then freeze the resolved
exact version to match repo style). Without it, `pulumi up` fails to import the
program.

---

## 8. Validation plan

### 8.1 Static (Claude, no AWS spend)
1. `registry.discover()` lists `dangerdev` with all required keys + `readiness`.
2. `import emulations.dangerdev.MANIFEST` → dict valid; `import
   emulations.dangerdev.attack` → `run(outputs, region)` signature correct.
3. `python -c "import ast; ast.parse(...)"` / byte-compile `infra/__main__.py`.
4. `pulumi preview` type-checks the infra (needs AWS creds or at minimum a clean
   import with `pulumi-aws` + `pulumi-tls` available); confirm no `pulumi_tls`
   import error and no v7-only API usage.
5. Backend change: unit-style check that `deploy_emulation_stack` branches to
   `READY_FOR_ATTACK` for `readiness.type == none` and preserves the poll path
   otherwise.

### 8.2 Paired live run (Claude drives, user approves each AWS step)
1. Deploy via backend (enterprise user + STS role + state bucket + enterprise
   worker), region `us-east-1`.
2. Confirm `pulumi up` succeeds (keypair via `pulumi-tls`), `stack.outputs`
   populated, status → `READY_FOR_ATTACK` (no probe).
3. Trigger the attack; watch streamed stdout for the 17 steps; verify expected
   CloudTrail events + GuardDuty findings.
4. `pulumi destroy`; verify no orphaned IAM users/roles
   (`DangerDev@protonmail.me`, `ses` are attack-created and removed by the
   self-cleanup steps — confirm).

---

## 9. Risks & open items
- **Live cost/footprint:** Windows t2.micro + GuardDuty + CloudTrail + KMS;
  short TTL + prompt destroy. GPU mining is documented-only (t2.micro lifecycle
  only) — no surprise spend.
- **IAM eventual consistency** on rapid destroy/redeploy → transient
  `EntityAlreadyExists`; attack handles it gracefully.
- **Self-cleanup ordering:** verify `leaked_admin_session` is still valid at
  Step 15 (it is never invalidated; only `dangerdev_session` is).
- **`total_resources`** must be counted from an actual preview for an accurate
  progress bar.
- **Shared-account edge:** if two enterprise users ever share one AWS account,
  static IAM names could collide. Out of scope; note for the future generalized
  recipe (a per-emulation `naming: static|stack_suffixed` knob).

---

## 10. Repeatable recipe (feeds future migrations + pipeline changes)
1. Copy `<TS>_<ACTOR>/` → `emulations/<slug>/`; clean slug; add `__init__.py`.
2. Synthesize `MANIFEST.py` from `phase0b_metadata.json` + `attack_plan.json`
   (required keys + `attack_path` + `mitre_mappings` + `readiness`).
3. Rewrite `attack.py`: `run(outputs, region)`; creds from `outputs`; drop
   env/`sys.exit`/auto-trigger coupling; thread `region`.
4. Fix `infra/__main__.py`: remove auto-trigger; `runtime: python`; region-derive
   AZ; standardize tags; ensure every third-party import is in the worker image.
5. Set `Pulumi.yaml` name `mayatrail-<slug>` + `requirements.txt`.
6. `PLAYBOOK.md` to root (sanitized) + copy `detections/`.
7. Declare `readiness` (`none` for non-web; `ec2_http` for web-readiness emulations).
8. Static-validate, then live-validate.

The pipeline should eventually emit packages in this shape directly (entry point,
naming, `readiness`, no auto-trigger, no `virtualenv`).

---

## 11. Git handling
- Emulation package + backend change + worker change → **MayaTrail/step1 `main`**.
- **This spec file is gitignored** and must not be pushed.
- Per standing rule: confirm repo/branch + commit message before any
  `git commit` / `git push`.
