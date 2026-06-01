# Changelog

## 2026-05-28 (session: fix-emulations) — fix vuln-app image (build on instance)
### Changes
- [emulations/scarleteel/infra/__main__.py] Replaced the broken `docker run mayatrailsec/scarleteel-vuln-app:latest` (registry pull — the image does not exist / is private, so deploys reached ec2_booting then failed readiness) with a build-on-instance UserData ported from the APT_Pipeline reference: writes a Flask app.py (GET /health, POST /cmd command-injection) + Dockerfile (python:3.9-slim + curl/wget + flask), then `docker build` + `docker run`. Switched yum->dnf and `set -euo pipefail`->`set -ex` to match the proven reference

### Root cause (from live deploy 2026-05-26)
- EC2 console output showed: `pull access denied for mayatrailsec/scarleteel-vuln-app, repository does not exist`. The infra never built the image; it tried to pull a non-existent registry image. The image is meant to be built locally on the EC2.

### Why curl/wget matter
- Phase 2 of attack.py runs `curl http://169.254.169.254/...` via POST /cmd from INSIDE the container to steal instance-role creds over IMDSv1. The container image must therefore ship curl/wget; the instance already permits a 2-hop IMDS PUT so the container can reach the metadata endpoint

## 2026-05-25 (session: fix-emulations) — attack.py + cost_estimator real logic
### Changes
- [emulations/scarleteel/attack.py] Replaced all 6 TODO stubs with working logic, ported from the APT_Pipeline reference and adapted to our infra + the run(outputs, region) Celery interface. Phase 1 container RCE via POST /cmd + cryptominer decoy; Phase 2 IMDSv1 credential theft -> boto3 session; Phase 3 IAM/S3/Secrets Manager enumeration; Phase 4 CloudTrail StopLogging (graceful if no trail); Phase 5 lateral movement adapted to retrieve the Secrets Manager bait secret (not tfstate); Phase 6 Lambda backdoor built from an in-memory zip using lambda_role_arn
- [backend/apps/emulations/tasks.py] run_emulation_attack now calls run(outputs, region=stack.region); added estimate_emulation_cost task that runs `pulumi preview --json` on an ephemeral stack and prices the result via cost_estimator (removes the ephemeral stack after)
- [backend/apps/emulations/cost_estimator.py] New module: prices pulumi-preview resources via the live AWS Pricing API (region-aware location mapping) with a hardcoded EC2/service table fallback; normalises pulumi type tokens; parses preview steps into a resource list
- [backend/apps/emulations/views.py] EmulationEstimateView now enqueues estimate_emulation_cost on the worker and blocks on the result (~live preview), falling back to static MANIFEST figures on timeout/failure; added _default_region() helper

### Decisions
- Phase 5/6 adapted to our infra (Secrets Manager secret as lateral target; Lambda backdoor for persistence) rather than the reference's tfstate-bait-cred theft, per product direction
- RCE endpoint is /cmd (matches the confirmed-functional reference; our old /execute comment was a stale guess)
- The cost estimate runs on the worker (Pulumi CLI is only in the worker image); the view blocks on the Celery result so the API stays synchronous (no frontend contract change)
- Cost: AWS Pricing API is primary, hardcoded tables are fallback (per direction). Flat-rate services stay table-based since their real cost is usage-based, not hourly

### Live validation results
- cost estimate validated END-TO-END against the real AWS account: `pulumi preview --json` returns 20 steps, parser correctly extracts 19 priced resources, total ~$0.0124/hr (~$8.94/mo) for scarleteel in ap-south-1
- Found + fixed: ephemeral estimate stack name was too long — interpolated into `mayatrail-scarleteel-ec2-role-{stack}` it exceeded the IAM 64-char limit, causing a partial preview. Shortened to `est-{8hex}`
- Added a guard: estimate task now raises on non-zero preview exit / error diagnostics instead of returning a partial (silently wrong) estimate; the view falls back to the MANIFEST figures
- attack.py structure/imports verified on the worker; full attack end-to-end still requires a live deployed stack (EC2 + container reachable)

### LIVE pricing confirmed (2026-05-26)
- `pricing:GetProducts` granted to `mayatrail-user-aws-dev`; live region-accurate pricing now flows through. Confirmed estimate: scarleteel/ap-south-1 = 19 resources, EC2 t3.micro at the live Mumbai rate $0.0112/hr (vs hardcoded us-east-1 $0.0104), total ~$0.0132/hr (~$9.52/mo), zero warnings
- [backend/apps/emulations/cost_estimator.py] Fixed cache poisoning: fallback prices are no longer cached — only authoritative Pricing API results are. Previously a transient API failure (or a not-yet-granted permission) cached the hardcoded fallback for the whole worker-process lifetime and served it silently (no warning) on later cache hits. Now the API is retried until it succeeds

## 2026-05-24 (session: fix-emulations) — S3 force_destroy for clean teardown
### Changes
- [emulations/scarleteel/infra/__main__.py] Added `force_destroy=True` to both BucketV2 resources (tfstate + cloudtrail). The CloudTrail bucket accumulates AWSLogs/ objects written by CloudTrail itself (not Pulumi-tracked), so `pulumi destroy` hit `BucketNotEmpty` (409) and left the bucket + stack record orphaned. force_destroy lets Pulumi empty the bucket before deleting it

### Decisions
- For the already-deployed stack whose state had force_destroy=false, the bucket was emptied manually via boto3 (assumed role) then destroy re-run — force_destroy only affects buckets created after the fix
- destroy_emulation_stack only deletes the DB record on full success; a partial destroy (e.g. one bucket failing) leaves the record in FAILED so the orphan is visible and retryable

## 2026-05-24 (session: fix-emulations) — default region changed to ap-south-1
### Changes
- [backend/apps/infrastructure/models.py] `Stack.region` default changed from us-east-1 to ap-south-1. The field default is applied at the Python/ORM level on create(), so no DB migration is required for new stacks to pick it up
- [emulations/scarleteel/infra/__main__.py] Region fallback `aws.config.region or "us-east-1"` changed to `"ap-south-1"` (defensive — the task always sets aws:region from the stack record)
- [backend/apps/emulations/tasks.py, backend/apps/infrastructure/tasks.py] Updated region docstring examples to ap-south-1

### Decisions
- All new provisioning now defaults to ap-south-1, co-locating stack resources with the Pulumi state bucket (STATE_BUCKET_REGION=ap-south-1). The existing scarleteel-verify-001 stack remains in us-east-1 since it was deployed before this change with an explicit region

## 2026-05-24 (session: fix-emulations) — deploy debugging: three blocking bugs fixed
### Changes
- [backend/apps/emulations/tasks.py] Fixed `_make_progress_handler` — Pulumi invokes on_output from a separate consumer thread where Celery's `self.request.id` is empty, so `update_state()` raised "task_id must not be empty" and aborted the entire deploy. Now the task id is captured in the main thread and passed in explicitly, and the update_state call is wrapped in try/except so progress reporting can never break a deploy
- [emulations/scarleteel/infra/__main__.py] Security Group `description` used an em-dash (U+2014) — AWS rejects non-ASCII in GroupDescription (InvalidParameterValue). Replaced with an ASCII hyphen
- [DB hotfix] Manually added the `stacks.task_id` column via ALTER TABLE — the migration never applied (see root cause below)

### Root cause analysis (the chain that blocked all deploys)
1. **Missing `task_id` column** — broke every Stack ORM query (`SELECT *` includes task_id), so `deploy_emulation_stack` died on its first line `_get_stack()`. Underlying cause: docker-compose runs `makemigrations` at container startup with NO committed migration files. On restart Django regenerates `0001_initial` with the new field folded into CreateModel, but the DB already marks 0001 as applied, so `migrate` skips it and the column is never created.
2. **Wrong endpoint** — stacks created via `POST /api/stacks/` (infrastructure CRUD) have no emulation_type; our cleanup made `_resolve_work_dir("")` raise. Emulation deploys must use `POST /api/emulations/deploy/`.
3. **Progress handler thread bug** — see Changes above.
4. **Non-ASCII security group description** — see Changes above.

### Decisions
- Progress-reporting from the Pulumi output thread must be best-effort (try/except) — a monitoring feature must never be able to abort the operation it monitors
- Migration persistence to be solved via Docker named volumes over the migrations directories (keeps migrations out of the repo per user preference, while making makemigrations do incremental diffs instead of regenerating 0001) — pending implementation

## 2026-05-24 (session: fix-emulations) — stack deployment progress endpoint
### Changes
- [backend/apps/infrastructure/models.py] Added `task_id` CharField — stores the Celery task ID of the most recent deploy operation so the progress endpoint can query Redis
- [backend/apps/infrastructure/serializers.py] Exposed `task_id` as a read-only field on `StackSerializer`
- [backend/apps/infrastructure/views.py] Added `GET /api/stacks/{id}/progress/` action — reads `AsyncResult(task_id).info` from Redis and returns `resources_created`, `total_resources`, `percentage`, `recent_logs`; falls back gracefully for all terminal statuses
- [backend/apps/emulations/tasks.py] Added `_make_progress_handler` helper — replaces `_make_log_handler` in `deploy_emulation_stack`; counts Pulumi " created" lines and calls `self.update_state(state='PROGRESS', meta={...})` every 2 lines; reads `total_resources` from emulation MANIFEST
- [backend/apps/emulations/views.py] `EmulationDeployView` now stores `task.id` on the Stack record after `apply_async`
- [emulations/scarleteel/MANIFEST.py] Added `total_resources: 19` — consumed by the progress handler for percentage calculation

### Decisions
- Progress is stored in Redis (via Celery result backend) rather than the DB — avoids a write per Pulumi log line during a deploy that can produce 100+ lines
- `percentage` is capped at 99 while the task is running — only the terminal states (READY, EC2_BOOTING, etc.) return 100, so the frontend never shows 100% while Pulumi is still finishing up
- `recent_logs` returns the last 10 lines — enough context without bloating the poll response

## 2026-05-24 (session: fix-emulations) — addendum: full legacy reference purge
### Changes
- [backend/apps/emulations/tasks.py] Removed `PULUMI_WORK_DIR` constant and both demo tasks (`provision_demo_stack`, `destroy_demo_stack`); renamed `EMULATIONS_PATH` → `EMULATIONS_BASE_DIR`; updated `_emulation_work_dir` to use it directly with existence validation; stripped demo branch from `auto_destroy_expired_stacks`; removed static credential fallback from `_build_workspace_env` (enterprise STS credentials only); fixed sys.path insertion in `run_emulation_attack` to derive parent from `EMULATIONS_BASE_DIR`; added `select_related("owner")` to `_get_stack`
- [backend/apps/emulations/registry.py] Replaced `EMULATIONS_PATH` with `EMULATIONS_BASE_DIR`; sys.path insertion now uses `os.path.dirname(EMULATIONS_BASE_DIR)` so the correct parent directory is added
- [backend/apps/emulations/views.py] Replaced `EMULATIONS_PATH` with `EMULATIONS_BASE_DIR` in module constant and playbook fallback path
- [backend/apps/connectors/views.py] Removed `provision_demo_stack.apply_async` call from `DemoActivateView.post` — demo stack provisioning has no place in the enterprise codebase
- [backend/config/settings/base.py] Renamed `EMULATIONS_PATH` → `EMULATIONS_BASE_DIR` with updated comment
- [backend/.env.example] Replaced `EMULATIONS_PATH` + `EMULATIONS_HOST_PATH` with single `EMULATIONS_BASE_DIR`; removed demo credential comment
- [docker-compose.yml] Renamed `EMULATIONS_PATH: /opt` → `EMULATIONS_BASE_DIR: /opt/emulations` in both `backend` and `worker_enterprise`; updated header comment to reflect enterprise-only service set

### Decisions
- `EMULATIONS_BASE_DIR` points directly at the emulations directory (`/opt/emulations`) rather than its parent — more explicit and removes the ambiguity of `EMULATIONS_PATH=/opt` where `/opt` was used for two different things (sys.path and path construction)
- `provision_demo_stack` and `destroy_demo_stack` removed entirely rather than kept as stubs — dead code in an enterprise repo creates confusion and maintenance burden

## 2026-05-24 (session: fix-emulations)
### Changes
- [src/] Removed entire directory — runner.py, entrypoint.sh, cleanup.py, Dockerfile, Pulumi.yaml, __main__.py, requirements.txt, .dockerignore all deleted; step1 is enterprise-only and no longer uses the generic IAM+S3 stack or the legacy CLI path
- [docker-compose.yml] Removed `pulumi` service (build-only CLI image, dead path) and `worker` service (demo queue, no role in enterprise); removed `PULUMI_WORK_DIR: /app/src` and `./src:/app/src:ro` from `worker_enterprise`; renamed `EMULATIONS_PATH` to `EMULATIONS_BASE_DIR: /opt/emulations` for clarity
- [backend/apps/infrastructure/tasks.py] Replaced `PULUMI_WORK_DIR` constant with `EMULATIONS_BASE_DIR`; added `_resolve_work_dir(emulation_type)` which maps any emulation type to its `infra/` directory under `EMULATIONS_BASE_DIR` — zero task changes needed when new emulations are added; all 4 tasks (deploy, destroy, refresh, preview) now route through `_resolve_work_dir`; removed dead demo credential branch from `_get_aws_credentials`; dropped default value from `_get_pulumi_stack.work_dir` parameter to make the required path explicit

### Decisions
- `_resolve_work_dir` raises `ValueError` (not a silent fallback) when `emulation_type` is empty or the infra directory is missing — fails loudly at task start rather than silently deploying the wrong program
- Demo credential path removed from `_get_aws_credentials` because step1 is enterprise-only; demo codebase separation means static platform credentials have no place in this repo
- `worker` service removed because the Pulumi Automation API runs in-process inside `worker_enterprise`; the container-spawning pattern it was built for no longer exists

### Discussion Summary
- Decision to separate demo and enterprise codebases; step1 is the enterprise foothold
- `src/` was identified as containing two dead paths: the legacy CLI runner (runner.py/entrypoint.sh) and the generic demo infra program (__main__.py/Pulumi.yaml), neither of which serves the enterprise Automation API flow
- Emulation routing redesigned to be convention-based: `emulations/{type}/infra/` — adding a new emulation requires no changes to tasks.py

## 2026-05-24
### Changes
- [backend/apps/infrastructure/tasks.py] Migrated all Pulumi operations (deploy, destroy, refresh, preview) from Docker SDK container spawning to Pulumi Automation API; eliminated Docker socket dependency from worker services
- [backend/apps/emulations/tasks.py] Same Automation API migration for demo and enterprise emulation tasks; removed EMULATIONS_HOST_PATH Docker-in-Docker path hack
- [backend/Dockerfile.worker] New Dockerfile for worker services — Python 3.12-slim + Pulumi CLI 3.207.0; API backend keeps its lean Dockerfile
- [backend/requirements.txt] Replaced docker==7.1.0 with pulumi==3.207.0, pulumi-aws==7.11.1, pulumi-std==2.2.0, requests==2.32.3
- [docker-compose.yml] Workers use Dockerfile.worker; removed Docker socket mounts; added ./src:/app/src:ro volume; corrected STATE_BUCKET to mayatrail-state-bucket
- [backend/config/settings/base.py] Added CELERY_TASK_DEFAULT_QUEUE="default" — tasks were silently routed to Celery's built-in "celery" queue and never consumed
- [backend/apps/infrastructure/tasks.py] Added _assume_user_role() and _get_aws_credentials() — enterprise users now use STS AssumeRole credentials for all Pulumi operations instead of static platform credentials that lacked S3 access
- [backend/.env.example] Documented STATE_BUCKET and PULUMI_CONFIG_PASSPHRASE as required variables
- [frontend/UI/src/components/stacks/StacksPage.tsx] Added force-destroy button for stuck emulation stacks; added tab system (Details / Resource Graph) in expanded stack row
- [frontend/UI/src/components/stacks/InfraGraphView.tsx] New SVG DAG component showing the 10 AWS resources Pulumi deploys; node click opens detail panel with resource config and outputs
- [frontend/UI/src/components/dashboard/DashboardPage.tsx] Replaced static getPlatformData() with live API calls — APT Emulations, MITRE Techniques, and Detection Rules metrics now show real counts from /api/emulations/; loading state shows — until data arrives
- [backend/MayaTrail.postman_collection.json] Added Force Destroy Stack endpoint

### Decisions
- Pulumi Automation API chosen over Docker container spawning: eliminates Docker socket security risk, removes container cold-start latency (~15s), provides real-time log streaming via on_output callback, and gives typed stack outputs instead of stdout scraping
- STATE_BUCKET corrected from mayatrail-pulumi-state (does not exist) to mayatrail-state-bucket (confirmed accessible via STS role)
- Enterprise users' STS role is now used for ALL Pulumi operations, not just emulation stacks — static platform credentials had no S3 access

### Discussion Summary
- Three layered bugs caused deployment failures: wrong Celery queue name, wrong AWS credentials (static vs STS), wrong S3 bucket name
- Celery's built-in default queue name "celery" conflicts with the explicit "default" queue the workers listened on — fixed with CELERY_TASK_DEFAULT_QUEUE setting
- PULUMI_CONFIG_PASSPHRASE still needs to be added to backend/.env by the user (matches value used at stack creation time; default in src/Dockerfile is enter-your-passphrase-here)

## 2026-05-20 — Legacy simulations removal
### Changes
- [simulations/] Deleted entire root simulations package (8 modules: attach_role_policy, enumeration, eventual_consistency, s3_initial_access, s3_kms_encryption, registry, logger, __init__)
- [backend/apps/simulations/] Deleted entire Django app (models, views, serializers, tasks, urls, admin, apps — 8 files)
- [frontend/UI/src/data/platforms/aws/emulations.ts] Deleted static old simulation data file (dead code since last session)
- [backend/config/settings/base.py] Removed apps.simulations from INSTALLED_APPS
- [backend/config/urls.py] Removed /api/simulations/ URL route
- [backend/apps/logs/models.py] Removed SimulationRun FK and run field; replaced simulation.* event types with emulation.*; removed simulations import
- [backend/apps/logs/views.py] Removed simulation run queryset filter
- [backend/apps/logs/serializers.py] Removed run field
- [backend/apps/emulations/tasks.py] Deleted reset_demo_stack_state task (was S3 re-seed for post-simulation cleanup)
- [docker-compose.yml] Removed SIMULATIONS_PATH from backend and worker; removed ./simulations volume mounts from both; removed simulations from makemigrations command
- [frontend/UI/src/types/platform.ts] Removed SimulationModule, SimulationStatus, SimulationRun, TriggerSimulationRequest, TriggerSimulationResponse, EMULATION_MODULE_MAP
- [frontend/UI/src/components/auth/ConnectorPage.tsx] Updated IAM policy Sid and all UI text: simulation → emulation
- [frontend/UI/src/components/dashboard/DashboardPage.tsx] Updated feature card body text: simulation → emulation
- [backend/openapi.yaml] Removed all simulation schemas and /api/simulations/ paths; updated LogEntry events to emulation.*
- [backend/MayaTrail.postman_collection.json] Removed Simulations (Legacy) folder

### Decisions
- Enterprise APT emulations are the only execution model going forward — no backward-compat stubs kept
- LogEntry event enum updated from simulation.* to emulation.* to keep audit logs useful for the new workflow
- Database migration required on next docker-compose up: drops run_id FK from log_entries table and drops simulations_simulationrun table

## 2026-05-20
### Changes
- [emulations/scarleteel/MANIFEST.py] Full rewrite — added schema_version:1, origin, severity, tags, attack_path (6 phases), mitre_mappings (8 techniques), references, and all UI catalogue fields
- [emulations/scarleteel/attack.py] Removed duplicate MANIFEST dict; all metadata now lives exclusively in MANIFEST.py
- [emulations/scarleteel/detections/] Created detections directory with 12 new files: SIGMA + KQL rules for T1190, T1552.005, T1087.004, T1562.008, T1548.005, T1098
- [emulations/registry.py] Updated discover() — schema_version validation, detection file auto-enumeration, detections_path and detection_files included in catalogue entries
- [backend/apps/emulations/tasks.py] Fixed run_emulation_attack to read phase_total from the registry instead of attack.py's MANIFEST dict
- [backend/apps/emulations/views.py] Added EmulationTechniquesView, EmulationDetectionsView, EmulationPlaybookView; added _manifest_to_api() camelCase transformer; updated EmulationDeployView/AttackView/DestroyView to return camelCase response keys
- [backend/apps/emulations/urls.py] Registered 3 new routes: techniques/, detections/, playbook/ per emulation type
- [frontend/UI/src/types/platform.ts] Added enterprise StackStatus values (ec2_booting, ready_for_attack, attacking, attack_complete, destroyed); added EmulationRunRecord, DeployEmulationResponse, TriggerAttackResponse, EmulationEstimate types; cleared EMULATION_MODULE_MAP
- [frontend/UI/src/services/platform.service.ts] Replaced static data with real /api/emulations/ API calls; added parsePlaybookMarkdown() to parse PLAYBOOK.md into Playbook steps
- [frontend/UI/src/services/emulation.service.ts] Full rewrite — enterprise emulation lifecycle API (deploy, attack, destroy, poll, techniques, detections, playbook)
- [frontend/UI/src/hooks/usePlatformData.ts] useDetections now accepts emulationType (per-emulation); usePlaybook now accepts emulationType (per-emulation); deprecated usePlaybooks/usePlaybookById stubs retained
- [frontend/UI/src/components/detections/DetectionsPage.tsx] Rewritten as per-emulation page — reads emulationId from route params, shows SIGMA/KQL format toggle
- [frontend/UI/src/components/playbooks/PlaybookPage.tsx] Rewritten as per-emulation page — reads emulationId from route params
- [frontend/UI/src/components/modals/RunEmulationModal.tsx] Full rewrite for enterprise flow: cost estimate → deploy → poll ready_for_attack → attack → poll run; graceful 403 handling with "Enterprise account required" message
- [frontend/UI/src/App.tsx] Updated routes: /:platformId/emulations/:emulationId/playbook and /:platformId/emulations/:emulationId/detections (per-emulation)
- [frontend/UI/src/components/layout/Sidebar.tsx] Playbooks and Detections sidebar links now redirect to emulations list (per-emulation navigation)
- [frontend/UI/src/components/emulations/EmulationDetailPage.tsx] Updated Playbook link to new per-emulation route
- [frontend/UI/src/components/emulations/EmulationsListPage.tsx] Updated Playbook link to new per-emulation route
- [frontend/UI/src/components/stacks/StacksPage.tsx] Added all enterprise StackStatus values to STATUS_CONFIG
- [frontend/UI/src/data/platforms/aws/detections.ts] Removed static detection rules (now served from backend); kept awsGuardrails
- [frontend/UI/src/data/platforms/aws/index.ts] Removed static emulations/detections/playbooks data (all now backend-driven)

### Decisions
- Detections are per-emulation, not per-platform — more logical given each emulation has its own MITRE coverage
- Old /api/simulations/ endpoints are no longer called by the frontend; old static data files in data/platforms/aws/ are emptied
- The MANIFEST.py is the single source of truth for all emulation metadata including UI fields — no duplication in attack.py
- schema_version:1 introduced as the versioning contract for the emulation package format
- 403 from any emulation endpoint surfaces as a dedicated "Enterprise account required" message rather than a generic error

### Discussion Summary
- Decision to implement emulations as a content pipeline (apt_pipeline tool) → emulations/ packages → platform API → enterprise user
- Git is the deployment mechanism: committing a new emulations/{name}/ package causes it to be auto-discovered at next Docker build
- Static frontend data layer (data/platforms/aws/) was always a temporary TODO-placeholder — this session completes the swap to real API calls

## 2026-05-10
### Changes
- [frontend/UI/src/components/auth/LoginPage.tsx] Refactored login page from a centered single-column card to a **two-column SaaS-grade split layout** (max `min(960px, 92vw)`) with a deep double-ring inset box-shadow card
- [frontend/UI/src/components/auth/LoginPage.tsx] Added **left brand panel** (`#101111` surface, `border-right` separator): MayaTrail logo + wordmark, product tagline headline, 3 feature bullet points with `#FF6363` icon accents, monospace usage disclaimer footer
- [frontend/UI/src/components/auth/LoginPage.tsx] Replaced heavy segmented tab bar with **inline contextual switch links** ("No account? Create one →" / "Already have an account? Sign in →") placed under the form heading
- [frontend/UI/src/components/auth/LoginPage.tsx] Changed `PrimaryButton` from white pill (86px border-radius, dark text) to **solid `#FF6363` rectangular button** (6px radius, white text) matching the reference image's SaaS CTA style
- [frontend/UI/src/components/auth/LoginPage.tsx] Removed `AsciiArtBackground`, `FloatingDotsBackground`, red/green corner glow blobs — replaced with a single static subtle grid overlay (`rgba(255,255,255,0.03)`, 48px cells)
- [frontend/UI/src/components/auth/LoginPage.tsx] Removed unused `TabButton` component (no longer referenced after switching to inline links)
- [frontend/UI/src/components/auth/LoginPage.tsx] Retained all auth logic untouched: `SignInForm`, `SignUpForm`, `ForgotPasswordForm`, `ResetPasswordOTPForm`, `OTPVerificationForm`, `GoogleSignInButton`, `ErrorBanner`, `InputErrorIcon`, `FormField`

### Decisions
- Removed decorative backgrounds (ASCII art, floating dots, glows) to shift from a "fancy app" aesthetic to a clean, functional SaaS tool aesthetic — inspired by Linear, Vercel, Supabase
- Left panel deliberately contains no imagery — only copy and feature bullets — so focus stays on the form and the value proposition communicates without visual noise
- `PrimaryButton` red CTA (`#FF6363`) matches the DESIGN.md Raycast Red accent; rectangular shape (not pill) signals "action" rather than "marketing CTA"
- Tab switch is now zero-chrome — just a red inline link — reduces visual weight on the form side where density is already high
- All auth logic, error states, OTP flows, Google SSO, and forgot-password multi-step remain fully intact

### Discussion Summary
- User shared a reference image of a two-panel login UI (photo left / form right) and asked to refactor the login page to that style while following DESIGN.md tokens
- After initial plan, user clarified the page should feel like a SaaS application (not a marketing/fancy app), which drove removal of animations and decorative layers
- Final result: clean split-card layout with left brand panel and right minimal form — TypeScript-clean, zero new dependencies

## 2026-05-10 (ConnectorPage)
### Changes
- [frontend/UI/src/components/auth/ConnectorPage.tsx] Removed `AsciiArtBackground`, `FloatingDotsBackground`, radial-mask grid, and corner glow blobs
- [frontend/UI/src/components/auth/ConnectorPage.tsx] Wrapped entire page content in a **bordered outer card** (`min(1100px, 94vw)`, 16px radius, same double-ring inset box-shadow as LoginPage)
- [frontend/UI/src/components/auth/ConnectorPage.tsx] Added **brand bar** at top of card (`#101111` surface, border-bottom): logo + "MayaTrail / Cloud Connectors" breadcrumb + Support and Sign Out actions relocated here
- [frontend/UI/src/components/auth/ConnectorPage.tsx] Changed primary "Verify & Connect" button from white pill (9999px radius, dark text) to **solid `#FF6363` rectangular button** (6px radius, white text) — consistent with LoginPage `PrimaryButton`
- [frontend/UI/src/components/auth/ConnectorPage.tsx] Simplified card footer: duplicate Support/Sign-Out links removed (now in brand bar); upgrade flow shows only "← Back to Profile" ghost link; standard flow shows inline "Contact support" text link
- [frontend/UI/src/components/auth/ConnectorPage.tsx] Grid background updated to static `rgba(255,255,255,0.03)` / 48px cells (matching LoginPage, no radial mask)
- [frontend/UI/src/components/auth/ConnectorPage.tsx] All auth logic, IAM form, provider dropdown, error states, demo/upgrade flows, policy reference panel untouched

### Decisions
- Brand bar replaces the per-card footer links — one consistent location for nav actions avoids duplication across the connector and helper info cards
- Outer card pattern mirrors LoginPage exactly: same `border`, `borderRadius`, `boxShadow` — the two auth pages now feel like a unified flow
- `#FF6363` CTA matches LoginPage's `PrimaryButton` — consistent action color throughout the auth journey

## 2026-04-09
### Changes
- [backend/apps/users/models.py] Added `google_sub` CharField and `auth_method` property to User model
- [backend/apps/users/serializers.py] Added `GoogleOAuthSerializer` — verifies Google ID token, resolves/creates user (3 cases: returning SSO user, email link, new user); updated `MayaTrailTokenObtainPairSerializer.get_token()` to include `auth_method` claim; added `auth_method` SerializerMethodField to `UserSerializer`
- [backend/apps/users/views.py] Added `GoogleOAuthView` — POST `/api/auth/google/`, verifies token via serializer, issues JWT pair using `RefreshToken.for_user()`
- [backend/apps/users/urls.py] Registered `google/` route pointing to `GoogleOAuthView`
- [backend/apps/users/migrations/0001_initial.py] Created initial migration including all User fields (with `google_sub`) and EmailOTP model
- [backend/config/settings/base.py] Added `GOOGLE_CLIENT_ID` setting (from env var)
- [backend/requirements.txt] Added `google-auth==2.29.0`
- [backend/.env.example] Added `GOOGLE_CLIENT_ID=` with documentation comment
- [frontend/UI/index.html] Added Google Identity Services `<script>` tag
- [frontend/UI/.env] Added `VITE_GOOGLE_CLIENT_ID=` with documentation comment
- [frontend/UI/src/services/auth.service.ts] Added `googleSSO(idToken)` function; updated `fetchMe` to read `auth_method` from `/auth/me/` response
- [frontend/UI/src/context/AuthContext.tsx] Added `googleSSO` method and exposed it in the context interface
- [frontend/UI/src/components/auth/LoginPage.tsx] Added global `Window.google` type declaration; added `GoogleSignInButton` component (GIS `renderButton` with polling for script load); integrated button with divider into both `SignInForm` and `SignUpForm`

### Decisions
- Google OAuth bypasses the invite code gate — Google's identity verification provides equivalent friction
- Account resolution order: `google_sub` match → email match (link accounts) → create new user
- New Google SSO users get `set_unusable_password()` — they always authenticate via Google
- Username for new SSO users derived from the email local part; numeric suffix appended on collision
- `VITE_GOOGLE_CLIENT_ID` left empty by default — the Google button only renders when the env var is set, making the feature opt-in per deployment
- GIS button uses `filled_black` theme with `width: 342` to match the card width

### Discussion Summary
- Decided Google OAuth users skip invite code requirement
- Google SSO on the sign-up tab completes registration and navigates directly (no OTP step)
- `RefreshToken.for_user()` calls through `MayaTrailTokenObtainPairSerializer.get_token()` so all custom claims (is_verified, is_demo, auth_method, etc.) are embedded in Google-issued tokens too

## 2026-02-26
### Changes
- [backend/requirements.txt] Created — Django 5, DRF, simplejwt, Celery, Redis, psycopg2, decouple, CORS headers, gunicorn
- [backend/.env.example] Created — template for all required environment variables
- [backend/manage.py] Created — Django CLI entry point
- [backend/config/__init__.py] Created — loads Celery app at startup via celery.py
- [backend/config/celery.py] Created — Celery app instance, autodiscovers tasks from all installed apps
- [backend/config/wsgi.py] Created — WSGI entry point for gunicorn
- [backend/config/asgi.py] Created — ASGI entry point for async servers
- [backend/config/urls.py] Created — root URL conf mounting all four app routers plus Django admin
- [backend/config/settings/base.py] Created — shared settings: INSTALLED_APPS, DRF (JWT auth), SimpleJWT, Celery, static files
- [backend/config/settings/dev.py] Created — DEBUG=True, CORS allow-all, local PostgreSQL via individual env vars
- [backend/config/settings/prod.py] Created — DEBUG=False, RDS via env vars, explicit CORS origins, security headers
- [backend/apps/users/] Created — custom User model (AbstractUser), RegisterView, MeView, JWT login/refresh endpoints
- [backend/apps/infrastructure/] Created — Stack model (UUID PK, 5 status choices, outputs JSONField), StackViewSet with deploy/destroy custom actions, Celery tasks wrapping `pulumi up/destroy`
- [backend/apps/simulations/] Created — SimulationRun model, trigger endpoint POST /run/, Celery task that dynamically imports src/simulations/<module> and captures stdout/stderr
- [backend/apps/logs/] Created — LogEntry model (immutable audit trail), read-only ViewSet filtered to the authenticated user's context
- [backend/Dockerfile] Created — Python 3.12-slim, psycopg2 system deps, gunicorn entrypoint
- [docker-compose.yml] Created at step1/ root — four services: db (postgres:16-alpine), redis (7-alpine), backend (Django), worker (Celery)

### Decisions
- Custom User model (AbstractUser) defined from the start to allow painless extension without auth model migration
- UUID primary keys on all domain models for API safety and future distributed use
- Celery tasks call into existing src/ code (subprocess for Pulumi, importlib for simulations) without modifying src/
- SRC_DIR computed as `Path(__file__).resolve().parents[4] / "src"` — no hardcoded absolute paths
- Logs app is read-only via API; entries are written programmatically by tasks/views only
- dev.py uses individual POSTGRES_* env vars (not a single DATABASE_URL string) for docker-compose compatibility
- DefaultRouter with trailing slashes to match the plan's URL structure

### Discussion Summary
- Built the full Django REST API backend as specified in the backend plan
- Four apps: users, infrastructure, simulations, logs
- Wires to existing Pulumi IaC and boto3 simulations in src/ via Celery without touching src/ code

## 2026-02-26 (testing fixes)
### Changes
- [backend/config/settings/base.py] Fixed BASE_DIR: parents[3] -> parents[2] (parents[3] is filesystem root / inside the container)
- [backend/apps/infrastructure/tasks.py] Fixed SRC_DIR: replaced parents[4] (IndexError in container) with parents[2].parent / "src"; added os.environ.get("SRC_DIR") override
- [backend/apps/simulations/tasks.py] Same SRC_DIR fix as infrastructure/tasks.py
- [docker-compose.yml] Added SRC_DIR=/src env var and ./src:/src:ro volume mount to backend and worker services

### Decisions
- SRC_DIR is computed as backend_dir.parent/src by default, overridable via SRC_DIR env var for Docker deployments
- src/ is mounted read-only (:ro) in the containers — tasks can read/run it but never write to it

## 2026-02-23
### Changes
- [architectures/frontend.md] Created frontend architecture documentation
- [architectures/backend.md] Created backend architecture documentation (Pulumi infra + simulations)
- [architectures/docker.md] Created Docker architecture documentation (both containers)
- [CLAUDE.md] Rewritten as a routing file with workflows, memory rules, and changelog tracking

### Decisions
- CLAUDE.md should stay under ~150 lines and act as a routing file; detailed architecture lives in `architectures/`
- Workflows follow a sequential pattern: Learning, Planning, Development, Testing, Deployment
- Memory updates are mandatory and automatic (no asking)

### Discussion Summary
- Discussed best practices for writing CLAUDE.md to reduce token usage while maintaining quality output
- Referenced old Windsurf rules (nuclei template project) as a workflow pattern to adapt

## 2026-02-22
### Changes
- [src/Dockerfile] Created infrastructure container using pulumi/pulumi-python:3.207.0
- [src/entrypoint.sh] Created container entrypoint for Pulumi stack management
- [src/.dockerignore] Created to exclude venvs, caches, and non-essential files
- [src/__main__.py] Resource names now use stack-aware naming via `pulumi.get_stack()`
- [src/Pulumi.yaml] Removed `virtualenv: venv` for Docker compatibility
- [README.md] Added Docker-based deployment section with team usage instructions

### Decisions
- Use S3 backend for Pulumi state (shared across team, each member has own stack)
- Stack naming convention: `dev-<username>` (e.g., dev-himan10, dev-ayush)
- EC2 Instance Role for AWS credentials instead of env vars when running on EC2
- Docker image defaults to `preview` action for safety

### Discussion Summary
- Evaluated whether Pulumi setup should be containerized — concluded yes, for team consistency
- Discussed how Pulumi state management works with Docker on EC2
- Explained why manual boto3 existence checks conflict with Pulumi's declarative model
