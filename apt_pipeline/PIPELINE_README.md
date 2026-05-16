# MayaTrail APT Emulation Pipeline v2

An internal content authoring tool that transforms APT threat intelligence articles into complete, human-verified adversary emulation packages — infrastructure code, attack scripts, detection rules, IR playbooks, and guardrail policies.

This pipeline is **not customer-facing**. It is the factory that produces the pre-built emulation library shipped inside the MayaTrail platform. Every output is reviewed by a human before it reaches the product.

---

## What It Produces

For every APT article or MITRE technique you feed it, the pipeline generates a complete emulation package:

```
emulation_output/{run_id}/
│
├── run_manifest.json              # Full run metadata, phase timings, token costs, tool versions
├── security_posture.json          # Phase 0A: AWS security services status
├── article.txt                    # Fetched article content (cached for --resume)
├── ti_extract.json                # Phase 0B: Structured threat intel (canonical source of truth)
├── phase0b_metadata.json          # Phase 0B call-1 output (metadata only)
├── phase0b_techniques.json        # Phase 0B call-2 output (techniques array)
├── cost_estimate.json             # Standing + per-run cost breakdown
│
├── infra_plan.json                # Phase 1: Sonnet's infrastructure plan
├── infra_plan_approved.json       # Phase 2: Opus-approved version
├── PHASE-2_iterations/            # All review loop iterations preserved
│
├── attack_plan.json               # Phase 3: Sonnet's attack plan
├── attack_plan_approved.json      # Phase 4: Opus-approved version
├── PHASE-4_iterations/            # All review loop iterations preserved
│
├── infra/                         # Phase 5A: Complete Pulumi Python project
│   ├── Pulumi.yaml
│   ├── Pulumi.dev.yaml            # Stack config (provider URLs, secrets)
│   ├── __main__.py                # Infrastructure + UserData + auto-trigger hook
│   ├── requirements.txt
│   ├── resource_names.json        # ★ Resource name contract (see below)
│   └── requirements.json          # ★ Machine-readable prerequisites for MayaTrail (see below)
│
├── emulation_scripts/
│   └── attack.py                  # Phase 5B: Credential-chaining attack script
│
├── PREFLIGHT.md                   # Provider credentials + env vars needed before pulumi up
│
└── detections/                    # Phase 6A/6B/6C outputs
    ├── sigma_T1078_004.yml        # SIGMA rules for control_plane techniques
    ├── kql_T1078_004.kql          # KQL queries for Microsoft Sentinel
    ├── detection_note_T1190.md    # Detection notes for data_plane techniques
    ├── ir_playbooks/
    │   └── playbook_{actor}.md    # Phase 6B: SANS PICERL IR playbook
    └── guardrails/                # Phase 6C: SCP / Azure Policy / GCP Org Policy
```

---

## Prerequisites

### Required Tools

```bash
# Claude Code CLI — authenticated with Pro/Max subscription
claude --version

# Pulumi CLI
pulumi version

# Python 3.11+
python3 --version
```

### Installation

```bash
# Extract the pipeline
tar xzf apt_pipeline.tar.gz
cd apt_pipeline

# Install Python dependencies
pip install -r requirements.txt
```

### Optional

```bash
# AWS CLI — needed for Phase 0A security posture check
# Not required for authoring-only mode (the pipeline works without it)
aws sts get-caller-identity --profile sandbox
```

---

## Quick Start

### Generate from an APT article

```bash
python pipeline.py --url https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
```

The pipeline fetches the article, extracts threat intelligence, plans infrastructure, plans the attack chain, reviews both plans with Opus, generates all code, detection rules, playbooks, and guardrails. Human gates pause at three checkpoints for your review.

### Generate from a single MITRE technique

```bash
python pipeline.py --technique T1078.004
```

Skips article fetch. Sonnet creates a self-contained TI extract from its knowledge of the ATT&CK technique, then proceeds through the same pipeline.

### Plan only (no code generation)

```bash
python pipeline.py --url https://example.com/apt-article --plan-only
```

Stops after Phase 4 (attack plan approved). Useful for validating TI extraction and planning accuracy before committing to code generation.

### Auto-approve human gates (for testing)

```bash
python pipeline.py --technique T1552.005 --auto-approve
```

Skips all three human gates. **Never use this for content that will ship to the product** — it is strictly for testing the pipeline's end-to-end flow.

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--url <url>` | — | APT article URL (full-apt mode) |
| `--technique <id>` | — | MITRE ATT&CK technique ID (single-technique mode) |
| `--resume [RUN_ID]` | latest | Resume a previous run; skips completed phases |
| `--auto-approve` | off | Skip all human gates (testing / CI only) |
| `--plan-only` | off | Stop after Phase 4 (planning), no code generation |
| `--playbook-only` | off | Phase 6: generate IR playbook only (skip SIGMA + guardrails) |
| `--max-iterations <n>` | 3 | Opus review-loop iteration cap |
| `--max-concurrency <n>` | 2 | Max simultaneous Claude calls within a phase (1 = serial) |
| `--test-mode` | off | Override `attack.py` delays with 2–5 s values for iterative testing |
| `--skip-security-check` | off | Skip Phase 0A advisory check |
| `--skip-cost` | off | Skip cost estimation (use when AWS creds unavailable) |
| `--aws-profile <name>` | default | AWS profile for Phase 0A checks |
| `--aws-region <region>` | us-east-1 | AWS region for security checks |
| `--output-dir <path>` | emulation_output/ | Custom output root directory |

---

## Pipeline Architecture

### Phase Flow

```
                                  ┌─────────────────────────────────┐
                                  │         INPUT                   │
                                  │  APT Article URL  OR  T1234.001 │
                                  └──────────┬──────────────────────┘
                                             │
                                             ▼
                            ┌────────────────────────────────┐
                            │  PHASE 0A: Security Check      │
                            │  (advisory only — never blocks) │
                            │  Checks: CloudTrail, GuardDuty, │
                            │  SecurityHub status              │
                            └──────────┬─────────────────────┘
                                       │
                                       ▼
                            ┌────────────────────────────────┐
                            │  PHASE 0B: TI Extraction        │
                            │  Model: Sonnet (2 structured     │
                            │  calls with --json-schema flag) │
                            │  Call 1: metadata + kill_chain  │
                            │  Call 2: techniques array       │
                            │  → ti_extract.json (merged)     │
                            │  Three execution planes:        │
                            │    control / data / host        │
                            │  Credential chain mapping       │
                            │  IOC extraction                 │
                            │  Content-hash cache skips both  │
                            │  calls on repeated URLs         │
                            └──────────┬─────────────────────┘
                                       │
                              ⛔ HUMAN GATE: Review TI Extract
                                       │
                                       ▼
                            ┌────────────────────────────────┐
                            │  PHASE 1: Infrastructure Plan   │
                            │  Model: Sonnet                  │
                            │  Three resource categories:     │
                            │    attack_surface / target / bait│
                            │  UserData actions for host_plane│
                            │  Vulnerable app specification   │
                            └──────────┬─────────────────────┘
                                       │
                                       ▼
                            ┌────────────────────────────────┐
                            │  PHASE 2: Infra Review Loop     │◄──┐
                            │  Model: Opus                    │   │
                            │  Reviews: isolation, attack     │   │ max
                            │  surface, bait realism, cost    │   │ 3x
                            │                                 │───┘
                            │  APPROVED ──→ continue          │
                            │  REVISION ──→ Sonnet redrafts   │
                            └──────────┬─────────────────────┘
                                       │
                              ⛔ HUMAN GATE: Review Resources
                                       │
                                       ▼
                            ┌────────────────────────────────┐
                            │  PHASE 3: Attack Planning       │
                            │  Model: Sonnet                  │
                            │  Credential chaining across     │
                            │  phases (stolen creds flow)     │
                            │  8 execution contexts:          │
                            │    api/container/host/sso/...    │
                            │  Operational tempo (delays)     │
                            └──────────┬─────────────────────┘
                                       │
                                       ▼
                            ┌────────────────────────────────┐
                            │  PHASE 4: Attack Review Loop    │◄──┐
                            │  Model: Opus                    │   │
                            │  Reviews: credential chain,     │   │ max
                            │  fidelity, detection coverage,  │   │ 3x
                            │  safety, operational tempo      │   │
                            │                                 │───┘
                            │  APPROVED ──→ continue          │
                            │  REVISION ──→ Sonnet redrafts   │
                            └──────────┬─────────────────────┘
                                       │
                              ⛔ HUMAN GATE: Review Attack Plan
                                       │
                        ┌───────────────┴──────────────┐
                        │ (stops here if --plan-only)  │
                        ▼                              ▼
           ┌─────────────────────┐       ┌─────────────────────────┐
           │  PHASE 5A: Pulumi   │       │  PHASE 5B: attack.py    │
           │  Model: Opus        │       │  Model: Opus             │
           │  __main__.py with   │       │  Single file with        │
           │  all infra + auto-  │       │  credential chaining +   │
           │  trigger hook       │       │  operational delays      │
           │                     │       │                          │
           └────────┬────────────┘       └────────┬────────────────┘
                    │                              │
                    └───────────┬──────────────────┘
                                │
                    ┌───────────┴──────────────┐
                    │  VALIDATION              │
                    │  Tier 1: AST syntax      │
                    │  Tier 2: Import check    │
                    │  Tier 3: boto3 API index │
                    │  Cross-val: resource     │
                    │  names.json contract +   │
                    │  5B retry loop (2x)      │
                    └───────────┬──────────────┘
                                │
                  ┌─────────────┼──────────────────┐
                  ▼             ▼                   ▼
     ┌──────────────┐  ┌────────────────┐  ┌───────────────┐
     │ PHASE 6A:    │  │ PHASE 6B:      │  │ PHASE 6C:     │
     │ Detection    │  │ IR Playbooks   │  │ Guardrails    │
     │ Rules        │  │ SANS PICERL    │  │ SCP/RCP/IAM   │
     │ SIGMA + KQL  │  │ with real CLI  │  │ policy JSON   │
     │ Model: Opus  │  │ Model: Sonnet  │  │ Model: Sonnet │
     └──────────────┘  └────────────────┘  └───────────────┘
                                │
                                ▼
                      ┌──────────────────┐
                      │  ✅ COMPLETE      │
                      │  Summary printed │
                      │  Token costs     │
                      └──────────────────┘
```

### Model Assignment

| Phase | Model | Why |
|-------|-------|-----|
| 0B TI Extraction | Sonnet | First-draft work — cheaper, faster, good at structured extraction |
| 1 Infra Planning | Sonnet | Structured planning — Sonnet handles this well |
| 2 Infra Review | **Opus** | Quality gate — catches over-provisioning, isolation gaps, missing resources |
| 3 Attack Planning | Sonnet | Structured planning with MITRE mappings |
| 4 Attack Review | **Opus** | Quality gate — validates credential chain, detection completeness, fidelity |
| 5A Pulumi Code | **Opus** | Critical code gen — must produce working IaC with UserData |
| 5B Attack Script | **Opus** | Critical code gen — credential chaining, RCE via HTTP, error handling |
| 6A Detection Rules | **Opus** | Requires precise CloudTrail field taxonomy |
| 6B IR Playbooks | Sonnet | Long-form content generation — Sonnet handles well |
| 6C Guardrails | Sonnet | Policy JSON generation from known patterns |

### Human Gates

Three checkpoints pause the pipeline for operator review:

| Gate | After Phase | What You Review | Why |
|------|-------------|-----------------|-----|
| TI Extract | 0B | Techniques, execution planes, credential chain | Foundation of everything — wrong here = wrong everywhere |
| Infrastructure | 2 | Resource list, attack surface config, bait realism | Last chance before Opus generates code |
| Attack Plan | 4 | Attack steps, credential flow, expected detections | Last chance before code generation |

Each gate accepts: `APPROVED`, `OVERRIDE` (force continue), `ABORT` (stop pipeline), `SKIP`.

---

## Core Concepts

### Three Execution Planes

Every technique operates on one of three planes. Many threat actors use techniques that are invisible to CloudTrail — for example, data-plane actions like IMDS credential theft or SaaS OAuth token replay generate zero audit log events.

| Plane | Description | Audit-Visible | Examples |
|-------|-------------|---------------|----------|
| **control_plane** | Cloud/SaaS API calls | ✅ Yes | `iam:ListUsers`, `cloudtrail:StopLogging`, Okta user creation, GitHub repo clone |
| **data_plane** | HTTP/network-level | ❌ No | IMDS credential theft, container RCE via HTTP, OAuth token replay, SaaS data download |
| **host_plane** | OS-level commands | ❌ No | `iptables -F`, `history -cw`, credential sweep, persistence mechanisms |

The TI extractor classifies every technique into one of these planes. This ensures the pipeline never hallucinates audit events for techniques that don't generate them, and generates appropriate alternative detection guidance for non-audit-visible techniques.

### Credential Chaining

Real APTs don't use separate credentials per technique — they steal creds in one phase and reuse them across all subsequent phases. The pipeline models this explicitly:

The specific credential chain depends on the threat actor:

- **Cloud-focused**: IMDS creds -> STS session -> API calls -> lateral movement via tfstate keys
- **Identity-focused**: Phished IDP creds -> SAML federation -> cloud API access
- **SaaS-focused**: Stolen OAuth/PAT tokens -> SaaS API access -> lateral to cloud

The implementor generates a **single `attack.py`** that manages these sessions internally — not separate scripts per technique.

### Resource Categories

Infrastructure resources serve one of four purposes:

| Category | Description | Examples |
|----------|-------------|----------|
| **attack_surface** | Infrastructure that IS the vulnerability | EC2 with IMDSv1, IDP with weak MFA, OAuth app with broad scopes, over-privileged IAM role |
| **target** | Resources the attacker discovers/exfiltrates | S3 buckets, Lambda functions, SecretsManager secrets, source code repos |
| **bait** | Resources that exist to be DISCOVERED | terraform.tfstate with embedded creds, canary tokens, honey IAM users |
| **support** | Lab infrastructure | VPCs, subnets, security groups, log buckets |

### `resource_names.json` — The Resource Name Contract

Every emulation package includes `infra/resource_names.json`. This file is the **single source of truth** for all resource names and eliminates the class of bugs where `attack.py` uses Pulumi logical names (e.g. `"lucr3-secrets-prod-db"`) instead of actual AWS names (e.g. `"prod/database/master_credentials"`).

**Written by**: the infra implementor (Phase 5A) alongside `__main__.py`.
**Read by**: `attack.py` at startup, and the UI for attack path visualization.

```json
{
  "campaign": "CAMPAIGN-NAME",
  "csp": "aws | azure | gcp | multi",
  "resources": {
    "trail_name":       "my-cloudtrail",
    "secret_prod_db":   "prod/database/master_credentials",
    "honey_user_name":  "svc-terraform-automation"
  },
  "pulumi_export_keys": {
    "bucket_name":          "bucket_name",
    "victim_access_key_id": "victim_access_key_id",
    "ec2_instance_id":      "ec2_instance_id"
  }
}
```

| Section | Contains | Used for |
|---------|----------|----------|
| `resources` | **Static** AWS names — known at author time, never change across deployments | `_r("key")` in attack.py; prevents boto3 calls using wrong names |
| `pulumi_export_keys` | **Dynamic** semantic-key → Pulumi export-key mapping | `_p(infra, "key")` in attack.py; UI queries for live resource IDs/ARNs |

**`attack.py` boilerplate** (generated by Phase 5B for every new campaign):

```python
import pathlib, json, os

_NAMES_FILE = pathlib.Path(__file__).parent.parent / "infra" / "resource_names.json"
_NAMES = json.loads(_NAMES_FILE.read_text()) if _NAMES_FILE.exists() else {"resources": {}, "pulumi_export_keys": {}}
_R   = _NAMES.get("resources", {})
_PKS = _NAMES.get("pulumi_export_keys", {})

def _r(key, env_var=None, default=""):
    """Static name from resource_names.json, env var fallback."""
    return _R.get(key) or (os.environ.get(env_var, default) if env_var else default)

def _p(infra, key, env_var=None, default=""):
    """Dynamic Pulumi export via pulumi_export_keys indirection."""
    export_key = _PKS.get(key, key)
    return infra.get(export_key) or (os.environ.get(env_var, default) if env_var else default)
```

**`__main__.py` boilerplate** (sourcing constants from the JSON):

```python
import pathlib, json

_NAMES_FILE = pathlib.Path(__file__).parent / "resource_names.json"
_NAMES = json.loads(_NAMES_FILE.read_text()) if _NAMES_FILE.exists() else {"resources": {}, "pulumi_export_keys": {}}
_R = _NAMES.get("resources", {})

def _rn(key, default=""):
    return _R.get(key, default)

TRAIL_NAME   = _rn("trail_name",   "my-cloudtrail")
SECRET_DB    = _rn("secret_prod_db", "prod/database/master_credentials")
```

**Rules:**
- Static names (constant across all deployments, e.g. secret paths) → `resources` section
- Dynamic names (change per deployment, e.g. bucket IDs, instance IPs, access key IDs) → `pulumi_export_keys` section
- Campaigns where all names are stack-suffixed (e.g. Codefinger) → `resources: {}`, all names in `pulumi_export_keys`

**Cross-validation** (run automatically by the pipeline after Phase 5B): if `resources` is non-empty, `validators.cross_validate_phase5()` checks that both `__main__.py` and `attack.py` load `resource_names.json`. It also detects Pulumi logical names used as string literals in boto3 calls and flags mismatched export keys.

---

### `requirements.json` — Machine-Readable Prerequisites

Every emulation package includes `infra/requirements.json`. This file is read by the **MayaTrail platform before allowing execution** to validate that all required credentials, configuration, and packages are present. It replaces the manual checklist in `PREFLIGHT.md` with a structured, machine-parseable format.

**Written by**: the infra implementor (Phase 5A) alongside `resource_names.json`.
**Read by**: MayaTrail platform (pre-flight checks), and humans inspecting what a campaign needs.

```json
{
  "campaign": "CODEFINGER",
  "csp": "aws",
  "providers": {
    "aws": {
      "required": true,
      "credentials": [
        {"env_var": "AWS_ACCESS_KEY_ID",     "description": "AWS access key ID"},
        {"env_var": "AWS_SECRET_ACCESS_KEY", "description": "AWS secret access key"},
        {"env_var": "AWS_DEFAULT_REGION",    "description": "AWS region", "default": "us-east-1"}
      ],
      "min_permissions": ["s3:*", "iam:*", "cloudtrail:*", "sts:GetCallerIdentity"]
    }
  },
  "pulumi_config": [
    {
      "key": "mystack:some_config_key",
      "required": true,
      "description": "What this value is",
      "secret": false,
      "how_to_get": "Step-by-step instructions"
    }
  ],
  "attack_env_vars": [
    {
      "env_var": "PULUMI_CONFIG_PASSPHRASE",
      "required": true,
      "description": "Pulumi stack passphrase",
      "how_to_get": "Set any secure passphrase before pulumi up; reuse here"
    }
  ],
  "python_packages": ["pulumi>=3.0.0,<4.0.0", "pulumi-aws>=7.0.0,<8.0.0", "boto3>=1.38.0"]
}
```

| Field | What it contains | Who reads it |
|-------|-----------------|--------------|
| `providers` | Pulumi provider credentials (env vars) + minimum IAM/RBAC permissions | MayaTrail: validates env vars exist before deploy |
| `pulumi_config` | Values set via `pulumi config set` — stored in `Pulumi.dev.yaml`, NOT env vars | MayaTrail: prompts operator to set missing config |
| `attack_env_vars` | Env vars needed when `attack.py` runs (post-deploy) — always includes `PULUMI_CONFIG_PASSPHRASE` | MayaTrail: validates env vars exist before attack |
| `python_packages` | Contents of `requirements.txt` as an array | MayaTrail: checks package availability before deploy |

**Distinction: `pulumi_config` vs `attack_env_vars`**
- `pulumi_config` entries are set with `pulumi config set [--secret]` and live in `Pulumi.dev.yaml`. They are consumed by `__main__.py` via `pulumi.Config()`.
- `attack_env_vars` entries are shell environment variables available when `attack.py` runs. They include `PULUMI_CONFIG_PASSPHRASE` (always required), any attacker-controlled tokens, and fallback values for Pulumi outputs.

**Schema file**: `agents/schemas/requirements.json` — full JSON Schema (Draft 2020-12) used for validation.

---

### Emulation Categories

Every technique is categorized by safety:

| Category | Description | Example |
|----------|-------------|---------|
| **emulated** | Fully executable in sandbox | `iam:CreateUser`, `cloudtrail:StopLogging` |
| **simulated** | Approximated for safety | Cryptominer (bash loop, not real binary) |
| **documented** | Described but NOT executed | Exfil to external C2 (safety/legal reasons) |

---

## File Structure

```
apt_pipeline/
│
├── pipeline.py              # Main orchestrator — CLI, phase sequencing, human gates
│                              730 lines. Entry point. Run with: python pipeline.py [options]
│
├── utils.py                 # Core utilities shared across all phases
│                              578 lines. Contains:
│                              • call_claude()     — Claude CLI invocation with retries
│                              • extract_json()    — JSON extraction from LLM output
│                              • extract_code_blocks() — Code block extraction from responses
│                              • human_gate()      — Interactive approval checkpoints
│                              • review_loop()     — Opus review → Sonnet redraft loop
│                              • fetch_article()   — URL → clean article text via Claude
│                              • Token tracking, manifest management, logging
│
├── validators.py            # Validation stack
│                              Contains:
│                              • Tier 1: AST syntax check (ast.parse)
│                              • Tier 2: Import validation (package allowlist)
│                              • Tier 3: boto3 API index (runtime introspection)
│                              • Tier 4: JSON schema validation (pipeline outputs)
│                              • Tier 5: SIGMA rule validation (YAML structure + fields)
│                              • cross_validate_phase5(): resource_names.json contract
│                                checks + export key consistency between infra and attack
│
├── requirements.txt         # Python dependencies: requests, boto3, pyyaml
│
├── agents/                  # LLM agent prompt files — composable overlays
│   ├── sonnet_ti_extractor.md            # Phase 0B — Article → structured TI JSON
│   ├── sonnet_infra_planner.md           # Phase 1  — TI → infrastructure plan
│   ├── opus_infra_reviewer.md            # Phase 2  — Opus reviews infra
│   ├── sonnet_attack_planner.md          # Phase 3  — Plans → attack chain
│   ├── opus_attack_reviewer.md           # Phase 4  — Opus reviews attack plan
│   │
│   │   # Phase 5+6 implementor — split into base + task overlays + platform overlays
│   ├── opus_implementor_base.md          # Shared compat rules (all phases, all platforms)
│   ├── opus_implementor_infra.md         # TASK: IMPLEMENT INFRASTRUCTURE
│   ├── opus_implementor_attack.md        # TASK: IMPLEMENT ATTACK SCRIPT
│   ├── opus_implementor_detections.md    # TASK: GENERATE DETECTIONS
│   ├── opus_implementor_playbook.md      # TASK: GENERATE PLAYBOOK
│   ├── opus_implementor_guardrails.md    # TASK: GENERATE GUARDRAILS
│   ├── opus_implementor_compat_azure.md  # Azure-specific rules (auto-loaded for azure platform)
│   ├── opus_implementor_compat_gcp.md    # GCP-specific rules (auto-loaded for gcp platform)
│   ├── opus_implementor_legacy.md        # Original monolith (archived, not used)
│   │
│   └── schemas/                          # JSON Schema files (single source of truth)
│       ├── ti_metadata_schema.json       # JSON Schema for Phase 0B call 1
│       ├── ti_techniques_schema.json     # JSON Schema for Phase 0B call 2
│       ├── resource_names.json           # JSON Schema for infra/resource_names.json
│       └── requirements.json             # JSON Schema for infra/requirements.json
│
└── emulation_output/        # Pipeline outputs (auto-created per run)
    └── {YYYYMMDD_HHMMSS}/   # Timestamped run directory
```

---

## How Each Component Works

### `pipeline.py` — The Orchestrator

The orchestrator is the entry point. It:

1. Parses CLI arguments and validates the environment (Claude CLI, Pulumi, Python)
2. Creates a timestamped output directory under `emulation_output/`
3. Executes phases 0A → 0B → 1 → 2 → 3 → 4 → 5 → 6 in sequence
4. Pauses at three human gates for operator review
5. Tracks all state in `run_manifest.json` for resumability
6. Prints a final summary with token costs

Each phase function (`phase_0b_ti_extraction`, `phase_1_infra_plan`, etc.) follows the same pattern:
- Load the appropriate agent prompt from `agents/`
- Construct a user prompt with context from previous phases
- Call Claude via `call_claude()`
- Extract JSON from the response via `extract_json()`
- Validate the output via `validate_json_schema()`
- Save the result and update the manifest

### `utils.py` — Core Utilities

**`call_claude(model, system_prompt, user_prompt, label)`**

Invokes Claude via the CLI: `claude --print --dangerously-skip-permissions --model <model>`. The system prompt (agent instructions) and user prompt (task context) are combined and piped via stdin. Retries up to 2 times with exponential backoff on failure. Returns the response text and estimated token usage.

**`extract_json(text)`**

Extracts JSON from LLM output. Handles three scenarios:
- Raw JSON (response starts with `{`)
- JSON inside `` ```json ``` `` code fences
- JSON embedded in prose (finds outermost `{...}` block using brace depth tracking)

When multiple JSON blocks are found, returns the largest (most complete).

**`review_loop(reviewer_agent, drafter_fn, initial_draft, ...)`**

The Opus review → Sonnet redraft loop. Opus reviews the current draft and outputs a JSON verdict: `APPROVED` or `REVISION_REQUIRED` with issues. If revision is needed, the drafter function (which calls Sonnet) redrafts with the feedback injected. Loops up to `max_iterations` times (default: 3). If max iterations are exhausted, asks the operator to `OVERRIDE` or `ABORT`.

**`human_gate(gate_id, display_content, prompt_text)`**

Displays content and waits for the operator to type a response: `APPROVED`, `OVERRIDE`, `ABORT`, or `SKIP`. Used at three checkpoints in the pipeline.

### `validators.py` — The 5-Tier Validation Stack

Every generated Python file passes through these validation tiers before the pipeline reports success:

**Tier 1 — AST Syntax (`ast.parse`)**
Catches syntax errors, indentation issues, unclosed brackets. If this fails, further validation is impossible — the pipeline reports the syntax error and stops validating that file.

**Tier 2 — Import Check**
Validates all `import` and `from X import Y` statements against an allowlist of known-good packages (boto3, pulumi, standard library, etc.). Catches hallucinated packages like `import aws_toolkit` that don't exist.

**Tier 3 — boto3 API Index**
The highest-ROI validation layer. Dynamically introspects the installed `boto3` package to build a complete index of valid services and methods. Then walks the AST to find every `boto3.client('service')` call and every `client.method()` call, and validates each against the index. Catches hallucinated methods like `s3.get_buckets()` (real: `s3.list_buckets()`) and fake services like `boto3.client('s3x')`. Uses Levenshtein distance to suggest corrections. The index is persisted to `~/.cache/aptpipeline/boto3_index.pkl` so it only costs 2–3 s once per machine, not per run.

**Tier 3B — Module Load**
Runs `exec_module` in a subprocess: `python -c "import importlib, importlib.util; ..."`. Catches undefined names, logic errors at import time, and missing relative imports that only surface when Python actually evaluates the module — not just when AST-parsing it. Advisory only (pipeline continues on failure), but the warning is surfaced prominently.

**Cross-validation — `cross_validate_phase5(infra_content, attack_content, resource_names)`**
Dedicated cross-file consistency check run after both Phase 5A and 5B complete. Checks:
- **0a/0b** — Both `__main__.py` and `attack.py` load `resource_names.json` (enforced only when `resources` section is non-empty — all-dynamic campaigns like Codefinger are exempt).
- **0c** — Coverage: every key in `resources` is referenced via `_r("key")` in `attack.py` (warning on unused keys).
- **0d** — Logical-name guard: detects Pulumi logical resource names (e.g. `"lucr3-secrets-prod-db"`) used as string literals in boto3 API calls.
- **6** — Export key consistency: every key `attack.py` reads via `infra.get()` / `_p()` is actually exported by `__main__.py` via `pulumi.export()`.
- **7** — `sts:AssumeRole` in victim IAM policy — only checked when `attack.py` actually calls `assume_role` (not fired for ransomware/data-exfil campaigns that never assume roles).
- **10** — Boto3 deprecation: catches removed methods and services.

When errors are found, the pipeline runs up to 2 automatic retries by feeding the error list back to the LLM as a correction prompt. Errors remaining after retries are logged and counted in `total_errors`.

**Tier 4 — JSON Schema**
Validates that structured pipeline outputs (`ti_extract.json`, `infra_plan.json`, `attack_plan.json`) contain all required fields. Checks enum values like `execution_plane` (must be `control_plane`, `data_plane`, or `host_plane`) and `resource_category` (must be `attack_surface`, `target`, `bait`, or `support`).

**Tier 5 — SIGMA Schema**
Validates generated SIGMA rules for required fields (`title`, `status`, `description`, `logsource`, `detection`), correct `logsource` structure (must have `product`, `category`, or `service`), detection logic (must have `condition` plus at least one selection), and valid `level`/`status` enum values. Warns about missing MITRE ATT&CK tags.

### Agent Prompts (`agents/*.md`)

Each agent file is a detailed system prompt defining the agent's identity, rules, output schema, and examples. The prompts are loaded at runtime and combined with user prompts before being sent to Claude.

**`sonnet_ti_extractor.md`** — Extracts structured threat intelligence. Defines the three execution planes, credential chaining, IOC extraction, emulation categorization, and the `cannot_safely_emulate` list.

**`sonnet_infra_planner.md`** — Plans infrastructure with three resource categories (attack_surface/target/bait), UserData actions for host-plane techniques, and vulnerable app specifications.

**`opus_infra_reviewer.md`** — Reviews infrastructure for attack surface correctness, sandbox isolation, bait realism, cleanup coverage, and cost sanity.

**`sonnet_attack_planner.md`** — Plans the attack chain with credential chaining, 8 execution contexts (api_attack, container_attack, host_attack, sso_attack, saas_attack, idp_attack, phishing_attack, lateral_movement), operational tempo, and cleanup manifests.

**`opus_attack_reviewer.md`** — Reviews the attack plan for credential chain integrity, execution plane accuracy, detection completeness, safety, and fidelity.

**`opus_implementor_*.md`** — The multi-mode code generator, split across composable overlay files. Each phase loads `base + [platform_compat] + task_overlay` (~40–60% smaller than the original monolith). Handles five tasks:

| Overlay | Task |
|---------|------|
| `opus_implementor_infra.md` | `IMPLEMENT INFRASTRUCTURE` — Pulumi project with UserData and auto-trigger hook |
| `opus_implementor_attack.md` | `IMPLEMENT ATTACK SCRIPT` — Single attack.py with credential chaining |
| `opus_implementor_detections.md` | `GENERATE DETECTIONS` — SIGMA rules + KQL queries with real CloudTrail field names |
| `opus_implementor_playbook.md` | `GENERATE PLAYBOOK` — SANS PICERL playbook with CLI commands |
| `opus_implementor_guardrails.md` | `GENERATE GUARDRAILS` — SCP/RCP/permission boundary JSON |

`opus_implementor_compat_azure.md` and `opus_implementor_compat_gcp.md` are appended automatically when the TI extract's `platform` field is `azure` or `gcp` respectively.

---

## Validation Details

### What the boto3 API Index Catches

The index is built at first use by introspecting the installed `boto3` package:

```python
session = boto3.Session()
for service in session.get_available_services():
    client = session.client(service, region_name="us-east-1")
    methods = [m for m in dir(client) if not m.startswith("_") and callable(getattr(client, m))]
    index[service] = set(methods)
```

This catches:
- **Hallucinated services**: `boto3.client('s3x')` → "unknown service 's3x'. Did you mean: s3, s3control, s3outposts?"
- **Hallucinated methods**: `s3.get_buckets()` → "'get_buckets' not valid for boto3 's3'. Similar: list_buckets, create_bucket, delete_bucket"
- **Wrong service/method combinations**: `iam.describe_instances()` → "'describe_instances' not valid for boto3 'iam'. Similar: list_users, get_user, create_user"

### What the Cross-Validator Catches

The `cross_validate_phase5()` function catches the most common class of runtime failures — mismatches between what `__main__.py` provisions and what `attack.py` expects:

| Check | What it catches | Severity |
|-------|----------------|----------|
| 0a/0b | Neither file loads `resource_names.json` (when static names exist) | Error |
| 0c | Keys in `resource_names.json["resources"]` not referenced in attack.py | Warning |
| 0d | Pulumi logical names (e.g. `"lucr3-secrets-prod-db"`) in boto3 calls | Error |
| 6 | `attack.py` reads infra keys that `__main__.py` doesn't export | Error |
| 7 | Victim IAM policy missing `sts:AssumeRole` when attack uses role assumption | Error |
| 10 | Removed boto3 methods / deprecated call patterns | Warning |

**Example**: before this validator, a generated `attack.py` could contain `secretsmanager.get_secret_value(SecretId="lucr3-secrets-prod-db")` — the Pulumi logical name, not the AWS path `"prod/database/master_credentials"`. The call would silently fail at runtime with `ResourceNotFoundException`. Check 0d now catches this at generation time and the retry loop regenerates the script.

### What the SIGMA Validator Catches

- Missing required fields (`title`, `logsource`, `detection`)
- Invalid `logsource` structure (must have at least one of `product`, `category`, `service`)
- Missing `condition` in `detection` block
- Detection with only `condition` and no selection (useless rule)
- Non-standard `level` or `status` values
- Missing MITRE ATT&CK `tags` (warning, not error)

---

## Output Details

### `ti_extract.json` — The Canonical Source of Truth

This file drives everything downstream. Key fields:

```json
{
  "status": "PHASE_0B_COMPLETE",
  "threat_actor": {"name": "{THREAT_ACTOR}", "motivation": "..."},
  "platform": "aws | azure | gcp | saas | identity_provider | multi_cloud",
  "targeted_services": ["Service1", "Service2"],
  "techniques": [
    {
      "mitre_id": "T1190",
      "name": "Exploit Public-Facing Application",
      "execution_plane": "data_plane",       // control_plane | data_plane | host_plane
      "execution_context": "container_attack", // api_attack | host_attack | container_attack
                                              // sso_attack | saas_attack | idp_attack
                                              // phishing_attack | lateral_movement
      "emulation_category": "emulated",      // emulated | simulated | documented
      "api_calls": [],                       // Empty for data_plane
      "data_plane_actions": ["..."],         // Non-API actions
      "expected_audit_events": [],           // Empty for data_plane
      "audit_visible": false,
      "detection_sources": ["Platform-appropriate sources"]
    }
  ],
  "credential_chain": [
    {"phase": 1, "source": "Credential source matching TI", "used_in_phases": [2,3,4,5,6]}
  ],
  "iocs": {"ip_addresses": [], "domains": [], "file_paths": []},
  "operational_notes": {
    "cannot_safely_emulate": [
      {"technique": "...", "reason": "...", "original_command": "..."}
    ]
  }
}
```

### `run_manifest.json` — State Tracking

Tracks every phase's status, timing, and metadata. Enables future `--resume` capability.

```json
{
  "run_id": "20260411_143022",
  "start_time": "2026-04-11T14:30:22Z",
  "phases": {
    "phase_0a": {"status": "complete", "services": {"CloudTrail": {"enabled": true}}},
    "phase_0b": {"status": "complete", "techniques": 12, "threat_actor": "{THREAT_ACTOR}",
                 "source": "fetch"},
    "phase_1":  {"status": "complete", "resources": 11,
                 "categories": {"attack_surface": 3, "target": 4, "bait": 3}},
    "phase_2":  {"status": "complete", "verdict": "APPROVED", "fell_back": false},
    "phase_3":  {"status": "complete", "steps": 15, "credential_pivots": 2},
    "phase_4":  {"status": "complete", "verdict": "APPROVED", "fidelity_score": 0.92,
                 "fell_back": false},
    "phase_5":  {"status": "complete", "infra_files": 4, "attack_files": 1,
                 "validation_errors": 0, "cross_validation_errors": 0,
                 "xval_retries": 0, "technique_coverage_pct": 100.0},
    "phase_6":  {"status": "complete", "sigma": 8, "kql": 8, "playbooks": 1,
                 "guardrails": 6},
    "pipeline": {
      "status": "complete",
      "tokens": {"total_tokens": 180000, "estimated_cost_usd": 14.20},
      "fallback_count": 0,
      "fallback_phases": [],
      "tool_versions": {
        "claude": "Claude Code 1.2.17",
        "pulumi": "3.105.0",
        "python": "Python 3.14.3",
        "tiktoken": "0.7.0",
        "trafilatura": "1.12.0"
      }
    }
  }
}
```

`phase_0b.source` is `"content_hash_cache"` when the TI extract was loaded from disk rather than re-extracted; `"fetch"` otherwise. `fallback_count`/`fallback_phases` are non-zero only when a review loop exhausted its iteration cap and fell back to the last draft automatically.

---

## After the Pipeline: Human Review Process

The pipeline produces a draft. Before shipping to the product:

1. **Review `ti_extract.json`** — Are the techniques correct? Are execution planes right? Is the credential chain accurate?

2. **Review generated Pulumi code** — Does `__main__.py` create the right attack surface? Are platform-specific configs correct? Is the UserData complete (if applicable)? Are bait resources realistic?

3. **Review `attack.py`** — Does the credential chain work? Are boto3 method calls correct? Are expected errors handled? Are delays realistic?

4. **Test in sandbox** — Deploy with `pulumi up`, run the attack script, verify it works end-to-end. Check CloudTrail for the expected events.

5. **Review detection rules** — Are SIGMA rules using correct field names? Do KQL queries work in Sentinel? Are data_plane detection notes helpful?

6. **Review the playbook** — Would a SOC analyst be able to follow this during a real incident? Are CLI commands correct?

7. **Register in backend** — Once verified, create `Emulation` + `EmulationStep` records in the Django backend. The emulation is now live in the product.

---

## Error Handling

| Failure | What Happens | Recovery |
|---------|-------------|----------|
| Article fetch fails | Pipeline exits with URL error | Fix URL, re-run |
| TI extraction returns invalid JSON | Raw output saved to `phase0b_raw.md` | Review raw output, fix agent prompt |
| Opus max review iterations (3x) | Pipeline pauses, asks OVERRIDE or ABORT | Review iteration files, decide |
| Human gate — ABORT | Pipeline exits cleanly, all outputs saved | Outputs preserved for inspection |
| Code validation finds errors | Warning printed, pipeline continues | Review validation errors in output |
| Claude CLI timeout (600s) | Retries up to 2x with backoff | Check model availability |
| Claude CLI not found | Pipeline exits with install instructions | Install Claude Code CLI |

---

## Cost Estimates

Typical pipeline run costs (approximate, based on token estimates):

| Mode | Sonnet Calls | Opus Calls | Est. Tokens | Est. Cost |
|------|-------------|-----------|-------------|-----------|
| Single technique | 3-4 | 3-4 | ~80K | ~$4-6 |
| Simple article (3-5 techniques) | 4-5 | 4-5 | ~120K | ~$8-12 |
| Complex APT (10+ techniques) | 5-6 | 5-7 | ~200K | ~$14-20 |
| Plan only (no code gen) | 3-4 | 2-3 | ~60K | ~$3-5 |

Token estimates are rough (1 token ≈ 4 characters). Actual costs depend on article length, technique count, and review loop iterations.

---

## Multi-Cloud Support

The pipeline is cloud-agnostic. The `platform` field in the TI extract (`aws`, `azure`, `gcp`, `saas`, `identity_provider`, `on_premises`, `multi_cloud`) routes all downstream phases automatically:

- **Infrastructure** — Pulumi provider selection, resource types, and auth patterns match the platform
- **Attack script** — SDK selection (boto3 / azure-mgmt / google-cloud) and credential flow match the platform
- **Detections** — Audit log field names (`CloudTrail eventName` vs `protoPayload.methodName` vs `azure.activityLogs`) match the platform
- **Playbooks** — CLI commands (`aws` / `az` / `gcloud`) match the platform

Platform-specific compatibility rules live in `agents/opus_implementor_compat_<platform>.md` and are automatically appended to the implementor prompt only when relevant.

---

## Caching

### Content-hash cache (Phase 0B)

Repeated runs against the same article URL skip Phase 0B entirely — both Claude calls **and** the HTTP fetch. The TI extract is keyed by SHA-256 of the URL:

```
~/.cache/aptpipeline/ti_cache/ti_<sha256[:16]>.json
```

Cache hit is recorded in the manifest as `"source": "content_hash_cache"`. Saves ~180 k tokens (~$0.54) per repeated run. To force re-extraction, delete the cache file or use a different URL.

### boto3 API index

The boto3 service/method index (used by the Tier 3 validator) is built once by introspecting the installed package and persisted across runs:

```
~/.cache/aptpipeline/boto3_index.pkl
```

Saves 2–3 s of introspection time per run after the first.

### EC2 price cache (cost estimator)

EC2 hourly prices are cached in-memory per `instance_type|os|region` key within a single pipeline run, avoiding repeated calls to the AWS Pricing API.

---

## Token Optimisation

| Optimisation | Saving |
|---|---|
| Agent file splitting (task + platform overlays) | ~12 k tokens/phase |
| TI extract projections (`ti_for_infra`, `ti_for_attack`, `ti_for_detections`) | 57–74% payload reduction per phase |
| Phase 0B article truncation (1 500 chars in call 2) | ~6 k tokens |
| Content-hash cache (skip Phase 0B on repeated URLs) | ~180 k tokens/run |
| **Total** | **~56 k tokens / ~$0.17 per run** |

### TI Extract Projections

Each downstream phase receives only the TI fields it actually needs, rather than the full `ti_extract.json`:

| Projection | Keeps | Drops |
|---|---|---|
| `ti_for_infra` | platform, targeted_services, credential_chain, resource_needs, userdata_actions | iocs, kill_chain_order, expected_audit_events, indicators_of_compromise |
| `ti_for_attack` | kill_chain_order, credential_chain, iocs, expected_audit_events, indicators_of_compromise | resource_needs, userdata_actions, targeted_services |
| `ti_for_detections` | kill_chain_order, iocs, expected_audit_events, execution_plane, tactic | credential_chain, targeted_services, resource_needs, userdata_actions |

---

## Resuming Runs

All phases record their completion status in `run_manifest.json`. To resume after a rate-limit, timeout, or interruption:

```bash
python pipeline.py --resume                    # resume the latest run
python pipeline.py --resume 20260415_120437    # resume a specific run
```

Completed phases are skipped automatically. The manifest also records:
- Tool versions (`claude`, `pulumi`, `python`, `tiktoken`, `trafilatura`) at run start
- Token usage and cost per model
- Review-loop fallback count (warned prominently if non-zero)

---

## Recent Changes

### Architecture
- **`requirements.json` prerequisites manifest**: New file generated by Phase 5A alongside `resource_names.json`. Machine-readable prerequisites consumed by the MayaTrail platform before allowing execution. Documents provider credentials (env vars + min IAM permissions), `pulumi config set` values, attack-time env vars, and Python packages. Schema at `agents/schemas/requirements.json`. All 6 existing emulations backfilled.
- **`resource_names.json` contract**: New file generated alongside `__main__.py` in Phase 5A. Splits resource names into `resources` (static, author-time) and `pulumi_export_keys` (dynamic, deploy-time). `attack.py` reads both sections via `_r()` / `_p()` helpers — eliminates the entire class of Pulumi logical-name vs. AWS-name mismatches. Also queryable by the UI for attack path visualization without parsing code.
- **Phase 5B retry loop**: When `cross_validate_phase5()` finds errors, the pipeline feeds them back to the LLM as a correction prompt and regenerates `attack.py` (up to 2 retries). Cross-validation errors now count in `total_errors` and are recorded in `run_manifest.json` as `cross_validation_errors` + `xval_retries`.
- **Agent file splitting**: monolithic `opus_implementor.md` (481 lines) split into `base` + 5 task overlays + 2 platform overlays. Each phase loads only the subset it needs (~40–60% token reduction vs. the monolith).
- **Platform overlays**: `opus_implementor_compat_azure.md` and `opus_implementor_compat_gcp.md` auto-loaded for Azure/GCP articles.
- **Schema single source of truth**: `TI_METADATA_JSON_SCHEMA`, `TI_TECHNIQUES_JSON_SCHEMA`, `resource_names.json` schema, and `requirements.json` schema extracted to `agents/schemas/*.json`; pipeline and validators load from the same files — no duplicated Python dicts.

### Performance
- **TI extract projections**: `ti_for_infra`, `ti_for_attack`, `ti_for_detections` reduce prompt payload by 57–74%.
- **Content-hash caching**: Phase 0B skipped entirely on repeated URLs (~180 k tokens saved per repeated run).
- **boto3 disk cache**: service/method index persisted to `~/.cache/aptpipeline/boto3_index.pkl` (saves 2–3 s per run after the first).
- **EC2 price in-memory cache**: Pricing API calls cached per `instance_type|os|region` key within a run.
- **Manifest loaded once**: `done()` checks read an in-memory dict instead of hitting disk 27× on resume.
- **Phase 0B article truncation**: Call 2 receives only the first 1 500 chars of the article (the kill_chain from call 1 already anchors the technique set).
- **Phase 1/3 timeouts**: Bumped from 300 s to 600 s to handle complex actors with 17+ techniques.

### Reliability
- **Phase 0B split**: Two structured calls with `--json-schema` flag prevent response truncation on large technique sets.
- **`extract_json` brace-matching**: Improved guardrails refuse fragments from truncated responses.
- **Schema validation**: Now blocks on critical missing fields instead of advisory-only warnings.
- **Review-loop fallback tracking**: `fallback_count`/`fallback_phases` recorded in manifest and surfaced at warn level in run summary when non-zero.
- **Article fetch validation**: `trafilatura` + `_looks_like_article` heuristic + length gate + wall-phrase detection.
- **Tier 3B module-load check**: `exec_module` in subprocess catches undefined names and logic errors at import time.

### Developer Experience
- **`--max-concurrency`**: New flag (default 2) caps simultaneous Claude calls within Phase 5 and Phase 6, preventing rate-limit bursts on restricted accounts.
- **`--test-mode`**: New flag overrides `attack.py` inter-step and inter-phase delays with 2–5 s values for faster iterative testing.
- **`--playbook-only`**: New flag generates only the IR playbook in Phase 6, skipping SIGMA rules and guardrails.
- **`--skip-cost`**: New flag skips cost estimation entirely (useful when AWS credentials are unavailable).
- **`--resume`**: New flag resumes the latest (or a named) interrupted run, skipping already-completed phases.
- **Tool versions in manifest**: `validate_environment()` now returns and stamps `claude`, `pulumi`, `python`, `tiktoken`, `trafilatura` versions into `run_manifest.json` at run start for reproducibility.
- **Zero-technique log fix**: Phase 0B now logs `⚠` at `warn` level (not green `✅`) when kill_chain or technique count is zero.
- **User-agent update**: `fetch_article` sends a current Chrome 124 UA string to reduce bot-detection hits.
- **strptime deprecation fix**: Rate-limit timestamp parsing now includes the year to avoid Python 3.15 breakage.

---

## Design Decisions

### Why Claude CLI instead of Anthropic SDK?

The CLI requires zero API key management — it uses the authenticated Claude Code session. For an internal tool run by the founder, this eliminates setup friction. If the pipeline ever moves to production (automated CI/CD), switching to the SDK is a one-function change in `call_claude()`.

### Why a single attack.py instead of per-technique scripts?

Real APTs execute as a continuous operation with credential chaining — they don't run separate scripts. A single `attack.py` managing stolen credentials across multiple phases produces dramatically more realistic behavior than separate scripts. Detection rules that correlate events across phases only work when the attack is a continuous flow.

### Why three execution planes?

Many threat actors use techniques that are invisible to audit logs. Without explicit plane classification, the pipeline would either hallucinate audit events for data_plane techniques (false confidence in detection coverage) or miss them entirely (incomplete emulation). The three-plane model forces every downstream phase to handle each technique correctly.

### Why Opus for review and implementation, Sonnet for planning?

Sonnet is 5x cheaper and ~2x faster than Opus. It excels at structured planning and content generation. Opus excels at catching edge cases, security nuances, and generating correct code. The split optimizes for both cost and quality — Sonnet produces good first drafts cheaply, Opus catches what Sonnet misses.
