"""
MayaTrail APT Pipeline v2 — Validation Layer
=============================================
5-tier validation catching hallucinations BEFORE code ships.

Tier 1: AST Parse — valid Python syntax?
Tier 2: Import Check — real packages?
Tier 3: boto3 API Index — real method calls?
Tier 4: JSON Schema — structured outputs match expected shape?
Tier 5: SIGMA Schema — detection rules have required fields?
"""

import ast
import json
import pickle
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

from utils import log

# Persistent disk cache for the boto3 service/method index.
# Building the index takes 2-3s (introspects ~250 services). Caching to disk
# means subsequent runs in the same environment pay zero rebuild cost.
_BOTO3_CACHE_PATH = Path.home() / ".cache" / "aptpipeline" / "boto3_index.pkl"


# ══════════════════════════════════════════════════════════════════════════
# TIER 1: AST Syntax Validation
# ══════════════════════════════════════════════════════════════════════════

def validate_python_syntax(code: str, filename: str = "<generated>") -> dict:
    """Parse Python code into AST. Returns {"valid": bool, "errors": list}"""
    try:
        ast.parse(code, filename=filename)
        return {"valid": True, "errors": []}
    except SyntaxError as e:
        return {"valid": False, "errors": [f"Line {e.lineno}: {e.msg}"]}


# ══════════════════════════════════════════════════════════════════════════
# TIER 2: Import Validation
# ══════════════════════════════════════════════════════════════════════════

ALLOWED_PACKAGES = {
    # AWS
    "boto3", "botocore",
    # Azure
    "azure", "msrest", "msrestazure", "msal", "msgraph",
    # GCP
    "google", "googleapiclient",
    # Identity providers
    "okta", "onelogin", "pysaml2",
    # SaaS SDKs
    "github", "pygithub", "slack_sdk", "slack", "atlassian",
    "jira", "confluence",
    # Auth / OAuth
    "requests_oauthlib", "oauthlib", "jwt", "jwcrypto", "cryptography",
    # Directory / LDAP
    "ldap3",
    # Pulumi (all providers)
    "pulumi", "pulumi_aws", "pulumi_azure_native", "pulumi_gcp",
    "pulumi_kubernetes", "pulumi_tls", "pulumi_azuread", "pulumi_okta",
    "pulumi_github",
    # Standard library
    "json", "os", "sys", "time", "datetime", "argparse", "logging",
    "pathlib", "subprocess", "hashlib", "base64", "uuid", "re", "io",
    "csv", "collections", "functools", "itertools", "typing",
    "dataclasses", "contextlib", "tempfile", "shutil", "glob",
    "signal", "random", "math", "string", "textwrap", "copy",
    "http", "urllib", "socket", "struct", "binascii", "hmac",
    "secrets", "getpass", "threading", "concurrent",
    # Third-party (from requirements.txt)
    "yaml", "requests", "colorama", "urllib3", "certifi",
}


def validate_imports(code: str) -> dict:
    """Check all imports reference real packages."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {"valid": False, "errors": ["Syntax error — cannot check imports"], "imports_found": []}

    errors = []
    imports_found = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                imports_found.append(alias.name)
                if root not in ALLOWED_PACKAGES:
                    errors.append(f"Line {node.lineno}: unknown package '{alias.name}'")

        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            imports_found.append(node.module)
            if root not in ALLOWED_PACKAGES:
                errors.append(f"Line {node.lineno}: unknown package '{node.module}'")

    return {"valid": len(errors) == 0, "errors": errors, "imports_found": imports_found}


# ══════════════════════════════════════════════════════════════════════════
# TIER 3: SDK API Validation
# Currently validates boto3 (AWS). Skips gracefully for non-AWS code.
# Future: add Azure SDK, GCP SDK, Okta SDK validation.
# ══════════════════════════════════════════════════════════════════════════

_boto3_index_cache = None


def _build_boto3_index() -> dict:
    """Introspect installed boto3 to build valid method index.

    Result is cached to disk at _BOTO3_CACHE_PATH so subsequent pipeline runs
    skip the 2-3s rebuild cost. The cache is a plain pickle of the index dict.
    """
    global _boto3_index_cache
    if _boto3_index_cache is not None:
        return _boto3_index_cache

    # Try loading from disk cache first
    if _BOTO3_CACHE_PATH.exists():
        try:
            with _BOTO3_CACHE_PATH.open("rb") as fh:
                _boto3_index_cache = pickle.load(fh)
            total = sum(len(v) for v in _boto3_index_cache.values())
            log("VALIDATE",
                f"boto3 index loaded from cache "
                f"({len(_boto3_index_cache)} services, {total} methods)", "ok")
            return _boto3_index_cache
        except Exception:
            pass  # Corrupted cache — fall through to rebuild

    try:
        import boto3
    except ImportError:
        log("VALIDATE", "boto3 not installed — skipping API index", "warn")
        return {}

    index = {}
    session = boto3.Session()
    for service in session.get_available_services():
        try:
            client = session.client(service, region_name="us-east-1")
            methods = [
                m for m in dir(client)
                if not m.startswith("_")
                and callable(getattr(client, m, None))
                and m not in ("meta", "exceptions", "waiter_names",
                              "get_paginator", "get_waiter", "can_paginate")
            ]
            index[service] = set(methods)
        except Exception:
            continue

    total_methods = sum(len(v) for v in index.values())
    log("VALIDATE", f"boto3 index: {len(index)} services, {total_methods} methods (rebuilt)", "ok")

    # Persist to disk for next run
    try:
        _BOTO3_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _BOTO3_CACHE_PATH.open("wb") as fh:
            pickle.dump(index, fh)
    except Exception:
        pass  # Non-fatal — in-memory cache still works

    _boto3_index_cache = index
    return index


def validate_boto3_calls(code: str) -> dict:
    """Validate boto3 client method calls against installed package."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {"valid": False, "errors": ["Syntax error"], "calls_checked": 0}

    index = _build_boto3_index()
    if not index:
        return {"valid": True, "errors": [], "calls_checked": 0}

    errors = []
    calls_checked = 0
    client_vars = {}  # var_name → service_name

    for node in ast.walk(tree):
        # Track boto3.client('service') assignments
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = node.value
            if _is_boto3_client_call(call):
                service = _extract_first_string_arg(call)
                if service:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            client_vars[target.id] = service
                            if service not in index:
                                similar = _closest_matches(service, index.keys(), 3)
                                errors.append(
                                    f"Line {node.lineno}: unknown boto3 service '{service}'. "
                                    f"Did you mean: {', '.join(similar)}?"
                                )

        # Also track session.client('service')
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Attribute) and call.func.attr == "client":
                service = _extract_first_string_arg(call)
                if service:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            client_vars[target.id] = service

        # Check client.method() calls
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                var = node.func.value.id
                method = node.func.attr
                if var in client_vars:
                    service = client_vars[var]
                    calls_checked += 1
                    if service in index and method not in index[service]:
                        similar = _closest_matches(method, index[service], 3)
                        errors.append(
                            f"Line {node.lineno}: '{method}' not valid for "
                            f"boto3 '{service}'. Similar: {', '.join(similar)}"
                        )

    return {"valid": len(errors) == 0, "errors": errors, "calls_checked": calls_checked}


def _is_boto3_client_call(node) -> bool:
    if isinstance(node.func, ast.Attribute) and node.func.attr == "client":
        if isinstance(node.func.value, ast.Name):
            return node.func.value.id == "boto3"
    return False


def _extract_first_string_arg(node) -> Optional[str]:
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


def _closest_matches(target: str, candidates, n: int = 3) -> list[str]:
    """Simple Levenshtein-based closest matches."""
    def _lev(s1, s2):
        if len(s1) < len(s2):
            return _lev(s2, s1)
        if not s2:
            return len(s1)
        prev = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
            prev = curr
        return prev[-1]

    scored = sorted(candidates, key=lambda c: _lev(target, c))
    return scored[:n]


# ══════════════════════════════════════════════════════════════════════════
# TIER 4: JSON Schema Validation
# ══════════════════════════════════════════════════════════════════════════

SCHEMAS = {
    "ti_extract": {
        # Critical: missing one of these means the extraction itself failed —
        # halt the pipeline. Advisory: descriptive metadata that downstream
        # phases don't strictly require; missing → warn, don't halt.
        "required_top_critical": ["status", "techniques"],
        "required_top_advisory": ["kill_chain_order", "targeted_services"],
        "required_per_technique": ["mitre_id", "name", "execution_plane", "emulation_category"],
        "valid_execution_planes": ["control_plane", "data_plane", "host_plane"],
        "valid_emulation_categories": ["emulated", "simulated", "documented"],
    },
    "infra_plan": {
        "required_top_critical": ["status", "resources"],
        "required_top_advisory": [],
        "required_per_resource": ["name", "pulumi_type", "purpose", "resource_category"],
        "valid_resource_categories": ["attack_surface", "target", "bait", "support"],
    },
    "attack_plan": {
        # script_manifest + credential_chain are advisory: Phase 5 can generate
        # attack.py from attack_chain alone, and not every actor has a credential
        # pivot (e.g., web-only or DDoS actors).
        "required_top_critical": ["status", "attack_chain"],
        "required_top_advisory": ["script_manifest", "credential_chain"],
        "required_per_step": ["step", "technique_id", "technique_name", "execution_context"],
        "valid_execution_contexts": [
            "api_attack", "host_attack", "container_attack",
            "sso_attack", "saas_attack", "idp_attack",
            "phishing_attack", "lateral_movement",
        ],
    },
}


def validate_json_schema(data: dict, schema_name: str) -> dict:
    """Validate pipeline output against expected schema.

    Returns a dict with:
      - valid: True iff no errors at all.
      - errors: full list of issues (critical + advisory).
      - critical_errors: subset that must halt the pipeline (missing
        critical top-level fields, malformed items, bad enum values).
      - advisory_errors: subset that should warn but not halt (missing
        descriptive metadata fields like `kill_chain_order`).
    """
    schema = SCHEMAS.get(schema_name)
    if not schema:
        return {"valid": True, "errors": [], "critical_errors": [], "advisory_errors": []}

    critical_errors = []
    advisory_errors = []

    # Top-level required fields — tiered
    for field in schema.get("required_top_critical", []):
        if field not in data:
            critical_errors.append(f"Missing critical top-level field: '{field}'")
    for field in schema.get("required_top_advisory", []):
        if field not in data:
            advisory_errors.append(f"Missing advisory top-level field: '{field}'")

    # Per-item errors and bad enums are always critical — a malformed item
    # or a typo'd enum value means downstream code will mishandle it silently.
    if "required_per_technique" in schema and "techniques" in data:
        for i, tech in enumerate(data["techniques"]):
            for field in schema["required_per_technique"]:
                if field not in tech:
                    critical_errors.append(f"techniques[{i}]: missing '{field}'")
            plane = tech.get("execution_plane")
            if plane and plane not in schema.get("valid_execution_planes", []):
                critical_errors.append(f"techniques[{i}]: invalid execution_plane '{plane}'")
            cat = tech.get("emulation_category")
            if cat and cat not in schema.get("valid_emulation_categories", []):
                critical_errors.append(f"techniques[{i}]: invalid emulation_category '{cat}'")

    if "required_per_resource" in schema and "resources" in data:
        for i, res in enumerate(data["resources"]):
            for field in schema["required_per_resource"]:
                if field not in res:
                    critical_errors.append(f"resources[{i}]: missing '{field}'")

    if "required_per_step" in schema and "attack_chain" in data:
        for i, step in enumerate(data["attack_chain"]):
            for field in schema["required_per_step"]:
                if field not in step:
                    critical_errors.append(f"attack_chain[{i}]: missing '{field}'")

    errors = critical_errors + advisory_errors
    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "critical_errors": critical_errors,
        "advisory_errors": advisory_errors,
    }


# ══════════════════════════════════════════════════════════════════════════
# JSON Schemas for `claude --json-schema` (CLI-side structured output)
# ══════════════════════════════════════════════════════════════════════════
#
# These are distinct from the tier-4 SCHEMAS above:
#   - SCHEMAS drives `validate_json_schema()` — Python-side lightweight check.
#   - Below are JSON Schema Draft-07 dicts passed to the Claude CLI's
#     `--json-schema <inline>` flag. They constrain the model's output
#     shape at generation time. Kept deliberately lean so the model retains
#     flexibility for descriptive fields; only structure/enums that downstream
#     phases actually depend on are enforced here.
#
# Phase 0B is split into two calls (CRIT-1 / HIGH-1): metadata first,
# techniques array second. Each call gets its own schema.
#
# Single source of truth: the schema dicts live in agents/schemas/*.json
# and are loaded once at import time. Edit the JSON files, not this module.

_SCHEMAS_DIR = Path(__file__).parent / "agents" / "schemas"

TI_METADATA_JSON_SCHEMA: dict = json.loads(
    (_SCHEMAS_DIR / "ti_metadata_schema.json").read_text(encoding="utf-8")
)
TI_TECHNIQUES_JSON_SCHEMA: dict = json.loads(
    (_SCHEMAS_DIR / "ti_techniques_schema.json").read_text(encoding="utf-8")
)


# ══════════════════════════════════════════════════════════════════════════
# TIER 5: SIGMA Rule Validation
# ══════════════════════════════════════════════════════════════════════════

SIGMA_REQUIRED = ["title", "status", "description", "logsource", "detection"]
SIGMA_LEVELS = ["informational", "low", "medium", "high", "critical"]
SIGMA_STATUSES = ["stable", "test", "experimental", "deprecated", "unsupported"]


def validate_sigma_rule(rule_text: str) -> dict:
    """Validate SIGMA YAML structure."""
    try:
        import yaml
    except ImportError:
        return {"valid": True, "errors": [], "warnings": ["PyYAML not installed"]}

    errors = []
    warnings = []

    try:
        rule = yaml.safe_load(rule_text)
    except yaml.YAMLError as e:
        return {"valid": False, "errors": [f"Invalid YAML: {e}"], "warnings": []}

    if not isinstance(rule, dict):
        return {"valid": False, "errors": ["Must be a YAML mapping"], "warnings": []}

    for field in SIGMA_REQUIRED:
        if field not in rule:
            errors.append(f"Missing: '{field}'")

    if "logsource" in rule:
        ls = rule["logsource"]
        if not isinstance(ls, dict):
            errors.append("'logsource' must be a mapping")
        elif not any(k in ls for k in ("product", "category", "service")):
            errors.append("'logsource' needs product, category, or service")

    if "detection" in rule:
        det = rule["detection"]
        if not isinstance(det, dict):
            errors.append("'detection' must be a mapping")
        elif "condition" not in det:
            errors.append("'detection' needs a 'condition'")
        elif len(det) < 2:
            errors.append("'detection' needs at least one selection + condition")

    if "level" in rule and rule["level"] not in SIGMA_LEVELS:
        warnings.append(f"Non-standard level: '{rule['level']}'")

    if "status" in rule and rule["status"] not in SIGMA_STATUSES:
        warnings.append(f"Non-standard status: '{rule['status']}'")

    if "tags" not in rule:
        warnings.append("No MITRE ATT&CK tags")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}


# ══════════════════════════════════════════════════════════════════════════
# TIER 4: Credential / Secret Detection
# ══════════════════════════════════════════════════════════════════════════

# Patterns that strongly indicate real credentials, not variable names or comments.
_SECRET_PATTERNS = [
    # AWS access keys (AKIA... is the real prefix for permanent keys)
    (r'AKIA[0-9A-Z]{16}', "AWS access key ID"),
    # AWS secret keys (40-char base64)
    (r'(?:aws_secret_access_key|secret_key)\s*=\s*["\'][A-Za-z0-9/+=]{40}["\']', "AWS secret access key"),
    # Generic long secrets assigned to variables with credential-like names
    (r'(?:password|secret|api_key|apikey|token|private_key)\s*=\s*["\'][A-Za-z0-9/+=_\-]{20,}["\']',
     "Hardcoded secret/token"),
    # Azure client secrets (typically 34+ chars)
    (r'(?:client_secret|tenant_secret)\s*=\s*["\'][A-Za-z0-9~._\-]{34,}["\']', "Azure client secret"),
    # GitHub PATs (ghp_, gho_, ghs_, ghr_ prefix)
    (r'gh[posh]_[A-Za-z0-9_]{36,}', "GitHub personal access token"),
    # Slack tokens
    (r'xox[baprs]-[0-9A-Za-z\-]{10,}', "Slack token"),
    # Private key blocks
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Embedded private key"),
]


def validate_no_secrets(code: str) -> dict:
    """Scan generated code for hardcoded credentials and secrets.

    Returns {"valid": bool, "errors": [...], "warnings": [...]}.
    Errors are high-confidence real credentials.
    Warnings are patterns that might be intentional (e.g., placeholder strings).
    """
    errors = []
    warnings = []

    for pattern, label in _SECRET_PATTERNS:
        for match in re.finditer(pattern, code):
            # Skip if inside a comment line
            line_start = code.rfind("\n", 0, match.start()) + 1
            line = code[line_start:match.start()]
            if line.lstrip().startswith("#"):
                continue

            # Check context — is this a real value or a placeholder/example?
            snippet = match.group(0)
            # Common safe patterns: EXAMPLE, PLACEHOLDER, YOUR_, REPLACE, XXXX, <...>
            if re.search(r'EXAMPLE|PLACEHOLDER|YOUR_|REPLACE|XXXX|<[A-Z_]+>', snippet, re.IGNORECASE):
                continue

            line_num = code[:match.start()].count("\n") + 1
            errors.append(f"Line {line_num}: Possible {label} — {snippet[:40]}...")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}


# ══════════════════════════════════════════════════════════════════════════
# TIER 5: Attack Plan Technique Coverage
# ══════════════════════════════════════════════════════════════════════════

def validate_technique_coverage(code: str, attack_plan: dict) -> dict:
    """Check that generated attack.py references all technique IDs from the plan.

    Scans for technique IDs (T####, T####.###) in comments, strings, and variable
    names. Techniques with execution_context in {host_attack, phishing_attack}
    are excluded: host_attack is implemented in UserData (not attack.py), and
    phishing_attack is documented-only (out-of-band social engineering with no
    code implementation — see phase_5_code_generation prompt).

    Returns {"valid": bool, "errors": [...], "warnings": [...],
             "covered": [...], "missing": [...], "coverage_pct": float}
    """
    errors = []
    warnings = []

    steps = attack_plan.get("attack_chain", [])
    if not steps:
        return {"valid": True, "errors": [], "warnings": ["No attack_chain in plan"],
                "covered": [], "missing": [], "coverage_pct": 100.0}

    # Collect expected technique IDs. Skip host_attack (UserData) and
    # phishing_attack (documented-only, out-of-band) — neither should have
    # executable code in attack.py, so their absence is not a coverage miss.
    _NON_CODE_CONTEXTS = {"host_attack", "phishing_attack"}
    expected = set()
    non_code_skipped = set()
    for step in steps:
        tid = step.get("technique_id", "")
        ctx = step.get("execution_context", "")
        if ctx in _NON_CODE_CONTEXTS:
            non_code_skipped.add(f"{tid} ({ctx})")
        elif tid:
            expected.add(tid)

    if not expected:
        return {"valid": True, "errors": [], "warnings": [
            f"All techniques are non-code contexts: {', '.join(sorted(non_code_skipped))}"
        ], "covered": [], "missing": [], "coverage_pct": 100.0}

    # Scan code for technique ID references (comments, strings, variable names).
    # Case-insensitive so lower-case references (t1078, tid_1078) in variable
    # names or comments still count as coverage; normalize to upper before
    # set-comparing against canonical IDs in `expected`.
    found_ids = {m.upper() for m in re.findall(r'T\d{4}(?:\.\d{3})?', code, re.IGNORECASE)}

    covered = expected & found_ids
    missing = expected - found_ids

    coverage_pct = round(len(covered) / len(expected) * 100, 1) if expected else 100.0

    if missing:
        errors.append(
            f"Missing {len(missing)}/{len(expected)} technique(s) in attack.py: "
            f"{', '.join(sorted(missing))}")
    if non_code_skipped:
        # Informational — not an error. host_attack = UserData; phishing_attack = documented-only.
        warnings.append(
            f"Non-code-context techniques (excluded from attack.py coverage): "
            f"{', '.join(sorted(non_code_skipped))}")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "covered": sorted(covered),
        "missing": sorted(missing),
        "coverage_pct": coverage_pct,
    }


# ══════════════════════════════════════════════════════════════════════════
# COMBINED VALIDATOR
# ══════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════
# TIER 1B: Module Load Check (importlib)
# ══════════════════════════════════════════════════════════════════════════
# Syntax validation proves the AST parses; it doesn't prove the module loads.
# A call to an undefined helper, a missing top-level name, or an exception
# in a module-level statement all pass `ast.parse` and fail here. Run in a
# subprocess so side effects (logging.basicConfig, sys.path mutation,
# registering signal handlers) stay out of the pipeline process.

def validate_module_loads(path: Path, timeout: int = 30) -> dict:
    """Import the module in a fresh subprocess. Returns {"valid", "errors"}."""
    loader = (
        "import importlib.util, sys\n"
        "path = sys.argv[1]\n"
        "spec = importlib.util.spec_from_file_location('_loadcheck', path)\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "sys.modules['_loadcheck'] = mod\n"
        "spec.loader.exec_module(mod)\n"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", loader, str(path)],
            capture_output=True, text=True, encoding="utf-8",
            timeout=timeout, cwd=str(path.parent),
        )
    except subprocess.TimeoutExpired:
        return {"valid": False, "errors": [
            f"Module import timed out after {timeout}s — likely a hang "
            f"in a module-level statement (network call, input(), etc.)"
        ]}

    if result.returncode == 0:
        return {"valid": True, "errors": []}

    err = (result.stderr or result.stdout).strip()
    return {"valid": False, "errors": [err[-1000:] if err else f"Exit {result.returncode} with no output"]}


def cross_validate_phase5(
    infra_content: str,
    attack_content: str,
    resource_names: Optional[dict] = None,
) -> dict:
    """Cross-check __main__.py vs attack.py for name/path/env-var consistency.

    Primary check (check 0): Both files load resource_names.json and all boto3/SDK
    calls use names from _r() / _p() rather than hardcoded Pulumi logical names.

    Legacy checks (1-9): Retained for backward compatibility with infra that
    predates resource_names.json; they fire only when resource_names.json is absent.

    Args:
        infra_content:   Text of infra/__main__.py
        attack_content:  Text of emulation_scripts/attack.py
        resource_names:  Parsed resource_names.json dict (if available); when
                         supplied the legacy name-extraction checks are skipped.

    Returns {"valid": bool, "errors": list[str], "warnings": list[str]}
    """
    errors: list = []
    warnings: list = []

    # ── 0. resource_names.json — single source of truth ─────────────────────
    # New campaigns: __main__.py loads resource_names.json and uses _R["key"].
    # attack.py loads resource_names.json and uses _r() / _p() helpers.
    # When resource_names is supplied we validate both files reference it, then
    # cross-check that attack.py never uses Pulumi logical names as boto3 args.

    has_rn_json = resource_names is not None
    rn_resources = (resource_names or {}).get("resources", {})
    rn_pks       = (resource_names or {}).get("pulumi_export_keys", {})

    # 0a. __main__.py must load resource_names.json (only enforced when there are static
    #     resource names to protect — if resources dict is empty, all names are dynamic
    #     and resolved via Pulumi exports, so the old infra.get() pattern is still correct).
    _has_static_resources = bool(rn_resources)
    if has_rn_json and _has_static_resources:
        if 'resource_names.json' not in infra_content:
            errors.append(
                "__main__.py does not load resource_names.json — resource names will be defined "
                "as inline constants that attack.py cannot share; hardcoded names will diverge."
            )
        # 0b. attack.py must load resource_names.json (same gate — only when static names exist)
        if 'resource_names.json' not in attack_content:
            errors.append(
                "attack.py does not load resource_names.json — it will hardcode or guess resource "
                "names that may differ from what __main__.py provisions at deploy time."
            )
        # 0c. Every key in resource_names["resources"] should be referenced in attack.py
        #     via _r("key") — warn on unused keys (coverage check).
        unused_keys = []
        for key in rn_resources:
            if f'_r("{key}"' not in attack_content and f"_r('{key}'" not in attack_content:
                unused_keys.append(key)
        if unused_keys and len(unused_keys) < len(rn_resources):
            # Only warn if some keys are used (avoids noise on fully-legacy scripts)
            warnings.append(
                f"resource_names.json keys not referenced in attack.py via _r(): {unused_keys} — "
                f"verify these resources are not needed by the attack chain."
            )
        # 0d. Cross-check: attack.py must not use a Pulumi logical name that differs
        #     from the corresponding AWS name in resource_names["resources"].
        #     Pulumi logical names appear as the first arg to resource constructors in infra.
        logical_names: set = set(re.findall(
            r'aws\.\w+\.\w+\s*\(\s*["\']([^"\']+)["\']', infra_content
        ))
        aws_names: set = set(rn_resources.values())
        pulumi_only = logical_names - aws_names  # names that exist as logical but not as AWS names
        for name in pulumi_only:
            if f'"{name}"' in attack_content or f"'{name}'" in attack_content:
                errors.append(
                    f"attack.py uses Pulumi logical name '{name}' in a string literal — "
                    f"this is NOT an AWS resource name and will cause ResourceNotFoundException. "
                    f"Use _r('<key>') from resource_names.json instead."
                )
        # When resource_names.json is present the legacy checks below are largely
        # redundant — skip the noisy ones but keep the structural checks (3, 4, 5, 11).
        _skip_legacy_name_checks = True
    else:
        warnings.append(
            "resource_names.json not supplied to cross_validate_phase5 — running legacy name "
            "checks. New campaigns should write resource_names.json from the infra implementor."
        )
        _skip_legacy_name_checks = False

    # ── Extract module-level constants (UPPER_CASE = "string") ───────────────
    # Used by legacy checks 1-9 when resource_names.json is absent.
    constants: dict = {}
    for m in re.finditer(r'^([A-Z][A-Z0-9_]+)\s*=\s*["\']([^"\']+)["\']', infra_content, re.MULTILINE):
        constants[m.group(1)] = m.group(2)

    def _extract_arg(content: str, constructor: str, param: str) -> tuple:
        """Find constructor(...) in content, return (const_name_or_None, resolved_value_or_None).

        Handles:
          - param="literal"   → (None, "literal")
          - param=CONST_NAME  → ("CONST_NAME", constants["CONST_NAME"]) if defined
          - param=unknown     → (None, None)
        """
        pos = content.find(constructor)
        if pos < 0:
            return None, None
        window = content[pos: pos + 600]
        # Try string literal first: param="value"
        m = re.search(r'\b' + re.escape(param) + r'\s*=\s*["\']([^"\']+)["\']', window)
        if m:
            return None, m.group(1)
        # Try constant reference: param=CONST_NAME
        m = re.search(r'\b' + re.escape(param) + r'\s*=\s*([A-Z][A-Z0-9_]+)\b', window)
        if m:
            const_name = m.group(1)
            return const_name, constants.get(const_name)  # None if const not defined
        return None, None

    def _find_export_key(const_name: str) -> Optional[str]:
        """Find pulumi.export("key", CONST_NAME) in infra_content → return "key"."""
        m = re.search(
            r'pulumi\.export\s*\(\s*["\']([^"\']+)["\']'
            r'\s*,\s*' + re.escape(const_name) + r'\b',
            infra_content,
        )
        return m.group(1) if m else None

    def _attack_reads_key(key: str) -> bool:
        """Return True if attack.py reads infra.get("key") or infra["key"]."""
        return (
            f'infra.get("{key}"' in attack_content
            or f"infra.get('{key}'" in attack_content
            or f'infra["{key}"]' in attack_content
            or f"infra['{key}']" in attack_content
        )

    # ── 1. ECS cluster name (legacy check — skipped when resource_names.json present) ──
    if not _skip_legacy_name_checks:
        const_name, cluster_name = _extract_arg(infra_content, "aws.ecs.Cluster(", "name")
        if cluster_name:
            if const_name:
                export_key = _find_export_key(const_name)
                if not export_key:
                    errors.append(
                        f"ECS cluster constant {const_name}='{cluster_name}' is not exported via "
                        f"pulumi.export() — attack.py cannot resolve cluster name from stack outputs"
                    )
                elif not _attack_reads_key(export_key):
                    errors.append(
                        f"attack.py doesn't read export key '{export_key}' (ECS cluster name) — "
                        f"RunTask / DescribeTasks will receive an empty cluster name"
                    )
            else:
                if f'"{cluster_name}"' not in attack_content and f"'{cluster_name}'" not in attack_content:
                    errors.append(
                        f"ECS cluster name '{cluster_name}' (from __main__.py) not found in "
                        f"attack.py — RunTask / DescribeTasks will fail with ClusterNotFoundException"
                    )
        else:
            warnings.append("Could not extract ECS cluster name from __main__.py")

    # ── 2. Task definition family (legacy check) ─────────────────────────────
    if not _skip_legacy_name_checks:
        const_name, family_name = _extract_arg(infra_content, "aws.ecs.TaskDefinition(", "family")
        if family_name:
            if const_name:
                export_key = _find_export_key(const_name)
                if not export_key:
                    errors.append(
                        f"Task definition constant {const_name}='{family_name}' is not exported via "
                        f"pulumi.export() — attack.py cannot resolve task family from stack outputs"
                    )
                elif not _attack_reads_key(export_key):
                    errors.append(
                        f"attack.py doesn't read export key '{export_key}' (task definition family) — "
                        f"RunTask will receive an empty taskDefinition"
                    )
            else:
                if f'"{family_name}"' not in attack_content and f"'{family_name}'" not in attack_content:
                    errors.append(
                        f"Task definition family '{family_name}' (from __main__.py) not found in "
                        f"attack.py — RunTask will fail with InvalidParameterException"
                    )
        else:
            warnings.append("Could not extract task definition family from __main__.py")

    # ── 3. --show-secrets in get_pulumi_outputs ──────────────────────────────
    if "get_pulumi_outputs" in attack_content:
        pos = attack_content.find("def get_pulumi_outputs")
        if pos >= 0:
            fn_window = attack_content[pos: pos + 400]
            if "--show-secrets" not in fn_window:
                errors.append(
                    "attack.py get_pulumi_outputs() is missing '--show-secrets' — "
                    "Pulumi secret outputs (victim IAM keys) will be redacted as [secret]"
                )

    # ── 4. _launch_attack path must include emulation_scripts ───────────────
    if "_launch_attack" in infra_content:
        pos = infra_content.find("def _launch_attack")
        if pos >= 0:
            fn_window = infra_content[pos: pos + 600]
            if "attack.py" in fn_window and "emulation_scripts" not in fn_window:
                errors.append(
                    "__main__.py _launch_attack() resolves attack.py relative to the infra/ "
                    "directory, but attack.py lives in emulation_scripts/ — "
                    "auto-trigger will fail with FileNotFoundError"
                )

    # ── 5. Env var name consistency: _launch_attack ↔ attack.py ─────────────
    launch_envs: set = set(re.findall(r'env\["([A-Z_]+)"\]\s*=', infra_content))
    attack_envs: set = set(re.findall(r'os\.environ\.get\s*\(\s*["\']([A-Z_]+)["\']', attack_content))

    for keyword, label in [("SUBNET", "subnet"), ("SECURITY|_SG_", "security-group")]:
        in_launch = {e for e in launch_envs if re.search(keyword, e)}
        in_attack  = {e for e in attack_envs  if re.search(keyword, e)}
        if in_launch and in_attack and not (in_launch & in_attack):
            errors.append(
                f"Env var mismatch ({label}): __main__.py sets {sorted(in_launch)} "
                f"but attack.py reads {sorted(in_attack)} — "
                f"auto-trigger will pass empty string to RunTask"
            )

    # ── 6. Pulumi export key ↔ _p() key alignment (new pattern) ─────────────
    # New pattern: attack.py uses _p(infra, "semantic_key") where semantic_key maps
    # to a pulumi export via pulumi_export_keys in resource_names.json.
    # Legacy pattern: attack.py uses infra.get("export_key") directly.
    # Check both: dynamic reads must resolve to an exported key.
    exported_keys: set = set(re.findall(r'pulumi\.export\s*\(\s*["\']([^"\']+)["\']', infra_content))

    # New pattern reads: _p(infra, "semantic_key") → resolves via _PKS
    new_pattern_reads: set = set(re.findall(r'_p\s*\(\s*\w+\s*,\s*["\']([^"\']+)["\']', attack_content))
    if has_rn_json and new_pattern_reads:
        # Each semantic_key must appear in pulumi_export_keys and its mapped export key must be exported
        for sem_key in new_pattern_reads:
            mapped_export = rn_pks.get(sem_key)
            if mapped_export and mapped_export not in exported_keys:
                errors.append(
                    f"attack.py calls _p(infra, '{sem_key}') → maps to pulumi export key "
                    f"'{mapped_export}' via resource_names.json, but __main__.py does not export "
                    f"that key via pulumi.export() — value will be empty at runtime."
                )
            elif not mapped_export:
                warnings.append(
                    f"attack.py calls _p(infra, '{sem_key}') but '{sem_key}' is not in "
                    f"resource_names.json pulumi_export_keys — falling back to direct key lookup."
                )

    # Legacy pattern reads: infra.get("export_key") or infra["export_key"]
    legacy_reads: set = set(re.findall(r'infra(?:\.get\s*\(\s*|\[)["\']([^"\']+)["\']', attack_content))
    if not has_rn_json:
        # Only run legacy check when resource_names.json is absent
        unresolvable = legacy_reads - exported_keys
        if unresolvable:
            errors.append(
                f"attack.py reads infra keys {sorted(unresolvable)} that __main__.py does not export — "
                f"these will always be empty/None at runtime. "
                f"Exported keys: {sorted(exported_keys)}"
            )

    # ── 7. Victim IAM policy must allow sts:AssumeRole (only when attack uses role assumption) ──
    # Only fire when attack.py actually calls assume_role / AssumeRole — campaigns like
    # ransomware (Codefinger) provision a victim user policy without needing role assumption.
    _attack_uses_assume_role = (
        "assume_role" in attack_content
        or "AssumeRole" in attack_content
        or "sts:AssumeRole" in attack_content
    )
    if _attack_uses_assume_role:
        if "UserPolicy" in infra_content or "user_policy" in infra_content or '"iam:CreateRole"' in infra_content:
            if "sts:AssumeRole" not in infra_content:
                errors.append(
                    "Victim IAM policy appears to be defined but lacks 'sts:AssumeRole' — "
                    "the victim cannot assume attacker-created roles at runtime (Phase 4 will fail)"
                )

    # ── 8. Removed AWS managed policy blocklist ──────────────────────────────
    _removed_policies = ["AmplifyFullAccess"]
    for dead_policy in _removed_policies:
        if dead_policy in attack_content or dead_policy in infra_content:
            errors.append(
                f"AWS managed policy '{dead_policy}' no longer exists — "
                f"AttachRolePolicy/attach_role_policy will return NoSuchEntity at runtime"
            )

    # ── 9. Pulumi logical name vs AWS resource name (legacy check) ───────────
    # Replaced by check 0d when resource_names.json is present.
    if not _skip_legacy_name_checks:
        logical_name_map = {}
        for m in re.finditer(
            r'aws\.\w+\.\w+\s*\(\s*\n?\s*["\']([^"\']+)["\']'
            r'[\s\S]{0,400}?\bname\s*=\s*'
            r'(?:["\']([^"\']+)["\']|([A-Z][A-Z0-9_]+))',
            infra_content,
        ):
            logical = m.group(1)
            aws_name = m.group(2) or constants.get(m.group(3) or "", "")
            if aws_name and logical != aws_name:
                logical_name_map[logical] = aws_name

        for logical, aws_name in logical_name_map.items():
            if f'"{logical}"' in attack_content or f"'{logical}'" in attack_content:
                errors.append(
                    f"attack.py references Pulumi logical name '{logical}' but AWS resource name is '{aws_name}' — "
                    f"boto3 calls using '{logical}' will fail with ResourceNotFoundException"
                )

    # ── 10. Dynamic reads must map to exported keys ───────────────────────────
    # (Covers both _p() and legacy infra.get() patterns for campaigns without resource_names.json)
    if not has_rn_json and legacy_reads:
        missing = legacy_reads - exported_keys
        if missing:
            errors.append(
                f"attack.py reads infra keys {sorted(missing)} via infra.get() / infra[] "
                f"that __main__.py does not export — these will be empty/None at runtime. "
                f"Exported keys: {sorted(exported_keys)}"
            )

    # ── 11. PULUMI_CONFIG_PASSPHRASE must be forwarded to Pulumi subprocess ───
    if "get_pulumi_outputs" in attack_content:
        pos = attack_content.find("def get_pulumi_outputs")
        if pos >= 0:
            fn_window = attack_content[pos: pos + 500]
            if "PULUMI_CONFIG_PASSPHRASE" not in fn_window:
                errors.append(
                    "attack.py get_pulumi_outputs() does not forward PULUMI_CONFIG_PASSPHRASE to "
                    "the subprocess env — 'pulumi stack output' will prompt for a passphrase and hang"
                )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "error_count": len(errors),
        "warning_count": len(warnings),
    }


def validate_generated_code(code: str, filename: str = "<generated>") -> dict:
    """Run all applicable tiers on generated Python code."""
    results = {}
    total_errors = 0

    # Tier 1
    results["syntax"] = validate_python_syntax(code, filename)
    if not results["syntax"]["valid"]:
        total_errors += len(results["syntax"]["errors"])
        return {
            "valid": False, "tiers": results, "error_count": total_errors,
            "summary": f"❌ {filename}: syntax errors — cannot validate further",
        }

    # Tier 2
    results["imports"] = validate_imports(code)
    total_errors += len(results["imports"]["errors"])

    # Tier 3 — SDK API validation (currently boto3 only, skips if no boto3 usage)
    results["sdk_api"] = validate_boto3_calls(code)
    total_errors += len(results["sdk_api"]["errors"])

    # Tier 4 — Credential / secret scanning
    results["secrets"] = validate_no_secrets(code)
    total_errors += len(results["secrets"]["errors"])

    all_valid = all(t["valid"] for t in results.values())
    tier_summary = " | ".join(
        f"{'OK' if r['valid'] else 'FAIL'} {name}" for name, r in results.items()
    )

    return {
        "valid": all_valid, "tiers": results, "error_count": total_errors,
        "summary": f"{filename}: {tier_summary} — {total_errors} error(s)",
    }
