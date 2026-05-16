## TASK: IMPLEMENT ATTACK SCRIPT

Generate a SINGLE `attack.py` that implements the complete attack chain with credential chaining.

### Requirements:
- ONE file, ONE main() function, sequential phases matching the attack plan
- Credential chaining: follow the `credential_chain` from the attack plan exactly
  - Steal creds in the designated phase, create a session, use in all subsequent phases
  - If multiple credential pivots exist, manage multiple sessions
- Implement EVERY step from the `attack_chain` in order
- For each `execution_context`, use the appropriate method:
  - `container_attack`: HTTP POST to the vulnerable app endpoint (requests library)
  - `api_attack`: boto3/SDK calls using the stolen session
  - `sso_attack`: SAML/OAuth/OIDC federation flows
  - `saas_attack`: SaaS API calls using stolen tokens
  - `idp_attack`: Identity provider API manipulation
  - `lateral_movement`: Pivoting using harvested credentials
- If the attack plan includes a container/app RCE step, implement wait_for_app() to poll until ready
- op_delay(min, max) between API calls for realistic tempo
- phase_delay() between major phases
- Print progress: [*] for actions, [+] for success, [-] for errors
- Handle expected errors gracefully (AccessDenied, NoSuchEntity, etc.)
- Document tradecraft notes inline (why the real APT did something)
- Return/print a summary at the end listing all events generated

---

### Resource names — ALWAYS load from resource_names.json

`__main__.py` writes `infra/resource_names.json` (single source of truth). `attack.py` MUST load
it at startup. **Never hardcode a resource name — never use a Pulumi logical name in an SDK call.**

The Pulumi logical name (first arg to `aws.xxx.Yyy("logical-name", ...)`) is an internal Pulumi
identifier. It is NOT the AWS/Azure/GCP resource name. Using it in boto3/SDK calls causes
`ResourceNotFoundException` / `NoSuchEntity` at runtime.

#### Boilerplate: load resource_names.json

```python
import json, pathlib, os, subprocess

# ── Resource names: single source of truth ──────────────────────────────────
_NAMES_FILE = pathlib.Path(__file__).parent.parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} — names will fall back to env vars")

_R   = _NAMES.get("resources", {})           # static names (IAM users, secret paths, table names…)
_PKS = _NAMES.get("pulumi_export_keys", {})  # semantic key → pulumi export key (for dynamic values)

def _r(key, env_var=None, default=""):
    """Resolve a static resource name: resource_names.json > env var > default."""
    return _R.get(key) or (os.environ.get(env_var, default) if env_var else default)

def get_pulumi_outputs(stack_dir):
    """Read dynamic Pulumi outputs (ARNs, account-ID-embedded bucket names, etc.)."""
    try:
        env = {**os.environ, "PULUMI_CONFIG_PASSPHRASE": os.environ.get("PULUMI_CONFIG_PASSPHRASE", "")}
        result = subprocess.run(
            ["pulumi", "stack", "output", "--json", "--show-secrets"],
            cwd=stack_dir, capture_output=True, text=True, env=env, timeout=60,
        )
        if result.returncode != 0:
            print(f"[-] pulumi stack output failed: {result.stderr.strip()}")
            return {}
        return json.loads(result.stdout)
    except Exception as e:
        print(f"[-] get_pulumi_outputs error: {e}")
        return {}

def _p(infra, semantic_key, env_var=None, default=""):
    """Resolve a dynamic value via pulumi_export_keys → infra dict → env var → default."""
    export_key = _PKS.get(semantic_key, semantic_key)
    return infra.get(export_key) or (os.environ.get(env_var, default) if env_var else default)
```

#### Usage pattern

```python
def main():
    stack_dir = pathlib.Path(__file__).parent.parent / "infra"
    infra = get_pulumi_outputs(stack_dir)

    # Static names — from _r()
    trail_name     = _r("trail_name",     "TRAIL_NAME",     "my-trail")
    secret_db      = _r("secret_prod_db", "SECRET_DB_NAME", "prod/database/master_credentials")
    backdoor_user  = _r("attacker_iam_user", "ATTACKER_USERNAME")

    # Dynamic values — from _p()
    corporate_bucket  = _p(infra, "corporate_bucket_name",  "CORPORATE_BUCKET")
    victim_key_id     = _p(infra, "victim_access_key_id",   "VICTIM_KEY_ID")
    victim_key_secret = _p(infra, "victim_secret_access_key","VICTIM_KEY_SECRET")
    guardduty_id      = _p(infra, "guardduty_detector_id",  "GD_DETECTOR_ID")

    # boto3 calls use the resolved strings — never Pulumi logical names
    sm.get_secret_value(SecretId=secret_db)
    iam.get_user(UserName=backdoor_user)
    s3.list_objects_v2(Bucket=corporate_bucket)
```

---

### Structure:
```python
"""
{APT_NAME} — Automated Post-Exploitation Attack Script
Executes a {N}-phase attack chain matching the approved attack plan.
"""
import sys, time, random, json, pathlib, os, subprocess

# Cross-platform UTF-8 output — prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Resource names ───────────────────────────────────────────────────────────
_NAMES_FILE = pathlib.Path(__file__).parent.parent / "infra" / "resource_names.json"
_NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8")) if _NAMES_FILE.exists() else {"resources": {}, "pulumi_export_keys": {}}
_R   = _NAMES.get("resources", {})
_PKS = _NAMES.get("pulumi_export_keys", {})

def _r(key, env_var=None, default=""):
    return _R.get(key) or (os.environ.get(env_var, default) if env_var else default)

def _p(infra, key, env_var=None, default=""):
    export_key = _PKS.get(key, key)
    return infra.get(export_key) or (os.environ.get(env_var, default) if env_var else default)

def get_pulumi_outputs(stack_dir):
    try:
        env = {**os.environ, "PULUMI_CONFIG_PASSPHRASE": os.environ.get("PULUMI_CONFIG_PASSPHRASE", "")}
        r = subprocess.run(["pulumi", "stack", "output", "--json", "--show-secrets"],
                           cwd=stack_dir, capture_output=True, text=True, env=env, timeout=60)
        return json.loads(r.stdout) if r.returncode == 0 else {}
    except Exception:
        return {}

def print_step(msg): print(f"\n[*] {msg}")
def op_delay(min_s=2, max_s=6): time.sleep(random.uniform(min_s, max_s))
def phase_delay(): time.sleep(random.uniform(5, 15))

# Add helper functions matching the attack plan's execution contexts

def main():
    stack_dir = pathlib.Path(__file__).parent.parent / "infra"
    infra = get_pulumi_outputs(stack_dir)

    # Resolve names
    # (replace with keys from resource_names.json for this campaign)

if __name__ == "__main__":
    main()
```

---

### IAM backdoor user cleanup (T1070)
When deleting a backdoor IAM user, always enumerate ALL access keys before calling `delete_user` — not just the key captured during creation. Previous crashed runs may leave additional active keys, causing `DeleteConflict`. Pattern:
```python
all_keys = iam.list_access_keys(UserName=backdoor_user)["AccessKeyMetadata"]
for key in all_keys:
    iam.delete_access_key(UserName=backdoor_user, AccessKeyId=key["AccessKeyId"])
iam.delete_user(UserName=backdoor_user)
```
