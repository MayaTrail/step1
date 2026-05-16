## TASK: IMPLEMENT INFRASTRUCTURE

Generate a complete Pulumi Python project. Output each file in a code block with `# FILE: filename`.

### REQUIRED OUTPUT FILES (must all be present)
1. `resource_names.json` — **generate this first, before `__main__.py`**
2. `requirements.json` — **machine-readable prerequisites manifest for the MayaTrail platform**
3. `__main__.py` — loads names from `resource_names.json`, never redefines them inline
4. `Pulumi.yaml`, `requirements.txt`

---

### resource_names.json — single source of truth

**Every resource name used in boto3/SDK calls must appear here. No exceptions.**

`resource_names.json` schema:
```json
{
  "campaign": "<THREAT_ACTOR>",
  "csp": "aws|azure|gcp|multi",
  "resources": {
    "<semantic_key>": "<exact_aws_name>"
  },
  "pulumi_export_keys": {
    "<semantic_key>": "<pulumi_export_string>"
  }
}
```

- **`resources`**: every static name (IAM usernames, secret names, DynamoDB table names, CloudTrail trail names, GitHub repo names, ECS cluster names, etc.) — the exact value passed as `name=` to the cloud SDK.  Bait secrets must use realistic paths (`prod/database/master_credentials`, not `test-secret`).
- **`pulumi_export_keys`**: any value known only after `pulumi up` (ARNs, bucket names that embed account-ID, EC2 instance IDs, subnet IDs, detector IDs) — map from semantic key to the `pulumi.export("key", ...)` string used in `__main__.py`.

Example:
```json
{
  "campaign": "CODEFINGER",
  "csp": "aws",
  "resources": {
    "victim_iam_user": "codefinger-victim-dev",
    "trail_name": "codefinger-trail-dev",
    "target_bucket": "codefinger-target-dev"
  },
  "pulumi_export_keys": {
    "victim_access_key_id": "victim_access_key_id",
    "victim_secret_access_key": "victim_secret_access_key",
    "target_bucket_name": "target_bucket_name"
  }
}
```

---

### requirements.json — machine-readable emulation prerequisites

**Generate this alongside `resource_names.json`, before `__main__.py`.**

The MayaTrail platform reads `requirements.json` before allowing execution to validate that all required
credentials and configuration are present. Every emulation MUST have one.

`requirements.json` schema:
```json
{
  "campaign": "<THREAT_ACTOR>",
  "csp": "aws|azure|gcp|multi",
  "providers": {
    "<provider_short_name>": {
      "required": true,
      "credentials": [
        {"env_var": "ENV_VAR_NAME", "description": "human-readable explanation"},
        {"env_var": "OPTIONAL_VAR", "description": "...", "default": "us-east-1"}
      ],
      "min_permissions": ["service:Action", "service:Action2"]
    }
  },
  "pulumi_config": [
    {
      "key": "config:key",
      "required": true,
      "description": "What this value is and where to get it",
      "secret": false,
      "how_to_get": "Step-by-step instructions"
    }
  ],
  "attack_env_vars": [
    {
      "env_var": "ENV_VAR_NAME",
      "required": true,
      "description": "What this env var is for",
      "how_to_get": "Where to get this value"
    }
  ],
  "python_packages": ["boto3>=1.38", "pulumi>=3.0.0", "pulumi-aws>=6.0.0"]
}
```

**Field rules:**
- **`providers`**: one entry per Pulumi provider installed. Key is the provider short-name (`aws`, `okta`, `azuread`, `github`, `gcp`, `azure`). List ALL providers the `__main__.py` imports.
- **`pulumi_config`**: list every `pulumi config set` value required before `pulumi up`. These are NOT env vars — they live in `Pulumi.dev.yaml`. Set `secret: true` for sensitive values (API keys, passwords). Always include `PULUMI_CONFIG_PASSPHRASE` in `attack_env_vars`, not here.
- **`attack_env_vars`**: env vars needed when `attack.py` runs (post-deploy). Always include `PULUMI_CONFIG_PASSPHRASE` (required). Also list any attacker-controlled API keys or tokens the attack script reads from environment.
- **`python_packages`**: contents of `requirements.txt` as an array — copy them directly.

**Example (AWS-only campaign):**
```json
{
  "campaign": "CODEFINGER",
  "csp": "aws",
  "providers": {
    "aws": {
      "required": true,
      "credentials": [
        {"env_var": "AWS_ACCESS_KEY_ID",     "description": "AWS access key ID with admin or targeted permissions"},
        {"env_var": "AWS_SECRET_ACCESS_KEY", "description": "AWS secret access key"},
        {"env_var": "AWS_DEFAULT_REGION",    "description": "AWS region to deploy into", "default": "us-east-1"}
      ],
      "min_permissions": ["s3:*", "iam:*", "cloudtrail:*", "sts:GetCallerIdentity"]
    }
  },
  "pulumi_config": [],
  "attack_env_vars": [
    {
      "env_var": "PULUMI_CONFIG_PASSPHRASE",
      "required": true,
      "description": "Passphrase for the Pulumi state encryption — must match what was set during pulumi up",
      "how_to_get": "Set any secure passphrase before pulumi up; reuse the same value here"
    }
  ],
  "python_packages": ["pulumi>=3.0.0", "pulumi-aws>=6.0.0", "boto3>=1.38.0"]
}
```

**Example (multi-cloud with Okta + Azure AD):**
```json
{
  "campaign": "LUCR-3",
  "csp": "multi",
  "providers": {
    "aws": {
      "required": true,
      "credentials": [
        {"env_var": "AWS_ACCESS_KEY_ID",     "description": "AWS access key with IAM + Secrets Manager + CloudTrail permissions"},
        {"env_var": "AWS_SECRET_ACCESS_KEY", "description": "AWS secret access key"},
        {"env_var": "AWS_DEFAULT_REGION",    "description": "Target region", "default": "us-east-1"}
      ],
      "min_permissions": ["iam:*", "secretsmanager:*", "cloudtrail:*", "sts:*"]
    },
    "okta": {
      "required": true,
      "credentials": [
        {"env_var": "OKTA_API_TOKEN", "description": "Okta API token with org admin scope"},
        {"env_var": "OKTA_ORG_NAME",  "description": "Okta org domain, e.g. dev-12345678"}
      ],
      "min_permissions": ["okta.apps.manage", "okta.users.manage", "okta.groups.manage"]
    },
    "azuread": {
      "required": true,
      "credentials": [
        {"env_var": "ARM_TENANT_ID",     "description": "Azure AD tenant ID (GUID)"},
        {"env_var": "ARM_CLIENT_ID",     "description": "Service principal application (client) ID"},
        {"env_var": "ARM_CLIENT_SECRET", "description": "Service principal client secret"}
      ],
      "min_permissions": ["Application.ReadWrite.All", "Directory.ReadWrite.All"]
    }
  },
  "pulumi_config": [
    {
      "key": "lucr3:okta_org_name",
      "required": true,
      "description": "Okta org domain used to configure the SAML provider",
      "how_to_get": "Found in Okta Admin Console > Settings > Account. Format: dev-XXXXXXXX"
    }
  ],
  "attack_env_vars": [
    {
      "env_var": "PULUMI_CONFIG_PASSPHRASE",
      "required": true,
      "description": "Pulumi stack encryption passphrase",
      "how_to_get": "Set any secure passphrase before pulumi up; reuse same value here"
    },
    {
      "env_var": "OKTA_API_TOKEN",
      "required": true,
      "description": "Okta API token — attack.py reads Okta app assignments directly",
      "how_to_get": "Okta Admin Console > Security > API > Tokens > Create Token"
    }
  ],
  "python_packages": ["pulumi>=3.0.0", "pulumi-aws>=6.0.0", "pulumi-okta>=4.0.0", "pulumi-azuread>=5.0.0", "boto3>=1.38.0"]
}
```

---

### `__main__.py` — load names from resource_names.json

At the top of `__main__.py`, load `resource_names.json` and assign module-level constants from it:

```python
import json, pathlib
_NAMES = json.loads((pathlib.Path(__file__).parent / "resource_names.json").read_text())
_R = _NAMES["resources"]

# Use _R["key"] everywhere — never redefine names as string literals
TRAIL_NAME         = _R["trail_name"]
VICTIM_USER_NAME   = _R["victim_iam_user"]
TARGET_BUCKET_NAME = _R["target_bucket"]
```

`pulumi.export()` calls must use the keys declared in `pulumi_export_keys`:
```python
# Keys in pulumi_export_keys → exported so attack.py can resolve them via pulumi stack output
pulumi.export("victim_access_key_id",     victim_access_key.id)
pulumi.export("victim_secret_access_key", victim_access_key.secret)
pulumi.export("target_bucket_name",       target_bucket.bucket)
```

### General Requirements:
- `__main__.py` must create ALL resources from the approved infra plan
- Follow the `resource_dependency_order` from the infra plan
- Sandbox VPC first (if cloud-based), then all resources inside it (except IAM which is global)
- Resource configurations MUST match the infra plan's `configuration_notes` exactly
- UserData script (if the infra plan includes `userdata_actions`) must implement ALL actions
- UserData must NOT use `set -e` — individual failures must not abort the chain
- UserData must include `history -cw` after each logical stage
- If the infra plan specifies a `vulnerable_app`, deploy it via the method specified (Docker, native, etc.)
- Bait resources must have REALISTIC names (prod/database/master_credentials, not test-1)
- If the infra plan includes bait terraform.tfstate, use `pulumi.Output.all()` to embed real access keys
- Auto-trigger hook: after all resources ready, execute attack.py with relevant resource outputs

### Phishing operator permissions
If the attack plan designates a target user as the phishing operator (i.e., their credentials are used
to send phishing emails or register sending identities), provision them with the relevant email service
permissions in Pulumi — in addition to any data-access policies the attack plan requires:
- **AWS SES:** `arn:aws:iam::aws:policy/AmazonSESFullAccess`
- **SendGrid (SaaS):** include a SendGrid API key secret and grant the user access
- **Azure Communication Services:** assign the `Contributor` role on the ACS resource

Without these permissions, attack steps that call `ses:VerifyEmailIdentity`,
`ses:SendEmail`, or equivalent will fail with `AccessDenied`, breaking the attack chain.

### Critical Pulumi patterns:
```python
# Auto-trigger attack after infra is ready — adapt args to what the attack script needs
pulumi.Output.all(
    *[resource.output for resource in key_resources]
).apply(lambda args: trigger_attack(*args))
```

Bait terraform.tfstate (if infra plan includes this) — adapt storage to the platform:
- AWS: `aws.s3.BucketObject` with `content=pulumi.Output.all(key.id, key.secret).apply(...)`
- Azure: `azure_native.storage.Blob` with embedded service principal credentials
- GCP: `gcp.storage.BucketObject` with embedded service account key JSON

### UserData / startup script (only if infra plan has userdata_actions):

For **Linux** hosts (AWS EC2, Azure Linux VM, GCP Compute):
- Use `#!/bin/bash`, do NOT use `set -e`
- Use `history -cw` after each logical stage to clear command history
- For simulated techniques, use SAFE approximations (bash loops, echo/sleep — no real malware)

For **Windows** hosts (Azure Windows VM, etc.):
- Use PowerShell, `Clear-History` instead of `history -cw`

For each userdata_action from the infra plan:
- Comment with `# [EMULATED] T{XXXX}: {description}` or `# [SIMULATED] T{XXXX}: {description}`
- Implement all commands from the action's `commands` array
- If `vulnerable_app` is specified, deploy it after host setup (Docker, native, etc.)
