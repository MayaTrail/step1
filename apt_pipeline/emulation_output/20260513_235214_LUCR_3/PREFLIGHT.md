# LUCR-3 Emulation — Pre-flight Checklist

Run this checklist top-to-bottom before `pulumi up`. Every item must be green.

---

## 1. Python dependencies

```bash
cd infra
pip install -r requirements.txt   # pulumi pulumi-aws pulumi-okta pulumi-azuread pulumi-github
```

Verify provider packages installed:
```bash
python -c "import pulumi_aws, pulumi_okta, pulumi_azuread, pulumi_github; print('ok')"
```

---

## 2. AWS credentials

Standard boto3 / Pulumi credential chain. One of:

| Method | Command |
|--------|---------|
| Named profile | `export AWS_PROFILE=<lab-account>` |
| Env vars | `export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=us-east-1` |
| Instance role | Available automatically on EC2 with IAM role |

Verify:
```bash
aws sts get-caller-identity
```
Expected: IAM user/role in the target lab account (`940482414561`).

---

## 3. Pulumi state passphrase

LUCR-3 uses local state encryption. Set before any `pulumi` command:
```bash
export PULUMI_CONFIG_PASSPHRASE="<your-passphrase>"
```

Initialize stack if first time:
```bash
cd infra
pulumi stack init dev
```

---

## 4. Pulumi config values

Set these in the `dev` stack config. Values with defaults are optional but recommended for accuracy:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `okta_org_url` | **YES** | `https://lab.okta.com` | Full Okta org URL, e.g. `https://acme.okta.com` |
| `github_org` | **YES** | `acme-lab` | GitHub org that owns the `lucr3-core-platform` repo |
| `okta_saml_metadata` | **YES** | Placeholder XML | SAML metadata XML from Okta AWS app |
| `operator_cidr` | no | `10.0.0.1` | Your IP for EC2 security group ingress |
| `victim_password` | no | `LabP@ssw0rd2025!` | Okta victim account password (secret) |

```bash
cd infra

pulumi config set okta_org_url "https://YOUR_ORG.okta.com"
pulumi config set github_org "YOUR_GITHUB_ORG"

# Get SAML metadata: Okta Admin > Applications > LUCR-3 AWS app > Sign On > Identity Provider metadata
pulumi config set okta_saml_metadata "$(cat /path/to/okta-metadata.xml)"

# Optional overrides
pulumi config set operator_cidr "$(curl -s https://checkip.amazonaws.com)/32"
pulumi config set --secret victim_password "YOUR_VICTIM_PASSWORD"
```

---

## 5. Okta provider credentials

`pulumi-okta` reads from env vars:

```bash
export OKTA_ORG_NAME="YOUR_ORG"          # e.g. "acme" (without .okta.com)
export OKTA_BASE_URL="okta.com"
export OKTA_API_TOKEN="<okta-api-token>" # Okta Admin > Security > API > Tokens > Create Token
```

---

## 6. Azure AD provider credentials

`pulumi-azuread` reads ARM_ env vars (service principal with Graph API permissions):

```bash
export ARM_CLIENT_ID="<sp-app-id>"
export ARM_CLIENT_SECRET="<sp-secret>"
export ARM_TENANT_ID="<aad-tenant-id>"
export ARM_SUBSCRIPTION_ID="<azure-subscription-id>"  # can be dummy for AAD-only resources
```

Required Graph API permissions for the service principal:
- `Application.ReadWrite.All`
- `ServicePrincipalEndpoint.ReadWrite.All`

---

## 7. GitHub provider credentials

`pulumi-github` reads:

```bash
export GITHUB_TOKEN="ghp_..."     # GitHub PAT with repo:write + admin:org scopes
export GITHUB_OWNER="YOUR_ORG"    # Same as github_org Pulumi config value
```

---

## 8. Attack-time env vars (needed when attack.py runs after deploy)

These are NOT available as Pulumi outputs — set manually before running attack.py:

| Env var | Description | How to get |
|---------|-------------|------------|
| `OKTA_VICTIM_USERNAME` | Victim's Okta email | `victim.employee@lab.internal` (created by Pulumi) |
| `OKTA_VICTIM_PASSWORD` | Victim's Okta password | Same as `victim_password` Pulumi config |
| `OKTA_API_TOKEN` | Okta API token for programmatic MFA | Same as Step 5 `OKTA_API_TOKEN` |
| `OKTA_AWS_APP_ID` | Okta Application ID for the AWS SAML app | Okta Admin > Applications > app Settings > General |
| `M365_TENANT_ID` | Azure AD / M365 tenant ID | Same as `ARM_TENANT_ID` |
| `M365_CLIENT_ID` | Azure AD app client ID for Graph API | Same as `ARM_CLIENT_ID` |
| `GITHUB_OWNER` | GitHub org name | Same as `github_org` Pulumi config |

```bash
export OKTA_VICTIM_USERNAME="victim.employee@lab.internal"
export OKTA_VICTIM_PASSWORD="<victim-password>"
export OKTA_API_TOKEN="<okta-api-token>"
export OKTA_AWS_APP_ID="<okta-app-id>"
export M365_TENANT_ID="<azure-tenant-id>"
export M365_CLIENT_ID="<azure-client-id>"
export GITHUB_OWNER="<github-org>"
```

---

## 9. Deploy

```bash
cd infra

# Preview (no cost)
pulumi preview

# Deploy (~5-10 min for multi-cloud resources)
pulumi up --yes
```

`pulumi up` automatically launches `attack.py` via `_launch_attack()` after all resources are provisioned. The attack output streams to stdout.

---

## 10. Destroy

```bash
cd infra
pulumi destroy --yes
```

---

## Quick reference — full env var block

Copy-paste template (fill in values):

```bash
# AWS
export AWS_PROFILE=lab-account
export AWS_DEFAULT_REGION=us-east-1
export PULUMI_CONFIG_PASSPHRASE="..."

# Okta provider
export OKTA_ORG_NAME="acme"
export OKTA_BASE_URL="okta.com"
export OKTA_API_TOKEN="..."

# Azure AD provider
export ARM_CLIENT_ID="..."
export ARM_CLIENT_SECRET="..."
export ARM_TENANT_ID="..."
export ARM_SUBSCRIPTION_ID="..."

# GitHub provider
export GITHUB_TOKEN="ghp_..."
export GITHUB_OWNER="..."

# Attack-time (attack.py reads these)
export OKTA_VICTIM_USERNAME="victim.employee@lab.internal"
export OKTA_VICTIM_PASSWORD="..."
export OKTA_AWS_APP_ID="..."
export M365_TENANT_ID="$ARM_TENANT_ID"
export M365_CLIENT_ID="$ARM_CLIENT_ID"
```
