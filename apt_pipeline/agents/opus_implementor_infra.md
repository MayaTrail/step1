## TASK: IMPLEMENT INFRASTRUCTURE

Generate a complete Pulumi Python project. Output each file in a code block with `# FILE: filename`.

### Requirements:
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
