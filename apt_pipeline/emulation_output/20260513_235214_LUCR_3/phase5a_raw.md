All three files written. Summary of what was generated:

**`Pulumi.yaml`** — project definition with multi-cloud runtime and emulation tags.

**`requirements.txt`** — pulumi-aws v7, pulumi-okta v4, pulumi-azuread v5, pulumi-github v6.

**`__main__.py`** — complete infrastructure in dependency order:
- Constants block at top; every string literal appears exactly once
- All 25 resources from the plan, in `resource_dependency_order`
- pulumi-aws v7 APIs throughout: `BucketVersioningV2`, `BucketServerSideEncryptionConfigurationV2`, `DetectorFeature` (no inline Bucket args or `datasources=`), `enable_logging=True` on CloudTrail
- SAML provider trust policy uses `aws_saml_provider.arn` Output (no placeholder account IDs)
- All secrets have `recovery_window_in_days=0`
- No SecretsManager deny policies
- Honey IAM user with `AccessKey` resource + canary EventBridge rules on all three bait secrets and the tfstate object
- DynamoDB seeded with 5 sample rows (full 100-row population left to attack setup script via Faker)
- GitHub repo with Dockerfile, deploy workflow, and Terraform files containing synthetic embedded secrets
- M365/SharePoint documented as manual setup (no stable Pulumi provider)
- `_launch_attack()` path follows constraint 11 (`emulation_scripts/attack.py`, two `dirname` levels up)
- All env var keys exported match what attack.py expects