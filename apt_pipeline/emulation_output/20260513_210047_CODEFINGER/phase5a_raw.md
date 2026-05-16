All three files written. Here's what was generated:

**`Pulumi.yaml`** — project named `codefinger-emulation`, Python runtime.

**`requirements.txt`** — `pulumi>=3.0.0,<4.0.0` + `pulumi-aws>=7.0.0,<8.0.0`.

**`__main__.py`** — 13 resources in dependency order with all compatibility fixes applied:

| Fix applied | Where |
|---|---|
| ASCII-only resource fields | All names, tags, SIDs |
| `pulumi.get_stack()` in bucket names | All 3 S3 buckets — global uniqueness |
| No `acl=` on any BucketObject | `exposed_credentials` uses bucket policy for public read |
| Explicit `BucketPublicAccessBlock` (all 4 flags=false) | Bait bucket — required since S3 April 2023 default |
| `BucketPolicy depends_on BucketPublicAccessBlock` | Bait policy |
| No default SSE-KMS on target bucket | SSE-C conflict avoided |
| Versioning DISABLED on target bucket | Codefinger needs irrecoverable deletion |
| `enable_logging=True` on Trail (not `is_logging`) | pulumi-aws v7 CloudTrail API |
| `pulumi.Output.concat(...)` for all ARN strings | No hardcoded bucket names |
| `account_id` from `aws.get_caller_identity()` | No placeholder account IDs |
| `is_dry_run()` guard in `_launch_attack` | No attack fired during `pulumi preview` |
| Attack script path via double `dirname` | Points to `emulation_scripts/attack.py` |