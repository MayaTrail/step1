`attack.py` written to `emulation_output/20260513_210047_CODEFINGER/emulation_scripts/attack.py`.

**What the script does:**

| Phase | Technique | Key actions |
|---|---|---|
| 1 | T1078.004 / T1552.001 | Anonymous `GetObject` on bait bucket -> parse `terraform.tfvars` -> `GetCallerIdentity` + `ListBuckets` to validate |
| 2 | T1530 | Paginated `ListObjectsV2`, `HeadObject` per key, sample `GetObject` per prefix |
| 3 | T1486 (simulated) | Runtime `os.urandom(32)` AES-256 SSE-C key, `GetObject` + `PutObject` with SSE-C per synthetic object, ransom note `README.txt` per prefix |
| 4 | T1485 (simulated) | `DeleteObject` per original key, `PutBucketLifecycleConfiguration` 1-day rule, immediate `DeleteBucketLifecycle` |
| 5 | T1490 | `PutBucketVersioning` Suspended, paginated `ListObjectVersions`, batched `DeleteObjects` (1000/call) |

**Usage:**
```bash
python attack.py /path/to/pulumi/infra/dir
# or via env vars:
BAIT_BUCKET_NAME=acme-devops-tfstate-dev TARGET_BUCKET_NAME=codefinger-target-dev python attack.py
```

The SSE-C key is saved to `ssec_key.bin` next to the script for cleanup use. All resource names are resolved from `pulumi stack output --json --show-secrets` — nothing is hardcoded.