All three files written. Here's what the implementation covers:

**`__main__.py` — 17 resources in dependency order:**

| Resource | Key detail |
|---|---|
| VPC + IGW + subnet + SG + RT | 10.99.0.0/16, HTTPS-only egress, mining ports implicitly denied |
| `/ecs/ambersquid` log group | 7-day retention |
| `ambersquid-cloudtrail-logs-{acct}` bucket | `BucketVersioningV2` + `BucketServerSideEncryptionConfigurationV2` (v7 standalone resources); CloudTrail policy uses `s3:GetBucketAcl` + `s3:PutObject` |
| `ambersquid-trail` | Multi-region, all mgmt events, `depends_on=[ct_bucket_policy]` |
| `prod-infra-terraform-state-{acct}` bucket | Bucket policy grants victim user `s3:GetObject`/`s3:ListBucket` |
| `terraform.tfstate` object | `pulumi.Output.all(honey_key.id, honey_key.secret)` embeds real honey access key |
| `prod/database/master_credentials` secret | `recovery_window_in_days=0`; realistic fake RDS creds |
| `ambersquid-victim` user + inline policy + access key | All 5 `Sid` blocks from the approved plan; key exported as stack secret |
| `prod-deploy-svc` honey user + key | No policies attached; any use generates `AuthFailure` CloudTrail event |
| ECS execution role | `AmazonECSTaskExecutionRolePolicy` only; attacker `ecsTaskExecutionRole` created at runtime by `attack.py` |
| ECS cluster | `containerInsights=enabled`, `capacity_providers=["FARGATE"]` |
| Task definition | `ubuntu:22.04`, `sleep infinity`, victim creds in env vars, `awslogs` to `/ecs/ambersquid` |
| CodeCommit `test` repo | Empty; T1525 simulated |

**Auto-trigger:** `pulumi.Output.all(11 outputs).apply(_launch_attack)` launches `attack.py` as a `Popen` subprocess with all resource identifiers passed as env vars once the stack resolves.