Written to `emulation_output/20260426_053635/infra/attack.py` — 530 lines, single file.

**What's implemented:**

| Phase | Steps | Techniques | Notes |
|---|---|---|---|
| 1 | 1-2 | T1583.001, T1608.001 | `print_doc` / `print_sim` — no API calls |
| 2 | 3 | T1204.003 | ECS `run_task` + `describe_tasks`; resolves subnet/SG from Pulumi outputs |
| 3 | 4 | T1078.004 | `get_caller_identity`, `get_user`, `list_attached_user_policies` |
| 4 | 5-6 | T1136.003, T1098.001 | Creates 3 roles + attaches AMBERSQUID-exact policies; assumes all 3 |
| 5 | 7 | T1059.009 | CodeCommit (us-west-2), Amplify, CodeBuild, ECS cluster+TD, SageMaker notebook |
| 6 | 8 | T1525 | `get_repository` verify access; `print_sim` for actual push |
| 7 | 9 | T1580 | 9 API calls including terraform.tfstate canary + secrets canary |
| 8 | 10 | T1610 | `register_task_definition` miner-fargate-task; `print_sim` for CreateService |
| 9 | 11 | T1578.002 | 4 dry-run describe/validate calls only |
| 10 | 12 | T1070 | `stop_logging` + S3 `delete_object` (1 log); `list_repositories` via codecommit session |
| 11 | 13 | T1496 | `describe_tasks` verify; `print_sim` for mining pools |

**Cleanup** runs in a `finally` block — CloudTrail `start_logging` fires first regardless of any phase failure.