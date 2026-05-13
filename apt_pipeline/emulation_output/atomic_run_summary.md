# Atomic Emulation Run Summary

Generated: 2026-05-13 00:07 UTC

## Overall: 43/43 passed | 0 failed | 0 warn | 0 pending

| Technique | Status | Time |
|-----------|--------|------|
| `aws.credential-access.ec2-get-password-data` | ✅ pass | ?s |
| `aws.defense-evasion.organizations-leave` | ✅ pass | ?s |
| `aws.persistence.iam-create-backdoor-role` | ✅ pass | ?s |
| `aws.persistence.iam-create-user-login-profile` | ✅ pass | ?s |
| `aws.persistence.iam-create-admin-user` | ✅ pass | ?s |
| `aws.persistence.rolesanywhere-create-trust-anchor` | ✅ pass | ?s |
| `aws.persistence.sts-federation-token` | ✅ pass | ?s |
| `aws.discovery.ec2-download-user-data` | ✅ pass | ?s |
| `aws.discovery.ses-enumerate` | ✅ pass | ?s |
| `aws.execution.ec2-launch-unusual-instances` | ✅ pass | ?s |
| `aws.impact.bedrock-invoke-model` | ✅ pass | ?s |
| `aws.persistence.iam-backdoor-role` | ✅ pass | ?s |
| `aws.persistence.iam-backdoor-user` | ✅ pass | ?s |
| `aws.initial-access.console-login-without-mfa` | ✅ pass | ?s |
| `aws.privilege-escalation.iam-update-user-login-profile` | ✅ pass | ?s |
| `aws.defense-evasion.cloudtrail-stop` | ✅ pass | ?s |
| `aws.defense-evasion.cloudtrail-delete` | ✅ pass | ?s |
| `aws.defense-evasion.cloudtrail-event-selectors` | ✅ pass | ?s |
| `aws.defense-evasion.cloudtrail-lifecycle-rule` | ✅ pass | ?s |
| `aws.exfiltration.s3-backdoor-bucket-policy` | ✅ pass | ?s |
| `aws.impact.s3-ransomware-batch-deletion` | ✅ pass | ?s |
| `aws.impact.s3-ransomware-client-side-encryption` | ✅ pass | ?s |
| `aws.impact.s3-ransomware-individual-deletion` | ✅ pass | ?s |
| `aws.persistence.lambda-backdoor-function` | ✅ pass | ?s |
| `aws.persistence.lambda-layer-extension` | ✅ pass | ?s |
| `aws.persistence.lambda-overwrite-code` | ✅ pass | ?s |
| `aws.credential-access.ec2-steal-instance-credentials` | ✅ pass | 107.6s |
| `aws.execution.ec2-user-data` | ✅ pass | 87.3s |
| `aws.execution.ssm-send-command` | ✅ pass | 131.4s |
| `aws.execution.ssm-start-session` | ✅ pass | 137.6s |
| `aws.discovery.ec2-enumerate-from-instance` | ✅ pass | 95.2s |
| `aws.lateral-movement.ec2-instance-connect` | ✅ pass | 102.0s |
| `aws.lateral-movement.ec2-serial-console-send-ssh-public-key` | ✅ pass | 100.2s |
| `aws.defense-evasion.dns-delete-logs` | ✅ pass | 70.9s |
| `aws.defense-evasion.vpc-remove-flow-logs` | ✅ pass | 37.4s |
| `aws.exfiltration.ec2-share-ami` | ✅ pass | 121.6s |
| `aws.exfiltration.ec2-share-ebs-snapshot` | ✅ pass | 111.6s |
| `aws.execution.sagemaker-update-lifecycle-config` | ✅ pass | 36.4s |
| `aws.credential-access.secretsmanager-retrieve-secrets` | ✅ pass | 53.1s |
| `aws.credential-access.secretsmanager-batch-retrieve-secrets` | ✅ pass | 37.3s |
| `aws.credential-access.ssm-retrieve-securestring-parameters` | ✅ pass | 51.5s |
| `aws.exfiltration.ec2-security-group-open-port-22-ingress` | ✅ pass | 65.1s |
| `aws.exfiltration.rds-share-snapshot` | ✅ pass | 573.5s |