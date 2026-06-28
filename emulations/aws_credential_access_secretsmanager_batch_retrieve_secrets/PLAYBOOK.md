# Retrieve a High Number of Secrets Manager Secrets via Batch — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.credential-access.secretsmanager-batch-retrieve-secrets` (MITRE T1555).
Simulates an attacker using the BatchGetSecretValue API to retrieve secrets in bulk. More efficient than individual GetSecretValue calls and generates a distinct API call pattern in CloudTrail.

## Detection
secretsmanager:BatchGetSecretValue from a single principal — distinct from individual GetSecretValue pattern
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
