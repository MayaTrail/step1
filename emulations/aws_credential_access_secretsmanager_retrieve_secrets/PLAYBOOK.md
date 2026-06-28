# Retrieve a High Number of Secrets Manager Secrets — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.credential-access.secretsmanager-retrieve-secrets` (MITRE T1555).
Simulates an attacker retrieving a high number of Secrets Manager secrets by first enumerating them via ListSecrets then calling GetSecretValue on each. Generates high-volume GetSecretValue CloudTrail events from a single principal.

## Detection
High volume of secretsmanager:GetSecretValue from single principal in short window
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
