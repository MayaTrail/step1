# Backdoor IAM User with Additional Access Key — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.persistence.iam-backdoor-user` (MITRE T1098.001).
Simulates an attacker creating a second access key for an existing IAM user, giving them persistent programmatic access even if the original key is rotated. A single iam:CreateAccessKey call is the only CloudTrail evidence.

## Detection
iam:CreateAccessKey on an existing user where the requesting principal is NOT the user themselves — indicates an external actor creating credentials
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
