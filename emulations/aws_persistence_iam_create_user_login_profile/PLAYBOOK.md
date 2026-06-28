# Create IAM User with Console Access — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.persistence.iam-create-user-login-profile` (MITRE T1136.003).
Simulates an attacker creating a new IAM user with a console login profile (password), enabling persistent console access as a new identity that may evade user-based alerting.

## Detection
iam:CreateUser followed by iam:CreateLoginProfile — new console-enabled user created outside normal IAM provisioning pipeline
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
