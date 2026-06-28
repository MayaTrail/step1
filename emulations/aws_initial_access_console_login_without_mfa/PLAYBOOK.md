# Console Login Without MFA — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.initial-access.console-login-without-mfa` (MITRE T1078.004).
Simulates an attacker logging into the AWS console using IAM user credentials without MFA, generating a CloudTrail ConsoleLogin event with MFAUsed=No — a high-signal indicator for accounts that should enforce MFA.

## Detection
CloudTrail ConsoleLogin event with additionalEventData.MFAUsed=No for users that should have MFA enforced
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
