# Backdoor IAM User Console Login via UpdateLoginProfile — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.privilege-escalation.iam-update-user-login-profile` (MITRE T1098.001).
Simulates an attacker with iam:UpdateLoginProfile permission changing a legitimate IAM user's console password to one they control, enabling console login as that user. High-signal single API call with no prerequisites beyond the target user existing.

## Detection
iam:UpdateLoginProfile in CloudTrail where the caller is not an expected administrator or password-reset automation
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
