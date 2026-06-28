# Overwrite Lambda Function Code — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.persistence.lambda-overwrite-code` (MITRE T1525).
Simulates an attacker overwriting a Lambda function's code with a malicious payload using lambda:UpdateFunctionCode, replacing legitimate business logic with attacker-controlled code.

## Detection
lambda:UpdateFunctionCode from an unexpected principal or at an unusual time — especially if the update replaces legitimate code
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
