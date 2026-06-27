# Backdoor Lambda Function via Resource Policy — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.persistence.lambda-backdoor-function` (MITRE T1098).
Simulates an attacker adding a resource-based policy to an existing Lambda function, granting an external AWS account (193672423079) the ability to invoke it — establishing a persistent execution backdoor.

## Detection
lambda:AddPermission granting cross-account or wildcard invoke access to a Lambda function
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
