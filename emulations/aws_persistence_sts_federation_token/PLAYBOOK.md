# Backdoor IAM User with Federated Token — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.persistence.sts-federation-token` (MITRE T1550.001).
Simulates an attacker using sts:GetFederationToken to mint long-lived federated credentials (up to 36 hours) with an attacker-controlled inline policy, providing persistent access that survives access key rotation.

## Detection
sts:GetFederationToken called with a permissive inline policy or from an unexpected principal; federated sessions appear in CloudTrail with token source info
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
