# Create IAM Roles Anywhere Trust Anchor — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.persistence.rolesanywhere-create-trust-anchor` (MITRE T1550.001).
Simulates an attacker creating an IAM Roles Anywhere trust anchor using a self-signed certificate, enabling external workloads to assume IAM roles using X.509 certificates without long-term AWS credentials.

## Detection
rolesanywhere:CreateTrustAnchor — rare API call almost never made outside initial IAM Roles Anywhere setup; warrants immediate investigation
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
