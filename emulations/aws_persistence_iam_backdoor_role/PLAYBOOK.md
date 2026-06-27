# Backdoor IAM Role Trust Policy — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.persistence.iam-backdoor-role` (MITRE T1098).
Simulates an attacker modifying an existing IAM role's trust policy to add an external account (193672423079) as a trusted principal, enabling them to assume the role from outside the AWS organization.

## Detection
iam:UpdateAssumeRolePolicy with an external account principal added to an existing role's trust policy
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
