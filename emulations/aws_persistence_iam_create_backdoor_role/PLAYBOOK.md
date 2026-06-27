# Create IAM Backdoor Role with Admin Access — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.persistence.iam-create-backdoor-role` (MITRE T1098).
Simulates an attacker creating a new IAM role trusted by an external account (193672423079) and attaching AdministratorAccess, establishing persistent admin-level access that survives credential rotation.

## Detection
iam:CreateRole with a cross-account trust principal followed by iam:AttachRolePolicy attaching AdministratorAccess or broad managed policies
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
