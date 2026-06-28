# Create an IAM User with an Inline Admin Policy — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.persistence.iam-create-admin-user` (MITRE T1136.003).
Simulates an attacker creating a backdoor IAM user with AdministratorAccess and generating access keys. No prerequisites required — the attack creates and then cleans up its own resources.

## Detection
iam:CreateUser followed immediately by iam:AttachUserPolicy with AdministratorAccess in CloudTrail
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
