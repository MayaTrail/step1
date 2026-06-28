# Retrieve EC2 Windows Password Data — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.credential-access.ec2-get-password-data` (MITRE T1552.005).
Simulates an attacker calling ec2:GetPasswordData 30 times against randomly-generated fake instance IDs. Even though all calls fail with InvalidInstanceID.NotFound, each generates a CloudTrail event that reveals credential-hunting behavior.

## Detection
ec2:GetPasswordData called in rapid succession, especially with nonexistent or unexpected instance IDs
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
