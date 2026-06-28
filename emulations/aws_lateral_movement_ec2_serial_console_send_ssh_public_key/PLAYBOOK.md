# Usage of EC2 Serial Console to Push an SSH Public Key — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.lateral-movement.ec2-serial-console-send-ssh-public-key` (MITRE T1021.004).
Simulates an attacker pushing their SSH public key to an EC2 instance via the serial console API, which bypasses security groups and network ACLs — providing access even when port 22 is blocked.

## Detection
CloudTrail ec2-instance-connect:SendSerialConsoleSSHPublicKey — a niche API almost never called in normal operations
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
