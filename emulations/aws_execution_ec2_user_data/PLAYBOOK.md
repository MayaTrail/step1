# Execute Malicious Code via EC2 User Data — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.execution.ec2-user-data` (MITRE T1059).
Simulates an attacker stopping an EC2 instance, replacing its user-data script with a malicious shell script (C2 callback), then restarting it — causing the malicious code to execute as root on the next boot.

## Detection
ec2:ModifyInstanceAttribute with attribute=userData on a stopped instance, especially when followed by ec2:StartInstances
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
