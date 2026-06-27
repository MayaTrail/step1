# Download EC2 Instance User Data — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.discovery.ec2-download-user-data` (MITRE T1552.001).
Simulates an attacker enumerating all EC2 instances and downloading their user-data scripts, which often contain secrets, credentials, configuration values, or bootstrap commands that can be leveraged for lateral movement.

## Detection
ec2:DescribeInstanceAttribute with Attribute=userData called on multiple instances in rapid succession from a principal without normal operational need
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
