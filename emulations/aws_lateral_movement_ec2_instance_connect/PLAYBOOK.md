# Usage of EC2 Instance Connect on Multiple Instances — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.lateral-movement.ec2-instance-connect` (MITRE T1021.004).
Simulates an attacker pushing their SSH public key to an EC2 instance via EC2 Instance Connect, granting a 60-second SSH window without persisting any key on the instance.

## Detection
CloudTrail ec2-instance-connect:SendSSHPublicKey from an unexpected principal or source IP address
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
