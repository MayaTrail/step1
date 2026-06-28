# Enumerate AWS Environment from EC2 Instance — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.discovery.ec2-enumerate-from-instance` (MITRE T1580).
Simulates an attacker using SSM to run a series of AWS CLI discovery commands from a compromised EC2 instance, using its attached IAM role to enumerate VPCs, instances, buckets, and IAM users.

## Detection
Rapid ec2:Describe*, s3:ListBuckets, iam:ListUsers called from an EC2 instance role — especially if the instance is not a known bastion or operations server
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
