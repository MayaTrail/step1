# Steal EC2 Instance Credentials via IMDS — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.credential-access.ec2-steal-instance-credentials` (MITRE T1552.005).
Simulates an attacker using SSM to execute a curl command against the EC2 Instance Metadata Service (IMDS) to steal the attached IAM role's temporary credentials, then uses those credentials to prove access via STS and EC2 APIs.

## Detection
ssm:SendCommand executing IMDS queries; sts:GetCallerIdentity or ec2:DescribeInstances called with instance-profile credentials from an IP not associated with the instance
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
