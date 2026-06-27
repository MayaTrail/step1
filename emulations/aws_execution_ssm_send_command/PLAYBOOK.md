# Execute Commands on EC2 Instances via SSM — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.execution.ssm-send-command` (MITRE T1651).
Simulates an attacker using SSM SendCommand to execute arbitrary shell commands across multiple EC2 instances using the AWS-RunShellScript document — no SSH or direct network access required.

## Detection
ssm:SendCommand in CloudTrail, especially with AWS-RunShellScript document targeting multiple instances
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
