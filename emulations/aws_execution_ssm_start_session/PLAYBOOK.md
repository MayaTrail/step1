# Open SSM Sessions to Multiple EC2 Instances — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.execution.ssm-start-session` (MITRE T1021.004).
Simulates an attacker opening SSM interactive sessions to multiple EC2 instances in rapid succession, using ssm:StartSession as an alternative to SSH that leaves fewer network traces.

## Detection
ssm:StartSession called on multiple instances in rapid succession from unexpected principals — especially combined with ssm:TerminateSession
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
