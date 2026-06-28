# Launch Unusual EC2 Instance Types for Cryptomining — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.execution.ec2-launch-unusual-instances` (MITRE T1204.003).
Simulates an attacker launching GPU or compute-optimized EC2 instances (p2.xlarge or similar) associated with cryptocurrency mining, triggering GuardDuty findings and unexpected cost spikes.

## Detection
ec2:RunInstances with unusual instance types (GPU, high-compute) not in baseline; GuardDuty CryptoCurrency:EC2/BitcoinTool.B if mining traffic detected
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
