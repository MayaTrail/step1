# Open Ingress Port 22 on Security Group — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.exfiltration.ec2-security-group-open-port-22-ingress` (MITRE T1562.007).
Simulates an attacker opening port 22 (SSH) to the world (0.0.0.0/0) on a security group to allow direct access to EC2 instances, bypassing network-layer controls.

## Detection
ec2:AuthorizeSecurityGroupIngress with CidrIp=0.0.0.0/0 or CidrIpv6=::/0 on port 22 — indicates deliberate exposure of SSH access
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
