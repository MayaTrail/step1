# Retrieve SSM Parameters from the Parameter Store — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.credential-access.ssm-retrieve-securestring-parameters` (MITRE T1552.007).
Simulates an attacker enumerating and decrypting SSM SecureString parameters. Calls DescribeParameters to enumerate then GetParameters with WithDecryption=true in batches of 10.

## Detection
ssm:GetParameters with withDecryption=true for large number of parameters from single principal
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
