# Enumerate SES for Phishing Capability — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.discovery.ses-enumerate` (MITRE T1087).
Simulates an attacker probing AWS SES to assess phishing capability: checks sending limits, verified identities, and account sending status. Multiple read APIs called in rapid succession reveal the attacker's intent to abuse email infrastructure.

## Detection
Multiple SES read APIs (ses:GetAccountSendingEnabled, ses:GetSendQuota, ses:ListIdentities, ses:GetIdentityVerificationAttributes) called in rapid succession from unexpected principals
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
