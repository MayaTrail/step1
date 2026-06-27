# Invoke Bedrock Model for Resource Exhaustion — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.impact.bedrock-invoke-model` (MITRE T1496).
Simulates an attacker invoking Amazon Bedrock foundation models in a loop to exhaust quota and generate unexpected costs — analogous to cryptomining but targeting LLM inference billing.

## Detection
bedrock:InvokeModel called at high volume or from an unexpected principal; sudden spike in Bedrock spend in cost explorer
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
