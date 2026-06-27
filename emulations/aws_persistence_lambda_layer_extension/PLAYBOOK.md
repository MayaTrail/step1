# Persist via Lambda Layer — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.persistence.lambda-layer-extension` (MITRE T1525).
Simulates an attacker publishing a malicious Lambda layer and attaching it to a legitimate function, injecting code that executes alongside every function invocation without modifying the function's own code.

## Detection
lambda:PublishLayerVersion followed by lambda:UpdateFunctionConfiguration adding an unexpected layer — especially a newly created layer from an unknown principal
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
