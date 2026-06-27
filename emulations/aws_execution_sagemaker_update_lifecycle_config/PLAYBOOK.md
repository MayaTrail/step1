# Malicious Script Execution via SageMaker Lifecycle Config — IR & Detection Playbook

## Summary
Atomic emulation of Stratus Red Team `aws.execution.sagemaker-update-lifecycle-config` (MITRE T1059).
Simulates an attacker backdooring a SageMaker Notebook Instance lifecycle configuration with a malicious OnStart shell script that downloads and executes a payload on every notebook restart.

## Detection
CloudTrail sagemaker:UpdateNotebookInstanceLifecycleConfig with a base64-encoded OnStart script from an unexpected principal
See the rules in `detections/`.

## Response
TODO: containment / investigation steps.

## Revert
Handled by `pulumi destroy` (and any in-attack remediation).
