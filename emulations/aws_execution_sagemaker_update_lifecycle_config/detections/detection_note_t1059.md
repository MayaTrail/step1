# Detection Note — T1059 (Malicious Script Execution via SageMaker Lifecycle Config)

**Signal:** CloudTrail sagemaker:UpdateNotebookInstanceLifecycleConfig with a base64-encoded OnStart script from an unexpected principal

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
