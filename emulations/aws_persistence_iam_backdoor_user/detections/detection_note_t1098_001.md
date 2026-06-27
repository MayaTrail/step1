# Detection Note — T1098.001 (Backdoor IAM User with Additional Access Key)

**Signal:** iam:CreateAccessKey on an existing user where the requesting principal is NOT the user themselves — indicates an external actor creating credentials

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
