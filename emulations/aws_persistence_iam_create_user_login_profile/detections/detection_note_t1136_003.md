# Detection Note — T1136.003 (Create IAM User with Console Access)

**Signal:** iam:CreateUser followed by iam:CreateLoginProfile — new console-enabled user created outside normal IAM provisioning pipeline

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
