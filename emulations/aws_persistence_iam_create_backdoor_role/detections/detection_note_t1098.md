# Detection Note — T1098 (Create IAM Backdoor Role with Admin Access)

**Signal:** iam:CreateRole with a cross-account trust principal followed by iam:AttachRolePolicy attaching AdministratorAccess or broad managed policies

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
