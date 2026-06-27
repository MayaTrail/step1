# Detection Note — T1098 (Backdoor IAM Role Trust Policy)

**Signal:** iam:UpdateAssumeRolePolicy with an external account principal added to an existing role's trust policy

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
