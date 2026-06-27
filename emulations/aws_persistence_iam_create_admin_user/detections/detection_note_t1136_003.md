# Detection Note — T1136.003 (Create an IAM User with an Inline Admin Policy)

**Signal:** iam:CreateUser followed immediately by iam:AttachUserPolicy with AdministratorAccess in CloudTrail

**GuardDuty:** Persistence:IAMUser/UserPermissions

See the sigma/kql rules in this directory (complete their TODO event names).
