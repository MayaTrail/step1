# Detection Note — T1098.001 (Backdoor IAM User Console Login via UpdateLoginProfile)

**Signal:** iam:UpdateLoginProfile in CloudTrail where the caller is not an expected administrator or password-reset automation

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
