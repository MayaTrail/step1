# Detection Note — T1550.001 (Backdoor IAM User with Federated Token)

**Signal:** sts:GetFederationToken called with a permissive inline policy or from an unexpected principal; federated sessions appear in CloudTrail with token source info

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
