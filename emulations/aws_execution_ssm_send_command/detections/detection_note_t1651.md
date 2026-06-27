# Detection Note — T1651 (Execute Commands on EC2 Instances via SSM)

**Signal:** ssm:SendCommand in CloudTrail, especially with AWS-RunShellScript document targeting multiple instances

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
