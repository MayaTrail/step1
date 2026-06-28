# Detection Note — T1580 (Enumerate AWS Environment from EC2 Instance)

**Signal:** Rapid ec2:Describe*, s3:ListBuckets, iam:ListUsers called from an EC2 instance role — especially if the instance is not a known bastion or operations server

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
