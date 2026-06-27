# Detection Note — T1552.001 (Download EC2 Instance User Data)

**Signal:** ec2:DescribeInstanceAttribute with Attribute=userData called on multiple instances in rapid succession from a principal without normal operational need

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
