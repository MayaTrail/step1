# Detection Note — T1059 (Execute Malicious Code via EC2 User Data)

**Signal:** ec2:ModifyInstanceAttribute with attribute=userData on a stopped instance, especially when followed by ec2:StartInstances

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
