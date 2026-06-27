# Detection Note — T1021.004 (Usage of EC2 Serial Console to Push an SSH Public Key)

**Signal:** CloudTrail ec2-instance-connect:SendSerialConsoleSSHPublicKey — a niche API almost never called in normal operations

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
