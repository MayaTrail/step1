# Detection Note — T1021.004 (Open SSM Sessions to Multiple EC2 Instances)

**Signal:** ssm:StartSession called on multiple instances in rapid succession from unexpected principals — especially combined with ssm:TerminateSession

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
