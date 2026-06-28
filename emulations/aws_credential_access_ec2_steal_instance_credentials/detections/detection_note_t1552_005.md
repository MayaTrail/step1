# Detection Note — T1552.005 (Steal EC2 Instance Credentials via IMDS)

**Signal:** ssm:SendCommand executing IMDS queries; sts:GetCallerIdentity or ec2:DescribeInstances called with instance-profile credentials from an IP not associated with the instance

**GuardDuty:** UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration

See the sigma/kql rules in this directory (complete their TODO event names).
