# Detection Note — T1562.007 (Open Ingress Port 22 on Security Group)

**Signal:** ec2:AuthorizeSecurityGroupIngress with CidrIp=0.0.0.0/0 or CidrIpv6=::/0 on port 22 — indicates deliberate exposure of SSH access

**GuardDuty:** UnauthorizedAccess:EC2/SSHBruteForce (if traffic follows)

See the sigma/kql rules in this directory (complete their TODO event names).
