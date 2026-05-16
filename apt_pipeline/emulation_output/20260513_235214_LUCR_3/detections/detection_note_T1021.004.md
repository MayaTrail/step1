# Detection Note: T1021.004 - Remote Services: SSH (via AWS SSM Session Manager)

This technique operates on the data plane. LUCR-3 uses AWS SSM Session Manager
to establish an interactive shell on EC2 instances without requiring an exposed SSH port.
SSM tunnels over HTTPS (port 443); standard SSH port monitoring does not apply.

The lateral movement itself generates NO CloudTrail events matching a traditional
"remote login" pattern. CloudTrail does record the SSM API call that initiates the
session, but the subsequent shell activity is data-plane traffic.

## Detection Alternatives

### AWS SSM Session Manager Logs (control-plane visible)
- CloudTrail: StartSession event on ssm.amazonaws.com from attacker IAM user principal
  - KQL: AWSCloudTrail | where EventName == "StartSession" | where EventSource == "ssm.amazonaws.com"
  - SIGMA logsource: product: aws, service: cloudtrail; eventName: StartSession
- SSM Session Manager can stream session logs to CloudWatch Logs and S3. Enable this
  in SSM Preferences -> Session Manager -> CloudWatch Logs for full shell transcript.

### VPC Flow Logs
- HTTPS (443) traffic from attacker EC2 instance to target EC2 instance within the VPC
- Unexpected east-west traffic between instances that do not normally communicate
- AzureNSGFlowLogs equivalent: aws_vpcflow table in Sentinel or S3-based flow log ingestion

### EC2 Host / OS Telemetry
- Linux auth logs (/var/log/auth.log or /var/log/secure): new interactive session
  opened by ssm-user or ec2-user via SSM agent
- EDR telemetry (CrowdStrike Falcon, SentinelOne): shell spawned by amazon-ssm-agent
  process - parent-child process chain is a reliable indicator
- auditd rules: track session open events (type=USER_START) on the target instance

### GuardDuty (partially suppressed - detector disabled at Step 16)
- If GuardDuty is active: UnauthorizedAccess:EC2/SSHBruteForce (not applicable here
  as SSM bypasses SSH) or Behavior:EC2/NetworkPortUnusual for unusual outbound traffic

### SIEM Correlation
Correlate StartSession (CloudTrail) from attacker IAM user with VPC flow HTTPS traffic
to the same target instance IP within a 5-minute window for high-confidence lateral
movement detection even without shell transcript logging.
