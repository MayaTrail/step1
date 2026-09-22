# Detection Note: T1552.001 - Unsecured Credentials: Credentials In Files

**Execution plane:** host_plane (not control_plane, not data_plane)
**Audit visible:** No - credential harvest from ~/.aws/credentials generates no CloudTrail event.
The attacker reads a local file; AWS never sees this action.

## Why no SIGMA/KQL rule

Credential harvesting from the developer workstation filesystem is entirely a host-side
operation. There is no AWS API call at harvest time - the attacker uses the static key
*later* (T1078.004 validation). This technique is pre-cloud and generates no CloudTrail,
VPC flow, or GuardDuty finding at the moment of harvest.

## Detection alternatives for this emulation environment

### EC2 / Host telemetry (hazybeacon-dev-instance)
- **auditd file-access rules** on hazybeacon-dev-instance: add an auditd rule watching
  reads of `/home/*/.aws/credentials` and `/home/*/.aws/config`. A read by any process
  other than the owning user's shell or aws-cli binary is suspicious.
  Rule example: `-a always,exit -F path=/home/ubuntu/.aws/credentials -F perm=r -k aws_creds_read`
- **CloudWatch Agent** forwarding auditd logs: if the UserData-configured CloudWatch Agent
  ships /var/log/audit/audit.log to CloudWatch Logs, filter for `key="aws_creds_read"`.
- **EC2 Systems Manager Session Manager logs**: any interactive session to hazybeacon-dev-instance
  that reads credential files will appear in SSM session history if SSM logging is enabled.

### AWS-side leading indicators (circumstantial, not direct)
- **Unusual GetCallerIdentity source IP** (see T1078.004 detection): the first sign that
  credentials were harvested is when the stolen key is *used* from a non-EC2 IP. Correlate
  GetCallerIdentity source IP against the hazybeacon-dev-instance Elastic IP to detect
  off-instance usage.
- **IMDSv2 hop-limit enforcement**: if the instance required IMDSv2 and hop limit 1, any
  credential derived from IMDS cannot be forwarded. Static credentials in the credentials
  file bypass this entirely - their use from an external IP is the detection trigger.

### Bait / deception controls
- The terraform.tfstate bait file in ~/projects/infra-prod/ contains AKIA credentials that
  are instrumented as canary tokens. Any call using those AKIA values immediately triggers
  a notification regardless of whether CloudTrail is being monitored.
- AWS CloudTrail will capture the first API call using the bait credential even if the
  attacker attempts to avoid enumeration - the canary key can be configured to alert on
  any usage via EventBridge + Lambda.

## IOCs from this emulation step
- Presence of `~/.aws/credentials` on hazybeacon-dev-instance (normal; established by UserData)
- Presence of `~/projects/infra-prod/terraform.tfstate` containing bait AKIA key
