# Detection Note: T1021.001 — Remote Services: Remote Desktop Protocol

This technique operates on the **data plane** — there is no CloudTrail audit event
generated for an RDP TCP connection or interactive RDP session. No SIGMA rule or
KQL query against `AWSCloudTrail` will detect actual RDP usage.

| Field | Value |
|-------|-------|
| Technique | T1021.001 — Remote Desktop Protocol |
| Tactic | Lateral Movement |
| Execution Plane | Data Plane |
| Platform | AWS EC2 Windows (dangerdev-ec2-windows-instance) |
| Audit Visible | NO |
| Attack Plan Step | Step 8 — TCP SYN probe to port 3389 via Python socket |

## Detection Alternatives

### VPC Flow Logs (Primary)
Enable on the VPC or subnet ENI. Captures source IP, dest port, protocol, action (ACCEPT/REJECT).

```sql
-- CloudWatch Logs Insights (VPC Flow Log group)
fields @timestamp, srcAddr, dstAddr, dstPort, action, bytes
| filter dstPort = 3389 AND action = "ACCEPT"
| filter srcAddr not like "10.%" and srcAddr not like "192.168.%" and srcAddr not like "172.16.%"
| sort @timestamp desc
```

- Single successful TCP connection from a foreign IP = lateral movement candidate
- Repeated connections from same IP = GuardDuty `UnauthorizedAccess:EC2/RDPBruteForce`

### AWS GuardDuty
- `UnauthorizedAccess:EC2/RDPBruteForce` — repeated inbound port 3389 attempts (threshold-based)
- `Backdoor:EC2/C&CActivity` — outbound traffic from EC2 to known C2 IPs post-session
- **Emulation note:** Step 8 performs a single TCP SYN probe. GuardDuty's brute-force
  threshold will NOT fire on one connection — check VPC Flow Logs directly.

### AWS Security Hub / Config (Control-Plane Proxy)
- EC2.19: Security group allows unrestricted inbound on port 3389 (0.0.0.0/0)
- Fires on the group *configuration* (detectable via CloudTrail — see sigma_t1578_002.yml),
  not the RDP session itself. Open SG is the necessary precondition.

### CloudTrail (Indirect — Attack Surface Creation)
```kql
// Detect open RDP security group creation (precondition for T1021.001)
AWSCloudTrail
| where EventSource == "ec2.amazonaws.com"
| where EventName == "AuthorizeSecurityGroupIngress"
| where RequestParameters has "0.0.0.0/0" and RequestParameters has "3389"
| project TimeGenerated, UserIdentityArn, SourceIpAddress, RequestParameters
```

### Windows Host Events (via CloudWatch Agent)
- EventID 4624 Type 10 (RemoteInteractive) — successful RDP logon
- EventID 4625 — failed RDP authentication
- EventID 4778 / 4779 — RDP session reconnected / disconnected
- Forward to CloudWatch Logs; alert on Type 10 from non-approved source IPs

### Preventive Controls
- AWS Network Firewall stateful rule blocking inbound port 3389 from 0.0.0.0/0
- Security group allow-listing specific management IP CIDRs (eliminates EC2.19)
- AWS Systems Manager Session Manager as an RDP-less alternative (no port 3389 needed)
