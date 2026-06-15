# Detection Note: T1496 — Resource Hijacking (Cryptomining)

This technique operates on the **host plane** — cryptomining binary execution generates
no AWS CloudTrail audit events. Detection requires host telemetry, network traffic
analysis, and cloud metric anomaly detection.

| Field | Value |
|-------|-------|
| Technique | T1496 — Resource Hijacking |
| Tactic | Impact |
| Execution Plane | Host Plane (UserData PowerShell) |
| Platform | AWS EC2 Windows (dangerdev-ec2-windows-instance) |
| Audit Visible | NO |
| Attack Plan Step | Step 9 — benign CPU loop via UserData (not called by attack.py) |
| Real TI | 3× p3.16xlarge GPU instances; ~$24/hr each; hit account limits |

## Detection Alternatives

### Amazon GuardDuty (Primary)
- `CryptoCurrency:EC2/BitcoinTool.B` — EC2 instance DNS queries resolve to known mining pool domains
- `CryptoCurrency:EC2/BitcoinTool.B!DNS` — same signal via DNS query log path
- `UnauthorizedAccess:EC2/MaliciousIPCaller.Custom` — add mining pool IPs to custom threat list
- **Emulation note:** The UserData CPU loop makes no DNS queries to mining pools.
  GuardDuty mining findings will NOT fire during emulation. To validate the GuardDuty
  finding path: add a known stratum domain to Route53 Resolver DNS Firewall and make
  a test DNS query from the instance to trigger `CryptoCurrency:EC2/BitcoinTool.B!DNS`.

### VPC Flow Logs
- Outbound TCP to mining pool ports: 3333, 4444, 8333, 14444, 45560 (stratum protocol)
- Sustained high-volume outbound flows to a single external IP from a newly launched instance

### CloudWatch Metrics — CPUUtilization
- Sustained CPUUtilization ≥90% immediately after instance launch with no defined workload
- The emulation's `Math.Sqrt` loop is observable here
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "EC2-SustainedHighCPU-MiningCandidate" \
  --metric-name CPUUtilization \
  --namespace AWS/EC2 \
  --statistic Average \
  --period 300 \
  --evaluation-periods 3 \
  --threshold 90 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions <SNS_TOPIC_ARN>
```

### AWS Cost Anomaly Detection
- 3× p3.16xlarge at ~$24/hr = ~$72/hr billing impact visible within hours
- Configure Cost Anomaly Detection on EC2 service with $50/day threshold alert
```bash
aws ce create-anomaly-monitor \
  --anomaly-monitor '{"MonitorName":"EC2-CostSpike","MonitorType":"DIMENSIONAL","MonitorDimension":"SERVICE"}'
```

### Windows Application Event Log (Emulation-Specific)
- The UserData script writes **EventID 9999**, source `Application` as a T1496 simulation marker
- CloudWatch Logs Insights filter: `{ $.EventId = 9999 }` on the Windows Event Log group
- This event appears approximately 5 minutes after instance launch (after loop completion)

### EDR / Host-Based
- Process creation for known mining binaries: `xmrig.exe`, `cgminer.exe`, `nbminer.exe`, `ethminer.exe`
- Process with sustained high CPU affinity spawned from `powershell.exe` (UserData parent)

### Preventive Controls (SCP to Block GPU Instance Launch)
```json
{
  "Effect": "Deny",
  "Action": "ec2:RunInstances",
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringLike": {
      "ec2:InstanceType": ["p3.*", "p4d.*", "g4dn.*", "g4ad.*", "p2.*"]
    }
  }
}
```
Apply to all non-ML OUs via AWS Organizations SCP.
