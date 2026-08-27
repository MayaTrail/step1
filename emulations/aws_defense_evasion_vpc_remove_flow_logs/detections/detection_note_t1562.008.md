# Detection Note: T1562.008 (Remove VPC Flow Logs)

**Signal:** `ec2:DeleteFlowLogs` by any principal outside your IaC destroy
pipeline.

**Why this is high-confidence.** Flow logs are configured once and effectively
never deleted in normal operations. Unlike CloudTrail (which has legitimate
lifecycle churn), a `DeleteFlowLogs` event has almost no benign explanation
outside a full VPC teardown — and a VPC teardown produces a burst of other
delete events you can correlate against. A lone `DeleteFlowLogs` with no
accompanying `DeleteVpc` / `DeleteSubnet` is the attacker pattern.

## Field shape

```
requestParameters.DeleteFlowLogsRequest.FlowLogId   the deleted flow log id(s)
```

CloudTrail does **not** record which VPC the flow log belonged to — only the
flow-log id. To name the affected VPC you need either a prior `CreateFlowLogs`
event for the same id, or a Config snapshot. Keep a mapping if you can.

## The visibility gap this opens

Once flow logs are gone, these detections go blind for the affected VPC:

- East-west lateral movement (no `srcaddr`/`dstaddr` records)
- Exfiltration volume / unusual destination ports
- C2 beaconing patterns
- Reachability of resources that "should not" have network paths

GuardDuty findings that depend on VPC Flow Logs (e.g.
`Backdoor:EC2/C&CActivity.B`, `UnauthorizedAccess:EC2/*`) stop firing for that
VPC.

## Response

1. Recreate the flow log immediately (`pulumi up` / re-apply IaC).
2. Treat the window between deletion and recreation as unmonitored — pull
   CloudTrail, GuardDuty and any host logs for that period.
3. Revoke the acting principal's sessions and review its other recent activity.

**MITRE:** T1562.008 (*Impair Defenses: Disable or Modify Cloud Logs*).
**Severity:** manifest MEDIUM; IR view HIGH when paired with other activity.
**GuardDuty:** no finding type for the deletion itself.
