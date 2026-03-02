import type { DetectionData, Guardrails } from '@/types'

export const awsDetections: DetectionData = {
  ruleCount: 212,
  formats: 'SIGMA \u00b7 KQL \u00b7 YARA',
  rules: [
    {
      title: 'SIGMA Rule \u2014 APT29 CloudTrail Logging Disabled',
      code: `title: APT29 CloudTrail Logging Disabled
status: experimental
description: Detects disabling of CloudTrail logging, a known APT29 defense evasion technique
references:
  - https://attack.mitre.org/techniques/T1562/008/
tags:
  - attack.defense_evasion
  - attack.t1562.008
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: StopLogging
    eventSource: cloudtrail.amazonaws.com
  condition: selection
falsepositives:
  - Legitimate maintenance operations
level: high`,
    },
    {
      title: 'KQL Query \u2014 Microsoft Sentinel (CloudTrail)',
      code: `AWSCloudTrail
| where EventName == "StopLogging"
| where EventSource == "cloudtrail.amazonaws.com"
| project TimeGenerated, UserIdentityArn, SourceIpAddress, UserAgent, RequestParameters
| where TimeGenerated > ago(24h)
| extend ThreatActor = "APT29", Technique = "T1562.008"`,
    },
    {
      title: 'SIGMA Rule \u2014 Unauthorized IAM User Creation',
      code: `title: Unauthorized IAM User Creation
status: experimental
description: Detects creation of new IAM users which may indicate persistence by APT41
references:
  - https://attack.mitre.org/techniques/T1136/003/
tags:
  - attack.persistence
  - attack.t1136.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: CreateUser
    eventSource: iam.amazonaws.com
  filter:
    userIdentity.arn|contains: "automation"
  condition: selection and not filter
falsepositives:
  - Automated provisioning pipelines
level: high`,
    },
    {
      title: 'SIGMA Rule \u2014 S3 Bulk Data Exfiltration Pattern',
      code: `title: S3 Bulk Data Exfiltration Pattern
status: experimental
description: Detects high-volume S3 GetObject calls indicating potential data exfiltration
tags:
  - attack.exfiltration
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: GetObject
    eventSource: s3.amazonaws.com
  timeframe: 5m
  condition: selection | count(requestParameters.bucketName) by sourceIPAddress > 100
falsepositives:
  - Backup operations
  - Analytics pipelines
level: medium`,
    },
  ],
}

export const awsGuardrails: Guardrails = {
  excluded: [
    'prod-* (all production buckets)',
    'arn:aws:iam::*:role/ProductionRole',
    'RDS instances tagged Environment=Production',
    'arn:aws:lambda:*:*:function:prod-*',
    'arn:aws:eks:*:*:cluster/production-*',
  ],
  schedule: 'Monday \u2013 Friday  |  02:00 \u2013 06:00 UTC  |  Auto-pause on incidents',
  scopeLimits: [
    'Maximum 10 concurrent API calls per emulation',
    'No data modification in S3 buckets tagged critical=true',
    'EC2 instance launches limited to t3.micro in sandbox VPC',
    'No IAM policy changes in production accounts',
    'Automatic rollback if GuardDuty CRITICAL finding detected',
  ],
}
