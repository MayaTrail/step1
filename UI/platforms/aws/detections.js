/* ══════════════════════════════════════════
   MayaTrail — AWS Detections & Guardrails
   ══════════════════════════════════════════ */

window.MayaTrail.platforms.aws = window.MayaTrail.platforms.aws || {};

window.MayaTrail.platforms.aws.detections = {
  ruleCount: 212,
  formats: 'SIGMA \u00b7 KQL \u00b7 YARA',
  rules: [
    {
      title: 'SIGMA Rule \u2014 APT29 CloudTrail Logging Disabled',
      code: 'title: APT29 CloudTrail Logging Disabled\nstatus: experimental\ndescription: Detects disabling of CloudTrail logging, a known APT29 defense evasion technique\nreferences:\n  - https://attack.mitre.org/techniques/T1562/008/\ntags:\n  - attack.defense_evasion\n  - attack.t1562.008\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  selection:\n    eventName: StopLogging\n    eventSource: cloudtrail.amazonaws.com\n  condition: selection\nfalsepositives:\n  - Legitimate maintenance operations\nlevel: high'
    },
    {
      title: 'KQL Query \u2014 Microsoft Sentinel (CloudTrail)',
      code: 'AWSCloudTrail\n| where EventName == "StopLogging"\n| where EventSource == "cloudtrail.amazonaws.com"\n| project TimeGenerated, UserIdentityArn, SourceIpAddress, UserAgent, RequestParameters\n| where TimeGenerated > ago(24h)\n| extend ThreatActor = "APT29", Technique = "T1562.008"'
    },
    {
      title: 'SIGMA Rule \u2014 Unauthorized IAM User Creation',
      code: 'title: Unauthorized IAM User Creation\nstatus: experimental\ndescription: Detects creation of new IAM users which may indicate persistence by APT41\nreferences:\n  - https://attack.mitre.org/techniques/T1136/003/\ntags:\n  - attack.persistence\n  - attack.t1136.003\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  selection:\n    eventName: CreateUser\n    eventSource: iam.amazonaws.com\n  filter:\n    userIdentity.arn|contains: "automation"\n  condition: selection and not filter\nfalsepositives:\n  - Automated provisioning pipelines\nlevel: high'
    },
    {
      title: 'SIGMA Rule \u2014 S3 Bulk Data Exfiltration Pattern',
      code: 'title: S3 Bulk Data Exfiltration Pattern\nstatus: experimental\ndescription: Detects high-volume S3 GetObject calls indicating potential data exfiltration\ntags:\n  - attack.exfiltration\n  - attack.t1530\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  selection:\n    eventName: GetObject\n    eventSource: s3.amazonaws.com\n  timeframe: 5m\n  condition: selection | count(requestParameters.bucketName) by sourceIPAddress > 100\nfalsepositives:\n  - Backup operations\n  - Analytics pipelines\nlevel: medium'
    }
  ]
};

window.MayaTrail.platforms.aws.guardrails = {
  excluded: [
    'prod-* (all production buckets)',
    'arn:aws:iam::*:role/ProductionRole',
    'RDS instances tagged Environment=Production',
    'arn:aws:lambda:*:*:function:prod-*',
    'arn:aws:eks:*:*:cluster/production-*'
  ],
  schedule: 'Monday \u2013 Friday  |  02:00 \u2013 06:00 UTC  |  Auto-pause on incidents',
  scopeLimits: [
    'Maximum 10 concurrent API calls per emulation',
    'No data modification in S3 buckets tagged critical=true',
    'EC2 instance launches limited to t3.micro in sandbox VPC',
    'No IAM policy changes in production accounts',
    'Automatic rollback if GuardDuty CRITICAL finding detected'
  ]
};
