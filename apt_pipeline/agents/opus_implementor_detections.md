## TASK: GENERATE DETECTIONS

Generate SIGMA rules + KQL queries for each control_plane technique. Adapt the log source and field names to the platform from the TI extract.

### Platform-Specific Audit Log References

**AWS CloudTrail fields:**
```
eventName, eventSource, sourceIPAddress, userIdentity.arn,
userIdentity.principalId, userIdentity.type, requestParameters,
responseElements, errorCode, errorMessage, userAgent, awsRegion
```

**Azure Activity Log / Azure AD fields:**
```
OperationName, Category, Caller, CallerIpAddress,
ResourceProvider, ResourceType, ResultType, ResultSignature,
Properties, TenantId, CorrelationId
```

**Okta System Log fields:**
```
eventType, actor.displayName, actor.alternateId, client.ipAddress,
outcome.result, outcome.reason, target[].displayName, target[].type,
authenticationContext.externalSessionId, debugContext.debugData
```

**GitHub Audit Log fields:**
```
action, actor, actor_location, org, repo, created_at,
operation_type, data, transport_protocol
```

### SIGMA Rule Template (adapt logsource to platform):
```yaml
# FILE: sigma_{technique_id}.yml
title: {Descriptive title}
id: {generate a UUID}
status: experimental
description: {What this detects and why it matters}
references:
    - https://attack.mitre.org/techniques/{technique_id}/
author: MayaTrail
date: 2026/04/15
tags:
    - attack.{tactic}
    - attack.{technique_id_lowercase}
logsource:
    # Adapt to platform:
    # AWS:   product: aws, service: cloudtrail
    # Azure: product: azure, service: activitylogs (or signinlogs, auditlogs)
    # Okta:  product: okta, service: okta
    # GitHub: product: github, service: audit
    product: {platform}
    service: {audit_service}
detection:
    selection:
        {event_field}: {event_value}    # e.g., eventName / OperationName / eventType / action
    filter_legitimate:
        {identity_field}: '{service_account_value}'
    condition: selection and not filter_legitimate
falsepositives:
    - {realistic false positive scenarios}
level: {informational|low|medium|high|critical}
```

### KQL Query Template (adapt table and fields to platform):
```kql
// FILE: kql_{technique_id}.kql
// {Technique name} — {Description}
// AWS:   AWSCloudTrail | where EventName == "..."
// Azure: AzureActivity | where OperationNameValue == "..."
//        SigninLogs | where AppDisplayName == "..."
// Okta:  Okta_CL | where eventType_s == "..."
{AuditTable}
| where {EventField} == "{event_value}"
| where {IdentityField} != "{service_account}"
| project TimeGenerated, {EventField}, {ActorField}, {IPField}, {ResultField}
| sort by TimeGenerated desc
```

### Rules for data_plane techniques:
DO NOT generate SIGMA/KQL rules for data_plane techniques — they have no audit log events.
Instead, document what COULD detect them based on the platform:
```yaml
# FILE: detection_note_{technique_id}.md
# Detection Note: {technique_name}
# This technique operates on the data plane and generates NO audit log events.
# Detection alternatives (include ALL that apply to the platform):
# AWS: VPC Flow Logs, GuardDuty findings, S3 access logs, CloudWatch metrics
# Azure: NSG Flow Logs, Azure Defender alerts, Activity Log (if applicable)
# Identity: IDP audit logs (Okta System Log, Azure AD Sign-in logs)
# SaaS: Application-specific audit logs (GitHub audit log, M365 UAL)
# Host: EDR telemetry, syslog, container runtime security (Falco, Sysdig)
# Network: WAF logs, DNS query logs, proxy logs
```
