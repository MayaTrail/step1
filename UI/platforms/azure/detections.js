/* ══════════════════════════════════════════
   MayaTrail — Azure Detections & Guardrails
   ══════════════════════════════════════════ */

window.MayaTrail.platforms.azure = window.MayaTrail.platforms.azure || {};

window.MayaTrail.platforms.azure.detections = {
  ruleCount: 189,
  formats: 'SIGMA \u00b7 KQL \u00b7 Microsoft Sentinel',
  rules: [
    {
      title: 'SIGMA Rule \u2014 Suspicious Azure AD Sign-In Pattern',
      code: 'title: Azure AD Password Spray Detection\nstatus: experimental\ndescription: Detects distributed password spray against Azure AD by correlating failed login attempts\nreferences:\n  - https://attack.mitre.org/techniques/T1110/003/\ntags:\n  - attack.credential_access\n  - attack.t1110.003\nlogsource:\n  product: azure\n  service: signinlogs\ndetection:\n  selection:\n    ResultType: "50126"\n  timeframe: 1h\n  condition: selection | count(UserPrincipalName) by IPAddress > 10\nfalsepositives:\n  - Automated monitoring tools\n  - Legitimate authentication testing\nlevel: high'
    },
    {
      title: 'KQL \u2014 Azure Key Vault Secret Access Anomaly',
      code: 'let baseline = AzureDiagnostics\n| where ResourceType == "VAULTS"\n| where OperationName == "SecretGet"\n| where TimeGenerated between(ago(30d) .. ago(7d))\n| summarize BaselineCount = count() by CallerIPAddress;\nAzureDiagnostics\n| where ResourceType == "VAULTS"\n| where OperationName == "SecretGet"\n| where TimeGenerated > ago(24h)\n| summarize RecentCount = count() by CallerIPAddress\n| join kind=leftanti baseline on CallerIPAddress\n| where RecentCount > 5\n| project CallerIPAddress, RecentCount\n| extend ThreatActor = "Peach Sandstorm", Technique = "T1555.006"\n| sort by RecentCount desc'
    },
    {
      title: 'KQL \u2014 Suspicious Azure AD Application Permission Grant',
      code: 'AuditLogs\n| where TimeGenerated > ago(7d)\n| where OperationName in (\n    "Consent to application",\n    "Add app role assignment grant to user",\n    "Add delegated permission grant"\n  )\n| extend AppName = tostring(TargetResources[0].displayName)\n| extend Permissions = tostring(TargetResources[0].modifiedProperties)\n| where Permissions has_any ("Mail.Read", "Mail.ReadWrite", "Files.ReadWrite.All", "User.ReadWrite.All")\n| project TimeGenerated, \n    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),\n    AppName,\n    Permissions,\n    CorrelationId\n| extend ThreatActor = "APT29/Midnight Blizzard"\n| extend Technique = "T1098.003"'
    }
  ]
};

window.MayaTrail.platforms.azure.guardrails = {
  excluded: [
    'Production Azure subscriptions (tag: env=production)',
    'Azure Key Vaults containing production secrets',
    'Entra ID Global Administrator accounts',
    'Exchange Online production mailboxes',
    'Azure DevOps production organizations'
  ],
  schedule: 'Monday \u2013 Friday  |  02:00 \u2013 06:00 UTC  |  Auto-pause on Sentinel incidents',
  scopeLimits: [
    'Maximum 5 concurrent API calls per emulation',
    'No modifications to Conditional Access policies in production tenant',
    'Azure VMs limited to Standard_B1s in sandbox subscription',
    'No Entra ID role assignments above Directory Reader',
    'Automatic rollback if Defender for Cloud HIGH alert detected'
  ]
};
