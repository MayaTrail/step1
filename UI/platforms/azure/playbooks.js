/* ══════════════════════════════════════════
   MayaTrail — Azure IR Playbooks Data
   ══════════════════════════════════════════ */

window.MayaTrail.platforms.azure = window.MayaTrail.platforms.azure || {};

window.MayaTrail.platforms.azure.playbooks = [
  // [0] APT29 / Midnight Blizzard Azure Playbook
  {
    steps: [
      {
        title: 'Detect OAuth Token Abuse',
        body: 'Query Azure AD Sign-in Logs for anomalous OAuth application activity. Look for consent grants to unfamiliar applications, token issuance from unexpected IP ranges, and application access to sensitive APIs like Microsoft Graph mail endpoints.',
        code: 'SigninLogs\n| where TimeGenerated > ago(7d)\n| where AppDisplayName !in ("Microsoft Office", "Azure Portal")\n| where ResultType == 0\n| summarize count() by AppDisplayName, IPAddress, UserPrincipalName\n| sort by count_ desc'
      },
      {
        title: 'Revoke Compromised Tokens & Sessions',
        body: 'Immediately revoke all refresh tokens for compromised accounts. Disable suspicious application registrations. Remove credential secrets from compromised app registrations. Force re-authentication for all affected users.',
        code: 'az ad user update --id compromised@company.com \\\n  --force-change-password-next-sign-in true\naz ad app credential reset --id APP_OBJECT_ID\naz account clear'
      },
      {
        title: 'Audit Application Registrations',
        body: 'APT29 adds credentials to existing app registrations for persistence. Review all app registrations for new secrets or certificates added during the compromise window. Check for excessive API permissions (Mail.Read, Files.ReadWrite).',
        code: 'az ad app list --query "[].{name:displayName,appId:appId,passwordCredentials:passwordCredentials}" --output table\naz ad app permission list --id APP_ID'
      },
      {
        title: 'Check Exchange Online Email Exfiltration',
        body: 'Review Unified Audit Log for MailItemsAccessed events. Identify which mailboxes were accessed using the compromised OAuth tokens. Check for mail forwarding rules or inbox rules created by the attacker.',
        code: 'Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) \\\n  -Operations MailItemsAccessed -ResultSize 5000 | \\\n  Select-Object CreationDate, UserIds, Operations, AuditData'
      },
      {
        title: 'Restore Audit Logging Integrity',
        body: 'Verify Azure AD Diagnostic Settings are sending logs to Log Analytics. Confirm Unified Audit Log is enabled. Check for any modifications to Conditional Access policies that might have been weakened by the attacker.',
        code: 'az monitor diagnostic-settings list --resource "/providers/Microsoft.aadiam/diagnosticSettings"\naz ad conditional-access policy list'
      },
      {
        title: 'Implement Post-Incident Hardening',
        body: 'Enable Conditional Access policies requiring compliant devices for admin access. Restrict app consent to admin-approved apps only. Enable continuous access evaluation. Implement token protection policies. Require phishing-resistant MFA for all admins.'
      }
    ]
  },
  // [1] Storm-0558 Playbook
  {
    steps: [
      {
        title: 'Detect Forged Token Activity',
        body: 'Search Azure AD Sign-in Logs for tokens issued with anomalous claims or from unexpected issuers. Check for authentication events that bypass normal Conditional Access policies. Look for access to Exchange Online from IPs not associated with your organization.',
        code: 'SigninLogs\n| where TimeGenerated > ago(30d)\n| where ResourceDisplayName == "Office 365 Exchange Online"\n| where IPAddress !startswith "10." and IPAddress !startswith "172."\n| summarize count() by UserPrincipalName, IPAddress, Location\n| where count_ > 50'
      },
      {
        title: 'Identify Affected Mailboxes',
        body: 'Storm-0558 specifically targets email. Enumerate all mailboxes accessed during the compromise window. Check for GetItem and GetFolder operations in the Unified Audit Log. Identify any email forwarding rules or delegates added.',
        code: 'Search-UnifiedAuditLog -StartDate "2023-05-15" -EndDate "2023-07-16" \\\n  -RecordType ExchangeItem -ResultSize 5000 | \\\n  Where-Object { $_.Operations -match "MailItemsAccessed" }'
      },
      {
        title: 'Rotate All Signing Keys & Certificates',
        body: 'If token forging is confirmed, work with Microsoft to rotate all tenant-level signing keys. Regenerate all SAML and OAuth signing certificates. This is a critical step that requires coordination with Microsoft support.',
        code: 'az ad app key list --id APP_ID\naz ad sp credential list --id SERVICE_PRINCIPAL_ID'
      },
      {
        title: 'Enable Enhanced Token Protection',
        body: 'Enable Conditional Access token protection policies. Implement Continuous Access Evaluation (CAE) to detect revoked tokens in real-time. Configure token lifetime policies to reduce the window of exploitation.'
      },
      {
        title: 'Deploy Advanced Monitoring',
        body: 'Enable Microsoft Sentinel with Azure AD connector. Deploy custom analytics rules for token anomaly detection. Monitor for unusual Graph API access patterns. Alert on any new application permissions being granted.',
        code: 'AuditLogs\n| where OperationName has "Consent to application"\n| where TimeGenerated > ago(24h)\n| project TimeGenerated, InitiatedBy, TargetResources\n| sort by TimeGenerated desc'
      }
    ]
  },
  // [2] MuddyWater Azure Playbook
  {
    steps: [
      {
        title: 'Detect Exchange Server Exploitation',
        body: 'Check for indicators of ProxyShell or ProxyLogon exploitation on Exchange servers. Review IIS logs for webshell access patterns. Monitor for unusual w3wp.exe child processes on Exchange servers.',
        code: 'SecurityEvent\n| where EventID == 4688\n| where ParentProcessName has "w3wp.exe"\n| where Process has_any ("cmd.exe", "powershell.exe", "certutil.exe")\n| project TimeGenerated, Computer, ParentProcessName, CommandLine'
      },
      {
        title: 'Isolate Compromised Azure VMs',
        body: 'Apply Network Security Group rules to block all inbound and outbound traffic from compromised VMs. Preserve VM disk snapshots for forensic analysis. Do not deallocate VMs as this destroys volatile memory.',
        code: 'az network nsg rule create \\\n  --nsg-name compromised-vm-nsg \\\n  --name DenyAllInbound --priority 100 \\\n  --direction Inbound --access Deny \\\n  --source-address-prefixes "*" --destination-port-ranges "*"\naz snapshot create --name forensic-snapshot \\\n  --source /subscriptions/.../disks/compromised-disk'
      },
      {
        title: 'Hunt for PowerShell Persistence',
        body: 'MuddyWater uses PowerShell extensively. Search for encoded PowerShell commands, scheduled tasks, and startup scripts on compromised Azure VMs. Check Azure Automation accounts for rogue runbooks.',
        code: 'az automation runbook list \\\n  --automation-account-name MyAutomation \\\n  --resource-group MyResourceGroup \\\n  --output table'
      },
      {
        title: 'Audit Azure AD Changes',
        body: 'Review Azure AD Audit Logs for account creation, role assignments, and application permission changes made during the compromise window. Check for new guest accounts or federated domain additions.',
        code: 'AuditLogs\n| where TimeGenerated > ago(7d)\n| where OperationName in ("Add user", "Add member to role", "Add app role assignment")\n| project TimeGenerated, OperationName, InitiatedBy, TargetResources'
      },
      {
        title: 'Patch & Harden Exchange',
        body: 'Apply all Exchange Server security updates immediately. Enable Extended Protection. Restrict Exchange server internet exposure via Azure Application Proxy. Consider migration to Exchange Online if not already done.'
      },
      {
        title: 'Deploy Detection & Prevention',
        body: 'Enable Microsoft Defender for Endpoint on all Azure VMs. Deploy Azure Firewall for centralized network inspection. Enable Azure AD Identity Protection risk-based policies. Create Sentinel analytics rules for MuddyWater TTPs.'
      }
    ]
  },
  // [3] LAPSUS$ Azure Playbook
  {
    steps: [
      {
        title: 'Detect MFA Fatigue Attacks',
        body: 'Search Azure AD Sign-in Logs for multiple failed MFA challenges followed by a successful authentication. This pattern indicates MFA push bombing. Check for sign-ins from unfamiliar locations after MFA approval.',
        code: 'SigninLogs\n| where TimeGenerated > ago(7d)\n| where ResultType in ("50074", "500121")\n| summarize FailCount=count(), SuccessCount=countif(ResultType==0) by UserPrincipalName, bin(TimeGenerated, 1h)\n| where FailCount > 5 and SuccessCount > 0'
      },
      {
        title: 'Contain Azure DevOps Access',
        body: 'If Azure DevOps is compromised, immediately revoke Personal Access Tokens (PATs) for affected users. Remove compromised accounts from DevOps organizations. Review recent repository clone and download activity.',
        code: 'az devops security permission list --org https://dev.azure.com/company\naz repos list --organization https://dev.azure.com/company --project MyProject'
      },
      {
        title: 'Audit Entra ID Role Assignments',
        body: 'LAPSUS$ assigns Global Administrator role to compromised accounts. Review all role assignments made during the compromise window. Check for Privileged Identity Management (PIM) role activations.',
        code: 'AuditLogs\n| where OperationName == "Add member to role"\n| where TargetResources[0].modifiedProperties[0].newValue has "Global Administrator"\n| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].userPrincipalName'
      },
      {
        title: 'Check for Source Code Exfiltration',
        body: 'Review Azure DevOps audit logs for git clone operations. Check for Azure Repos being accessed by unfamiliar service connections. Identify if any pipeline secrets or variable groups were accessed.',
        code: 'az devops audit-log query \\\n  --org https://dev.azure.com/company \\\n  --start-time 2024-01-01T00:00:00Z'
      },
      {
        title: 'Implement Anti-MFA-Fatigue Controls',
        body: 'Switch from push notifications to number matching or FIDO2 security keys. Enable Conditional Access policies requiring compliant devices. Implement risk-based Conditional Access with Identity Protection. Enforce phishing-resistant MFA for all admin accounts.',
        code: 'az ad conditional-access policy list \\\n  --query "[?state==\'enabled\'].{name:displayName,grantControls:grantControls}"'
      }
    ]
  },
  // [4] Peach Sandstorm Azure Playbook
  {
    steps: [
      {
        title: 'Detect Password Spray Campaign',
        body: 'Monitor Azure AD Sign-in Logs for distributed password spray patterns: same password attempted across many accounts from rotating IP addresses. Check for Smart Lockout triggers and risky sign-in detections.',
        code: 'SigninLogs\n| where TimeGenerated > ago(7d)\n| where ResultType == "50126"\n| summarize AttemptCount=count(), DistinctUsers=dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 1h)\n| where DistinctUsers > 10'
      },
      {
        title: 'Contain Successfully Sprayed Accounts',
        body: 'Identify accounts that had successful sign-ins from spray source IPs. Force password reset. Revoke all refresh tokens. Check if attackers established persistence via app registrations or MFA registration.',
        code: 'az ad user list --query "[?accountEnabled].{UPN:userPrincipalName,LastPasswordChange:lastPasswordChangeDateTime}" --output table'
      },
      {
        title: 'Audit Azure Key Vault Access',
        body: 'Peach Sandstorm targets Key Vault for secrets and certificates. Review Key Vault access policies and RBAC assignments. Check diagnostic logs for secret read operations from compromised identities.',
        code: 'az keyvault list --output table\naz monitor diagnostic-settings list --resource /subscriptions/SUB_ID/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/VAULT_NAME'
      },
      {
        title: 'Review Azure Storage Access',
        body: 'Check Azure Storage account access logs for unusual download activity. Review SAS tokens that may have been generated. Verify storage account network rules restrict access to known IPs.',
        code: 'az storage account list --query "[].{name:name,networkRuleSet:networkRuleSet.defaultAction}" --output table'
      },
      {
        title: 'Harden Against Password Spray',
        body: 'Enable Azure AD Password Protection with custom banned password lists. Implement Smart Lockout with aggressive thresholds. Enforce Conditional Access requiring MFA for all sign-ins. Enable Risk-based policies in Identity Protection.',
        code: 'az ad password-policy show\naz ad conditional-access policy create \\\n  --display-name "Require MFA for all users" \\\n  --state enabled'
      }
    ]
  }
];
