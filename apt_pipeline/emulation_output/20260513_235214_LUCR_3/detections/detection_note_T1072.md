# Detection Note: T1072 - Software Deployment Tools (SCCM / Microsoft Intune)

This technique operates on the host/endpoint plane and is documented-only in the
LUCR-3 emulation - NOT implemented in the attack script. The sandbox has no domain
controller or domain-joined endpoints, so this technique cannot be safely emulated.

Real LUCR-3 execution: after gaining privileged AD/Entra ID access via federated
identity, the actor leverages SCCM or Microsoft Intune to push payloads to domain-joined
endpoints across the organization, achieving broad lateral movement and persistence
without direct host-by-host access.

## Detection Alternatives

### Microsoft SCCM / ConfigMgr Audit Logs (out of scope for this sandbox)
- SCCM audit log: new Software Distribution Package or Application Deployment created
  by an account that is not part of the standard change-management group
- SCCM: Script Execution approval bypassed or new PowerShell script deployed to large
  collection outside change window
- Windows Event ID 4688 (process creation) on managed endpoints: msiexec.exe,
  powershell.exe, or cmd.exe spawned by CcmExec.exe (SCCM client) with unusual arguments

### Microsoft Intune / Endpoint Manager
- Microsoft Endpoint Manager audit log: new Device Configuration Policy or Win32 App
  created by a recently-onboarded or federated account
- Azure AD Audit Log (OperationName: "Add device configuration policy") from anomalous
  principal
- Microsoft Defender for Endpoint: alert on suspicious child process of
  IntuneManagementExtension.exe

### Active Directory / Entra ID (prerequisite detection)
- Entra ID Audit Log: privileged role (Intune Administrator, Global Administrator)
  assigned to a federated user shortly before SCCM deployment activity
- Azure AD Sign-in Log: Intune admin portal access from anomalous geolocation

### Endpoint EDR Telemetry
- CrowdStrike / SentinelOne: process tree showing CcmExec.exe or
  IntuneManagementExtension.exe as parent of attacker payload
- Sysmon Event ID 1 (process creation): look for unexpected executables dropped to
  C:\Windows\ccmcache\ or %ProgramData%\Microsoft\IntuneManagementExtension\

### Network
- Unusual HTTPS traffic from a large number of endpoints to the same external IP
  immediately after a new Intune policy push (beaconing pattern)
- DNS: sudden spike in queries to an unknown domain from domain-joined hosts following
  a new application deployment
