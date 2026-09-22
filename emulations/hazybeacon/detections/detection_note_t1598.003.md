# Detection Note: T1598.003 - Phishing for Information: Spearphishing Link

**Execution plane:** data_plane
**Audit visible:** No - the phishing delivery is entirely outside AWS infrastructure.
This technique is documented as a precursor; the emulation lab simulates the post-compromise
state via EC2 UserData (pre-staging credentials) and does not replay the phishing delivery.

## Why no SIGMA/KQL rule

There is no AWS CloudTrail event for a phishing email being delivered or a user clicking a
link. The HazyBeacon backdoor was delivered via spearphishing; once the developer's workstation
was compromised, the backdoor harvested credentials. AWS only becomes visible at the first
API call using the stolen key (T1078.004).

## Detection alternatives

### Email gateway / MTA telemetry
- **Email security gateway logs**: inspect for messages with malicious URLs,
  lookalike sender domains, or attachment types matching the HazyBeacon delivery mechanism.
  Correlate sender domain against threat intelligence for HazyBeacon-associated infrastructure.
- **URL filtering / web proxy logs**: DNS and proxy logs for resolution of the phishing domain
  at the time of click. Look for newly-registered domains or domains matching HazyBeacon TI IOCs.

### Endpoint telemetry (on hazybeacon-dev-instance or developer workstation)
- **EDR process spawn from email client**: parent process = Outlook/Thunderbird/browser,
  child = powershell/python/curl downloading payload. This is the canonical spearphishing
  execution chain.
- **Network connection from email client process**: EDR network telemetry showing the email
  client or browser initiating a connection to an external host immediately after link click.
- **HazyBeacon backdoor artifacts**: file drops in temp or home directories from the email
  client process. The backdoor subsequently reads ~/.aws/credentials (see T1552.001 note).

### AWS-side retrospective indicators
- **GuardDuty UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration**: if the instance
  profile credential was involved, GuardDuty flags use of the credential from outside EC2.
  For static credentials pre-placed in credentials file, this finding does not fire -
  use the T1078.004 source IP anomaly instead.

## Emulation note
This technique is not re-executed in the lab. UserData on hazybeacon-dev-instance pre-stages
the credential state that the phishing -> backdoor chain would have produced in a real
intrusion. The emulation begins at T1078.004 (credential validation via stolen key).
