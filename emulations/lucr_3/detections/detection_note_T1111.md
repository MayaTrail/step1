# Detection Note: T1111 - Multi-Factor Authentication Interception

This technique operates on the data plane (telecom provider infrastructure) and generates
NO audit log events within AWS, Okta, Azure AD, or M365.

Real LUCR-3 execution: SIM swapping via telecom fraud or helpdesk social engineering to
forward SMS OTPs. The outcome (a valid sessionToken) is indistinguishable in Okta logs
from a legitimate MFA approval - only the delivery mechanism differs.

Lab emulation: operator manually approves MFA on enrolled test device; same sessionToken
outcome without illegal telecom manipulation.

## Detection Alternatives

### Telecom / Carrier-Side (out of scope for cloud sandbox)
- Carrier SIM-swap fraud alert feeds (AT&T, Verizon, T-Mobile Protect APIs)
- Number porting alert subscriptions via CTIA Short Message Service registry

### Okta / Identity (indirect signals - no direct interception event)
- user.session.start from geolocation that does not match user's registered address
  (Okta ThreatInsight anomalous location heuristic)
- Sudden MFA factor type change (e.g. SMS -> TOTP) correlated with prior T1621 flood:
  Sigma: sigma_T1621.yml + sigma_T1098.005.yml sequential correlation
- Okta System Log: user.account.update_phone_number - phone number changed hours before
  successful auth (pre-SIM-swap indicator)

### SIEM Correlation Rule
Combine T1621 (MFA flood) + T1098.005 (new factor enrolled from external IP) within
a 2-hour window on the same actor. The sequence MFA-flood -> attacker-device-enrolled
is the audit-visible footprint of what SIM-swap achieves covertly.

### Vendor Threat Intelligence
- Okta ThreatInsight: enabled suspicious-activity scoring for the tenant
- Microsoft Entra ID Protection: "Unfamiliar sign-in properties" risk policy
- Telecom Intelligence: subscribe to SIM-swap notification APIs (carrier-dependent)
