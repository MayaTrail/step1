# Detection Note: T1087 (Enumerate SES for Phishing Capability)

**Signal:** several **distinct** SES capability-read APIs called by one
principal in a short window, an actor establishing whether the account can
send mail, at what volume, and from which verified identities.

**The fingerprint is the signal, not any single call.** `GetSendQuota` and
`GetAccountSendingEnabled` are read by dashboards and health checks. A rule
matching any one of them fires on benign monitoring. Threshold on the count of
*distinct* SES read APIs per principal instead, and require at least one
identity-enumeration call, quota checks alone are monitoring; enumerating
which verified identities exist is the phishing-specific step.

**SESv2 coverage is mandatory.** The original rule listed v1 names only, so an
attacker using the SESv2 SDK produced `GetAccount` and `ListEmailIdentities`
and was never matched. Both are included now.

**One event source:** SES v1 and SESv2 both log under `ses.amazonaws.com`.
There is no separate `email.amazonaws.com` source.

**The follow-on abuse is only half-visible in CloudTrail.** `ses:SendEmail` and
`SendRawEmail` are **data-plane** events, they are not management events and
will not appear in `lookup-events` or the `AWSCloudTrail` table. To detect the
actual sending:

| What to watch | Where |
|---|---|
| Send volume spikes | CloudWatch `AWS/SES` `Send` metric, or SES event publishing |
| Sandbox exit / sending re-enabled | CloudTrail, `UpdateAccountSendingEnabled` |
| New sending identity created | CloudTrail, `VerifyEmailIdentity`, `CreateEmailIdentity` |

The third Sigma document covers the CloudTrail-visible half.

**Error strings:** SES denials surface as `AccessDenied` /
`AccessDeniedException`, not `Client.`-prefixed like EC2. Match both if you add
a permission-probing rule, and confirm against a real event.

**MITRE note:** the manifest maps T1087 (*Account Discovery*), a poor fit for
an email-service capability probe. T1526 (*Cloud Service Discovery*) is closer.
The mapping is inherited from the upstream catalogue and retained for
traceability.

**Severity:** the manifest rates this LOW; the IR view is **Medium**, recon is
a precursor to send abuse, which carries real reputational and deliverability
damage.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1087.yml`, three documents: the read base rule (`low`), the
  fingerprint `value_count` correlation (`high`), and the
  account-prepared-for-sending follow-on rule (`high`).
- `kql_t1087.kql`, the fingerprint detection with identity-enumeration
  weighting.

Full response procedure is in `../PLAYBOOK.md`.
