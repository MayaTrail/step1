# Detection Note — T1087 (Enumerate SES for Phishing Capability)

**Signal:** Multiple SES read APIs (ses:GetAccountSendingEnabled, ses:GetSendQuota, ses:ListIdentities, ses:GetIdentityVerificationAttributes) called in rapid succession from unexpected principals

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
