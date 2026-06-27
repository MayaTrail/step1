# Detection Note — T1550.001 (Create IAM Roles Anywhere Trust Anchor)

**Signal:** rolesanywhere:CreateTrustAnchor — rare API call almost never made outside initial IAM Roles Anywhere setup; warrants immediate investigation

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
