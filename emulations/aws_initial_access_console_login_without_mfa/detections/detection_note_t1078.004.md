# Detection Note: T1078.004 (Console Login Without MFA)

**Signal:** a CloudTrail `ConsoleLogin` event with
`additionalEventData.MFAUsed = No` and `responseElements.ConsoleLogin =
Success`, for an identity that should have MFA enforced.

## These shipped rules were already good

Worth stating, because it is the exception in this catalogue: the original
Sigma and KQL here were correctly scoped, filtered both `MFAUsed` and the login
result, and documented false positives. They were hand-written, not
auto-derived, and they were deployable as-is.

Everything added is **coverage they lacked**, not a fix for brokenness:

| Addition | Why |
|---|---|
| SSO/SAML exclusion | Stops false positives on compliant IdP-MFA sessions |
| Root variant at `critical` | Root without MFA is categorically worse |
| Brute-force companion | The success rule cannot see the attempts that preceded it |

## The SSO false positive

For SAML and IAM Identity Center console sessions, MFA is enforced at the
**identity provider**, and AWS may record `MFAUsed=No` even though the user did
complete MFA. Alerting on those is a false positive that erodes trust in the
rule until it gets muted.

Exclusions must cover **three** things, not one:

1. Identity Center default roles, `:assumed-role/AWSReservedSSO_`
2. External SAML federation, `userIdentity.type: SAMLUser`
3. **Your own custom-named permission sets**, the `AWSReservedSSO_` prefix
   only matches Identity Center defaults. Renamed permission sets will not
   match it and must be enumerated locally.

Treat MFA posture for all of these as an IdP-side control.

## Field details

- `responseElements.ConsoleLogin` is `Success` or `Failure`.
- `additionalEventData.MFAUsed` is `Yes` or `No`.
- Match these exact strings. In KQL, `parse_json` then compare with `==`,
  do **not** use `has`, which is whole-term and unreliable here.
- Console sign-in is a **global** event, recorded in **us-east-1**. A
  region-filtered workspace or query returns nothing.
- **Root has no `userName`.** Any triage query pivoting on `Username` is
  IAM-user-only and will silently miss root entirely. Pivot on
  `userIdentity.type` and the ARN.

**Containment note:** `aws:TokenIssueTime` conditions do not constrain
long-lived IAM user access keys, that lever works on STS sessions, not static
credentials.

**MITRE:** T1078.004 (*Valid Accounts: Cloud Accounts*) is correct, no caveat.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1078.004.yml`, four documents: the original success rule with the
  SSO/SAML exclusion added (`medium`), the root variant (`critical`), the
  brute-force correlation (`high`), and its failure base rule (`low`).
- `kql_t1078.004.kql`, the enriched success query plus the brute-force
  companion query in comments.

Full response procedure is in `../PLAYBOOK.md`.
