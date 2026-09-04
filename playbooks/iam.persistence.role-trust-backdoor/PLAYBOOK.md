# IR Playbook: IAM Role Trust-Policy Backdoor — Persistent Outside Access through `iam:UpdateAssumeRolePolicy`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / Account manipulation (a role's trust policy is rewritten so a principal outside the organisation can assume it) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | **High**, P0 when the trust names a foreign account, a wildcard principal, or an unrecognised federated provider with no confining `Condition`. This is **resource-based-policy persistence** — one of the few AWS persistence classes credential rotation does not touch, alongside a backdoored S3 bucket policy, Lambda resource policy or KMS key policy. The attacker holds no credential of yours, so rotating every access key, console password and session token in the account leaves the backdoor working. Blast radius is every permission attached to the role, indefinitely, for whoever controls the trusted identity. The source rules rate the two paths P2 and P3 — and the P3 sits on the *more* severe finding, so the account-takeover case arrives with the lower priority. Correcting the disposition matters more than any rule-logic change |
| MITRE Tactics | Persistence (TA0003), Privilege Escalation (TA0004); the federated variant adds Defense Impairment (TA0112) through T1484.002 |
| MITRE Techniques | T1098.001 **and T1098.003** (T1484.002 for the federated-provider variant) — see the mapping note in §6 |
| Services in Scope | IAM, STS, CloudTrail, Organizations (SCP), IAM Access Analyzer, plus every service reachable by the backdoored role |

**What the technique does:** the actor calls `iam:UpdateAssumeRolePolicy` on a role it can
already modify and replaces the role's **trust policy** — the resource-based document that
answers "who may become this role". The new document adds an `Allow` on `sts:AssumeRole`
for a principal the actor controls: a 12-digit account ID in another AWS account,
`"Principal":{"AWS":"*"}`, or a `Federated` OIDC/SAML provider they registered. The same
backdoor can be planted at birth with `iam:CreateRole`, whose `assumeRolePolicyDocument`
parameter carries the identical document under a different field name. From then on the
actor calls `sts:AssumeRole` from outside and receives temporary credentials with every
permission the role holds, on demand, for as long as the document stands.

**Why this is potent, and why the usual reflexes miss it.** The reflex after a compromise
is to rotate — keys, passwords, tokens. None of it applies: the attacker authenticates as
*themselves*, in an account you do not control, and your account has been told to accept
that. The next reflex is to audit permissions, and `list-attached-role-policies` and
`list-role-policies` both return exactly what they returned yesterday, because the role's
*permissions* did not change. Same ARN, same policies, same tags, same name. The change is
one document no routine audit reads, and `UpdateAssumeRolePolicy` **overwrites** it with no
version history — once applied, the previous trust exists nowhere but an earlier CloudTrail
event.

**Detection is the decoded principal paired with the absence of a confining `Condition`,
not the event name and not the wildcard.** A trust naming a foreign account with
`sts:ExternalId` or `aws:PrincipalOrgID` is the documented third-party-access pattern; the
identical trust without one is a backdoor. The source rules match the event name with no
content inspection (P2) and the literal wildcard with no `Condition` test (P3), so the
ordinary case — one specific foreign account — is matched by neither.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail capturing IAM and STS **management** events. `UpdateAssumeRolePolicy` carries `requestParameters.roleName` and `requestParameters.policyDocument`, and returns **no** `responseElements`. `CreateRole` carries `requestParameters.roleName` and `requestParameters.assumeRolePolicyDocument`, and **nests** its response: `responseElements.role.arn` / `.roleName` / `.roleId` / `.assumeRolePolicyDocument`. A flat `responseElements.arn` is `null`
- **IAM is global — its CloudTrail events land in `us-east-1` only.** STS splits: calls to the global endpoint `sts.amazonaws.com` are logged in `us-east-1`, calls to a regional endpoint are logged in that Region. A single-region STS query misses the other half
- Cross-account use lands in **this** account's trail with `userIdentity.type: "AWSAccount"`, `userIdentity.accountId` = the calling account, and **no** `userIdentity.arn`; federated use as `WebIdentityUser` / `SAMLUser` with `userIdentity.identityProvider`. `sharedEventID` links this account's copy to the caller's
- **IAM Access Analyzer** with the **organization** as its zone of trust, in every Region you use — the only control here that finds a backdoor planted before the detection existed
- A **trust-policy baseline** per role in version control (IaC state, or a nightly `get-role` dump). The API keeps no prior version, so without this there is nothing to restore to

**Alerting (must be pre-configured)**
- **Trust policy written naming an AWS account outside the organisation with no confining `Condition` → P0**
- **Trust policy written with a wildcard principal (`"AWS":"*"` — the one wildcard form a trust policy accepts) → P0**
- **Trust policy written naming an OIDC/SAML provider not on the known-provider allowlist → P0**
- **`sts:AssumeRole` into this account by `userIdentity.type: AWSAccount` whose `accountId` is outside the organisation → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation and — specifically — not a session of any role whose trust is in question
- `jq`; `tools/decode_policy_documents.py` from the kit root; the trust-policy baseline files; the organisation's account-ID list from `aws organizations list-accounts` (generated, not hand-maintained)

**Known IOC Baselines**
- Which principals legitimately call `iam:UpdateAssumeRolePolicy` — normally the IaC deploy role and a named IAM-administration role, and nothing else
- Every 12-digit account ID inside the zone of trust, and **separately** every partner account you have deliberately granted cross-account access, with the `sts:ExternalId` each presents. Keeping the two lists apart is what makes a partner relationship ending into a detection
- Every OIDC and SAML provider ARN you trust, and the token claim each trust is pinned on

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Trust policy written naming an AWS account outside the organisation with no confining `Condition` | CloudTrail (management) | T1098.001 |
| P0 | Trust policy written with a wildcard principal (`"AWS":"*"` — the one wildcard form a trust policy accepts) | CloudTrail (management) | T1098.001 |
| P0 | Trust policy written naming an OIDC/SAML provider not on the known-provider allowlist | CloudTrail (management) | T1098.001, T1484.002 |
| P1 | `sts:AssumeRole` into this account by `userIdentity.type: AWSAccount` whose `accountId` is outside the organisation | CloudTrail (management) | T1098.001 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `UpdateAssumeRolePolicy` succeeding for a principal outside the IAM-administration set | CloudTrail (management) | T1098.001 |
| P2 | Four or more denied IAM role-write calls by one principal in ten minutes | CloudTrail (management) | T1098.001 |
| P2 | IAM Access Analyzer external-access finding on an `AWS::IAM::Role` | IAM Access Analyzer | T1098.001 |
| P3 | Cross-account trust added **with** a confining `Condition` (a new partner integration), or `CreateRole` by a principal outside the provisioning set | CloudTrail (management) | T1098.001 |

### Detection Rule Quality Notes

One rule matches the event name and inspects nothing; the other inspects the document only
for a literal wildcard, and rates it below the first.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `eventName:"UpdateAssumeRolePolicy"` with no content inspection, threshold 0 over 10m, `group_by: []` | Fires on every legitimate trust edit. One IaC apply touching N roles produces N alerts with no grouping key to collapse them — the volume that gets a rule muted, and muting takes the rare true positive with it | Keep the event as the trigger, but require the decoded document to name a principal outside the organisation with no confining `Condition`. Demote the bare event-name form to a `medium` rule scoped to callers outside the IAM-administration set |
| The wildcard rule matches only a literal `*`, and `CreateRole` is covered by nothing else | The ordinary technique — a trust naming one specific foreign 12-digit account — matches **nothing**, on either event. This is the case the playbook exists for and it is the case with no alert | Match an account principal in both accepted forms (bare 12-digit ID and `:root`/`:role`/`:user` ARN), subtract the organisation's own account IDs, and match both events as **sibling** blocks — `policyDocument` for the update, `assumeRolePolicyDocument` for the create, never ANDed into one |
| No `Condition` and no `Effect` test | The discriminator is absent: a trust confined by `sts:ExternalId` fires identically to an unconfined one, so partner integrations tune the rule off. And a `Deny` on `"Principal":{"AWS":"*"}` with `StringNotEquals` on `aws:PrincipalOrgID` is a **hardening** change that fires it — deploying a guardrail raises the alert | Read `Effect`, `Principal` and `Condition` from the **same** statement: only `Allow` creates trust, and `sts:ExternalId` / `aws:PrincipalOrgID` / `aws:PrincipalArn` / a pinned OIDC `:sub`-`:aud` claim confines it. A parse, not a substring match |
| Three of the four wildcard branches name a shape a role trust policy rejects, and the `\s*` in all four is dialect-dead | The extract *does* carry `\s*` — a missing one is not the defect. The dialect is: these are Lucene `regexp` terms (`...keyword:/.../`), and Lucene's RegExp grammar has no `\s` shorthand — `\<char>` means that literal character — so `\s*` reads as "zero or more letter `s`" and matches nothing in `"Principal":  {`. A document submitted with `--assume-role-policy-document file://trust.json` is pretty-printed, so all four branches miss it. Separately, `"Service":"*"`, `"Federated":"*"` and bare `"Principal":"*"` are each **rejected by IAM**, and a rejected write sets `errorCode`, which the rule already excludes — dead twice over | Keep `{"AWS":"*"}`, the one wildcard form AWS documents as accepted in a trust policy, and drop the other three under **one** evidentiary standard rather than three: AWS publishes `ROLE_TRUST_POLICY_UNSUPPORTED_WILDCARD_IN_PRINCIPAL` and `INVALID_FEDERATED_PRINCIPAL_SYNTAX_IN_ROLE_TRUST_POLICY` as Access Analyzer ERROR checks, and the User Guide states "The service principal in an IAM policy can't be `"Service": "*"`". Re-express the whitespace tolerance in a flavour the target backend defines — Sigma `|re` on RE2/PCRE/.NET/Lucene 9+, or an explicit `[ \t\n\r]*` class on Lucene 8 |
| Wildcard rule is P3, bare event-name rule is P2 | Inverted disposition. "Any AWS principal on the internet may assume this role" routes to a lower queue than "somebody edited a trust policy", and both fire on the same event so the P2 buries the P3 | P0 for an unconfined outside principal; `medium` for the caller-based rule |
| Neither rule looks at the denied path | A principal probing which role it may reshape is invisible, and denied probing and a completed rewrite are different incidents — merged into one alert, the rewrite is buried under the retries | A denied-write base rule plus a per-principal volume correlation, kept strictly separate from the success path. What must **not** be added is a size/omission companion: CloudTrail omits `requestParameters` only above 100 KB, and a role trust policy is quota-capped at 2,048 characters (8,192 at the adjustable maximum), ~12x below it. The 131,072 in the API reference is the parameter length constraint, not the enforced quota — a document between the two is refused with `LimitExceeded`, never stored, never logged as a success. There is no size-based evasion path here, so a rule built on one can never fire |

**Recommended detection — a trust policy that reaches outside the organisation.**

```yaml
# IAM Role Trust-Policy Backdoor (T1098.001)
#
# Two rules were supplied. The first matched `eventName:"UpdateAssumeRolePolicy"` with no
# content inspection at all, at P2, firing on every legitimate trust edit an IaC pipeline
# makes. The second inspected the document but only for a literal wildcard principal, at
# P3 — so the ordinary case, a trust naming a specific foreign 12-digit account, matched
# nothing, and the case that DID match (anyone on the internet may assume this role) was
# routed below the bare event-name rule that fires on everything.
#
# The discriminator is not the event and not the wildcard. It is whether the decoded trust
# document names a principal outside the organisation — a foreign account, `"AWS":"*"`, or
# an unfamiliar federated provider — WITH NO CONFINING `Condition`. A cross-account trust
# carrying `sts:ExternalId` or `aws:PrincipalOrgID` is the documented third-party-access
# pattern and is normal; the same trust without one is a backdoor. Every rule below is
# built on that pair of tests, and the pair is why an org-account allowlist and a known-IdP
# allowlist are deployment parameters rather than hard-coded values.
#
# ENCODING, and the direction matters. `requestParameters.policyDocument` and
# `.assumeRolePolicyDocument` are RAW JSON. The accepted pattern for both parameters
# explicitly admits the tab, line-feed and carriage-return escapes — literal whitespace a
# percent-encoded string could not contain — and both reference sample requests carry
# bare JSON. Percent-encoding (RFC 3986) is a property of what IAM RETURNS. So the
# request-side hazard is WHITESPACE, not encoding: a document submitted with
# `--assume-role-policy-document file://trust.json` is pretty-printed. Every pattern below
# is either a bare alphanumeric token or a `|re` with explicit `\s*`.
#
# FIELD SPLIT. `UpdateAssumeRolePolicy` carries the trust document in `policyDocument`;
# `CreateRole` carries it in `assumeRolePolicyDocument`. They never co-occur on one event,
# so they are SIBLING blocks ORed in `condition:` throughout — never two keys in one block,
# which would AND them and produce a rule that can never fire.
#
# SHAPES A ROLE TRUST POLICY REJECTS, and therefore shapes NO rule below matches. Every
# rule here carries `errorCode: null`, so a shape IAM refuses to store cannot fire one:
# matching it is dead code, and describing it as a hazard sends a responder hunting for a
# document that was never written. AWS publishes four such shapes, each as an Access
# Analyzer ERROR-type policy check:
#   NotPrincipal   "must be used with "Effect":"Deny"", and "You cannot use the
#                  NotPrincipal element in an IAM identity-based policy nor in an IAM role
#                  trust policy"      -> ROLE_TRUST_POLICY_SYNTAX_ERROR_NOTPRINCIPAL
#   "Principal":"*"  bare             -> ROLE_TRUST_POLICY_UNSUPPORTED_WILDCARD_IN_PRINCIPAL
#   "Federated":"*"                   -> INVALID_FEDERATED_PRINCIPAL_SYNTAX_IN_ROLE_TRUST_POLICY
#                  ("Update the federated principal to a domain name or a SAML metadata ARN")
#   "Service":"*"                     -> "The service principal in an IAM policy can't be
#                  "Service": "*"" (IAM User Guide, Principal element)
# All four fail with `MalformedPolicyDocument`. That is not nothing — it is an actor
# trying a shape and being refused — but it is EVIDENCE ON THE ERROR PATH, which is
# `iam_trust_write_denied`'s neighbourhood, not a stored-backdoor alert. `{"AWS":"*"}` is
# the one wildcard form AWS documents as accepted in a role trust policy, so it is the one
# the wildcard rule matches.
title: IAM role trust policy grants assume-role to a principal outside the organisation
id: 0d42d22b-b1a3-4faf-8798-62b4d2736c61
name: iam_role_trust_external_principal
status: experimental
description: >-
  A role trust policy was written naming an AWS account principal that is not on the
  organisation allowlist. Whoever controls that account can mint STS credentials for the
  role at will, and rotating every key and password in this account does not revoke it.
references:
  - https://attack.mitre.org/techniques/T1098/001/                                          # retrieved 2026-08-27
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html     # retrieved 2026-08-27
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html  # retrieved 2026-08-27
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.001
  - attack.t1098.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName:
      - 'UpdateAssumeRolePolicy'
      - 'CreateRole'
  # An account principal in either accepted form — bare 12-digit ID, or :root/:role/:user
  # ARN — scalar or array. `\s*` absorbs pretty-printing, the real request-side hazard.
  # DIALECT: `\s` needs a backend whose regex flavour defines it — RE2, PCRE, .NET, or
  # Lucene 9.0 and later. Lucene 8's RegExp grammar admits only `\<char>` meaning that
  # literal character, so there `\s*` reads as "zero or more letter s" and the pattern
  # silently matches nothing. On such a backend substitute an explicit class of space,
  # tab, LF and CR — the four characters the parameter's own pattern admits.
  account_principal_update:
    requestParameters.policyDocument|re: '"AWS"\s*:\s*\[?\s*"(arn:aws[a-z0-9-]*:(iam|sts)::)?[0-9]{12}'
  account_principal_create:
    requestParameters.assumeRolePolicyDocument|re: '"AWS"\s*:\s*\[?\s*"(arn:aws[a-z0-9-]*:(iam|sts)::)?[0-9]{12}'
  # DEPLOYMENT PARAMETER. Every account ID inside your zone of trust. Account IDs are bare
  # digits, so they are byte-identical in every submission form.
  org_accounts_update:
    requestParameters.policyDocument|contains:
      - '<this-account-id>'
      - '<other-org-account-id>'
  org_accounts_create:
    requestParameters.assumeRolePolicyDocument|contains:
      - '<this-account-id>'
      - '<other-org-account-id>'
  success:
    errorCode: null
  condition: selection and success and (account_principal_update or account_principal_create) and not (org_accounts_update or org_accounts_create)
falsepositives:
  - A cross-account trust confined by `sts:ExternalId` or `aws:PrincipalOrgID` — the
    documented third-party-access pattern, and the most common benign hit. This rule reads
    no `Condition`, by design — reading one is a parse, not a substring match. Decode
    before dispositioning; do not retune the rule.
  - A document naming BOTH an org account and a foreign account is suppressed here, because
    the allowlist filter is per-document rather than per-principal. The decoded sweep and
    the KQL evaluate each principal separately and close that gap — keep both deployed.
  - Account-vending provisioning a new member account before its ID reaches the allowlist.
    Generate the allowlist rather than maintaining it by hand.
level: high
---
# The wildcard case, reduced to the ONE form a role trust policy accepts. The source rule
# tried four: `Principal`, `AWS`, `Federated` and `Service`. Three of them are rejected
# shapes — see the four Access Analyzer ERROR checks in the header — and a rejected shape
# sets `errorCode`, which this rule filters out, so each was dead twice over. Dropping
# `Federated` and bare `Principal` alongside `Service` applies one evidentiary standard
# rather than three: where AWS publishes the rejection, the branch goes.
#
# What survives is `{"AWS":"*"}`, which AWS documents as accepted and dangerous: "After
# you create the role, you can change the account to "*" to allow everyone to assume the
# role... Do not leave your role accessible to everyone!"
#
# The cost of the reduction is one shape: a client that submits bare `"Principal":"*"`
# against an endpoint that accepts it. That write appears instead as
# `MalformedPolicyDocument` on the error path, where the rejected shapes belong.
title: IAM role trust policy grants assume-role to a wildcard principal
id: cae814ca-e4fc-46f0-b4b5-f1047ab6758e
name: iam_role_trust_wildcard_principal
status: experimental
description: >-
  A role trust policy was written whose principal is `*`. Absent a confining Condition,
  any AWS principal anywhere may assume the role and inherit every permission attached
  to it.
references:
  - https://attack.mitre.org/techniques/T1098/001/                                              # retrieved 2026-08-27
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html  # retrieved 2026-08-27
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.001
  - attack.t1098.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName:
      - 'UpdateAssumeRolePolicy'
      - 'CreateRole'
  wildcard_principal_update:
    requestParameters.policyDocument|re: '"AWS"\s*:\s*\[?\s*"\*"'
  wildcard_principal_create:
    requestParameters.assumeRolePolicyDocument|re: '"AWS"\s*:\s*\[?\s*"\*"'
  success:
    errorCode: null
  condition: selection and success and (wildcard_principal_update or wildcard_principal_create)
falsepositives:
  - A Deny statement using `"Principal":{"AWS":"*"}` with `StringNotEquals` on
    `aws:PrincipalOrgID` — a hardening change, not a backdoor. This rule reads neither
    `Effect` nor `Condition`, by design, so deploying that guardrail fires it. Decode to
    read the Effect; do not retune the rule.
  - An `"AWS":"*"` principal confined by `aws:PrincipalOrgID`, which is a legitimate
    organisation-wide trust. The Condition is not visible to a substring match.
level: high
---
# The federated route. `Federated` is a bare alphanumeric token, so this rule is immune to
# both the whitespace and the encoding hazards. An adversary who registers their own OIDC
# provider and points a role's trust at it holds a credential source that no key rotation
# in this account touches — which is why MITRE's Trust Modification is carried as a second
# tag here and nowhere else in this file.
title: IAM role trust policy grants assume-role to an unrecognised federated provider
id: dafe5600-32f2-4e35-b8f5-a666f1183a46
name: iam_role_trust_unknown_federated_provider
status: experimental
description: >-
  A role trust policy was written naming an OIDC or SAML federated principal that is not
  on the known-provider allowlist. The provider, not this account, decides who receives a
  token that satisfies the trust.
references:
  - https://attack.mitre.org/techniques/T1098/001/                                              # retrieved 2026-08-27
  - https://attack.mitre.org/techniques/T1484/002/                                              # retrieved 2026-08-27
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html  # retrieved 2026-08-27
tags:
  - attack.persistence
  - attack.privilege-escalation
  # T1484.002's own tactics are Defense Impairment (TA0112) and Privilege Escalation — NOT
  # Persistence, which arrives here from T1098.001. Both tactic tags are therefore carried.
  # `attack.defense-evasion` is retired: TA0005 is now Stealth and is not a tactic of either.
  - attack.defense-impairment
  - attack.t1098.001
  - attack.t1484.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName:
      - 'UpdateAssumeRolePolicy'
      - 'CreateRole'
  federated_update:
    requestParameters.policyDocument|contains: 'Federated'
  federated_create:
    requestParameters.assumeRolePolicyDocument|contains: 'Federated'
  # DEPLOYMENT PARAMETER. Substrings of the provider ARNs and built-in provider names you
  # deliberately trust, e.g. 'oidc-provider/token.actions.githubusercontent.com',
  # 'saml-provider/CorporateIdP', 'cognito-identity.amazonaws.com'.
  known_provider_update:
    requestParameters.policyDocument|contains:
      - '<oidc-provider/your-idp-host>'
      - '<saml-provider/YourIdPName>'
  known_provider_create:
    requestParameters.assumeRolePolicyDocument|contains:
      - '<oidc-provider/your-idp-host>'
      - '<saml-provider/YourIdPName>'
  success:
    errorCode: null
  condition: selection and success and (federated_update or federated_create) and not (known_provider_update or known_provider_create)
falsepositives:
  - A newly onboarded identity provider before its ARN reaches the allowlist. Onboarding a
    provider is itself a change that should be reviewed, so treat the hit as the review.
  - A trust pinned to a specific token subject (`token.actions.githubusercontent.com:sub`)
    for a provider you already trust but have not listed. Pinning is what makes an OIDC
    trust safe; list the provider rather than loosening the rule.
level: high
---
# The "who", for when the "what" is unreadable. Rewriting the trust policy of an EXISTING
# role is the narrow, rare act; CreateRole is deliberately excluded here because new roles
# are created constantly by ordinary automation and would bury this.
title: IAM role trust policy rewritten by a principal outside the IAM-administration set
id: 241393e8-0760-40a7-b9ee-272d7dd5dca9
name: iam_role_trust_written_by_unexpected_principal
status: experimental
description: >-
  UpdateAssumeRolePolicy succeeded for a principal that is not an IAM administrator or a
  provisioning pipeline. Who may become a role is an identity-perimeter change and has a
  short, enumerable list of legitimate callers.
references:
  - https://attack.mitre.org/techniques/T1098/001/                                          # retrieved 2026-08-27
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html     # retrieved 2026-08-27
tags:
  - attack.persistence
  - attack.t1098.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'UpdateAssumeRolePolicy'
  # DEPLOYMENT PARAMETER — the principals that legitimately edit trust policies.
  iam_admins:
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/IAMAdministrator'
      - ':role/BreakGlassAdmin'
  success:
    errorCode: null
  condition: selection and success and not iam_admins
falsepositives:
  - A trust edit submitted through CloudFormation. `userIdentity.arn` remains the
    submitting principal and `userIdentity.invokedBy` is `cloudformation.amazonaws.com`;
    do not blanket-exclude that, because a stack is also a way to launder the change.
  - Service-linked-role maintenance performed by an AWS service principal. Those carry
    `userIdentity.invokedBy` and no user ARN.
level: medium
---
# THE "WAS IT USED" PIVOT, as a rule.
#
# Verified against the AWS-published cross-account example: when a principal in another
# account assumes a role here, the ROLE OWNER's trail carries its own AssumeRole event in
# which `userIdentity.type` is `AWSAccount` and `userIdentity.accountId` is the CALLING
# account. There is no `userIdentity.arn` on that shape — a rule keyed on the ARN sees
# nothing. It is a management event, so lookup-events can retrieve it.
#
# Federated use lands with `userIdentity.type` `WebIdentityUser` or `SAMLUser` and a
# `userIdentity.identityProvider`. Those two values appear in AWS's example events but are
# not in the enumeration published for the flattened Sentinel column, so match both here
# and confirm the literal values against your own trail.
#
# THE ALLOWLIST IS SPLIT BECAUSE `identityProvider` CARRIES TWO DIFFERENT THINGS. AWS:
# "For SAMLUser, this is the saml:namequalifier key for the SAML assertion. For
# WebIdentityUser, this is the issuer name of the web identity federation provider." The
# OIDC form is the provider ARN and an ARN allowlist matches it. The SAML form is a hash —
# AWS's own AssumeRoleWithSAML example event carries
# `"identityProvider": "bdGOnTesti4+ExamplexL/jEvs="` — and no provider-ARN allowlist can
# ever match that. A single allowlist keyed on `identityProvider` therefore makes
# `federated_caller and not known_idp` TRUE for every workforce SSO sign-in in the estate:
# the rule fires on all of them, gets muted inside a day, and takes the real signal with
# it. The SAML provider ARN is a request parameter, not an identity field —
# `requestParameters.principalArn`, `arn:aws:iam::444455556666:saml-provider/Shibboleth`
# in that same example — so the two halves are sibling blocks ORed in the condition.
# `principalArn` is absent from AssumeRoleWithWebIdentity, which is why neither block can
# serve both.
#
# EVIDENCE LIMIT: CloudTrail does not log DENIED cross-account assume-role requests in the
# target account. An empty result proves nothing about attempts that failed.
title: STS AssumeRole into this account by an identity outside the organisation
id: d41ddff3-519f-46c7-a7d6-0bb10f2b4315
name: sts_assumerole_by_external_identity
status: experimental
description: >-
  A role in this account was assumed by a principal from an account outside the
  organisation, or through an unrecognised federated provider. Paired with a recent trust
  rewrite of the same role, this is the backdoor being exercised.
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html            # retrieved 2026-08-27
  - https://attack.mitre.org/techniques/T1098/001/                                          # retrieved 2026-08-27
tags:
  - attack.persistence
  - attack.t1098.001
  - attack.t1098.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sts.amazonaws.com'
    eventName:
      - 'AssumeRole'
      - 'AssumeRoleWithWebIdentity'
      - 'AssumeRoleWithSAML'
  external_account_caller:
    userIdentity.type: 'AWSAccount'
  federated_caller:
    userIdentity.type:
      - 'WebIdentityUser'
      - 'SAMLUser'
  # DEPLOYMENT PARAMETER — same org account list as the first rule.
  org_accounts:
    userIdentity.accountId:
      - '<this-account-id>'
      - '<other-org-account-id>'
  # DEPLOYMENT PARAMETER — OIDC half. `userIdentity.identityProvider` is the provider ARN
  # for WebIdentityUser, so an ARN substring matches it.
  known_idp_oidc:
    userIdentity.identityProvider|contains:
      - '<oidc-provider/your-idp-host>'
      - 'cognito-identity.amazonaws.com'
  # DEPLOYMENT PARAMETER — SAML half. For SAMLUser `identityProvider` is the
  # saml:namequalifier HASH, which no ARN can match; the provider ARN is here instead.
  known_idp_saml:
    requestParameters.principalArn|contains:
      - '<saml-provider/YourIdPName>'
  success:
    errorCode: null
  condition: selection and success and ((external_account_caller and not org_accounts) or (federated_caller and not (known_idp_oidc or known_idp_saml)))
falsepositives:
  - A third party you deliberately granted cross-account access. Their account ID belongs
    on a separate partner allowlist, not on the organisation list — keeping the two apart
    is what lets a partner relationship ending become a detection.
  - AWS Marketplace or a managed-service vendor assuming a delegated role. Baseline them
    once; the set is small and changes rarely.
  - A newly onboarded SAML or OIDC provider before its ARN reaches the matching half of
    the allowlist. Deploy this rule only once both halves are populated — with either half
    empty, every federated sign-in through that protocol is a hit.
level: high
---
title: IAM trust-policy write denied
id: 3107335f-dee0-4cd1-823a-883ec610f61b
name: iam_trust_write_denied
status: experimental
description: Base rule — volume component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html  # retrieved 2026-08-27
tags:
  - attack.discovery
  - attack.t1098.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName:
      - 'UpdateAssumeRolePolicy'
      - 'CreateRole'
      - 'UpdateRole'
      - 'PutRolePolicy'
      - 'AttachRolePolicy'
  denied:
    errorCode|contains: 'AccessDenied'
  condition: selection and denied
level: low
---
# Kept strictly separate from the success path. A principal collecting AccessDenied across
# role-write calls is finding out which role it can reshape, which is reconnaissance and
# must not share an alert with a completed trust rewrite. Neither source rule covers this
# at all: both carry a success filter and nothing looks at the denied path.
#
# `errorCode|contains: 'AccessDenied'` is prefix-tolerant deliberately. IAM policy denials
# surface as `AccessDenied` and service-evaluated denials as `AccessDeniedException`;
# matching the substring catches both. Confirm the exact form against a real denied event
# in your own trail. The full non-denial error set for these two calls, from their API
# reference Errors sections — `MalformedPolicyDocument`, `NoSuchEntity`, `LimitExceeded`,
# `UnmodifiableEntity` (service-linked roles, UpdateAssumeRolePolicy only),
# `EntityAlreadyExists`, `InvalidInput`, `ConcurrentModification` (CreateRole only) and
# `ServiceFailure` — is NOT probing and is excluded by construction.
#
# ONE OF THEM IS EVIDENCE, THOUGH. `MalformedPolicyDocument` naming `NotPrincipal`,
# `"Principal":"*"`, `"Federated":"*"` or `"Service":"*"` is an actor trying a shape a
# role trust policy rejects and being refused. Pull those out of the error stream by hand
# during an investigation — they are attempts, and they sit beside the AccessDenied
# probing above rather than beside a stored backdoor.
#
# THRESHOLD BASIS: derived from operator behaviour, not from an observed baseline — there
# is no emulation behind this rule. A human denied on a role write retries once, maybe
# twice, then stops or asks. Automation with a stale policy retries on a fixed interval,
# which the per-principal grouping and the ten-minute window separate out. Four or more
# denials in ten minutes sits above ordinary human retry. Baseline against your own
# account before deploying: this is a starting point, not a measurement.
title: IAM role-write calls denied repeatedly for one principal
id: 8043599c-e8ac-4a0f-91fa-921210eb0722
status: experimental
description: >-
  One principal was denied four or more IAM role-write calls within ten minutes — the
  signature of an actor searching for a role whose trust policy it is permitted to
  rewrite.
references:
  - https://attack.mitre.org/techniques/T1098/001/                                          # retrieved 2026-08-27
tags:
  - attack.discovery
  - attack.t1098.001
correlation:
  type: event_count
  rules:
    - iam_trust_write_denied
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gt: 3
level: medium
```

Reproduced byte-for-byte from the first rule document of `detections/sigma_t1098_001.yml`
(the file's leading comment block is not repeated — §2 above says the same thing in prose).
Six further documents ship in that file: the wildcard-principal and
unrecognised-federated-provider rules (`high`), the unexpected-principal rule (`medium`),
the external `AssumeRole` pivot (`high` — it is the P1 alerting bullet in §1, and a P1
signal backed by a `medium` rule routes to the wrong queue), and the denied-write base rule
(`low`) with its correlation (`medium`). **Deploy the file, not this excerpt.**

**What these rules structurally cannot do.** The disposition turns on three facts read from
the *same statement* — `Effect`, which principals it names, whether a `Condition` confines
them — and none is a substring question. The org-account filter is per-**document**, not
per-principal, so a trust naming an org account *and* a foreign one is suppressed; Query 2
and the `parse_json()` path in `detections/kql_t1098_001.kql` close that gap. **Treat a
Sigma hit as the trigger for the decode, not as a disposition.**

---

### Key Investigation Queries

> **IAM is a global service — its CloudTrail events land in `us-east-1` only.** STS is different: global-endpoint calls are logged in `us-east-1` and regional-endpoint calls in their own Region, so Query 5 sweeps Regions. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: who rewrote which role's trust, and when

```bash
REGION="us-east-1"; WINDOW="24 hours ago"

for EV in UpdateAssumeRolePolicy CreateRole; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d "$WINDOW" +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "iam.amazonaws.com") |
    (.userIdentity.arn // "") as $arn | ($arn | split("/")) as $p |
    # assumed-role ARN: role name is the 2nd "/" segment, the LAST is the SESSION name.
    # IAM-user ARN: the name IS the last segment. One idiom does not serve both.
    ((if ($arn | test(":assumed-role/")) then $p[1] else $p[-1] end)) as $caller |
    {time: .eventTime, event: .eventName,
     caller_arn: $arn, caller_name: $caller,
     access_key: .userIdentity.accessKeyId,        # feeds ACCESS_KEY_ID in Query 4
     role: .requestParameters.roleName,            # feeds ROLE in Containment Step 1
     created_role_arn: (.responseElements.role.arn // "-"),   # NESTED; flat .arn is null
     # The document is under a DIFFERENT key per event, and the two never co-occur.
     doc_present: ((.requestParameters.policyDocument //
                    .requestParameters.assumeRolePolicyDocument) != null),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

`role` and `time` drive Containment; `caller_arn` and `access_key` drive Step 3 and Query 4.
`doc_present: false` on a row whose `error` is `SUCCESS` is a **collection fault, not
evasion** — a trust policy is quota-capped ~12x below CloudTrail's 100 KB omission
threshold, so go to Query 3 for that role's live policy and fix the pipeline. Rows with an
`error` are the probing path: count them per `caller_arn`, never score them as changes. A
`MalformedPolicyDocument` whose document names `NotPrincipal`, `"Federated":"*"`,
`"Service":"*"` or a bare `"Principal":"*"` is an actor trying a shape IAM refuses —
an attempt, with nothing stored to find. If `caller_arn` belongs to a CloudFormation-driven principal, contain the stack as
well — the next drift reconciliation re-applies the change otherwise.

#### Query 2 — Inspect: decode each trust document and read it principal by principal

The shared decoder answers what no substring match can — `Effect`, which principals the
statement names, whether a `Condition` confines them — with the scalar-or-array and
bare-`"*"` shape guards an ad-hoc `jq` gets wrong. `ORG_ACCOUNTS` and `KNOWN_IDPS` are the
lists the Sigma rules carry.

```bash
REGION="us-east-1"; WINDOW="24 hours ago"
KIT="<path-to-playbook-authoring-kit>"
export ORG_ACCOUNTS="$(aws organizations list-accounts --query 'Accounts[].Id' \
                        --output text 2>/dev/null | tr '\t' ',')"
export KNOWN_IDPS="<oidc-provider/your-idp-host>,<saml-provider/YourIdPName>"
[ -n "$ORG_ACCOUNTS" ] || echo "[!] ORG_ACCOUNTS empty — set it by hand or every trust reads as external"

for EV in UpdateAssumeRolePolicy CreateRole; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d "$WINDOW" +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -c '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "iam.amazonaws.com") | select(.errorCode == null) |
    {time: .eventTime, caller: .userIdentity.arn,
     grantee: .requestParameters.roleName,
     policy_name: "trust-policy",
     doc: (.requestParameters.policyDocument //
           .requestParameters.assumeRolePolicyDocument)}' | \
  python3 "$KIT/tools/decode_policy_documents.py"
```

`[!] EXTERNAL` and `[!] PUBLIC` are terminal — the role was reachable from outside the
organisation from that timestamp. `[!] UNKNOWN IDP` is the same finding by the federated
route: the provider, not this account, decides who gets a satisfying token.
`[i] CONFINED` is an outside principal bounded by `sts:ExternalId` or `aws:PrincipalOrgID`:
disposition it against your partner list, do not act. The accepted verdicts are the full
`[i]` set — `INTERNAL`, `SERVICE`, `CONFINED`, `KNOWN IDP` and `UNPARSED`, the last meaning a
principal string carrying no 12-digit account, read by hand rather than dispositioned.
**No trust document reaches the decoder's `NotPrincipal` branch:** a role trust policy cannot
carry `NotPrincipal` under either `Effect`, so the branch is gated on `Effect: Deny` and
survives only for the resource-policy dialects that share the tool. The attempt surfaces as
`MalformedPolicyDocument` on the error path instead. A document that will not parse is
malformed or double-encoded — read it by hand.

#### Query 3 — Sweep: every role in the account whose live trust reaches outside the organisation

The account-wide hunt, and the only step that finds a backdoor planted before your log
retention window. It reads live policy, so it is also the ground truth whenever a
CloudTrail event's `requestParameters` did not reach your pipeline.

```bash
KIT="<path-to-playbook-authoring-kit>"
export ORG_ACCOUNTS="$(aws organizations list-accounts --query 'Accounts[].Id' \
                        --output text 2>/dev/null | tr '\t' ',')"
export KNOWN_IDPS="<oidc-provider/your-idp-host>,<saml-provider/YourIdPName>"

# list-roles hands back the trust document ALREADY PARSED into an object. That is botocore's
# `after-call.iam` handler — IMPLEMENTATION, not documentation: the "URL-encoded compliant
# with RFC 3986" sentence AWS attaches to GetRole and the Get*Policy APIs is ABSENT from the
# ListRoles reference, whose sample response carries bare JSON. Do not depend on the encoding
# either way — `tojson` returns the string the decoder expects, and its decode is conditional.
aws iam list-roles --output json | \
  jq -c '.Roles[] | {time: .CreateDate, caller: "-", grantee: .RoleName,
                     policy_name: "live-trust-policy",
                     doc: (.AssumeRolePolicyDocument | tojson)}' | \
  python3 "$KIT/tools/decode_policy_documents.py"
```

Every `[!]` is a role assumable from outside the organisation **right now**,
incident-related or not. Reconcile against the §1 baseline: here and not there is this
incident; in both is pre-existing exposure for the §6 findings. Service-linked roles appear
as `[i] SERVICE` and are expected. Cross-check with `aws accessanalyzer list-findings-v2`
against an analyzer whose zone of trust is the organization — it reasons over the policy
rather than matching patterns in it. **An IAM role is a global resource:** AWS states that a
role trust policy granting external access "generates a finding in each enabled Region". So
one backdoored role yields N identical findings to archive — and, the direction that matters
here, a **single-Region** analyzer still covered every role in the account. Never read one as
having been blind to this.

#### Query 4 — Session reconstruction: what else the principal did

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"
CHANGE_TIME="<time-from-Query-1>"          # ISO8601, the moment the trust write succeeded

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg t "$CHANGE_TIME" '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     phase: (if .eventTime > $t then "AFTER-CHANGE" else "before" end),
     role: (.requestParameters.roleName // "-"),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Read for **other trust writes first** — a principal that backdoored one role usually
backdoored several, and each is another `role` for Containment. Then for the primitives that
outlive the trust restore: `CreateAccessKey` / `CreateLoginProfile`, `PutRolePolicy` /
`AttachRolePolicy`, and `CreateOpenIDConnectProvider` / `CreateSAMLProvider` — registering a
provider is the federated half of this technique and must be removed with the trust naming it.

#### Query 5 — "Was it used": external assumption of the affected role, in this account's own trail

```bash
ROLE_ARN="<created_role_arn-from-Query-1-or-arn:aws:iam::ACCT:role/ROLE>"
STS_REGIONS="us-east-1 <your-other-active-regions>"

for R in $STS_REGIONS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$R" --output json 2>/dev/null
done | \
  jq -r --arg role "$ROLE_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "sts.amazonaws.com") |
    select((.requestParameters.roleArn // "") == $role
           or any(.resources[]?; (.ARN // "") == $role)) |
    # In the ROLE OWNER trail a cross-account assumption has NO userIdentity.arn.
    {time: .eventTime, event: .eventName,
     role_arn: $role,                              # feeds ROLE_ARN in Recovery
     caller_type: .userIdentity.type,
     calling_account: (.userIdentity.accountId // "-"),
     idp: (.userIdentity.identityProvider // "-"),
     session: (.requestParameters.roleSessionName // "-"),
     shared_event_id: (.sharedEventID // "-"),
     ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Any row whose `calling_account` is outside the organisation, or whose `caller_type` is
`WebIdentityUser` / `SAMLUser` with an unrecognised `idp`, is the backdoor being exercised —
escalate to a full account compromise. `shared_event_id` is the same GUID in the calling
account's trail and is how you attribute the session to a named principal there if you own
that account. **A `select` over `.resources[]` without the `?` drops every event whose
`resources` is absent, so both match arms are needed.**

> **The limit, stated because its absence gets misread as safety.** CloudTrail does not log
> **denied** cross-account assume-role requests in the target account. An empty result is
> evidence about successful use only — never that nobody tried.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The backdoor mints new credentials on demand and already-issued sessions run to their
expiry. **Restore the trust policy first, then revoke sessions** — the reverse order leaves
a window in which the attacker re-assumes and gets a fresh session whose
`aws:TokenIssueTime` is after the cutoff and therefore not denied.

> Run every command under the **break-glass responder credentials** from §1 — not under any
> principal being contained, and not under a session of any role whose trust is in question.

#### Step 1 — Capture each backdoored trust document, then restore the known-good one

```bash
# Every role Query 1, Query 2 and Query 3 flagged. Quote the placeholder into a variable
# first: a bare <...> in a for-list is a shell syntax error.
AFFECTED_ROLES="<space-separated-role-names-from-Query-1-2-3>"
BASELINE_DIR="<path-to-baseline>"

for R in $AFFECTED_ROLES; do
  if ! aws iam get-role --role-name "$R" >/dev/null 2>&1; then
    echo "[!] Role $R not found — confirm the name from Query 1"; continue
  fi
  # UpdateAssumeRolePolicy OVERWRITES with no version history — capture before restoring or
  # the backdoored document exists nowhere but the CloudTrail event. get-role NESTS.
  aws iam get-role --role-name "$R" --query 'Role.AssumeRolePolicyDocument' \
    --output json > "./evidence-${R}-trust.json"
  echo "[OK] Captured live trust policy for $R to ./evidence-${R}-trust.json"
  if [ -s "$BASELINE_DIR/${R}.trust.json" ]; then
    aws iam update-assume-role-policy --role-name "$R" \
      --policy-document "file://$BASELINE_DIR/${R}.trust.json" && \
      echo "[OK] $R trust restored — no NEW sessions can be minted"
  else
    echo "[!] $R has no baseline. Do NOT guess: apply a minimal trust naming only the"
    echo "    principals you can account for, then reconstruct the rest from the earlier"
    echo "    CloudTrail event that set it. Evidence: ./evidence-${R}-trust.json"
  fi
done
```

> Restoring the trust stops new sessions. It does **not** end sessions already issued, it
> does not remove any resource the attacker created while the backdoor stood, and it does
> not undo a federated provider they registered — that is Eradication.

#### Step 2 — Revoke the sessions the backdoor already minted

```bash
AFFECTED_ROLES="<space-separated-role-names-from-Query-1-2-3>"
CUTOFF="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

for R in $AFFECTED_ROLES; do
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}' && \
    echo "[OK] Denied every session of $R issued before $CUTOFF"
done
```

> `aws:TokenIssueTime` denies only tokens issued **before** the cutoff. It is safe here
> *because* Step 1 already ran: with the trust restored, no newer token can be issued to the
> attacker. Run in the other order and the deny is a no-op against the session they take out
> one second later.
>
> **It is indiscriminate, and it does not apply everywhere.** `Deny` on `"Action":"*"` kills
> **every** session of the role issued before the cutoff — the legitimate workloads running
> under it as much as the attacker's. Treat it as a deliberate outage, tell whoever owns the
> workload, and remove it in §4. And `put-role-policy` against a **service-linked role** fails
> with `UnmodifiableEntity` ("service-linked roles are protected AWS resources... Only the
> service that depends on the service-linked role can modify or delete the role"), so if the
> loop prints that, the trust was never attacker-writable — go back to Query 1.

#### Step 3 — Contain the principal that rewrote the trust

```bash
SUSPECT_ARN="<caller_arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')       # user ARN: name = last segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] Disabled key $K for $U"
  done
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')        # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}}}]}'
  echo "[OK] Revoked sessions for role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi

# Deny further identity-perimeter changes by the principal. All FIVE actions below are real
# IAM actions — IAM accepts an unknown action silently, so one typo makes this a no-op that
# reads as protection.
DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:UpdateAssumeRolePolicy","iam:CreateRole","iam:UpdateRole","iam:CreateOpenIDConnectProvider","iam:CreateSAMLProvider"],"Resource":"*"}]}'
if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  aws iam put-role-policy --role-name "$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')" \
    --policy-name "EmergencyDenyTrustEdits" --policy-document "$DENY_DOC"
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  aws iam put-user-policy --user-name "$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')" \
    --policy-name "EmergencyDenyTrustEdits" --policy-document "$DENY_DOC"
fi
```

> Disable, do not delete — an inactive key stays enumerable and keeps its creation
> metadata, while deleting destroys the evidence of what the attacker built.

---

## 4. Eradication

### Remove Attacker Access

#### Confirm every affected role's trust is back to known-good

Re-run Query 3. Every role that produced a `[!]` must now produce `[i] INTERNAL`,
`[i] SERVICE`, or `[i] CONFINED` against the reconciled partner list. A remaining `[!]` is
an unremediated backdoor, not a tuning issue.

#### Remove the federated half, if there is one

```bash
# A rogue provider is a credential source in its own right: removing one role's trust is
# not enough if another trusts it. List providers, reconcile against §1, then find every
# dependent role BEFORE deleting — the delete breaks them.
aws iam list-open-id-connect-providers --output json
aws iam list-saml-providers --output json
PROVIDER_ARN="<rogue-provider-arn>"
aws iam list-roles --output json | jq -r --arg p "$PROVIDER_ARN" \
  '.Roles[] | select((.AssumeRolePolicyDocument | tojson) | contains($p)) | .RoleName'
# aws iam delete-open-id-connect-provider --open-id-connect-provider-arn "$PROVIDER_ARN"
```

#### Remove other persistence by the same principal

From Query 4, remediate everything the principal established that outlives the trust
restore — access keys and login profiles, inline and managed policy grants, other roles it
created — with `../iam.privilege-escalation.inline-policy-grant/` and
`../_superseded/aws.privilege-escalation.iam-managed-policy-escalation/`.

#### Right-size the permission that made this possible

```bash
SUSPECT_ROLE="<role-name>"
# Both calls are needed: list-attached-* returns MANAGED policies only, so an inline grant
# is invisible to it. Remove iam:UpdateAssumeRolePolicy from every principal that is not an
# IAM administrator or the provisioning pipeline — it has no partial form, and a principal
# holding it on a role owns who may become that role.
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
```

#### Remove emergency policies once clean

```bash
EMERGENCY_ROLES="<space-separated-role-names-touched-in-Containment>"
for RN in $EMERGENCY_ROLES; do
  aws iam delete-role-policy --role-name "$RN" --policy-name "EmergencyRevokeSessions" 2>/dev/null
  aws iam delete-role-policy --role-name "$RN" --policy-name "EmergencyDenyTrustEdits" 2>/dev/null
done
# If the rewriting principal was an IAM USER, Step 3 used put-user-policy — delete-role-policy
# does not cover that path.
aws iam delete-user-policy --user-name "<suspect-user-name>" \
  --policy-name "EmergencyDenyTrustEdits" 2>/dev/null
# D-0: assert, do not announce. delete-*-policy exits 0 whether or not anything was
# there, so re-list and confirm absence; a listing failure is INCONCLUSIVE, never [OK].
LEFT=0; UNK=0
for RN in "<grantor-role-name>" "<grantee-role-name>"; do
  L=$(aws iam list-role-policies --role-name "$RN" --query 'PolicyNames[]' --output text 2>/dev/null)
  if [ -z "$L" ] && ! aws iam get-role --role-name "$RN" >/dev/null 2>&1; then UNK=$((UNK+1)); continue; fi
  printf '%s' "$L" | tr '\t' '\n' | grep -qE '^Emergency' && { echo "[FAIL] $RN still carries an Emergency* policy"; LEFT=$((LEFT+1)); }
done
U=$(aws iam list-user-policies --user-name "<grantor-user-name>" --query 'PolicyNames[]' --output text 2>/dev/null)
printf '%s' "$U" | tr '\t' '\n' | grep -qE '^Emergency' && { echo "[FAIL] grantor user still carries an Emergency* policy"; LEFT=$((LEFT+1)); }
[ "$UNK" -gt 0 ] && echo "[!] $UNK principal(s) could not be listed — INCONCLUSIVE, not clean"
{ [ "$LEFT" -eq 0 ] && [ "$UNK" -eq 0 ]; } && echo "[OK] No Emergency* policy remains on any contained principal"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the live trust policy matches the baseline

```bash
ROLE="<role-from-Query-1>"
BASELINE="<path-to-baseline>/${ROLE}.trust.json"
# get-role NESTS: Role.AssumeRolePolicyDocument.
#
# A STRING COMPARE HERE IS THE CHECK AWS TELLS YOU NOT TO WRITE. IAM transforms a policy on
# store: "insignificant white space can be removed, and elements within JSON maps can be
# reordered. In addition, AWS account IDs within the principal elements can be replaced by the
# Amazon Resource Name (ARN) of the AWS account root user. Because of these possible changes,
# you should not compare JSON policy documents as strings."
#
# `jq -S -c` alone covers two of those four. The account-ID rewrite is the one that bites: a
# trust authored as {"AWS":"111122223333"} — the most common way a cross-account trust is
# written — comes back as {"AWS":"arn:aws:iam::111122223333:root"}, so an UNCHANGED policy
# reports [FAIL]. CANON normalises Statement object-or-array and Principal
# bare-string-or-object, expands a bare 12-digit account to its :root ARN, and sorts. It does
# NOT canonicalise Condition values — read the diff by hand if it lands there.
CANON='
  def plist: if type=="array" then . else [.] end;
  def princ:
    if type=="string" then {AWS:[.]}
    else with_entries(.value |= (plist | map(
           if type=="string" and test("^[0-9]{12}$")
           then "arn:aws:iam::" + . + ":root" else . end) | sort))
    end;
  .Statement |= ((. // []) | if type=="object" then [.] else . end)
  | .Statement |= (map(
      (if has("Principal")    then .Principal    |= princ else . end)
    | (if has("NotPrincipal") then .NotPrincipal |= princ else . end)
    | (if has("Action")       then .Action       |= (plist | sort) else . end)) | sort)
'
LIVE=$(aws iam get-role --role-name "$ROLE" --query 'Role.AssumeRolePolicyDocument' \
        --output json 2>/dev/null | jq -S -c "$CANON" 2>/dev/null)
WANT=$(jq -S -c "$CANON" "$BASELINE" 2>/dev/null)
if [ -z "$LIVE" ] || [ -z "$WANT" ]; then
  echo "[!] INCONCLUSIVE — get-role returned nothing, or the baseline file is missing/unparsable"
elif [ "$LIVE" = "$WANT" ]; then
  echo "[OK] $ROLE trust policy is semantically identical to the baseline"
else
  echo "[FAIL] $ROLE trust differs from baseline"
  diff <(printf '%s\n' "$WANT") <(printf '%s\n' "$LIVE")
fi
```

#### Verify no role in the account still trusts outside the organisation

```bash
KIT="<path-to-playbook-authoring-kit>"
export ORG_ACCOUNTS="<comma-separated-org-account-ids>"
# KNOWN_IDPS is NOT optional here. Unset, every legitimate federated trust in the account
# decodes as [!] UNKNOWN IDP and this assertion prints [FAIL] on a clean estate.
export KNOWN_IDPS="<oidc-provider/your-idp-host>,<saml-provider/YourIdPName>"
ROLES=$(aws iam list-roles --output json 2>/dev/null)
# COUNT is the anti-false-[OK] guard. A failed call, a wrong Region or a credential without
# iam:ListRoles yields an empty page, the decoder is handed nothing, and it still reports
# "0 escalating grant(s)" — a clean bill of health for a sweep that never ran. Every account
# has roles, so a non-positive COUNT means the CHECK failed, not that the estate is clean.
COUNT=$(printf '%s' "$ROLES" | jq -r '.Roles | length' 2>/dev/null)
RAW=$(printf '%s' "$ROLES" | jq -c '.Roles[] | {time: .CreateDate,
    caller: "-", grantee: .RoleName, policy_name: "live-trust-policy",
    doc: (.AssumeRolePolicyDocument | tojson)}' 2>/dev/null | \
  python3 "$KIT/tools/decode_policy_documents.py" 2>&1)
BANGS=$(printf '%s\n' "$RAW" | grep -c '^\[!\]')
if [ -z "$ORG_ACCOUNTS" ] || [ -z "$KNOWN_IDPS" ]; then
  echo "[!] INCONCLUSIVE — ORG_ACCOUNTS or KNOWN_IDPS is empty; this check cannot run"
elif ! printf '%s' "$COUNT" | grep -qE '^[1-9][0-9]*$'; then
  echo "[!] INCONCLUSIVE — list-roles returned no roles; the sweep did not run. Do NOT read as clean"
elif ! printf '%s\n' "$RAW" | grep -q '^\[OK\] Decode-and-parse pass complete'; then
  echo "[!] INCONCLUSIVE — the decoder did not complete; do NOT read this as clean"
  printf '%s\n' "$RAW" | tail -3
elif [ "$BANGS" -eq 0 ]; then
  echo "[OK] No role trusts a principal outside the organisation ($COUNT roles decoded)"
else
  echo "[FAIL] $BANGS role trust(s) still reach outside — re-run Query 3"
fi
```

#### Verify no external assumption of the role since containment

```bash
ROLE_ARN="<role-arn-from-Query-5>"
CONTAINED_AT="<iso8601-containment-timestamp>"
STS_REGIONS="us-east-1 <your-other-active-regions>"

# Capture the raw pages FIRST. If every lookup failed — wrong Region, expired break-glass,
# missing cloudtrail:LookupEvents — the count collapses to zero and reads as clean.
RAW=$(for R in $STS_REGIONS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --start-time "$CONTAINED_AT" --region "$R" --output json 2>/dev/null
done)
EXTERNAL=$(printf '%s\n' "$RAW" | jq -s --arg role "$ROLE_ARN" '[.[].Events[].CloudTrailEvent | fromjson |
  select((.requestParameters.roleArn // "") == $role) |
  select(.userIdentity.type | IN("AWSAccount","WebIdentityUser","SAMLUser"))] | length' 2>/dev/null)
if [ -z "$RAW" ] || ! printf '%s' "$EXTERNAL" | grep -qE '^[0-9]+$'; then
  echo "[!] INCONCLUSIVE — no lookup-events pages came back; this is not evidence of no use"
elif [ "$EXTERNAL" -eq 0 ]; then
  echo "[OK] No external assumption of $ROLE_ARN since $CONTAINED_AT"
else
  echo "[FAIL] $EXTERNAL external assumption(s) since containment — the trust is not restored"
fi
```

> A `[OK]` here means no **successful** external assumption was logged. Denied cross-account
> requests are not recorded in this account, so it is not evidence nobody tried, and it says
> nothing about a session issued *before* containment still inside its `MaxSessionDuration`.
> Step 2's `TokenIssueTime` deny closes that; this check does not verify it.

#### Confirm the corrected detection fires

The test is split **by artifact**, because the Sigma rules and the decoder are not supposed
to agree on every case. Two of the four shapes a first draft lists as "must not fire" *do*
fire, by design, and retuning the rules to silence them is the wrong fix.

```bash
KIT="<path-to-playbook-authoring-kit>"
export ORG_ACCOUNTS="<comma-separated-org-account-ids>"   # must NOT list 999988887777
export KNOWN_IDPS="<oidc-provider/your-idp-host>,<saml-provider/YourIdPName>"

cat <<'SPEC'
SIGMA — MUST FIRE   (iam.amazonaws.com, errorCode absent)
  1. UpdateAssumeRolePolicy, requestParameters.policyDocument =
     {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
      "Principal":{"AWS":"999988887777"},"Action":"sts:AssumeRole"}]}
  2. case 1 PRETTY-PRINTED — what --policy-document file://trust.json submits
  3. case 1 on CreateRole, under requestParameters.assumeRolePolicyDocument
  4. "Principal":{"AWS":"*"}                 -> iam_role_trust_wildcard_principal
  5. "Principal":{"Federated":"arn:aws:iam::<acct>:oidc-provider/evil.example"}
                                             -> iam_role_trust_unknown_federated_provider

SIGMA — MUST NOT FIRE
  6. "Principal":{"Service":"ec2.amazonaws.com"}
  7. a trust naming only organisation account IDs
  8. any of cases 1-5 on an event that carries an errorCode

SIGMA — EXPECTED FALSE POSITIVES, BY DESIGN.  These FIRE and are NOT findings.
  9.  case 1 plus "Condition":{"StringEquals":{"sts:ExternalId":"<id>"}}
      -> fires iam_role_trust_external_principal
  10. "Effect":"Deny" on "Principal":{"AWS":"*"} with
      "Condition":{"StringNotEquals":{"aws:PrincipalOrgID":"<o-your-org-id>"}}
      -> fires iam_role_trust_wildcard_principal
  Neither rule reads Condition, and neither reads Effect. That is deliberate — both are
  a parse, not a substring match — and each rule states it as the FIRST entry of its own
  falsepositives:. DECODE TO DISPOSITION; DO NOT RETUNE THE RULE.
SPEC

# DECODER — MUST NOT FLAG EITHER OF THE TWO. This half is executable, and it is the half
# the disposition is actually made on.
OUT=$(printf '%s\n' \
 '{"time":"FP-9","caller":"-","grantee":"r","policy_name":"trust","doc":"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"999988887777\"},\"Action\":\"sts:AssumeRole\",\"Condition\":{\"StringEquals\":{\"sts:ExternalId\":\"x\"}}}]}"}' \
 '{"time":"FP-10","caller":"-","grantee":"r","policy_name":"trust","doc":"{\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"sts:AssumeRole\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalOrgID\":\"o-x\"}}}]}"}' \
 | python3 "$KIT/tools/decode_policy_documents.py" 2>&1)
if ! printf '%s\n' "$OUT" | grep -q '^\[OK\] Decode-and-parse pass complete'; then
  echo "[!] INCONCLUSIVE — decoder did not run; check \$KIT"; printf '%s\n' "$OUT"
elif [ "$(printf '%s\n' "$OUT" | grep -c '^\[!\]')" -eq 0 ] \
     && printf '%s\n' "$OUT" | grep -q '^\[i\] CONFINED .*FP-9' \
     && ! printf '%s\n' "$OUT" | grep -q 'FP-10'; then
  echo "[OK] Case 9 decodes [i] CONFINED, case 10 yields no verdict — both correctly non-findings"
else
  echo "[FAIL] the decoder flagged a by-design Sigma false positive:"; printf '%s\n' "$OUT"
fi
```

Case 10 is asserted as *absent* rather than as `[i]` because a `Deny` cannot create trust, so
the decoder emits nothing for it. Where the rules and the decoder disagree on these two, the
decoder is right: the rules are the trigger, the decoder is the disposition.

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could rewrite a role's trust policy | `iam:UpdateAssumeRolePolicy` held outside the IAM-administration set; no SCP restricting who may change who may become a role |
| The rewrite went undetected | The shipped rules matched the event name with no content inspection, and the literal wildcard with no `Condition` test — so the ordinary foreign-account case matched nothing |
| The previous trust policy could not be produced | No trust-policy baseline in version control, and the API keeps no prior version — `UpdateAssumeRolePolicy` overwrites |
| Persistence survived credential rotation | The incident response reflex is to rotate; nothing in this technique depends on a credential of ours, so rotation was work that changed nothing |
| Outside trust was never reviewed, and the finding routed to the wrong queue | IAM Access Analyzer not enabled with the organization as its zone of trust, so a role reachable from outside raised nothing until a human read the document — and the unconfined-wildcard case was rated P3, below the bare event-name rule at P2 that fires on every legitimate trust edit |

### Recommended Guardrails

**Restrict who may change a role's trust policy**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["iam:UpdateAssumeRolePolicy", "iam:CreateOpenIDConnectProvider", "iam:CreateSAMLProvider"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/IAMAdministrator", "arn:aws:iam::*:role/BreakGlassAdmin"] } }
}
```

**Require every role trust to stay inside the organisation**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// RCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// A Resource control policy, NOT an SCP. AWS: "SCPs affect only IAM users and roles that
// are managed by accounts that are part of the organization... They also don't affect
// users or roles from accounts outside the organization" — which is precisely the
// principal this technique creates. SCPs also do not affect resource-based policies
// directly, and a role trust policy is one. Written as an SCP this statement is
// unreachable in both directions: the foreign principal is out of scope, and your own
// principals always match your org ID so StringNotEquals is never true.
// The Bool guard is load-bearing: without it this denies service-initiated role
// assumption and is an outage. RCPs do not apply to service-linked roles or to
// management-account resources.
{
  "Sid": "RCPEnforceIdentityPerimeterSts",
  "Effect": "Deny",
  "Principal": "*",
  "Action": ["sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"],
  "Resource": "*",
  "Condition": {
    "StringNotEqualsIfExists": { "aws:PrincipalOrgID": "<o-your-org-id>" },
    "Bool": { "aws:PrincipalIsAWSService": "false" }
  }
}
```

> **Every wildcarded condition value needs a `*Like` operator.** `aws:PrincipalArn` above
> carries `*`, so it uses `StringNotLike`; `StringNotEquals` there would match nothing it was
> meant to exempt and the `Deny` would fail **closed** — an outage, not a bypass.
> `<o-your-org-id>` has no wildcard, so `StringNotEquals` is correct for it.

**Structural controls**
- **Baseline every trust policy in version control** and reconcile on a schedule — the one control that makes both restoration and drift detection possible
- **Enable IAM Access Analyzer with the organization as the zone of trust.** For external access it analyses the resources in the Region where it is enabled — but an IAM role is **global**, so AWS generates a role-trust finding *"in each enabled Region"*: one backdoor, N duplicate findings to archive, and a single-Region analyzer is **not** blind to roles used elsewhere. Enable it in every Region you use for the other resource types. AWS documents up to 30 minutes between a policy change and the finding update. It is the only control here that finds backdoors predating your detections
- **Require `sts:ExternalId` on every third-party trust** and **pin every federated trust to a token claim** (`:sub`, `:aud`). Without these, a partner trust is indistinguishable from a backdoor at review time and an OIDC trust covers every workload at that provider, not just yours
- **Set `MaxSessionDuration` to the minimum each role needs** — the ceiling on how long a session minted through a backdoor outlives its restoration
- Manage trust policies through reviewed IaC only; treat any out-of-band `UpdateAssumeRolePolicy` as an incident

**Detection improvements**
- Deploy the seven documents in `detections/sigma_t1098_001.yml`; never the bare event-name match
- Run the decoded sweep (Query 3) on a schedule — the drift detector here, and the only rule-independent way to catch a backdoor written by a principal your allowlist exempts
- Alert on Access Analyzer external-access findings for `AWS::IAM::Role` at P2, reconciled against the partner list rather than suppressed
- Alert on `CreateOpenIDConnectProvider` / `CreateSAMLProvider` — the federated half of this technique, and rarer than the trust edit

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098.003 — Account Manipulation: Additional Cloud Roles (primary); T1098.001 — Additional Cloud Credentials (retained); T1484.002 — Trust Modification (federated variant) |
| MITRE tactic | Persistence (TA0003), Privilege Escalation (TA0004); T1484.002 adds Defense Impairment (TA0112) and does **not** carry Persistence |
| Primary API | `iam:UpdateAssumeRolePolicy` (rewrite an existing role's trust) or `iam:CreateRole` (plant it at birth) → `sts:AssumeRole` from outside |
| Event source | `iam.amazonaws.com` for the write (**global — logged in `us-east-1` only**); `sts.amazonaws.com` for the use (global endpoint → `us-east-1`, regional endpoints → their own Region) |
| Management or data | **Both management.** `lookup-events` sees the write and the use; there is no data-plane blind spot in this technique |
| Field split and nesting | `UpdateAssumeRolePolicy` → `requestParameters.policyDocument` and **no** `responseElements`; `CreateRole` → `requestParameters.assumeRolePolicyDocument` and a **nested** `responseElements.role.arn` / `.roleName` / `.roleId` / `.assumeRolePolicyDocument`. The two document fields never co-occur — sibling blocks ORed, never ANDed |
| Encoding | `requestParameters` is **raw JSON** — the hazard is pretty-printed whitespace. RFC 3986 encoding applies to what IAM **returns** (`GetRole` states it); the CLI and boto3 decode responses via a handler on `after-call.iam` with no request-side counterpart |
| Key discriminator | The decoded trust `Allow` names a principal outside the organisation — a foreign 12-digit account, `"AWS":"*"`, or an unrecognised federated provider — **with no confining `Condition`** (`sts:ExternalId`, `aws:PrincipalOrgID`, or a pinned OIDC `:sub`/`:aud`) |
| Shape hazards | `Statement` object-or-array; `Principal` object **or the bare string `"*"`**; `Principal.AWS`/`.Federated`/`.Service` string-or-array. **`NotPrincipal` is not one of them:** a role trust policy cannot carry it under either `Effect` (AWS: *"must be used with `"Effect":"Deny"`"* and *"You cannot use the `NotPrincipal` element in an IAM identity-based policy nor in an IAM role trust policy"*; Access Analyzer `ROLE_TRUST_POLICY_SYNTAX_ERROR_NOTPRINCIPAL`). It is an error-path artefact, never a stored shape |
| "Was it used" pivot | `sts:AssumeRole` in the **role owner's** trail with `userIdentity.type: "AWSAccount"`, `userIdentity.accountId` = the calling account, and **no** `userIdentity.arn`; `sharedEventID` links to the caller's copy. Federated use: type `WebIdentityUser` / `SAMLUser` with `userIdentity.identityProvider` |
| Evidence limits | CloudTrail does **not** log denied cross-account assume-role requests in the target account, so an empty pivot proves nothing about attempts. And there is no rollback: `UpdateAssumeRolePolicy` overwrites with no version history, so the prior document survives only in the earlier CloudTrail event |
| Ground truth / blast radius | The live `Role.AssumeRolePolicyDocument` differs from the baseline and names an outside principal. What that costs: every permission attached to the role, on demand, for whoever holds the trusted identity — unaffected by rotating any credential in this account |
| Error strings | `LimitExceeded` when the trust document exceeds quota — 2,048 characters by default, 8,192 at the adjustable maximum. **There is no size-based evasion path here:** that ceiling sits ~12x below CloudTrail's 100 KB `requestParameters` omission threshold, so an oversized trust policy is rejected outright rather than applied with its body missing from the log. `AccessDenied` / `AccessDeniedException`. Non-denials that must not be counted as probing: `MalformedPolicyDocument`, `NoSuchEntity`, `LimitExceeded`, `ServiceFailure`, `UnmodifiableEntity` (service-linked role — also what `put-role-policy` throws in Containment Step 2), plus `EntityAlreadyExists`, `InvalidInput` and `ConcurrentModification` on `CreateRole`. One of them is evidence: a `MalformedPolicyDocument` naming `NotPrincipal`, `"Federated":"*"`, `"Service":"*"` or a bare `"Principal":"*"` is an actor trying a shape a role trust policy rejects |

**MITRE mapping note:** the account-principal rules carry **T1098.003** (*Additional Cloud
Roles*) alongside `T1098.001`, and T1098.003 is the closer of the two. Its published text is
this technique stated exactly: *"adversaries may add roles to adversary-controlled accounts
outside the victim cloud tenant. This allows these external accounts to perform actions
inside the victim tenant without requiring the adversary to Create Account or modify a
victim-owned account."* `T1098.001` (*Additional Cloud Credentials*) is retained rather than
replaced — the rewritten trust is a credential source the adversary controls, added alongside
the legitimate ones — but its own description does not mention trust policies. Both sit under
Persistence (TA0003) and Privilege Escalation (TA0004), so carrying both changes no
disposition. For the **federated** variant `T1484.002` (*Trust Modification*) is the closer
fit and is explicit that adding an identity provider in AWS lets an adversary federate in;
its tactics are **Defense Impairment (TA0112)** and Privilege Escalation, *not* Persistence,
so `iam_role_trust_unknown_federated_provider` carries `attack.defense-impairment` beside its
persistence tag. `attack.defense-evasion` is retired — TA0005 is now **Stealth** — and it is
not a tactic of anything cited here. Every ID above was verified live with
`tools/attack_currency_check.py`. A mapping-precision note, not an operational defect.

### Residual Risk

**Sessions already issued outlive the restoration.** Restoring the trust stops new
assumptions; a session minted before it runs to its expiry, up to the role's
`MaxSessionDuration` — settable to 12 hours. Step 2's `TokenIssueTime` deny closes that, and
only for tokens issued before its cutoff.

**Everything the attacker did while the backdoor stood stays done** — credentials read from
Secrets Manager or SSM, data copied out of S3, resources created elsewhere, further
persistence planted through the role. Query 4 and the sibling playbooks enumerate that set;
assume it is incomplete until each has been worked.

**You cannot prove the backdoor went unused.** Successful external assumptions are logged;
denied ones are not, in this account. If the trust stood longer than your CloudTrail
retention there is no window to look in at all, and Query 3 tells you what is true now, not
what was true then.

**A federated provider outlives the trust that named it, and so does the permission.**
Deleting one role's trust removes neither a rogue OIDC/SAML provider — any other role
trusting it is still reachable — nor `iam:UpdateAssumeRolePolicy` from the principal, which
leaves the technique repeatable with one call. Both are §4 work; until then this incident
is not closed.
