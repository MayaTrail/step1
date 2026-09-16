# IR Playbook: Identity Pool Configured to Allow Unauthenticated Access — Anonymous AWS Credential Vending via `cognito-identity:SetIdentityPoolRoles` + `GetCredentialsForIdentity`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / Initial access (an identity pool is set to accept anonymous identities and given a role for them to assume, so any caller on the internet who knows the pool ID receives temporary AWS credentials) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **Critical** where a role is attached; **High** for the flag alone. The source rates it **P2**, and the gap is not a matter of degree. There is no intermediate step, no credential to steal and no privilege to escalate: a guest-enabled pool hands an unauthenticated internet caller a live AWS session *by design*, and the only thing between that and account impact is the unauthenticated role's policy — which is not in the event, not in any Cognito API, and unknown to the person triaging the alert until they go and get it |
| MITRE Tactics | Persistence (TA0003), Initial Access (TA0001) |
| MITRE Techniques | T1098 (primary), T1078.004 (secondary) — both verified live 2026-08-29 |
| Services in Scope | Cognito identity pools, IAM (the unauthenticated **and** authenticated roles and every policy on them), STS, CloudTrail (management **and** `AWS::Cognito::IdentityPool` data events), Organizations (RCP — **not** SCP), and every service the unauthenticated role can reach |

**Tier 1, and which tests.** Three of `07-TIERS.md`'s five. **Test 1 — account access reachable in
one further hop:** it is reachable in *zero* — `GetId` then `GetCredentialsForIdentity`, neither
requiring any credential, returns a real `ASIA…` key, secret and session token. **Test 3 — the blast
radius is not in the event:** `SetIdentityPoolRoles` records role ARNs and nothing else, no Cognito
API returns a policy document, and because that call is a full replacement, clearing the mapping
during containment erases the only pointer from the pool to the role — so it must be captured first.
**Test 5 — a structural blind spot:** issuance is a CloudTrail *data* event, off by default, and in
the default enhanced flow Cognito calls STS on your behalf, so in a default-configured account
exploitation leaves **no CloudTrail record at all**. **Test 2** applies too: the revocation in §3
Step 3 is ineffective unless the issuance cut in Step 2 lands first.

**What the technique does:** the actor calls `UpdateIdentityPool` (or `CreateIdentityPool`) with
`AllowUnauthenticatedIdentities: true`, then `SetIdentityPoolRoles` with a role under the literal
`unauthenticated` key. Nothing else is required. Any client that knows the pool ID — a `REGION:GUID`
string AWS documents as *"not confidential information"*, shipped inside mobile binaries and
JavaScript bundles — calls `GetId` then `GetCredentialsForIdentity` and receives temporary AWS
credentials valid for one hour. Both APIs carry AWS's *"This is a public API. You do not need any
credentials to call this API"*, and the second adds *"Amazon Cognito doesn't evaluate AWS Identity
and Access Management (IAM) policies in requests for this API operation."* Downstream, the session
is indistinguishable from any other assumed-role session.

**Why the usual reflexes miss it.** A responder checks who has permissions and finds nothing wrong —
the attacker holds no IAM principal, no access key and no role of their own. They check for a public
resource policy and find none, because the exposure is not on a resource. They check CloudTrail for
the abuse and find nothing, because `GetId` and `GetCredentialsForIdentity` are **data events, off
by default**, and in the enhanced flow the `AssumeRoleWithWebIdentity` is made by Cognito, not by
the caller. Every instinct returns clean while an anonymous client holds a live session — and the
configuration event looks unremarkable, a boolean set to true on a service most reviewers read as an
authentication product rather than as a credential broker.

**Detection thesis.** The discriminator is **the pairing** — the guest flag and an attached
unauthenticated role — because either alone vends nothing and the two arrive on different API calls
with different field shapes. The source rule matches only the flag, on only `Create`/`Update`, so
the most dangerous single change in the technique — `SetIdentityPoolRoles` attaching an
unauthenticated role to a pool that was *already* guest-enabled — produces no event it matches at
all.

> `../cognito.impact.identity-pool-deletion-detected/` covers the same resource being destroyed and
> carries the orphaned-role analysis. A guest-enabled pool that is then **deleted** is that
> playbook's reconfigure-then-destroy correlation, and these roles survive the deletion.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail capturing Cognito Identity **management** events. AWS: *"Amazon Cognito logs the remainder of Amazon Cognito identity pools API operations as management events"* — `CreateIdentityPool`, `UpdateIdentityPool`, `SetIdentityPoolRoles`, `GetIdentityPoolRoles`, `DescribeIdentityPool`, `DeleteIdentityPool`, on by default. `eventSource` is `cognito-identity.amazonaws.com`, **not** `cognito-idp.amazonaws.com`; a rule pointed at the wrong one returns zero forever
- **Field casing is verified for this service.** AWS publishes a real `CreateIdentityPool` CloudTrail event: `requestParameters.identityPoolName`, `requestParameters.allowUnauthenticatedIdentities` (unquoted boolean), `requestParameters.supportedLoginProviders`, `responseElements.identityPoolId`. `allowClassicFlow` and `roles.unauthenticated` follow the same convention but appear in no published example — confirm them in your own trail
- **CloudTrail data events on `AWS::Cognito::IdentityPool` — the single most valuable thing on this list.** `GetId`, `GetCredentialsForIdentity`, `GetOpenIdToken`, `GetOpenIdTokenForDeveloperIdentity` and `UnlinkIdentity` are **data events, off by default and billable**. Without the selector there is **no record of credential issuance at all**, and none can be created retroactively. With it, an anonymous call is unmistakable: AWS's own published examples show `userIdentity` as `{"type": "Unknown"}`
- **STS management events**, which are on by default and are the *other* evidence path. IAM documents that CloudTrail *"also logs non-authenticated requests to the AWS STS actions, `AssumeRoleWithSAML` and `AssumeRoleWithWebIdentity`"* — so in the **basic (classic)** flow the guest exchange is captured, with `userIdentity.type: WebIdentityUser`. In the **enhanced** flow Cognito makes that call on your behalf and nothing equivalent lands in your trail. The less secure flow is the more observable one
- **An inventory of every IAM role trusting `cognito-identity.amazonaws.com`**, recording for each: the pool its `aud` condition is pinned to, whether it carries a `ForAnyValue:StringLike` condition on `...:amr`, and its attached **and inline** policies. This is the blast radius, it is in no Cognito event, and it must exist before the incident because containment destroys the pointer to it
- A record of which pools are **deliberately** guest-enabled and what each guest role is approved to do — without it every alert is a research project — and the `AllowClassicFlow` state of each. In the enhanced flow AWS applies an inline session policy plus the managed `AmazonCognitoUnAuthedIdentitiesSessionPolicy`, so effective permissions are the **intersection** with that ceiling; in the classic flow the client composes its own STS call and the ceiling does not apply

**Alerting (must be pre-configured)**
- **An identity pool set to allow unauthenticated identities and given an `unauthenticated` role within 24 hours → P0**
- **`SetIdentityPoolRoles` attaching a role under the `unauthenticated` key to a pool that was already guest-enabled → P0**
- **`GetId` or `GetCredentialsForIdentity` with `userIdentity.type: Unknown` against a pool not on the approved guest-access list → P0**
- **`CreateIdentityPool` or `UpdateIdentityPool` with `allowUnauthenticatedIdentities: true` by a principal outside the identity-pool pipeline → P1**
- **`sts:AssumeRoleWithWebIdentity` succeeding against a Cognito unauthenticated role → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
  and — specifically — not a session of any role the identity pool can vend.
- `jq`; `tools/decode_policy_documents.py` for any policy document read from raw CloudTrail rather
  than from the API. Note the split (A4): the CLI and boto3 decode IAM **responses** via botocore's
  `after-call.iam` handler, so `get-role` and `get-policy-version` hand back parsed objects and must
  **not** be decoded again. Keep the role inventory and guest-access list in files, not in memory —
  containment Step 1 compares against them before anything changes.

**Known IOC Baselines**
- Which principals legitimately call `cognito-identity:CreateIdentityPool`, `UpdateIdentityPool` and
  `SetIdentityPoolRoles` — normally one deployment role and one break-glass role.
- The ARN of every approved unauthenticated role and the permission set each is signed off for: a
  guest role gaining a policy is a change to the internet's permissions. And every identity pool ID
  with whether guest access is intended — the ID is not a secret and is public in every risk
  conversation.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | An identity pool set to allow unauthenticated identities and given an `unauthenticated` role within 24 hours, in either order | CloudTrail (management) | T1098 |
| P0 | `SetIdentityPoolRoles` attaching a role under the `unauthenticated` key to a pool that was already guest-enabled — the change the source rule cannot see | CloudTrail (management) | T1098 |
| P0 | `GetId` or `GetCredentialsForIdentity` with `userIdentity.type: Unknown` against a pool not on the approved guest-access list | CloudTrail (**data**) | T1078.004 |
| P1 | `CreateIdentityPool` or `UpdateIdentityPool` with `allowUnauthenticatedIdentities: true` by a principal outside the identity-pool pipeline | CloudTrail (management) | T1098 |
| P1 | `sts:AssumeRoleWithWebIdentity` succeeding against a Cognito unauthenticated role | CloudTrail (management) | T1078.004 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `allowClassicFlow: true` on a pool that also allows unauthenticated identities — removes AWS's automatic scope-down session policy | CloudTrail (management) | T1098 |
| P2 | An IAM role trusting `cognito-identity.amazonaws.com` with **no `aud` condition** — assumable through any identity pool, including one in an attacker's account | IAM (`list-roles` sweep) | T1078.004 |
| P2 | An **authenticated** role with an `aud` condition but **no `amr` condition** — a guest token satisfies it, which is anonymous-to-authenticated escalation | IAM (`list-roles` sweep) | T1078.004 |
| P3 | `InvalidIdentityPoolConfigurationException` on `GetCredentialsForIdentity` — a guest-enabled pool with no role attached, one call from live; or `NotAuthorizedException` on `SetIdentityPoolRoles` across several pools, which is boundary mapping | CloudTrail (**data** / management) | T1098 |

### Detection Rule Quality Notes

The source rule's observable is correct as far as it goes, and it stops one API call short of the
thing that actually vends credentials.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Watches only `CreateIdentityPool` / `UpdateIdentityPool` | **The flag alone vends nothing.** `CreateIdentityPool` has no `Roles` parameter at all, and until a `SetIdentityPoolRoles` call attaches one a guest request fails with `InvalidIdentityPoolConfigurationException`. So the rule alerts on the announcement and is silent on the weaponisation — and a `SetIdentityPoolRoles` attaching an unauthenticated role to an **already** guest-enabled pool produces no matching event whatsoever | Ship the `SetIdentityPoolRoles` rule, and a `temporal` (unordered) correlation over both — either call can legitimately come first |
| No principal check, and nothing looks at `allowClassicFlow` | The flag rule fires on every provisioning run for every deliberately guest-enabled application, where the caller is what separates provisioning from an unreviewed change. And `allowClassicFlow` rides on the **same event**: in the enhanced flow AWS caps guest sessions with an inline session policy plus `AmazonCognitoUnAuthedIdentitiesSessionPolicy` and in the classic flow it does not, so the severity of an identical-looking alert differs by one adjacent boolean | Allowlist the lifecycle roles on the flag rule and keep the role-attachment rule unfiltered; ship the classic-flow rule and project the flag beside every finding |
| No coverage of issuance | The rule reports a configuration and never asks whether anyone used it. The answer exists on two paths — data events on `AWS::Cognito::IdentityPool`, and classic-flow `sts:AssumeRoleWithWebIdentity` — and neither is watched | Ship both issuance rules, and report the **absence** of the data-event path as an absence of visibility rather than as an absence of abuse |
| P2 priority | A configuration that hands live AWS credentials to anonymous internet callers is triaged alongside routine changes | P1 for the flag, P0 for the flag plus a role, P0 for observed anonymous issuance |
| Severity cannot be derived from the alert at all | `SetIdentityPoolRoles` records role ARNs only — its `Roles` map is documented as a string-to-string map with values 20–2048 characters, an ARN and not a policy — and **no** Cognito API returns a policy document. The alert cannot say whether guests got `s3:GetObject` on one prefix or `iam:*` | Make the IAM pivot a mandatory, scripted triage step (Query 2), not an analyst's discretion |

**Recommended detection — an identity pool set to accept anonymous identities.**

```yaml
# Identity Pool Configured to Allow Unauthenticated Access (T1098 / T1078.004)
#
# WHAT THIS ACTUALLY IS. `AllowUnauthenticatedIdentities: true` plus an unauthenticated role means
# any caller on the internet who knows the identity pool ID calls `GetId` and then
# `GetCredentialsForIdentity` and receives real, signable AWS credentials. AWS states both halves
# without hedging: "Anyone who knows your identity pool ID can request unauthenticated
# credentials. Your identity pool ID isn't confidential information", and "Activate guest access
# only when you are confident that you would grant the permissions in your IAM role to anyone on
# the internet." Neither call needs AWS credentials - both API references carry "This is a public
# API. You do not need any credentials to call this API" - and the response contains an ASIA
# access key, a secret, a session token and an expiry, valid for one hour.
#
# WHAT THE ORIGINAL RULE GOT RIGHT, AND THE ONE THING IT MISSES. It matches
# `CreateIdentityPool` OR `UpdateIdentityPool` with `allowUnauthenticatedIdentities: true` and a
# success filter, which is correct, and its field casing is right: AWS publishes a real
# CreateIdentityPool CloudTrail example carrying `requestParameters.allowUnauthenticatedIdentities`
# in lower camel. What it misses is that THE FLAG ALONE VENDS NOTHING. `CreateIdentityPool` has no
# Roles parameter at all - roles are attached by a separate `SetIdentityPoolRoles` call, and until
# one lands a guest request fails with InvalidIdentityPoolConfigurationException ("the identity
# pool has no unauthenticated role configured"). So the flag is the announcement and
# `SetIdentityPoolRoles` is the weaponisation, the source rule watches only the announcement, and
# the far more dangerous case - `SetIdentityPoolRoles` attaching an unauthenticated role to a pool
# that was ALREADY guest-enabled - produces no event the rule matches at all.
#
# THE BLAST RADIUS IS NOT IN ANY OF THESE EVENTS. `SetIdentityPoolRoles` records role ARNs and
# nothing else: its Roles map is documented as "String to string map", value length 20 to 2048 -
# an ARN, not a policy document. No policy document appears anywhere in CreateIdentityPool,
# UpdateIdentityPool, DescribeIdentityPool, SetIdentityPoolRoles or GetIdentityPoolRoles. What the
# event says is "guests now get role X". What role X permits is a separate trip to IAM, and it is
# the only thing that determines severity.
#
# BOTH WRITES ARE FULL REPLACEMENTS. `UpdateIdentityPool` requires IdentityPoolId,
# IdentityPoolName AND AllowUnauthenticatedIdentities, and carries AWS's "If you don't provide a
# value for a parameter, Amazon Cognito sets it to its default value". `SetIdentityPoolRoles`
# requires its whole Roles map, capped at two entries, so a call sending only `authenticated`
# removes the `unauthenticated` mapping and vice versa. Every event here is a whole-configuration
# write, never a field edit - which matters for the response as much as for the detection.
#
# CLASSIC FLOW IS A SEVERITY MULTIPLIER. In the default enhanced flow AWS applies an inline
# session policy plus the managed `AmazonCognitoUnAuthedIdentitiesSessionPolicy` to guest
# sessions, so effective permissions are the INTERSECTION of the role's policies and that ceiling.
# In the basic (classic) flow the client composes its own AssumeRoleWithWebIdentity and the
# scope-down does not apply. `AllowClassicFlow: true` on a guest-enabled pool therefore removes
# the safety net, and it is a separate field on the same UpdateIdentityPool event.
#
# ISSUANCE IS A DATA EVENT AND IS OFF BY DEFAULT. `GetId`, `GetCredentialsForIdentity`,
# `GetOpenIdToken`, `GetOpenIdTokenForDeveloperIdentity` and `UnlinkIdentity` are logged by AWS as
# DATA events, requiring an advanced event selector on resources.type =
# AWS::Cognito::IdentityPool. And in the enhanced flow Cognito calls STS on your behalf, so there
# is no `sts:AssumeRoleWithWebIdentity` event attributable to your caller either. In a
# default-configured account, exploitation of this misconfiguration produces NO CloudTrail
# evidence at all. Rules 5 and 6 below cover the two paths that DO leave evidence, and each says
# what it depends on.
title: Cognito identity pool configured to allow unauthenticated access
id: ea8e0bf3-1e06-4023-9eb4-a63264fd59b6
name: cognito_identitypool_guest_enabled
status: experimental
description: >-
  An identity pool was created or updated with AllowUnauthenticatedIdentities set to true. Any
  caller on the internet who knows the pool ID - which AWS documents as not confidential - can
  then request AWS credentials for the pool's unauthenticated role. The flag alone vends nothing
  until a role is attached; pair this with the SetIdentityPoolRoles rule below.
references:
  - https://attack.mitre.org/techniques/T1098/  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1078/004/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_CreateIdentityPool.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools-security-best-practices.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
  - attack.initial-access
  - attack.t1078.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-identity.amazonaws.com'
    eventName:
      - 'CreateIdentityPool'
      - 'UpdateIdentityPool'
  # Documented Type: Boolean, and AWS's published CloudTrail example shows it unquoted in
  # requestParameters. A quoted 'true' matches nothing on a JSON-typed backend.
  guest_enabled:
    requestParameters.allowUnauthenticatedIdentities: true
  success:
    errorCode: null
  condition: selection and guest_enabled and success
falsepositives:
  - >-
    A deliberate guest-access application - anonymous analytics, an unauthenticated media player,
    a pre-sign-in catalogue browse. These exist and are legitimate; what makes them safe is the
    unauthenticated role's policy, which this event does not contain. Triage by fetching the role,
    not by recognising the pool name.
level: high
---
# The weaponisation, and the case the source rule cannot see. A guest-enabled pool with no
# unauthenticated role issues nothing - AWS returns InvalidIdentityPoolConfigurationException:
# "If you provided no authentication information in the request, the identity pool has no
# unauthenticated role configured". Attaching one is what turns the flag into credentials, and it
# is a DIFFERENT API on a DIFFERENT event that the source rule does not match.
#
# The match is on the Roles map key documented as literally "authenticated" or "unauthenticated"
# (Key Pattern: (un)?authenticated). `|contains: ':role/'` is used rather than an existence test
# because every value is a role ARN and the substring is portable across backends; it also fails
# closed, matching nothing rather than everything, if the field is absent.
title: Cognito unauthenticated role attached to an identity pool
id: 5cda3f39-b5b0-4dc5-b94d-c001b87fe11c
name: cognito_identitypool_unauth_role_set
status: experimental
description: >-
  SetIdentityPoolRoles attached a role under the "unauthenticated" key. From this moment any
  anonymous caller who knows the pool ID can obtain temporary AWS credentials for that role. The
  event names the role ARN and nothing about what the role permits - that has to be fetched from
  IAM, and it is the only thing that determines severity.
references:
  - https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_SetIdentityPoolRoles.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetCredentialsForIdentity.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
  - attack.initial-access
  - attack.t1078.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-identity.amazonaws.com'
    eventName: 'SetIdentityPoolRoles'
  unauth_role_present:
    requestParameters.roles.unauthenticated|contains: ':role/'
  success:
    errorCode: null
  condition: selection and unauth_role_present and success
falsepositives:
  - >-
    The provisioning pipeline attaching the intended guest role to a pool designed for guest
    access. Distinguishable by principal; if the pipeline is the only caller and the role is on
    the reviewed list, this is expected traffic.
level: high
---
# Both halves inside a day is the complete weapon: the pool accepts anonymous identities AND a
# role is attached for them to assume. `temporal` rather than `temporal_ordered` on purpose -
# either call can come first. A pool can be created guest-enabled and have roles attached
# afterwards, or a role can be attached to a pool that is later flipped to guest access, and both
# orders produce the same live exposure.
#
# Grouped by the POOL, so a chain split across two principals still correlates. Twenty-four hours
# because these are two provisioning steps, often in the same apply and sometimes a change window
# apart.
title: Cognito identity pool made guest-accessible with a role attached
id: 4a29e0a2-6f13-4f0e-9a1c-2b7f5d3c8e41
status: experimental
description: >-
  Within twenty-four hours the same identity pool was set to allow unauthenticated identities and
  had a role attached under the unauthenticated key. That combination hands temporary AWS
  credentials to any anonymous caller who knows the pool ID.
references:
  - https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools-security-best-practices.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
  - attack.initial-access
  - attack.t1078.004
correlation:
  type: temporal
  rules:
    - cognito_identitypool_guest_enabled
    - cognito_identitypool_unauth_role_set
  group-by:
    - requestParameters.identityPoolId
  timespan: 24h
level: critical
---
# Classic flow removes AWS's safety net, and it rides on the same event as the guest flag. In the
# default ENHANCED flow AWS applies an inline session policy plus the managed
# AmazonCognitoUnAuthedIdentitiesSessionPolicy to guest sessions, so effective permissions are the
# intersection of the role's policies and that ceiling. In the BASIC (classic) flow the client
# composes its own AssumeRoleWithWebIdentity and the scope-down does not apply - AWS: "In the
# basic (classic) flow, you make your own AssumeRoleWithWebIdentity API request... As a best
# security practice, don't assign any permissions above this scope-down policy to unauthenticated
# users."
#
# Note the casing caveat: `allowClassicFlow` is INFERRED from the family convention. AWS's
# published CloudTrail example is for CreateIdentityPool and does not carry this field, so
# confirm it in your own trail before relying on it.
title: Cognito identity pool classic authentication flow enabled
id: 7d6b1f84-05ac-4a52-b3d9-6c0e9a417b52
status: experimental
description: >-
  AllowClassicFlow was set to true on an identity pool. In the classic flow the client makes its
  own AssumeRoleWithWebIdentity request and AWS's automatic scope-down session policy for guest
  sessions does not apply, so an unauthenticated role's full permissions become reachable.
references:
  - https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-identity.amazonaws.com'
    eventName:
      - 'CreateIdentityPool'
      - 'UpdateIdentityPool'
  classic_flow:
    requestParameters.allowClassicFlow: true
  success:
    errorCode: null
  condition: selection and classic_flow and success
falsepositives:
  - >-
    A legacy application that predates the enhanced flow and composes its own STS request. Real,
    and worth migrating; on a pool that also allows unauthenticated identities it is not a
    tolerable combination.
level: medium
---
# "WAS IT USED", PATH ONE - and it exists only if you turned it on. GetId and
# GetCredentialsForIdentity are CloudTrail DATA events, off by default and billable, requiring an
# advanced event selector on resources.type = AWS::Cognito::IdentityPool. With that selector, an
# anonymous guest call is unmistakable: AWS's own published examples for both operations show
# `userIdentity` as {"type": "Unknown"} - there is no principal, because there is no
# authentication. That is a high-signal primitive and it is the cleanest evidence of exploitation
# available anywhere.
#
# WITHOUT the selector this rule matches nothing, forever, and its silence is not evidence.
title: Cognito unauthenticated identity issued AWS credentials
id: 9b3c7e15-48fd-4d26-8a0b-1e5c6f2a9d73
status: experimental
description: >-
  GetCredentialsForIdentity or GetId was called by an unauthenticated caller - userIdentity type
  Unknown - against an identity pool. This is credential vending to an anonymous internet client.
  Requires CloudTrail data events on AWS::Cognito::IdentityPool; without them the rule cannot fire.
references:
  - https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognito/latest/developerguide/understanding-amazon-cognito-entries.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
  - attack.initial-access
  - attack.t1078.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-identity.amazonaws.com'
    eventName:
      - 'GetId'
      - 'GetCredentialsForIdentity'
      - 'GetOpenIdToken'
  anonymous_caller:
    userIdentity.type: 'Unknown'
  condition: selection and anonymous_caller
falsepositives:
  - >-
    Every legitimate guest session on a pool that is deliberately guest-enabled. On such a pool
    this rule is a volume baseline rather than an alert - deploy it scoped to pools that should
    NOT have guest access, or feed it to a threshold on distinct source addresses.
level: high
---
# "WAS IT USED", PATH TWO - and counter-intuitively the LESS secure flow is the MORE observable
# one. In the basic (classic) flow the client makes its own AssumeRoleWithWebIdentity call, which
# is an ordinary STS MANAGEMENT event, on by default. IAM documents that CloudTrail "also logs
# non-authenticated requests to the AWS STS actions, AssumeRoleWithSAML and
# AssumeRoleWithWebIdentity", so the unsigned guest exchange IS captured, with userIdentity.type
# WebIdentityUser. In the ENHANCED flow Cognito makes that call on your behalf and no equivalent
# event lands in your trail.
#
# POPULATE THE ROLE ARN BEFORE DEPLOYING. Unpopulated, `unauth_role` matches nothing and this rule
# is inert - it fails closed, which is the right direction for a rule whose false positives would
# be every federated sign-in in the account.
title: Cognito unauthenticated role assumed directly through STS
id: 2f8a4c60-9d71-4bb3-85e2-c4370a6b1d98
status: experimental
description: >-
  A Cognito unauthenticated role was assumed through sts:AssumeRoleWithWebIdentity. This is the
  basic (classic) flow, in which AWS's automatic scope-down session policy for guest sessions does
  not apply, and it is the only credential-issuance path that is visible in a default-configured
  trail.
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
  - attack.initial-access
  - attack.t1078.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sts.amazonaws.com'
    eventName: 'AssumeRoleWithWebIdentity'
  unauth_role:
    requestParameters.roleArn|contains:
      - ':role/Cognito_'          # replace with this account's unauthenticated role ARNs
      - ':role/GuestAccessRole'   # replace with this account's unauthenticated role ARNs
  success:
    errorCode: null
  condition: selection and unauth_role and success
falsepositives:
  - >-
    A legacy classic-flow application whose guest role is on the reviewed list. If that is the
    only caller, this rule is a usage baseline; a new source address or user agent against the
    same role is the signal.
level: high
```

This rule is deliberately only half the detection. It cannot see the role attachment, which is a
different API on a different event, and it cannot express the severity, which lives in an IAM
policy no Cognito API returns. `detections/sigma_t1098.yml` carries the `SetIdentityPoolRoles` rule
and the unordered `temporal` correlation that joins them; `detections/kql_t1098.kql` projects the
two halves as one row and reports whether either issuance-evidence path was even available.

---

### Key Investigation Queries

> Identity pools are regional — run these in the pool's Region, except the IAM sweeps, which are global and land in `us-east-1`. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: which pool was opened, by whom, and which role was attached

```bash
REGION="us-east-1"
RAW=$(for EV in CreateIdentityPool UpdateIdentityPool SetIdentityPoolRoles; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong Region, or"
  echo "    missing cloudtrail:LookupEvents. This is NOT 'no pool was opened'."
else
  # Lower-camel casing is VERIFIED for this service by AWS's published CreateIdentityPool example.
  # allowClassicFlow and roles.unauthenticated follow the convention but are inferred - they are
  # read defensively and nothing is FILTERED on them.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "cognito-identity.amazonaws.com") |
    {time: .eventTime, event: .eventName,
     caller_arn: (.userIdentity.arn // "no-arn"),
     access_key: (.userIdentity.accessKeyId // "none"),
     identity_pool_id: (.requestParameters.identityPoolId // .responseElements.identityPoolId // "unknown"),
     pool_name: (.requestParameters.identityPoolName // .responseElements.identityPoolName // null),
     allow_unauth: (.requestParameters.allowUnauthenticatedIdentities //
                    .responseElements.allowUnauthenticatedIdentities // null),
     classic_flow: (.requestParameters.allowClassicFlow //
                    .responseElements.allowClassicFlow // null),
     unauth_role: (.requestParameters.roles.unauthenticated // null),
     auth_role: (.requestParameters.roles.authenticated // null),
     ip: .sourceIPAddress, agent: .userAgent,
     error: (.errorCode // "SUCCESS")}' |
  jq -s 'sort_by(.identity_pool_id, .time)'
fi
```

Read it per `identity_pool_id` and look for **the pair**, in either order: `allow_unauth` of `true`
and a non-null `unauth_role`. Either alone is incomplete — the flag without a role returns
`InvalidIdentityPoolConfigurationException` to every guest request, and a role without the flag is
inert. `classic_flow` of `true` alongside the pair is a severity multiplier: AWS's scope-down session
policy does not apply. And `SetIdentityPoolRoles` is a **full replacement** capped at two entries, so
a row with `unauth_role` set and `auth_role` null has *removed* the authenticated mapping — a second,
separate outage. Record `identity_pool_id`, both role ARNs, `caller_arn` and `access_key` as IOCs.

#### Query 2 — Inspect the blast radius, which is in IAM and in no Cognito event

```bash
UNAUTH_ROLE_ARN="<unauth-role-from-Query-1>"
ROLE=$(printf '%s' "$UNAUTH_ROLE_ARN" | awk -F'/' '{print $NF}')   # role ARN: name is the LAST segment

# get-role NESTS: Role.AssumeRolePolicyDocument - and botocore's after-call.iam handler has ALREADY
# PARSED it into an object. That is implementation, not documentation, so do not decode it again
# and do not assume it is a string (A4). Statement is an object OR an array, Principal.Federated a
# string OR an array; iterating an object crashes the filter and silently empties the check (D3).
R=$(aws iam get-role --role-name "$ROLE" --output json 2>&1)
case "$R" in
  *AssumeRolePolicyDocument*)
    printf '%s' "$R" | jq -r '
      def stmts: (.Statement // []) | if type == "object" then [.] else . end;
      def fed:   (.Principal.Federated // []) | if type == "string" then [.] else . end;
      .Role.AssumeRolePolicyDocument | stmts
      | map(select(.Effect == "Allow" and (fed | any(. == "cognito-identity.amazonaws.com")))) as $c
      | {t: (($c | length) > 0),
         aud: [$c[] | (.Condition.StringEquals."cognito-identity.amazonaws.com:aud" //
                       .Condition."ForAnyValue:StringEquals"."cognito-identity.amazonaws.com:aud" // empty)] | flatten,
         amr: [$c[] | (.Condition."ForAnyValue:StringLike"."cognito-identity.amazonaws.com:amr" //
                       .Condition."ForAnyValue:StringEquals"."cognito-identity.amazonaws.com:amr" // empty)] | flatten}
      | if (.t | not) then "[i] this role does not trust cognito-identity at all - check the ARN"
        elif (.aud | length) == 0 then "[FAIL] UNPINNED TRUST - no aud condition. AWS: STS permits web identities to assume roles not secured with conditions, so ANY identity pool, including one in an attacker account, can assume this role"
        elif (.amr | length) == 0 then "[FAIL] NO amr CONDITION - guest and authenticated tokens satisfy this trust identically"
        else "[OK] trust pinned to aud=\(.aud | join(",")) with amr=\(.amr | join(","))" end';;
  *) echo "[!] INCONCLUSIVE - get-role failed for $ROLE; the blast radius is UNKNOWN, not empty: $R";;
esac

# Grade every policy the role holds. list-attached-role-policies returns MANAGED policies only,
# so both listings are required or the sweep understates the blast radius. `NotAction` is checked
# explicitly: an Allow with NotAction grants EVERYTHING EXCEPT, and a parser reading only Action is
# silent on the most dangerous shape a policy can take (D-a). Action is a string OR an array (D3).
GRADE='def stmts: (.Statement // []) | if type == "object" then [.] else . end;
       def acts:  (.Action // .NotAction // []) | if type == "string" then [.] else . end;
       stmts | map(select(.Effect == "Allow")) |
       {star: any(.[]; acts | any(. == "*")),
        iam:  any(.[]; acts | any(. == "iam:*" or . == "sts:AssumeRole" or startswith("iam:Put") or startswith("iam:Attach"))),
        na:   any(.[]; has("NotAction")),
        a:    ([.[] | acts] | flatten | unique | .[0:40])} |
       if .star or .na then "  [FAIL] ADMIN-EQUIVALENT: star=\(.star) NotAction=\(.na)"
       elif .iam then "  [FAIL] IDENTITY-PERIMETER GRANT: \(.a | join(","))"
       else "  [i] \(.a | join(","))" end'
M=$(aws iam list-attached-role-policies --role-name "$ROLE" --output json 2>&1)
I=$(aws iam list-role-policies --role-name "$ROLE" --output json 2>&1)
case "$M$I" in
  *AttachedPolicies*PolicyNames*)
    for P in $(printf '%s' "$M" | jq -r '.AttachedPolicies[].PolicyArn'); do
      V=$(aws iam get-policy --policy-arn "$P" --query 'Policy.DefaultVersionId' --output text 2>/dev/null)
      D=$(aws iam get-policy-version --policy-arn "$P" --version-id "$V" --query 'PolicyVersion.Document' --output json 2>&1)
      case "$D" in *Statement*) echo "managed $P"; printf '%s' "$D" | jq -r "$GRADE";;
                   *) echo "[!] INCONCLUSIVE - could not read $P: $D";; esac
    done
    for N in $(printf '%s' "$I" | jq -r '.PolicyNames[]'); do
      D=$(aws iam get-role-policy --role-name "$ROLE" --policy-name "$N" --query 'PolicyDocument' --output json 2>&1)
      case "$D" in *Statement*) echo "inline $N"; printf '%s' "$D" | jq -r "$GRADE";;
                   *) echo "[!] INCONCLUSIVE - could not read inline $N: $D";; esac
    done;;
  *) echo "[!] INCONCLUSIVE - the policy listings failed; permissions are UNKNOWN: $M $I";;
esac
```

**This is the step that determines severity, and nothing in Cognito substitutes for it.** Read the
trust verdict first: an `UNPINNED TRUST` is worse than the incident you are investigating, because
the role is reachable through an identity pool in someone else's account and always was. Then the
permissions, remembering the ceiling — in the **enhanced** flow effective permissions are the
**intersection** with AWS's session policy, so an `s3:*` grant is not `s3:*` in practice; in the
**classic** flow, which Query 1 reports as `classic_flow`, the grade above is the real permission
set.

#### Query 3 — Sweep: every guest-enabled pool in the account, and every role that trusts Cognito

```bash
REGION="us-east-1"
POOLS=$(aws cognito-identity list-identity-pools --max-results 60 --region "$REGION" --output json 2>&1)
# `IdentityPools` is always present on a successful call, even when the list is empty. Testing for
# the KEY rather than for a non-zero length is what separates "no pools" from "the call failed" -
# a length test alone reports a failed sweep as a clean account (D-0).
if ! printf '%s' "$POOLS" | jq -e 'has("IdentityPools")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE - list-identity-pools did not return a pool list: $POOLS"
else
  echo "[i] $(printf '%s' "$POOLS" | jq '.IdentityPools | length') pool(s) in $REGION (paginate on NextToken above 60)"
  for IPID in $(printf '%s' "$POOLS" | jq -r '.IdentityPools[].IdentityPoolId'); do
    D=$(aws cognito-identity describe-identity-pool --identity-pool-id "$IPID" --region "$REGION" --output json 2>&1)
    RS=$(aws cognito-identity get-identity-pool-roles --identity-pool-id "$IPID" --region "$REGION" --output json 2>&1)
    case "$D$RS" in *IdentityPoolId*Roles*) : ;; *) echo "[!] INCONCLUSIVE - could not read $IPID"; continue;; esac
    GUEST=$(printf '%s' "$D" | jq -r '.AllowUnauthenticatedIdentities')
    CLASSIC=$(printf '%s' "$D" | jq -r '.AllowClassicFlow // false')
    UROLE=$(printf '%s' "$RS" | jq -r '.Roles.unauthenticated // empty')
    if   [ "$GUEST" = "true" ] && [ -n "$UROLE" ] && [ "$CLASSIC" = "true" ]; then
      echo "[FAIL] $IPID : LIVE guest access, role=$UROLE, CLASSIC FLOW - no scope-down ceiling"
    elif [ "$GUEST" = "true" ] && [ -n "$UROLE" ]; then
      echo "[FAIL] $IPID : LIVE guest access, role=$UROLE"
    elif [ "$GUEST" = "true" ]; then
      echo "[i]    $IPID : guest flag on, NO unauth role - vends nothing yet, one call from live"
    else
      echo "[OK]   $IPID : guest access off"
    fi
  done
fi

# The IAM half, and it is independent of which pool alerted. A role trusting Cognito with no `aud`
# condition is assumable through ANY identity pool; an authenticated role with no `amr` condition
# is assumable with a GUEST token. Neither is found anywhere else.
ROLES=$(aws iam list-roles --output json)
RC=$(printf '%s' "$ROLES" | jq '.Roles | length' 2>/dev/null)
# Every account has roles, so a non-positive count is a failed sweep, never a clean estate.
if [ "${RC:-0}" -le 0 ]; then
  echo "[!] INCONCLUSIVE - list-roles returned no roles. That is a failed sweep, not a clean one."
else
  printf '%s' "$ROLES" | jq -r '
    def stmts: (.Statement // []) | if type == "object" then [.] else . end;
    def fed:   (.Principal.Federated // []) | if type == "string" then [.] else . end;
    .Roles[] | . as $r |
    (($r.AssumeRolePolicyDocument // {}) | stmts
      | map(select(.Effect == "Allow" and (fed | any(. == "cognito-identity.amazonaws.com"))))) as $c |
    select(($c | length) > 0) |
    {role: $r.RoleName,
     aud: [$c[] | (.Condition.StringEquals."cognito-identity.amazonaws.com:aud" //
                   .Condition."ForAnyValue:StringEquals"."cognito-identity.amazonaws.com:aud" // empty)] | flatten,
     amr: [$c[] | (.Condition."ForAnyValue:StringLike"."cognito-identity.amazonaws.com:amr" //
                   .Condition."ForAnyValue:StringEquals"."cognito-identity.amazonaws.com:amr" // empty)] | flatten} |
    if   (.aud | length) == 0 then "[FAIL] \(.role) : UNPINNED - assumable through ANY identity pool"
    elif (.amr | length) == 0 then "[FAIL] \(.role) : no amr condition - a guest token satisfies this trust"
    else "[OK]   \(.role) : aud=\(.aud | join(",")) amr=\(.amr | join(","))" end'
fi
```

The pool sweep is the eradication work-list; the role sweep is a standing finding that outlives this
incident. Run both **before** changing anything — containment rewrites the role mapping and the
pointer disappears with it.

#### Query 4 — "Was it used": both evidence paths, and the honest answer when neither exists

```bash
REGION="us-east-1"; POOL="<identity-pool-id-from-Query-1>"
UNAUTH_ROLE_ARN="<unauth-role-from-Query-1>"

# PATH ONE - data events. Off by default, so their ABSENCE is a visibility fact, not a finding.
# Check the selector FIRST: without this branch, every zero below reads as "no abuse".
SEL=$(aws cloudtrail get-event-selectors --trail-name "<trail-name>" --region "$REGION" --output json 2>&1)
case "$SEL" in
  *AWS::Cognito::IdentityPool*) echo "[OK] data events on AWS::Cognito::IdentityPool are configured";;
  *EventSelectors*) echo "[!] NO DATA-EVENT SELECTOR for AWS::Cognito::IdentityPool. GetId and"
                    echo "    GetCredentialsForIdentity are NOT logged and never were. Any zero"
                    echo "    below is the absence of LOGGING, not the absence of ABUSE.";;
  *) echo "[!] INCONCLUSIVE - get-event-selectors failed: $SEL";;
esac
# A1: lookup-events returns MANAGEMENT events only, so even with the selector on, these data
# events land in the trail's S3 destination and are read there or through Athena - not here. This
# command surfaces the shape when a trail is misconfigured; a zero from it proves nothing.

# PATH TWO - STS management events, ON BY DEFAULT, and present only in the BASIC (classic) flow.
# In the enhanced flow Cognito makes this call on your behalf and nothing lands in your trail.
STS=$(aws cloudtrail lookup-events \
        --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithWebIdentity \
        --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
        --region "$REGION" --output json)
if [ -z "$STS" ]; then
  echo "[!] INCONCLUSIVE - the STS lookup returned nothing at all. Failed call or wrong Region."
else
  printf '%s' "$STS" | jq -r --arg r "$UNAUTH_ROLE_ARN" '.Events[].CloudTrailEvent | fromjson |
    select((.requestParameters.roleArn // "") == $r) |
    {time: .eventTime, identity_type: (.userIdentity.type // "absent"),
     ip: .sourceIPAddress, agent: .userAgent,
     issued_key: (.responseElements.credentials.accessKeyId // null),
     session: (.responseElements.assumedRoleUser.arn // null),
     error: (.errorCode // "SUCCESS")}' | jq -s 'sort_by(.time)'
fi
```

Every `issued_key` is an `ASIA…` access key handed to an anonymous caller and is the pivot for
Query 5. An `identity_type` of `WebIdentityUser` — or, in the data-event path, `Unknown` — confirms
there was no authenticated principal behind the request. **If the selector check reported no
data-event selector, write "no issuance evidence available" into the incident record, never "no
issuance occurred".** In the enhanced flow with data events off there is nothing to find, and the
absence means only that. Where the data events *are* collected, query them at the trail's S3
destination for `GetId` and `GetCredentialsForIdentity` with `userIdentity.type` of `Unknown`.

Then **follow each `issued_key` forward**: an `ASIA…` key handed to an anonymous caller appears as
`userIdentity.accessKeyId` on every subsequent call that session makes in every other service's
trail, and `lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<key>` is the
only join that answers what the caller actually did. Group by
`userIdentity.sessionContext.sessionIssuer.userName`, which carries the **role** name — A5 applies,
because `AttributeKey=Username` matches Cognito's generated session name and returns zero forever. A
session touching only `cognito-sync` or `mobileanalytics` is behaving as intended; anything reaching
S3, DynamoDB, Lambda, Secrets Manager or IAM is the incident.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**The order is load-bearing twice.** Capture the role and its policies **before** touching the pool:
`SetIdentityPoolRoles` is a full-replacement write and clearing the `unauthenticated` mapping erases
the only pointer from the pool to the role. And stop issuance **before** revoking sessions: an
`aws:TokenIssueTime` deny reaches only tokens issued before the cutoff (E4), so if it lands first
the actor calls `GetCredentialsForIdentity` again and gets a newer session the deny does not reach.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Capture the role and its permissions before anything is changed

```bash
REGION="us-east-1"; POOL="<identity-pool-id-from-Query-1>"
OUT="/tmp/cognito-guest-evidence-$POOL"; mkdir -p "$OUT"

D=$(aws cognito-identity describe-identity-pool --identity-pool-id "$POOL" --region "$REGION" --output json 2>&1)
R=$(aws cognito-identity get-identity-pool-roles --identity-pool-id "$POOL" --region "$REGION" --output json 2>&1)
case "$D" in *IdentityPoolId*) printf '%s' "$D" > "$OUT/pool.json";; *) D="";; esac
case "$R" in *Roles*)          printf '%s' "$R" > "$OUT/roles.json";; *) R="";; esac

if [ -z "$D" ] || [ -z "$R" ]; then
  echo "[!] STOP - the pool's current state could not be captured. Containment below would destroy"
  echo "    the only record of which role guests were handed. Resolve the read first."
else
  UROLE=$(printf '%s' "$R" | jq -r '.Roles.unauthenticated // empty')
  AROLE=$(printf '%s' "$R" | jq -r '.Roles.authenticated // empty')
  if [ -z "$UROLE" ]; then
    echo "[i] no unauthenticated role is mapped - the pool vends nothing. Containment is Step 2 only."
  else
    N=$(printf '%s' "$UROLE" | awk -F'/' '{print $NF}')
    aws iam get-role --role-name "$N" --output json > "$OUT/role.json" 2>&1
    aws iam list-attached-role-policies --role-name "$N" --output json > "$OUT/managed.json" 2>&1
    aws iam list-role-policies --role-name "$N" --output json > "$OUT/inline.json" 2>&1
    for P in $(jq -r '.AttachedPolicies[]?.PolicyArn' "$OUT/managed.json" 2>/dev/null); do
      V=$(aws iam get-policy --policy-arn "$P" --query 'Policy.DefaultVersionId' --output text 2>/dev/null)
      aws iam get-policy-version --policy-arn "$P" --version-id "$V" --output json >> "$OUT/documents.json" 2>&1
    done
    for J in $(jq -r '.PolicyNames[]?' "$OUT/inline.json" 2>/dev/null); do
      aws iam get-role-policy --role-name "$N" --policy-name "$J" --output json >> "$OUT/documents.json" 2>&1
    done
    # get-role ALWAYS returns a role document and both listings ALWAYS return their key for a live
    # role, so an empty or malformed file means the call failed - and proceeding destroys the
    # evidence this step exists to preserve. All three are asserted, not just the first.
    if   ! grep -q 'AssumeRolePolicyDocument' "$OUT/role.json" 2>/dev/null; then
      echo "[!] STOP - $N's trust policy could not be read back. Do NOT clear the role mapping."
    elif ! grep -q 'AttachedPolicies' "$OUT/managed.json" 2>/dev/null \
      || ! grep -q 'PolicyNames' "$OUT/inline.json" 2>/dev/null; then
      echo "[!] STOP - $N's policy listings are incomplete, so what guests could DO is unrecorded."
    else
      echo "[OK] captured pool, role mapping and $N's trust and permissions under $OUT"
      echo "     unauthenticated=$UROLE  authenticated=${AROLE:-none}"
    fi
  fi
fi
```

#### Step 2 — Stop issuance, without breaking authenticated sign-in

```bash
REGION="us-east-1"; POOL="<identity-pool-id-from-Query-1>"
OUT="/tmp/cognito-guest-evidence-$POOL"

# BOTH writes are FULL REPLACEMENTS. UpdateIdentityPool requires IdentityPoolId, IdentityPoolName
# AND AllowUnauthenticatedIdentities, and AWS states "If you don't provide a value for a parameter,
# Amazon Cognito sets it to its default value" - so a bare flag flip silently wipes
# SupportedLoginProviders, CognitoIdentityProviders, the OIDC and SAML provider ARNs and
# AllowClassicFlow, taking AUTHENTICATED sign-in down with the guest access. Build FROM the capture.
if [ ! -s "$OUT/pool.json" ]; then
  echo "[!] STOP - no captured pool state at $OUT/pool.json. Step 1 did not complete."
else
  jq '{IdentityPoolId, IdentityPoolName, AllowUnauthenticatedIdentities: false}
      + with_entries(select(.key | test("^(AllowClassicFlow|SupportedLoginProviders|DeveloperProviderName|OpenIdConnectProviderARNs|CognitoIdentityProviders|SamlProviderARNs|IdentityPoolTags)$")))' \
     "$OUT/pool.json" > "$OUT/close-guest.json"
  echo "[i] request body written to $OUT/close-guest.json - READ IT, then:"
  echo "    aws cognito-identity update-identity-pool --region $REGION --cli-input-json file://$OUT/close-guest.json"
  # SetIdentityPoolRoles is also a full replacement, capped at two entries: resending ONLY the
  # authenticated mapping removes the unauthenticated one. An empty map removes BOTH.
  AROLE=$(jq -r '.Roles.authenticated // empty' "$OUT/roles.json")
  if [ -z "$AROLE" ]; then
    echo "[i] no authenticated role was mapped; clearing roles entirely is safe:"
    echo "    aws cognito-identity set-identity-pool-roles --identity-pool-id $POOL --roles '{}' --region $REGION"
  else
    echo "[i] then, to drop ONLY the unauthenticated mapping:"
    echo "    aws cognito-identity set-identity-pool-roles --identity-pool-id $POOL --region $REGION \\"
    echo "      --roles '{\"authenticated\":\"$AROLE\"}'"
  fi
fi
```

#### Step 3 — Revoke the sessions already issued — only after Step 2 has landed

```bash
UNAUTH_ROLE_ARN="<unauth-role-from-Query-1>"
ROLE=$(printf '%s' "$UNAUTH_ROLE_ARN" | awk -F'/' '{print $NF}')
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# E4, and it is the reason Step 2 comes first: this denies only tokens issued BEFORE the cutoff.
# Run before issuance is cut, the actor calls GetCredentialsForIdentity again, receives a session
# with a newer TokenIssueTime, and is not denied. Run after, there is no way to obtain a new one.
aws iam put-role-policy --role-name "$ROLE" --policy-name "EmergencyRevokeGuestSessions" \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'

# Assert the policy is actually attached rather than announcing that it is. put-role-policy exits 0
# on success but a wrong role name or a missing permission is a silent no-op from the caller's
# point of view, and Recovery would then certify a live role as contained.
V=$(aws iam get-role-policy --role-name "$ROLE" --policy-name "EmergencyRevokeGuestSessions" \
      --output json 2>&1)
case "$V" in
  *TokenIssueTime*) echo "[OK] pre-$CUTOFF guest sessions on $ROLE are denied";;
  *NoSuchEntity*)   echo "[FAIL] the revoke policy is NOT attached to $ROLE - the sessions are live";;
  *)                echo "[!] INCONCLUSIVE - could not read the policy back: $V";;
esac
```

#### Step 4 — Contain the principal that made the change

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["cognito-identity:CreateIdentityPool","cognito-identity:UpdateIdentityPool","cognito-identity:SetIdentityPoolRoles","iam:AttachRolePolicy","iam:PutRolePolicy","iam:UpdateAssumeRolePolicy"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)          U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')   # user ARN: LAST segment
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"; done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyIdentityPerimeter" --policy-document "$DENY";;
  *:assumed-role/*)  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')    # role ARN: 2ND segment
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyIdentityPerimeter" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied identity-perimeter changes for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - contain manually.";;
esac
```

---

## 4. Eradication

### Remove Attacker Access

#### Close every other guest-enabled pool in the account

Query 3's `[FAIL]` lines are the work-list, and each needs the same read-modify-write as §3 Step 2 —
a bare `update-identity-pool --no-allow-unauthenticated-identities` resets `SupportedLoginProviders`,
`CognitoIdentityProviders` and the provider ARNs, taking authenticated sign-in down with the guest
access. Do the `AllowClassicFlow: true` pools first: those are where AWS's scope-down session policy
does not apply and the role's full permissions are reachable.

#### Right-size or retire the unauthenticated role

Removing the mapping deletes nothing and revokes nothing. Decide explicitly:

```bash
ROLE="<role-name-parsed-from-unauth-role-from-Query-1>"
# list-attached-role-policies returns MANAGED policies only, so both loops are needed or the role
# keeps whatever was granted inline.
for P in $(aws iam list-attached-role-policies --role-name "$ROLE" \
             --query 'AttachedPolicies[].PolicyArn' --output text); do
  aws iam detach-role-policy --role-name "$ROLE" --policy-arn "$P" && echo "[OK] detached $P"
done
for I in $(aws iam list-role-policies --role-name "$ROLE" --query 'PolicyNames[]' --output text); do
  aws iam delete-role-policy --role-name "$ROLE" --policy-name "$I" && echo "[OK] deleted inline $I"
done
M=$(aws iam list-attached-role-policies --role-name "$ROLE" --query 'AttachedPolicies[]' --output text 2>&1)
I=$(aws iam list-role-policies --role-name "$ROLE" --query 'PolicyNames[]' --output text 2>&1)
case "$M$I" in
  *NoSuchEntity*|*AccessDenied*) echo "[!] INCONCLUSIVE - could not list policies back: $M $I";;
  "")                            echo "[OK] $ROLE now carries no managed or inline policy";;
  *)                             echo "[FAIL] policies remain on $ROLE: $M $I";;
esac
```

#### Fix every unpinned and `amr`-less trust the sweep found

These are independent of this incident and more dangerous than it. A role trusting
`cognito-identity.amazonaws.com` with **no `aud` condition** is assumable through any identity pool,
including one in an attacker's own account; an **authenticated** role with `aud` but no `amr` can be
assumed with a **guest** token in the basic flow — straight anonymous-to-authenticated escalation.
Add both with `iam:UpdateAssumeRolePolicy`, using the documented shape:

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"Federated":"cognito-identity.amazonaws.com"},
 "Action":"sts:AssumeRoleWithWebIdentity",
 "Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":"<this-pool-id>"},
              "ForAnyValue:StringLike":{"cognito-identity.amazonaws.com:amr":"unauthenticated"}}}]}
```

Set `AllowClassicFlow: false` in the same read-modify-write wherever guest access remains by design —
it restores AWS's scope-down ceiling for guest sessions.

#### Remove the emergency policies once clean, and assert it

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
UNAUTH_ROLE_ARN="<unauth-role-from-Query-1>"
GUEST_ROLE=$(printf '%s' "$UNAUTH_ROLE_ARN" | awk -F'/' '{print $NF}')
aws iam delete-role-policy --role-name "$GUEST_ROLE" --policy-name "EmergencyRevokeGuestSessions" 2>/dev/null
# delete-role-policy exits 0 whether or not anything was there, so re-read rather than announce.
G=$(aws iam get-role-policy --role-name "$GUEST_ROLE" --policy-name "EmergencyRevokeGuestSessions" 2>&1)
case "$G" in
  *NoSuchEntity*)      echo "[OK] the guest-session revoke policy is removed from $GUEST_ROLE";;
  *TokenIssueTime*)    echo "[FAIL] the revoke policy is STILL attached to $GUEST_ROLE";;
  *)                   echo "[!] INCONCLUSIVE - could not read $GUEST_ROLE back: $G";;
esac
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyIdentityPerimeter EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyIdentityPerimeter"
    LEFT=$(aws iam list-user-policies --user-name "$N" --query 'PolicyNames[]' --output text);;
  *) N=""; LEFT="UNCHECKED";;
esac
case "$LEFT" in
  UNCHECKED)   echo "[!] INCONCLUSIVE - neither user nor role; check manually";;
  *Emergency*) echo "[FAIL] an emergency policy is still attached: $LEFT";;
  *)           echo "[OK] no emergency policy remains on $N";;
esac
```

---

## 5. Recovery

### Restore Clean State

#### Verify the pool no longer vends to guests — and that authenticated sign-in survived

```bash
REGION="us-east-1"; POOL="<identity-pool-id-from-Query-1>"
OUT="/tmp/cognito-guest-evidence-$POOL"
D=$(aws cognito-identity describe-identity-pool --identity-pool-id "$POOL" --region "$REGION" --output json 2>&1)
R=$(aws cognito-identity get-identity-pool-roles --identity-pool-id "$POOL" --region "$REGION" --output json 2>&1)
case "$D" in *IdentityPoolId*) : ;; *) D="";; esac
case "$R" in *Roles*)          : ;; *) R="";; esac

if [ -z "$D" ] || [ -z "$R" ]; then
  echo "[!] INCONCLUSIVE - the pool could not be read back. Not restored, not broken: unknown."
else
  GUEST=$(printf '%s' "$D" | jq -r '.AllowUnauthenticatedIdentities')
  CLASSIC=$(printf '%s' "$D" | jq -r '.AllowClassicFlow // false')
  UROLE=$(printf '%s' "$R" | jq -r '.Roles.unauthenticated // empty')
  AROLE=$(printf '%s' "$R" | jq -r '.Roles.authenticated // empty')
  # Collateral check: Step 2's write is a full replacement, so the federated providers are exactly
  # what a careless flag flip destroys - and an outage of authenticated sign-in is a failure of this
  # remediation even though guest access is closed.
  CNT='[(.SupportedLoginProviders//{}|keys[]),(.CognitoIdentityProviders//[]|.[].ProviderName),(.OpenIdConnectProviderARNs//[]|.[]),(.SamlProviderARNs//[]|.[])]|length'
  NOW=$(printf '%s' "$D" | jq "$CNT"); WAS=$(jq "$CNT" "$OUT/pool.json" 2>/dev/null)
  if   [ -z "$GUEST" ]; then
    echo "[!] INCONCLUSIVE - AllowUnauthenticatedIdentities was absent from the response. It is"
    echo "    always present on a live pool, so this is a parse or permission problem."
  elif [ "$GUEST" = "true" ] && [ -n "$UROLE" ]; then
    echo "[FAIL] $POOL still allows unauthenticated identities AND maps role $UROLE - live exposure"
  elif [ "$GUEST" = "true" ]; then
    echo "[FAIL] $POOL still allows unauthenticated identities - no role mapped, so it vends nothing"
    echo "       yet, but it is one SetIdentityPoolRoles call from live"
  elif [ -n "$UROLE" ]; then
    echo "[FAIL] $POOL has guest access off but still maps unauthenticated role $UROLE - remove it"
  elif [ "$CLASSIC" = "true" ]; then
    echo "[FAIL] $POOL still has AllowClassicFlow=true - the scope-down ceiling does not apply"
  elif [ -n "$WAS" ] && [ "${NOW:-0}" -lt "$WAS" ]; then
    echo "[FAIL] identity providers dropped from $WAS to $NOW - the full-replacement write took"
    echo "       authenticated sign-in down with the guest access. Restore from $OUT/pool.json"
  elif [ -z "$WAS" ]; then
    # Guest access IS verified closed; the collateral half could not run. Saying so is the whole
    # point - a missing baseline must not be reported as a passed comparison.
    echo "[OK, PARTIAL] $POOL: guest=false, no unauthenticated role, classic=$CLASSIC. The"
    echo "     provider-count comparison was SKIPPED - no capture at $OUT/pool.json - so whether"
    echo "     the write broke authenticated sign-in is UNVERIFIED. Check it by hand."
  else
    echo "[OK] $POOL: guest=false, no unauthenticated role, classic=$CLASSIC, $NOW provider(s)"
    echo "     intact, authenticated role='${AROLE:-none}'"
  fi
fi
```

Every branch is reachable — the pool still exists and answers — and the two failure modes it catches
are the real ones: a partial close that left the role mapped, and a full-replacement write that
closed guest access by breaking authenticated sign-in.

#### Verify no guest session acted after the cutoff, and no Cognito trust is left unpinned

```bash
REGION="us-east-1"
ROLE_NAME="<role-name-parsed-from-unauth-role-from-Query-1>"
CUTOFF="<iso8601-containment-time-from-Section-3>"

# This CAN still emit a signal after the remediation: the role still exists and is still assumable
# in principle, so a session acting now appears - and with the revoke policy in place it appears as
# an AccessDenied, which is an event rather than silence. Capture the raw pages first so a failed
# lookup cannot collapse into a reassuring zero.
POST=$(aws cloudtrail lookup-events --start-time "$CUTOFF" --region "$REGION" --output json)
ROLES=$(aws iam list-roles --output json)
RC=$(printf '%s' "$ROLES" | jq '.Roles | length' 2>/dev/null)
# A5: post-filter on sessionIssuer.userName, which carries the ROLE name. Keying on
# AttributeKey=Username matches Cognito's generated session name and returns zero forever.
F='.Events[].CloudTrailEvent | fromjson | select((.userIdentity.sessionContext.sessionIssuer.userName // "") == $role)'
N=$(printf '%s' "$POST" | jq -r --arg role "$ROLE_NAME" "[$F] | length" 2>/dev/null)
SUCC=$(printf '%s' "$POST" | jq -r --arg role "$ROLE_NAME" "[$F | select(.errorCode == null)] | length" 2>/dev/null)
UNPINNED=$(printf '%s' "$ROLES" | jq '
  def stmts: (.Statement // []) | if type == "object" then [.] else . end;
  def fed:   (.Principal.Federated // []) | if type == "string" then [.] else . end;
  [.Roles[] | (.AssumeRolePolicyDocument // {}) | stmts
    | map(select(.Effect == "Allow" and (fed | any(. == "cognito-identity.amazonaws.com"))))
    | select(length > 0)
    | select(any(.[]; (.Condition.StringEquals."cognito-identity.amazonaws.com:aud" //
                       .Condition."ForAnyValue:StringEquals"."cognito-identity.amazonaws.com:aud" //
                       null) == null))] | length' 2>/dev/null)

if   [ -z "$POST" ]; then
  echo "[!] INCONCLUSIVE - the post-containment lookup returned nothing at all. Failed call or"
  echo "    wrong Region, NOT proof that the guest sessions stopped."
elif [ "${N:-x}" = "x" ] || [ "${SUCC:-x}" = "x" ] || [ "${UNPINNED:-x}" = "x" ]; then
  echo "[!] INCONCLUSIVE - the events or trust policies could not be parsed; counts unknown, not zero."
# Every account has roles, so a non-positive count is a failed sweep, never a clean estate.
elif [ "${RC:-0}" -le 0 ]; then
  echo "[!] INCONCLUSIVE - list-roles returned no roles. That is a failed sweep, not a clean one."
elif [ "$SUCC" -gt 0 ]; then
  echo "[FAIL] $SUCC successful call(s) by a $ROLE_NAME session AFTER $CUTOFF - containment did not hold"
elif [ "$UNPINNED" -gt 0 ]; then
  echo "[FAIL] $UNPINNED role(s) trust cognito-identity with NO aud condition - assumable through"
  echo "       any identity pool, including one in an attacker's account. Independent of this"
  echo "       incident and not closed by it."
elif [ "$N" -gt 0 ]; then
  echo "[OK] $N call(s) by a $ROLE_NAME session after $CUTOFF, all denied - the revoke is working,"
  echo "     and every Cognito trust across $RC role(s) is pinned"
else
  echo "[OK] no $ROLE_NAME session activity since $CUTOFF, and every Cognito trust across $RC"
  echo "     role(s) is pinned to a pool"
fi
```

The account-wide pool sweep is not repeated here — Query 3 produces it and §4's work-list consumes
it — but the trust half is, because it is the finding most likely to be closed with the incident
rather than fixed.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     CreateIdentityPool or UpdateIdentityPool / cognito-identity.amazonaws.com"
echo "  with requestParameters.allowUnauthenticatedIdentities = true (unquoted boolean) and no"
echo "  errorCode; AND, separately, SetIdentityPoolRoles whose requestParameters.roles has an"
echo "  'unauthenticated' key containing ':role/'. The temporal correlation must fire when both"
echo "  land on the same requestParameters.identityPoolId within 24 hours IN EITHER ORDER."
echo "MUST NOT fire on: a quoted 'true' - the field is a documented Boolean and a string match is"
echo "  dead logic; a SetIdentityPoolRoles carrying only an 'authenticated' key, which is the"
echo "  containment action itself; an UpdateIdentityPool setting the flag to false."
echo "EXPECTED FP, by design: every deliberate guest-access application - anonymous analytics, an"
echo "  unauthenticated media player, a pre-sign-in catalogue browse. These are legitimate and the"
echo "  rule cannot tell them apart, because what makes them safe is the unauthenticated role's"
echo "  policy and no Cognito event contains it. Triage by fetching the role, never by recognising"
echo "  the pool name."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A configuration change handed live AWS credentials to any anonymous internet caller | `cognito-identity:UpdateIdentityPool` and `SetIdentityPoolRoles` granted beyond the provisioning pipeline, and **no IAM condition key exists** that could have permitted pool creation while forbidding guest-enabled pools |
| The alert could not say how bad it was | `SetIdentityPoolRoles` records role ARNs only and no Cognito API returns a policy document, so severity lived in IAM and nobody fetched it as part of triage |
| Nobody could say whether the exposure had been used | Data events on `AWS::Cognito::IdentityPool` were off — the default — and in the enhanced flow Cognito calls STS on your behalf, so neither issuance path was recorded |
| The unauthenticated role's permissions had grown since approval | No baseline of what each guest role is signed off for, and no alert on a policy attached to one — a change to what the internet may do arrives as an ordinary `iam:AttachRolePolicy` |
| A role trusting Cognito with no `aud` condition had been assumable through any identity pool for years | No periodic sweep of Cognito trust policies. IAM only enforces the condition on new policies, so legacy roles keep the gap indefinitely |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// RESOURCE CONTROL POLICY fragment, NOT an SCP (wrap in a full
// {"Version":"2012-10-17","Statement":[ ... ]} document). An SCP cannot help: SCPs act on
// principals, and GetId / GetCredentialsForIdentity have NO principal - AWS states
// "unauthenticated operations aren't associated with an IAM principal. Your VPC endpoint policy or
// RCP must allow all principals for these actions." Hence Principal "*", and it is mandatory.
// The Null operator tests for the PRESENCE of the key: cognito-identity-unauth:IdentityPoolArn is
// populated only on an unauthenticated call, so "false" means "this is a guest request".
// FAILURE DIRECTION: this Deny fails CLOSED - get it wrong and guest access stops working, never
// the reverse. The aws:PrincipalIsAWSService guard keeps a service-initiated call out of it.
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": ["cognito-identity:GetId", "cognito-identity:GetCredentialsForIdentity", "cognito-identity:GetOpenIdToken"],
  "Resource": "*",
  "Condition": {
    "Null": { "cognito-identity-unauth:IdentityPoolArn": "false" },
    "Bool": { "aws:PrincipalIsAWSService": "false" }
  }
}
```

Where guest access is genuinely required for some pools, invert it: allow those pool ARNs
explicitly with `StringEquals` on `cognito-identity-unauth:IdentityPoolArn` — AWS publishes that
exact shape — and deny the rest. The values are concrete ARNs, so `StringEquals` is correct here;
had they carried a wildcard, `StringLike` would be required (E1).

### Structural Controls

- **Confine the write side with an SCP, since the read side needs an RCP.** `cognito-identity:CreateIdentityPool`,
  `UpdateIdentityPool` and `SetIdentityPoolRoles` are IAM-authorized, so an SCP restricting them to
  the provisioning pipeline is reachable and effective. It is blunt — no condition key inspects
  `AllowUnauthenticatedIdentities` — and blunt is what is available.
- **Guard the role, not the flag.** A guest-enabled pool with no unauthenticated role vends nothing
  and returns `InvalidIdentityPoolConfigurationException`, so ensuring no role trusts
  `cognito-identity.amazonaws.com` with `amr: unauthenticated` is the strongest preventative control
  available — enforced by the periodic sweep rather than by a policy condition, because IAM has no
  condition key over policy content either.
- **Pin every Cognito trust** — `aud` to the specific pool and `ForAnyValue:StringLike` on `amr` to
  the intended state, on **both** roles; IAM enforces `aud` on new policies only, so legacy roles
  need a one-off remediation and a recurring check. Set `AllowClassicFlow: false` wherever guest
  access remains, and turn on `AWS::Cognito::IdentityPool` **data events** there — it is the only
  way the next incident can answer "was it used", and the cost is proportional to guest traffic,
  which is exactly the traffic worth paying to see.

### Detection Improvements

- Alert on `iam:AttachRolePolicy` and `iam:PutRolePolicy` targeting any approved unauthenticated
  role. A new policy on a guest role is a change to what the internet may do, and it arrives as an
  ordinary IAM event with no Cognito context attached.
- Run the Query 3 sweep on a schedule, not only during an incident. Both of its findings — a
  guest-enabled pool with a role, and an unpinned Cognito trust — are **states** rather than events,
  and a state that predates your rules will never fire one.
- Where guest access is intended, convert the anonymous-issuance rule into a baseline on **distinct
  source addresses per pool per hour**, and feed `responseElements.credentials.accessKeyId` into the
  IOC pipeline automatically — it is the only durable link between an issuance and what the session
  then does everywhere else.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098 — Account Manipulation (primary, and the source's own label); T1078.004 — Valid Accounts: Cloud Accounts (secondary, what the configuration yields) |
| Primary API | `cognito-identity:UpdateIdentityPool` / `CreateIdentityPool` (`AllowUnauthenticatedIdentities: true`) **and** `cognito-identity:SetIdentityPoolRoles` (`unauthenticated` key); exercised by `GetId` → `GetCredentialsForIdentity` |
| Event source | `cognito-identity.amazonaws.com`. Configuration calls are **management** events, on by default. `GetId`, `GetCredentialsForIdentity`, `GetOpenIdToken`, `GetOpenIdTokenForDeveloperIdentity` and `UnlinkIdentity` are **data** events, **off by default**, needing an advanced event selector on `AWS::Cognito::IdentityPool` |
| Key discriminator | The **pairing** of the guest flag with an attached `unauthenticated` role. Either alone vends nothing, and they arrive on different API calls with different field shapes |
| Field shape | `requestParameters.allowUnauthenticatedIdentities` — **verified** lower-camel, unquoted boolean, from AWS's published `CreateIdentityPool` CloudTrail example. `requestParameters.roles.unauthenticated` and `requestParameters.allowClassicFlow` follow the convention but appear in no published example. `SetIdentityPoolRoles` returns HTTP 200 with an **empty body** — no `responseElements`. Pool ID form is `REGION:GUID` |
| "Was it used" pivot | Two paths, and both may be unavailable. Data events give `userIdentity.type: "Unknown"` on `GetId`/`GetCredentialsForIdentity` plus `responseElements.credentials.accessKeyId` — the `ASIA…` key that joins forward into every other service. Basic (classic) flow gives `sts:AssumeRoleWithWebIdentity` as a **management** event with `userIdentity.type: WebIdentityUser`. In the enhanced flow with data events off there is **no evidence at all** |
| Blast radius | Whatever the unauthenticated role permits, capped in the **enhanced** flow by AWS's inline session policy plus `AmazonCognitoUnAuthedIdentitiesSessionPolicy` (the effective set is the **intersection**) and **uncapped** in the basic flow. Not in any Cognito event — it must be fetched from IAM |
| Error strings | `CreateIdentityPool`: `InternalErrorException` (500), `InvalidParameterException`, `LimitExceededException`, `NotAuthorizedException`, `ResourceConflictException`, `TooManyRequestsException`. `UpdateIdentityPool` adds `ConcurrentModificationException`, `ResourceNotFoundException`. `SetIdentityPoolRoles`: the same set plus `ConcurrentModificationException` and `ResourceNotFoundException`, without `LimitExceededException`. `GetCredentialsForIdentity` adds **`InvalidIdentityPoolConfigurationException`** — the "guest flag on, no role attached" state — plus `ExternalServiceException`. **An authorization failure is `NotAuthorizedException` at HTTP 400, not a 403**; carry `AccessDeniedException` for the IAM-layer form |

**MITRE mapping note.** The source's structured label is `T1098/TA0003`, and it is correct.
`T1098.001` (Additional Cloud Credentials) and `T1098.003` (Additional Cloud Roles) were both
considered and rejected on the merits: nothing is *added* to an account here — the credential is
minted on demand by AWS, and the role already existed. What changed is **who may assume it**, which
is the parent technique. `T1078.004` is carried as a genuine second mapping, because downstream the
guest session is an ordinary assumed-role session and is treated as a valid cloud account by every
service it touches.

### Residual Risk

**Every credential issued before containment remains valid for its full hour**, and the
`aws:TokenIssueTime` deny reaches only sessions of the role it was attached to — a guest session
that had already assumed something else, or a role you did not find, is untouched. In the enhanced
flow with data events off you **cannot enumerate the sessions that existed**, so the honest entry in
the incident record is that an unknown number of anonymous sessions held credentials for an unknown
duration, not that none did. The exposure window cannot be bounded backwards either: the
configuration change is dated, but whether anyone used it is answerable only if data events were on
beforehand, and they cannot be enabled retroactively.

**The pool ID is public and stays public** — embedded in shipped clients, documented by AWS as not
confidential, and not rotatable as a control; if guest access is ever re-enabled on this pool it is
immediately reachable by everyone who harvested the ID. And **the unauthenticated role outlives the
mapping**: removing it from the pool does not delete the role, revoke its policies or change its
trust, and a role whose trust carries no `aud` condition remains assumable through an identity pool
in an attacker's own account, permanently and independently of anything done here. That finding is
the one most likely to be closed along with the incident, and it should not be.

**Nothing above addresses what the guest sessions already did.** If they wrote data, created
resources or read secrets within the role's permissions, those actions are complete and are
attributable only to a session ARN whose identity is, by design, unknown.
