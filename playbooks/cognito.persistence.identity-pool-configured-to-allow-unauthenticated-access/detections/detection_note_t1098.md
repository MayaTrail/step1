# Detection Note — T1098 / T1078.004 (Identity Pool Configured to Allow Unauthenticated Access)

**Signal:** an identity pool created or updated with `AllowUnauthenticatedIdentities: true`, and —
the half the source rule does not watch — a `SetIdentityPoolRoles` call attaching a role under the
`unauthenticated` key.

**This is not a misconfiguration that leads to account access. It is account access.** AWS states
both halves without hedging: *"Anyone who knows your identity pool ID can request unauthenticated
credentials. Your identity pool ID isn't confidential information"*, and *"Activate guest access
only when you are confident that you would grant the permissions in your IAM role to anyone on the
internet."* Neither `GetId` nor `GetCredentialsForIdentity` requires AWS credentials — both API
references carry *"This is a public API. You do not need any credentials to call this API"* — and
`GetCredentialsForIdentity` explicitly documents that *"Amazon Cognito doesn't evaluate AWS
Identity and Access Management (IAM) policies in requests for this API operation."* The response
carries an `ASIA…` access key, a secret, a session token and an expiry, valid for one hour.

The pool ID is not a control. It is a `REGION:GUID` string that AWS documents as non-confidential
and that ships inside mobile binaries and JavaScript bundles. For triage, assume the attacker has
it; do not let "it's a UUID" downgrade the severity.

## The flag alone vends nothing — and that is the rule's blind spot

`CreateIdentityPool` has **no `Roles` parameter at all**. Roles are attached by a separate
`SetIdentityPoolRoles` call, and until one lands, a guest request fails with
`InvalidIdentityPoolConfigurationException` — AWS: *"If you provided no authentication information
in the request, the identity pool has no unauthenticated role configured."*

So there are two events and the source rule watches one:

| Event | What it means |
|---|---|
| `CreateIdentityPool` / `UpdateIdentityPool` with `allowUnauthenticatedIdentities: true` | The pool will *accept* anonymous identities. Nothing is issued yet |
| `SetIdentityPoolRoles` with an `unauthenticated` key | Anonymous identities now have a role to assume. **This is the moment credentials become obtainable** |

The consequence is a false negative in the most dangerous direction. **A `SetIdentityPoolRoles`
call attaching an unauthenticated role to a pool that was already guest-enabled produces no event
the source rule matches** — no `Create`, no `Update`, no flag in `requestParameters` — and it is
exactly the change that turns a dormant pool into a live one. The shipped rules cover both halves
and correlate them with a `temporal` (unordered) correlation, because either call can legitimately
come first.

## What the original rule got right

Credit where it is due: the source rule's field spelling is correct. AWS publishes a real
`CreateIdentityPool` CloudTrail event and it settles the casing —
`requestParameters.allowUnauthenticatedIdentities`, lower-camel, unquoted boolean:

```json
"eventSource": "cognito-identity.amazonaws.com", "eventName": "CreateIdentityPool",
"requestParameters": {"identityPoolName": "TestPool", "allowUnauthenticatedIdentities": true,
                      "supportedLoginProviders": {"graph.facebook.com": "000000000000000"}},
"responseElements": {"identityPoolId": "us-east-1:1cf667a2-49a6-454b-9e45-23199EXAMPLE", ...}
```

A quoted `'true'` would match nothing on a JSON-typed backend. It also correctly covers both
`Create` and `Update` and carries a success filter. The `P2` rating is the disagreement: this is a
`high` on the configuration change and a `critical` when the role attachment correlates with it.

## The blast radius is not in the event — and that is a Tier-1 property

`SetIdentityPoolRoles` records role **ARNs and nothing else**. Its `Roles` map is documented as a
*"String to string map"* with value length constraints of 20 to 2048 characters — an ARN, not a
policy document. **No policy document appears anywhere** in `CreateIdentityPool`,
`UpdateIdentityPool`, `DescribeIdentityPool`, `SetIdentityPoolRoles` or `GetIdentityPoolRoles`.

So the event says *"guests now get role X"*, and what role X permits is a separate trip to IAM —
`GetRole` for the trust policy, `ListAttachedRolePolicies` + `GetPolicyVersion` for managed, and
`ListRolePolicies` + `GetRolePolicy` for inline, because the first of those returns managed
policies only. Budget for it as a mandatory second hop; the Cognito event can never tell you the
severity.

One mitigating factor to check during that pivot, and one that removes it:

- **In the default *enhanced* flow AWS caps guest sessions.** Cognito applies an inline session
  policy plus the managed `AmazonCognitoUnAuthedIdentitiesSessionPolicy`, so effective permissions
  are the **intersection** of the role's policies and that ceiling. The ceiling is broad but real.
- **`AllowClassicFlow: true` removes the cap.** AWS: *"In the basic (classic) flow, you make your
  own AssumeRoleWithWebIdentity API request… As a best security practice, don't assign any
  permissions above this scope-down policy to unauthenticated users."* Treat classic flow on a
  guest-enabled pool as a severity multiplier, and note it rides on the same `UpdateIdentityPool`
  event as the guest flag.

The default policies are **not** the risk. AWS says the console's generated roles *"have
effectively no permissions granted"* beyond access to Cognito Sync and Mobile Analytics. The risk
is what operators attach afterwards, which is precisely why the IAM pivot is non-optional.

## Two trust-policy shapes that are worse than the pool

The documented trust policy for a Cognito unauthenticated role is:

```json
{"Version":"2012-10-17","Statement":[{"Sid":"","Effect":"Allow",
 "Principal":{"Federated":"cognito-identity.amazonaws.com"},
 "Action":"sts:AssumeRoleWithWebIdentity",
 "Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":"us-east-1:12345678-corner-cafe-123456790ab"},
              "ForAnyValue:StringLike":{"cognito-identity.amazonaws.com:amr":"unauthenticated"}}}]}
```

Both conditions are load-bearing, and neither is visible in any Cognito event:

1. **No `aud` condition → the role is assumable through *any* identity pool**, including one an
   attacker creates in their own account. AWS: *"AWS STS permits web identities to assume roles
   that are not secured with conditions, but those roles can't be modified without introducing
   those conditions."* IAM refuses to save a *new* trust policy without one — *"If you attempt to
   save a role trust policy without a condition of this type, IAM returns an error"* — so this
   exists only on legacy roles, and nothing will surface it except a sweep.
2. **An *authenticated* role with `aud` but no `amr` is a privilege-escalation path.** AWS
   documents `amr` as the claim Cognito sets to `authenticated` or `unauthenticated`, and in the
   basic flow *"users can exchange the tokens from basic authentication for any IAM roles that
   trust your identity pool and amr, or authenticated/unauthenticated state."* Without the `amr`
   condition, a **guest** token satisfies the authenticated role's trust. That is anonymous →
   authenticated in one call, and it is the single highest-value check in this playbook.

## The structural blind spot: in a default account there is no evidence of use

This is worth stating plainly because it inverts the usual triage instinct.

- **`GetId`, `GetCredentialsForIdentity`, `GetOpenIdToken`, `GetOpenIdTokenForDeveloperIdentity`
  and `UnlinkIdentity` are CloudTrail *data* events.** AWS: *"Data events are high-volume
  data-plane API operations that CloudTrail doesn't log by default. Additional charges apply."*
  They require an advanced event selector on `resources.type = AWS::Cognito::IdentityPool`.
- **In the *enhanced* flow — the default — Cognito calls `AssumeRoleWithWebIdentity` on your
  behalf**, so there is no STS event attributable to your caller either. AWS's PrivateLink
  documentation confirms the shape: network context keys on that call *"contain values from the
  identity pools service infrastructure, not from your application's network context."*

Put together: **in a default-configured account, exploitation of this misconfiguration produces no
CloudTrail record at all.** Absence of events is not evidence of non-exploitation, and writing
"no abuse observed" into an incident record on that basis is a false negative of exactly the shape
this corpus keeps finding.

Two paths *do* leave evidence, and the shipped rules cover both:

| Path | Visible? | Shape |
|---|---|---|
| Enhanced flow, data events **on** | Yes | `GetId` / `GetCredentialsForIdentity` with `userIdentity` = `{"type": "Unknown"}` — AWS's own published examples show exactly that, and it is the cleanest anonymous-caller primitive in CloudTrail |
| Basic (classic) flow | **Yes, by default** | `sts:AssumeRoleWithWebIdentity`, a management event. IAM documents that CloudTrail *"also logs non-authenticated requests to the AWS STS actions, AssumeRoleWithSAML and AssumeRoleWithWebIdentity"*, with `userIdentity.type: WebIdentityUser` |
| Enhanced flow, data events **off** | **No** | Nothing. Pivot to the issued `accessKeyId` if you have one, or to downstream services' logs |

Counter-intuitively, **the less secure flow is the more observable one.**

The one durable pivot when data events *are* on: `GetCredentialsForIdentity`'s response carries
`credentials.accessKeyId`, `sessionToken` and `expiration` — but **not** `secretKey`. That `ASIA…`
key id appears as `userIdentity.accessKeyId` on every subsequent call the guest session makes
against every other service, and it is the single best join key in the whole investigation.

## Response levers

**Error strings:** `CreateIdentityPool` (6): `InternalErrorException` (500), `InvalidParameterException`,
`LimitExceededException`, `NotAuthorizedException`, `ResourceConflictException`,
`TooManyRequestsException`.
`UpdateIdentityPool` (8) adds `ConcurrentModificationException` and `ResourceNotFoundException`.
`SetIdentityPoolRoles` (7): `ConcurrentModificationException`, `InternalErrorException`,
`InvalidParameterException`, `NotAuthorizedException`, `ResourceConflictException`,
`ResourceNotFoundException`, `TooManyRequestsException`.
`GetCredentialsForIdentity` adds the operationally meaningful ones: `NotAuthorizedException`,
`ResourceConflictException`, `ResourceNotFoundException`, `InvalidIdentityPoolConfigurationException`,
`InvalidParameterException`, `ExternalServiceException`, `InternalErrorException`,
`TooManyRequestsException`.

Two to write down. **`InvalidIdentityPoolConfigurationException` is the "flag on, no role
attached" state** — a guest-enabled pool that vends nothing yet — and seeing it in a trail is a
one-call-from-live warning. And **an authorization failure is `NotAuthorizedException` at HTTP
400, not a 403**, across every one of these APIs; a rule keyed on the status code misses it. Carry
`AccessDeniedException` alongside for the IAM-layer form.

## Guardrails, and the gap

**There is no IAM condition key that inspects `AllowUnauthenticatedIdentities`.** No
`cognito-identity:AllowUnauthenticatedIdentities` exists, so you cannot write a preventative policy
that permits `CreateIdentityPool` but forbids guest-enabled pools. This is a real gap and the
playbook states it rather than papering over it.

The condition keys that do exist are on the **unauthenticated data plane**:
`cognito-identity-unauth:IdentityPoolArn`, `cognito-identity-unauth:AccountId` and their `-auth:`
counterparts, applying to `GetId`, `GetCredentialsForIdentity`, `GetOpenIdToken` and
`UnlinkIdentity`. They are reachable only from a **resource control policy or a VPC endpoint
policy**, never from an identity-based policy — AWS: *"Unlike endpoint policies, you can't
configure permissions for unauthenticated operations in identity-based policies"* — and such a
policy **must** specify `"Principal": "*"`, because *"unauthenticated operations aren't associated
with an IAM principal."* An SCP is structurally unable to help: there is no principal for it to
attach to (D-i, exactly).

The strongest preventative control is therefore indirect: **a guest-enabled pool with no
unauthenticated role issues nothing.** Guard the role, not the flag.

**GuardDuty:** There is **no GuardDuty finding type specific to Cognito guest access.** `CredentialAccess:` and
`Discovery:` findings may fire on the *assumed-role session* once it acts, but nothing fires on the
configuration change or on the credential issuance itself. Do not build the response on one
existing.

**Severity:** **Critical** where a role is attached, against the source's **P2**. The gap is not a matter of
degree. There is no intermediate step, no credential to steal and no privilege to escalate: a
correctly configured guest pool hands an unauthenticated internet caller a live AWS session by
design, and the only thing standing between that and account impact is the unauthenticated role's
policy — which is not in the event, not in any Cognito API, and not known to the person triaging
the alert until they go and get it. **High** for the flag alone, because it is one
`SetIdentityPoolRoles` call from live.

**MITRE:** Primary **T1098 — Account Manipulation**, Persistence (TA0003) — the source's own structured label,
and correct: the technique is the modification of an identity configuration so that access
persists, here for an actor who need not authenticate at all. Secondary **T1078.004 — Valid
Accounts: Cloud Accounts**, for what the configuration then yields — a legitimate, AWS-issued
session that is indistinguishable from any other assumed-role session downstream.

Two sub-techniques were considered and rejected on the merits. **T1098.001 (Additional Cloud
Credentials)** describes adding adversary-controlled credentials to an account; nothing is added
here, the credential is minted on demand by AWS. **T1098.003 (Additional Cloud Roles)** describes
adding roles or permissions to an adversary-controlled account; the role already exists and what
changed is *who may assume it*. The parent is the honest mapping.

**Files here:**

- `sigma_t1098.yml` — six documents: the guest-flag rule (`high`, and the source rule's observable
  corrected); the `SetIdentityPoolRoles` unauthenticated-role rule (`high`, the half the source
  rule cannot see); a `temporal` — deliberately unordered — correlation firing `critical` when both
  land on the same pool within twenty-four hours; a `medium` rule for `AllowClassicFlow`, which
  removes AWS's scope-down ceiling; a `high` rule for anonymous credential issuance keyed on
  `userIdentity.type: Unknown`, which requires data events; and a `high` rule for the classic-flow
  `sts:AssumeRoleWithWebIdentity` path, which is the only issuance evidence a default trail carries.
- `kql_t1098.kql` — joins the guest flag to the role attachment **across two event names**, which
  the Sigma correlation can group but not project together; reports whether classic flow is also
  on; and counts the two independent evidence paths side by side with an `EvidenceAvailable` column
  so that "nothing found" reads as "nothing could have been found".

Full response procedure is in `../PLAYBOOK.md`. The sibling
`../../cognito.impact.identity-pool-deletion-detected/` covers the same resource being destroyed,
and its note carries the orphaned-role analysis that applies whenever a pool goes away.

Full response procedure is in `../PLAYBOOK.md`.
