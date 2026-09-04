# Detection Note — T1110.003 / T1110.004 (Failed User Authentication From a Single Source IP)

**Signal:** a single source address failing Cognito user-pool authentication at volume through
`InitiateAuth` and `RespondToAuthChallenge`.

## Why these two are not one rule

This use case and
`../../cognito.credential-access.multiple-failed-administrative-authentication-attempts/` look
like one rule at two thresholds. They are not, and the difference is **the caller, not the
target** — `AdminInitiateAuth` authenticates an ordinary end user on a server's behalf, so
nothing about its target is administrative. AWS documents the two APIs in opposite terms:

- `InitiateAuth`: *"Amazon Cognito doesn't evaluate AWS Identity and Access Management (IAM)
  policies in requests for this API operation. For this operation, you can't use IAM credentials
  to authorize requests, and you can't grant IAM permissions in policies."*
- `AdminInitiateAuth`: *"you must use IAM credentials to authorize requests."*

So there is **no calling principal here at all**: `userIdentity` degrades to an `accountId` or
`{"type": "Unknown"}`, and `sourceIPAddress` is the only actor identifier the event carries. The
consequence is that the two use cases share no containment lever. An IAM deny — the entire
containment of the sibling — is a documented no-op against this API. AWS WAF — the entire
containment of this one — has a documented scope of *"public API operations… that don't use AWS
credentials to authorize"*, which excludes the sibling by definition. Their `AuthFlow` enums are
disjoint at the point that matters: AWS states `ADMIN_USER_PASSWORD_AUTH` and `ADMIN_NO_SRP_AUTH`
*"isn't valid for InitiateAuth"*, and `USER_PASSWORD_AUTH` *"isn't valid for AdminInitiateAuth"*.
The full merge assessment is in `../_source/PROVENANCE.md`.

The two do share two structural traps, explained here and cross-referenced there.

## What the original rule got wrong — trap one, the wrong event

The source rule matches `InitiateAuth` with `NotAuthorizedException` or `UserNotFoundException`
and an `authFlow` in `USER_SRP_AUTH`, `USER_PASSWORD_AUTH`, `USER_AUTH` or `CUSTOM_AUTH`. Only
**one** of those four carries the password in the initial call.

In `USER_SRP_AUTH` the initial call exchanges `SRP_A` for a salt and `SRP_B` and **succeeds**; AWS
documents the password verdict as a "generic `NotAuthorizedException`" at
`RespondToAuthChallenge`. `CUSTOM_AUTH` and the `PASSWORD` challenge of `USER_AUTH` have the same
shape. And AWS documents the default: an app client with no `ExplicitAuthFlows` supports
`ALLOW_REFRESH_TOKEN_AUTH`, `ALLOW_USER_SRP_AUTH` and `ALLOW_CUSTOM_AUTH` — so **on a default app
client the only reachable flows are the ones whose failure lands on the Respond call**. The
corrected rules match both event names.

## Trap two: `PreventUserExistenceErrors` is an app-client setting the rule never checks

AWS: when it is active, *"the authentication flows `ADMIN_USER_PASSWORD_AUTH`,
`USER_PASSWORD_AUTH`, and the `PASSWORD` flow of `USER_AUTH` return a `NotAuthorizedException`
with the message `Incorrect username or password`… When `PreventUserExistenceErrors` is inactive,
these flows return `UserNotFoundException`."* Under SRP the suppression is stronger still — a
nonexistent user receives a **simulated** RFC 5054 salt and a UUID, so the response is
indistinguishable from a wrong password.

The defaults disagree: *"When you create a new app client with the Amazon Cognito user pools API,
`PreventUserExistenceErrors` is `LEGACY`, or disabled, by default. In the Amazon Cognito console,
the option **Prevent user existence errors** … is selected by default."* The rule's
`UserNotFoundException` clause is therefore live on IaC-created clients and dead on
console-created ones, with nothing in the rule to say which. Enumeration coverage cannot rest on
that code.

## The threshold is unreachable for the attack the rule names

This is the sharpest defect in the source rule and it is arithmetic, not opinion.

AWS: *"After five failed sign-in attempts with a user's password… Amazon Cognito locks out your
user for one second. The lockout duration then doubles after each additional one failed attempt,
up to a maximum of approximately 15 minutes… For a cumulative number of failed sign-in attempts
n, not including `Password attempts exceeded` exceptions, Amazon Cognito locks out your user for
2^(n-5) seconds."* And: *"Attempts made during a lockout period generate a `Password attempts
exceeded` exception"* — a form the source rule does not match.

So to accumulate **fifteen counted failures against one account**, an attacker must wait out
2⁰+2¹+…+2⁹ = **1,023 seconds**, over seventeen minutes — outside the rule's own ten-minute window.
A sustained single-account brute force therefore **can never fire this rule**: the first five
attempts are counted, and every attempt after that returns a form the rule ignores. Fifteen is an
implicit *multi-account* threshold that the rule neither states nor verifies, because it never
counts accounts.

The correction is in two parts. The base rule OR-s a sibling block on
`errorMessage|contains: 'Password attempts exceeded'`, which makes the single-account case
reachable. And a second correlation treats sustained lockouts as what they actually are — an
**availability attack**. Because the lockout counter is shared *"regardless of whether those are
requested with unauthenticated or IAM-authorized API operations"*, an actor who fails five times
against each of a list of usernames holds every one of those accounts in a doubling lockout
without guessing anything. There is no successful sign-in to detect and nothing is exfiltrated;
the symptom that reaches the business is a support queue full of people who cannot sign in.

## The blind spot that swallows most real traffic

**Managed login and the classic hosted UI produce no `InitiateAuth` event.** They produce their
own event names with `eventType: AwsServiceEvent` — `login_POST`, `login_continue_POST`,
`selectChallenge_POST`, `mfa_totp_POST`, `passkeys_add_POST` for managed login; `Login_GET`,
`CognitoAuthentication`, `OAuth2_Authorize_GET`, `Token_POST`, `ForgotPassword_POST` for the
classic hosted UI. On a consumer-facing pool that is where the users are, and therefore where the
credential stuffing is. Nothing in the source rule or in the shipped Sigma sees it. Cover it with
a rule keyed on those event names, and with AWS WAF, which does inspect the managed-login
endpoints.

## Field shape

`cognito-idp` operations are CloudTrail **management** events, logged by default. AWS publishes
**no example CloudTrail event for any `cognito-idp` management operation**, so whether
`requestParameters` carries `authFlow`, `clientId`, `userPoolId` or any target identifier — and in
what casing — is **unverified**. Every shipped rule keys on `eventSource`, `eventName`,
`errorCode` and `errorMessage` only. The KQL reads request fields best-effort and gates its
shape verdicts on whether a target sub was actually present, so an absent field yields
`SHAPE UNKNOWN` rather than a wrong verdict.

Two documented facts about the record: AWS *"records `UserSub` but not `UserName` in CloudTrail
logs for requests that are specific to a user"*, and private fields — including the
`AuthParameters` map holding `USERNAME`, `PASSWORD` and `SRP_A` — are obscured as
`HIDDEN_DUE_TO_SECURITY_REASONS`.

## Response levers

**Error strings:** `InitiateAuth` documents eighteen operation-specific exceptions: `ForbiddenException`,
`InternalErrorException`, `InvalidEmailRoleAccessPolicyException`,
`InvalidLambdaResponseException`, `InvalidParameterException`,
`InvalidSmsRoleAccessPolicyException`, `InvalidSmsRoleTrustRelationshipException`,
`InvalidUserPoolConfigurationException`, `NotAuthorizedException`, `OperationNotEnabledException`,
`PasswordResetRequiredException`, `ResourceNotFoundException`, `TooManyRequestsException`,
`UnexpectedLambdaException`, `UnsupportedOperationException`, `UserLambdaValidationException`,
`UserNotConfirmedException`, `UserNotFoundException`.

Three of them are worth separating out:

- **`ForbiddenException` on `cognito-idp` can only be an AWS WAF block.** It is documented on
  `InitiateAuth` and **absent** from `AdminInitiateAuth`, because WAF inspects public operations
  only. It is positive confirmation that a web ACL is associated and firing — and blocked
  requests are never authentication failures, because AWS states they *"do not count towards the
  request rate quota"* and the WAF handler runs before the API throttling handler.
- **`TooManyRequestsException`** is the account-level `UserAuthentication` category quota — 120
  RPS, pooled across `InitiateAuth`, `AdminInitiateAuth` and the token endpoint — not the per-user
  lockout. Counting it as a credential failure conflates a capacity event with an attack.
- **`UserNotConfirmedException`** and **`PasswordResetRequiredException`** are failed
  authentications that are simultaneously positive existence oracles, and they survive
  `PreventUserExistenceErrors` where `UserNotFoundException` does not.

`AccessDeniedException` (HTTP 403) is in the Cognito user pools Common Error Types list, but it
cannot arise from an IAM evaluation on this API, since AWS states IAM is not evaluated for it.

**GuardDuty:** There is **no GuardDuty finding type specific to Cognito authentication failures.** Do not build
the response on one existing.

**Severity:** **Medium** for the volume alert, against the source's **P3** — a modest raise, and deliberately
more modest than its IAM-authorized sibling. Nothing here implies the account boundary has been
crossed; a consumer-facing pool on the public internet is scanned continuously, and an alert with
no principal and a NAT-shared address is weak evidence on its own. The **failures-then-success**
correlation is `critical`, because that is a compromised account with tokens already issued, and
the **lockout** correlation is `high`, because it is a live availability incident regardless of
whether any password is guessed.

**MITRE:** Primary **T1110.003 — Brute Force: Password Spraying**, Credential Access (TA0006). The source's
own label is the parent **T1110**. The refinement is justified by the arithmetic above: a
threshold of fifteen inside ten minutes is only reachable across multiple accounts, which is
spraying by definition — the rule is a spraying detector that does not know it. **T1110.004 —
Credential Stuffing** is carried as a genuine second mapping for the shape the KQL separates out,
where a small number of attempts is made against each of many accounts and a few succeed, which
is a reused-password list rather than a guessed password.

**Files here:**

- `sigma_t1110_003.yml` — six documents: an `event_count` correlation firing `high` at fifteen
  failures in ten minutes from one address; a failure base rule (`low`) matching both
  `InitiateAuth` and `RespondToAuthChallenge` and OR-ing the lockout message; a success base rule
  (`low`); a `temporal_ordered` correlation firing `critical` on failures-then-success within
  fifteen minutes; a lockout base rule (`low`); and an `event_count` correlation firing `high` at
  ten lockouts in ten minutes, which is the availability attack the source rule cannot express.
- `kql_t1110_003.kql` — counts **distinct target subs** to separate guessing from spraying from
  stuffing, intersects failing subs with succeeding subs to distinguish a real compromise from a
  coincidental success behind a shared address, allowlists known NAT egress by CIDR, and keeps
  WAF blocks and RPS throttles out of the failure count.

Full response procedure is in `../PLAYBOOK.md`. The sibling note in
`../../cognito.credential-access.multiple-failed-administrative-authentication-attempts/detections/detection_note_t1110_001.md`
covers the same two traps from the IAM-authorized side.

Full response procedure is in `../PLAYBOOK.md`.
