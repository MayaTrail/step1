# Detection Note — T1110.001 / T1078.004 (Failed Administrative Authentication Attempts)

**Signal:** an AWS principal producing repeated failed server-side authentications against a
Cognito user pool through `AdminInitiateAuth` and `AdminRespondToAuthChallenge`.

**The caller is already inside the account, and that is what separates this from its
neighbour.** `AdminInitiateAuth` is IAM-authorized — AWS states plainly that "you must use IAM
credentials to authorize requests, and you must grant yourself the corresponding IAM permission
in a policy." An anonymous attacker on the internet cannot reach it. Every event therefore
carries a real `userIdentity.arn`, and every alert is downstream of an AWS principal that is
either an insider or already compromised. Its sibling use case,
`../../cognito.credential-access.multiple-failed-authentication-attempts-from-single-source/`,
fires on `InitiateAuth`, which AWS documents as the exact opposite: "you can't use IAM
credentials to authorize requests, and you can't grant IAM permissions in policies." Same
directory, same technique, and no overlapping containment lever — see that note's *Why these
two are not one rule* section.

## What the original rule got wrong — it cannot fire on a default user pool

The source rule matches `AdminInitiateAuth`, an `errorCode` of `NotAuthorizedException` or
`UserNotFoundException`, and an `authFlow` in `ADMIN_USER_PASSWORD_AUTH`, `ADMIN_NO_SRP_AUTH`,
`USER_SRP_AUTH` or `CUSTOM_AUTH`. Two of those four flows **cannot produce a password failure
on that event**.

In `USER_SRP_AUTH` the initial call exchanges `SRP_A` for a salt and `SRP_B` and **succeeds**;
the password claim is verified on the following `AdminRespondToAuthChallenge`, which is where
AWS documents the "generic `NotAuthorizedException`". `CUSTOM_AUTH` has the same shape — the
challenge is answered on the Respond call — and so does the `PASSWORD` challenge inside
`USER_AUTH`, which the rule omits entirely.

That is not an edge case, it is the default configuration. AWS: if `ExplicitAuthFlows` is not
specified, an app client supports `ALLOW_REFRESH_TOKEN_AUTH`, `ALLOW_USER_SRP_AUTH` and
`ALLOW_CUSTOM_AUTH` — and nothing else. `ADMIN_USER_PASSWORD_AUTH` has to be turned on
deliberately. **On a default app client the only reachable flows are exactly the two whose
password failures land on the Respond call**, so the rule watches an event that never carries
the failure. The corrected rules match both halves of every flow.

There is one residue worth keeping. On a `USER_SRP_AUTH` call for a username that does not
exist, the *Initiate* call itself can fail with `UserNotFoundException` — so the source rule's
`USER_SRP_AUTH` clause is not wholly dead: it catches **enumeration**, never **guessing**.
Stating that precisely matters, because a reader who sees the rule fire once concludes it
works.

## The second suppression: `PreventUserExistenceErrors` is an app-client setting

AWS documents that when it is active, "the authentication flows `ADMIN_USER_PASSWORD_AUTH`,
`USER_PASSWORD_AUTH`, and the `PASSWORD` flow of `USER_AUTH` return a `NotAuthorizedException`
with the message `Incorrect username or password`… When `PreventUserExistenceErrors` is
inactive, these flows return `UserNotFoundException`."

And the defaults disagree with each other: "When you create a new app client with the Amazon
Cognito user pools API, `PreventUserExistenceErrors` is `LEGACY`, or disabled, by default. In
the Amazon Cognito console, the option **Prevent user existence errors** … is selected by
default." So the source rule's `UserNotFoundException` clause is live on every IaC- or
CLI-created app client and dead on every console-created one, and nothing in the rule tells you
which pool you are looking at. Enumeration coverage cannot rest on that error code. It rests on
volume and on distinct subs, which is what the shipped correlation and the KQL count.

Under SRP the suppression is stronger still: AWS returns a *simulated* RFC 5054 salt and a
generic `NotAuthorizedException` at `RespondToAuthChallenge`, so a nonexistent user is
indistinguishable from a wrong password.

## The lockout, which neither the source rule nor a naive correction matches

AWS: "After five failed sign-in attempts with a user's password, regardless of whether those
are requested with unauthenticated or IAM-authorized API operations, Amazon Cognito locks out
your user for one second. The lockout duration then doubles after each additional one failed
attempt, up to a maximum of approximately 15 minutes. Attempts made during a lockout period
generate a `Password attempts exceeded` exception, and don't affect the duration of subsequent
lockout periods."

Three consequences the detection has to carry:

1. **A sustained run against one account stops producing `NotAuthorizedException`** after the
   fifth attempt and starts producing the lockout form. A rule matching only the two documented
   codes undercounts the attack and can fail to reach its own threshold. The shipped base rule
   OR-s a sibling block on `errorMessage|contains: 'Password attempts exceeded'` — a sibling,
   not a second key inside the error block, because two keys in one Sigma block are ANDed and
   `errorCode` and that message never co-occur in the way that would require (B4).
2. **The counter is shared with the unauthenticated API.** "Regardless of whether those are
   requested with unauthenticated or IAM-authorized API operations" means a principal holding
   `AdminInitiateAuth` can drive any account in the directory into a fifteen-minute lockout —
   a denial-of-service against the user base that produces no successful authentication at all
   and no data loss to point at.
3. **The threshold of five is not arbitrary.** Five is the exact count at which a real user's
   account state changes. `gte: 5`, never `gt` (F6).

## Field shape, and what cannot be pivoted on

`cognito-idp` API operations are CloudTrail **management** events, logged by default, with
`eventType: AwsApiCall`. AWS publishes **no example CloudTrail event for any `cognito-idp`
management operation**, so the exact `requestParameters` shape — whether `authFlow`,
`userPoolId` and `clientId` are present and in what casing — is **unverified**. The shipped
Sigma rules therefore key on `eventSource`, `eventName` and `errorCode` only, and read the
request fields nowhere. Do not add a `requestParameters.authFlow` filter until you have
confirmed the field in your own trail; a filter on a field that is absent matches nothing.

Two things AWS does document about the record:

- "Amazon Cognito records `UserSub` but not `UserName` in CloudTrail logs for requests that are
  specific to a user. You can find a user for a given `UserSub` by calling the `ListUsers` API,
  and using a filter for sub." Every target in this playbook is a `sub`.
- Private fields are obscured with the literal string `HIDDEN_DUE_TO_SECURITY_REASONS`. The
  `AuthParameters` map carrying `USERNAME`, `PASSWORD` and `SRP_A` is redaction-class.

## The blind spot: managed login

Browser-driven sign-in produces neither `AdminInitiateAuth` nor `InitiateAuth`. It produces its
own event names with `eventType: AwsServiceEvent` — `login_POST`, `login_continue_POST`,
`selectChallenge_POST`, `mfa_totp_POST` and the rest for managed login; `Login_GET`,
`CognitoAuthentication`, `Token_POST` and the rest for the classic hosted UI. **A brute force
driven through the hosted pages is invisible to every rule in this file and to the source
rule.** Cover it with a separate rule keyed on those event names, and with AWS WAF.

## Response levers

**Error strings:** `AdminInitiateAuth` documents eighteen operation-specific exceptions:
`InternalErrorException`, `InvalidEmailRoleAccessPolicyException`, `InvalidLambdaResponseException`,
`InvalidParameterException`, `InvalidSmsRoleAccessPolicyException`,
`InvalidSmsRoleTrustRelationshipException`, `InvalidUserPoolConfigurationException`,
`MFAMethodNotFoundException`, `NotAuthorizedException`, `OperationNotEnabledException`,
`PasswordResetRequiredException`, `ResourceNotFoundException`, `TooManyRequestsException`,
`UnexpectedLambdaException`, `UnsupportedOperationException`, `UserLambdaValidationException`,
`UserNotConfirmedException`, `UserNotFoundException`.

Of those, the credential-attack set is `NotAuthorizedException` (wrong password, or a suppressed
nonexistent user), `UserNotFoundException` (nonexistent user, `LEGACY` clients only) and
`UserNotConfirmedException` (the account exists but was never confirmed — a failed
authentication that is simultaneously a positive existence oracle). `PasswordResetRequiredException`
is the same oracle in a different form. `TooManyRequestsException` is the account-level RPS
quota, not the per-user lockout, and must not be counted as a credential failure.

Two deltas against the unauthenticated sibling matter:

- **`ForbiddenException` appears on `InitiateAuth` and not on `AdminInitiateAuth`.** It is the
  AWS WAF block, and WAF only inspects public operations — so its absence here is structural.
- **`MFAMethodNotFoundException` appears on `AdminInitiateAuth` and not on `InitiateAuth`.**

Denials of the API itself are a separate class. The Cognito user pools Common Error Types list
carries **`AccessDeniedException`** (HTTP 403) — "You don't have permission to perform this
action" — and separately `NotAuthorized` (HTTP 401), distinct from the Cognito-specific
`NotAuthorizedException` (HTTP 400). Match `AccessDeniedException` and treat it as
reconnaissance, never as a credential failure; the bare `AccessDenied` form is **not** in
Cognito's documented list. Confirm against a real denied event before hard-coding one form.

**GuardDuty:** There is **no GuardDuty finding type specific to Cognito authentication failures.** Identity-side
findings such as `Impact:IAMUser/AnomalousBehavior` may fire on the calling principal, not on the
user pool. Do not build the response on one existing.

**Severity:** **High**, against the source's **P3**. The gap is not about volume. `AdminInitiateAuth` cannot
be called without AWS credentials, so by the time this rule fires the account boundary has
already been crossed — the user pool attack is the *second* stage, and the first stage is
whatever gave an unexpected principal `cognito-idp:AdminInitiateAuth`. A rule whose precondition
is "an AWS principal is behaving unexpectedly" does not belong at the same priority as a noisy
volume alert. The successful-after-failures correlation is `critical`: it means user pool tokens
have been issued for an account whose password was guessed.

**MITRE:** Primary **T1110.001 — Brute Force: Password Guessing**, Credential Access (TA0006). The source's
own label is the parent **T1110**, which is defensible but less precise: grouping by
`(source IP, principal)` with a threshold of five, against an API that authenticates one named
account per call, is guessing rather than spraying. Where the KQL's `DistinctSubs` count shows
one attempt against each of many accounts, **T1110.003 — Password Spraying** is the better
reading, and the KQL says so in its verdict rather than forcing one label.

Secondary **T1078.004 — Valid Accounts: Cloud Accounts**, carried because the calling principal
must already hold valid AWS credentials for any of this to be possible. That is the half of the
incident the source mapping omits entirely, and it is the half that determines containment.

**Files here:**

- `sigma_t1110_001.yml` — five documents: an `event_count` correlation firing `high` at five
  failures in ten minutes by one principal from one address; a failure base rule (`low`) that
  matches both `AdminInitiateAuth` and `AdminRespondToAuthChallenge` and OR-s the lockout
  message; a success base rule (`low`); a `temporal_ordered` correlation firing `critical` on
  failures-then-success within fifteen minutes; and a `high` rule for admin authentication by a
  principal outside the server-side-auth allowlist.
- `kql_t1110_001.kql` — counts **distinct target subs**, which the Sigma correlation cannot,
  and so separates guessing from spraying; intersects the failing subs with the succeeding subs
  to distinguish a confirmed compromise from a coincidental success; and keeps IAM denials in
  their own column so reconnaissance is never counted as a credential failure.

Full response procedure is in `../PLAYBOOK.md`.
