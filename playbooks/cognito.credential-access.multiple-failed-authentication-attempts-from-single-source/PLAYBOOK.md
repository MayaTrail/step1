# IR Playbook: Failed Authentication From a Single Source IP — Anonymous Password Attack on a User Directory via `cognito-idp:InitiateAuth`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential access (an anonymous internet client repeatedly fails to authenticate user-pool accounts, spraying or stuffing passwords, enumerating the directory, or holding accounts in AWS's exponential lockout) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **Medium** for the volume alert, against the source's **P3** — a deliberately modest raise. `InitiateAuth` is a public API on the internet and a consumer-facing pool is scanned continuously; with no calling principal and an address that may be shared NAT, volume alone is weak evidence. Two derived signals are not: **failures then a success on the same account is Critical** — tokens are issued and the account is compromised — and **sustained lockouts are High**, because that is a live availability incident whether or not any password is ever guessed |
| MITRE Tactics | Credential Access (TA0006) |
| MITRE Techniques | T1110.003 (primary), T1110.004 (secondary) — both verified live 2026-08-29 |
| Services in Scope | Cognito user pools, CloudTrail, AWS WAF, CloudWatch (`AWS/Cognito`), Cognito threat protection and `userAuthEvents` log export where the pool is on the Plus feature plan, IAM (for the operators who own app-client configuration, not for the attacker) |

**What the technique does:** the actor calls `InitiateAuth` against a user pool app client with a username
and a candidate password. No AWS credentials are involved — AWS states plainly that for this
operation *"you can't use IAM credentials to authorize requests, and you can't grant IAM
permissions in policies"* — so the only identifier the event carries is `sourceIPAddress`. For
`USER_PASSWORD_AUTH` the password is in that call and a wrong one returns
`NotAuthorizedException`. For `USER_SRP_AUTH`, `CUSTOM_AUTH` and the `PASSWORD` challenge of
`USER_AUTH` the initial call **succeeds** — it exchanges `SRP_A` for a salt — and the failure
lands on `RespondToAuthChallenge`. After five failed password attempts the account is locked for
`2^(n-5)` seconds to a ceiling of about fifteen minutes, and further attempts return
`Password attempts exceeded`. A success returns ID, access and refresh tokens for that account,
and the refresh token keeps working long after the source address is blocked.

**Detection thesis.** The discriminator is **the number of distinct accounts behind the failure
count**, because that is what separates guessing (one account, now locked out) from spraying and
stuffing (many accounts, none locked, the directory mapped) — and the source rule counts only
events, from an address that on a consumer pool is frequently shared NAT. Worse, it watches
`InitiateAuth` alone, where on a default app client no password failure ever lands, and it does
not match the lockout form, which makes its own fifteen-in-ten-minutes threshold arithmetically
unreachable for the single-account attack it names.

> The IAM-authorized counterpart is
> `../cognito.credential-access.multiple-failed-administrative-authentication-attempts/`. It is a
> separate use case because the two share **no containment lever**: an IAM deny is a documented
> no-op here, and AWS WAF does not inspect the API there. See `_source/PROVENANCE.md`.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing Cognito user pool **management** events. AWS: *"Amazon Cognito logs user pool events to CloudTrail as management events"* — on by default. `eventSource` is `cognito-idp.amazonaws.com`; API calls carry `eventType: AwsApiCall`, and `userIdentity` degrades to an `accountId` or `{"type": "Unknown"}` because the call is unauthenticated
- **AWS publishes no example CloudTrail event for any `cognito-idp` management operation**, so whether `requestParameters` carries `authFlow`, `clientId` or a target identifier, and in what casing, is **unverified**. Generate one failed sign-in in a test pool and read your own trail before writing any rule that filters on a request field
- The target account is a **`sub`, never a username** — AWS: *"Amazon Cognito records `UserSub` but not `UserName` in CloudTrail logs for requests that are specific to a user."* Private fields, including the `AuthParameters` map holding `USERNAME`, `PASSWORD` and `SRP_A`, appear as `HIDDEN_DUE_TO_SECURITY_REASONS`
- **An AWS WAF web ACL associated with the user pool, before the incident.** It is the only preventative control that reaches this API, it is available in all feature plans, and — critically — it also inspects the managed-login endpoints that CloudTrail records under entirely different event names. Association is made from WAF's side (`wafv2 associate-web-acl`), because Cognito has no API of its own for it. Retain WAF logs; identify Cognito traffic by the `x-amzn-cognito-client-id` and `x-amzn-cognito-operation-name` headers
- **The list of managed-login and hosted-UI event names**, because nothing else in this playbook covers them: `login_POST`, `login_continue_POST`, `selectChallenge_POST`, `mfa_totp_POST`, `signup_POST`; `Login_GET`, `CognitoAuthentication`, `OAuth2_Authorize_GET`, `Token_POST`, `ForgotPassword_POST`
- `AWS/Cognito` metrics `SignInSuccesses` and `SignInThrottles` per `UserPool` and `UserPoolClient`. **There is no failure metric** — AWS documents the derivation as `SampleCount` minus `Sum`, and throttled requests count as unsuccessful. A metric with no datapoints for two weeks disappears from `list-metrics`; use `get-metric-data`
- Where the pool is on the **Plus** feature plan: threat protection in at least Audit-only mode and `userAuthEvents` log export. That export is the only source carrying `userName`, `clientId` and `requestId` beside the risk decision; it is `INFO`-level only, so throttling errors are excluded, and AWS states delivery is best effort
- **A maintained list of known egress CIDRs** — corporate NAT, mobile carrier CGNAT, partner VPNs. Without it, every source-IP threshold on a consumer pool is a false-positive generator that gets muted inside a week

**Alerting (must be pre-configured)**
- **Authentication failures from one source address followed by a success from that address within 15 minutes → P0**
- **Fifteen or more failed authentications in ten minutes from one source address → P1**
- **Ten or more `Password attempts exceeded` responses in ten minutes from one source address → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- **The normal value for this measure, per resource, from a quiet week.** The rule compares against a resource's own history rather than a fleet average, so without the baseline the threshold is a guess.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Authentication failures from one source address followed by a success from that address within 15 minutes, on the same `sub` | CloudTrail (management) | T1110.004 |
| P1 | Fifteen or more failed authentications in ten minutes from one source address, counted across `InitiateAuth` and `RespondToAuthChallenge` and including the lockout form | CloudTrail (management) | T1110.003 |
| P1 | Ten or more `Password attempts exceeded` responses in ten minutes from one source address — accounts held in lockout | CloudTrail (management) | T1110.003 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Failures spread thinly across ten or more distinct `sub` values from one address — spraying or credential stuffing | CloudTrail (management) | T1110.004 |
| P2 | A burst of managed-login or hosted-UI event names (`login_POST`, `Login_GET`, `Token_POST`) with failures from one address — the half of the traffic this technique's rules cannot see | CloudTrail (`AwsServiceEvent`) | T1110.003 |
| P3 | `SignInSuccesses` `SampleCount` far exceeding its `Sum` for one app client | CloudWatch `AWS/Cognito` | T1110.003 |
| P3 | `ForbiddenException` on `InitiateAuth` — an AWS WAF block. Confirmation the control is present and firing, and never an authentication failure | CloudTrail (management) | T1110.003 |

### Detection Rule Quality Notes

The source rule watches an event where the failure does not land, and sets a threshold its own
matching cannot reach.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Matches `InitiateAuth` only, while listing `USER_SRP_AUTH`, `USER_AUTH` and `CUSTOM_AUTH` in its `authFlow` clause | In those flows the initial call **succeeds** and the password is verified on `RespondToAuthChallenge`. AWS documents an app client with no `ExplicitAuthFlows` as supporting `ALLOW_REFRESH_TOKEN_AUTH`, `ALLOW_USER_SRP_AUTH` and `ALLOW_CUSTOM_AUTH` — so on a **default** app client no password failure ever reaches the event the rule watches | Match `InitiateAuth` **and** `RespondToAuthChallenge` |
| Threshold of 15 in 10 minutes, with no match on the lockout form | AWS locks an account out after five failures for `2^(n-5)` seconds; reaching fifteen **counted** failures on one account needs 2⁰+2¹+…+2⁹ = 1,023 seconds of cumulative waiting — over seventeen minutes, outside the window. So a sustained single-account brute force **can never fire this rule**, and 15 is an unstated multi-account threshold the rule never verifies | OR a sibling block on `errorMessage|contains: 'Password attempts exceeded'`, which makes the single-account case reachable, and add a second correlation for the lockout as an availability attack |
| `UserNotFoundException` treated as a reliable enumeration signal | It is suppressed into `NotAuthorizedException` on every app client with `PreventUserExistenceErrors` active — the console's default, though the API's default is `LEGACY` — and under SRP a nonexistent user gets a **simulated** salt, so the two are indistinguishable. The clause is live on some pools and dead on others and the rule cannot say which | Add `UserNotConfirmedException` and `PasswordResetRequiredException`, which are existence oracles that survive the suppression; record each client's setting in §1 |
| Grouped by source IP alone; distinct accounts never counted | Fifteen attempts on one account and one attempt on each of fifteen accounts are the same alert and are three different incidents with three different responses | Count distinct `sub` per address; the KQL does this and gates its verdict on whether a sub was actually present |
| No egress allowlist | On a consumer-facing pool behind carrier NAT, fifteen failures from one address in ten minutes is ordinary traffic. The rule fires constantly and is muted, taking the P0 correlation with it | Allowlist known egress by CIDR and triage on the distinct-sub count rather than the raw failure count |
| Nothing covers managed login | Browser sign-in produces no `InitiateAuth` at all — it produces `AwsServiceEvent` records under different names. On a consumer pool that is where most of the traffic and most of the stuffing is, and it is invisible | Ship a companion rule on those event names, and associate a WAF web ACL, which does inspect them |

**Recommended detection — repeated authentication failure from one source address.**

```yaml
# Failed User Authentication From a Single Source IP (T1110.003 / T1110.004)
#
# WHAT THE ORIGINAL RULE GOT WRONG, IN THREE PLACES.
#
# 1. IT WATCHES THE WRONG EVENT FOR THE FLOWS THAT ACTUALLY EXIST. The source rule matches
#    `InitiateAuth` with an errorCode of NotAuthorizedException or UserNotFoundException and an
#    authFlow in (USER_SRP_AUTH, USER_PASSWORD_AUTH, USER_AUTH, CUSTOM_AUTH). In USER_SRP_AUTH
#    the initial call only exchanges SRP_A for a salt and SRP_B - it SUCCEEDS - and AWS documents
#    the password verdict as a "generic NotAuthorizedException" at `RespondToAuthChallenge`.
#    CUSTOM_AUTH and the PASSWORD challenge of USER_AUTH have the same shape. Only
#    USER_PASSWORD_AUTH carries the password in the initial call. AWS: an app client with no
#    ExplicitAuthFlows supports ALLOW_REFRESH_TOKEN_AUTH, ALLOW_USER_SRP_AUTH and
#    ALLOW_CUSTOM_AUTH - so on a DEFAULT app client the only reachable flows are exactly the ones
#    whose failure lands on the Respond call, and the rule is structurally dead. Every rule below
#    matches BOTH `InitiateAuth` and `RespondToAuthChallenge`.
#
# 2. ITS THRESHOLD IS UNREACHABLE FOR THE ATTACK IT NAMES. AWS locks a user out after five failed
#    password attempts for 2^(n-5) seconds, and "attempts made during a lockout period generate a
#    `Password attempts exceeded` exception" which the source rule does not match. Reaching
#    fifteen COUNTED failures against ONE account inside ten minutes would require waiting out
#    2^0+2^1+...+2^9 = 1,023 seconds of cumulative lockout - over seventeen minutes. So a
#    sustained single-account brute force can never fire the rule: the first five attempts count,
#    and every attempt after that returns a form the rule ignores. Fifteen is therefore an
#    implicit MULTI-ACCOUNT threshold that the rule never states and never verifies, because it
#    does not count accounts. The base rule below OR-s the lockout form in, which makes the
#    single-account case reachable, and a second correlation treats sustained lockouts as the
#    availability attack they are.
#
# 3. ITS ENUMERATION HALF DEPENDS ON AN APP-CLIENT SETTING IT NEVER CHECKS.
#    `PreventUserExistenceErrors` is set per app client. AWS: when it is active, the password
#    flows "return a NotAuthorizedException with the message Incorrect username or password"
#    where they would otherwise have returned UserNotFoundException - and under SRP a nonexistent
#    user gets a SIMULATED salt, so the two are indistinguishable. The console selects it by
#    default; the API leaves it LEGACY. The clause is therefore live on IaC-created clients and
#    dead on console-created ones, with nothing in the rule to say which.
#
# THERE IS NO PRINCIPAL HERE, AND THAT IS THE WHOLE POINT. AWS on `InitiateAuth`: "Amazon Cognito
# doesn't evaluate AWS Identity and Access Management (IAM) policies in requests for this API
# operation. For this operation, you can't use IAM credentials to authorize requests, and you
# can't grant IAM permissions in policies." The events are still CloudTrail MANAGEMENT events,
# logged by default with eventType AwsApiCall - but `userIdentity` degrades to an accountId or
# `{"type": "Unknown"}`, so `sourceIPAddress` is the only actor identifier that exists. An IAM
# deny is a no-op against this technique; AWS WAF is the control, and its documented scope is
# "public API operations - requests from your app to the Amazon Cognito API that don't use AWS
# credentials to authorize", naming InitiateAuth, RespondToAuthChallenge and GetUser. The
# IAM-authorized sibling in
# ../../cognito.credential-access.multiple-failed-administrative-authentication-attempts/ is the
# exact inverse on both counts, which is why the two are separate use cases.
#
# THE BLIND SPOT THAT SWALLOWS MOST REAL TRAFFIC. Managed login and the classic hosted UI do not
# produce InitiateAuth. They produce their own event names with eventType AwsServiceEvent -
# login_POST, login_continue_POST, selectChallenge_POST, mfa_totp_POST; Login_GET,
# CognitoAuthentication, Token_POST - and nothing in this file or in the source rule sees them.
# For a consumer-facing pool that is where the users are. Cover it with a rule keyed on those
# event names and with AWS WAF, which does inspect the managed-login endpoints.
title: Cognito user authentication failing repeatedly from one source address
id: 31633bf9-a467-4d9b-9930-5f1002be233e
name: cognito_user_auth_failure_burst
status: experimental
description: >-
  Fifteen or more failed user-pool authentications inside ten minutes from a single source
  address, counted across both halves of every authentication flow and including the lockout
  form. There is no calling principal on this API, so the address is the only actor identifier
  the event carries.
references:
  - https://attack.mitre.org/techniques/T1110/003/  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1110/004/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognito/latest/developerguide/authentication.html  # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1110.003
  - attack.t1110.004
correlation:
  type: event_count
  rules:
    - cognito_user_auth_failure_bb
  group-by:
    - sourceIPAddress
  timespan: 10m
  condition:
    gte: 15
falsepositives:
  - >-
    A corporate NAT gateway or mobile carrier CGNAT egress, behind which hundreds of unrelated
    users share one address. This is the dominant false positive for any source-IP threshold on a
    consumer-facing pool, and it cannot be tuned away by raising the number - allowlist the known
    egress ranges, or the rule will be muted within a week.
  - >-
    A mobile client with a stale refresh token retrying in a tight loop after a password change.
level: high
---
# Threshold basis - fifteen in ten minutes, inherited from the source and now REACHABLE, which it
# was not before. The base rule below counts the lockout form as a failure, so a sustained attack
# on one account no longer stalls at five counted events. `gte`, never `gt` (F6).
#
# Re-baseline before deploying. On a consumer-facing pool fronted by carrier NAT, fifteen
# failures from one address in ten minutes is ordinary and the rule will drown; raise the number
# AND allowlist known egress, rather than muting it. On an internal pool with a few hundred users
# it is already high. The number is a tuning parameter with no observed baseline behind it -
# derive yours from your own SignInSuccesses SampleCount-minus-Sum series.
title: Cognito user authentication failed
id: 360534cc-ba5e-4aa9-a268-e458d3e077b9
name: cognito_user_auth_failure_bb
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. Matches both halves of every
  authentication flow, because the password is verified on InitiateAuth only for
  USER_PASSWORD_AUTH and on RespondToAuthChallenge for USER_SRP_AUTH, CUSTOM_AUTH and the
  PASSWORD challenge of USER_AUTH.
references:
  - https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-managing-errors.html  # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1110.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-idp.amazonaws.com'
    eventName:
      - 'InitiateAuth'
      - 'RespondToAuthChallenge'
  # UserNotConfirmedException is a failed authentication that also proves the account EXISTS.
  # UserNotFoundException survives only where PreventUserExistenceErrors is LEGACY.
  auth_failure:
    errorCode:
      - 'NotAuthorizedException'
      - 'UserNotFoundException'
      - 'UserNotConfirmedException'
  # A sibling block, OR-ed - never a second key inside auth_failure, which would AND it against
  # errorCode and match nothing (B4). AWS documents the lockout by its message, not by a code.
  lockout:
    errorMessage|contains: 'Password attempts exceeded'
  condition: selection and (auth_failure or lockout)
level: low
---
title: Cognito user authentication succeeded
id: 341aa563-4696-45cd-816c-5359d69af49c
name: cognito_user_auth_success_bb
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. Carries the success filter so a
  failed call cannot compose into the critical correlation below (D-f).
references:
  - https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html  # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1110.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-idp.amazonaws.com'
    eventName:
      - 'InitiateAuth'
      - 'RespondToAuthChallenge'
  success:
    errorCode: null
  condition: selection and success
level: low
---
# Failures then a success from the same address is the only shape here that says the attack
# WORKED. Fifteen minutes spans the documented lockout ceiling of "approximately 15 minutes", so
# a success arriving inside it is the same run resuming after waiting out a doubling interval.
#
# TWO LIMITATIONS, stated so a hit is not over-read. First, this cannot require the success to be
# on the same ACCOUNT as the failures: CloudTrail records the target as `sub` and Sigma cannot
# join across events on a field value. Second, and specific to this use case, `sourceIPAddress`
# is a weak grouping key - behind a NAT egress the failures and the success may be entirely
# unrelated people. Confirm the sub before treating a hit as a compromise; the KQL reports the
# sub sets so the analyst can intersect them.
title: Cognito user authentication failures followed by a success from the same address
id: 50fffaf0-2554-4061-99be-433619236049
status: experimental
description: >-
  A source address that was failing user-pool authentication then succeeded within fifteen
  minutes. If the successful call names a sub the run was failing against, a password has been
  guessed or replayed and ID, access and refresh tokens are already issued for that account.
references:
  - https://attack.mitre.org/techniques/T1110/004/  # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1110.004
correlation:
  type: temporal_ordered
  rules:
    - cognito_user_auth_failure_bb
    - cognito_user_auth_success_bb
  group-by:
    - sourceIPAddress
  timespan: 15m
level: critical
---
title: Cognito account lockout reached
id: fb65657b-2ad9-4bae-aef9-f4a5e8bf2d2b
name: cognito_user_auth_lockout_bb
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. AWS documents the exception by
  its message rather than by a distinct errorCode, so this matches errorMessage.
references:
  - https://docs.aws.amazon.com/cognito/latest/developerguide/authentication.html  # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1110.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-idp.amazonaws.com'
    eventName:
      - 'InitiateAuth'
      - 'RespondToAuthChallenge'
  lockout:
    errorMessage|contains: 'Password attempts exceeded'
  condition: selection and lockout
level: low
---
# The availability attack the source rule cannot express at all. Because AWS's lockout counter is
# shared - "regardless of whether those are requested with unauthenticated or IAM-authorized API
# operations" - an actor who simply fails five times against each of a list of usernames holds
# every one of those accounts in a doubling lockout without ever guessing a password. There is no
# successful sign-in to detect, no data touched, and the symptom reaching the business is a
# support queue full of people who cannot log in.
#
# Ten in ten minutes is set at twice the lockout entry count, deliberately low: a legitimate user
# reaching this state produces a handful of lockout events, not ten, and the events only exist at
# all once someone has already crossed five failures.
title: Cognito accounts held in lockout from one source address
id: f171540f-8580-4ffb-a2fe-29d5ba7487e3
status: experimental
description: >-
  Ten or more Password-attempts-exceeded responses inside ten minutes from one source address.
  Accounts are being kept in AWS's exponential lockout, which is an availability attack on the
  user base whether or not any password is ever guessed.
references:
  - https://attack.mitre.org/techniques/T1110/003/  # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1110.003
correlation:
  type: event_count
  rules:
    - cognito_user_auth_lockout_bb
  group-by:
    - sourceIPAddress
  timespan: 10m
  condition:
    gte: 10
level: high
```

The correlation cannot count distinct accounts — Sigma has no distinct-value count usable over
this group — so it cannot tell guessing from spraying, and it cannot require that a following
success names the same `sub` as the failures. `detections/kql_t1110_003.kql` does both, allowlists
known egress by CIDR, and keeps WAF blocks and RPS throttles out of the failure count.

---

### Key Investigation Queries

> Cognito user pools are regional — run these in the pool's Region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: which address attacked which accounts, in which flow, and did any succeed

```bash
REGION="us-east-1"
RAW=$(for EV in InitiateAuth RespondToAuthChallenge; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong Region, or"
  echo "    missing cloudtrail:LookupEvents. This is NOT 'no authentication was attempted'."
else
  # requestParameters shape for cognito-idp management events is UNVERIFIED - AWS publishes no
  # example. Every field is read with // fallbacks and NOTHING is filtered on a request field.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "cognito-idp.amazonaws.com") |
    {time: .eventTime, event: .eventName, ip: .sourceIPAddress, agent: .userAgent,
     identity_type: (.userIdentity.type // "absent"),
     user_pool_id: (.requestParameters.userPoolId // .requestParameters.UserPoolId // "unknown"),
     client_id: (.requestParameters.clientId // .requestParameters.ClientId // "unknown"),
     auth_flow: (.requestParameters.authFlow // .requestParameters.AuthFlow // "unknown"),
     target_sub: (.requestParameters.userSub // .requestParameters.sub // "unknown"),
     error: (.errorCode // "SUCCESS"), message: (.errorMessage // "")} |
    . + {outcome: (if .error == "SUCCESS" then "SUCCESS"
                   elif (.message | test("Password attempts exceeded")) then "LOCKED_OUT"
                   elif .error == "ForbiddenException" then "WAF_BLOCKED"
                   elif .error == "TooManyRequestsException" then "ACCOUNT_RPS_QUOTA"
                   elif .error == "UserNotFoundException" then "NO_SUCH_USER"
                   elif .error == "UserNotConfirmedException" then "USER_EXISTS_UNCONFIRMED"
                   else .error end)}' |
  jq -s 'sort_by(.time)'
fi
```

Count `target_sub` values, not events. **Many events on one sub** is guessing and that account is
already inside AWS's lockout. **One event on each of many subs** is spraying or stuffing, nothing
is locked, and the directory has been mapped. An `auth_flow` of `USER_SRP_AUTH` or `CUSTOM_AUTH`
on an `InitiateAuth` with `outcome` `SUCCESS` is **not** a sign-in — it is the first leg, and the
verdict is on the matching `RespondToAuthChallenge`. `WAF_BLOCKED` and `ACCOUNT_RPS_QUOTA` are not
authentication failures and must be excluded from the count: AWS states WAF-blocked requests *"do
not count towards the request rate quota"* and never reach the authentication path. If
`target_sub` is `unknown` throughout, the field is not in your trail's `requestParameters` and the
shape question cannot be answered from CloudTrail — say so rather than assuming one account.

#### Query 2 — Resolve the accounts, and read what CloudTrail does not carry

```bash
REGION="us-east-1"
POOL="<user-pool-id-from-Query-1>"
TARGET_SUBS="<space-separated-target-sub-values-from-Query-1>"

for S in $TARGET_SUBS; do
  U=$(aws cognito-idp list-users --user-pool-id "$POOL" --region "$REGION" \
        --filter "sub = \"$S\"" --output json 2>&1)
  case "$U" in
    *Users*) NAME=$(printf '%s' "$U" | jq -r '.Users[0].Username // empty')
             STAT=$(printf '%s' "$U" | jq -r '.Users[0].UserStatus // empty')
             if [ -z "$NAME" ]; then
               echo "[i] $S : NO SUCH USER - the attempt named an account that does not exist"
             else
               echo "[OK] $S : $NAME  status=$STAT"
             fi;;
    *)       echo "[!] INCONCLUSIVE - list-users failed for $S: $U";;
  esac
done

# Is a WAF web ACL actually associated with this pool? This is the containment lever, and its
# ABSENCE is the most common reason the incident is still running. The user pool ARN form is
# arn:aws:cognito-idp:REGION:ACCOUNT:userpool/POOL_ID, and the scope is REGIONAL.
ACCT=$(aws sts get-caller-identity --query Account --output text)
POOL_ARN="arn:aws:cognito-idp:${REGION}:${ACCT}:userpool/${POOL}"
W=$(aws wafv2 get-web-acl-for-resource --resource-arn "$POOL_ARN" --scope REGIONAL \
      --region "$REGION" --output json 2>&1)
case "$W" in
  *WAFNonexistentItemException*|*'"WebACL": null'*)
    echo "[FAIL] no WAF web ACL is associated with $POOL - the only preventative control that"
    echo "       reaches InitiateAuth is absent. Containment Step 1 has to create one.";;
  *WebACL*)
    printf '%s' "$W" | jq -r '"[OK] web ACL " + .WebACL.Name + " (" + .WebACL.Id + ") is associated"';;
  *) echo "[!] INCONCLUSIVE - get-web-acl-for-resource failed: $W";;
esac
```

Resolve every sub before touching an account: `admin-user-global-sign-out` and
`admin-reset-user-password` both take a username, and running them against the wrong account is a
self-inflicted outage. The WAF branch is deliberately three-way — an absent association is a
`[FAIL]` that changes the containment plan, and a failed call is an unknown, never a clean result.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="InitiateAuth NotAuthorizedException RespondToAuthChallenge UserNotConfirmedException UserNotFoundException"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "cognito-idp.amazonaws.com") |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'group_by(.caller) | map({caller: .[0].caller, calls: length,
                                       events: (map(.event) | unique),
                                       keys: (map(.access_key) | unique),
                                       first: (map(.time) | min), last: (map(.time) | max)})
             | sort_by(-.calls)'
```

The alerting event named one resource; this asks whether the same principal did the same thing
elsewhere, and whether anyone else did it too. Group by caller rather than by resource: the
question the eradication phase needs answered is *how much of this is one actor's work*, and a
per-resource list cannot say. `access_key` is emitted here because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` regardless of whether it happened — see the caveat in the preamble.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-3>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique),
                               errors: (map(.error) | unique),
                               ips: (map(.ip) | unique | .[0:5])})'
```

Keyed on the access key rather than the ARN, because one credential is used across many
sessions and the key is what identifies the credential. The per-service grouping answers the
question this playbook cannot: whether this technique was the objective or one stop on a tour.
A service in that list with no business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID — so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Block the traffic **before** resetting any account. A password reset while the run is still going
sends the user an email the attacker may also be racing for, and it destroys the evidence of
which password was guessed. There is **no principal to contain** here — AWS does not evaluate IAM
for `InitiateAuth`, so an IAM deny, a session revocation and an access-key disable are all
no-ops. The address and the app client are what stand in for one.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Block the source at AWS WAF, which is the only lever that reaches this API

```bash
REGION="us-east-1"; POOL="<user-pool-id-from-Query-1>"
SUSPECT_IPS="<space-separated-ip-from-Query-1>"
IPSET_NAME="cognito-incident-block"
ACCT=$(aws sts get-caller-identity --query Account --output text)
POOL_ARN="arn:aws:cognito-idp:${REGION}:${ACCT}:userpool/${POOL}"

ADDRS=""
for IP in $SUSPECT_IPS; do ADDRS="$ADDRS ${IP}/32"; done

# The IP set carries the block list; a rule referencing it, plus a rate-based rule, goes in the
# web ACL. Both halves matter: the IP set stops this run, the rate-based rule stops the next one
# from a different address.
OUT=$(aws wafv2 create-ip-set --name "$IPSET_NAME" --scope REGIONAL --region "$REGION" \
        --ip-address-version IPV4 --addresses $ADDRS --output json 2>&1)
case "$OUT" in
  *WAFDuplicateItemException*)
    echo "[i] IP set $IPSET_NAME already exists - update it with wafv2 update-ip-set, passing the"
    echo "    current LockToken from wafv2 get-ip-set. Do not create a second one.";;
  *Summary*|*ARN*) echo "[OK] IP set created: $(printf '%s' "$OUT" | jq -r '.Summary.ARN')";;
  *) echo "[!] INCONCLUSIVE - create-ip-set failed: $OUT";;
esac

# Associate the web ACL with the pool if Query 2 reported none. Cognito has no API for this - the
# association is made from WAF's side, and the scope is REGIONAL.
WEBACL_ARN="<web-acl-arn-containing-the-ip-set-rule-and-a-rate-based-rule>"
A=$(aws wafv2 associate-web-acl --web-acl-arn "$WEBACL_ARN" --resource-arn "$POOL_ARN" \
      --region "$REGION" --output json 2>&1)
case "$A" in
  "") echo "[OK] web ACL associated with $POOL - blocked requests will now return ForbiddenException";;
  *WAFUnavailableEntityException*) echo "[!] the web ACL or the pool was not found - check both ARNs";;
  *) echo "[i] associate-web-acl returned: $A";;
esac
```

#### Step 2 — Contain the accounts, since there is no principal to contain

```bash
REGION="us-east-1"; POOL="<user-pool-id-from-Query-1>"
# Usernames RESOLVED in Query 2, not raw subs - the admin APIs take a username and a wrong one is
# an outage. Quote the placeholder into a variable first: a bare <...> in a for-list is a shell
# syntax error (D5).
COMPROMISED="<space-separated-usernames-resolved-in-Query-2-with-a-SUCCESS-in-Query-1>"
for U in $COMPROMISED; do
  # Sign-out FIRST. It revokes the refresh tokens the successful attempt already minted, which
  # outlive the password and are not touched by a reset.
  S=$(aws cognito-idp admin-user-global-sign-out --user-pool-id "$POOL" --username "$U" \
        --region "$REGION" --output json 2>&1)
  case "$S" in
    "") echo "[OK] $U : all tokens revoked";;
    *UserNotFoundException*) echo "[!] $U : no such user - the sub was resolved wrongly, re-check Query 2";;
    *) echo "[!] INCONCLUSIVE - global sign-out failed for $U: $S";;
  esac
  # Then the reset, in that order. A reset first would leave live refresh tokens against a
  # password that no longer exists.
  R=$(aws cognito-idp admin-reset-user-password --user-pool-id "$POOL" --username "$U" \
        --region "$REGION" --output json 2>&1)
  case "$R" in
    "") echo "[OK] $U : password reset required at next sign-in";;
    *) echo "[!] INCONCLUSIVE - admin-reset-user-password failed for $U: $R";;
  esac
done
```

---

## 4. Eradication

### Remove Attacker Access

- **Reset every account with a success in Query 1, and every account whose `sub` appears more than
  five times** — the latter are inside AWS's lockout and their password space has been materially
  explored, whether or not the trail shows a success. Sign-out precedes reset, always: tokens
  outlive passwords.
- **Keep the rate-based WAF rule after the IP block comes off.** Blocking one address ends this
  run and nothing else; a rate-based rule is what makes the next address unprofitable. Two
  documented limits to design around: WAF *"can't configure web ACL rules to match on personally
  identifiable information… usernames, passwords"*, so a per-username rate limit is not available,
  and `AWSManagedRulesATPRuleSet` cannot be used with a user pool.
- **Set `PreventUserExistenceErrors` to `ENABLED`** on every app client. The API leaves it
  `LEGACY`, so every IaC-provisioned client is a user-existence oracle. **`UpdateUserPoolClient`
  is a full replacement** — AWS: *"If you don't provide a value for an attribute, Amazon Cognito
  sets it to its default value"* — so read the client with `describe-user-pool-client` and resend
  the whole object, or the call will reset `ExplicitAuthFlows`, the callback URLs and the token
  validities as collateral.
- **Remove `ALLOW_USER_PASSWORD_AUTH` where the client does not need it.** It is the only flow
  that puts a plaintext password in the `InitiateAuth` call; SRP does not.
- **Turn on threat protection** if the pool is on, or can move to, the Plus feature plan. It is
  the only source that ties an attempt to a username, a device, a city and a risk decision, and it
  retains that history for two years. Know its limits before relying on it: it *"doesn't apply
  rate limits"*, cannot be used with federated sign-in, and *"doesn't have access to passwords in
  `USER_SRP_AUTH` sign-in"*, so its compromised-credentials check is blind on the default flow.
- **Ship the managed-login rule.** Everything above covers the API path only. Until a rule keyed
  on `login_POST`, `Login_GET`, `Token_POST` and their siblings exists, the hosted-UI half of the
  attack surface has no detection at all.

---

## 5. Recovery

### Restore Clean State

#### Verify the web ACL is attached, the enumeration oracle is closed, and nothing succeeded after the block

```bash
REGION="us-east-1"; POOL="<user-pool-id-from-Query-1>"
CLIENT="<client-id-from-Query-1>"; SUSPECT_IP="<ip-from-Query-1>"
CUTOFF="<iso8601-containment-time-from-Section-3>"
ACCT=$(aws sts get-caller-identity --query Account --output text)
POOL_ARN="arn:aws:cognito-idp:${REGION}:${ACCT}:userpool/${POOL}"

W=$(aws wafv2 get-web-acl-for-resource --resource-arn "$POOL_ARN" --scope REGIONAL \
      --region "$REGION" --output json 2>&1)
ACL=$(printf '%s' "$W" | jq -r '.WebACL.Name // empty' 2>/dev/null)

# DescribeUserPoolClient NESTS under UserPoolClient - a flat .PreventUserExistenceErrors is null
# and would certify every pool as clean.
C=$(aws cognito-idp describe-user-pool-client --user-pool-id "$POOL" --client-id "$CLIENT" \
      --region "$REGION" --output json 2>&1)
PUEE=$(printf '%s' "$C" | jq -r '.UserPoolClient.PreventUserExistenceErrors // empty' 2>/dev/null)
FLOWS=$(printf '%s' "$C" | jq -r '.UserPoolClient.ExplicitAuthFlows // empty | join(",")' 2>/dev/null)

# This assertion can still emit a signal after the remediation: the address is blocked at WAF, not
# routed away, so further attempts land as ForbiddenException - events, not silence. Capture the
# raw pages first so a failed lookup cannot collapse into a reassuring zero.
POST=$(for EV in InitiateAuth RespondToAuthChallenge; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$CUTOFF" --region "$REGION" --output json
done)

if [ -z "$C" ] || [ -z "$FLOWS" ]; then
  echo "[!] INCONCLUSIVE - the app client could not be read back. ExplicitAuthFlows is never empty"
  echo "    on a live client, so an empty value means the call failed, not that the client is clean."
elif [ -z "$POST" ]; then
  echo "[!] INCONCLUSIVE - the post-containment lookup returned nothing at all. That is a failed"
  echo "    call or a wrong Region, NOT proof that the source stopped."
else
  SUCC=$(printf '%s' "$POST" | jq -r --arg ip "$SUSPECT_IP" '[.Events[].CloudTrailEvent | fromjson |
           select(.eventSource == "cognito-idp.amazonaws.com") |
           select(.sourceIPAddress == $ip) | select(.errorCode == null)] | length')
  if   [ "${SUCC:-x}" = "x" ]; then
    echo "[!] INCONCLUSIVE - the post-containment events could not be parsed; count unknown, not zero."
  elif [ "$SUCC" -gt 0 ]; then
    echo "[FAIL] $SUSPECT_IP authenticated successfully $SUCC time(s) AFTER $CUTOFF - the block did not hold"
  elif [ -z "$ACL" ]; then
    echo "[FAIL] no WAF web ACL is associated with $POOL - the run stopped, but nothing prevents the next one"
  elif [ "$PUEE" != "ENABLED" ]; then
    echo "[FAIL] client $CLIENT has PreventUserExistenceErrors=$PUEE - the enumeration oracle is still open"
  else
    echo "[OK] web ACL $ACL associated, PreventUserExistenceErrors=$PUEE, flows=$FLOWS, and no"
    echo "     successful authentication from $SUSPECT_IP since $CUTOFF"
  fi
fi
```

Every branch is reachable after the remediation: the pool, the client and the web ACL all still
exist and still answer, so the common partial outcome — the address blocked but the app client
never touched — lands on `[FAIL]` rather than being certified clean.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     fifteen or more events across InitiateAuth AND RespondToAuthChallenge /"
echo "  cognito-idp.amazonaws.com, in ten minutes, from one sourceIPAddress, with errorCode"
echo "  NotAuthorizedException, UserNotFoundException or UserNotConfirmedException, OR"
echo "  errorMessage containing 'Password attempts exceeded'. gte 15, not gt. The lockout"
echo "  correlation must fire at exactly ten lockout events in ten minutes."
echo "MUST NOT fire on: an InitiateAuth that SUCCEEDED as the first leg of USER_SRP_AUTH or"
echo "  CUSTOM_AUTH - the verdict belongs to the matching RespondToAuthChallenge; a"
echo "  ForbiddenException, which is a WAF block that never reached the authentication path;"
echo "  a TooManyRequestsException, which is the 120 RPS UserAuthentication category quota."
echo "EXPECTED FP, by design: a corporate NAT or carrier CGNAT egress with hundreds of real users"
echo "  behind one address. Allowlist those CIDRs - raising the threshold does not fix it and"
echo "  muting the rule takes the P0 correlation with it."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| An anonymous client could attempt unlimited authentications against the directory | No AWS WAF web ACL associated with the user pool — the only preventative control that reaches this API, and it is available in every feature plan |
| The attack ran below the alerting threshold for its whole duration | The rule matched `InitiateAuth` only, and on this pool's default app client every reachable flow fails on `RespondToAuthChallenge`; the lockout form was matched by nothing |
| Accounts that do not exist could be told from accounts that do | The app client was API-created, so `PreventUserExistenceErrors` was left at its `LEGACY` default |
| Nobody could say which named users were targeted, or from where | CloudTrail records `sub` and not `UserName`, and threat protection — the only source carrying the username, device, city and risk decision — was not enabled |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// NOTE WHAT THIS DOES AND DOES NOT DO. It cannot constrain the attacker: InitiateAuth is not
// IAM-authorized, the caller is not an IAM principal, and aws:PrincipalArn is unpopulated - so
// any SCP written against the attacker is unreachable in both directions (D-i). What an SCP CAN
// do is stop your own operators from re-opening the enumeration oracle by accident, because
// UpdateUserPoolClient is a full replacement and a partial call silently resets
// PreventUserExistenceErrors to LEGACY. StringNotLike, because the value is wildcarded.
{
  "Effect": "Deny",
  "Action": ["cognito-idp:UpdateUserPoolClient", "cognito-idp:CreateUserPoolClient"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- The real control is **AWS WAF**, associated with every internet-facing user pool before an
  incident: a rate-based rule, an IP-set rule for incident blocks, and — because WAF also inspects
  the managed-login endpoints — the only coverage that exists for the hosted-UI half of the
  attack surface. Pair it with `PreventUserExistenceErrors: ENABLED` set explicitly rather than
  inherited, `ALLOW_USER_PASSWORD_AUTH` removed where SRP will do, and threat protection in at
  least Audit-only mode where the pool is on the Plus plan. Threat protection's CIDR-based
  **Always block** list is a second lever, with one caveat AWS states directly: requests blocked
  that way *"contribute to the request rate quotas for your user pools"*, where WAF-blocked
  requests do not.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1110.003 — Brute Force: Password Spraying (primary); T1110.004 — Credential Stuffing (secondary, the shape where few attempts hit many accounts and some succeed) |
| Primary API | `cognito-idp:InitiateAuth`, and `cognito-idp:RespondToAuthChallenge` where the flow is SRP, custom, or the `PASSWORD` challenge of `USER_AUTH` |
| Event source | `cognito-idp.amazonaws.com`, **management** plane, on by default, regional. `eventType: AwsApiCall`; managed login and the hosted UI emit `AwsServiceEvent` under entirely different event names and are **not** covered by any rule here |
| Key discriminator | The count of **distinct target accounts** behind the failure volume, not the volume itself. There is no principal: AWS does not evaluate IAM for this API, and `userIdentity` degrades to an `accountId` or `{"type": "Unknown"}` |
| Field shape | **Unverified.** AWS publishes no example CloudTrail event for any `cognito-idp` management operation. The target is a `sub`, never a `UserName`; the `AuthParameters` map is `HIDDEN_DUE_TO_SECURITY_REASONS` |
| "Was it used" pivot | A success on the same `sub` inside the failure window. Corroborate with `AdminListUserAuthEvents` (`EventResponse: Pass`, `MaxResults` ≤ 60, two-year retention) where threat protection is enabled — its absence is an unknown, not a negative |
| Blast radius | Every account in the pool: sprayable, enumerable where `PreventUserExistenceErrors` is `LEGACY`, and lockable for up to ~15 minutes each. A success yields ID, access and refresh tokens that outlive the IP block |
| Error strings | Credential failures: `NotAuthorizedException`, `UserNotFoundException` (`LEGACY` clients only), `UserNotConfirmedException`, and the lockout, documented by its message `Password attempts exceeded`. Existence oracle: `PasswordResetRequiredException`. **Not** failures: `ForbiddenException` (an AWS WAF block — unique to public operations, so it cannot appear on the admin path) and `TooManyRequestsException` (the 120 RPS `UserAuthentication` category quota). Also documented: `InvalidParameterException`, `ResourceNotFoundException`, `OperationNotEnabledException`, `UnsupportedOperationException`, `InvalidUserPoolConfigurationException`, `UserLambdaValidationException`, `UnexpectedLambdaException`, `InvalidLambdaResponseException`, `InvalidEmailRoleAccessPolicyException`, `InvalidSmsRoleAccessPolicyException`, `InvalidSmsRoleTrustRelationshipException`, `InternalErrorException` |

### Residual Risk

Blocking the address ends this run and nothing more: the account list, the password list and the
knowledge of which usernames exist all survive, and the next run comes from somewhere else. Every
token minted by a successful attempt stays valid until `admin-user-global-sign-out` reaches that
specific account — and it reaches only the accounts a `sub` was recorded for, which excludes every
attempt made through managed login. Where `PreventUserExistenceErrors` was `LEGACY`, the
enumeration was exact and permanent; there is no way to un-learn which accounts exist. Every
account driven past five failures spent up to fifteen minutes locked out, and the real users
behind them experienced an authentication outage with no incident record of their own. If the pool
was not on the Plus feature plan there is **no** per-user authentication history at all, and none
can be created retroactively — the attempts the trail recorded as a `sub` can never be tied to a
device, a location or a risk score. And the hosted-UI half of the surface remains uncovered: its
absence from every timeline in this playbook is a property of the event names, not evidence that
nothing happened there.
