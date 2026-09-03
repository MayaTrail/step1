# IR Playbook: Multiple Failed Administrative Authentication Attempts — Server-Side Password Attack on a User Directory via `cognito-idp:AdminInitiateAuth`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential access (an AWS principal repeatedly fails to authenticate user-pool accounts through the IAM-authorized server-side authentication API, guessing passwords, enumerating the directory, or driving accounts into lockout) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High.** The source rates it **P3**, which reads the alert as a noisy volume signal. It is not one. `AdminInitiateAuth` is IAM-authorized — AWS: *"you must use IAM credentials to authorize requests"* — so an anonymous attacker cannot reach it and every event names a real principal. By the time this fires, the account boundary has already been crossed and the user pool attack is the **second** stage; the first stage is whatever gave an unexpected principal `cognito-idp:AdminInitiateAuth`. Failures followed by a success on the same account is **Critical**: tokens have been issued for a guessed account |
| MITRE Tactics | Credential Access (TA0006) |
| MITRE Techniques | T1110.001 (primary), T1078.004 (secondary) — both verified live 2026-08-29 |
| Services in Scope | Cognito user pools, CloudTrail, IAM, STS, CloudWatch (`AWS/Cognito`), Cognito threat protection and `userAuthEvents` log export where the pool is on the Plus feature plan, Organizations (SCP) |

**What the technique does:** the actor holds AWS credentials carrying `cognito-idp:AdminInitiateAuth` and
calls it against a user pool with a username and a candidate password. For
`ADMIN_USER_PASSWORD_AUTH` and the legacy `ADMIN_NO_SRP_AUTH` the password is in that call and a
wrong one returns `NotAuthorizedException` immediately. For `USER_SRP_AUTH`, `CUSTOM_AUTH` and
the `PASSWORD` challenge of `USER_AUTH` the initial call **succeeds** — it only exchanges `SRP_A`
for a salt — and the password is verified on the following `AdminRespondToAuthChallenge`, which
is where the failure lands. After five failed password attempts AWS locks the account out for
`2^(n-5)` seconds to a ceiling of about fifteen minutes, and further attempts return a
`Password attempts exceeded` exception. That lockout counter is shared across the authenticated
and unauthenticated APIs, so a principal holding this permission can lock every account in the
directory out without ever authenticating. A success returns real user pool tokens — ID, access
and refresh — for that user, and the refresh token outlives the containment of the AWS
credential that obtained it.

**Detection thesis.** The discriminator is **which principal is allowed to authenticate users at
all**: `AdminInitiateAuth` requires AWS credentials, so in most accounts exactly one backend role
has any business calling it, and the calling ARN separates a stale service credential from an
attack. The source rule groups by that ARN but never asks whether the ARN belongs there — and it
watches only the `AdminInitiateAuth` half of a flow whose password failure lands on
`AdminRespondToAuthChallenge` for every authentication flow a default app client actually
supports.

> The unauthenticated counterpart is
> `../cognito.credential-access.multiple-failed-authentication-attempts-from-single-source/`.
> Same technique, different API, and — because `InitiateAuth` is explicitly not IAM-authorized —
> **no containment lever in common**. The two are deliberately separate use cases; the reasoning
> is in `_source/PROVENANCE.md`.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing Cognito user pool **management** events. AWS: *"Amazon Cognito logs user pool events to CloudTrail as management events"* — on by default, no data-event selector needed. `eventSource` is `cognito-idp.amazonaws.com` and API calls carry `eventType: AwsApiCall`
- **AWS publishes no example CloudTrail event for any `cognito-idp` management operation**, so the exact `requestParameters` shape for `AdminInitiateAuth` — whether `authFlow`, `userPoolId` and `clientId` are present, and in what casing — is **unverified**. Generate one call in a test pool and read your own trail before building any rule that filters on a request field
- The target account is a **`sub`, never a username**. AWS: *"Amazon Cognito records `UserSub` but not `UserName` in CloudTrail logs for requests that are specific to a user."* Private fields are obscured with the literal `HIDDEN_DUE_TO_SECURITY_REASONS`, which covers the `AuthParameters` map holding `USERNAME`, `PASSWORD` and `SRP_A`
- **Managed login and the classic hosted UI produce different event names entirely** — `login_POST`, `selectChallenge_POST`, `Login_GET`, `CognitoAuthentication`, `Token_POST` — with `eventType: AwsServiceEvent`. Nothing in this playbook sees a browser-driven brute force
- `AWS/Cognito` CloudWatch metrics `SignInSuccesses` and `SignInThrottles`, per `UserPool` and `UserPoolClient`. **There is no failure metric**: AWS documents the derivation as `SampleCount` minus `Sum` on `SignInSuccesses`, and throttled requests count as unsuccessful. Metrics with no datapoints for two weeks vanish from `list-metrics` — use `get-metric-data`
- Where the pool is on the **Plus** feature plan, Cognito **threat protection** (formerly advanced security features) in at least Audit-only mode, and `userAuthEvents` log export to CloudWatch Logs, S3 or Firehose. That export is the only source carrying `userName`, `clientId` and `requestId` alongside the risk decision; it is `INFO`-level only, so throttling errors are **not** in it, and AWS states delivery is best effort
- A baseline of which principals legitimately call `AdminInitiateAuth`, and which app clients have `ALLOW_ADMIN_USER_PASSWORD_AUTH` in `ExplicitAuthFlows` at all

**Alerting (must be pre-configured)**
- **Admin authentication failures by one principal followed by a success from that principal within 15 minutes → P0**
- **Five or more admin authentication failures in ten minutes from one principal and source address → P1**
- **`AdminInitiateAuth` or `AdminRespondToAuthChallenge` by a principal outside the server-side-authentication allowlist, any outcome → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Admin authentication failures by one principal followed by a success from that principal within 15 minutes, on the same `sub` | CloudTrail (management) | T1110.001 |
| P1 | Five or more admin authentication failures in ten minutes from one principal and source address | CloudTrail (management) | T1110.001 |
| P1 | `AdminInitiateAuth` or `AdminRespondToAuthChallenge` by a principal outside the server-side-authentication allowlist, any outcome | CloudTrail (management) | T1078.004 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `errorMessage` containing `Password attempts exceeded` — accounts already driven into AWS's documented lockout | CloudTrail (management) | T1110.001 |
| P2 | `AccessDeniedException` on `AdminInitiateAuth` — a principal probing whether it holds the permission. Reconnaissance, not a credential failure | CloudTrail (management) | T1078.004 |
| P3 | A burst of `UserNotConfirmedException` or `PasswordResetRequiredException` — a positive user-existence oracle that survives `PreventUserExistenceErrors` | CloudTrail (management) | T1110.001 |
| P3 | `SignInSuccesses` `SampleCount` far exceeding its `Sum` for one app client | CloudWatch `AWS/Cognito` | T1110.001 |

### Detection Rule Quality Notes

The source rule watches one event of a two-event flow, and on a default app client the failure
it is looking for lands on the other one.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Matches `AdminInitiateAuth` only, while listing `USER_SRP_AUTH` and `CUSTOM_AUTH` in its `authFlow` clause | In SRP and custom flows the initial call **succeeds** and the password is verified on `AdminRespondToAuthChallenge`. AWS documents an app client with no `ExplicitAuthFlows` as supporting `ALLOW_REFRESH_TOKEN_AUTH`, `ALLOW_USER_SRP_AUTH` and `ALLOW_CUSTOM_AUTH` — so on a **default** app client the only reachable flows are exactly the two the rule cannot see the failure for, and it returns zero forever | Match `AdminInitiateAuth` **and** `AdminRespondToAuthChallenge` |
| `errorCode:("NotAuthorizedException" OR "UserNotFoundException")` is not the failure set | `UserNotFoundException` is suppressed into `NotAuthorizedException` on every app client with `PreventUserExistenceErrors` active — the console's default, though the API's default is `LEGACY` — so half the clause is dead on half the pools and the rule cannot say which. And after five failures AWS returns `Password attempts exceeded`, matched by neither code, so a sustained run against one account undercounts and may never reach the threshold | Add `UserNotConfirmedException`, and OR a sibling block on `errorMessage|contains: 'Password attempts exceeded'` |
| No principal allowlist | `AdminInitiateAuth` cannot be called without AWS credentials, so the calling ARN is the single most informative field on the event — and it is used only as a group-by key, never as a filter. A backend with a stale password and an attacker with stolen credentials produce identical alerts | Alert on the first call by any principal outside the server-side-auth allowlist, without waiting for a threshold |
| Grouped by `(source IP, principal)`; the target account is never counted | Five attempts against one account (guessing — that account is now locked out) and one attempt against each of five accounts (spraying — nothing is locked out, the directory has been mapped) are the same alert and need different responses | Count distinct `sub` in the window; the KQL does this and states which shape it found |
| Denials of the API itself are excluded by the `errorCode` clause | A principal probing whether it holds `cognito-idp:AdminInitiateAuth` produces `AccessDeniedException` — the strongest single indication that the caller does not belong — and the rule filters it out | Keep denials in their own trigger row and their own KQL column; never count them as credential failures |
| P3 priority | An alert whose precondition is "an AWS principal is doing something it should not" is triaged alongside volume noise | P1 for the volume case, P0 for failures-then-success |

**Recommended detection — repeated server-side authentication failures from one AWS principal.**

```yaml
# Failed Administrative Authentication Attempts (T1110.001 / T1078.004)
#
# WHAT THE ORIGINAL RULE GOT WRONG, AND WHY IT RETURNS ZERO ON A DEFAULT USER POOL.
# The source rule matches `AdminInitiateAuth` with an errorCode of NotAuthorizedException or
# UserNotFoundException and an authFlow in
# (ADMIN_USER_PASSWORD_AUTH, ADMIN_NO_SRP_AUTH, USER_SRP_AUTH, CUSTOM_AUTH). Two of those four
# flows cannot produce a PASSWORD failure on that event at all. In USER_SRP_AUTH the initial
# call only exchanges SRP_A for a salt and SRP_B - it SUCCEEDS - and the password claim is
# verified in the following `AdminRespondToAuthChallenge`, which is where AWS documents the
# "generic NotAuthorizedException". CUSTOM_AUTH is the same shape: the challenge is answered on
# the Respond call. So for those two flows the rule sees a success and a failure it never looks
# at. The same is true of the PASSWORD challenge inside USER_AUTH, which the rule omits
# entirely.
#
# That is not a corner case, it is the default. AWS: if `ExplicitAuthFlows` is not specified,
# an app client supports ALLOW_REFRESH_TOKEN_AUTH, ALLOW_USER_SRP_AUTH and ALLOW_CUSTOM_AUTH -
# and nothing else. ADMIN_USER_PASSWORD_AUTH must be turned on deliberately. On a default app
# client the only reachable flows are exactly the two whose password failures land on the
# Respond call, so the source rule is structurally dead. The rules below match BOTH halves of
# every flow: `AdminInitiateAuth` and `AdminRespondToAuthChallenge`.
#
# THE SECOND SUPPRESSION. `PreventUserExistenceErrors` is an APP CLIENT setting, and AWS
# documents that when it is active the password flows return `NotAuthorizedException` with the
# message "Incorrect username or password" where they would otherwise have returned
# `UserNotFoundException`. The console selects it by default; the API leaves it `LEGACY`. So
# the source rule's UserNotFoundException clause is live on IaC-created clients and dead on
# console-created ones, and nothing in the rule reveals which. Enumeration coverage therefore
# cannot rest on that code - it rests on volume and on distinct usernames.
#
# THE THIRD THING NEITHER SIDE MATCHES: THE LOCKOUT. AWS documents that after five failed
# password attempts Cognito locks the user out for 2^(n-5) seconds, to a ceiling of about
# fifteen minutes, and that attempts during a lockout "generate a `Password attempts exceeded`
# exception". The counter is shared: "regardless of whether those are requested with
# unauthenticated or IAM-authorized API operations". A sustained run against ONE account
# therefore stops producing NotAuthorizedException and starts producing the lockout form, so a
# rule matching only the two codes undercounts a real attack and can miss the threshold. The
# lockout is matched here as a sibling block on `errorMessage`.
#
# FIELD SHAPE, AND WHAT CANNOT BE PIVOTED ON. `cognito-idp` API operations are CloudTrail
# MANAGEMENT events, on by default, with `eventType: AwsApiCall`. `AdminInitiateAuth` is
# IAM-authorized - AWS: "you must use IAM credentials to authorize requests" - so every event
# carries a real `userIdentity.arn`, which is the opposite of its unauthenticated sibling in
# ../../cognito.credential-access.multiple-failed-authentication-attempts-from-single-source/.
# But AWS also states it "records UserSub but not UserName in CloudTrail logs for requests that
# are specific to a user", and obscures private fields with the literal string
# HIDDEN_DUE_TO_SECURITY_REASONS. The targeted account is therefore identified by `sub`, not by
# username, and the AuthParameters map carrying USERNAME and PASSWORD is redaction-class. AWS
# publishes no example CloudTrail event for any cognito-idp management operation, so the exact
# `requestParameters` shape is UNVERIFIED - do not gate a rule on
# `requestParameters.authFlow` until you have confirmed it in your own trail.
title: Repeated Cognito administrative authentication failures from one principal
id: 4fbcd659-ca99-44ee-b541-4bc897a344fa
name: cognito_admin_auth_failure_burst
status: experimental
description: >-
  One AWS principal produced five or more failed server-side user-pool authentications inside
  ten minutes from one source address. The caller already holds AWS credentials carrying
  cognito-idp:AdminInitiateAuth, so this is not an anonymous internet brute force - it is an
  in-account principal guessing or spraying passwords against the user directory.
references:
  - https://attack.mitre.org/techniques/T1110/001/  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1078/004/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognito/latest/developerguide/authentication.html  # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1110.001
  - attack.initial-access
  - attack.t1078.004
correlation:
  type: event_count
  rules:
    - cognito_admin_auth_failure_bb
  group-by:
    - userIdentity.arn
    - sourceIPAddress
  timespan: 10m
  condition:
    gte: 5
falsepositives:
  - >-
    A backend service holding a stale credential for one service account, retrying in a loop.
    Distinguishable because it repeats against a single sub with an unchanging user agent; a
    guessing run walks distinct subs or distinct passwords. If it is frequent, the finding is
    that a machine identity is authenticating as a human user.
level: high
---
# Threshold basis - five in ten minutes, inherited from the source and defensible for a reason
# the source does not state. AWS locks an account out after exactly FIVE failed password
# attempts, so five is the point at which a guessing run has already changed the state of a
# real user's account. `gte`, never `gt`: a run that stops at exactly five must not fall
# through the rule it was designed to catch (F6).
#
# Ten minutes is retained as the window because it spans the documented lockout ceiling of
# "approximately 15 minutes" poorly but the ATTACK's own cadence well - a scripted run makes
# five calls in seconds. Re-baseline against your own account: if a backend service legitimately
# produces five auth failures in ten minutes, raise the threshold rather than muting the rule,
# and record which principal it was in the allowlist that rule 3 below uses.
title: Cognito administrative authentication failed
id: e8de9471-e5ce-4861-a7cc-7770e3f155ee
name: cognito_admin_auth_failure_bb
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. Matches both halves of every
  admin auth flow, because the password is verified on AdminInitiateAuth for the
  ADMIN_USER_PASSWORD_AUTH and ADMIN_NO_SRP_AUTH flows and on AdminRespondToAuthChallenge for
  USER_SRP_AUTH, CUSTOM_AUTH and the PASSWORD challenge of USER_AUTH.
references:
  - https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRespondToAuthChallenge.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-managing-errors.html  # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1110.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-idp.amazonaws.com'
    eventName:
      - 'AdminInitiateAuth'
      - 'AdminRespondToAuthChallenge'
  # UserNotConfirmedException is a FAILED authentication that also proves the account EXISTS,
  # which is why it is counted here and not treated as noise. UserNotFoundException survives
  # only on app clients where PreventUserExistenceErrors is LEGACY.
  auth_failure:
    errorCode:
      - 'NotAuthorizedException'
      - 'UserNotFoundException'
      - 'UserNotConfirmedException'
  # The lockout form. AWS documents the exception by its message rather than by a distinct
  # code, so this is a sibling block on errorMessage OR-ed into the condition - never a second
  # key inside `auth_failure`, which would AND it and match nothing (B4).
  lockout:
    errorMessage|contains: 'Password attempts exceeded'
  condition: selection and (auth_failure or lockout)
level: low
---
title: Cognito administrative authentication succeeded
id: 787d4b71-57cc-484f-b958-4d8126d79b1f
name: cognito_admin_auth_success_bb
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. Carries the success filter so a
  denied or failed call cannot compose into the critical correlation below (D-f).
references:
  - https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html  # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1110.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-idp.amazonaws.com'
    eventName:
      - 'AdminInitiateAuth'
      - 'AdminRespondToAuthChallenge'
  success:
    errorCode: null
  condition: selection and success
level: low
---
# Failures then a success is the only shape in this file that says the brute force WORKED.
# Fifteen minutes is chosen against the lockout curve rather than arbitrarily: a run that has
# tripped the lockout waits out a doubling interval capped at about fifteen minutes, so a
# success arriving inside that span is the same run resuming, and one arriving much later is a
# separate session.
#
# LIMITATION, stated so nobody reads more into a hit than is there. The correlation groups by
# `userIdentity.arn` and CANNOT require that the success is against the SAME user account as
# the failures - CloudTrail records the target as `sub`, not username, and Sigma has no
# cross-event field join. A backend legitimately signing in user B seconds after failing on
# user A will match. Confirm the sub is the same before treating a hit as a confirmed
# compromise; the KQL reports the sub set so the analyst can do exactly that.
title: Cognito administrative authentication failures followed by a success
id: 747d52c1-f007-4324-a932-3affc943cbe8
status: experimental
description: >-
  One AWS principal failed server-side user-pool authentication repeatedly and then succeeded
  within fifteen minutes. If the successful call names the same sub as the failures, a user
  pool account password has been guessed and the tokens it returned are already issued.
references:
  - https://attack.mitre.org/techniques/T1110/001/  # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1110.001
correlation:
  type: temporal_ordered
  rules:
    - cognito_admin_auth_failure_bb
    - cognito_admin_auth_success_bb
  group-by:
    - userIdentity.arn
  timespan: 15m
level: critical
---
# The correction the source rule omits entirely: WHO is allowed to authenticate users
# server-side. AdminInitiateAuth is IAM-authorized, so unlike its unauthenticated sibling every
# event names a principal - and in most accounts exactly one backend role has any business
# calling it. This rule fires on the FIRST call by anyone else, success or failure, without
# waiting for a threshold.
#
# POPULATE BEFORE DEPLOYING. Unpopulated, `backend_auth_principals` matches nothing and this
# fires on every legitimate server-side sign-in. That is the safe failure direction - noisy
# toward surfacing - but it is still a rule you must tune before it is useful.
title: Cognito administrative authentication by a principal outside the server-side auth allowlist
id: 09b1b215-39e7-4e9b-af7b-ae6e78f3c006
status: experimental
description: >-
  A principal that does not own server-side authentication called AdminInitiateAuth or
  AdminRespondToAuthChallenge. The API returns real user pool tokens, so a principal holding it
  can impersonate any user in the directory without knowing a password only if it also holds a
  valid password - but it can enumerate the directory and drive every account into lockout
  regardless.
references:
  - https://docs.aws.amazon.com/cognito/latest/developerguide/security_iam_service-with-iam.html  # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1110.001
  - attack.initial-access
  - attack.t1078.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-idp.amazonaws.com'
    eventName:
      - 'AdminInitiateAuth'
      - 'AdminRespondToAuthChallenge'
  backend_auth_principals:
    userIdentity.arn|contains:
      - ':role/app-backend-auth'    # replace with this account's server-side auth role
      - ':role/BreakGlassAdmin'     # replace with this account's break-glass role
  condition: selection and not backend_auth_principals
falsepositives:
  - >-
    An engineer testing sign-in from a workstation under a personal role. Should be rare and
    traceable; if it is common, the finding is that user impersonation is not gated on a
    dedicated role.
level: high
```

The correlation cannot tell guessing from spraying — Sigma has no distinct-value count over the
target — and it cannot require that a following success names the **same** account as the
failures, because CloudTrail records the target as a `sub` and Sigma cannot join across events on
a field value. `detections/kql_t1110_001.kql` does both, and keeps IAM denials in a column of
their own so reconnaissance is never counted as a credential failure.

---

### Key Investigation Queries

> Cognito user pools are regional — run these in the pool's Region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: which principal attacked which accounts, in which flow, and did any succeed

```bash
REGION="us-east-1"
RAW=$(for EV in AdminInitiateAuth AdminRespondToAuthChallenge; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong Region, or"
  echo "    missing cloudtrail:LookupEvents. This is NOT 'no authentication was attempted'."
else
  # requestParameters shape for cognito-idp management events is UNVERIFIED - AWS publishes no
  # example. Every field below is read defensively with // fallbacks so a missing key yields
  # "unknown" rather than dropping the record. Nothing is FILTERED on a request field.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "cognito-idp.amazonaws.com") |
    {time: .eventTime, event: .eventName,
     caller_arn: (.userIdentity.arn // "no-arn"),
     access_key: (.userIdentity.accessKeyId // "none"),
     user_pool_id: (.requestParameters.userPoolId // .requestParameters.UserPoolId // "unknown"),
     client_id: (.requestParameters.clientId // .requestParameters.ClientId // "unknown"),
     auth_flow: (.requestParameters.authFlow // .requestParameters.AuthFlow // "unknown"),
     target_sub: (.requestParameters.userSub // .requestParameters.sub // "unknown"),
     ip: .sourceIPAddress, agent: .userAgent,
     error: (.errorCode // "SUCCESS"),
     message: (.errorMessage // "")} |
    . + {outcome: (if .error == "SUCCESS" then "SUCCESS"
                   elif (.message | test("Password attempts exceeded")) then "LOCKED_OUT"
                   elif .error == "AccessDeniedException" then "IAM_DENIED_RECON"
                   elif .error == "UserNotFoundException" then "NO_SUCH_USER"
                   elif .error == "UserNotConfirmedException" then "USER_EXISTS_UNCONFIRMED"
                   else .error end)}' |
  jq -s 'sort_by(.time)'
fi
```

Read it three ways. **Shape:** many events on one `target_sub` is guessing and that account is
already inside AWS's `2^(n-5)`-second lockout; one event on each of many subs is spraying and
nothing is locked. **Reachability:** an `auth_flow` of `USER_SRP_AUTH` or `CUSTOM_AUTH` with an
`event` of `AdminInitiateAuth` and `outcome` `SUCCESS` is not a successful sign-in — it is the
first leg, and the verdict is on the matching `AdminRespondToAuthChallenge`. **Boundary:**
`IAM_DENIED_RECON` counts separately from every other outcome; it is a principal mapping its
permissions, not a failed password. Record `caller_arn`, `access_key`, `user_pool_id` and every
`target_sub` as IOCs.

#### Query 2 — Resolve the subs to real accounts, and read the evidence CloudTrail does not carry

```bash
REGION="us-east-1"
POOL="<user-pool-id-from-Query-1>"
TARGET_SUBS="<space-separated-target-sub-values-from-Query-1>"

for S in $TARGET_SUBS; do
  # CloudTrail carries the sub only. list-users with a sub filter is the documented resolution.
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

# Threat protection's own record of the sign-in, which carries what CloudTrail does not: the
# risk decision, the device, the city and country, and Pass/Fail per attempt. It is Plus-plan
# only, so the not-enabled case must reach INCONCLUSIVE rather than reading as "no risk found".
SUB1=$(printf '%s' "$TARGET_SUBS" | awk '{print $1}')
AE=$(aws cognito-idp admin-list-user-auth-events --user-pool-id "$POOL" --region "$REGION" \
       --username "$SUB1" --max-results 60 --output json 2>&1)
case "$AE" in
  *UserPoolAddOnNotEnabledException*)
    echo "[!] INCONCLUSIVE - threat protection is not enabled on $POOL. There is no auth-event"
    echo "    history for this pool and none can be created retroactively.";;
  *AuthEvents*)
    printf '%s' "$AE" | jq -r '.AuthEvents[] |
      {t: .CreationDate, type: .EventType, response: .EventResponse,
       risk: (.EventRisk.RiskLevel // "none"), decision: (.EventRisk.RiskDecision // "none"),
       compromised: (.EventRisk.CompromisedCredentialsDetected // false),
       ip: (.EventContextData.IpAddress // "?"), city: (.EventContextData.City // "?"),
       country: (.EventContextData.Country // "?"), device: (.EventContextData.DeviceName // "?")}';;
  *) echo "[!] INCONCLUSIVE - admin-list-user-auth-events failed: $AE";;
esac
```

An `EventResponse` of `Pass` on an event the CloudTrail timeline shows as part of the failure run
is a successful compromise the trail alone would not have proved. `RiskDecision` of
`AccountTakeover` or `Block`, or `CompromisedCredentialsDetected: true`, escalates immediately.
AWS retains this history for **two years**, and it is the only place the source IP is tied to a
named user rather than to a `sub` — but it exists only where threat protection was already on,
which is why the not-enabled branch above is `INCONCLUSIVE` and not a clean result.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="AdminInitiateAuth AdminRespondToAuthChallenge NotAuthorizedException UserNotConfirmedException UserNotFoundException"
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

Cut the principal off from the user pool **before** revoking its sessions. A session revocation
that lands first leaves a window in which the actor re-fetches credentials and keeps
authenticating, and the deny policy is what makes the re-fetched credential useless. Do not
force-reset the targeted accounts yet — that destroys the ability to confirm which password was
guessed, and §4 does it in the right order.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Deny the principal any further user-pool authentication

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["cognito-idp:AdminInitiateAuth","cognito-idp:AdminRespondToAuthChallenge","cognito-idp:AdminSetUserPassword","cognito-idp:AdminUpdateUserAttributes","cognito-idp:ListUsers"],"Resource":"*"}]}'
case "$SUSPECT_ARN" in
  *:user/*)          U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')     # user ARN: LAST segment
                     aws iam put-user-policy --user-name "$U" \
                       --policy-name "EmergencyDenyCognitoAdminAuth" --policy-document "$DENY"
                     echo "[OK] denied Cognito admin authentication for user $U";;
  *:assumed-role/*)  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')      # role ARN: 2ND segment
                     aws iam put-role-policy --role-name "$R" \
                       --policy-name "EmergencyDenyCognitoAdminAuth" --policy-document "$DENY"
                     echo "[OK] denied Cognito admin authentication for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or a"
     echo "    service principal. Contain manually; neither branch above applies.";;
esac
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done;;
  *:assumed-role/*)
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    # E4: this revokes tokens issued BEFORE the cutoff only. A credential re-fetched after the
    # policy lands carries a newer TokenIssueTime and is NOT denied - which is exactly why
    # Step 1's action deny had to go on first.
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    echo "[OK] revoked pre-$CUTOFF sessions for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - contain manually.";;
esac
```

---

## 4. Eradication

### Remove Attacker Access

- **Revoke the user pool tokens first, because they outlive everything else.** A successful
  `AdminInitiateAuth` returned ID, access and refresh tokens for that account, and none of them
  care that the AWS credential is now denied. `aws cognito-idp admin-user-global-sign-out
  --user-pool-id "$POOL" --username "$NAME"` for every account Query 1 shows a success against —
  the resolved username from Query 2, not the raw sub, so the action is auditable.
- **Then force the password reset**, in that order: `aws cognito-idp admin-reset-user-password`.
  Doing it before the sign-out leaves live refresh tokens against a password that no longer
  exists. Reset every account with a success, and every account whose `sub` appears more than
  five times in Query 1 — those are inside AWS's lockout and their password space has been
  materially explored.
- **Right-size `cognito-idp:AdminInitiateAuth`.** It authenticates as an arbitrary end user and
  no workload needs it except the one that owns server-side sign-in. Remove it from every other
  principal, inline and managed both — `list-attached-*-policies` returns managed policies only,
  so an inline grant is invisible to it.
- **Turn off the flows that let the password travel in the API call.** `ALLOW_ADMIN_USER_PASSWORD_AUTH`
  and the legacy `ADMIN_NO_SRP_AUTH` exist only for migration; SRP never puts a plaintext password
  on the wire. This is the same misconfiguration the register tracks as
  the non-SRP app-client use case (not in this set).
  **`UpdateUserPoolClient` is a full replacement** — AWS: *"If you don't provide a value for an
  attribute, Amazon Cognito sets it to its default value"* — so read the client with
  `describe-user-pool-client` and resend the whole object, or the call will silently reset
  `PreventUserExistenceErrors` to `LEGACY` and re-open the enumeration oracle.
- **Set `PreventUserExistenceErrors` to `ENABLED`** on every app client while you are there. The
  API leaves it `LEGACY`, so any IaC-provisioned client is leaking user existence.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyCognitoAdminAuth EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyCognitoAdminAuth"
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

#### Verify the plaintext-password flows are off and no authentication succeeded after the cutoff

```bash
REGION="us-east-1"; POOL="<user-pool-id-from-Query-1>"
CLIENT="<client-id-from-Query-1>"; SUSPECT_ARN="<caller-arn-from-Query-1>"
CUTOFF="<iso8601-containment-time-from-Section-3>"

# DescribeUserPoolClient NESTS its response under UserPoolClient - a flat .ExplicitAuthFlows is
# null and would make every pool look clean.
C=$(aws cognito-idp describe-user-pool-client --user-pool-id "$POOL" --client-id "$CLIENT" \
      --region "$REGION" --output json 2>&1)
FLOWS=$(printf '%s' "$C" | jq -r '.UserPoolClient.ExplicitAuthFlows // empty | join(",")' 2>/dev/null)
PUEE=$(printf '%s' "$C" | jq -r '.UserPoolClient.PreventUserExistenceErrors // empty' 2>/dev/null)

# This check MUST still be able to emit a signal after the remediation. It can: the principal is
# denied, not deleted, so a further attempt now lands as AccessDeniedException - an event, not
# silence. Capture the raw pages first so a failed lookup cannot collapse into a zero.
POST=$(for EV in AdminInitiateAuth AdminRespondToAuthChallenge; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$CUTOFF" --region "$REGION" --output json
done)

if [ -z "$C" ] || [ -z "$FLOWS" ]; then
  echo "[!] INCONCLUSIVE - the app client could not be read back. ExplicitAuthFlows is never"
  echo "    empty on a live client, so an empty value here means the call failed, not that the"
  echo "    flows are clean."
elif [ -z "$POST" ]; then
  echo "[!] INCONCLUSIVE - the post-containment lookup returned nothing at all. That is a failed"
  echo "    call or a wrong Region, NOT proof that the principal stopped."
else
  SUCC=$(printf '%s' "$POST" | jq -r --arg a "$SUSPECT_ARN" '[.Events[].CloudTrailEvent | fromjson |
           select(.eventSource == "cognito-idp.amazonaws.com") |
           select((.userIdentity.arn // "") == $a) | select(.errorCode == null)] | length')
  if   [ "${SUCC:-x}" = "x" ]; then
    echo "[!] INCONCLUSIVE - the post-containment events could not be parsed; count unknown, not zero."
  elif [ "$SUCC" -gt 0 ]; then
    echo "[FAIL] $SUSPECT_ARN authenticated $SUCC time(s) AFTER $CUTOFF - containment did not hold"
  elif printf '%s' "$FLOWS" | grep -q 'ADMIN_USER_PASSWORD_AUTH\|ADMIN_NO_SRP_AUTH'; then
    echo "[FAIL] client $CLIENT still permits a plaintext-password admin flow: $FLOWS"
  elif [ "$PUEE" != "ENABLED" ]; then
    echo "[FAIL] client $CLIENT has PreventUserExistenceErrors=$PUEE - the enumeration oracle is open"
  else
    echo "[OK] flows=$FLOWS, PreventUserExistenceErrors=$PUEE, no successful admin auth by"
    echo "     $SUSPECT_ARN since $CUTOFF"
  fi
fi
```

Every branch is reachable after the remediation. The client still exists and still returns its
flows, so a partial fix — the commonest real outcome, where the deny policy went on but the app
client was never touched — lands on `[FAIL]` instead of being certified clean.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     five or more events across AdminInitiateAuth AND"
echo "  AdminRespondToAuthChallenge / cognito-idp.amazonaws.com, in ten minutes, from one"
echo "  userIdentity.arn and one sourceIPAddress, with errorCode NotAuthorizedException,"
echo "  UserNotFoundException or UserNotConfirmedException, OR errorMessage containing"
echo "  'Password attempts exceeded'. gte 5, not gt."
echo "MUST NOT fire on: an AdminInitiateAuth that SUCCEEDED as the first leg of USER_SRP_AUTH"
echo "  or CUSTOM_AUTH - the verdict belongs to the matching Respond call; a burst of"
echo "  AccessDeniedException, which is permission probing and is counted separately."
echo "EXPECTED FP, by design: a backend service retrying a stale credential for one service"
echo "  account. It repeats on a single sub with an unchanging user agent; a guessing run walks"
echo "  distinct subs or distinct passwords."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal that does not own server-side sign-in could authenticate as any user in the directory | `cognito-idp:AdminInitiateAuth` granted beyond the one backend role that needs it; no SCP confining it |
| The attack was invisible until it crossed a volume threshold | The source rule watched only `AdminInitiateAuth`, and on a default app client every reachable flow fails on `AdminRespondToAuthChallenge` instead |
| Accounts that do not exist could be distinguished from accounts that do | The app client was API-created, so `PreventUserExistenceErrors` was left at its `LEGACY` default and returned `UserNotFoundException` |
| Nobody could say which named users were targeted | CloudTrail records `sub` and not `UserName`, and threat protection — the only source that carries the username, the device and the risk decision — was not enabled |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the value is wildcarded: Deny + StringNotEquals against a
// wildcarded ARN matches every principal and denies server-side sign-in outright - an outage.
{
  "Effect": "Deny",
  "Action": ["cognito-idp:AdminInitiateAuth", "cognito-idp:AdminRespondToAuthChallenge"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/app-backend-auth", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- The SCP reaches the caller, which is always an in-organisation principal here — `AdminInitiateAuth`
  is IAM-authorized and cannot be invoked anonymously, so `aws:PrincipalArn` is always populated
  (D-i does not apply). Pair it with `ALLOW_ADMIN_USER_PASSWORD_AUTH` removed from every app
  client, `PreventUserExistenceErrors: ENABLED` set explicitly rather than inherited, and — where
  the pool is on the Plus plan — threat protection in at least Audit-only mode so the username,
  device and risk decision exist somewhere. **AWS WAF is not a control for this technique**: its
  documented scope is *"public API operations… that don't use AWS credentials to authorize"*, and
  `AdminInitiateAuth` is not one of them.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1110.001 — Brute Force: Password Guessing (primary); T1078.004 — Valid Accounts: Cloud Accounts (secondary, the AWS credential that made the attempt possible) |
| Primary API | `cognito-idp:AdminInitiateAuth`, and `cognito-idp:AdminRespondToAuthChallenge` where the flow is SRP, custom, or the `PASSWORD` challenge of `USER_AUTH` |
| Event source | `cognito-idp.amazonaws.com`, **management** plane, on by default, regional — AWS: *"Amazon Cognito logs user pool events to CloudTrail as management events"*. `eventType` is `AwsApiCall`; managed-login sign-in is `AwsServiceEvent` under entirely different event names |
| Key discriminator | The calling principal. The API cannot be reached without AWS credentials, so `userIdentity.arn` is always present and always meaningful — the opposite of the unauthenticated sibling use case |
| Field shape | **Unverified.** AWS publishes no example CloudTrail event for any `cognito-idp` management operation. The target is a `sub`, never a `UserName`; private fields including the `AuthParameters` map are `HIDDEN_DUE_TO_SECURITY_REASONS` |
| "Was it used" pivot | A success on the same `sub` inside the failure window. Corroborate with `AdminListUserAuthEvents` (`EventResponse: Pass`, two-year retention, `MaxResults` ≤ 60) where threat protection is enabled — its absence is an unknown, not a negative |
| Blast radius | Every account in the pool: guessable by password, enumerable by error code, and lockable for ~15 minutes each without any successful sign-in. A success yields ID, access and refresh tokens that survive containment of the AWS credential |
| Error strings | Credential failures: `NotAuthorizedException`, `UserNotFoundException` (`LEGACY` clients only), `UserNotConfirmedException`, and the lockout, documented by its message `Password attempts exceeded`. Existence oracle: `PasswordResetRequiredException`. Not credential failures: `AccessDeniedException` (403, permission probing), `NotAuthorized` (401), `TooManyRequestsException` (the account RPS quota, not the per-user lockout). Also documented on this API: `MFAMethodNotFoundException`, `InvalidParameterException`, `ResourceNotFoundException`, `OperationNotEnabledException`, `UnsupportedOperationException`, `InvalidUserPoolConfigurationException`, `UserLambdaValidationException`, `UnexpectedLambdaException`, `InvalidLambdaResponseException`, `InvalidEmailRoleAccessPolicyException`, `InvalidSmsRoleAccessPolicyException`, `InvalidSmsRoleTrustRelationshipException`, `InternalErrorException`. **`ForbiddenException` cannot appear here** — it is the WAF block and WAF inspects public operations only |

### Residual Risk

Every token issued by a successful attempt remains valid until it is explicitly revoked, and
denying the AWS principal does nothing to them — `admin-user-global-sign-out` is the only step
that reaches them, and it reaches only the accounts you knew to name. Accounts targeted but not
guessed are still enumerated: the actor now holds a list of which `sub` values exist, which are
unconfirmed and which require a password reset, and that list does not expire. Where
`PreventUserExistenceErrors` was `LEGACY` the enumeration was exact. Every account driven past
five failures spent up to fifteen minutes locked out, and legitimate users hitting that window
saw an authentication outage with no incident to point at. If the pool was not on the Plus
feature plan there is **no** per-user authentication history at all — the sign-in the trail
recorded as a `sub` can never be tied to a device, a city or a risk decision, and none of that can
be created retroactively. And nothing here covers managed login: a brute force driven through the
hosted pages produced no `AdminInitiateAuth` event, so its absence from the timeline is not
evidence it did not happen.
