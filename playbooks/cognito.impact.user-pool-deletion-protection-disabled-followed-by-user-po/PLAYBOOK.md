# IR Playbook: User Pool Deletion Protection Disabled Then Pool Deleted — Guardrail Removal and Directory Destruction via `cognito-idp:UpdateUserPool` → `cognito-idp:DeleteUserPool`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data destruction / Account access removal (a user pool's deletion guardrail is deactivated and the pool is then destroyed, taking every user account, group, app client, identity provider and Lambda trigger with it) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **Critical.** The source rates the flow **P1**, which is close and defensible; the correction is in the reasoning rather than the number. This is not a resource-availability event — it is the removal of every account's ability to authenticate anywhere the pool is trusted, and the ordering makes intent unambiguous because AWS provides no force flag on `DeleteUserPool`. It is also **time-critical in a way this corpus's other destruction playbooks are not**: AWS retains a deleted pool in an inactive state for **14 days** and offers restoration assistance through Support inside that window. Missing the window converts a recoverable outage into a permanent loss of every credential |
| MITRE Tactics | Impact (TA0040) |
| MITRE Techniques | T1485 (primary), T1531 (secondary) — both verified live 2026-08-29 |
| Services in Scope | Cognito user pools, Cognito identity pools (which trust the pool as an IdP), CloudTrail, IAM, AWS Support, Organizations (SCP), and every application and OIDC relying party that names the pool ID |

**What the technique does:** the actor calls `UpdateUserPool` with `DeletionProtection: INACTIVE`. That call
is a **full replacement, not a patch** — AWS: *"If you don't provide a value for an attribute,
Amazon Cognito sets it to its default value"* — so a request carrying only the pool ID and the flag
simultaneously resets `MfaConfiguration`, the entire `LambdaConfig` trigger set, `UserPoolAddOns`
where threat protection lives, the password and sign-in policies, `UserAttributeUpdateSettings`
including verification-on-attribute-change, the email and SMS configuration, the tags and the
feature tier — none of it separately visible in CloudTrail. If the pool has a domain, a
`DeleteUserPoolDomain` call must follow, because AWS's own example refusal is *"User pool cannot be
deleted. It has a domain configured that should be deleted first"*, taking managed login offline
first. Then `DeleteUserPool`, whose only parameter is the pool ID, and the pool is *"no longer
visible or operational"* immediately.

**Detection thesis.** The discriminator is **the ordering, bounded, on the same pool**: deletion
protection has no reason to be turned off except to permit a deletion, so `UpdateUserPool` with
`INACTIVE` followed by `DeleteUserPool` inside thirty minutes is intent rather than coincidence.
The source flow captures exactly that and is reproduced; what it does not know is that a configured
domain is a **second** mandatory obstacle, so on a user-facing pool the chain is three calls and
the domain deletion is the earlier warning.

> The two component alerts are separately registered use cases —
> `../cognito.impact.user-pool-deletion-protection-disabled-followed-by-user-po/` and
> the user-pool deletion use case (not in this set) — and neither is merged here; see
> `_source/PROVENANCE.md`. The identity-pool analogue,
> `../cognito.impact.identity-pool-deletion-detected/`, has **no** deletion-protection concept and
> **no** restore window, so neither half of this playbook transfers to it.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing Cognito user pool **management** events. AWS: *"Amazon Cognito logs user pool events to CloudTrail as management events"* — on by default. `eventSource` is `cognito-idp.amazonaws.com`, API calls carry `eventType: AwsApiCall`, and hosted-UI activity carries `AwsServiceEvent` under entirely different event names
- **The two request fields this detection depends on are UNVERIFIED.** AWS publishes no example CloudTrail event for any `cognito-idp` management operation. `requestParameters.userPoolId` and `requestParameters.deletionProtection` are the lower-camel forms consistent with every published `cognito-identity` example and with the general CloudTrail convention, but they are inferred. Generate one `UpdateUserPool` in a test pool and read your own trail: a group-by on an absent field collapses every pool into one bucket, and a value match on an absent field matches nothing
- `DeleteUserPool` carries **only** `requestParameters.userPoolId` and no useful `responseElements` — no user count, no app-client list, no domain name, nothing about what was destroyed. So a scheduled **`DescribeUserPool` + `DescribeUserPoolClient` snapshot to durable storage** is not optional and has no substitute: **AWS Backup does not support Amazon Cognito**, there is no snapshot, no PITR and no vault, and Cognito keeps no configuration history
- The pool ID recorded wherever it is depended on — every identity pool names the IdP as `cognito-idp.<region>.amazonaws.com/<user-pool-id>`, and the same ID appears in every OIDC issuer and JWKS URL and in shipped client builds. A rebuilt pool gets a **new** ID: `CreateUserPool` has no parameter for requesting one. Alongside it, a baseline of which principals own pool lifecycle — normally one deployment role and one break-glass role
- **Deletion protection actually turned on.** AWS: *"Amazon Cognito activates Deletion protection by default when you create a new user pool in the AWS Management Console. When you create a user pool with the `CreateUserPool` API, deletion protection is inactive by default."* Every IaC-provisioned pool is unprotected unless the template sets it, and on those pools this detection has no stage 1 to fire on

**Alerting (must be pre-configured)**
- **`UpdateUserPool` setting `deletionProtection` to `INACTIVE` followed by `DeleteUserPool` on the same pool within 30 minutes → P0**
- **`DeleteUserPoolDomain` followed by `DeleteUserPool` on the same pool within 30 minutes → P1**
- **`DeleteUserPool` refused with `InvalidParameterException` → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- Which principals and automation roles touch this service at all. In most estates the list is short, which makes an unfamiliar caller a finding before any threshold is evaluated.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `UpdateUserPool` setting `deletionProtection` to `INACTIVE` followed by `DeleteUserPool` on the same pool within 30 minutes | CloudTrail (management) | T1485 |
| P1 | `DeleteUserPoolDomain` followed by `DeleteUserPool` on the same pool within 30 minutes — the obstacle the source flow does not model | CloudTrail (management) | T1485 |
| P1 | `DeleteUserPool` refused with `InvalidParameterException` — blocked by deletion protection **or** by a configured domain; the two share a code and differ only in the message | CloudTrail (management) | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `UpdateUserPool` setting `deletionProtection` to `INACTIVE` by a principal outside the pool-lifecycle allowlist, with no deletion following | CloudTrail (management) | T1685 |

### Detection Rule Quality Notes

The source flow's design is sound and is reproduced. Its defects are omissions rather than
errors, and one of them is in a field it cannot see.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Two stages only; a configured domain is not modelled | A domain independently blocks deletion — AWS's own example refusal is *"It has a domain configured that should be deleted first"* — so on any pool with managed login the real chain is three calls. The domain deletion is the **earlier** warning and is already an outage on its own, and the flow does not alert on it | Ship the `DeleteUserPoolDomain` → `DeleteUserPool` correlation as a second, independent trigger |
| Nothing covers the refused attempt | `DeleteUserPool` takes exactly one parameter, so an `InvalidParameterException` on it is never a malformed request — it is a guardrail refusal, which is intent without impact and the strongest early signal available. The flow only fires once the destruction has succeeded | Alert on the refusal, and read the `message` to tell the two blocking conditions apart |
| Stage 1 is treated as "a flag was flipped" | `UpdateUserPool` is a full replacement. The same call silently resets MFA, every Lambda trigger, threat protection, the password policy and verification-on-attribute-change — with **no separate event for any of it**. A responder who restores only the flag leaves a materially weakened pool | Treat every `UpdateUserPool` as a whole-configuration write; restore from a `DescribeUserPool` snapshot, not from the flag |
| Grouped by pool with no principal check on either stage | Fires on every scheduled decommission that goes through the pipeline, where the caller is most of the signal | Keep the pool group-by — it is the only grouping that catches a chain split across two identities — and add a lifecycle allowlist to the base rules |

**Recommended detection — the mandatory two-call destruction chain, grouped by pool.**

```yaml
# User Pool Deletion Protection Disabled, Then the Pool Deleted (T1485 / T1531)
#
# WHY THE ORDERING IS THE WHOLE SIGNAL, AND WHY IT IS MANDATORY RATHER THAN INCIDENTAL.
# AWS documents deletion protection on both CreateUserPool and UpdateUserPool in identical terms:
# "When you try to delete a protected user pool in a DeleteUserPool API request, Amazon Cognito
# returns an InvalidParameterException error. To delete a protected user pool, send a new
# DeleteUserPool request after you deactivate deletion protection in an UpdateUserPool API
# request." And DeleteUserPool's entire request body is `{"UserPoolId": "..."}` - there is no
# force flag, no override, nothing. So on a protected pool the destruction is NECESSARILY at
# least two calls, and the disable exists for no reason other than to permit the delete.
#
# THE THIRD CALL THE SOURCE RULE DOES NOT KNOW ABOUT. A configured domain independently blocks
# deletion. AWS's own DeleteUserPool example response is:
#     {"__type":"InvalidParameterException",
#      "message":"User pool cannot be deleted. It has a domain configured that should be deleted
#      first."}
# So against a pool with managed login or a custom domain - which is most user-facing pools - the
# real chain is THREE calls: UpdateUserPool(deletionProtection INACTIVE) -> DeleteUserPoolDomain
# -> DeleteUserPool. Both blocking conditions surface as the SAME errorCode and are
# distinguishable only by the message string. The domain half is covered by its own correlation
# below, because it is an independent early-warning signal: the domain deletion alone takes
# managed login offline.
#
# WHAT STAGE ONE ACTUALLY DOES, WHICH IS FAR MORE THAN REMOVING A GUARDRAIL. UpdateUserPool is a
# full replacement, not a patch. AWS: "If you don't provide a value for an attribute, Amazon
# Cognito sets it to its default value." A call carrying only UserPoolId and
# DeletionProtection=INACTIVE therefore also resets MfaConfiguration, the whole LambdaConfig
# (PreAuthentication, PostAuthentication, PreTokenGeneration, UserMigration and the custom
# sender triggers), Policies (password policy and SignInPolicy), UserPoolAddOns - which is where
# threat protection lives - AccountRecoverySetting, EmailConfiguration, SmsConfiguration,
# UserAttributeUpdateSettings including AttributesRequireVerificationBeforeUpdate, UserPoolTags
# and UserPoolTier. An actor gets an MFA teardown, a threat-protection teardown and the removal of
# verification-on-attribute-change for free, in one call, and none of it is separately visible in
# CloudTrail. This is also why a tag-based guardrail on user pools is self-defeating: the
# attacker's first call removes the tag the guardrail reads.
#
# FIELD SHAPE - THE ONE UNVERIFIED THING IN THIS FILE, AND IT IS LOAD-BEARING. AWS publishes NO
# example CloudTrail event for any cognito-idp management operation. `requestParameters.userPoolId`
# and `requestParameters.deletionProtection` are the lower-camel forms consistent with every
# published cognito-identity example (identityPoolId, allowUnauthenticatedIdentities) and with the
# general CloudTrail convention, and they are the spellings the source rule itself uses - but they
# are INFERRED. Confirm both in your own trail before deploying: a group-by on a field that is
# absent collapses every pool into one bucket, and a value match on an absent field matches
# nothing. Map to a case-insensitive comparison on any backend that supports one.
title: Cognito user pool deletion protection disabled and the pool then deleted
id: 397bf04e-779c-4408-8089-1335af4db300
status: experimental
description: >-
  The same user pool had deletion protection deactivated and was then deleted within thirty
  minutes. AWS provides no force flag on DeleteUserPool, so the disable is a mandatory preceding
  call whose only purpose is to permit the deletion - the pair is intent, not coincidence. Every
  user account, group, app client, identity provider and Lambda trigger in the pool is gone.
references:
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1531/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPool.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-deletion-protection.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
  - attack.t1531
correlation:
  type: temporal_ordered
  rules:
    - cognito_userpool_deletion_protection_off_bb
    - cognito_userpool_deleted_bb
  # Grouped by the POOL, not by the principal. A chain split across two identities - a stolen
  # pipeline credential disabling protection and a second principal deleting - is the case a
  # principal group-by would miss, and it is the more sophisticated one.
  group-by:
    - requestParameters.userPoolId
  timespan: 30m
level: critical
---
# Thirty minutes is the source's own second-stage timeframe and it is retained. The disable and
# the delete are two calls a scripted actor makes back to back, so the real interval is seconds;
# thirty minutes is generous headroom that still excludes a decommission days later. Where a
# domain is configured the DeleteUserPoolDomain call sits between them and consumes some of the
# window - another reason not to shrink it.
title: Cognito user pool deletion protection deactivated
id: bde86004-ee40-4f88-b2b6-8b00d160a299
name: cognito_userpool_deletion_protection_off_bb
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting; deactivation on its own is a
  separately registered use case. Carries the success filter so a call that was itself refused
  cannot compose into the critical correlation above (D-f).
references:
  - https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserPool.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-idp.amazonaws.com'
    eventName: 'UpdateUserPool'
  # Documented Valid Values are the strings ACTIVE and INACTIVE. The AWS developer guide page for
  # this feature says to "set the DeletionProtection parameter to True" - that is a documentation
  # error; True is not in the API's value set and matching it would match nothing.
  protection_off:
    requestParameters.deletionProtection: 'INACTIVE'
  success:
    errorCode: null
  condition: selection and protection_off and success
level: low
---
title: Cognito user pool deleted
id: bdf0f36c-32f0-4258-908f-480190c41031
name: cognito_userpool_deleted_bb
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. DeleteUserPool's only request
  parameter is UserPoolId, so the request is the entire record and there is nothing else to
  filter on.
references:
  - https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPool.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
  - attack.t1531
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-idp.amazonaws.com'
    eventName: 'DeleteUserPool'
  success:
    errorCode: null
  condition: selection and success
level: low
---
title: Cognito user pool domain deleted
id: c8206422-1d0b-4064-8deb-690368790da7
name: cognito_userpool_domain_deleted_bb
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. Deleting the domain takes managed
  login and the authorization server offline on its own, and it is a mandatory step before a pool
  carrying a domain can be deleted.
references:
  - https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPoolDomain.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-idp.amazonaws.com'
    eventName: 'DeleteUserPoolDomain'
  success:
    errorCode: null
  condition: selection and success
level: low
---
# The half of the chain the source flow does not model. AWS: "After you delete a user pool domain,
# your managed login pages and authorization server are no longer available" - so this pair is
# already an outage before the pool itself is touched, and it is the earlier of the two warnings
# on any pool that has a domain. Grouped by pool for the same reason as the primary correlation.
title: Cognito user pool domain deleted and the pool then deleted
id: add7c356-41ae-4c47-ba2b-5b082d9c50a0
status: experimental
description: >-
  A user pool's domain was deleted and the pool followed within thirty minutes. A configured
  domain independently blocks DeleteUserPool, so on a pool with managed login this is a mandatory
  step in the destruction chain rather than routine domain maintenance.
references:
  - https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPoolDomain.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: temporal_ordered
  rules:
    - cognito_userpool_domain_deleted_bb
    - cognito_userpool_deleted_bb
  group-by:
    - requestParameters.userPoolId
  timespan: 30m
level: high
---
# An attempt that the guardrail stopped. DeleteUserPool takes exactly one parameter, UserPoolId,
# so an InvalidParameterException on it is not a malformed request - it is one of the two
# documented blocking conditions: deletion protection is ACTIVE, or a domain is still configured.
# AWS gives them the SAME errorCode and different message strings, so this rule cannot separate
# them and the analyst reads the message. Either way somebody tried to destroy a user pool and
# was refused, which is a stronger intent signal than most successful events.
title: Cognito user pool deletion refused by a guardrail
id: 63ea2d89-fa33-49a9-aaf7-67b19fee83c5
status: experimental
description: >-
  A DeleteUserPool call was refused with InvalidParameterException. On this API that means either
  deletion protection is active or a domain is still configured - the two documented blocking
  conditions - and the next call in the sequence is the one that removes the obstacle.
references:
  - https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPool.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-idp.amazonaws.com'
    eventName: 'DeleteUserPool'
  blocked:
    errorCode: 'InvalidParameterException'
  condition: selection and blocked
falsepositives:
  - >-
    An operator running a decommission by hand and meeting the domain requirement for the first
    time. Distinguishable by whether a change record exists and by whether the same principal then
    deletes the domain; if it is frequent, the finding is that decommissions are not scripted.
level: high
```

The correlation cannot report the **gap** between the stages — the strongest separator between a
scripted destruction (seconds) and a decommission (hours, with a change record) — and it cannot
flag the split-identity case it exists to catch. `detections/kql_t1485.kql` does both, keeps
refused attempts in their own columns, and computes the 14-day restore deadline as an output.

---

### Key Investigation Queries

> Cognito user pools are regional — run these in the pool's Region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct the chain: which pool, which principals, how long between stages

```bash
REGION="us-east-1"
RAW=$(for EV in UpdateUserPool DeleteUserPool DeleteUserPoolDomain SetUserPoolMfaConfig; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong Region, or"
  echo "    missing cloudtrail:LookupEvents. This is NOT 'no pool was deleted'."
else
  # Both casings are coalesced because the cognito-idp requestParameters shape is UNVERIFIED.
  # If pool_id is "unknown" throughout, the field is not in your trail and the stages cannot be
  # joined - that is a finding about the trail, not about the incident.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "cognito-idp.amazonaws.com") |
    {time: .eventTime, event: .eventName,
     caller_arn: (.userIdentity.arn // "no-arn"),
     access_key: (.userIdentity.accessKeyId // "none"),
     pool_id: (.requestParameters.userPoolId // .requestParameters.UserPoolId // "unknown"),
     deletion_protection: (.requestParameters.deletionProtection //
                           .requestParameters.DeletionProtection // null),
     domain: (.requestParameters.domain // .requestParameters.Domain // null),
     ip: .sourceIPAddress, agent: .userAgent,
     error: (.errorCode // "SUCCESS"), message: (.errorMessage // "")} |
    . + {stage: (if .event == "UpdateUserPool" and .deletion_protection == "INACTIVE" then "1-GUARDRAIL-REMOVED"
                 elif .event == "DeleteUserPoolDomain" then "2-DOMAIN-REMOVED"
                 elif .event == "DeleteUserPool" and .error == "SUCCESS" then "3-POOL-DESTROYED"
                 elif .event == "DeleteUserPool" and (.message | test("domain configured")) then "BLOCKED-BY-DOMAIN"
                 elif .event == "DeleteUserPool" then "BLOCKED-OR-FAILED"
                 else "OTHER-CONFIG-WRITE" end)}' |
  jq -s 'sort_by(.pool_id, .time)'
fi
```

Read it per `pool_id`. `1-GUARDRAIL-REMOVED` followed within seconds by `3-POOL-DESTROYED` is a
script; the same pair an hour apart with a change record is a decommission. Compare `caller_arn`
across the stages — **different callers is worse, not better**: two credentials, both to contain.
Every `OTHER-CONFIG-WRITE` on the pool is a full-replacement write whose collateral is invisible,
so treat each as a potential MFA and threat-protection teardown. Record `pool_id`, `caller_arn`,
`access_key` and the earliest `3-POOL-DESTROYED` time — the restore clock starts there.

#### Query 2 — What still points at a pool that no longer exists

```bash
REGION="us-east-1"; POOL="<pool-id-from-Query-1>"
PROVIDER="cognito-idp.${REGION}.amazonaws.com/${POOL}"

# Identity pools name a user pool IdP by that string. Nothing enumerates the dependency for you;
# after the deletion the identity pool keeps the stale reference and silently stops issuing.
IDS=$(aws cognito-identity list-identity-pools --max-results 60 --region "$REGION" --output json)
if [ -z "$IDS" ]; then
  echo "[!] INCONCLUSIVE - list-identity-pools failed. The dependency set is unknown, not empty."
else
  N=$(printf '%s' "$IDS" | jq '.IdentityPools | length')
  if [ "${N:-0}" -eq 0 ]; then
    echo "[i] no identity pools in $REGION - nothing federates from this user pool here."
  else
    for IPID in $(printf '%s' "$IDS" | jq -r '.IdentityPools[].IdentityPoolId'); do
      D=$(aws cognito-identity describe-identity-pool --identity-pool-id "$IPID" \
            --region "$REGION" --output json 2>&1)
      case "$D" in
        *IdentityPoolId*)
          HIT=$(printf '%s' "$D" | jq -r --arg p "$PROVIDER" \
                  '[.CognitoIdentityProviders[]? | select(.ProviderName == $p)] | length')
          [ "${HIT:-0}" -gt 0 ] && echo "[FAIL] identity pool $IPID still trusts the deleted user pool as $PROVIDER";;
        *) echo "[!] INCONCLUSIVE - describe-identity-pool failed for $IPID: $D";;
      esac
    done
  fi
fi

# The pre-incident snapshot from Section 1. Without one nothing reconstructs the pool's MFA,
# triggers, password policy or app clients: AWS Backup does not cover Cognito.
SNAP="<path-of-the-scheduled-DescribeUserPool-snapshot>"
if [ -f "$SNAP" ]; then
  jq -r '.UserPool | "[OK] snapshot: mfa=\(.MfaConfiguration // "unset") protection=\(.DeletionProtection // "unset") triggers=\((.LambdaConfig // {}) | keys | join(","))"' "$SNAP"
else echo "[!] INCONCLUSIVE - no snapshot at $SNAP. The configuration is unknown, not default."; fi
```

Every `[FAIL]` line is an application that will stop authenticating and will not say why. The
snapshot branch decides the rest of the response: with one, a rebuild is possible; without one the
14-day Support restore is the **only** way the configuration comes back, and Step 1 becomes the
whole plan rather than its first part.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="DeleteUserPool DeleteUserPoolDomain UpdateUserPool"
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
elsewhere, and whether anyone else did it too. Grouped by caller rather than by resource,
because the question eradication needs answered is *how much of this is one actor's work* — a
per-resource list cannot say. `access_key` is emitted because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` whether or not it happened; the preamble's caveat applies.

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

Keyed on the access key rather than the ARN: one credential is used across many sessions, and
the key identifies the credential. The per-service grouping answers what this playbook cannot —
whether this technique was the objective or one stop on a tour. A service in that list with no
business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID, so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The destruction is complete and the pool is already offline, so containment is about the **clock**
and the **next** pool. Open the AWS Support case first — it is the only action that recovers users
and credentials, and it expires. Only then contain the principal: a revocation that lands first
does nothing for a pool that is already gone, and the 14-day window counts from the deletion, not
from the alert.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Confirm the pool is genuinely gone, and open the restoration case inside the window

```bash
REGION="us-east-1"; POOL="<pool-id-from-Query-1>"
DELETED_AT="<iso8601-deletion-time-from-Query-1>"

# D-0: an API ERROR here is not a result. ResourceNotFoundException means the pool is deleted;
# any other failure means the check did not run, and neither is "the pool is fine".
D=$(aws cognito-idp describe-user-pool --user-pool-id "$POOL" --region "$REGION" \
      --output json 2>&1)
case "$D" in
  *ResourceNotFoundException*)
    DEADLINE=$(date -u -d "$DELETED_AT +14 days" +%Y-%m-%dT%H:%M:%SZ)
    echo "[CONFIRMED] $POOL is deleted. AWS retains it inactive for 14 days."
    echo "            Restoration assistance must be requested from AWS Support BEFORE $DEADLINE."
    echo "            There is no undelete API, no console recycle bin and no self-service path.";;
  *UserPool*)
    echo "[i] $POOL still exists - the deletion did not succeed, or you are in the wrong Region."
    printf '%s' "$D" | jq -r '.UserPool | "    protection=\(.DeletionProtection // "unset") mfa=\(.MfaConfiguration // "unset")"'
    echo "    Re-protect it now with the read-modify-write in Section 4 - do NOT send a bare update.";;
  *AccessDenied*|*NotAuthorized*)
    echo "[!] INCONCLUSIVE - the responder credential cannot read this pool. Nothing was determined.";;
  *)
    echo "[!] INCONCLUSIVE - describe-user-pool failed for an unexpected reason: $D";;
esac

# The support case is not scriptable to a verdict: `aws support create-case` lives in us-east-1
# and needs a Business or Enterprise support plan. Open it by whatever route you have.
echo "[ACTION] Open the AWS Support restoration case now; record the case ID in the incident record."
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["cognito-idp:DeleteUserPool","cognito-idp:UpdateUserPool","cognito-idp:DeleteUserPoolDomain","cognito-idp:SetUserPoolMfaConfig","cognito-idp:DeleteUserPoolClient","cognito-identity:DeleteIdentityPool"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyCognitoDestroy" \
      --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyCognitoDestroy" \
      --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied Cognito destruction for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or a"
     echo "    service principal. Contain manually; neither branch above applies.";;
esac
```

---

## 4. Eradication

### Remove Attacker Access

- **Re-protect every surviving pool with a read-modify-write, never a bare update.** A bare
  `update-user-pool --deletion-protection ACTIVE` re-arms the guardrail and resets everything else
  on the way. Generate the request from the live configuration, read it, then apply it:

```bash
REGION="us-east-1"; POOL="<pool-id-from-Query-1>"
D=$(aws cognito-idp describe-user-pool --user-pool-id "$POOL" --region "$REGION" --output json 2>&1)
case "$D" in
  *UserPool*)
    printf '%s' "$D" | jq '.UserPool
      | {UserPoolId: .Id, PoolName: .Name}
        + with_entries(select(.key | test("^(Policies|LambdaConfig|AutoVerifiedAttributes|SmsVerificationMessage|EmailVerificationMessage|EmailVerificationSubject|VerificationMessageTemplate|SmsAuthenticationMessage|UserAttributeUpdateSettings|MfaConfiguration|DeviceConfiguration|EmailConfiguration|SmsConfiguration|UserPoolTags|AdminCreateUserConfig|UserPoolAddOns|AccountRecoverySetting|UserPoolTier)$")))
      | .DeletionProtection = "ACTIVE"' > /tmp/reprotect-"$POOL".json
    echo "[OK] body written to /tmp/reprotect-$POOL.json - READ IT first: DescribeUserPool returns"
    echo "     fields UpdateUserPool rejects, so the filter is a subset and may need hand-editing."
    echo "     Then: aws cognito-idp update-user-pool --region $REGION --cli-input-json file:///tmp/reprotect-$POOL.json";;
  *) echo "[!] INCONCLUSIVE - could not read $POOL; no request body was generated: $D";;
esac
```

- **Reconcile every identity pool Query 2 flagged.** The stale `ProviderName` does not error, it
  stops issuing credentials, so the symptom arrives as an application outage with no event behind
  it. Repoint each with `UpdateIdentityPool` — **also** a full replacement, same discipline.
- **Reclaim the domain prefix if one was deleted.** AWS documents the namespace as shared and the
  console as requiring *"an available domain prefix"*, but **no AWS statement confirms whether a
  released prefix becomes claimable by another account** — recreate it promptly regardless.
- **Right-size the permissions.** `cognito-idp:DeleteUserPool` is needed by nothing at runtime.
  `cognito-idp:UpdateUserPool` deserves the same treatment for a different reason: its
  full-replacement semantics make it a silent MFA and threat-protection teardown. Check inline
  grants too — `list-attached-*-policies` returns managed policies only. Do **not** fall back to a
  tag-based guardrail: `UpdateUserPool` resets `UserPoolTags`, so the attacker's first call removes
  the tag the condition reads.
- **Remove the emergency policies once clean, and assert it** — both branches, since §3 took one:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyCognitoDestroy EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyCognitoDestroy"
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

#### Verify the pool that now serves this identity is protected and still hardened

```bash
REGION="us-east-1"
# The RESTORED pool keeps its original ID; a REBUILT one has a new one, because CreateUserPool has
# no parameter for requesting an ID. Set this to whichever is now authoritative.
POOL="<pool-id-from-Query-1>"
DELETED_AT="<iso8601-deletion-time-from-Query-1>"

D=$(aws cognito-idp describe-user-pool --user-pool-id "$POOL" --region "$REGION" --output json 2>&1)
case "$D" in
  *ResourceNotFoundException*)
    # THE TRAP THIS BLOCK EXISTS TO AVOID: an API error on a deleted pool is not a pass, and it is
    # not a generic failure either. It is a specific, expected state with a deadline attached.
    DEADLINE=$(date -u -d "$DELETED_AT +14 days" +%Y-%m-%dT%H:%M:%SZ)
    NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    if [ "$NOW" \< "$DEADLINE" ]; then
      echo "[PENDING] $POOL is still deleted. The AWS Support restore window closes $DEADLINE."
      echo "          Recovery is NOT complete and this is NOT a clean result."
    else
      echo "[FAIL] $POOL is still deleted and the 14-day retention window closed at $DEADLINE."
      echo "       AWS begins full cleanup after that point. Rebuild is now the only path, and it"
      echo "       does not return the users or their credentials."
    fi;;
  *UserPool*)
    PROT=$(printf '%s' "$D" | jq -r '.UserPool.DeletionProtection // empty')
    MFA=$(printf '%s' "$D"  | jq -r '.UserPool.MfaConfiguration // empty')
    TRIG=$(printf '%s' "$D" | jq -r '(.UserPool.LambdaConfig // {}) | keys | length')
    ASF=$(printf '%s' "$D"  | jq -r '.UserPool.UserPoolAddOns.AdvancedSecurityMode // "NONE"')
    if   [ -z "$PROT" ] || [ -z "$MFA" ]; then
      echo "[!] INCONCLUSIVE - the pool answered but DeletionProtection or MfaConfiguration was"
      echo "    absent from the response. DescribeUserPool always returns them on a live pool, so"
      echo "    this is a parse or permission problem, not a clean pool."
    elif [ "$PROT" != "ACTIVE" ]; then
      echo "[FAIL] $POOL exists with DeletionProtection=$PROT - the guardrail was never restored"
    elif [ "$MFA" = "OFF" ]; then
      echo "[FAIL] $POOL has MfaConfiguration=OFF - the full-replacement UpdateUserPool reset it"
      echo "       and the re-protect did not carry the old value back"
    elif [ "$ASF" = "NONE" ] || [ "$ASF" = "OFF" ]; then
      echo "[FAIL] $POOL has threat protection AdvancedSecurityMode=$ASF - also collateral of the"
      echo "       full-replacement write. Restore it from the snapshot."
    else
      echo "[OK] $POOL: DeletionProtection=$PROT, MfaConfiguration=$MFA, AdvancedSecurityMode=$ASF,"
      echo "     $TRIG Lambda trigger(s) wired"
    fi;;
  *AccessDenied*|*NotAuthorized*)
    echo "[!] INCONCLUSIVE - the responder credential cannot read $POOL. Nothing was determined.";;
  *) echo "[!] INCONCLUSIVE - describe-user-pool failed unexpectedly: $D";;
esac
```

Every branch is reachable, and the two that matter most are the error branches. A pool that is
still deleted lands on `[PENDING]` or `[FAIL]`, never `[OK]` — an error from a resource the
incident destroyed must never read as success. And a pool that came back with the guardrail on but
MFA and threat protection still reset, the commonest outcome of a bare update, lands on `[FAIL]`.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     UpdateUserPool / cognito-idp.amazonaws.com with"
echo "  requestParameters.deletionProtection = 'INACTIVE' and no errorCode, followed within 30"
echo "  minutes by a successful DeleteUserPool carrying the SAME requestParameters.userPoolId -"
echo "  including when the two calls come from DIFFERENT principals, and including when a"
echo "  DeleteUserPoolDomain sits between them."
echo "MUST NOT fire on: UpdateUserPool setting deletionProtection to ACTIVE; a DeleteUserPool that"
echo "  returned InvalidParameterException, which is the guardrail HOLDING and has its own rule;"
echo "  a deletion of a pool that was never protected, which has no stage 1 and is a separate case."
echo "EXPECTED FP, by design: a scheduled decommission by the pipeline role. The ordering is"
echo "  identical and only the principal and a change record separate it - which is why the base"
echo "  rules take a lifecycle allowlist and the KQL reports the inter-stage gap."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the pipeline could remove the deletion guardrail and destroy the directory | `cognito-idp:DeleteUserPool` and `cognito-idp:UpdateUserPool` granted beyond the one lifecycle owner; no SCP confining either |
| The pool came back without MFA, threat protection or its Lambda triggers | `UpdateUserPool` is a full replacement and the re-protect was sent as a bare flag update, resetting everything the request did not carry |
| Nobody could say what the pool had been configured to do, and applications kept failing after the rebuild | No scheduled `DescribeUserPool` snapshot — AWS Backup does not cover Cognito — and the rebuilt pool's new ID was embedded in every identity pool `ProviderName`, OIDC issuer and shipped client build |
| The restore window was nearly missed | The 14-day retention and its Support path were not in the runbook, and the response began with containment rather than with the clock |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the value is wildcarded: Deny + StringNotEquals against a
// wildcarded ARN matches every principal and denies pool lifecycle outright - an outage.
// BLANKET ACTION DENY on purpose: Cognito supports no condition key that inspects
// DeletionProtection, and a tag condition is self-defeating because UpdateUserPool resets
// UserPoolTags. Resource-scoping to arn:aws:cognito-idp:REGION:ACCOUNT:userpool/POOL_ID is the
// one finer-grained lever available.
{
  "Effect": "Deny",
  "Action": ["cognito-idp:DeleteUserPool", "cognito-idp:UpdateUserPool", "cognito-idp:DeleteUserPoolDomain"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- The SCP reaches the caller, which is always an in-organisation principal: these are IAM-authorized
  operations and `aws:PrincipalArn` is always populated. Pair it with `DeletionProtection: ACTIVE`
  set explicitly in every template — **AWS leaves it inactive for API-created pools** — with a
  scheduled `DescribeUserPool`/`DescribeUserPoolClient` snapshot, the only configuration backup
  Cognito has, and with the 14-day Support restore path written into the runbook, since it recovers
  the users and is the step most likely to be skipped.
- **The exhaustive `cognito-idp` condition-key list could not be verified** — that reference page
  serves a client-rendered stub returning no content to a fetch. AWS's "How Amazon Cognito works
  with IAM" page reports condition-key support as *Yes* and ABAC as *Partial*, but every link in
  that section points at the **identity pools** reference, so the *Yes* is unconfirmed for
  `cognito-idp`. Treat the blanket action deny as the reliable control.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1485 — Data Destruction (primary, and the source's own structured label); T1531 — Account Access Removal (secondary — every user loses the ability to authenticate anywhere the pool is trusted) |
| Primary API | `cognito-idp:UpdateUserPool` (`DeletionProtection: INACTIVE`) → optionally `cognito-idp:DeleteUserPoolDomain` → `cognito-idp:DeleteUserPool` |
| Event source | `cognito-idp.amazonaws.com`, **management** plane, on by default, regional. `eventType: AwsApiCall` |
| Key discriminator | The **ordering, bounded, on the same pool**. There is no force flag on `DeleteUserPool`, so the disable is mandatory and has no other purpose. The gap between stages separates a script from a decommission |
| Field shape | `DeleteUserPool` carries **only** `requestParameters.userPoolId` and no useful `responseElements`. `UpdateUserPool` carries `deletionProtection` as the string `ACTIVE`/`INACTIVE` — the developer guide's *"set the `DeletionProtection` parameter to `True`"* is a documentation error and `True` is not in the API's value set. **Both field spellings are UNVERIFIED**: AWS publishes no `cognito-idp` CloudTrail example |
| "Was it used" pivot | Not applicable in the usual sense — the deletion *is* the outcome. The measurable questions are what was lost, answerable only from a pre-incident `DescribeUserPool` snapshot, and what still depends on the pool ID, answerable only by enumerating identity pools and client configurations by hand |
| Blast radius | Every user account, password, group, app client, identity provider, resource server, custom attribute and Lambda trigger wiring in the pool; the domain and its managed login pages; and, through the pool ID, every identity pool `ProviderName`, OIDC issuer and JWKS URL that names it |
| Error strings | `DeleteUserPool`: `InvalidParameterException` (the guardrail refusal — **overloaded** across "deletion protection is active" and "a domain is configured", distinguishable only by `message`), `UserImportInProgressException` (a running import job is a third obstacle), `NotAuthorizedException`, `OperationNotEnabledException`, `ResourceNotFoundException`, `TooManyRequestsException`, `InternalErrorException`. `UpdateUserPool` adds `ConcurrentModificationException`, `FeatureUnavailableInTierException`, `TierChangeNotAllowedException`, `UserPoolTaggingException` and the SMS/email role-policy set. Denials: match both `NotAuthorizedException` (Cognito's own, HTTP 400) and `AccessDeniedException` (Common Error Types, HTTP 403); the bare `AccessDenied` form is not in Cognito's documented list |

### Residual Risk

**The clock is the risk.** AWS retains the pool inactive for 14 days and offers *"restoration
assistance"* through Support — assistance, not a guaranteed restore, with no API and no
self-service path — after which cleanup begins and nothing brings the users back. The outage
meanwhile is total from the first second: the pool is *"no longer visible or operational"*
immediately, even while the data is retained. If the restore does not happen, a rebuild returns the pool's shape and none of its substance.
Cognito has **no password export** — no read API exposes a hash — so credentials cannot be
round-tripped within Cognito at all; hash *import* exists, but only from a source system outside
Cognito that you already hold. Without hashes every restored user lands in `RESET_REQUIRED`, and
*"the creation date for each user is the time when that user was imported"*, so account ages and
the forensic timeline go too. The new pool ID breaks every identity pool `ProviderName`, every OIDC
issuer and JWKS URL and every shipped client build, and nothing enumerates those dependencies.

Two things stay unresolved even after a successful restore. The collateral of the full-replacement
`UpdateUserPool` — MFA state, Lambda triggers, password policy, threat protection,
verification-on-attribute-change — has **no event of its own** in CloudTrail, so without a
pre-incident snapshot you cannot know what the pool used to be, only what it is now. And whether a
released domain prefix becomes claimable by another account is **not documented either way**.
