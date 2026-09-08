# IR Playbook: Identity Pool Deletion — Permanent Destruction of a Federation Resource via `cognito-identity:DeleteIdentityPool`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data destruction / Account access removal (an identity pool, every identity in it, every developer-provider linkage and the pool ID every client is hard-coded against are destroyed; the IAM roles survive as orphans) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, for a single deletion as much as for a mass one — irreversibility does not scale with count. The source rates it **P3**, which reads it as configuration noise. AWS states there is no undo: *"You can't undo identity pool deletion."* There is **no retention window and no Support restore path**, which is the opposite of the user-pool case and the single most important thing not to get backwards |
| MITRE Tactics | Impact (TA0040) |
| MITRE Techniques | T1485 (primary), T1531 (secondary) — both verified live 2026-08-29 |
| Services in Scope | Cognito identity pools, IAM (the orphaned authenticated and unauthenticated roles), STS, CloudTrail, Cognito user pools and any external IdP the pool federated, Organizations (SCP), and every mobile or browser client carrying the pool ID |

**What the technique does:** the actor calls `DeleteIdentityPool` with a pool ID. AWS destroys the pool, its
configuration — `AllowUnauthenticatedIdentities`, `AllowClassicFlow`, `SupportedLoginProviders`,
`CognitoIdentityProviders`, the OIDC and SAML provider ARNs, the tags — and *"all the user data it
contains"*: every identity, and every `LookupDeveloperIdentity` mapping between your backend user
IDs and Cognito identity IDs. The `DeveloperProviderName` goes with it, and it was immutable in
life. Applications stop being able to exchange a token for AWS credentials silently — no error at
configuration time, only a failure when a user signs in. **The IAM roles are not deleted.** They
remain with their policies attached and their trust policies pointing at a dead `aud`.

**Detection thesis.** The discriminator is **the calling principal**: `DeleteIdentityPool` is what
every teardown does, so the only field separating destruction from maintenance is whether the caller
owns identity-pool lifecycle — and the source rule groups by that ARN without ever testing it, while
never naming the pool it is reporting on.

> The sibling `../cognito.persistence.identity-pool-configured-to-allow-unauthenticated-access/`
> covers the same resource in the opposite direction — a pool made **more** reachable and left live
> — and carries the unauthenticated-role blast-radius analysis in full. A deletion following one of
> those changes is the §2 correlation, and a different incident from a bare teardown.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing Cognito Identity **management** events. AWS: *"Amazon Cognito logs the remainder of Amazon Cognito identity pools API operations as management events"* — `CreateIdentityPool`, `UpdateIdentityPool`, `DeleteIdentityPool`, `SetIdentityPoolRoles`, `GetIdentityPoolRoles` are all on by default. `eventSource` is `cognito-identity.amazonaws.com`, which is a **different source from `cognito-idp.amazonaws.com`**; a rule pointed at the wrong one returns zero forever
- **Field casing is verified for this service.** AWS publishes a real `CreateIdentityPool` CloudTrail example carrying `requestParameters.identityPoolName`, `requestParameters.allowUnauthenticatedIdentities` and `responseElements.identityPoolId` — lower-camel on both sides. No example exists for `DeleteIdentityPool`, so `requestParameters.identityPoolId` is inferred from the family convention
- **CloudTrail data events on `AWS::Cognito::IdentityPool`.** `GetId`, `GetCredentialsForIdentity`, `GetOpenIdToken`, `GetOpenIdTokenForDeveloperIdentity` and `UnlinkIdentity` are **data events, off by default and billable**. Without an advanced event selector there is **no record that the pool was ever used**, by whom, or how often — and after the deletion none can be created. There is no `AWS/Cognito` metric for identity pools and, per AWS, *"no log export capabilities exist for identity pools"*
- **The pool's configuration in infrastructure code**, plus a scheduled `describe-identity-pool` + `get-identity-pool-roles` + `list-identities` snapshot — after the deletion, the only places the guest-access flag, the role ARNs and the identity count still exist
- An inventory of every IAM role trusting `cognito-identity.amazonaws.com`, with the `aud` each is pinned to and whether it carries an `amr` condition — the part of the blast radius that **outlives** the incident, and it is in no Cognito event
- The pool ID recorded wherever it is depended on. It is not confidential — AWS: *"Your identity pool ID isn't confidential information"* — and is routinely hard-coded into mobile binaries and JavaScript bundles, so a rebuild needs a client re-release, not a config push. Alongside it, a baseline of which principals own identity-pool lifecycle

**Alerting (must be pre-configured)**
- **`DeleteIdentityPool` succeeding for a principal outside the identity-pool-lifecycle allowlist → P0**
- **Three or more `DeleteIdentityPool` successes by one non-pipeline principal within ten minutes → P1**
- **An identity pool reconfigured and then deleted within twenty-four hours → P1**

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
| P0 | `DeleteIdentityPool` succeeding for a principal outside the identity-pool-lifecycle allowlist | CloudTrail (management) | T1485 |
| P1 | Three or more `DeleteIdentityPool` successes by one non-pipeline principal within ten minutes | CloudTrail (management) | T1485 |
| P1 | `UpdateIdentityPool`, `SetIdentityPoolRoles` or `CreateIdentityPool` on a pool followed by `DeleteIdentityPool` on that pool within 24 hours | CloudTrail (management) | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `DeleteIdentityPool` refused with `NotAuthorizedException` or `AccessDeniedException` across several pools — boundary mapping, not destruction | CloudTrail (management) | T1485 |

### Detection Rule Quality Notes

The source rule matches an event name and the absence of an error code, and does not name the
resource it is reporting on.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `requestParameters.identityPoolId` is never surfaced, though the field carries it | The alert says an identity pool is gone and cannot say which. Every downstream step — which clients break, which roles are orphaned, what the pool handed out — needs that ID, and the responder has to go and find it before triage can begin | Emit the pool ID; group the volume correlation by principal and the sequence correlation by pool |
| `eventName:"DeleteIdentityPool"` with no principal check | Fires on every ephemeral test-stack teardown and every Terraform destroy. Where lifecycle belongs to a pipeline the caller is the entire signal, and it is used only as a grouping key | Allowlist the lifecycle roles; alert on everyone else |
| Denials discarded by the success filter and captured nowhere; P3 priority overall | A principal walking the account's pools to find one it can destroy produces the same volume as a real destruction and is invisible — and Cognito Identity returns `NotAuthorizedException` at **HTTP 400**, not 403, so a status-code rule misses it. Meanwhile an unrecoverable destruction is triaged alongside configuration noise | Ship the refusal rule at its own priority, matching exception names; raise the deletion to P0 |

**Recommended detection — an identity pool destroyed by a principal outside the lifecycle pipeline.**

```yaml
# Identity Pool Deletion (T1485 / T1531)
#
# WHAT THE ORIGINAL RULE GOT WRONG. It matches `DeleteIdentityPool` with a success filter and
# nothing else, and groups by `userIdentity.arn` while never surfacing WHICH POOL was destroyed -
# even though the pool ID is right there in `requestParameters.identityPoolId`. So the alert says
# a pool is gone and cannot say which one, and it fires equally on every ephemeral test-stack
# teardown. In an account where identity-pool lifecycle belongs to a pipeline, the caller is the
# entire signal and the rule does not use it.
#
# IRREVERSIBLE, AND WITHOUT THE MITIGATION ITS USER-POOL NEIGHBOUR HAS. AWS on identity pools:
# "You can't undo identity pool deletion. After you delete an identity pool, all apps and users
# that depend on it stop working", and "you will permanently delete your identity pool and all the
# user data it contains". There is no retention window, no recycle bin, no undelete API and no
# support restore path. That is the OPPOSITE of a user pool, where AWS "retains deleted user pools
# in an inactive state for 14 days" - see
# ../../cognito.impact.user-pool-deletion-protection-disabled-followed-by-user-po/. Do not carry
# the fourteen-day reflex across; there is nothing to call Support about here.
#
# THE POOL ID CANNOT BE RECOVERED EITHER. `CreateIdentityPool` has no IdentityPoolId request
# parameter - the ID is service-generated in the REGION:GUID form and returned only in the
# response - so a rebuilt pool is a new pool as far as every deployed client is concerned. AWS
# never states that an ID cannot be reissued, so treat "the ID is gone" as a strong operational
# assumption rather than a quoted fact; what IS certain is that there is no mechanism to ask for
# one.
#
# WHAT SURVIVES THE DELETION IS THE PART THAT MATTERS FOR DETECTION. The pool's IAM roles are NOT
# deleted with it. They remain, with their permissions attached and their trust policies intact,
# pointing at an `aud` that no longer exists. Two of those orphans are dangerous rather than
# merely untidy: a role whose trust policy carries NO `aud` condition is assumable through ANY
# identity pool - AWS: "AWS STS permits web identities to assume roles that are not secured with
# conditions" - including one an attacker creates in their own account; and a role with no `amr`
# condition does not distinguish an authenticated token from a guest one. Neither is visible in
# any Cognito event. The playbook's Query 2 sweeps for both.
#
# FIELD SHAPE - VERIFIED HERE, UNLIKE THE USER-POOL SIDE. AWS publishes a real CloudTrail example
# for `CreateIdentityPool` showing lower-camel `requestParameters`: `identityPoolName`,
# `allowUnauthenticatedIdentities`, `supportedLoginProviders`, and `identityPoolId` in
# `responseElements`. There is no published example for `DeleteIdentityPool` specifically, so
# `requestParameters.identityPoolId` is inferred from the family convention rather than quoted -
# but it is a far stronger inference than anything available for `cognito-idp`.
#
# EVENT PLANE. `DeleteIdentityPool`, `CreateIdentityPool`, `UpdateIdentityPool` and
# `SetIdentityPoolRoles` are CloudTrail MANAGEMENT events, logged by default. `GetId`,
# `GetCredentialsForIdentity`, `GetOpenIdToken`, `GetOpenIdTokenForDeveloperIdentity` and
# `UnlinkIdentity` are DATA events and are OFF by default, so the pool's actual usage - how many
# identities it vended credentials to, and to whom - is invisible unless an advanced event
# selector on AWS::Cognito::IdentityPool was configured beforehand. After the deletion it can
# never be reconstructed.
title: Cognito identity pool deleted by a principal outside the pool-lifecycle pipeline
id: aeec6977-f027-4bca-bb5a-7016191e7356
name: cognito_identitypool_deleted_nonpipeline
status: experimental
description: >-
  An identity pool was deleted by a principal that does not own identity-pool lifecycle. Deletion
  is permanent - AWS documents no undo, no retention window and no restore path - and it destroys
  every identity, every developer-provider linkage and the pool ID that every deployed client is
  hard-coded against. The IAM roles survive as orphans.
references:
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1531/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_DeleteIdentityPool.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
  - attack.t1531
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-identity.amazonaws.com'
    eventName: 'DeleteIdentityPool'
  # POPULATE BEFORE DEPLOYING. Unpopulated, this fires on every pipeline teardown. The allowlist
  # IS the discriminator - the event name carries no signal on its own.
  pool_lifecycle_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace with this account's deployment role
      - ':role/BreakGlassAdmin'     # replace with this account's break-glass role
  success:
    errorCode: null
  condition: selection and success and not pool_lifecycle_pipeline
falsepositives:
  - >-
    An engineer destroying a personal or ephemeral identity pool outside the pipeline. Common in
    development accounts and rare in production ones; if it is common in production, the finding is
    that identity-pool lifecycle is not owned by the pipeline.
level: high
---
title: Cognito identity pool reconfigured
id: e78b7209-b06a-40c2-ad9f-b194018f66c1
name: cognito_identitypool_reconfigured_bb
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. Both UpdateIdentityPool and
  SetIdentityPoolRoles are full-replacement writes, so either one is a whole-configuration change
  rather than a field edit.
references:
  - https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_SetIdentityPoolRoles.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-identity.amazonaws.com'
    eventName:
      - 'UpdateIdentityPool'
      - 'SetIdentityPoolRoles'
      - 'CreateIdentityPool'
  success:
    errorCode: null
  condition: selection and success
level: low
---
# Reconfigure-then-destroy. An identity pool that is changed and then deleted within a day is
# either a rollback - somebody noticed a guest-access mistake and removed the pool - or the
# cleanup half of an abuse: the pool was made to vend credentials, used, and then destroyed so
# that its configuration cannot be read back. CloudTrail cannot tell those apart, and neither can
# this rule, so it is `high` rather than `critical` and the falsepositive says which is which.
#
# Twenty-four hours rather than minutes, because the abusive version is not a burst: the pool has
# to be used between the two calls for the destruction to be worth making.
title: Cognito identity pool reconfigured and then deleted
id: f653093c-ca8a-484a-b1b3-f162fb5061b9
status: experimental
description: >-
  An identity pool's configuration or role mapping was changed and the pool was deleted within
  twenty-four hours. If the change enabled unauthenticated access or attached an unauthenticated
  role, the deletion removes the only record of what the pool was configured to hand out.
references:
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: temporal_ordered
  rules:
    - cognito_identitypool_reconfigured_bb
    - cognito_identitypool_deleted_nonpipeline
  group-by:
    - requestParameters.identityPoolId
  timespan: 24h
falsepositives:
  - >-
    A responder or an engineer remediating a guest-access misconfiguration by removing the pool
    outright. Distinguishable by whether the deleting principal is the one that made the change and
    by whether a ticket exists.
level: high
---
# Three or more identity pools destroyed by one principal inside ten minutes is not maintenance.
# Nothing a person does by hand reaches that rate, and the one process that legitimately does -
# a stack teardown - runs under the pipeline role, which the base rule already excludes. `gte` at
# the baseline, never `gt`, so a run that destroys exactly three does not fall through (F6). The
# source rule has no volume logic at all; this is added rather than inherited, and the number is
# derived from the technique's shape rather than from an observed baseline - re-derive it against
# your own account before deploying.
title: Cognito identity pools destroyed at volume by one principal
id: a5f0ccc6-36fa-4df4-8919-4a4ee24d27cb
status: experimental
description: >-
  One non-pipeline principal deleted three or more identity pools inside ten minutes. Every one is
  permanently gone, and the recovery work-list is every pool in the group plus every client
  hard-coded against its ID.
references:
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
  - attack.t1531
correlation:
  type: event_count
  rules:
    - cognito_identitypool_deleted_nonpipeline
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gte: 3
level: critical
---
# Denials are kept as their own rule and are never counted as deletions. A principal walking the
# account's identity pools to find one it can destroy produces the same event volume as a real
# destruction, and conflating the two puts reconnaissance and an outage in the same bucket.
#
# Note the code: Cognito Identity returns NotAuthorizedException at HTTP 400 for an authorization
# failure, not a 403 - so a rule keyed on the status code rather than the exception name misses
# it. AccessDeniedException is carried too, for the IAM-layer form.
title: Cognito identity pool deletion refused
id: 548959dd-e4c1-4321-b967-fa65aceed86e
status: experimental
description: >-
  A DeleteIdentityPool call was refused. Repeated refusals across pools are a principal mapping its
  own boundary, which is intent without impact and belongs in a different queue from a completed
  destruction.
references:
  - https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/CommonErrors.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cognito-identity.amazonaws.com'
    eventName: 'DeleteIdentityPool'
  denied:
    errorCode:
      - 'NotAuthorizedException'
      - 'AccessDeniedException'
  condition: selection and denied
level: medium
```

The rule cannot say what the pool contained or handed out — `DeleteIdentityPool` carries only the
pool ID and no useful `responseElements` — and it cannot see the orphaned IAM roles at all, because
they live in IAM and no Cognito event names them. `detections/kql_t1485.kql` joins each deletion
back to the pool's configuration history so the guest-access flag and role ARNs survive the
resource that carried them; Query 2 sweeps IAM for the orphans.

---

### Key Investigation Queries

> Identity pools are regional — run these in the pool's Region, except the IAM sweep, which is global and lands in `us-east-1`. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: which pool, who destroyed it, and what it was configured to hand out

```bash
REGION="us-east-1"
RAW=$(for EV in DeleteIdentityPool UpdateIdentityPool CreateIdentityPool SetIdentityPoolRoles; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong Region, or"
  echo "    missing cloudtrail:LookupEvents. This is NOT 'no identity pool was deleted'."
else
  # Lower-camel casing is VERIFIED here by AWS's published CreateIdentityPool example. Ninety days
  # deliberately: these events are the only surviving record of the pool's flag and its role ARNs.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "cognito-identity.amazonaws.com") |
    {time: .eventTime, event: .eventName,
     caller_arn: (.userIdentity.arn // "no-arn"),
     access_key: (.userIdentity.accessKeyId // "none"),
     pool_id: (.requestParameters.identityPoolId // .responseElements.identityPoolId // "unknown"),
     pool_name: (.requestParameters.identityPoolName // .responseElements.identityPoolName // null),
     allow_unauth: (.requestParameters.allowUnauthenticatedIdentities //
                    .responseElements.allowUnauthenticatedIdentities // null),
     unauth_role: (.requestParameters.roles.unauthenticated // null),
     auth_role: (.requestParameters.roles.authenticated // null),
     ip: .sourceIPAddress, agent: .userAgent,
     error: (.errorCode // "SUCCESS")}' |
  jq -s 'sort_by(.pool_id, .time)'
fi
```

Read it per `pool_id`. The `SetIdentityPoolRoles` and `Create`/`UpdateIdentityPool` rows before a
deletion are the pool's obituary: `unauth_role` and `auth_role` are the ARNs Query 2 must sweep, and
`allow_unauth` says whether the pool was handing AWS credentials to anonymous callers. A change
shortly before the deletion is either a rollback or the cleanup half of an abuse and CloudTrail
cannot tell them apart — resolve it against a change record, not by inference. Repeated
`NotAuthorizedException` values across different `pool_id`s are boundary mapping; count them
separately. Record `pool_id`, `caller_arn`, `access_key` and both role ARNs as IOCs.

#### Query 2 — Sweep IAM for the roles the deletion left behind

```bash
DEAD_POOL="<pool-id-from-Query-1>"
ROLES=$(aws iam list-roles --output json)          # IAM is global; events land in us-east-1
if [ -z "$ROLES" ]; then
  echo "[!] INCONCLUSIVE - list-roles returned nothing. The orphan set is unknown, not empty."
  exit 0
fi
COUNT=$(printf '%s' "$ROLES" | jq '.Roles | length')
# Every account has roles. A non-positive count means the CALL failed, not that the estate is
# clean - reporting it as "no orphans" would be a false all-clear over a live cross-account door.
if [ "${COUNT:-0}" -le 0 ]; then
  echo "[!] INCONCLUSIVE - list-roles returned zero roles. That is a failed sweep, not a clean one."
else
  # list-roles hands back AssumeRolePolicyDocument ALREADY PARSED - that is botocore's
  # after-call.iam handler, not a documented property, so do not decode it again. Statement is an
  # object OR an array and Principal.Federated is a string OR an array; both are normalised here,
  # because iterating an object crashes the filter and silently empties the sweep (D3).
  printf '%s' "$ROLES" | jq -r --arg dead "$DEAD_POOL" '
    def stmts: (.Statement // []) | if type == "object" then [.] else . end;
    def fed:   (.Principal.Federated // []) | if type == "string" then [.] else . end;
    .Roles[] | . as $r |
    (($r.AssumeRolePolicyDocument // {}) | stmts
      | map(select(.Effect == "Allow" and (fed | any(. == "cognito-identity.amazonaws.com"))))) as $c |
    select(($c | length) > 0) |
    {role: $r.RoleName, arn: $r.Arn,
     aud: [$c[] | (.Condition.StringEquals."cognito-identity.amazonaws.com:aud" //
                   .Condition."ForAnyValue:StringEquals"."cognito-identity.amazonaws.com:aud" //
                   empty)] | flatten,
     amr: [$c[] | (.Condition."ForAnyValue:StringLike"."cognito-identity.amazonaws.com:amr" //
                   .Condition."ForAnyValue:StringEquals"."cognito-identity.amazonaws.com:amr" //
                   empty)] | flatten} |
    . + {verdict: (if (.aud | length) == 0
                     then "[FAIL] UNPINNED - no aud condition. AWS: STS permits web identities to assume roles not secured with conditions, so ANY identity pool - including one in an attacker account - can assume this role"
                   elif (.aud | index($dead))
                     then "[FAIL] ORPHANED - pinned to the deleted pool. Its permissions are still attached and nothing can assume it, but nothing has reviewed them either"
                   elif (.amr | length) == 0
                     then "[FAIL] NO amr CONDITION - a guest token and an authenticated token satisfy this trust identically"
                   else "[OK] pinned to a live pool with an amr condition" end)}'
fi
```

Run this **before** anything is cleaned up. Every `[FAIL] UNPINNED` line is a role assumable through
an identity pool the attacker controls in their own account — unrelated to whether this deletion was
malicious; the deletion is simply when somebody looked. `ORPHANED` roles are inert but still carry
their permissions, and are the only surviving record of what the pool could reach: document first.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="AccessDeniedException CreateIdentityPool NotAuthorizedException SetIdentityPoolRoles UpdateIdentityPool"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "cognito-identity.amazonaws.com") |
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

The pool is gone and **nothing recovers it** — no retention window, no Support path — so do not
spend the first fifteen minutes on one. Containment is about the pools that remain and the orphaned
roles: stop the principal before rebuilding, because rebuilding while the actor still holds
`cognito-identity:DeleteIdentityPool` invites a second deletion.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Confirm the pool is gone, and stop the principal destroying another

```bash
REGION="us-east-1"; DEAD_POOL="<pool-id-from-Query-1>"
SUSPECT_ARN="<caller-arn-from-Query-1>"

# D-0: an API error here is a specific state, not a pass and not a generic failure.
# ResourceNotFoundException confirms the deletion; anything else means the check did not run.
D=$(aws cognito-identity describe-identity-pool --identity-pool-id "$DEAD_POOL" \
      --region "$REGION" --output json 2>&1)
case "$D" in
  *ResourceNotFoundException*)
    echo "[CONFIRMED] $DEAD_POOL is deleted. AWS documents NO undo, NO retention window and NO"
    echo "            Support restore path - do not open a case. Move to the orphans and the rebuild.";;
  *IdentityPoolId*)
    printf '%s' "$D" | jq -r '"[i] pool still EXISTS (wrong Region, or the delete failed): allowUnauth=\(.AllowUnauthenticatedIdentities)"';;
  *NotAuthorized*|*AccessDenied*)
    echo "[!] INCONCLUSIVE - the responder credential cannot read this pool. Nothing was determined.";;
  *) echo "[!] INCONCLUSIVE - describe-identity-pool failed unexpectedly: $D";;
esac

DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["cognito-identity:DeleteIdentityPool","cognito-identity:UpdateIdentityPool","cognito-identity:SetIdentityPoolRoles","cognito-identity:DeleteIdentities","cognito-idp:DeleteUserPool"],"Resource":"*"}]}'
case "$SUSPECT_ARN" in
  *:user/*)         U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')   # user ARN: LAST segment
                    aws iam put-user-policy --user-name "$U" \
                      --policy-name "EmergencyDenyCognitoDestroy" --policy-document "$DENY"
                    echo "[OK] denied Cognito destruction for user $U";;
  *:assumed-role/*) R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')    # role ARN: 2ND segment
                    aws iam put-role-policy --role-name "$R" \
                      --policy-name "EmergencyDenyCognitoDestroy" --policy-document "$DENY"
                    echo "[OK] denied Cognito destruction for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - contain manually.";;
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
    # E4: revokes tokens issued BEFORE the cutoff only - a credential re-fetched afterwards carries
    # a newer TokenIssueTime and is not denied, which is why Step 1's action deny went on first.
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    echo "[OK] revoked pre-$CUTOFF sessions for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - contain manually.";;
esac
```

---

## 4. Eradication

### Remove Attacker Access

- **Deal with the orphaned roles before rebuilding: document, then re-pin, then delete.** Their
  attached and inline policies are the only surviving description of what the pool could reach —
  `list-attached-role-policies` returns managed policies only, so `list-role-policies` and
  `get-role-policy` are both needed. Re-pin the trust `aud` to the new pool ID for the roles the
  rebuild reuses and delete the rest. **Every `[FAIL] UNPINNED` role from Query 2 is urgent
  independently of this incident** — it is assumable through any identity pool, including one in an
  attacker's own account.
- **Rebuild from infrastructure code, and expect a new ID** — `CreateIdentityPool` has no parameter
  for requesting one. Reattach roles with `SetIdentityPoolRoles`, a **full-replacement** write
  capped at two entries: a call sending only `authenticated` removes the `unauthenticated` mapping.
  Set `AllowUnauthenticatedIdentities` deliberately — it is `Required: Yes` on both create and
  update, so there is no "leave it as it was".
- **Re-release the clients.** The pool ID is hard-coded into mobile binaries and JavaScript
  bundles, so a new ID means a build and a release, not a config push. Until then every affected
  application fails at sign-in with no server-side error to correlate.
- **Rebuild the developer-provider linkage from your own systems, or accept its loss.** The
  `DeveloperProviderName` and every `LookupDeveloperIdentity` mapping died with the pool, so a new
  pool needs the mapping table regenerated from the backend that owns those user IDs.
- **Right-size the permission and turn on data events.** `cognito-identity:DeleteIdentityPool` is
  needed by nothing at runtime, and unlike a user pool there is **no deletion-protection flag** to
  fall back on — the IAM grant is the only control. Enable data events on
  `AWS::Cognito::IdentityPool` for the rebuilt pool, or the next incident again has no usage record.
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

#### Verify the replacement pool is configured as intended and no role is left unpinned

```bash
REGION="us-east-1"
NEW_POOL="<identity-pool-id-of-the-rebuilt-pool>"
DEAD_POOL="<pool-id-from-Query-1>"

# The assertion is on the REPLACEMENT, never on the dead pool. A ResourceNotFoundException from
# DEAD_POOL is the expected permanent state and proves nothing about the rebuild - querying it
# here would be the false-[OK] trap this section exists to avoid.
P=$(aws cognito-identity describe-identity-pool --identity-pool-id "$NEW_POOL" \
      --region "$REGION" --output json 2>&1)
R=$(aws cognito-identity get-identity-pool-roles --identity-pool-id "$NEW_POOL" \
      --region "$REGION" --output json 2>&1)
ROLES=$(aws iam list-roles --output json)

case "$P" in
  *IdentityPoolId*) : ;;
  *) echo "[!] INCONCLUSIVE - the replacement pool could not be read: $P"; P="";;
esac
case "$R" in
  *Roles*) : ;;
  *) echo "[!] INCONCLUSIVE - get-identity-pool-roles failed: $R"; R="";;
esac

if [ -z "$P" ] || [ -z "$R" ] || [ -z "$ROLES" ]; then
  echo "[!] INCONCLUSIVE - one or more reads failed. Recovery is unverified, not complete."
else
  UNAUTH_FLAG=$(printf '%s' "$P" | jq -r '.AllowUnauthenticatedIdentities')
  AUTH_ROLE=$(printf '%s' "$R" | jq -r '.Roles.authenticated // empty')
  UNAUTH_ROLE=$(printf '%s' "$R" | jq -r '.Roles.unauthenticated // empty')
  # Every account has roles, so a non-positive count is a failed sweep and must not read as clean.
  RC=$(printf '%s' "$ROLES" | jq '.Roles | length')
  UNPINNED=$(printf '%s' "$ROLES" | jq --arg dead "$DEAD_POOL" '
    def stmts: (.Statement // []) | if type == "object" then [.] else . end;
    def fed:   (.Principal.Federated // []) | if type == "string" then [.] else . end;
    [.Roles[] | (.AssumeRolePolicyDocument // {}) | stmts
      | map(select(.Effect == "Allow" and (fed | any(. == "cognito-identity.amazonaws.com"))))
      | select(length > 0)
      | select(all(.[]; (.Condition.StringEquals."cognito-identity.amazonaws.com:aud" //
                         .Condition."ForAnyValue:StringEquals"."cognito-identity.amazonaws.com:aud" //
                         null) == null
                        or ((.Condition.StringEquals."cognito-identity.amazonaws.com:aud" //
                             .Condition."ForAnyValue:StringEquals"."cognito-identity.amazonaws.com:aud")
                            | tostring | contains($dead))))] | length')
  if   [ "${RC:-0}" -le 0 ]; then
    echo "[!] INCONCLUSIVE - the IAM role sweep returned zero roles. That is a failed sweep."
  elif [ "${UNPINNED:-x}" = "x" ]; then
    echo "[!] INCONCLUSIVE - the trust-policy filter produced no result; orphan count unknown."
  elif [ "$UNPINNED" -gt 0 ]; then
    echo "[FAIL] $UNPINNED role(s) still trust cognito-identity with no aud condition, or are still"
    echo "       pinned to the deleted pool $DEAD_POOL. Re-run Query 2 and fix them."
  elif [ -z "$AUTH_ROLE" ]; then
    echo "[FAIL] $NEW_POOL has no authenticated role attached - SetIdentityPoolRoles is a full"
    echo "       replacement and the reattach did not carry it"
  elif [ "$UNAUTH_FLAG" = "true" ] && [ -z "$UNAUTH_ROLE" ]; then
    echo "[FAIL] $NEW_POOL allows unauthenticated identities with NO unauthenticated role -"
    echo "       every guest GetCredentialsForIdentity will fail with"
    echo "       InvalidIdentityPoolConfigurationException"
  else
    echo "[OK] $NEW_POOL: allowUnauthenticatedIdentities=$UNAUTH_FLAG, authenticated role set,"
    echo "     unauthenticated role='${UNAUTH_ROLE:-none}', and no unpinned or orphaned Cognito"
    echo "     trust remains across $RC role(s)"
  fi
fi
```

Every branch is reachable after the remediation: the replacement pool and the IAM roles all exist
and answer. The two failure modes it catches are the real ones — a `SetIdentityPoolRoles` that
dropped a mapping because it is a full replacement, and an orphaned or unpinned trust that survived
the rebuild because nothing in Cognito points at it.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     DeleteIdentityPool / cognito-identity.amazonaws.com / no errorCode, where"
echo "  userIdentity.arn is NOT on the identity-pool-lifecycle allowlist. The volume correlation"
echo "  must fire at exactly three such events in ten minutes from one principal - gte, not gt."
echo "MUST NOT fire on: DeleteUserPool, which is cognito-idp.amazonaws.com and a different use case;"
echo "  a DeleteIdentityPool that returned NotAuthorizedException or AccessDeniedException, which is"
echo "  an attempt and has its own rule at its own priority."
echo "EXPECTED FP, by design: an engineer destroying a personal or ephemeral pool outside the"
echo "  pipeline. If that is common in production, the finding is that identity-pool lifecycle is"
echo "  not owned by the pipeline."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the pipeline could permanently destroy a federation resource | `cognito-identity:DeleteIdentityPool` granted to an identity that never needs it; no SCP confining it, and identity pools have no deletion-protection flag to fall back on |
| The deletion was not distinguished from routine teardown, and the alert could not say which pool | The source rule matched the event name with no principal check and never surfaced `requestParameters.identityPoolId` |
| Nobody could say how many identities were lost or who had used the pool | Data events on `AWS::Cognito::IdentityPool` were off — the default — and there is no identity-pool metric or log export to fall back on |
| Roles trusting the deleted pool were still present days later, one with no `aud` condition | No inventory of roles trusting `cognito-identity.amazonaws.com`; they are not deleted with the pool and no Cognito event names them |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document). StringNotLike
// is required because the value is wildcarded: Deny + StringNotEquals against a wildcarded ARN
// matches every principal and denies identity-pool lifecycle outright - an outage.
{
  "Effect": "Deny",
  "Action": ["cognito-identity:DeleteIdentityPool", "cognito-identity:DeleteIdentities"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- The SCP reaches the caller: `DeleteIdentityPool` is IAM-authorized, so `aws:PrincipalArn` is
  always populated and D-i does not apply. Pair it with the pool's configuration in IaC — after a
  deletion the only place the guest-access flag and role ARNs still exist — with data events on
  `AWS::Cognito::IdentityPool`, and with a periodic sweep for roles trusting
  `cognito-identity.amazonaws.com` with no `aud` condition, which is a standing cross-account
  exposure independent of any deletion.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1485 — Data Destruction (primary, and the source's own label); T1531 — Account Access Removal (secondary — every federated identity loses its route to AWS credentials) |
| Primary API | `cognito-identity:DeleteIdentityPool`; `SetIdentityPoolRoles` and `UpdateIdentityPool` as the configuration history that outlives the pool |
| Event source | `cognito-identity.amazonaws.com`, **management** plane, on by default, regional — **not** `cognito-idp.amazonaws.com`, which is user pools. A rule on the wrong source returns zero forever |
| Key discriminator | The calling principal. `DeleteIdentityPool` is what every teardown does; only `userIdentity.arn` separates destruction from maintenance |
| Field shape | `requestParameters.identityPoolId`, lower-camel — **verified for this service** by AWS's published `CreateIdentityPool` example (`identityPoolName`, `allowUnauthenticatedIdentities`, `responseElements.identityPoolId`), though no example exists for the delete itself. Pool ID form is `REGION:GUID`, pattern `[\w-]+:[0-9a-f-]+` |
| "Was it used" pivot | Only where data events on `AWS::Cognito::IdentityPool` were already on: `GetId` and `GetCredentialsForIdentity` are **data events, off by default**. There is no identity-pool metric and, per AWS, *"no log export capabilities exist for identity pools"* — so absence is never evidence of non-use |
| Blast radius | The pool, its configuration, every identity, every developer-provider linkage and the pool ID every client is hard-coded against. **The IAM roles survive**, with their permissions and their trust policies, and an unpinned trust is assumable through any identity pool including one in another account |
| Error strings | `DeleteIdentityPool`: `InternalErrorException` (500), `InvalidParameterException`, `NotAuthorizedException`, `ResourceNotFoundException`, `TooManyRequestsException` — all 400 except the first. **An authorization failure is `NotAuthorizedException` at HTTP 400, not a 403**; match the exception name and carry `AccessDeniedException` for the IAM-layer form. Neighbouring APIs add `ConcurrentModificationException`, `LimitExceededException` and `ResourceConflictException` |

### Residual Risk

The pool is gone and **there is no restore**. Unlike a user pool, which AWS retains inactive for
fourteen days, an identity pool has no retention window, no recycle bin and no Support path — the
console warning is *"You can't undo identity pool deletion."* Every identity and developer-provider
linkage is unrecoverable, and no count exists unless a `list-identities` snapshot was already being
taken: there is no metric and no log export for identity pools, so the size of the loss is
permanently unknown rather than zero.

The rebuilt pool has a new ID, so every deployed client is broken until it is re-released, and
users meanwhile see a sign-in failure with no server-side error to correlate. If data events were
off — the default — there is no record of who the destroyed pool vended credentials to: any session
it issued in its last hour is untraceable, and those credentials stayed valid for their full hour
after the pool ceased to exist.

The orphaned IAM roles outlive everything else. They keep their permissions, and one whose trust
policy carries no `aud` condition is assumable through an identity pool an attacker creates in their
own account — a standing cross-account door that has nothing to do with this deletion and that
nothing in Cognito will ever surface.
