# IR Playbook: High Number of SSM Parameters Retrieval — Bulk `SecureString` Decryption via `ssm:GetParametersByPath` and `ssm:GetParameters`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential access (a principal reads Parameter Store `SecureString` values with `WithDecryption` set, at a scope no configuration loader needs, and leaves with plaintext database passwords, API keys and tokens) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High.** `SecureString` is where an AWS estate keeps the credentials it cannot put in IAM: RDS master passwords, third-party API keys, webhook signing secrets, service-account tokens. Every one of those authenticates outside AWS's authorisation boundary, so containing the AWS principal does nothing to them — the only revocation is rotation at each system of record. Severity scales with what the drained path fronts; a path holding a database credential or a long-lived access key makes this account-level rather than service-level. The source rule rates it P3 while its own metadata carries a `high` severity label, and P3 routes a live plaintext credential disclosure to a queue read the next business day |
| MITRE Tactics | Credential Access |
| MITRE Techniques | T1555.006 |
| Services in Scope | Systems Manager (Parameter Store), KMS, CloudTrail, IAM, STS, plus every system whose credential was stored as a parameter — RDS, third-party SaaS, internal services |

**What the technique does:** The actor holds a principal with `ssm:GetParameter*`
and `kms:Decrypt`. They call `GetParametersByPath` with `Path` set to a hierarchy
root, `Recursive` true and `WithDecryption` true. Parameter Store walks the
hierarchy, calls KMS `Decrypt` once per `SecureString` value, returns up to ten
parameters per page with plaintext values, and the actor follows `NextToken` until
the path is exhausted — a 500-parameter hierarchy is fifty requests and a few
seconds. `GetParameters` is the same move by name, ten per call; `GetParameter` is
the single-target version. At the end the actor holds plaintext for every secret
under the path, and none of it expires.

**Why this is potent, and why the usual reflexes miss it.** The first reflex is to
assume a high-volume read API must be data-plane, conclude the reads are not logged,
and blanket-rotate. That is wrong and expensive: AWS states *"Systems Manager logs
all control plane operations to CloudTrail as management events"*, and the only SSM
data events are the Session Manager control channel and the managed-node role-token
call — every parameter read is in a default trail, named. The second reflex, counting
events as the blast radius, under-reports by up to ten times, because `GetParameters`
takes ten names per call and `GetParametersByPath` returns ten per page whose names
are not in the event. The third, `Deny` on the parameters that were read, is defeated
by a recursive `GetParametersByPath` on the parent path, which AWS documents returns
children the caller was explicitly denied. The fourth — rotate the parameter — is not
a revocation at all: the old value keeps working until the credential behind it is
changed at the system that honours it.

**Detection is `WithDecryption`, and the count that matters is KMS's, not SSM's.**
Reading a `String` parameter is how nearly every workload on AWS gets its
configuration; decrypting a `SecureString` is the credential access, and AWS
states the flag "is ignored for `String` and `StringList` parameter types", so its
presence means the caller wanted plaintext of encrypted material. The source rule
never inspects it — despite its own description saying the alert is for a user who
"retrieves and decrypts" — never filters to successful calls, and omits
`GetParametersByPath` entirely, so the highest-yield call in the API cannot raise
it.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

- CloudTrail multi-region trail. Systems Manager control-plane calls are
  **management events, on by default**; the only SSM data events are
  `CreateControlChannel` / `OpenControlChannel` on
  `AWS::SSMMessages::ControlChannel` and `RequestManagedInstanceRoleToken` on
  `AWS::SSM::ManagedNode`. Parameter reads are not among them
- **Confirm the trail is not `ReadWriteType: WriteOnly`.** `Get*` calls are
  read-only management events; a write-only trail discards every one of them, and
  the queries below then return nothing while the events themselves existed
- Read events carry `userIdentity.arn`, `userIdentity.accessKeyId`,
  `sourceIPAddress`, `awsRegion`, and in `requestParameters` one of `name`
  (GetParameter), `names` — up to 10 (GetParameters) — or `path` plus `recursive`
  (GetParametersByPath), alongside `withDecryption`. The API Reference documents
  the wire spelling (`WithDecryption`, `Recursive`); AWS's published
  `ssm.amazonaws.com` CloudTrail examples render request keys with a lower-case
  initial, so read both until you confirm which your trail emits
- **The parameter value is never in CloudTrail** — it lives in the response body,
  which read APIs do not carry into `responseElements`. You learn what was taken,
  not what it was
- `kms:Decrypt` events, same trail, same management category. Parameter Store binds
  `{"PARAMETER_ARN": "arn:aws:ssm:<region>:<account>:parameter/<name>"}` as the
  encryption context on every `SecureString` operation, and AWS documents that it
  "appears in plaintext in logs, such as AWS CloudTrail logs" — the only telemetry
  that counts **parameters** rather than **API calls**
- A scheduled parameter inventory. `DescribeParameters` with
  `Key=Path,Option=Recursive` returns metadata only — `Name`, `Type`, `KeyId`,
  `Version`, `LastModifiedDate`, `LastModifiedUser`, never `Value` — and answers only
  for *now*; without a snapshot a drain cannot be reconstructed against *then*

**Alerting (must be pre-configured)**

- **Successful `GetParametersByPath` with `recursive` and `withDecryption` both true, by a principal outside the configuration-loader allowlist → P0**
- **30 or more distinct `PARAMETER_ARN` values across `kms:Decrypt` encryption contexts from one principal in five minutes → P0**
- **30 or more successful decrypting parameter reads by one principal in five minutes → P1**
- **A decrypting parameter read by an instance-profile session from an address outside that instance's egress set → P1**

**Response Tooling**

- AWS CLI v2 and `jq`. Break-glass responder credentials separate from every
  principal under investigation, and specifically not an instance-profile role that
  reads parameters itself
- The **rotation runbook per secret class** — which system of record owns each
  credential and who can rotate it out of hours. This is the long pole: the AWS half
  of this incident is over in twenty minutes and the rotation half is not
- A record of which KMS key each path uses; AWS states you "cannot establish access
  control policies for the default `aws/ssm` KMS key", so parameters on it have no
  encryption-context guardrail available. Plus the Regions in use — Parameter Store
  is regional, and a drain in an unused Region is invisible to a single-Region query

**Known IOC Baselines**

- The principals that legitimately bulk-read a path — application task roles, node
  roles, the pipeline's configuration loader — held as ARN fragments so a new task
  revision does not break the allowlist, plus the expected read shape for each: a
  task role that reads eight parameters at boot and never again is a different
  baseline from a poller
- Which paths hold `SecureString` and which hold plain configuration, so a P0 is
  triaged in one lookup rather than one per parameter

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Successful `GetParametersByPath` with `recursive` and `withDecryption` both true, by a principal outside the configuration-loader allowlist | CloudTrail (management) | T1555.006 |
| P0 | 30 or more distinct `PARAMETER_ARN` values across `kms:Decrypt` encryption contexts from one principal in five minutes | CloudTrail (management) | T1555.006 |
| P1 | 30 or more successful decrypting parameter reads by one principal in five minutes | CloudTrail (management) | T1555.006 |
| P1 | A decrypting parameter read by an instance-profile session from an address outside that instance's egress set | CloudTrail (management) | T1555.006, T1078.004 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `DescribeParameters` followed by decrypting reads from the same principal in one session — inventory then collect | CloudTrail (management) | T1526, T1555.006 |
| P2 | `kms:Decrypt` denied with a Parameter Store encryption context — the caller has `ssm:GetParameter*` but not the key | CloudTrail (management) | T1555.006 |
| P3 | `GetParameter` on a `SecureString` **without** decryption, then a direct `kms:Decrypt` by the same principal — ciphertext taken for offline decryption | CloudTrail (management) | T1555.006 |
| P3 | Any decrypting read in a Region where the account runs no workload | CloudTrail (management) | T1555.006 |

### Detection Rule Quality Notes

The source rule counts an event name and nothing else: no decryption flag, no
success filter, no `GetParametersByPath`, and a threshold its own description
contradicts.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `WithDecryption` never inspected, though the description says "retrieves and decrypts" | A service reading 50 plaintext `String` parameters at boot fires the identical P3 as an actor decrypting 50 `SecureString` secrets; the alert cannot be triaged without opening every event | Require `requestParameters.withDecryption: true` as a sibling block |
| `GetParametersByPath` omitted | The highest-yield call in the API never raises the rule — a recursive drain of a whole hierarchy is invisible to it | Add it to the event-name set, and alert on `recursive` + `withDecryption` as P0 on a single event |
| No success filter | A principal denied 50 times raises the same alert as one that succeeded 50 times, and the rotation work-list built from it names parameters that were never disclosed | `success: {errorCode: null}` on every counting rule, base rules included |
| Threshold counts API calls, not parameters | `GetParameters` takes 10 names and `GetParametersByPath` returns up to 10 per page, so 50 events can be 500 secrets — and 200 secrets is only 20 events, under the threshold | Count distinct `requestParameters.encryptionContext.PARAMETER_ARN` on `kms:Decrypt` instead |
| Threshold 50 contradicts the rule's own description of 30 | One of the two is wrong, and a deployer tuning from the description gets a rule that fires far less often than they believe | Both correlations use 30, the figure the description names, and say so |
| Grouped by `userIdentity.arn` only | For an assumed role the ARN carries the session name, so a slow drain spread across sessions of one role never accumulates | Keep the ARN group-by for precision; pivot on `sessionContext.sessionIssuer.userName` during investigation (Query 4) |

**Recommended detection — a whole parameter hierarchy decrypted in one call.**

```yaml
# High Number of SSM Parameters Retrieval (T1555.006)
#
# The original rule counted `GetParameter OR GetParameters` events, 50 in five
# minutes, grouped by userIdentity.arn, with no other condition. Three defects.
# It never inspects `WithDecryption`, although its own description says
# "retrieves and decrypts" — so it counts an application reading fifty plaintext
# `String` parameters at boot exactly the same as an actor decrypting fifty
# `SecureString` values. It omits `GetParametersByPath`, the one call that drains
# an entire hierarchy per request, so the highest-yield path is invisible. And it
# has no success filter, so a principal denied fifty times fires the identical
# alert as one that succeeded fifty times.
#
# Counting EVENTS also under-counts the blast radius by up to 10x: GetParameters
# takes up to 10 names per call and GetParametersByPath returns up to 10
# parameters per page (AWS SSM API Reference, MaxResults max 10). The correlation
# below counts KMS Decrypt operations instead — Parameter Store passes the
# encryption context {"PARAMETER_ARN": "<parameter ARN>"} on every SecureString
# decrypt and AWS documents that the encryption context "appears in plaintext in
# logs, such as AWS CloudTrail logs". That yields one countable, individually
# named parameter per decrypt rather than one per API call.
#
# FIELD CASING: the SSM API Reference documents the wire format (`WithDecryption`,
# `Recursive`). AWS's own published ssm.amazonaws.com CloudTrail examples render
# request keys with a lower-case initial (`requestParameters.name` on
# DeleteDocument), so the rules below key on `withDecryption` / `recursive`.
# Confirm against one real event from your own trail before deploying.
title: SSM parameter hierarchy drained with decryption in a single call
id: f9629b0e-ca03-499e-8e93-2cdeb82cd55c
name: ssm_path_drain_decrypted
status: experimental
description: >-
  A successful GetParametersByPath with Recursive and WithDecryption both set
  returns every SecureString value beneath a path in one request. The parameter
  names are not in the CloudTrail event, so the set retrieved must be
  reconstructed from the path.
references:
  - https://attack.mitre.org/techniques/T1555/006/
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParametersByPath.html
  - https://docs.aws.amazon.com/kms/latest/developerguide/services-parameter-store.html
tags:
  - attack.credential-access
  - attack.t1555.006
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'GetParametersByPath'
  decrypt:
    requestParameters.withDecryption: true
  recursive:
    requestParameters.recursive: true
  success:
    errorCode: null
  config_loaders:                      # tune: principals that legitimately bulk-read a path
    userIdentity.arn|contains:
      - ':role/app-config-loader'
      - ':role/ecs-task-'
      - ':role/eks-node-'
  condition: selection and decrypt and recursive and success and not config_loaders
falsepositives:
  - Application bootstrap that reads its whole configuration path with decryption — allowlist the specific task or node role, never the whole account
  - A deployment tool exporting an environment's parameters for a migration — should be time-boxed and traceable to a change record
level: high
---
title: Many distinct SSM SecureString parameters decrypted by one principal
id: bc3639fd-a0fd-4bbf-9e84-141723e0e5f4
status: experimental
description: >-
  Counts distinct parameters actually decrypted, using the PARAMETER_ARN
  encryption context on each KMS Decrypt, rather than counting SSM API calls.
  One GetParametersByPath call can decrypt ten parameters, so an event count
  under-reports the number of secrets exposed.
references:
  - https://attack.mitre.org/techniques/T1555/006/
  - https://docs.aws.amazon.com/kms/latest/developerguide/services-parameter-store.html
tags:
  - attack.credential-access
  - attack.t1555.006
correlation:
  type: value_count
  rules:
    - kms_decrypt_parameter_store
  group-by:
    - userIdentity.arn
  timespan: 5m
  field: requestParameters.encryptionContext.PARAMETER_ARN
  condition:
    gte: 30
falsepositives:
  - A fleet-wide application restart decrypting its own configuration set — allowlist by role, and size the threshold above the largest legitimate configuration path
level: high
---
title: KMS Decrypt carrying a Parameter Store encryption context
id: 70cba2c2-8c50-48ac-bac3-65870c199826
name: kms_decrypt_parameter_store
status: experimental
description: >-
  Base rule — count component only, not for direct alerting. Every SecureString
  decrypt names its parameter in requestParameters.encryptionContext.PARAMETER_ARN.
references:
  - https://docs.aws.amazon.com/kms/latest/developerguide/services-parameter-store.html
tags:
  - attack.credential-access
  - attack.t1555.006
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'kms.amazonaws.com'
    eventName: 'Decrypt'
  parameter_context:
    requestParameters.encryptionContext.PARAMETER_ARN|contains: ':parameter/'
  success:
    errorCode: null
  condition: selection and parameter_context and success
level: low
---
title: High volume of decrypted SSM parameter reads by one principal
id: 6c4393fe-dd81-42e7-b602-92b2f30f7c2a
status: experimental
description: >-
  The corrected form of the original volume rule — restricted to reads that
  requested decryption, restricted to successful calls, and extended to
  GetParametersByPath. Retained alongside the KMS count because it still fires
  when the parameters read are plaintext String values holding credentials.
references:
  - https://attack.mitre.org/techniques/T1555/006/
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameters.html
tags:
  - attack.credential-access
  - attack.t1555.006
correlation:
  type: event_count
  rules:
    - ssm_decrypted_parameter_read
  group-by:
    - userIdentity.arn
  timespan: 5m
  condition:
    gte: 30
falsepositives:
  - An application polling its configuration on a short interval — the group-by is the caller ARN, so a single misbehaving service is allowlistable
level: medium
---
title: SSM parameter read requesting decryption
id: 8511dfa1-3e41-4125-a6c5-3342c28a12b6
name: ssm_decrypted_parameter_read
status: experimental
description: >-
  Base rule — count component only, not for direct alerting. A successful read
  of one or more parameters with WithDecryption set.
references:
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameter.html
tags:
  - attack.credential-access
  - attack.t1555.006
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName:
      - 'GetParameter'
      - 'GetParameters'
      - 'GetParametersByPath'
  decrypt:
    requestParameters.withDecryption: true
  success:
    errorCode: null
  condition: selection and decrypt and success
level: low
```

Three things this rule structurally cannot do. **It cannot see enumeration:** AWS
documents that "for the `DeleteParameter` and `GetParameter` actions, if the specified
parameter doesn't exist, the `ParameterNotFound` exception is not recorded in AWS
CloudTrail event logs", so name-guessing through the singular call emits nothing for
the misses, while the plural call returns HTTP 200 with unknown names in
`InvalidParameters` and no `errorCode`. Neither is separable on error code; the signal
is a caller whose read set has a low hit rate against the inventory. **It cannot see a
two-step decryption:** a caller can read the `SecureString` without `WithDecryption`,
take the ciphertext, and call `kms:Decrypt` directly with the `PARAMETER_ARN`
encryption context — AWS documents that this works — which is why the shipped ruleset
counts on the KMS side. **It cannot bound what a path drain returned:** the response is
not logged, so Query 3 sizes it from the inventory and Query 2 gives the exact set.

### Key Investigation Queries

> Parameter Store is **regional** — run every query in each Region the account
> uses, not only the alerting one. Extraction uses
> `--output json | jq -r '.Events[].CloudTrailEvent | fromjson'`.
> **`lookup-events` returns ≤50 events per page**; paginate on `NextToken` or run
> the equivalent against your log platform for a busy window.

#### Query 1 — Reconstruct: who decrypted what, when, from where

```bash
REGION="<region>"
START="$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"

for EV in GetParameter GetParameters GetParametersByPath; do
  aws cloudtrail lookup-events --region "$REGION" \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$START" --max-results 50 --output json \
  | jq -r '.Events[].CloudTrailEvent | fromjson'
done | jq -s '
  # withDecryption is the discriminator. Accept both casings until you have
  # confirmed which one your own trail emits.
  map(select((.requestParameters.withDecryption // .requestParameters.WithDecryption) == true))
  | map(select(.errorCode == null))
  | map({
      time:      .eventTime,
      event:     .eventName,
      caller:    (.userIdentity.arn // "unknown"),
      accessKey: (.userIdentity.accessKeyId // "none"),
      session:   ((.userIdentity.arn // "") | split("/") | last),
      issuer:    (.userIdentity.sessionContext.sessionIssuer.userName // "n-a"),
      sourceIp:  .sourceIPAddress, agent: .userAgent, region: .awsRegion,
      path:      (.requestParameters.path // .requestParameters.Path // ""),
      recursive: ((.requestParameters.recursive // .requestParameters.Recursive) == true),
      names:     ([ (.requestParameters.name // .requestParameters.Name // empty) ]
                  + (.requestParameters.names // .requestParameters.Names // []))
    })
  | sort_by(.time)'
```

Read the `event` column first. A `GetParametersByPath` row with `recursive: true`
is the P0 shape — its `names` array is empty by construction, the names being in a
response CloudTrail does not record, so `path` is the only handle on what was
taken. `GetParameter` and `GetParameters` rows name parameters directly and are
already a rotation list. `session` is the last `/` segment of the ARN: for an EC2
instance-profile session that is the **instance ID**, which says the drain came
from a host and which one. `accessKey` is the pivot for Query 4. A `sourceIp` that
is a DNS name or `AWS Internal` means an AWS service made the call, so chase the
identity rather than the address.

#### Query 2 — The exact disclosed set, from the KMS encryption context

```bash
REGION="<region>"
START="$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"

aws cloudtrail lookup-events --region "$REGION" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt \
  --start-time "$START" --max-results 50 --output json \
| jq -r '.Events[].CloudTrailEvent | fromjson' \
| jq -s '
  map(select(.eventSource == "kms.amazonaws.com"))
  | map(select(.errorCode == null))
  | map(select(((.requestParameters.encryptionContext.PARAMETER_ARN) // "") | contains(":parameter/")))
  | map({ caller: (.userIdentity.arn // "unknown"), time: .eventTime,
          parameterArn: .requestParameters.encryptionContext.PARAMETER_ARN,
          keyId: (.requestParameters.keyId // "unknown") })
  | group_by(.caller)
  | map({ caller: .[0].caller, decrypts: length,
          distinct: ([.[].parameterArn] | unique | length),
          parameterArn: ([.[].parameterArn] | unique),
          keyId: ([.[].keyId] | unique),
          first: ([.[].time] | min), last: ([.[].time] | max) })
  | sort_by(-.distinct)'
```

`distinct` is the number of secrets disclosed — the real blast radius, and the
number for the incident record instead of the API-call count. The `parameterArn`
array is the rotation work-list: every ARN in it had its plaintext returned.
`keyId` says whether the parameters sat on `aws/ssm` or a customer managed key,
which decides whether an encryption-context guardrail is available afterwards. If
`distinct` far exceeds the parameters named in Query 1, the difference is what the
path drain returned.

This works for both parameter tiers by different routes — a standard
`SecureString` is decrypted directly under the key, an advanced one through the
AWS Encryption SDK's wrapped data key — and both carry the same encryption
context. **Not verified:** whether a `Decrypt` raised on Parameter Store's behalf
attributes `userIdentity` to the original SSM caller or carries an `invokedBy`
marker; AWS's published `Decrypt` examples show only directly invoked calls. So
correlate on `parameterArn` and Query 1's window rather than identity alone, and
confirm the identity shape against one real event.

#### Query 3 — Size what the path drain actually returned

```bash
REGION="<region>"
DRAINED_PATH="<drained-path-from-Query-1>"

RAW="$(aws ssm describe-parameters --region "$REGION" --output json \
        --parameter-filters "Key=Path,Option=Recursive,Values=$DRAINED_PATH")"
RC=$?
if [ "$RC" -ne 0 ] || [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE — describe-parameters failed for $DRAINED_PATH; the drain cannot be sized"
else
  printf '%s' "$RAW" | jq '{
    total:          (.Parameters | length),
    secureNames:    [.Parameters[] | select(.Type == "SecureString") | .Name],
    plaintextNames: [.Parameters[] | select(.Type != "SecureString") | .Name],
    lastWriters:    ([.Parameters[].LastModifiedUser] | unique)
  }'
fi
```

`secureNames` is the credential subset under the drained path and the set to
rotate. `plaintextNames` still matters: a `String` parameter holding a password is
disclosed by the same call and never appears in the KMS count. `lastWriters` names
the principal that last wrote each parameter, with no log at all — useful for
deciding who owns each rotation.

The listing is **as of now**, not as of the read. If parameters changed under the
path in between — including by your own remediation — the sets diverge and Query
2's KMS count is the more reliable one. Run this before you change anything.

#### Query 4 — Session reconstruction: everything that credential did

```bash
REGION="<region>"
ACCESS_KEY="<access-key-from-Query-1>"
START="$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"

aws cloudtrail lookup-events --region "$REGION" \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY" \
  --start-time "$START" --max-results 50 --output json \
| jq -r '.Events[].CloudTrailEvent | fromjson' \
| jq -s '
  map({ service: .eventSource, event: .eventName,
        caller: (.userIdentity.arn // "unknown"),
        issuer: (.userIdentity.sessionContext.sessionIssuer.userName // "n-a"),
        sourceIp: .sourceIPAddress, time: .eventTime, error: (.errorCode // "none") })
  | group_by(.service + ":" + .event)
  | map({ service: .[0].service, event: .[0].event, count: length,
          caller: ([.[].caller] | unique), issuer: ([.[].issuer] | unique),
          sourceIp: ([.[].sourceIp] | unique), errors: ([.[].error] | unique),
          first: ([.[].time] | min), last: ([.[].time] | max) })
  | sort_by(.first)'
```

Key on the **access key**, not the role name. `AttributeKey=Username` matches the
role **session name**, and for an instance-profile session that is the instance
ID, so a lookup by role name returns zero events forever and reads as "the role
did nothing". If you must use `Username`, pass Query 1's `session` value and
post-filter on `issuer`.

Read this for what else the credential touched. `iam:*` or `sts:AssumeRole` rows
mean this is no longer only a secrets incident. `GetParameterHistory` matters on
its own: it returns previous *versions*, of which Parameter Store keeps the 100
most recent, so an actor holding it reads the pre-rotation value after you rotate.
A long tail of `AccessDenied` across unrelated services is a stolen credential
being explored rather than an application doing its job.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The plaintext is already gone and nothing in AWS retrieves it. Containment has two
jobs — stop the principal reading anything further, and start the rotation clock on
what was read.

**The ordering hazard is specific.** If the compromised principal is an
instance-profile or task role that applications use to read their own
configuration, a blanket `Deny` on `ssm:GetParameter*` takes those applications
down *and* breaks Step 4: you rotate the parameters and the application cannot read
the new values. Establish the principal's type before denying anything; for a
workload role, contain the **session** — access key and token issue time — rather
than the role.

> Run every step under the **break-glass responder credentials** from §1, never
> under the principal being contained.

#### Step 1 — Confirm the trail is actually recording reads

```bash
TRAIL="<trail-name-or-arn>"

RAW="$(aws cloudtrail get-event-selectors --trail-name "$TRAIL" --output json)"
RC=$?

if [ "$RC" -ne 0 ] || [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE — could not read event selectors for $TRAIL"
else
  RW="$(printf '%s' "$RAW" | jq -r '(.EventSelectors // []) | map(.ReadWriteType) | unique | join(",")')"
  ADV="$(printf '%s' "$RAW" | jq -r '(.AdvancedEventSelectors // []) | length')"
  if [ -z "$RW" ] && [ "$ADV" = "0" ]; then
    echo "[!] INCONCLUSIVE — $TRAIL returned neither basic nor advanced selectors"
  elif [ "$RW" = "WriteOnly" ]; then
    echo "[FAIL] $TRAIL is WriteOnly — every GetParameter* event has been discarded."
    echo "       Set ReadWriteType=All before continuing; the queries above have no data."
  else
    echo "[OK] $TRAIL records read events (ReadWriteType=${RW:-advanced-selectors})"
  fi
fi
```

A `WriteOnly` trail is not a gap you note and move past — Queries 1, 2 and 4 return
nothing, and that nothing means nothing. Fix it, accept that history before this
moment is unrecoverable, and pivot the scope decision onto the inventory.

#### Step 2 — Freeze the principal's access to parameters and to the key

```bash
PRINCIPAL_ARN="<caller-arn-from-Query-1>"
POLICY_NAME="IR-ParamStore-Freeze"

cat > /tmp/ir-paramstore-freeze.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "FreezeParameterReads",
      "Effect": "Deny",
      "Action": ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath",
                 "ssm:GetParameterHistory", "ssm:DescribeParameters"],
      "Resource": "*" },
    { "Sid": "FreezeParameterDecryption",
      "Effect": "Deny",
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": { "Null": { "kms:EncryptionContext:PARAMETER_ARN": "false" } } }
  ]
}
JSON

case "$PRINCIPAL_ARN" in
  *:user/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $NF}')"
    aws iam put-user-policy --user-name "$IAM_NAME" \
      --policy-name "$POLICY_NAME" --policy-document file:///tmp/ir-paramstore-freeze.json
    echo "[OK] freeze applied to IAM user $IAM_NAME" ;;
  *:assumed-role/*|*:role/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $2}')"
    echo "[!] $IAM_NAME is a role. If applications assume it to read their own config,"
    echo "    this Deny is an outage AND it blocks Step 4's rotation. Confirm ownership, then:"
    echo "    aws iam put-role-policy --role-name $IAM_NAME --policy-name $POLICY_NAME \\"
    echo "      --policy-document file:///tmp/ir-paramstore-freeze.json" ;;
  *:root)
    echo "[!] root credential — no policy denies root. Rotate the root password, remove"
    echo "    any root access key, confirm root MFA." ;;
  *)
    echo "[!] unrecognised principal shape: $PRINCIPAL_ARN — contain manually." ;;
esac
```

The `kms:Decrypt` deny is scoped by a `Null` condition on the Parameter Store
encryption-context key, so it stops Parameter Store decryption without denying
every other KMS use the principal has — an unconditioned `kms:Decrypt` deny on a
workload role breaks S3, EBS and everything else. The `aws/ssm` managed key has no
editable key policy, which is why this must be an identity policy.

#### Step 3 — Revoke the sessions already issued

```bash
PRINCIPAL_ARN="<caller-arn-from-Query-1>"
ACCESS_KEY="<access-key-from-Query-1>"

case "$PRINCIPAL_ARN" in
  *:user/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $NF}')"
    # Disable before delete — the key is evidence.
    aws iam update-access-key --user-name "$IAM_NAME" --access-key-id "$ACCESS_KEY" --status Inactive
    echo "[OK] access key $ACCESS_KEY deactivated for user $IAM_NAME" ;;
  *:assumed-role/*|*:role/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $2}')"
    NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    cat > /tmp/ir-revoke-sessions.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Deny", "Action": ["*"], "Resource": ["*"],
      "Condition": { "DateLessThan": { "aws:TokenIssueTime": "$NOW" } } }
  ]
}
JSON
    aws iam put-role-policy --role-name "$IAM_NAME" \
      --policy-name AWSRevokeOlderSessions --policy-document file:///tmp/ir-revoke-sessions.json
    echo "[OK] sessions issued before $NOW revoked for role $IAM_NAME" ;;
  *)
    echo "[!] no session-revocation path for $PRINCIPAL_ARN — contain manually." ;;
esac
```

`aws:TokenIssueTime` denies only tokens issued **before** the cutoff. A host that
is still compromised re-fetches credentials from the metadata service, gets a
newer issue time, and is not denied. This kills the credential in the attacker's
hand; it does not gate the role and it does not stop fresh theft.

#### Step 4 — Rotate at the system of record, then write the new value

```bash
REGION="<region>"
PARAM_NAME="<one-name-from-Query-3-secureNames>"
NEW_VALUE_FROM_ROTATION="<value-produced-by-the-owning-system-rotation>"

# Rotate at the source FIRST — change the database password, revoke and reissue
# the API key — and only then write the result back. A new parameter value on its
# own changes nothing: the value the actor read still authenticates.

aws ssm put-parameter --region "$REGION" --name "$PARAM_NAME" \
  --value "$NEW_VALUE_FROM_ROTATION" --type SecureString --overwrite

aws ssm describe-parameters --region "$REGION" \
  --parameter-filters "Key=Name,Values=$PARAM_NAME" --output json \
| jq '.Parameters[0] | {Name, Type, Version, LastModifiedDate, LastModifiedUser}'
```

`PutParameter` creates a **new version** rather than replacing the old one, and
Parameter Store retains the 100 most recent — so anything holding
`ssm:GetParameterHistory` can still read the pre-rotation value. Where Query 4
showed `GetParameterHistory` activity, delete the parameter and recreate it
instead, allowing for AWS's requirement to "wait for at least 30 seconds to create
a parameter with the same name". Never generate a credential in this step and
discard it: take it from the owning system's rotation output.

#### Step 5 — Contain the acting principal fully

```bash
PRINCIPAL_ARN="<caller-arn-from-Query-1>"

case "$PRINCIPAL_ARN" in
  *:user/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $NF}')"
    aws iam list-access-keys --user-name "$IAM_NAME" --output json \
      | jq -r '.AccessKeyMetadata[] | "\(.AccessKeyId) \(.Status)"'
    echo "[!] deactivate every key above still Active; review console password and MFA." ;;
  *:assumed-role/*|*:role/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $2}')"
    aws iam get-role --role-name "$IAM_NAME" --output json | jq '.Role.AssumeRolePolicyDocument'
    echo "[!] an unexpected principal in the trust policy means the role itself is the"
    echo "    persistence, not just this session." ;;
  *)
    echo "[!] unrecognised principal shape: $PRINCIPAL_ARN — contain manually." ;;
esac
```

---

## 4. Eradication

### Remove Attacker Access

#### Complete the rotation before anything else is closed

Every ARN in Query 2's `parameterArn` list, and every name in Query 3's
`secureNames` and `plaintextNames`, is a disclosed credential until its system of
record says otherwise. Work the list by blast radius, not alphabetically: anything
authenticating to a database, an IAM principal or a third party first, feature
flags last. An AWS access key stored as a parameter is a separate incident.

#### Remove other persistence established by the same principal

Query 4 lists everything the credential did. Anything outside
`ssm.amazonaws.com` and `kms.amazonaws.com` belongs to a sibling playbook:

- `iam:CreateAccessKey`, `iam:PutUserPolicy`, `iam:AttachUserPolicy` →
  `../iam.privilege-escalation.inline-policy-grant/` and
  `../_superseded/aws.privilege-escalation.iam-managed-policy-escalation/`;
  `iam:UpdateAssumeRolePolicy` → `../iam.persistence.role-trust-backdoor/`
- `ssm:CreateDocument` → `../ssm.discovery.excessive-document-creation-detected/`;
  `ssm:PutParameter` on a path the principal does not own →
  `../ssm.discovery.excessive-parameter-creation-detected/`;
  `ssm:DeleteParameter*` → `../ssm.impact.parameter-deletion-detected/`
- `cloudtrail:StopLogging` or `UpdateTrail` →
  `../_superseded/aws.defense-evasion.cloudtrail-logging-tampered/`

#### Right-size the permission that made this possible

The enabling grant is almost always `ssm:GetParameter*` on
`arn:aws:ssm:<region>:<account>:parameter/*`. Replace it with the specific path the
workload needs and add the `ssm:Recursive` condition, so a principal scoped to
`/app/prod/db/*` cannot recurse from `/app/prod`. Where the parameters sit on
`aws/ssm`, move the sensitive paths to a customer managed key first — without one
there is no encryption-context condition and no key policy to write.

#### Remove the emergency policies once the rotation is complete

```bash
PRINCIPAL_ARN="<caller-arn-from-Query-1>"
POLICY_NAME="IR-ParamStore-Freeze"

case "$PRINCIPAL_ARN" in
  *:user/*)          KIND=user; IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $NF}')" ;;
  *:assumed-role/*|*:role/*)
                     KIND=role; IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $2}')" ;;
  *)                 KIND=""; IAM_NAME="" ;;
esac

if [ -z "$KIND" ]; then
  echo "[!] unrecognised principal shape: $PRINCIPAL_ARN — remove emergency policies manually."
elif aws iam "get-${KIND}-policy" "--${KIND}-name" "$IAM_NAME" --policy-name "$POLICY_NAME" --output json > /dev/null; then
  aws iam "delete-${KIND}-policy" "--${KIND}-name" "$IAM_NAME" --policy-name "$POLICY_NAME"
  echo "[OK] $POLICY_NAME removed from $KIND $IAM_NAME"
else
  echo "[!] $POLICY_NAME not present on $KIND $IAM_NAME — nothing removed; confirm it went to the right principal"
fi
```

Leave `AWSRevokeOlderSessions` in place — it expires by construction, denying only
tokens issued before its cutoff, and removing it early buys nothing.

---

## 5. Recovery

### Restore Clean State

#### Verify every disclosed parameter has been rewritten since containment

```bash
REGION="<region>"
CONTAINED_AT="<utc-timestamp-when-Step-2-completed>"
PARAM_ARNS="<parameter-arns-from-Query-2>"     # space-separated ARN list

CUT="$(date -u -d "$CONTAINED_AT" +%s)"
CHECKED=0; STALE=0; UNKNOWN=0

for ARN in $PARAM_ARNS; do
  PNAME="${ARN#*:parameter/}"
  case "$PNAME" in */*) PNAME="/$PNAME" ;; esac    # hierarchical names take a leading /

  RAW="$(aws ssm describe-parameters --region "$REGION" \
          --parameter-filters "Key=Name,Values=$PNAME" --output json)"
  RC=$?
  LM=""
  if [ "$RC" -eq 0 ] && [ -n "$RAW" ]; then
    LM="$(printf '%s' "$RAW" | jq -r '.Parameters[0].LastModifiedDate // empty')"
  fi
  if [ -z "$LM" ]; then
    UNKNOWN=$((UNKNOWN + 1))
    echo "[!] $PNAME — lookup failed or parameter absent; rotation not confirmable here"
    continue
  fi

  # CLI v2 renders timestamps ISO 8601; older configurations emit epoch seconds.
  case "$LM" in
    *[!0-9.]*) LMS="$(date -u -d "$LM" +%s)" ;;   # empty if date rejects it
    *)         LMS="${LM%%.*}" ;;
  esac
  if [ -z "$LMS" ]; then
    UNKNOWN=$((UNKNOWN + 1)); echo "[!] $PNAME — unparseable LastModifiedDate: $LM"; continue
  fi
  CHECKED=$((CHECKED + 1))
  if [ "$LMS" -gt "$CUT" ]; then
    echo "[OK] $PNAME rewritten after containment"
  else
    STALE=$((STALE + 1)); echo "[FAIL] $PNAME still holds its pre-incident value"
  fi
done

if [ "$UNKNOWN" -gt 0 ]; then
  echo "[!] INCONCLUSIVE — $UNKNOWN parameter(s) unchecked; do not close on this result"
fi
if [ "$CHECKED" -eq 0 ]; then
  echo "[!] INCONCLUSIVE — nothing checked; PARAM_ARNS is empty or every lookup failed"
elif [ "$STALE" -eq 0 ]; then
  echo "[OK] all $CHECKED disclosed parameters rewritten after $CONTAINED_AT"
else
  echo "[FAIL] $STALE of $CHECKED disclosed parameters not rotated"
fi
```

This asserts the parameter was **rewritten** — necessary, not sufficient. It says
nothing about whether the credential inside it changed at the system that honours
it, so pair it with the rotation runbook's own per-secret confirmation.

#### Verify the freeze is attached and being enforced

```bash
REGION="<region>"
PRINCIPAL_ARN="<caller-arn-from-Query-1>"
ACCESS_KEY="<access-key-from-Query-1>"
POLICY_NAME="IR-ParamStore-Freeze"
SINCE="<utc-timestamp-when-Step-2-completed>"

case "$PRINCIPAL_ARN" in
  *:user/*) POL="$(aws iam get-user-policy --policy-name "$POLICY_NAME" --output json \
              --user-name "$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $NF}')")"; PRC=$? ;;
  *:assumed-role/*|*:role/*)
            POL="$(aws iam get-role-policy --policy-name "$POLICY_NAME" --output json \
              --role-name "$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $2}')")"; PRC=$? ;;
  *)        POL=""; PRC=1 ;;
esac

if [ "$PRC" -ne 0 ] || [ -z "$POL" ]; then
  echo "[!] INCONCLUSIVE — could not read $POLICY_NAME for $PRINCIPAL_ARN"
else
  echo "[OK] $POLICY_NAME is attached to $PRINCIPAL_ARN"
fi

EV="$(aws cloudtrail lookup-events --region "$REGION" \
      --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY" \
      --start-time "$SINCE" --max-results 50 --output json)"
ERC=$?

if [ "$ERC" -ne 0 ] || [ -z "$EV" ]; then
  echo "[!] INCONCLUSIVE — post-containment lookup failed for $ACCESS_KEY"
else
  TOTAL="$(printf '%s' "$EV" | jq '.Events | length')"
  DEC="$(printf '%s' "$EV" | jq -r '.Events[].CloudTrailEvent | fromjson' | jq -s '.')"
  SUCCESS="$(printf '%s' "$DEC" | jq '[.[] | select(.eventSource == "ssm.amazonaws.com")
             | select(.eventName | startswith("GetParameter")) | select(.errorCode == null)] | length')"
  DENIED="$(printf '%s' "$DEC" | jq '[.[] | select(.eventSource == "ssm.amazonaws.com")
             | select((.errorCode // "") | test("AccessDenied"))] | length')"
  if [ "$SUCCESS" -gt 0 ]; then
    echo "[FAIL] $SUCCESS successful parameter read(s) by $ACCESS_KEY since $SINCE — the freeze is not effective"
  elif [ "$DENIED" -gt 0 ]; then
    echo "[OK] $DENIED denied attempt(s) and 0 successes since $SINCE — the freeze is live and being hit"
  elif [ "$TOTAL" -eq 0 ]; then
    echo "[!] INCONCLUSIVE — no events at all for $ACCESS_KEY since $SINCE. That is what an idle"
    echo "    credential looks like AND what a mis-keyed lookup looks like; re-run Query 4 over a"
    echo "    window you know contains activity before treating this as clean"
  else
    echo "[OK] $TOTAL event(s) since $SINCE, none a successful parameter read"
  fi
fi
```

The zero case is called out deliberately. "No further reads" after you removed the
permission is the expected result whether or not the check works, so it is not on
its own evidence of anything: the denial count asserts the control is live, and a
total of zero is inconclusive rather than clean.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     eventSource=ssm.amazonaws.com eventName=GetParametersByPath"
echo "                  requestParameters.path=/app/prod  requestParameters.recursive=true"
echo "                  requestParameters.withDecryption=true  errorCode absent"
echo "                  userIdentity.arn=arn:aws:sts::111122223333:assumed-role/AdHocAnalyst/alice"
echo "MUST fire on:     30+ kms.amazonaws.com Decrypt events in 5 minutes from one"
echo "                  userIdentity.arn, each with a distinct"
echo "                  requestParameters.encryptionContext.PARAMETER_ARN ending :parameter/..."
echo "MUST NOT fire on: the same GetParametersByPath with withDecryption absent or false"
echo "                  (a plaintext String read is routine configuration loading)"
echo "MUST NOT fire on: the same call carrying errorCode=AccessDenied"
echo "                  (a denial discloses nothing and must not enter the rotation list)"
echo "MUST NOT fire on: userIdentity.arn containing :role/ecs-task-web, recursive+decrypt"
echo "                  (the allowlisted configuration loader doing its job)"
echo "EXPECTED FP, by design: a genuine bulk export before an environment migration."
echo "                  Indistinguishable on the event; resolve it by change record, not tuning."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| One principal could read and decrypt every `SecureString` under a hierarchy in a single call | `ssm:GetParameter*` granted on `parameter/*` with no path scope and no `ssm:Recursive` condition |
| Decrypting the values needed no separate authorisation step | The parameters sat on the `aws/ssm` AWS managed key, which cannot carry a key policy, so no encryption-context condition was available |
| The number of secrets exposed was not knowable from the alert | Detection counted API calls; the response set is not logged, and no parameter inventory was retained to reconstruct the path as of the read |
| Rotation took days, not minutes | No mapping from parameter name to owning system of record, so each secret's owner had to be found during the incident |
| A denied probe and a successful drain raised the same alert | No success filter on the volume rule, so triage could not separate exposure from attempt |
| Pre-rotation values stayed readable after rotation | Parameter Store retains 100 versions and `ssm:GetParameterHistory` was granted alongside the read permissions |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Deny recursive hierarchy reads outside the configuration-loader roles. ssm:Recursive
// is a STRING key valued "true"/"false" — AWS's own examples use StringEquals, not Bool,
// and StringEquals is right here because the value is exact. The PrincipalArn allowlist
// IS wildcarded and needs ArnNotLike: Deny + ArnNotEquals against a wildcard fails
// CLOSED and denies every principal, loaders included.
{
  "Sid": "NoRecursiveParameterDrain",
  "Effect": "Deny",
  "Action": "ssm:GetParametersByPath",
  "Resource": "*",
  "Condition": {
    "StringEquals": { "ssm:Recursive": "true" },
    "ArnNotLike": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/app-config-loader",
        "arn:aws:iam::*:role/ecs-task-*"
      ]
    }
  }
}
```

Structural controls:

- **Move every sensitive path off `aws/ssm` onto a customer managed key**, then scope
  `kms:Decrypt` on that key to one path with
  `"StringLike": {"kms:EncryptionContext:PARAMETER_ARN": "arn:aws:ssm:<region>:<account>:parameter/app/prod/*"}`.
  `StringLike`, not `StringEquals` — the value is wildcarded and `StringEquals` against
  a wildcard matches nothing. On `aws/ssm` no key policy exists to write this into, so
  the control is unavailable rather than merely unwritten
- **Scope reads by path, never by `parameter/*`.** A leaf-level `Deny` is not a
  substitute: the `GetParametersByPath` API reference states a user with access to
  `/a` "can still call the `GetParametersByPath` API operation recursively for `/a`
  and view `/a/b`" even when explicitly denied `/a/b`, while the Parameter Store
  policy documentation states the opposite for the same construction. The two pages
  disagree; design as if the permissive reading holds and deny recursion at the
  path with `ssm:Recursive`, which both pages agree works
- **Split the hierarchy by blast radius** — `/app/prod/db/*` and
  `/app/prod/flags/*` under separate keys and grants, so no single over-broad role
  drains both
- **Deny `ssm:GetParameterHistory` outside the parameter-admin role**, with an
  `ArnNotLike` on `aws:PrincipalArn` — not `aws:username`, which is absent for
  assumed-role principals. Without it the pre-rotation value stays readable for
  100 versions and rotation does not close the exposure
- **Keep a parameter inventory.** A daily `DescribeParameters` snapshot per path
  turns "we do not know what was under that path last Tuesday" into a work-list

Detection improvements:

- Count distinct `encryptionContext.PARAMETER_ARN` on `kms:Decrypt`, not SSM API
  calls — the only count that tracks secrets rather than requests
- Alert on `kms:Decrypt` **denials** carrying a `PARAMETER_ARN` context — a principal
  that can read parameters but not decrypt them is misconfigured or probing — and on
  `GetParameter` with decryption **off** followed by a direct `kms:Decrypt` by the
  same principal, the two-step path the SSM-side rule cannot see
- Baseline each workload role's decrypted-read count and alert on deviation

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1555.006 — Credentials from Password Stores: Cloud Secrets Management Stores |
| MITRE tactic | Credential Access (TA0006) |
| Primary API | `ssm:GetParametersByPath` (Recursive + WithDecryption) → `kms:Decrypt` per value; `ssm:GetParameters` (≤10 names/call); `ssm:GetParameter` |
| Event source | `ssm.amazonaws.com` and `kms.amazonaws.com` — **management** events, recorded by default. Verified: AWS states "Systems Manager logs all control plane operations to CloudTrail as management events", and the only SSM data-event resource types are `AWS::SSMMessages::ControlChannel` and `AWS::SSM::ManagedNode` |
| Key discriminator | `requestParameters.withDecryption == true` — documented to be ignored for `String` and `StringList`, so it means the caller wanted plaintext of encrypted material |
| Ground-truth signal | `requestParameters.encryptionContext.PARAMETER_ARN` on each `kms:Decrypt` — one per parameter decrypted, naming it; documented to appear in plaintext in CloudTrail |
| "Was it used" pivot | The read **is** the use. No later event proves exploitation; treat retrieval as terminal evidence and rotate |
| Blast radius | Every parameter under the drained path, plus everything its credentials reach outside AWS, which no AWS control revokes. CloudTrail records `name` / `names` / `path` and **never the value** |
| Pagination limits | `GetParameters` ≤10 names per call; `GetParametersByPath` `MaxResults` 1–10 per page; `DescribeParameters` `MaxResults` 1–50; `lookup-events` ≤50 per page |
| Version retention | 100 most recent versions per parameter, readable via `ssm:GetParameterHistory` — rotation alone does not close the exposure |
| Error strings | `GetParameter`: `ParameterNotFound`, `ParameterVersionNotFound`, `InvalidKeyId`, `InternalServerError`. `GetParameters`: `InvalidKeyId`, `InternalServerError` only. `GetParametersByPath`: `InvalidFilterKey`, `InvalidFilterOption`, `InvalidFilterValue`, `InvalidKeyId`, `InvalidNextToken`, `InternalServerError`. Denials: `AccessDenied` and `AccessDeniedException` — match both |
| Silent-miss trap | A `GetParameter` for a nonexistent parameter is **not logged at all**; a `GetParameters` miss returns HTTP 200 with the name in `InvalidParameters` and no `errorCode`. Name enumeration is invisible to error-based detection on both paths |

**MITRE mapping note.** The source rule labels this T1552 (*Unsecured
Credentials*), the parent family. That is a category rather than a mapping: these
credentials are not unsecured — they are correctly encrypted under KMS and
correctly returned to a principal that was authorised and should not have been.
T1555.006 (*Credentials from Password Stores: Cloud Secrets Management Stores*)
names what happened. The tactic, Credential Access (TA0006), is right in both.
Where the reads originate from a stolen instance-profile session, T1078.004
(*Valid Accounts: Cloud Accounts*) describes the access rather than the collection
and is carried in the trigger table only.

### Residual Risk

**The plaintext is gone and nothing in AWS retrieves it.** Every step above
constrains the future; none affects the copy the actor already holds. Until each
credential is rotated at the system that honours it, the exposure is live
regardless of what the console says.

**Rotation is neither instantaneous nor always possible.** A third-party key with a
manual process, a credential in a running connection pool, a signing secret shared
with a partner — each has its own clock, and the incident is open until the slowest
one closes.

**Previous versions outlive the rotation.** Parameter Store keeps 100 versions, so
any principal retaining `ssm:GetParameterHistory` reads the pre-incident value after
a new one is written. Deleting and recreating the parameter is the only way to remove
it, and that discards the parameter's own change history with it.

**The reconstruction has an edge.** For a recursive drain the disclosed set is
rebuilt after the fact: a parameter that existed under the path at read time and was
deleted before you looked does not appear in `DescribeParameters`, and appears in the
KMS count only if it was `SecureString`. A plaintext `String` parameter deleted in
between is disclosed and unrecoverable from any source.

**Containment does not prove the entry point is closed.** If the credential came from
a compromised host, session revocation kills the session and the host mints a new one.
Whatever gave the actor the principal is a separate investigation.
