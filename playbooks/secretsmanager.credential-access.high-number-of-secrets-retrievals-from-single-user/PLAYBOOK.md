# IR Playbook: High Number of Secrets Retrievals From a Single Principal — Bulk Credential Theft via `secretsmanager:GetSecretValue` and `BatchGetSecretValue`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential access / bulk secret disclosure (one principal reads the plaintext values of many stored secrets) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High.** A secrets store is where an organisation deliberately concentrates the credentials that matter — database masters, third-party API keys, and often long-lived IAM access keys. Bulk retrieval hands the actor whatever the strongest secret in the set grants, which is one hop from account takeover when any of them is an AWS credential, and zero hops from a data breach when they are database or SaaS credentials. The disclosure is complete at the moment of the call: the plaintext leaves AWS, and nothing downstream is recoverable. Three source rules cover this observable at P2, P2 and P3. P3 for the first time a principal is seen reading production secret values is too low — that is the alert that fires earliest, before the volume threshold is reached, and it is the one worth waking someone for |
| MITRE Tactics | Credential Access (TA0006) |
| MITRE Techniques | T1555.006 — Credentials from Password Stores: Cloud Secrets Management Stores (primary); T1119 — Automated Collection (the batch path); T1526 — Cloud Service Discovery (the `ListSecrets` precursor) |
| Services in Scope | Secrets Manager, CloudTrail (management), KMS, IAM, Lambda (rotation functions), RDS and any downstream system whose credential was stored |

**What the technique does:** The actor holds a principal with `secretsmanager:GetSecretValue`
scoped wider than one workload's own secrets — commonly `Resource: "*"` on a shared
application role, an over-broad `SecretsManagerReadWrite`-style grant, or a compromised
CI/CD role. It optionally calls `secretsmanager:ListSecrets` first, which returns every
secret's ARN, name, description, tags and rotation state for the Region but never a value.
It then calls `secretsmanager:GetSecretValue` once per secret, or
`secretsmanager:BatchGetSecretValue` with a `SecretIdList` of up to 20 names or with
`Filters` matching a name prefix or tag. Secrets Manager decrypts each value with the
secret's KMS key and returns it in `SecretString` or `SecretBinary`. At that point the
actor holds working plaintext credentials to every system those secrets front, and AWS has
no further say in what happens with them.

**Why this is potent, and why the usual reflexes miss it.** Nothing is created, nothing is
modified, and nothing breaks. The secrets are still there, still encrypted at rest, still
rotating on schedule; `DescribeSecret` shows an unchanged `VersionIdsToStages`, IAM shows
no new policy, and a configuration-drift detector sees a perfectly clean account. The
reflex of "check what changed" returns nothing, because nothing changed — a read leaves the
resource exactly as it found it. The second reflex, checking whether the stolen credentials
were then used, also fails inside AWS: the credentials in those secrets mostly authenticate
to *databases, SaaS platforms and partner APIs*, which produce no CloudTrail at all. The
last AWS-observable event in the entire chain is the retrieval itself. Treat it as terminal
evidence, exactly as you would `ec2:GetPasswordData` (see
`../ec2.credential-access.imds-credential-theft/` for the same reasoning applied to a
different store).

**Detection is the count of distinct secrets successfully read by one principal, not the
count of API calls.** A principal denied on five secrets and a principal that read five
secrets produce the same number of events, and five retries of one secret produce the same
number as five distinct secrets read once — so the count has to be over distinct
`requestParameters.secretId` values on events with no `errorCode`, which is also the count
the rotation work-list has to match. The source rules count raw events, with no success
filter on the volume path, and their first-seen variant tracks
`userIdentity.sessionContext.sessionIssuer.userName` — a field a principal using long-term
IAM user access keys does not carry — so the rule named for unfamiliar IAM users is
structurally unable to see one.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

- **CloudTrail multi-region trail capturing management events.** Every Secrets Manager
  operation is a **management event**, recorded by default, and `lookup-events` can see it.
  Secrets Manager has **no** CloudTrail data-event resource type — it does not appear in
  CloudTrail's supported data-event table, so there is nothing to enable and no
  data-event trail to build. GuardDuty independently confirms the plane: its
  `CredentialAccess:IAMUser/AnomalousBehavior` finding lists `GetSecretValue` and
  `BatchGetSecretValue` with data source "CloudTrail management event".
- **`GetSecretValue` carries `requestParameters.secretId`** — the ARN *or* the bare name,
  whichever the caller passed. It is caller-typed, so the same secret can appear in two
  forms across events and must be normalised before it is counted or deduplicated.
- **`BatchGetSecretValue` carries `requestParameters.secretIdList` (array) OR
  `requestParameters.filters` (array), never both** — AWS documents them as mutually
  exclusive. On the `filters` path the request names no secret at all.
- **The secret value is never in CloudTrail.** `SecretString`, `SecretBinary` and
  `RotationToken` each carry AWS's sensitivity marker: *"the service does not include it in
  AWS CloudTrail log entries"*. You get the identity of what was read, never the content.
- **`resources[]` on Secrets Manager events is not documented.** AWS publishes no example
  Secrets Manager CloudTrail event, so no query here depends on `resources[].ARN` alone;
  every extraction falls back to `requestParameters.secretId`.
- **A record of what each secret is for** — which system it authenticates to, which team
  owns it, and whether it can be rotated without an outage. This is the blast-radius
  reference and CloudTrail cannot supply it.
- **`DescribeSecret` per secret** for `VersionIdsToStages` (which version id carries
  `AWSCURRENT`), `RotationEnabled`, `RotationLambdaARN`, `LastAccessedDate` and
  `LastChangedDate`. Snapshot `AWSCURRENT` version ids on a schedule — that snapshot is
  what makes "did rotation actually happen" answerable afterwards.

**Alerting (must be pre-configured)**

- **A principal reading ≥10 distinct secret values within 5 minutes, successfully → P0**
- **`secretsmanager:BatchGetSecretValue` succeeding for a principal outside the batch-reader baseline → P0**
- **A principal with no secret-read history in the trailing 30 days reading any secret value → P1**
- **Ordered sequence `ListSecrets` → `GetSecretValue` by one principal within 30 minutes → P1**
- GuardDuty `CredentialAccess:IAMUser/AnomalousBehavior` on a Secrets Manager API
- A run of `DecryptionFailure` across multiple secrets by one principal — a drain the KMS
  key policy stopped

**Response Tooling**

- AWS CLI v2 with **break-glass responder credentials**, separate from any principal under
  investigation and separate from any application role that reads secrets
- `jq`
- The secret-to-system inventory named above, and the rotation runbook for each system that
  cannot be rotated by an automated function
- The scheduled snapshot of each secret's `AWSCURRENT` version id — the only pre-incident
  value that makes the Recovery assertion in §5 able to fail
- A ticket or change record channel for the rotations, because rotating a shared database
  credential is an availability event and needs owners on the call

**Known IOC Baselines**

- The principals that legitimately read secrets, by ARN, and **which secrets each one
  reads**. Per-role scope is the useful form; an account-wide allowlist defeats the rule
- The principals that legitimately call `BatchGetSecretValue` — a much shorter list, because
  most SDK and agent paths use `GetSecretValue`
- The rotation function's execution role ARN, held separately: it is a legitimate
  high-volume reader **and** it must survive containment
- Expected source IPs and VPC endpoint ids for the readers above
- The account's total secret count from `ListSecrets`, which is the ceiling for any
  account-wide threshold

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | A principal reading ≥10 distinct secret values within 5 minutes, successfully | CloudTrail (management) | T1555.006 |
| P0 | `secretsmanager:BatchGetSecretValue` succeeding for a principal outside the batch-reader baseline | CloudTrail (management) | T1555.006 / T1119 |
| P1 | A principal with no secret-read history in the trailing 30 days reading any secret value | CloudTrail (management) | T1555.006 |
| P1 | Ordered sequence `ListSecrets` → `GetSecretValue` by one principal within 30 minutes | CloudTrail (management) | T1555.006 / T1526 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | GuardDuty `CredentialAccess:IAMUser/AnomalousBehavior` naming a Secrets Manager API | GuardDuty | T1555.006 |
| P2 | `DecryptionFailure` across several secrets by one principal — a drain the KMS key policy stopped | CloudTrail (management) | T1555.006 |
| P2 | Secret reads from a source IP or VPC endpoint outside the reader's baseline | CloudTrail (management) | T1555.006 |
| P3 | A baselined loader reading its own configured secrets at boot | CloudTrail (management) | T1555.006 |

### Detection Rule Quality Notes

The three source rules count API calls rather than secrets, and only one of the three
filters to successful calls — so the number they produce is not the number of secrets that
have to be rotated.

| Issue | Impact | Correction |
|-------|--------|-----------|
| The volume building block matches `eventSource:"secretsmanager.amazonaws.com" AND eventName:GetSecretValue` with **no `errorCode` filter** | A principal probing 5 secrets and being denied on all 5 fires the identical alert as a principal that read 5. The responder's work-list is then a list of secrets that were *not* disclosed, and the real drain is buried in the same alert stream | Add `success: {errorCode: null}` and count only successful reads (rule B6). The denied form is a separate use case — `../secretsmanager.discovery.access-repeatedly-denied/` |
| It counts **events**, not distinct secrets | Five retries of one secret trip the threshold while disclosing one credential; five distinct secrets read once each trip the same threshold while disclosing five. The alert cannot be sized against anything | `value_count` over `requestParameters.secretId` grouped by `userIdentity.arn`, so the number in the alert equals the number of rotations |
| "Retrieve a High Number of Secrets Manager Secrets" matches `eventName:BatchGetSecretValue` with **threshold 0** and no principal check | Named for a high number, fires on one call. Every configuration loader that adopts the batch API after a library upgrade becomes a permanent alert source, and the rule is muted within a week | Keep the fire-on-first-call behaviour — it is the fastest signal available — but add the success filter and a batch-reader baseline so the alert is actionable |
| Both bulk rules were treated as separate observables, on the assumption that the batch API hides a drain behind one event | The opposite is true and it changes the design. AWS: `BatchGetSecretValue` *"generates CloudTrail `GetSecretValue` log entries for each secret you request"*, and the `GetSecretValue` entry is *"Generated by the GetSecretValue **and BatchGetSecretValue** operations"*. A 20-secret batch emits 1 + up to 20 events | One `value_count` on `GetSecretValue` covers both paths and cannot be evaded by switching to the batch API. The batch rule is retained as the earlier-firing trigger, not as separate coverage |
| The first-seen rule tracks new values of `userIdentity.sessionContext.sessionIssuer.userName` | `sessionContext` is populated for requests made with temporary credentials. A principal using long-term IAM user access keys does not carry it — so a rule titled "Unfamiliar IAM User Retrieved Secrets" sees one perpetual absent value, alerts once, and is silent on every IAM user thereafter. It also collapses every session of one role to the role name, hiding which session did it | Track `userIdentity.arn`. Carry `sessionContext.sessionIssuer.userName` as role-name enrichment only (rule A5) |
| The flow rule's summary describes counting `GetSecretValue` volume; its logic requires a successful `ListSecrets` first | An actor who already knows the secret names — from infrastructure-as-code, a prior compromise, or a cross-account ARN handed to them — never triggers stage one. The better-prepared attacker is exactly the one the rule cannot see | Ship the enumerate-then-drain sequence as a `medium` corroborator, and make the unconditional distinct-secret count the primary |

**Recommended detection — distinct secrets successfully read by one principal in a short window.**

```yaml
# High Number of Secrets Retrievals From a Single Principal (T1555.006)
#
# Three source rules cover one observable and are merged here. A FLOW rule chained two
# building blocks — ListSecrets (success) THEN GetSecretValue at 5 events in 5 minutes,
# within 30 minutes, grouped by userIdentity.arn. A second rule fired on ANY
# BatchGetSecretValue, threshold zero, despite being named for a "high number". A third
# fired the first time a principal was seen calling GetSecretValue in a 7-day window.
#
# THE FACT THAT REORGANISES ALL THREE: BatchGetSecretValue does not hide behind one
# event. AWS documents that Secrets Manager "generates CloudTrail GetSecretValue log
# entries for each secret you request when you call this action", and the CloudTrail
# entries page lists the GetSecretValue entry as "Generated by the GetSecretValue and
# BatchGetSecretValue operations". A batch of 20 therefore emits one
# BatchGetSecretValue event plus up to 20 GetSecretValue events. Counting
# GetSecretValue does NOT under-count the batch path, and the two rules are two
# thresholds on the same drain: one fires at 5 calls, the other at a batch of 1.
#
# What the source rules got wrong, concretely. The volume building block has no success
# filter, so a principal denied on 5 secrets fires exactly as loudly as one that read 5
# (B6) — and it counts EVENTS, so five retries of one secret fire while five distinct
# secrets read once each also fire. The rules below count DISTINCT secretId values on
# SUCCESSFUL calls, which is the number the eradication work-list has to match. The
# first-seen rule tracked userIdentity.sessionContext.sessionIssuer.userName, a field a
# principal using long-term IAM user access keys does not carry at all — so the rule
# named for IAM users is the one shape of principal it cannot track. Everything here
# keys on userIdentity.arn and treats sessionIssuer.userName as role-name enrichment.
#
# CloudTrail records which secret was read, never the value: SecretString and
# SecretBinary are both documented "Sensitive: ... the service does not include it in
# AWS CloudTrail log entries". The event names the secret; only rotation removes the
# exposure.
title: Many distinct Secrets Manager secrets read by one principal
id: ae4a66ad-e245-4608-b020-f7a0f3da9536
status: experimental
description: >-
  Counts DISTINCT secrets successfully read by a single principal in a short
  window, not API calls. BatchGetSecretValue fans out into one GetSecretValue
  entry per secret, so this count covers the batch path and the single-read path
  with one rule, and it equals the number of secrets that must be rotated.
references:
  - https://attack.mitre.org/techniques/T1555/006/
  - https://docs.aws.amazon.com/secretsmanager/latest/userguide/cloudtrail_log_entries.html
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_BatchGetSecretValue.html
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
tags:
  - attack.credential-access
  - attack.t1555.006
correlation:
  type: value_count
  rules:
    - secretsmanager_getsecretvalue_success
  group-by:
    - userIdentity.arn
  timespan: 5m
  field: requestParameters.secretId
  condition:
    gte: 10
falsepositives:
  - An application or task loading its whole configuration set at boot — allowlist the specific task or execution role, never the account, and size the threshold above that role's known secret count
  - A migration or disaster-recovery export reading a whole environment's secrets — should be time-boxed and traceable to a change record
level: high
---
title: Secrets Manager batch secret retrieval by an unbaselined principal
id: e17088e8-2a4b-44ae-ab26-21b0f8cc9a85
status: experimental
description: >-
  BatchGetSecretValue is a deliberate bulk-read API that returns up to 20 secret
  values per call. Few workloads use it and those that do are enumerable, so a
  successful call by a principal outside that list is the fastest available
  signal that a drain is under way — it fires on the first call, before the
  distinct-secret count reaches its threshold.
references:
  - https://attack.mitre.org/techniques/T1555/006/
  - https://attack.mitre.org/techniques/T1119/
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_BatchGetSecretValue.html
tags:
  - attack.credential-access
  - attack.t1555.006
  - attack.t1119
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'secretsmanager.amazonaws.com'
    eventName: 'BatchGetSecretValue'
  success:
    errorCode: null
  batch_readers:                       # tune: principals that legitimately bulk-read secrets
    userIdentity.arn|contains:
      - ':role/app-config-loader'
      - ':role/ecs-task-'
      - ':role/eks-node-'
  condition: selection and success and not batch_readers
falsepositives:
  - A configuration loader adopting the batch API after a library upgrade — confirm against the deployment record, then add the role to batch_readers
level: high
---
title: Secrets Manager secret value retrieved successfully
id: f52d94e7-a993-41d0-83e0-3b01a3c16dad
name: secretsmanager_getsecretvalue_success
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. One entry per
  secret whose value was returned, including the per-secret entries that
  BatchGetSecretValue generates. requestParameters.secretId carries the ARN or
  name the caller supplied.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/userguide/cloudtrail_log_entries.html
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
tags:
  - attack.credential-access
  - attack.t1555.006
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'secretsmanager.amazonaws.com'
    eventName: 'GetSecretValue'
  success:
    errorCode: null
  # justified: base rule feeding the value_count and temporal_ordered correlations
  # below; informational level, never routed to an analyst on its own.
  condition: selection and success
level: informational
---
title: Secrets Manager secret inventory listed successfully
id: c2c59e02-1ec5-43ae-9205-64e32a3710f3
name: secretsmanager_listsecrets_success
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. ListSecrets
  returns metadata for every secret in the Region and never a secret value, so
  on its own it is enumeration, not exposure.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html
tags:
  - attack.credential-access
  - attack.t1555.006
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'secretsmanager.amazonaws.com'
    eventName: 'ListSecrets'
  success:
    errorCode: null
  # justified: base rule feeding the temporal_ordered correlation below;
  # informational level, never routed to an analyst on its own.
  condition: selection and success
level: informational
---
title: Secrets Manager inventory enumerated then secret values read by one principal
id: 07455312-47bc-459d-a871-8337356f35dd
status: experimental
description: >-
  The enumerate-then-drain fingerprint, and the composition the source FLOW rule
  expressed. A principal that calls ListSecrets before reading values did not
  already know the secret names — an application that reads its own secrets from
  configuration never needs the inventory first. Both stages are success-filtered
  so a denied enumeration followed by a legitimate read cannot raise this.
references:
  - https://attack.mitre.org/techniques/T1555/006/
  - https://attack.mitre.org/techniques/T1526/
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html
tags:
  - attack.credential-access
  - attack.t1555.006
  - attack.t1526
correlation:
  type: temporal_ordered
  rules:
    - secretsmanager_listsecrets_success
    - secretsmanager_getsecretvalue_success
  group-by:
    - userIdentity.arn
  timespan: 30m
falsepositives:
  - A console operator browsing the secrets list and then opening one secret — the console issues both calls; scope out named human operators or require the distinct-secret count rule to fire alongside
  - An inventory or compliance scanner that lists and then samples secrets — allowlist by role
level: medium
---
title: Secrets Manager secret read by a principal with no read history
id: 6c95aed8-967e-480f-98a9-8c28cd2dac1f
status: experimental
description: >-
  The deployable approximation of a first-seen-principal rule. Sigma has no
  new-value primitive, so the baseline is expressed as an explicit allowlist of
  principals known to read secrets; anything else reading a secret value is new
  by construction. Maintain the allowlist from the same inventory that feeds the
  §1 Known IOC Baselines table.
references:
  - https://attack.mitre.org/techniques/T1555/006/
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
tags:
  - attack.credential-access
  - attack.t1555.006
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'secretsmanager.amazonaws.com'
    eventName:
      - 'GetSecretValue'
      - 'BatchGetSecretValue'
  success:
    errorCode: null
  baselined_readers:                   # tune: every principal that legitimately reads secrets
    userIdentity.arn|contains:
      - ':role/app-config-loader'
      - ':role/ecs-task-'
      - ':role/eks-node-'
      - ':role/lambda-'
      - ':role/SecretsRotation'
  condition: selection and success and not baselined_readers
falsepositives:
  - A newly deployed workload whose role is not yet in the allowlist — expected on every first deploy; wire the allowlist to the same pipeline that creates the role
  - A human operator retrieving one secret during an approved break-glass procedure
level: medium
```

**Threshold basis.** There is no emulation behind this corpus, so `gte: 10` is derived from
documented behaviour, not observed counts. `BatchGetSecretValue` returns at most 20 secrets
per call (`SecretIdList` maximum 20 items, `MaxResults` range 1–20), so one maximal batch
always produces at least 20 countable entries and any threshold at or below 20 fires on it.
An application reading its own configuration reads a handful of named secrets and reads the
same ones every time. Ten sits above that shape and below one full batch. Size it against
your own inventory per role rather than account-wide.

**What this rule structurally cannot do.** It cannot tell you what was taken — the value is
absent from the log by design, so the impact of each disclosed secret comes from your own
inventory, not from the event. It cannot see a read performed by an *external* principal
through a resource-based policy in a way that lands in that account's trail rather than
this one; that path is a different use case
(`../secretsmanager.privilege-escalation.resource-based-permission-policy-attached-to-a-secret/`).
And `requestParameters.secretId` is caller-typed, so a caller that mixes bare names and full
ARNs will be counted as reading more distinct secrets than it did — normalise the trailing
name segment before counting if your callers are inconsistent. **On error strings:**
Secrets Manager documents the authorization failure as `AccessDeniedException` and also
carries `NotAuthorized`; unsuffixed `AccessDenied` is not in the service's documented set,
though an IAM-policy-evaluated denial can still surface that way in CloudTrail (rule A7).
Match all three prefix-tolerantly and confirm against one real denied event from your own
trail.

---

### Key Investigation Queries

> Secrets Manager is regional and each secret lives in one Region (replicas are separate
> resources with their own events) — run these in every Region that holds secrets, not just
> the one the alert came from. Extraction uses
> `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50
> events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: which secrets did this principal actually read, and did the reads succeed

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn-from-the-alert>"

for EV in GetSecretValue BatchGetSecretValue ListSecrets; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done | \
  jq -r --arg who "$SUSPECT_ARN" '
    .Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "secretsmanager.amazonaws.com") |
    select(.userIdentity.arn == $who) |
    {time:       .eventTime,
     event:      .eventName,
     caller:     .userIdentity.arn,
     role:       (.userIdentity.sessionContext.sessionIssuer.userName // "n/a — not a role session"),
     access_key: .userIdentity.accessKeyId,
     # secretId is caller-typed (bare name OR full ARN). resources[] is undocumented for
     # this service, so it is a fallback, never the sole source.
     secret:     (.requestParameters.secretId
                  // ([.resources[]?.ARN] | first)
                  // "n/a — batch request, see batch_list/batch_filters"),
     batch_list:    (.requestParameters.secretIdList // null),
     batch_filters: (.requestParameters.filters      // null),
     error:      (.errorCode // "SUCCESS"),
     ip:         .sourceIPAddress,
     ua:         .userAgent}' | \
  jq -s 'sort_by(.time)'
```

Read it in three passes. First, filter to `error == "SUCCESS"` and collect every distinct
`secret` — **that set, and only that set, is the rotation work-list**; anything with an
`error` was not disclosed. Second, look for a `BatchGetSecretValue` row: if `batch_list` is
populated it names the secrets directly, and if `batch_filters` is populated instead the
request named none of them and you must take the set from the per-secret `GetSecretValue`
rows in the same second or two (AWS generates one per secret requested). Third, note the
`access_key` and `ip` — `access_key` feeds Query 4, and a familiar role arriving from an
unfamiliar `ip` or `ua` is the difference between a compromised workload and a compromised
credential.

`eventTime` resolves to whole seconds, so read rhythm by bucketing rather than by diffing
adjacent timestamps (rule A6): pipe the output through
`jq -r '.[].time' | sort | uniq -c | sort -rn`. Twenty entries sharing one second is a batch
fan-out or a scripted loop, never a person; a steady one-per-minute rhythm across hours is
far more likely an application, and should be checked against Query 2's baseline before
escalating. A `ListSecrets` a few seconds before the first read is the enumerate-then-drain
fingerprint.

#### Query 2 — Sweep: every principal that read secrets in the window, ranked by how many

```bash
REGION="us-east-1"

RAW=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json)

if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE: lookup-events returned nothing at all in $REGION — the call failed,"
  echo "    the credential lacks cloudtrail:LookupEvents, or the region is wrong. Not 'clean'."
else
  echo "$RAW" | jq -r '
    .Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "secretsmanager.amazonaws.com") |
    select(.errorCode == null) |                       # successful reads only
    {caller: .userIdentity.arn,
     secret: (.requestParameters.secretId // ([.resources[]?.ARN] | first) // "unnamed"),
     time:   .eventTime,
     ip:     .sourceIPAddress}' | \
  jq -s 'group_by(.caller) |
         map({caller:          .[0].caller,
              distinct_secrets: ([.[].secret] | unique | length),
              secrets:          ([.[].secret] | unique),
              reads:            length,
              source_ips:       ([.[].ip]     | unique),
              first_seen:       ([.[].time]   | min),
              last_seen:        ([.[].time]   | max)}) |
         sort_by(-.distinct_secrets)'
  echo "[i] Ranked by distinct_secrets. Compare each caller against the §1 baseline."
fi
```

The top rows are the drains. A caller whose `distinct_secrets` far exceeds the number of
secrets its workload is supposed to hold is the finding, regardless of whether it is on the
allowlist — an allowlisted role reading forty secrets when it owns four is a compromised
allowlisted role. `source_ips` with more than one entry for a workload role that runs in one
subnet is a second, independent signal. The `[!] INCONCLUSIVE` branch matters: an empty
result here is far more likely to be a failed call than an account where nobody read a
secret in seven days.

#### Query 3 — Inspect: what each disclosed secret actually grants (CloudTrail does not log it)

```bash
REGION="us-east-1"
# Space-separated secret names or ARNs, taken from Query 1's `secret` field.
DRAINED_SECRETS="<secret-from-Query-1> <secret-from-Query-1>"

for S in $DRAINED_SECRETS; do
  META=$(aws secretsmanager describe-secret --secret-id "$S" --region "$REGION" --output json)
  if [ -z "$META" ]; then
    echo "[!] $S — INCONCLUSIVE: describe-secret returned nothing (call failed, no permission,"
    echo "    wrong region, or the secret has since been deleted). Do NOT treat as out of scope."
    continue
  fi
  echo "$META" | jq -r '
    {secret:        .Name,
     arn:           .ARN,
     description:   (.Description   // "none recorded"),
     owner_tags:    (.Tags          // []),
     kms_key:       (.KmsKeyId      // "aws/secretsmanager (AWS managed)"),
     rotation:      (if   has("RotationEnabled") then (.RotationEnabled | tostring)
                     else "never configured" end),
     rotation_fn:   (.RotationLambdaARN // "none"),
     last_rotated:  (.LastRotatedDate   // "never"),
     last_accessed: (.LastAccessedDate  // "never retrieved in this region"),
     current_version: ((.VersionIdsToStages // {})
                       | to_entries
                       | map(select(.value | index("AWSCURRENT")))
                       | (.[0].key // "no AWSCURRENT version"))}'
done
```

`description` and `owner_tags` are what tell you which system the credential opens — if
they are empty for a drained secret, that gap is itself a §6 finding, because the blast
radius of this incident is then unknowable from AWS alone. `rotation` distinguishes the
secrets an automated function can replace from the ones a human has to rotate by hand, and
that split is the shape of the §4 work. Record `current_version` for every secret here:
it is the pre-rotation value the Recovery assertion in §5 compares against, and without it
that assertion cannot fail. A `kms_key` of `aws/secretsmanager` also settles one question
immediately — AWS does not permit cross-account access to a secret encrypted with the AWS
managed key, so those secrets were read by an in-account principal.

#### Query 4 — Full session reconstruction of the acting principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time:   .eventTime,
     event:  .eventName,
     source: .eventSource,
     target: (.requestParameters.secretId // .requestParameters.roleName
              // .requestParameters.userName // "n/a"),
     error:  (.errorCode // "SUCCESS"),
     ip:     .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Look for what came before and after the drain. `sts:AssumeRole` or `sts:GetSessionToken`
immediately before tells you how the credential was obtained. `secretsmanager:PutResourcePolicy`
after it is a persistence grant and routes to
`../secretsmanager.privilege-escalation.resource-based-permission-policy-attached-to-a-secret/`;
`secretsmanager:CancelRotateSecret` is the actor protecting the credential it just stole and
routes to `../secretsmanager.persistence.rotation-disabled/`;
`iam:CreateAccessKey` or `iam:AttachRolePolicy` routes to the IAM playbooks. A dense run of
`AccessDeniedException` before the successful reads is permission mapping and confirms this
was exploratory rather than a misconfigured application.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The plaintext is already gone; containment here means stopping *further* reads and starting
the rotation clock, in that order. **The ordering hazard is the rotation function itself.**
It is a Secrets Manager principal with `GetSecretValue` and `PutSecretValue` on the secrets
you are about to rotate, so a blanket `Deny secretsmanager:*` applied to "the account" or to
a shared role severs it — and every rotation you then order fails quietly while the
compromised value stays live. Scope every deny to the acting principal, confirm the rotation
role is not that principal, and rotate before you tighten anything account-wide.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being contained, and not under a principal that reads secrets.

#### Step 1 — Deny further secret reads by the acting principal only

```bash
SUSPECT_ARN="<caller-from-Query-1>"
ROTATION_ROLE_ARN="<rotation-function-execution-role-arn-from-§1>"

if [ "$SUSPECT_ARN" = "$ROTATION_ROLE_ARN" ]; then
  echo "[!] The acting principal IS the rotation execution role. Do NOT apply this deny —"
  echo "    it severs rotation for every secret in the account. Treat the rotation function"
  echo "    as compromised, disable its trigger, and escalate before containing."
  exit 1
fi

DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["secretsmanager:GetSecretValue","secretsmanager:BatchGetSecretValue","secretsmanager:ListSecrets"],"Resource":"*"}]}'

if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')          # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" \
    --policy-name "EmergencyDenySecretRead" --policy-document "$DENY_DOC"
  echo "[OK] Denied secret reads for role $R"
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')         # user ARN: name = last segment
  aws iam put-user-policy --user-name "$U" \
    --policy-name "EmergencyDenySecretRead" --policy-document "$DENY_DOC"
  echo "[OK] Denied secret reads for user $U"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root, federated or a"
  echo "    service principal. Contain manually; an inline policy cannot be attached to it."
fi
```

#### Step 2 — Revoke the principal's existing sessions and credentials

```bash
SUSPECT_ARN="<caller-from-Query-1>"
CUTOFF="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  KEYS=$(aws iam list-access-keys --user-name "$U" \
           --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text)
  if [ -z "$KEYS" ]; then
    echo "[!] INCONCLUSIVE: no active keys returned for $U. That is either a user with no"
    echo "    keys or a failed/denied list-access-keys call — check before moving on."
  else
    for K in $KEYS; do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] Disabled access key $K for $U"
    done
  fi
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
  echo "[OK] Revoked sessions issued before $CUTOFF for role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — contain manually."
fi
```

> `aws:TokenIssueTime` denies only tokens issued **before** the cutoff (rule E4). If the
> underlying host or workload is still compromised it can assume the role again and get a
> newer token that this condition does not deny. This kills the leaked session; it does not
> gate the role.

#### Step 3 — Clear any stale rotation state, then rotate every disclosed secret

```bash
REGION="us-east-1"
DRAINED_SECRETS="<secret-from-Query-1> <secret-from-Query-1>"

for S in $DRAINED_SECRETS; do
  META=$(aws secretsmanager describe-secret --secret-id "$S" --region "$REGION" --output json)
  if [ -z "$META" ]; then
    echo "[!] $S — INCONCLUSIVE: describe-secret returned nothing. Rotation NOT attempted."
    continue
  fi

  # A cancelled or failed rotation leaves AWSPENDING attached to a partial version, and AWS
  # documents that this can block every future rotation. Clear it BEFORE ordering one.
  PENDING=$(echo "$META" | jq -r '(.VersionIdsToStages // {}) | to_entries
              | map(select(.value | index("AWSPENDING"))) | (.[0].key // "")')
  if [ -n "$PENDING" ]; then
    echo "[!] $S has a stale AWSPENDING version ($PENDING) — clearing it first."
    aws secretsmanager update-secret-version-stage --secret-id "$S" \
      --version-stage AWSPENDING --remove-from-version-id "$PENDING" --region "$REGION"
  fi

  ROT=$(echo "$META" | jq -r 'if has("RotationEnabled") then (.RotationEnabled|tostring) else "unset" end')
  case "$ROT" in
    true)
      aws secretsmanager rotate-secret --secret-id "$S" --rotate-immediately --region "$REGION" \
        && echo "[OK] $S — rotation requested (asynchronous; verify in §5, do not assume)"
      ;;
    false|unset)
      echo "[!] $S — rotation is $ROT. No automated rotation exists for this secret."
      echo "    Rotate the underlying credential by hand at its own system, then store the"
      echo "    new value with put-secret-value. Until then the disclosed value is LIVE."
      ;;
  esac
done
```

> `rotate-secret` starts an **asynchronous** process. A successful CLI return means the
> rotation was accepted, not that it completed — §5 verifies it by comparing the version id
> carrying `AWSCURRENT` against the pre-incident snapshot. Never confirm a rotation by
> reading the value back: you cannot see the old value to compare against, so the check
> could not fail even if the rotation silently did.

#### Step 4 — Confirm the actor left no standing access to re-read the secrets

```bash
REGION="us-east-1"
DRAINED_SECRETS="<secret-from-Query-1> <secret-from-Query-1>"

for S in $DRAINED_SECRETS; do
  POL=$(aws secretsmanager get-resource-policy --secret-id "$S" --region "$REGION" --output json)
  if [ -z "$POL" ]; then
    echo "[!] $S — INCONCLUSIVE: get-resource-policy returned nothing. The call failed or the"
    echo "    credential lacks secretsmanager:GetResourcePolicy. NOT the same as 'no policy'."
    continue
  fi
  DOC=$(echo "$POL" | jq -r '.ResourcePolicy // ""')
  if [ -z "$DOC" ]; then
    echo "[OK] $S — no resource policy attached (the API returned a document with none)."
  else
    echo "[!] $S — resource policy PRESENT. Capture it before touching it:"
    echo "$DOC" | tee "/tmp/resource-policy-$(echo "$S" | tr '/:' '__').json"
    echo "    Evaluate and remove it via ../secretsmanager.privilege-escalation.resource-based-permission-policy-attached-to-a-secret/"
  fi
done
```

A resource policy on a drained secret is how the actor keeps reading it after every IAM
change you just made — including from another account. Capture the document before deleting
it; `DeleteResourcePolicy` returns nothing and the document is not recoverable afterwards.

---

## 4. Eradication

### Remove Attacker Access

#### Rotate everything, in order of what the credential opens

Work the Query 1 success list, not the alert count. Order by blast radius rather than by
convenience: any secret holding an **AWS access key** first — that is the account-takeover
path and it is rotated in IAM, not in Secrets Manager — then credentials to systems holding
regulated data, then everything else. For each AWS key found in a secret, disable it with
`aws iam update-access-key --status Inactive` and treat that key as a separate incident;
storing a long-lived IAM key in a secret is itself a §6 finding.

#### Rotate the secrets that no function can rotate

Query 3's `rotation` field splits the list. For `never configured` and `false`, there is no
automation: the credential has to be changed at the system it authenticates to — the
database, the SaaS console, the partner portal — and the new value written back with
`put-secret-value`. Until that happens the disclosed value is live regardless of anything
done in AWS. Track these individually; they are the ones that get forgotten.

#### Remove other persistence established in the same session

From Query 4, remediate everything else the principal did, each with its own playbook:
`PutResourcePolicy` on any secret →
`../secretsmanager.privilege-escalation.resource-based-permission-policy-attached-to-a-secret/`;
`CancelRotateSecret` → `../secretsmanager.persistence.rotation-disabled/`;
`UpdateSecret` or `PutSecretValue` → `../secretsmanager.persistence.secret-value-replaced/`;
`DeleteSecret` → `../secretsmanager.impact.secret-deleted/`; IAM
changes → `../iam.privilege-escalation.inline-policy-grant/` and
`../iam.persistence.role-trust-backdoor/`.

#### Right-size the permission that made the drain possible

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Look for secretsmanager:GetSecretValue or secretsmanager:* on Resource "*". Replace with
# an explicit list of that workload's own secret ARNs. A workload that needs two secrets
# should be able to read exactly two.
```

#### Remove the emergency policies once clean

```bash
SUSPECT_ARN="<caller-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
  for P in EmergencyDenySecretRead EmergencyRevokeSessions; do
    aws iam delete-role-policy --role-name "$R" --policy-name "$P"
  done
  LEFT=$(aws iam list-role-policies --role-name "$R" --query 'PolicyNames' --output json)
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  aws iam delete-user-policy --user-name "$U" --policy-name "EmergencyDenySecretRead"
  LEFT=$(aws iam list-user-policies --user-name "$U" --query 'PolicyNames' --output json)
else
  LEFT=""
fi

if [ -z "$LEFT" ]; then
  echo "[!] INCONCLUSIVE: could not list inline policies for $SUSPECT_ARN — the delete may"
  echo "    or may not have taken effect. Verify by hand before closing."
elif echo "$LEFT" | grep -q "Emergency"; then
  echo "[FAIL] emergency policies still attached: $LEFT"
else
  echo "[OK] no emergency policies remain on $SUSPECT_ARN"
fi
```

---

## 5. Recovery

### Restore Clean State

#### Verify every drained secret actually rotated — by version id, not by value

```bash
REGION="us-east-1"
# One "<secret> <pre-incident-AWSCURRENT-version-id>" pair per line, from Query 3's
# `current_version` field captured BEFORE the rotation was ordered.
PRE_ROTATION_VERSIONS="<secret-from-Query-1>:<current_version-from-Query-3>"

FAILED=0
for PAIR in $PRE_ROTATION_VERSIONS; do
  S="${PAIR%%:*}"; OLD="${PAIR##*:}"
  META=$(aws secretsmanager describe-secret --secret-id "$S" --region "$REGION" --output json)
  if [ -z "$META" ]; then
    echo "[!] $S — INCONCLUSIVE: describe-secret returned nothing. Rotation UNVERIFIED."
    FAILED=1; continue
  fi
  NEW=$(echo "$META" | jq -r '(.VersionIdsToStages // {}) | to_entries
          | map(select(.value | index("AWSCURRENT"))) | (.[0].key // "")')
  if [ -z "$NEW" ]; then
    echo "[!] $S — INCONCLUSIVE: no version carries AWSCURRENT. The secret is in an"
    echo "    inconsistent state; do not report it as rotated."
    FAILED=1
  elif [ -z "$OLD" ]; then
    echo "[!] $S — INCONCLUSIVE: no pre-incident version id was captured, so 'changed'"
    echo "    cannot be established. Current AWSCURRENT is $NEW."
    FAILED=1
  elif [ "$NEW" = "$OLD" ]; then
    echo "[FAIL] $S — AWSCURRENT is still $NEW. The disclosed value is STILL LIVE."
    FAILED=1
  else
    echo "[OK] $S — AWSCURRENT moved $OLD -> $NEW; the disclosed value is no longer current."
  fi
done
[ "$FAILED" -eq 0 ] && echo "[OK] every drained secret rotated" \
                    || echo "[FAIL] at least one secret is unrotated or unverified — do not close"
```

This is the assertion the whole response rests on, so it is built to fail three different
ways. An API error reaches `[!] INCONCLUSIVE` rather than the pass branch; a secret with no
`AWSCURRENT` is flagged rather than silently skipped; and a missing baseline is reported as
unverifiable rather than treated as changed. It also deliberately does **not** read the
secret value back — you cannot see the old value to compare against, so that check could not
fail even when rotation silently did.

#### Verify the disclosed value is no longer reachable through the old version

```bash
REGION="us-east-1"
SECRET="<secret-from-Query-1>"

# AWSPREVIOUS still resolves to the version the actor read. Confirm whether it does.
PREV=$(aws secretsmanager describe-secret --secret-id "$SECRET" --region "$REGION" --output json \
        | jq -r '(.VersionIdsToStages // {}) | to_entries
                 | map(select(.value | index("AWSPREVIOUS"))) | (.[0].key // "")')
if [ -z "$PREV" ]; then
  echo "[OK] $SECRET has no AWSPREVIOUS version — the disclosed version carries no staging label."
else
  echo "[!] $SECRET — AWSPREVIOUS is $PREV. Any principal with GetSecretValue on this secret"
  echo "    can still request that version explicitly with --version-stage AWSPREVIOUS."
  echo "    If $PREV is the version the actor read, remove the label:"
  echo "      aws secretsmanager update-secret-version-stage --secret-id $SECRET \\"
  echo "        --version-stage AWSPREVIOUS --remove-from-version-id $PREV --region $REGION"
fi
```

Rotation moves `AWSCURRENT`; it does not delete the old version. AWS keeps the 100 most
recent versions and keeps every version created in the last 24 hours regardless, so the
version the actor read remains retrievable by staging label until you remove the label.

#### Verify the acting principal can no longer read secrets

```bash
REGION="us-east-1"
SUSPECT_ARN="<caller-from-Query-1>"

RAW=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "<iso8601-containment-timestamp>" \
  --region "$REGION" --output json)

if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE: lookup-events returned nothing — call failed or no permission."
else
  N=$(echo "$RAW" | jq --arg who "$SUSPECT_ARN" '[.Events[].CloudTrailEvent | fromjson
        | select(.userIdentity.arn == $who) | select(.errorCode == null)] | length')
  if [ "$N" -eq 0 ]; then
    echo "[OK] no SUCCESSFUL secret reads by $SUSPECT_ARN since containment"
  else
    echo "[FAIL] $N successful read(s) by $SUSPECT_ARN since containment — the deny did not take"
  fi
fi
```

This check still emits a signal after the remediation, which is why it is usable: the deny
turns successful reads into denied ones, and denied events remain in the trail. Contrast it
with the check not written here — "confirm the secret's `LastAccessedDate` has not moved" —
which AWS documents at date granularity and which is omitted from a same-day incident on
that ground rather than treated as a passing assertion.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     one principal, 10+ SUCCESSFUL GetSecretValue events naming 10+"
echo "                  distinct requestParameters.secretId values inside 5 minutes"
echo "MUST fire on:     one BatchGetSecretValue with errorCode absent by a principal whose"
echo "                  ARN matches none of the batch_readers entries -- and the same call's"
echo "                  per-secret GetSecretValue fan-out must trip the count rule too"
echo "MUST NOT fire on: 10+ GetSecretValue events all carrying errorCode"
echo "                  AccessDeniedException (permission probing, not disclosure)"
echo "MUST NOT fire on: 40 GetSecretValue events naming the SAME secretId (retry storm)"
echo "MUST NOT fire on: an allowlisted ecs-task- role reading its own 4 configured secrets"
echo "EXPECTED FP, by design: a newly deployed workload whose role is not yet in"
echo "                  baselined_readers fires the first-seen rule on its first boot."
echo "                  Wire the allowlist to the pipeline that creates the role."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| One principal could read the values of many unrelated secrets | `secretsmanager:GetSecretValue` granted on `Resource: "*"` instead of an explicit list of that workload's own secret ARNs |
| The drain was counted in API calls, so the alert number did not match the rotation work-list | Volume rule counted events with no success filter and no distinct-secret count; the denied and disclosed cases were indistinguishable |
| A principal that had never read a secret before was not treated as notable | The first-seen rule tracked `sessionContext.sessionIssuer.userName`, which a long-term IAM user key does not carry, so the rule could not see the principal type it was named for |
| Some disclosed secrets had no automated rotation and no recorded owner | Rotation was optional per secret, and `Description`/tags were not required, so the blast radius of a disclosure was not answerable from AWS |
| Long-lived AWS access keys were stored as secret values | No control prevented an IAM credential from being placed in Secrets Manager, turning a secret read into an account-takeover path |
| The old secret version stayed retrievable after rotation | `AWSPREVIOUS` was left attached to the disclosed version; rotation was treated as complete at the API call rather than at the label move |

### Recommended Guardrails

**Scope secret reads to the secrets a workload owns**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Denies broad secret reads to everything except the named workload and break-glass roles.
// The condition value is wildcarded, so it MUST use StringNotLike, not StringNotEquals:
// with StringNotEquals a concrete ARN never equals the pattern, so the Deny matches every
// principal and the account loses all secret access -- an outage, not a bypass.
{
  "Effect": "Deny",
  "Action": ["secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/app-config-loader",
        "arn:aws:iam::*:role/SecretsRotation*",
        "arn:aws:iam::*:role/BreakGlassResponder"
      ]
    }
  }
}
```

**Structural controls**

- **Deny `secretsmanager:BatchGetSecretValue` outright** wherever it is unused — a second
  `Deny` statement of the same shape as above, naming only the bulk-read callers. It is a
  small, enumerable set, and removing the API removes the fastest drain path at no cost.
- **Encrypt every secret that matters with a customer-managed KMS key**, and scope the key
  policy to the workload's role. This adds a second, independently administered
  authorisation check to every read, and a drain then produces `DecryptionFailure` instead
  of a value. It is also the only way cross-account access can exist at all — AWS does not
  permit it with the AWS managed key `aws/secretsmanager`.
- **Ban long-lived IAM access keys as secret values.** Use IAM roles for AWS-to-AWS access
  so that a secret read cannot become an account-takeover hop.
- **Require `Description` and an owner tag on every secret**, enforced at creation — the
  blast radius of a disclosure is unanswerable without them.
- **Turn on rotation for every secret whose system supports it**, so the response to a
  disclosure is a scheduled function rather than a manual runbook per credential.
- **Give the rotation function its own execution role**, never shared with an application,
  so containment can deny an application role without severing rotation.

**Detection improvements**

- Count **distinct successful** `requestParameters.secretId` values per principal, never
  raw event volume — the alert number should be the rotation work-list length
- Track first-seen readers on `userIdentity.arn` measured against the principal's own
  trailing history, not on a session-only field and not against a static allowlist
- Alert on `DecryptionFailure` volume separately: it is a drain the key policy stopped, and
  it is the earliest possible warning that a principal is enumerating secrets
- Snapshot each secret's `AWSCURRENT` version id on a schedule, so the "did it rotate"
  assertion in §5 has a baseline and can fail

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1555.006 — Credentials from Password Stores: Cloud Secrets Management Stores (primary); T1119 — Automated Collection (batch path); T1526 — Cloud Service Discovery (`ListSecrets` precursor) |
| MITRE tactic | Credential Access (TA0006) |
| Primary API | `secretsmanager:ListSecrets` (optional enumeration) → `secretsmanager:GetSecretValue` per secret, or `secretsmanager:BatchGetSecretValue` for up to 20 at a time |
| Event source | `secretsmanager.amazonaws.com` — **management events, recorded by default**. Secrets Manager has no CloudTrail data-event resource type, verified against CloudTrail's supported-resource table and corroborated by GuardDuty's own data-source label |
| Batch fan-out | `BatchGetSecretValue` emits its own event **plus one `GetSecretValue` entry per secret requested** — AWS: *"generates CloudTrail GetSecretValue log entries for each secret you request"*. Counting `GetSecretValue` therefore covers the batch path; it does not under-count it |
| Key discriminator | The number of **distinct** `requestParameters.secretId` values one principal reads **successfully** in a window, relative to the number that principal's workload owns |
| Ground-truth signal | `requestParameters.secretId` on `GetSecretValue` events with `errorCode` absent — the exact, enumerable list of secrets whose plaintext was returned |
| Content limit | The value is **never** in CloudTrail. `SecretString`, `SecretBinary` and `RotationToken` all carry AWS's marker: *"the service does not include it in AWS CloudTrail log entries"* |
| "Was it used" pivot | Mostly **outside AWS**. These credentials authenticate to databases, SaaS platforms and partner APIs, which emit no CloudTrail. Retrieval is the last AWS-observable event and must be treated as terminal evidence. Inside AWS, pivot on `userIdentity.accessKeyId` for any AWS key found in a disclosed secret |
| Rotation verification | Compare the version id carrying `AWSCURRENT` in `DescribeSecret.VersionIdsToStages` against the pre-incident snapshot. **Never** verify by reading the value back — the old value is not visible, so that check cannot fail |
| Rotation ordering hazard | The rotation function is a Secrets Manager principal. A blanket `Deny secretsmanager:*` severs it and every later rotation fails silently. A stale `AWSPENDING` label blocks future rotations — AWS: *"Failing to clean up a cancelled rotation can block you from starting future rotations"* |
| Version retention | AWS keeps the 100 most recent versions and keeps **all** versions created in the last 24 hours. `AWSPREVIOUS` keeps the disclosed version retrievable by staging label until the label is removed |
| Blast radius | Every system whose credential was in a disclosed secret, plus the AWS account itself where any secret held an IAM access key. Cross-account reads are possible only where the secret uses a customer-managed KMS key |
| Batch limits | 20 secrets per call (`SecretIdList` max 20 items; `MaxResults` 1–20); `Filters` and `SecretIdList` mutually exclusive; `Filters` requires `secretsmanager:ListSecrets` as well |
| Error strings | `AccessDeniedException`, `NotAuthorized`, `DecryptionFailure`, `InternalServiceError`, `InvalidParameterException`, `InvalidRequestException`, `InvalidNextTokenException` (batch pagination), `ResourceNotFoundException`, `ThrottlingException`. Unsuffixed `AccessDenied` is **not** in the service's documented set, but an IAM-policy-evaluated denial can still surface that way — match both (rule A7) |
| Historical field wart | AWS notes that before February 2024 some Secrets Manager events carried `aRN` instead of `arn` for the secret ARN — relevant to hunts over old data |

**MITRE mapping note.** The source rules label this `T1552` (*Unsecured Credentials*) and
`T1555` (*Credentials from Password Stores*), both with tactic TA0006. T1552 is the weaker
of the two and is arguably wrong: it describes credentials left somewhere they should not
be — in a file, in a config, in instance metadata — whereas a secret in Secrets Manager is
stored exactly where an organisation intends it to be and is taken by an authorised-looking
API call. T1555.006 (*Credentials from Password Stores: Cloud Secrets Management Stores*) is
the sub-technique MITRE added for precisely this and is used here. `T1119` (*Automated
Collection*) is carried as a secondary on the batch path, and `T1526` (*Cloud Service
Discovery*) on the `ListSecrets` precursor. A mapping-precision note, not an operational
defect: the tactic the source rules chose is correct.

### Residual Risk

**Every credential in every disclosed secret is compromised and stays compromised until it
is changed at the system it authenticates to.** Rotation inside Secrets Manager replaces
what AWS stores; it does not reach into a partner API or a SaaS console. For any secret
whose `RotationEnabled` was `false` or unset, nothing in §3 or §4 changed the actual
credential, and the plaintext the actor holds still works.

**The plaintext left AWS, and its use is largely invisible.** The value was returned over
the wire and copied; no step here and no AWS control affects what happens to it next.
Database logins, SaaS API calls and partner integrations produce no CloudTrail, so the
absence of further AWS activity by the contained principal is evidence about AWS, not about
the credentials.

**The disclosed secret version may still be retrievable.** Rotation moves `AWSCURRENT` and
attaches `AWSPREVIOUS` to the version the actor read; AWS retains it under the 100-version
and 24-hour rules. Any principal that still holds `GetSecretValue` on that secret can
request it explicitly by staging label until the label is removed.

**Containment does not gate the role, and history is bounded.** The `aws:TokenIssueTime`
deny in §3 Step 2 kills sessions issued before the cutoff only — a still-compromised
workload can assume the role again and receive a token it does not deny, so the underlying
compromise is what closes that path. And CloudTrail Event history covers 90 days: without a
trail to S3 or a Lake event data store, a drain older than that leaves no evidence, and the
rotation work-list is necessarily incomplete.
