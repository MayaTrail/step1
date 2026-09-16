# IR Playbook: Excessive Parameter Creation Detected — Configuration Poisoning via `ssm:PutParameter` with `Overwrite`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Stored data manipulation (an existing Parameter Store value that a running workload reads is replaced, or a parameter is armed with an expiration policy that deletes it later with no delete event) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High** for an overwrite of an existing parameter by a principal outside the owning pipeline; **Medium** for an expiration policy or a name-enumeration burst; **Low** for bulk creation of genuinely new parameters. Severity tracks what reads the parameter: a database endpoint, an authorisation feature flag or an AMI ID consumed by a launch template turns one write into a change in how the workload behaves. The source rule rates the whole condition P4, which is right only for the case it names — creation — and wrong for the overwrite it also matches but never distinguishes |
| MITRE Tactics | Impact |
| MITRE Techniques | T1565.001 |
| Services in Scope | Systems Manager (Parameter Store), KMS where the parameter is a `SecureString`, CloudTrail, IAM, plus every workload that reads the parameter — EC2, ECS, Lambda, launch templates, SSM documents resolving `{{ssm:<name>}}` |

**What the technique does:** the actor calls `PutParameter` with `Overwrite` set to true
against a name that already exists. Parameter Store stores a new version and every
consumer that reads the parameter afterwards gets the actor's value — at the next
boot, the next refresh, or the next `SendCommand` whose document resolves
`{{ssm:<name>}}`. Nothing is deleted, nothing errors, and the parameter still
exists with the same name and type, so an inventory check finds nothing wrong. The
variant with a delay uses the `Policies` parameter instead: an `Expiration` policy
tells Parameter Store to delete the parameter at a future timestamp, and Parameter
Store performs that delete itself, so the principal that armed it never appears in
a `DeleteParameter` event.

**Detection thesis.** The discriminator is `requestParameters.overwrite` — or,
independently, `responseElements.version` greater than 1, since AWS documents that
editing a value automatically creates a new version — together with a writing
principal outside the pipeline that owns the path. The source rule matches
`putparameter` and counts it, so it treats a ten-parameter deployment as more
serious than the single overwrite of a production credential, and its group-by key
is absent for IAM-user principals entirely.

---

## 1. Preparation

**Logging & Visibility**

- CloudTrail multi-region trail. AWS states "Systems Manager logs all control
  plane operations to CloudTrail as management events"; the only SSM data events
  are `CreateControlChannel` / `OpenControlChannel` on
  `AWS::SSMMessages::ControlChannel` and `RequestManagedInstanceRoleToken` on
  `AWS::SSM::ManagedNode`. `PutParameter` is a management event, on by default
- `PutParameter` carries `requestParameters.name`, `.type`, `.overwrite`,
  `.keyId`, `.tier`, `.dataType`, `.policies` and `.description`.
  `responseElements` is **flat** — `version` and `tier`, no nesting — unlike
  `CreateDocument`, which nests under `documentDescription`
- **The parameter value is not something to plan on seeing.** AWS does not
  document whether `requestParameters.value` is recorded. If your trail does carry
  it, treat that as a finding: the CloudTrail bucket has become a secret store
  with a broader reader set than Parameter Store had
- Parameter version history is the only place the previous value survives:
  `GetParameterHistory` returns `Value`, `Version`, `LastModifiedDate` and
  `LastModifiedUser` per version, for the **100 most recent versions**
- `DescribeParameters` with `Key=Path,Option=Recursive` gives `LastModifiedUser`
  per parameter with no log at all — the fastest way to find everything one
  principal last wrote under a path, and it still works after the trail window has
  rolled
- A **known-good baseline** of the values that matter, or at least their hashes,
  held outside Parameter Store. Without it there is nothing to compare the live
  value against and the incident becomes a judgement call

**Alerting (must be pre-configured)**

- **A successful `PutParameter` with `overwrite` true, or with `responseElements.version` above 1, by a principal outside the configuration-writer allowlist → P0**
- **A successful `PutParameter` carrying an `Expiration` parameter policy → P1**
- **An overwrite of a parameter that an SSM document resolves through `{{ssm:<name>}}` or that a launch template consumes → P1**

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
| P0 | A successful `PutParameter` with `overwrite` true, or with `responseElements.version` above 1, by a principal outside the configuration-writer allowlist | CloudTrail (management) | T1565.001 |
| P1 | A successful `PutParameter` carrying an `Expiration` parameter policy | CloudTrail (management) | T1565.001, T1485 |
| P1 | An overwrite of a parameter that an SSM document resolves through `{{ssm:<name>}}` or that a launch template consumes | CloudTrail (management) | T1565.001 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Ten or more distinct parameter names rejected with `ParameterAlreadyExists` from one principal in five minutes — the write API used as a read oracle | CloudTrail (management) | T1526 |
| P2 | A `SecureString` parameter rewritten with a different `keyId` — the value is now under a key the original readers may not hold | CloudTrail (management) | T1565.001 |
| P3 | Ten or more successful `PutParameter` calls by one principal in five minutes | CloudTrail (management) | T1565.001 |

### Detection Rule Quality Notes

The source rule matches an API that creates *or* updates, calls it creation, and
then counts it.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `Overwrite` never inspected | The one case with a victim — an existing value replaced under a running workload — is scored below a ten-parameter deployment, because one is not more than ten | Alert on `requestParameters.overwrite: true` on a single event, with the writer allowlist |
| `responseElements.version` never read | A client that omits the `Overwrite` flag in a way the trail does not render still produces an overwrite; without the version check that case is invisible | Read `version > 1` as an independent proof and say so in triage |
| Grouped by `sessionContext.sessionIssuer.userName` | `sessionContext` exists only for role sessions, so every IAM user's events carry a null key and either bucket together or drop out — an IAM user can write indefinitely without the count ever accumulating | Group by `userIdentity.arn`, which every event carries |
| No success filter | A principal denied ten times fires the same alert as one that wrote ten parameters, and the restore work-list names parameters that were never changed | `success: {errorCode: null}` on the base rule and the correlation |
| `Policies` never inspected | An `Expiration` policy is a scheduled deletion that Parameter Store performs itself, so the armed destruction produces no `DeleteParameter` event and nothing else in the rule set sees it | Dedicated rule on `requestParameters.policies` containing `Expiration` |
| `ParameterAlreadyExists` discarded as an error | A principal with write but not read permission enumerates the parameter namespace through that error; the rule filters to no error state at all and never sees it | `value_count` correlation on distinct `requestParameters.name` for that error code |

**Recommended detection — an existing parameter replaced by an unexpected principal.**

```yaml
# Excessive Parameter Creation Detected (T1565.001)
#
# The original rule counted `putparameter` events, more than 10 in five minutes,
# grouped by userIdentity.sessionContext.sessionIssuer.userName. It calls the
# condition "creation", but PutParameter is create-OR-update: AWS documents it as
# "Create or update a parameter in Parameter Store", and the flag that separates
# the two is `Overwrite`, default false. Creating ten new parameters is a deploy.
# Overwriting one existing parameter that a running application reads is config
# poisoning, and the rule scores it lower, because one is not more than ten.
#
# The group-by is empty for IAM users: sessionContext is present only for role
# sessions, so every IAM user's events carry a null key. The rules below group by
# userIdentity.arn, which every event carries.
#
# Two things worth knowing that the original rule does not use. PutParameter's
# `Policies` parameter accepts an Expiration policy, which AWS documents as
# deleting the parameter when the timestamp is reached — a delayed destruction
# that produces no delete event from the principal that armed it. And a
# PutParameter without Overwrite against a name that already exists returns
# `ParameterAlreadyExists`, which makes the write API a name-enumeration oracle
# for a principal that cannot read.
#
# FIELD CASING: the SSM API Reference documents the wire format (`Overwrite`,
# `Policies`). AWS's published ssm.amazonaws.com CloudTrail examples render
# request keys with a lower-case initial, so the rules key on `overwrite` /
# `policies`. Confirm against one real event before deploying.
title: SSM parameter overwritten by a principal outside the owning pipeline
id: 7c93bdca-6830-4c98-9da9-6344e61d8c3b
name: ssm_parameter_overwritten
status: experimental
description: >-
  A successful PutParameter with Overwrite set replaces the value an application
  reads at boot or on refresh. The value itself is not in CloudTrail, so the
  parameter name and the writing principal are the whole signal.
references:
  - https://attack.mitre.org/techniques/T1565/001/
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html
  - https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-policy-conditions.html
tags:
  - attack.impact
  - attack.t1565.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'PutParameter'
  overwrite:
    requestParameters.overwrite: true
  success:
    errorCode: null
  parameter_writers:                   # tune: principals that own configuration writes
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/ci-cd'
      - ':role/config-admin'
  condition: selection and overwrite and success and not parameter_writers
falsepositives:
  - A secret rotation function writing a new value — allowlist the rotation role specifically, not the account
  - A manual configuration fix outside the pipeline; should be rare and traceable to a change record
level: high
---
title: SSM parameter written with an expiration policy attached
id: 60980f5c-985d-4b13-9fc1-4e0366bfc513
status: experimental
description: >-
  PutParameter carrying an Expiration parameter policy arms a deletion at a
  future timestamp. Parameter Store performs the delete itself, so the principal
  that armed it produces no DeleteParameter event at all.
references:
  - https://attack.mitre.org/techniques/T1565/001/
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html
tags:
  - attack.impact
  - attack.t1565.001
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'PutParameter'
  expiration_policy:
    requestParameters.policies|contains: 'Expiration'
  success:
    errorCode: null
  condition: selection and expiration_policy and success
falsepositives:
  - A team that legitimately uses expiring parameters for short-lived configuration — allowlist by path, and note that expiring parameters are an advanced-tier feature and therefore billed, which makes them rare
level: medium
---
title: Many distinct parameter names probed through PutParameter
id: 2c88f3b4-9791-4c46-863f-e89d174e4f53
status: experimental
description: >-
  PutParameter without Overwrite returns ParameterAlreadyExists when the name is
  taken. A principal that cannot read parameters can therefore enumerate which
  names exist by attempting to write them.
references:
  - https://attack.mitre.org/techniques/T1565/001/
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html
tags:
  - attack.discovery
  - attack.t1526
correlation:
  type: value_count
  rules:
    - ssm_put_parameter_name_taken
  group-by:
    - userIdentity.arn
  timespan: 5m
  field: requestParameters.name
  condition:
    gte: 10
falsepositives:
  - An idempotent deploy script that writes without Overwrite and tolerates the error — allowlist the deployment role
level: medium
---
title: PutParameter rejected because the name already exists
id: 66f54318-955b-42de-bd23-a6d5d69a8a37
name: ssm_put_parameter_name_taken
status: experimental
description: >-
  Base rule — count component only, not for direct alerting. A PutParameter that
  failed with ParameterAlreadyExists.
references:
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html
tags:
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'PutParameter'
  name_taken:
    errorCode: 'ParameterAlreadyExists'
  condition: selection and name_taken
level: low
---
title: High volume of parameter writes by one principal
id: 5139e06a-3a50-4532-a83e-80f1ba364cd3
status: experimental
description: >-
  The corrected form of the original volume rule — successful writes only, and
  grouped by userIdentity.arn rather than a session-issuer field that is absent
  for IAM users. Kept as a secondary signal; the overwrite rule above is the one
  that catches a single deliberate write.
references:
  - https://attack.mitre.org/techniques/T1565/001/
tags:
  - attack.impact
  - attack.t1565.001
correlation:
  type: event_count
  rules:
    - ssm_parameter_written
  group-by:
    - userIdentity.arn
  timespan: 5m
  condition:
    gte: 10
falsepositives:
  - Infrastructure-as-code seeding a new environment's configuration set — allowlist the deployment role, which is the only principal that should write in bulk
level: low
---
title: SSM parameter written
id: 2a5a00b0-2b70-40a3-8734-9a11f0f78481
name: ssm_parameter_written
status: experimental
description: >-
  Base rule — count component only, not for direct alerting. A successful
  PutParameter, create or update.
references:
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html
tags:
  - attack.impact
  - attack.t1565.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'PutParameter'
  success:
    errorCode: null
  condition: selection and success
level: low
```

The rule cannot tell a harmful value from a harmless one, because the value is not
in the event — that judgement comes from Query 2's version-history diff. It also
cannot see the second proof of overwrite, `responseElements.version > 1`, in a
form Sigma can compare numerically; the KQL and Query 1 read it instead. And it
cannot catch a parameter deleted by an `Expiration` policy it armed earlier, since
Parameter Store performs that delete under its own identity — the expiration rule
in the same file is the only warning you get, and it fires at arming time, not at
deletion time.

---

### Key Investigation Queries

> Parameter Store is **regional** — run these in every Region the account uses.
> Extraction uses `--output json | jq -r '.Events[].CloudTrailEvent | fromjson'`.
> **`lookup-events` returns ≤50 events per page**; paginate on `NextToken` for a
> busy window.

#### Query 1 — Reconstruct: which parameters were written, by whom, create or overwrite

```bash
REGION="<region>"
START="$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"

aws cloudtrail lookup-events --region "$REGION" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutParameter \
  --start-time "$START" --max-results 50 --output json \
| jq -r '.Events[].CloudTrailEvent | fromjson' \
| jq -s '
  map({
    time:      .eventTime,
    caller:    (.userIdentity.arn // "unknown"),
    accessKey: (.userIdentity.accessKeyId // "none"),
    session:   ((.userIdentity.arn // "") | split("/") | last),
    sourceIp:  .sourceIPAddress,
    parameterName: (.requestParameters.name // .requestParameters.Name // ""),
    type:      (.requestParameters.type // .requestParameters.Type // ""),
    keyId:     (.requestParameters.keyId // .requestParameters.KeyId // ""),
    policies:  (.requestParameters.policies // .requestParameters.Policies // ""),
    # Two independent proofs that an EXISTING parameter was modified.
    overwriteFlag: ((.requestParameters.overwrite // .requestParameters.Overwrite) == true),
    newVersion:    (.responseElements.version // .responseElements.Version // 0),
    error:     (.errorCode // "none")
  })
  | map(. + { modifiedExisting: (.overwriteFlag or (.newVersion > 1)) })
  | sort_by(.time)'
```

`modifiedExisting: true` is the P0 set and the restore work-list. A row with
`overwriteFlag: false` but `newVersion` above 1 is the same finding arrived at from
the response side, and it is the one a client that omitted the flag produces.
`policies` containing `Expiration` is a scheduled deletion armed for later — note
the timestamp inside it, because nothing else in the log will mark that deletion
when it happens. A changed `keyId` on a `SecureString` means the value is now
under a different key, and consumers holding `kms:Decrypt` on only the old key
will start failing. `error: ParameterAlreadyExists` rows are not failures to
ignore: a run of them against distinct names is namespace enumeration by a
principal that cannot read.

#### Query 2 — Inspect: the previous value, and everything else that principal touched

```bash
REGION="<region>"
PARAM_NAME="<parameter-name-from-Query-1>"
CALLER="<caller-arn-from-Query-1>"
PARAM_PATH="<path-prefix-under-investigation>"

# The only place the pre-incident value survives. Pull it BEFORE remediating:
# Parameter Store keeps the 100 most recent versions and an attacker who rewrites
# the same parameter 100 times pushes the original out permanently.
HIST="$(aws ssm get-parameter-history --region "$REGION" --name "$PARAM_NAME" \
        --with-decryption --output json)"
RC=$?

if [ "$RC" -ne 0 ] || [ -z "$HIST" ]; then
  echo "[!] INCONCLUSIVE — get-parameter-history failed for $PARAM_NAME. The previous"
  echo "    value cannot be read here; fall back to the configuration baseline from §1."
else
  printf '%s' "$HIST" | jq '[.Parameters[]
    | {Version, LastModifiedDate, LastModifiedUser, Type, KeyId,
       Policies: (.Policies // []), ValueSha256: (.Value | @base64 | length)}]
    | sort_by(.Version)'
  echo "[!] Values are deliberately NOT printed above. Diff them in a controlled place:"
  echo "    aws ssm get-parameter-history --name $PARAM_NAME --with-decryption \\"
  echo "      --query 'Parameters[].{V:Version,User:LastModifiedUser,Val:Value}'"
fi

# Everything under the path this principal last wrote — works with no log at all.
aws ssm describe-parameters --region "$REGION" --output json \
  --parameter-filters "Key=Path,Option=Recursive,Values=$PARAM_PATH" \
| jq --arg c "$CALLER" '[.Parameters[] | select(.LastModifiedUser == $c)
    | {Name, Type, KeyId, Version, LastModifiedDate, LastModifiedUser,
       Policies: (.Policies // [])}]'
```

Read the history from the bottom up. The last version whose `LastModifiedUser` is
a legitimate writer is the known-good; every version above it is the actor's.
`Policies` on any version shows an expiration armed at that point. The second
command is the sweep: it names every parameter under the path whose most recent
write was by the suspect principal, without touching CloudTrail at all, which
matters when the incident is older than the trail's retention. It only sees the
**most recent** writer, so a parameter the actor changed and someone else has
since rewritten will not appear — cross-check against Query 1's
`parameterName` list.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="PutParameter"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "ssm.amazonaws.com") |
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

Capture the version history before you restore anything: the restore itself
consumes a version, and the 100-version window is the only place the pre-incident
value exists. Then restore, then contain the principal — in that order, because
containing a principal that turns out to be the deployment pipeline stops the
release that would otherwise correct the value.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Preserve the history, then restore the known-good value

```bash
REGION="<region>"
PARAM_NAME="<parameter-name-from-Query-1>"
KNOWN_GOOD_VERSION="<version-from-Query-2-history>"
EVIDENCE_DIR="/tmp/ir-ssm-param"
mkdir -p "$EVIDENCE_DIR"

HIST="$(aws ssm get-parameter-history --region "$REGION" --name "$PARAM_NAME" \
        --with-decryption --output json)"
RC=$?

if [ "$RC" -ne 0 ] || [ -z "$HIST" ]; then
  echo "[FAIL] could not read the history for $PARAM_NAME — NOT restoring."
  echo "       Overwriting now consumes a version and may push the original out of the"
  echo "       100-version window. Restore from the §1 baseline instead."
else
  printf '%s' "$HIST" > "$EVIDENCE_DIR/$PARAM_NAME.history.json"
  echo "[OK] history preserved at $EVIDENCE_DIR/$PARAM_NAME.history.json"

  GOOD="$(printf '%s' "$HIST" | jq -r --argjson v "$KNOWN_GOOD_VERSION" \
          '.Parameters[] | select(.Version == $v) | .Value // empty')"
  PTYPE="$(printf '%s' "$HIST" | jq -r --argjson v "$KNOWN_GOOD_VERSION" \
           '.Parameters[] | select(.Version == $v) | .Type // empty')"

  if [ -z "$GOOD" ] || [ -z "$PTYPE" ]; then
    echo "[FAIL] version $KNOWN_GOOD_VERSION not present in the history — nothing restored."
  else
    aws ssm put-parameter --region "$REGION" --name "$PARAM_NAME" \
      --value "$GOOD" --type "$PTYPE" --overwrite
    echo "[OK] $PARAM_NAME restored from version $KNOWN_GOOD_VERSION"
    echo "[!] consumers keep the poisoned value until they refresh — restart or force-refresh"
    echo "    every workload that reads $PARAM_NAME and record which ones in the incident."
  fi
fi
```

If the parameter carried an `Expiration` policy, the restore above does **not**
remove it — AWS states all existing policies are preserved until you send new
policies or an empty policy. Send an empty policy explicitly with
`--policies '[]'` on a follow-up `put-parameter`, and verify in §5.

#### Step 2 — Contain the principal

```bash
PRINCIPAL_ARN="<caller-arn-from-Query-1>"
POLICY_NAME="IR-ParamStore-Write-Freeze"

cat > /tmp/ir-paramstore-write-freeze.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "FreezeParameterWrites",
      "Effect": "Deny",
      "Action": ["ssm:PutParameter", "ssm:DeleteParameter", "ssm:DeleteParameters",
                 "ssm:LabelParameterVersion", "ssm:AddTagsToResource"],
      "Resource": "*" }
  ]
}
JSON

case "$PRINCIPAL_ARN" in
  *:user/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $NF}')"
    aws iam put-user-policy --user-name "$IAM_NAME" \
      --policy-name "$POLICY_NAME" --policy-document file:///tmp/ir-paramstore-write-freeze.json
    echo "[OK] write freeze applied to IAM user $IAM_NAME" ;;
  *:assumed-role/*|*:role/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $2}')"
    aws iam put-role-policy --role-name "$IAM_NAME" \
      --policy-name "$POLICY_NAME" --policy-document file:///tmp/ir-paramstore-write-freeze.json
    echo "[OK] write freeze applied to role $IAM_NAME"
    echo "[!] if this role is the deployment pipeline, configuration releases now fail —"
    echo "    say so in the channel before the next deploy blocks on it" ;;
  *:root)
    echo "[!] root credential — no policy denies root. Rotate the root password, remove"
    echo "    any root access key, confirm root MFA." ;;
  *)
    echo "[!] unrecognised principal shape: $PRINCIPAL_ARN — contain manually." ;;
esac
```

---

## 4. Eradication

### Remove Attacker Access

- **Restore every parameter in Query 1's `modifiedExisting` set and Query 2's
  sweep**, oldest write first, so a parameter the actor touched twice is not
  restored to an intermediate version. Each restore consumes a version — count
  them against the 100-version cap before you start
- **Send an empty policy to any parameter carrying an `Expiration`** —
  `aws ssm put-parameter --name <n> --value <v> --type <t> --overwrite --policies '[]'`.
  Existing policies survive an ordinary overwrite, so a restore alone leaves the
  scheduled deletion armed and it fires later with nobody attached to it
- **Restart or force-refresh every consumer.** A workload that read the poisoned
  value holds it until it refreshes; the parameter being correct is not the same
  as the system being correct. Name the consumers in the incident record
- **Check for a changed `keyId` on any `SecureString`.** If the actor rewrote the
  parameter under a different KMS key, consumers with `kms:Decrypt` on only the
  original key now fail at read time — an availability problem that surfaces hours
  later, at the next restart
- **Right-size `ssm:PutParameter`.** Scope it to the path the writer owns, and add
  a `Deny` conditioned on `ssm:Overwrite` for principals that should be able to
  create but never modify. Both `ssm:Overwrite` and `ssm:Policies` are real
  condition keys
- **Remove the emergency policy once clean, with a real check** — §5 asserts it
  rather than assuming it landed on the right principal

---

## 5. Recovery

### Restore Clean State

#### Verify the live value matches the baseline and no expiration remains armed

```bash
REGION="<region>"
PARAM_NAME="<parameter-name-from-Query-1>"
BASELINE_SHA256="<sha256-of-the-known-good-value-from-the-section-1-baseline>"

RAW="$(aws ssm get-parameter --region "$REGION" --name "$PARAM_NAME" \
        --with-decryption --output json)"
GRC=$?
META="$(aws ssm describe-parameters --region "$REGION" --output json \
         --parameter-filters "Key=Name,Values=$PARAM_NAME")"
MRC=$?

if [ "$GRC" -ne 0 ] || [ -z "$RAW" ] || [ "$MRC" -ne 0 ] || [ -z "$META" ]; then
  echo "[!] INCONCLUSIVE — a read failed for $PARAM_NAME; neither the value nor the"
  echo "    policy state is established. Re-run with credentials holding ssm:GetParameter,"
  echo "    ssm:DescribeParameters and kms:Decrypt on the parameter's key."
else
  VAL="$(printf '%s' "$RAW" | jq -r '.Parameter.Value // empty')"
  if [ -z "$VAL" ]; then
    # Value has a documented minimum length of 1, so empty means the read did not
    # return a parameter — not that the parameter is empty.
    echo "[!] INCONCLUSIVE — no value returned for $PARAM_NAME; the parameter may have"
    echo "    been deleted, or decryption was denied. This is not a clean result."
  else
    LIVE_SHA="$(printf '%s' "$VAL" | openssl dgst -sha256 -r | awk '{print $1}')"
    if [ "$LIVE_SHA" = "$BASELINE_SHA256" ]; then
      echo "[OK] $PARAM_NAME matches the known-good baseline"
    else
      echo "[FAIL] $PARAM_NAME does NOT match the baseline ($LIVE_SHA != $BASELINE_SHA256)"
    fi
  fi

  NPOL="$(printf '%s' "$META" | jq '[.Parameters[0].Policies // [] | .[]
           | select(.PolicyType == "Expiration")] | length')"
  LASTUSER="$(printf '%s' "$META" | jq -r '.Parameters[0].LastModifiedUser // empty')"
  if [ -z "$LASTUSER" ]; then
    echo "[!] INCONCLUSIVE — $PARAM_NAME returned no metadata; it may no longer exist"
  elif [ "$NPOL" -eq 0 ]; then
    echo "[OK] no Expiration policy remains on $PARAM_NAME; last written by $LASTUSER"
  else
    echo "[FAIL] $NPOL Expiration policy still armed on $PARAM_NAME — send --policies '[]'"
  fi
fi
```

Both halves can fail and both distinguish "could not check" from "clean". The
value check compares hashes rather than printing secrets, and it is deliberately
independent of CloudTrail — the trail cannot answer it, because the value was
never in it.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     eventSource=ssm.amazonaws.com eventName=PutParameter"
echo "                  requestParameters.name=/app/prod/db/endpoint"
echo "                  requestParameters.overwrite=true  errorCode absent"
echo "                  userIdentity.arn=arn:aws:iam::111122223333:user/contractor"
echo "MUST fire on:     the same call with requestParameters.policies containing"
echo "                  {\"Type\":\"Expiration\",...} — the armed-deletion rule"
echo "MUST NOT fire on: PutParameter with overwrite absent or false creating a NEW name"
echo "                  (a first write is a deployment, not a modification)"
echo "MUST NOT fire on: the same overwrite by userIdentity.arn containing :role/iac-deploy"
echo "                  (the allowlisted pipeline doing its job)"
echo "MUST NOT fire on: PutParameter carrying errorCode=ParameterAlreadyExists"
echo "                  (nothing was written; it belongs in the enumeration correlation)"
echo "EXPECTED FP, by design: a secret-rotation function writing a new value. Allowlist"
echo "                  the rotation role specifically — never the whole account."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the owning pipeline could replace the value of an existing parameter | `ssm:PutParameter` granted on `parameter/*` with no path scope and no `ssm:Overwrite` condition, so create and modify were the same permission |
| The change was invisible to inventory checks | Nothing was created or deleted; the name, type and tier were unchanged, and only the version number moved |
| The previous value had to be recovered from the parameter itself | No known-good configuration baseline held outside Parameter Store, so the 100-version history was the only source and the attacker could have exhausted it |
| A scheduled deletion could be armed without producing a delete event | `ssm:Policies` unrestricted, so an `Expiration` policy could be attached and Parameter Store performs the deletion under its own identity |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Separate "may create" from "may modify". ssm:Overwrite and ssm:Policies are STRING
// condition keys valued "true"/"false" — AWS's own examples use StringEquals, not Bool.
// StringEquals is correct here because the values are exact; the principal allowlist is
// wildcarded and so needs ArnNotLike. Deny + ArnNotEquals against a wildcard fails
// CLOSED and blocks the pipeline along with everyone else.
{
  "Sid": "NoParameterOverwriteOrExpiryOutsidePipeline",
  "Effect": "Deny",
  "Action": "ssm:PutParameter",
  "Resource": "arn:aws:ssm:*:*:parameter/*",
  "Condition": {
    "StringEquals": { "ssm:Overwrite": "true" },
    "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/iac-deploy" }
  }
}
```

- **Hold a known-good baseline of the values that matter outside Parameter
  Store** — hashes are enough, and they make §5's assertion possible at all.
  Without one, "is the value correct" has no answer that does not depend on the
  same store the attacker wrote to
- **Deny `ssm:Policies` for every principal that does not need expiring
  parameters.** They are an advanced-tier, billed feature, so the denial costs
  almost nothing and it removes a destruction path that produces no delete event
- **Scope write permissions by path.** `arn:aws:ssm:<region>:<account>:parameter/app/prod/*`
  for the pipeline that owns production configuration, and a separate grant for
  everything else, so one over-broad role cannot reach both

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1565.001 — Data Manipulation: Stored Data Manipulation |
| MITRE tactic | Impact (TA0040) |
| Primary API | `ssm:PutParameter` with `Overwrite`; `Policies` with an `Expiration` type for the delayed-deletion variant |
| Event source | `ssm.amazonaws.com` — **management** events, recorded by default. Verified: AWS states "Systems Manager logs all control plane operations to CloudTrail as management events", and the only SSM data-event resource types are `AWS::SSMMessages::ControlChannel` and `AWS::SSM::ManagedNode` |
| Key discriminator | `requestParameters.overwrite == true`, corroborated independently by `responseElements.version > 1` — AWS documents that editing a value automatically creates a new version |
| Field shape | `responseElements` is **flat** here (`version`, `tier`) — unlike `CreateDocument`, which nests under `documentDescription` |
| "Was it used" pivot | The consumers. Nothing in CloudTrail records a workload reading the poisoned value; the pivot is the consumer's own restart and refresh log, plus `GetParameter` reads by the workload role after the write time |
| Blast radius | Every workload that reads the parameter, including SSM documents resolving `{{ssm:<name>}}` at execution time and launch templates consuming an AMI-ID parameter |
| Evidence limit | The previous value exists only in the parameter's history, capped at **100 versions**; each restore consumes one. `LastModifiedUser` from `DescribeParameters` survives the trail window |
| Error strings | `ParameterAlreadyExists`, `ParameterLimitExceeded`, `ParameterMaxVersionLimitExceeded`, `ParameterPatternMismatchException`, `HierarchyLevelLimitExceededException`, `HierarchyTypeMismatchException`, `InvalidAllowedPatternException`, `InvalidKeyId`, `UnsupportedParameterType`, `PoliciesLimitExceededException`, `InvalidPolicyTypeException`, `InvalidPolicyAttributeException`, `IncompatiblePolicyException`, `TooManyUpdates`, `InternalServerError`; denials as `AccessDenied` and `AccessDeniedException` |
| HTTP 200 ≠ success | A parameter with `DataType: aws:ec2:image` is validated asynchronously — AWS states "a successful HTTP 200 response does not guarantee that your parameter was successfully created or updated" |

**MITRE mapping note.** The source rule maps T1082 (*System Information
Discovery*) under TA0007. Writing a parameter discovers nothing about the system;
overwriting one changes it. T1565.001 (*Data Manipulation: Stored Data
Manipulation*) under Impact (TA0040) is the mapping for the case with a victim.
There is one genuinely Discovery-shaped signal in this use case — the
`ParameterAlreadyExists` name oracle, where a principal with write but not read
permission enumerates the namespace through the error — and it is tagged T1526
(*Cloud Service Discovery*) on its own rule rather than folded into the primary
mapping. The directory slug keeps the source's `discovery` label so the register
stays navigable.

### Residual Risk

**A consumer that already read the value keeps it.** Restoring the parameter
changes what the *next* read returns. Anything holding the poisoned value in
memory, in a connection string, or baked into a launched instance keeps using it
until it refreshes, and there is no AWS-side signal that tells you which consumers
those are.

**The history window can be exhausted, and it is exhausted by the attack.**
Parameter Store keeps 100 versions. A principal that rewrites one parameter a
hundred times destroys the pre-incident value permanently, and every restore you
perform consumes another version. Where the count is close, take the history to a
file before touching anything.

**An expiration policy survives an ordinary restore.** AWS states existing
policies are preserved until you send new policies or an empty policy, so a
parameter restored with `--overwrite` alone is still scheduled for deletion at the
timestamp the actor chose — and when it fires, nothing in CloudTrail attributes it
to them.

**`LastModifiedUser` records only the most recent writer.** A parameter the actor
changed and someone else has since rewritten shows the innocent principal, and the
actor's write is visible only in the version history and the trail — both of which
have limits the actor can push past.
