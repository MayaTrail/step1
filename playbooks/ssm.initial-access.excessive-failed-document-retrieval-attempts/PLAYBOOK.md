# IR Playbook: Excessive Failed Document Retrieval Attempts — SSM Document Namespace Enumeration via `ssm:GetDocument`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Cloud service discovery (a principal probes SSM document names it cannot retrieve, mapping what exists in the account before deciding what to run) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **Medium** for the enumeration alone — it is reconnaissance and grants nothing — and **High** as soon as a successful retrieval follows it, because SSM documents routinely carry bootstrap tokens, internal endpoints, the parameter names an application reads, and the `assumeRole` an Automation runs under. The source rule rates it P2 and labels it brute force, which routes it to a credential-stuffing runbook where the responder hunts a compromised password that does not exist |
| MITRE Tactics | Discovery |
| MITRE Techniques | T1526 |
| Services in Scope | Systems Manager (Documents, Run Command, Automation, Session Manager), CloudTrail, IAM, plus Parameter Store where a document names the parameters it reads |

**What the technique does:** the principal calls `GetDocument` with a document name it is
guessing — from a wordlist, from AWS's public document naming conventions, or from
names it saw in a repository — and reads the error to learn whether the name
exists. AWS returns `InvalidDocument` both when the document does not exist and
when it exists but is not available to that caller, so a single error covers both
outcomes and the caller learns "not reachable" rather than "not there". Names that
do resolve are read, and their content is the payoff: SSM documents are not treated
as secrets and regularly carry hard-coded endpoints, embedded tokens,
`{{ssm:<name>}}` references naming the parameters an application reads, and the
`assumeRole` ARNs an Automation document executes under. The enumeration is
reconnaissance for the execution playbooks — `SendCommand`, `StartSession`,
`CreateAssociation` — that follow.

**Detection thesis.** The discriminator is the number of **distinct document names
that failed** for one principal, matched on both `InvalidDocument` and
`AccessDenied` families — not the number of attempts and not `AccessDenied` alone.
The source rule filters to `errorCode:"AccessDenied"`, which is the one error a
name-guessing principal does **not** generate, so it discards the entire
enumeration path and keeps the misconfigured-client case instead.

---

## 1. Preparation

**Logging & Visibility**

- CloudTrail multi-region trail. AWS states "Systems Manager logs all control
  plane operations to CloudTrail as management events"; the only SSM data events
  are `CreateControlChannel` / `OpenControlChannel` on
  `AWS::SSMMessages::ControlChannel` and `RequestManagedInstanceRoleToken` on
  `AWS::SSM::ManagedNode`. `GetDocument` is a management event, on by default —
  including its failures
- `GetDocument` carries `requestParameters.name`, `.documentVersion`,
  `.documentFormat` and `.versionName`; `DescribeDocument` carries `name` too, so
  both can be counted on the same field
- **`errorCode` is the whole game and there are two families.** `InvalidDocument`
  is documented as "The SSM document doesn't exist **or the document isn't
  available to the user**" — one error for two very different facts —
  and `InvalidDocumentVersion` sits beside it. IAM denials surface as
  `AccessDenied`, service-evaluated denials as `AccessDeniedException`. Match with
  `contains` so both pairs are caught, and confirm the exact strings against a real
  denied event in your own trail
- **`sessionContext` is present only for role sessions.** An IAM user's event has
  no `sessionContext` at all, so any rule grouped on
  `sessionContext.sessionIssuer.userName` gives every IAM user a null key. Group on
  `userIdentity.arn`
- A list of the documents that legitimately exist and who reads them, so a probed
  name can be classified in one lookup rather than one per name

**Alerting (must be pre-configured)**

- **A burst of failed distinct document names followed by a successful retrieval by the same principal within fifteen minutes → P0**
- **Ten or more distinct SSM document names failing retrieval for one principal within five minutes → P1**

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
| P0 | A burst of failed distinct document names followed by a successful retrieval by the same principal within fifteen minutes | CloudTrail (management) | T1526 |
| P1 | Ten or more distinct SSM document names failing retrieval for one principal within five minutes | CloudTrail (management) | T1526 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Twenty-five or more distinct document names read **successfully** by one principal in five minutes — the enumerator that produces no errors | CloudTrail (management) | T1526 |
| P2 | The same principal following enumeration with `CreateDocument`, `SendCommand`, `StartSession` or `CreateAssociation` | CloudTrail (management) | T1651 |
| P3 | Ten or more `AccessDenied` responses on `GetDocument` from one principal — usually a misconfigured client, occasionally a probe from a principal with almost no permissions | CloudTrail (management) | T1526 |

### Detection Rule Quality Notes

The source rule filters to the one error a name-guessing principal does not
produce.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `errorCode:"AccessDenied"` only | `InvalidDocument` — documented as "doesn't exist **or** isn't available to the user" — is what a name-guessing principal receives, and it is filtered out. The rule sees the misconfigured-client case and is blind to the enumeration it exists to catch | Match `errorCode|contains` on both `AccessDenied` and `InvalidDocument`, which also catches `AccessDeniedException` and `InvalidDocumentVersion` |
| Counts attempts, not distinct names | Ten retries of one document name by a broken deployment script fires identically to ten names probed, so the alert cannot be triaged without opening every event | `value_count` correlation on distinct `requestParameters.name` |
| Grouped by `sessionContext.sessionIssuer.userName` | Absent for IAM users, so every IAM user carries a null key and either buckets together or drops out — an IAM user can probe indefinitely without the count accumulating | Group by `userIdentity.arn`, which every event carries |
| No success side at all | The question that decides severity — did the enumeration find anything — is not asked, so a P2 is raised whether the principal found nothing or found a document with a token in it | `temporal_ordered` correlation from the failure burst to a successful `GetDocument` |
| Blind to the permitted enumerator | A principal with `ssm:GetDocument` on `*` enumerates by reading and produces no errors, so no error-based rule can ever see it | Second `value_count` correlation on distinct names read **successfully** |
| Labelled brute force | Routes the alert to a credential-stuffing runbook, where the responder searches for a compromised password. `GetDocument` takes a document name; nothing authenticates | Map to T1526 (*Cloud Service Discovery*); see §6 |

**Recommended detection — document-name enumeration by distinct failed names.**

```yaml
# Excessive Failed Document Retrieval Attempts (T1526)
#
# The original rule matched
#   eventSource:"ssm.amazonaws.com" AND eventName:"getdocument" AND errorCode:"AccessDenied"
# at more than 10 in five minutes, grouped by
# userIdentity.sessionContext.sessionIssuer.userName.
#
# The error code is the defect. AWS documents GetDocument's InvalidDocument error
# as "The SSM document doesn't exist or the document isn't available to the user",
# and that is the error a principal guessing document names receives — for names
# that do not exist AND for documents that exist but are not shared with it. The
# original rule filters that entire path out. What it keeps, AccessDenied, is the
# IAM-denied case: a principal that lacks ssm:GetDocument outright, which is a
# misconfigured client far more often than an actor.
#
# Two more problems. Counting ATTEMPTS rather than distinct NAMES makes ten
# retries of one document by a broken script indistinguishable from ten names
# probed; the rules below count distinct requestParameters.name. And
# sessionContext is present only for role sessions, so every IAM user's events
# carry a null group-by key and either bucket together or drop out of the
# aggregation entirely — the rules below group by userIdentity.arn.
#
# The enumerator who has permission produces no errors at all and is invisible to
# any error-based rule. That case is covered by the third correlation here,
# counting distinct document names read successfully.
title: SSM document name enumeration through failed retrievals
id: 608de217-3602-40d1-b5f6-d8efdd222c4b
name: ssm_document_enumeration_burst
status: experimental
description: >-
  Ten or more distinct SSM document names failing retrieval for one principal in
  five minutes. Distinct names, not attempts — a retry loop against one name is a
  broken client, ten names is a principal mapping what exists.
references:
  - https://attack.mitre.org/techniques/T1526/
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetDocument.html
tags:
  - attack.discovery
  - attack.t1526
correlation:
  type: value_count
  rules:
    - ssm_getdocument_failed
  group-by:
    - userIdentity.arn
  timespan: 5m
  field: requestParameters.name
  condition:
    gte: 10
falsepositives:
  - A deployment tool iterating a document list that has drifted from what exists — the names will look like a coherent naming scheme rather than a wordlist
level: medium
---
title: SSM document retrieval failed
id: 8b45abc0-5a79-41ba-8ef1-eec592237da1
name: ssm_getdocument_failed
status: experimental
description: >-
  Base rule — count component only, not for direct alerting. A GetDocument that
  failed. `contains` rather than equality so both AccessDenied and
  AccessDeniedException match, and both InvalidDocument and InvalidDocumentVersion.
references:
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetDocument.html
tags:
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'GetDocument'
  failed:
    errorCode|contains:
      - 'AccessDenied'
      - 'InvalidDocument'
  condition: selection and failed
level: low
---
title: SSM document enumeration followed by a successful retrieval
id: 5b776591-a210-4782-b13b-fcb85fcc426d
status: experimental
description: >-
  A burst of failed name probes and then a document read successfully by the same
  principal. The enumeration found something, and whatever it found is now in the
  actor's hands — including any credential or endpoint embedded in the document.
references:
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
correlation:
  type: temporal_ordered
  rules:
    - ssm_document_enumeration_burst
    - ssm_document_read_success
  group-by:
    - userIdentity.arn
  timespan: 15m
level: high
---
title: SSM document read successfully
id: f9f3d8a1-6c2b-4e0d-9a77-3d1c8b5e2f04
name: ssm_document_read_success
status: experimental
description: >-
  Base rule — sequence and count component only, not for direct alerting. A
  successful GetDocument or DescribeDocument. Both carry requestParameters.name.
references:
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetDocument.html
tags:
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName:
      - 'GetDocument'
      - 'DescribeDocument'
  success:
    errorCode: null
  condition: selection and success
level: low
---
title: SSM document enumeration by a principal that has permission
id: 0e6b1c94-58a3-4f2d-8c11-7ab9e4d05c63
status: experimental
description: >-
  Twenty-five or more distinct document names read successfully by one principal
  in five minutes. A principal with ssm:GetDocument on everything enumerates
  without producing a single error, so no error-based rule sees it at all.
references:
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
correlation:
  type: value_count
  rules:
    - ssm_document_read_success
  group-by:
    - userIdentity.arn
  timespan: 5m
  field: requestParameters.name
  condition:
    gte: 25
falsepositives:
  - The Systems Manager console listing documents, and inventory tooling that reads every document on a schedule — both are allowlistable by principal and by user agent
level: medium
```

This is a correlation; its base rule `ssm_getdocument_failed` ships in the same
file and carries the two-family `contains` match. What the correlation structurally
cannot do is tell "does not exist" from "exists but is not shared with you" — AWS
returns one error for both, so a probe that is actually finding documents it cannot
reach looks identical to one finding nothing. The compensating signal is the shape
of the probed names, which Query 1 emits, and the success side, which the
`temporal_ordered` rule in the same file covers. It also cannot see a principal
that holds `ssm:GetDocument` on everything: that enumeration produces no errors at
all, and the second `value_count` correlation is the only thing watching it.

---

### Key Investigation Queries

> SSM documents are **regional** — run these in every Region the account uses.
> Extraction uses `--output json | jq -r '.Events[].CloudTrailEvent | fromjson'`.
> **`lookup-events` returns ≤50 events per page**; paginate on `NextToken` for a
> busy window.

#### Query 1 — Reconstruct: which names were probed, which resolved, and how

```bash
REGION="<region>"
START="$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"

for EV in GetDocument DescribeDocument; do
  aws cloudtrail lookup-events --region "$REGION" \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$START" --max-results 50 --output json \
  | jq -r '.Events[].CloudTrailEvent | fromjson'
done | jq -s '
  map({
    time:      .eventTime,
    event:     .eventName,
    caller:    (.userIdentity.arn // "unknown"),
    accessKey: (.userIdentity.accessKeyId // "none"),
    session:   ((.userIdentity.arn // "") | split("/") | last),
    sourceIp:  .sourceIPAddress,
    agent:     .userAgent,
    documentName: (.requestParameters.name // .requestParameters.Name // ""),
    error: (.errorCode // "none")
  })
  | map(select(.documentName != ""))
  | map(. + { outcome:
      (if   .error == "none"                      then "success"
       elif (.error | test("InvalidDocument"))    then "not-found-or-not-shared"
       elif (.error | test("AccessDenied"))       then "iam-denied"
       else "other-error" end) })
  | group_by(.caller)
  | map({
      caller:        .[0].caller,
      attempts:      length,
      distinctNames: ([.[].documentName] | unique | length),
      foundNames:    ([.[] | select(.outcome == "success")   | .documentName] | unique),
      probedNames:   ([.[] | select(.outcome != "success")   | .documentName] | unique),
      notFound:      ([.[] | select(.outcome == "not-found-or-not-shared") | .documentName] | unique | length),
      iamDenied:     ([.[] | select(.outcome == "iam-denied") | .documentName] | unique | length),
      accessKey:     ([.[].accessKey] | unique),
      sourceIp:      ([.[].sourceIp] | unique),
      agent:         ([.[].agent] | unique),
      first: ([.[].time] | min), last: ([.[].time] | max)
    })
  | sort_by(-.distinctNames)'
```

Read `probedNames` before you read any count. Names that form a coherent internal
scheme — an environment prefix, a service prefix, a version suffix — are a
deployment tool whose document list has drifted. Names that read like a wordlist,
or like AWS's own public document names with a suffix bolted on, are a probe.
`notFound` versus `iamDenied` separates the two error families the source rule
conflates: `notFound` is the enumeration path and the one that matters,
`iamDenied` is usually a client without the permission at all. **`foundNames` is
the escalation trigger** — anything in it has had its content disclosed and feeds
Query 2. `session` is the last `/` segment of the caller ARN, which for an EC2
instance-profile session is the instance ID.

#### Query 2 — Inspect: what the documents that resolved actually disclosed

```bash
REGION="<region>"
FOUND_NAMES="<found-names-from-Query-1>"    # space-separated
CALLER="<caller-arn-from-Query-1>"
START="$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"

for DOC in $FOUND_NAMES; do
  RAW="$(aws ssm get-document --region "$REGION" --name "$DOC" \
          --document-version '$LATEST' --output json)"
  RC=$?
  if [ "$RC" -ne 0 ] || [ -z "$RAW" ]; then
    echo "[!] INCONCLUSIVE — get-document failed for $DOC. It may be owned by another"
    echo "    account and shared, in which case the content is not readable here."
    continue
  fi
  echo "=== $DOC ==="
  printf '%s' "$RAW" | jq -r '.Content' \
    | grep -nEi 'password|secret|token|api[_-]?key|assumeRole|\{\{ssm:|https?://' \
    || echo "  (no obvious secret, endpoint or parameter reference)"
done

# Did the enumeration turn into execution?
for EV in CreateDocument SendCommand StartAutomationExecution StartSession CreateAssociation; do
  aws cloudtrail lookup-events --region "$REGION" \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$START" --max-results 50 --output json \
  | jq -r '.Events[].CloudTrailEvent | fromjson'
done | jq -s --arg c "$CALLER" '
  map(select((.userIdentity.arn // "") == $c))
  | map({time: .eventTime, event: .eventName,
         documentName: (.requestParameters.documentName // .requestParameters.name // ""),
         targets: (.requestParameters.targets // []),
         instanceIds: (.requestParameters.instanceIds // []),
         error: (.errorCode // "none")})
  | sort_by(.time)'
```

The `grep` is a triage aid, not a verdict — read the content of anything it flags
and anything it does not. `{{ssm:` references name the Parameter Store paths the
document reads, which tells the actor exactly what to fetch next and hands you the
list for
`../ssm.credential-access.high-number-of-ssm-parameters-retrieval/`. An
`assumeRole` ARN in an Automation document names a role whose permissions are the
real blast radius of running it.

The second command is the escalation check. Any row means the enumeration became
execution and this incident is no longer only reconnaissance — take it to
`../ssm.discovery.excessive-document-creation-detected/` for the authoring case, or
treat every host in `targets` / `instanceIds` as compromised for the dispatch case.
An empty result is genuine here: `lookup-events` returns an empty `Events` array
for a principal that did nothing, and the loop exits non-zero on an API failure, so
"no rows" and "could not look" are distinguishable in the console output.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="AccessDenied DescribeDocument GetDocument InvalidDocument"
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

Nothing was changed, so there is nothing to restore and no forensic race. The two
jobs are to stop the principal reading more and to establish what the documents it
already read disclosed — and the second one determines whether this stays a
Medium reconnaissance incident or becomes something else entirely.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Stop further reading, without breaking the fleet

```bash
PRINCIPAL_ARN="<caller-arn-from-Query-1>"
POLICY_NAME="IR-SSM-Document-Read-Freeze"

cat > /tmp/ir-ssm-doc-read-freeze.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "FreezeDocumentDiscovery",
      "Effect": "Deny",
      "Action": ["ssm:GetDocument", "ssm:DescribeDocument", "ssm:ListDocuments",
                 "ssm:ListDocumentVersions", "ssm:CreateDocument", "ssm:SendCommand",
                 "ssm:StartSession", "ssm:StartAutomationExecution"],
      "Resource": "*" }
  ]
}
JSON

case "$PRINCIPAL_ARN" in
  *:user/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $NF}')"
    aws iam put-user-policy --user-name "$IAM_NAME" \
      --policy-name "$POLICY_NAME" --policy-document file:///tmp/ir-ssm-doc-read-freeze.json
    echo "[OK] read freeze applied to IAM user $IAM_NAME" ;;
  *:assumed-role/*|*:role/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $2}')"
    echo "[!] $IAM_NAME is a role. ssm:GetDocument is how the SSM agent resolves the"
    echo "    documents it runs, so denying it on an instance-profile or automation role"
    echo "    breaks Run Command and Session Manager for every node using that role."
    echo "    Confirm what assumes it first, then run:"
    echo "    aws iam put-role-policy --role-name $IAM_NAME \\"
    echo "      --policy-name $POLICY_NAME --policy-document file:///tmp/ir-ssm-doc-read-freeze.json" ;;
  *:root)
    echo "[!] root credential — no policy denies root. Rotate the root password, remove"
    echo "    any root access key, confirm root MFA." ;;
  *)
    echo "[!] unrecognised principal shape: $PRINCIPAL_ARN — contain manually." ;;
esac
```

The role branch does **not** apply the policy automatically, and that is
deliberate: `ssm:GetDocument` is on the path the SSM agent itself uses, so a
blanket deny on a shared instance-profile role takes Run Command and Session
Manager down across the fleet — including the channel you might need to reach the
hosts. Confirm what assumes the role first.

#### Step 2 — Contain the principal

```bash
PRINCIPAL_ARN="<caller-arn-from-Query-1>"
ACCESS_KEY="<access-key-from-Query-1>"

case "$PRINCIPAL_ARN" in
  *:user/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $NF}')"
    # Disable before delete — the key is evidence.
    aws iam update-access-key --user-name "$IAM_NAME" --access-key-id "$ACCESS_KEY" --status Inactive
    echo "[OK] access key $ACCESS_KEY deactivated for user $IAM_NAME"
    aws iam list-access-keys --user-name "$IAM_NAME" --output json \
      | jq -r '.AccessKeyMetadata[] | "  \(.AccessKeyId) \(.Status)"'
    echo "[!] deactivate any other key above that is still Active" ;;
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
    echo "[!] no containment path for $PRINCIPAL_ARN — contain manually." ;;
esac
```

`aws:TokenIssueTime` denies only tokens issued **before** the cutoff. A host still
holding the underlying compromise re-fetches credentials and gets a newer issue
time, so this kills the credential in hand and does not gate the role.

---

## 4. Eradication

### Remove Attacker Access

- **Rotate anything Query 2 found inside a document that was read.** A token or
  password embedded in a document the principal retrieved is disclosed; deleting it
  from the document afterwards does not un-read it. Rotate at the system of record,
  then remove it from the document and move it into Parameter Store as a
  `SecureString` reference
- **Follow every `{{ssm:<name>}}` reference in the documents that were read.**
  Those name the Parameter Store paths the document resolves at execution time, and
  they are what the actor learned to fetch next — hand them to
  `../ssm.credential-access.high-number-of-ssm-parameters-retrieval/` and check
  whether they were subsequently read
- **Check the `assumeRole` on any Automation document that was read.** That role's
  permissions are the blast radius of running the document, and knowing it is worth
  more to the actor than the document itself
- **Scope `ssm:GetDocument` and `ssm:DescribeDocument` by resource.** Both support
  resource-level permissions on
  `arn:aws:ssm:<region>:<account>:document/<name>`; grant a principal the documents
  it actually runs and nothing else. Removing `ssm:ListDocuments` alone does not
  stop enumeration — it forces it through `GetDocument`, where it becomes noisy,
  which is the trade this detection is built on
- **Remove the emergency policy once clean, with a real check** — §5 asserts it
  rather than assuming it landed on the right principal

---

## 5. Recovery

### Restore Clean State

#### Verify the read scope actually narrowed, and did not merely stop being used

```bash
REGION="<region>"
PRINCIPAL_ARN="<caller-arn-from-Query-1>"
ACCESS_KEY="<access-key-from-Query-1>"
POLICY_NAME="IR-SSM-Document-Read-Freeze"
SINCE="<utc-timestamp-when-Step-1-completed>"

case "$PRINCIPAL_ARN" in
  *:user/*) POL="$(aws iam get-user-policy --policy-name "$POLICY_NAME" --output json \
              --user-name "$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $NF}')")"; PRC=$? ;;
  *:assumed-role/*|*:role/*)
            POL="$(aws iam get-role-policy --policy-name "$POLICY_NAME" --output json \
              --role-name "$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $2}')")"; PRC=$? ;;
  *)        POL=""; PRC=1 ;;
esac

if [ "$PRC" -ne 0 ] || [ -z "$POL" ]; then
  echo "[!] INCONCLUSIVE — could not read $POLICY_NAME for $PRINCIPAL_ARN. If the role"
  echo "    branch of Step 1 deliberately did NOT apply it, that is expected — say so"
  echo "    explicitly in the incident record rather than leaving this ambiguous."
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
  READS="$(printf '%s' "$DEC" | jq '[.[] | select(.eventSource == "ssm.amazonaws.com")
           | select(.eventName == "GetDocument" or .eventName == "DescribeDocument")
           | select(.errorCode == null)] | length')"
  DENIED="$(printf '%s' "$DEC" | jq '[.[] | select(.eventSource == "ssm.amazonaws.com")
            | select((.errorCode // "") | test("AccessDenied"))] | length')"

  if [ "$READS" -gt 0 ]; then
    echo "[FAIL] $READS successful document read(s) by $ACCESS_KEY since $SINCE — the freeze is not effective"
  elif [ "$DENIED" -gt 0 ]; then
    echo "[OK] $DENIED denied attempt(s) and 0 successful reads since $SINCE — the freeze is live and being hit"
  elif [ "$TOTAL" -eq 0 ]; then
    echo "[!] INCONCLUSIVE — no events at all for $ACCESS_KEY since $SINCE. That is what an"
    echo "    idle credential looks like AND what a mis-keyed lookup looks like; re-run over a"
    echo "    window you know contains activity before treating this as clean"
  else
    echo "[OK] $TOTAL event(s) since $SINCE, none a successful document read"
  fi
fi
```

The zero case is called out deliberately. After removing the permission, "no
further reads" is the expected result whether or not the check works, so it proves
nothing on its own — the denial count is the assertion that the control is live,
and a total of zero has to be inconclusive rather than clean.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     10+ distinct requestParameters.name values on"
echo "                  eventSource=ssm.amazonaws.com eventName=GetDocument"
echo "                  errorCode=InvalidDocument, one userIdentity.arn, 5 minutes"
echo "MUST fire on:     the same burst followed within 15 minutes by a GetDocument"
echo "                  with no errorCode — the enumeration found something"
echo "MUST NOT fire on: 10 GetDocument failures against ONE repeated name"
echo "                  (a retry loop in a broken client, not enumeration)"
echo "MUST NOT fire on: 10 successful GetDocument calls by :role/ssm-agent-node"
echo "                  reading the documents it runs (no errors, allowlisted)"
echo "EXPECTED FP, by design: a deployment tool whose document list has drifted from"
echo "                  what exists. Distinguish by the SHAPE of probedNames — a"
echo "                  coherent naming scheme, not a wordlist — not by the count."
echo "NOTE: errorCode=AccessDenied alone is the P3 row, not this rule. A principal"
echo "                  that cannot call GetDocument at all is usually misconfigured."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could probe the document namespace at will | `ssm:GetDocument` and `ssm:DescribeDocument` granted on `*` instead of on the documents the principal actually runs |
| The enumeration was invisible to the deployed rule | The rule filtered failures to `AccessDenied`, which is the error a name-guessing principal does not receive; `InvalidDocument` — "doesn't exist or isn't available to the user" — was discarded |
| Documents disclosed more than their names | Secrets, internal endpoints and parameter references stored in document content rather than referenced from Parameter Store as `SecureString` values |
| Enumeration by an IAM user would never have accumulated | The rule grouped on `sessionContext.sessionIssuer.userName`, which is absent for IAM-user principals |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Confine document reads to a name prefix. The Resource element is wildcarded, which
// is correct — wildcards ARE expanded there — and NotResource is used rather than a
// condition because the constraint is on the resource, not on a request key. The
// principal allowlist is wildcarded and therefore needs ArnNotLike; Deny +
// ArnNotEquals against a wildcard fails CLOSED and blocks the agent roles too, which
// takes Run Command and Session Manager down fleet-wide.
{
  "Sid": "ReadOnlyOwnDocuments",
  "Effect": "Deny",
  "Action": ["ssm:GetDocument", "ssm:DescribeDocument"],
  "NotResource": [
    "arn:aws:ssm:*:*:document/AWS-*",
    "arn:aws:ssm:*:*:document/myorg-*"
  ],
  "Condition": {
    "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/ssm-runbook-author" }
  }
}
```

- **Move every secret out of document content and into Parameter Store**, then
  reference it as `{{ssm-secure:<name>}}` so the document names the secret rather
  than carrying it. A document that discloses only names is a much smaller loss
  when it is read
- **Alert on the permitted enumerator as well as the denied one.** A principal with
  `ssm:GetDocument` on everything maps the account without producing a single
  error, so an error-based rule alone leaves the more capable actor unwatched
- **Treat `ssm:ListDocuments` as a convenience, not a control.** Removing it does
  not prevent enumeration; it pushes the enumeration into `GetDocument`, where it
  is noisy and detectable, which is a good trade — but only if something is
  actually watching those failures

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1526 — Cloud Service Discovery |
| MITRE tactic | Discovery (TA0007) |
| Primary API | `ssm:GetDocument`, with `ssm:DescribeDocument` and `ssm:ListDocuments` as the quieter alternatives |
| Event source | `ssm.amazonaws.com` — **management** events, recorded by default, failures included. Verified: AWS states "Systems Manager logs all control plane operations to CloudTrail as management events", and the only SSM data-event resource types are `AWS::SSMMessages::ControlChannel` and `AWS::SSM::ManagedNode` |
| Key discriminator | The count of **distinct** `requestParameters.name` values that failed for one principal — not the attempt count, and not `AccessDenied` alone |
| Error strings | `InvalidDocument` — documented as "The SSM document doesn't exist or the document isn't available to the user", so one code covers two facts — plus `InvalidDocumentVersion` and `InternalServerError`. Denials as `AccessDenied` (IAM) and `AccessDeniedException` (service-evaluated); match both families with `contains` |
| "Was it used" pivot | A successful `GetDocument` after the burst, then `CreateDocument`, `SendCommand`, `StartAutomationExecution`, `StartSession` or `CreateAssociation` by the same principal |
| Blast radius | Whatever the documents that resolved contain — embedded tokens, internal endpoints, the `{{ssm:<name>}}` parameter paths an application reads, and the `assumeRole` an Automation runs under |
| Structural blind spot | A principal holding `ssm:GetDocument` on `*` enumerates without generating a single error and is invisible to every error-based rule; covered only by counting distinct names read successfully |
| Field-shape trap | `userIdentity.sessionContext` is present only for role sessions, so a group-by on `sessionIssuer.userName` is null for every IAM user |

**MITRE mapping note.** The source rule maps T1110 (*Brute Force*) under TA0001
(*Initial Access*). Neither half fits. Brute force is the guessing of credentials;
`GetDocument` takes a document name, and a correct guess grants no access the
principal did not already hold — there is no authentication in the loop at all. Nor
is this initial access: the principal is already authenticated to the account
before the first call. The behaviour is enumeration of a cloud service's contents,
which is T1526 (*Cloud Service Discovery*) under Discovery (TA0007). The mislabel
has an operational cost rather than a merely taxonomic one: a "brute force" alert
routes to a credential-stuffing runbook, and the responder spends the first twenty
minutes hunting a compromised password that does not exist. The directory slug
keeps the source's `initial-access` label so the register stays navigable against
the alert set; the Classification table and the shipped rules carry T1526. Where
the enumeration turns into execution, that half is T1651 (*Cloud Administration
Command*) and is carried in the trigger table and in
`../ssm.discovery.excessive-document-creation-detected/`.

### Residual Risk

**What was read stays read.** Nothing in AWS un-discloses a document. Every secret,
endpoint and parameter path in a document the principal retrieved is known, and the
only closure is rotating the secrets and treating the endpoints as public
knowledge.

**"Not found" and "not shared with you" are one error, so the negative result is
soft.** A probe that returned `InvalidDocument` for fifty names may have been
finding nothing, or may have been mapping fifty documents shared into the account
from elsewhere that it could not reach. The log cannot tell you which, and neither
can the responder without the document inventory the account may not have kept.

**The permitted enumerator leaves this playbook's main signal untouched.** If the
principal held `ssm:GetDocument` broadly, there were no failures to count and the
only evidence is the volume of successful reads — a signal that overlaps with the
console and with inventory tooling, and one that a patient actor stays under simply
by reading slowly.

**Enumeration is rarely the end of the sequence.** The value of a document name is
what you do with it. Closing this incident without checking `SendCommand`,
`StartSession`, `CreateAssociation` and `CreateDocument` for the same principal
closes the reconnaissance and leaves the execution unexamined.
