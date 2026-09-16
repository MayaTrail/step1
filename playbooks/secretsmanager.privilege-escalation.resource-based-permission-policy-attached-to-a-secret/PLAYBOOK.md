# IR Playbook: Resource-Based Permission Policy Attached to a Secret — Cross-Account Secret Access via `secretsmanager:PutResourcePolicy`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Privilege escalation / persistence (a document attached to the secret grants an outside principal the right to read it, or to rewrite the grant) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High.** The artefact is on the resource, not on a principal, so every identity-side containment — revoke the sessions, disable the keys, delete the inline policies — leaves it standing. Where the grant includes `secretsmanager:PutResourcePolicy`, AWS's own documentation says it *"lets principals escalate existing permissions like obtaining full administrative access to secrets"*, and it survives being removed because the grantee can put it back. The source rule rates it P3, which is the priority of a configuration observation rather than of a standing backdoor. One factor genuinely lowers per-alert severity: a secret encrypted with the AWS managed key `aws/secretsmanager` cannot be read cross-account at all, so an external grant on such a secret is inert until someone also re-keys it — a property of the secret, not of the technique |
| MITRE Tactics | Privilege Escalation (TA0004); Persistence (TA0003) |
| MITRE Techniques | T1098 — Account Manipulation (primary); T1555.006 — Credentials from Password Stores: Cloud Secrets Management Stores (what the grant discloses) |
| Services in Scope | Secrets Manager, CloudTrail (management), KMS, IAM, IAM Access Analyzer, AWS Organizations |

**What the technique does:** The actor holds `secretsmanager:PutResourcePolicy` on one or
more secrets — a permission that travels quietly inside `secretsmanager:*` and inside
several broad managed policies. It calls `PutResourcePolicy` with a `ResourcePolicy`
document naming a `Principal` outside the secret's own account: another AWS account, a
bare `"*"`, or an identity provider. The document is a JSON string of up to 20,480
characters and its `BlockPublicPolicy` guard is off unless the caller opts in — AWS: *"By
default, public policies aren't blocked."* From then on, any principal the document names
can call `GetSecretValue` on that secret from its own account, and if the document also
grants `secretsmanager:PutResourcePolicy`, that principal can rewrite the document that
grants it.

**Why this is potent, and why the usual reflexes miss it.** Every instinct for containing
a compromised principal is identity-side, and none of them touch this. You can delete the
actor's access keys, revoke every session with `aws:TokenIssueTime`, detach every policy,
and even delete the IAM user — and the grant on the secret is completely unaffected,
because it names a principal in an account you do not administer. The second reflex,
looking for the abuse in your own trail, fails differently: a cross-account read lands in
the **secret owner's** trail with `userIdentity.accountId` set to the *calling* account, so
if you go looking from the wrong account you find nothing. And the third reflex — checking
IAM — is looking at the wrong policy type entirely. Nothing in `list-attached-role-policies`
or `get-account-authorization-details` shows a resource policy on a secret.

**The discriminator is the Principal, not the action list.** A grant of
`secretsmanager:GetSecretValue` to a role in your own account is administration; the
identical action list pointed at an outside account is a backdoor. Whether a Principal is
external, and whether a `Condition` genuinely confines it, cannot be decided by matching
substrings — it needs the document parsed with `Statement`, `Principal` and `Action` each
normalised for their object-or-array shapes. The source rule inspects only the action list,
by ANDing two literal substrings, one of which — `"Resource":"*"` — cannot match a
pretty-printed document at all, so the rule fails to fire on its own canonical target.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

- **CloudTrail multi-region trail capturing management events.** `PutResourcePolicy`,
  `GetResourcePolicy`, `DeleteResourcePolicy` and `ValidateResourcePolicy` are all
  **management events**, recorded by default. Secrets Manager has no CloudTrail data-event
  resource type, so there is nothing extra to enable.
- **`requestParameters.resourcePolicy` carries the whole document as a raw JSON string**
  — this is the only place the grant is recorded. `PutResourcePolicy` echoes only `ARN`
  and `Name` in `responseElements`; `DeleteResourcePolicy` returns nothing. **Do not
  decode this field** — percent-encoding is a property of what IAM *returns*, not of a
  CloudTrail request parameter (rule A4). It arrives in whatever whitespace the client
  sent, which is why nothing here matches punctuation-with-assumed-spacing.
- **`requestParameters.blockPublicPolicy`** — absent means false, which is the AWS
  default and the state an attacker will leave it in.
- **A cross-account read is visible only in the secret owner's account**, where
  `userIdentity.accountId` (the caller) differs from `recipientAccountId` (the owner).
  That inequality is the cross-account proof.
- **IAM Access Analyzer enabled at the organization or account zone of trust**, reporting
  external access granted through resource policies continuously. This is the control that
  turns the account-wide question into an inventory instead of a §2 sweep.
- **A recorded inventory of intended cross-account secret grants** — which secret, which
  external account, which change record. Without it, every finding needs a human to
  adjudicate from scratch.
- **`DescribeSecret`'s `KmsKeyId` per secret.** Absent means the secret uses the AWS
  managed key `aws/secretsmanager`, which **cannot** be used for cross-account access.
  That single field triages a large share of these alerts.

**Alerting (must be pre-configured)**

- **`secretsmanager:PutResourcePolicy` succeeding for a principal outside the policy-admin baseline → P0**
- **A secret's resource policy granting `secretsmanager:PutResourcePolicy` or `secretsmanager:*` → P0**
- **A secret read after a resource policy was attached to it, within 24 hours → P1**
- **`GetSecretValue` where `userIdentity.accountId` differs from `recipientAccountId` → P1**
- `PutResourcePolicy` failing with `PublicPolicyException` — a broad grant the guard stopped
- IAM Access Analyzer finding of external access to a Secrets Manager secret

**Response Tooling**

- AWS CLI v2 with **break-glass responder credentials**, separate from any principal under
  investigation and separate from any role that manages secret policies
- `jq`, and `tools/decode_policy_documents.py` — the shared decoder. Do not write another
  one: `Statement` is an object or an array, `Principal` is an object or the bare string
  `"*"`, and `Action` is a string or an array, and an unguarded iteration over any of them
  reports clean on exactly the grant it exists to find (rule D3)
- `ORG_ACCOUNTS` set to your own account IDs, comma-separated, so the decoder can tell
  internal from external
- A durable evidence store for captured policy documents — `DeleteResourcePolicy` destroys
  the only live copy
- The intended-grant inventory and change-record channel from above

**Known IOC Baselines**

- The principals permitted to call `PutResourcePolicy`, by ARN — this should be a very
  short list, ideally one deploy role and one break-glass role
- Every account ID inside your organization, and every account ID you deliberately grant
  secret access to, held separately
- Your identity-provider ARNs, so a `Federated` principal can be judged known or unknown
- Which secrets are encrypted with a customer-managed KMS key — those are the only ones on
  which a cross-account grant can actually be used

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `secretsmanager:PutResourcePolicy` succeeding for a principal outside the policy-admin baseline | CloudTrail (management) | T1098 |
| P0 | A secret's resource policy granting `secretsmanager:PutResourcePolicy` or `secretsmanager:*` | CloudTrail (management) | T1098 |
| P1 | A secret read after a resource policy was attached to it, within 24 hours | CloudTrail (management) | T1098 / T1555.006 |
| P1 | `GetSecretValue` where `userIdentity.accountId` differs from `recipientAccountId` | CloudTrail (management, owner account) | T1555.006 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `PutResourcePolicy` failing with `PublicPolicyException` — a broad grant the guard stopped | CloudTrail (management) | T1098 |
| P2 | `ValidateResourcePolicy` by a principal outside the policy-admin baseline | CloudTrail (management) | T1098 |
| P2 | IAM Access Analyzer finding of external access to a Secrets Manager secret | Access Analyzer | T1098 |
| P2 | `UpdateSecret` changing `KmsKeyId` from the AWS managed key to a customer-managed key on a secret that carries an external grant | CloudTrail (management) | T1098 |
| P3 | A run of `MalformedPolicyDocumentException` on `PutResourcePolicy` by one principal — iterating on a document that keeps being rejected | CloudTrail (management) | T1098 |

### Detection Rule Quality Notes

The source rule inspects the action list and never the Principal, and one of its two
required substrings cannot match a document submitted the way real documents are
submitted.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Requires the literal substring `"Resource":"*"` in `requestParameters.resourcePolicy` | The field is raw JSON in the client own whitespace. Anyone attaching a real policy submits it from a file, so the stored string is pretty-printed as `"Resource": "*"` with a space and the substring never matches. The rule does not fire on its own canonical target | Match bare action tokens only — they have no interior spacing — and answer every structural question by parsing the document (rule A4) |
| ANDs `secretsmanager:*` with the `Resource` substring | Both must be present, so the rule fires only on a grant of every Secrets Manager action on every resource. The real backdoor — `"Action": "secretsmanager:GetSecretValue"` to an external account — contains neither, and is silently missed | Make the principal the discriminator: alert on `PutResourcePolicy` by anyone outside a named policy-admin allowlist, then grade the document by parsing |
| No Principal inspection at all | The one field that separates administration from a backdoor is never read. A same-account grant and a grant to an unknown outside account are indistinguishable to the rule | Parse `Principal` with the object-or-bare-`"*"` guard, resolve account IDs against your own, and check whether any `Condition` genuinely confines them |
| Grouped by `userIdentity.sessionContext.sessionIssuer.userName` | A principal using long-term IAM user access keys carries no session context, so the grouping key is absent for exactly the credential type most likely to do this out of band. It also collapses every session of a role to the role name (rule A5) | Group on `userIdentity.arn`; keep `sessionIssuer.userName` as role-name enrichment |
| No coverage of the escalation AWS names explicitly | A grant of `secretsmanager:PutResourcePolicy` is self-perpetuating — the grantee can rewrite the document that granted it — and AWS documents it as escalation to full administrative access to the secret. Nothing in the rule treats it differently from a read grant | A dedicated `high` rule on that action token and on `secretsmanager:*`, which contains it |
| No "was it used" signal | The rule reports that a grant was made and nothing about whether it was exercised. The grant and the read are performed by deliberately different principals, so a principal-grouped correlation would not join them | A `temporal_ordered` correlation grouped by `requestParameters.secretId`, so an attach followed by a read of the same secret raises regardless of who did each half |

**Recommended detection — a resource policy attached by a principal outside the policy-admin baseline.**

```yaml
# Resource-Based Permission Policy Attached to a Secret (T1098)
#
# The original rule matched PutResourcePolicy AND the literal substrings
# "secretsmanager:*" AND ""Resource":"*"" with no errorCode. The action token is a safe
# substring; the second one is not. requestParameters.resourcePolicy is RAW JSON in
# whatever whitespace the client sent (rule A4), and a document submitted from a file —
# which is how anyone attaching a real policy does it — is pretty-printed as
# "Resource": "*" with a space. The rule's own canonical target therefore does not match
# it. Worse, ANDing the two substrings means the rule only ever fires on a document that
# grants EVERY Secrets Manager action on EVERY resource, and misses the actual backdoor:
# "Action": "secretsmanager:GetSecretValue" to an external account, which grants a
# stranger the secret's plaintext forever and contains neither substring.
#
# THE DISCRIMINATOR IS THE PRINCIPAL, NOT THE ACTION. A secret's resource policy exists
# to name who outside the secret's own identity policies may use it. AWS's own warning is
# explicit: "Resource-based policies granting secretsmanager:PutResourcePolicy permission
# gives principals, even those in other accounts, the ability to modify your
# resource-based policies. This permission lets principals escalate existing permissions
# like obtaining full administrative access to secrets." Whether a Principal is external,
# and whether a Condition confines it, cannot be decided by substring matching — it needs
# the document parsed, which Sigma cannot do. So the primary rule below keys on the one
# thing Sigma can decide reliably: PutResourcePolicy is a rare administrative call, and a
# principal outside the small set permitted to make it has no business making it. The
# document is then graded by the shared decoder in the playbook's §2.
#
# BlockPublicPolicy defaults to FALSE — AWS: "By default, public policies aren't
# blocked." Nothing stops a wildcard-principal policy unless the caller opts in, and an
# attacker will not. The one case where the guard fires produces PublicPolicyException,
# which is its own rule below: a blocked attempt to make a secret world-readable is a
# stronger signal than most successes.
title: Secrets Manager resource policy attached by an unauthorised principal
id: d8a2fc4c-4c01-49c2-86bf-c418da927793
status: experimental
description: >-
  PutResourcePolicy on a secret is a rare administrative call that grants access
  from outside the secret's own account boundary. A successful call by a principal
  that is not on the short list permitted to manage secret policies is the signal;
  the grant's contents are graded separately because a substring cannot decide
  whether a Principal is external or a Condition confines it.
references:
  - https://attack.mitre.org/techniques/T1098/
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutResourcePolicy.html
  - https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples_cross.html
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'secretsmanager.amazonaws.com'
    eventName: 'PutResourcePolicy'
  success:
    errorCode: null
  policy_admins:                       # tune: principals permitted to manage secret policies
    userIdentity.arn|contains:
      - ':role/SecretsPolicyAdmin'
      - ':role/iac-deploy'
      - ':role/BreakGlassResponder'
  condition: selection and success and not policy_admins
falsepositives:
  - Infrastructure-as-code applying a reviewed cross-account grant — allowlist the deploy role by ARN, and keep the grant itself under review because the allowlist exempts the caller, not the document
level: high
---
title: Secrets Manager resource policy granting policy control or full service access
id: ac3fac9a-4f76-4c57-b61a-e530d8e59ac4
status: experimental
description: >-
  The self-perpetuating grant. A resource policy that hands out
  secretsmanager:PutResourcePolicy lets the grantee rewrite the policy that
  granted it, so removing the grantee from the document does not remove them;
  secretsmanager:* includes it. AWS documents this as escalation to full
  administrative access to the secret, and it works for principals in other
  accounts. Both operands are bare action tokens, which are safe substrings — the
  rule does not attempt to match punctuation whose spacing the client controls.
references:
  - https://attack.mitre.org/techniques/T1098/
  - https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples_cross.html
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'secretsmanager.amazonaws.com'
    eventName: 'PutResourcePolicy'
  escalating_action:
    requestParameters.resourcePolicy|contains:
      - 'secretsmanager:PutResourcePolicy'
      - 'secretsmanager:*'
  success:
    errorCode: null
  condition: selection and escalating_action and success
falsepositives:
  - A delegated-administration pattern where a security account is deliberately given policy control over another account's secrets — rare, and it should be visible in infrastructure-as-code
level: high
---
title: Secrets Manager resource policy attached
id: 1f8e4584-1981-49ff-ad18-71fb4344897b
name: secretsmanager_putresourcepolicy_success
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. One event per
  successful PutResourcePolicy. requestParameters.secretId names the secret and
  requestParameters.resourcePolicy carries the document as a raw JSON string.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutResourcePolicy.html
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'secretsmanager.amazonaws.com'
    eventName: 'PutResourcePolicy'
  success:
    errorCode: null
  # justified: base rule feeding the temporal_ordered correlation below;
  # informational level, never routed to an analyst on its own.
  condition: selection and success
level: informational
---
title: Secrets Manager secret value retrieved successfully
id: 690fae08-2d32-4877-980b-d5422e3b90b1
name: secretsmanager_getsecretvalue_success
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. Used here only to
  answer whether a secret was read after a resource policy was attached to it.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/userguide/cloudtrail_log_entries.html
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
  # justified: base rule feeding the temporal_ordered correlation below;
  # informational level, never routed to an analyst on its own.
  condition: selection and success
level: informational
---
title: Secret read after a resource policy was attached to it
id: fa7cb02e-36e0-4e2c-8726-ca5b1c2263fc
status: experimental
description: >-
  The "was the grant exercised" pivot expressed as a rule. Grouped by the secret
  rather than by the principal, because the principal that attaches the policy and
  the principal that uses it are deliberately different — often in different
  accounts. A read following an attach within a day is the grant being cashed in.
references:
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1555/006/
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098
correlation:
  type: temporal_ordered
  rules:
    - secretsmanager_putresourcepolicy_success
    - secretsmanager_getsecretvalue_success
  group-by:
    - requestParameters.secretId
  timespan: 24h
falsepositives:
  - A legitimate cross-account integration being provisioned and then immediately smoke-tested — should correlate with a change record
level: high
---
title: Public Secrets Manager resource policy blocked by BlockPublicPolicy
id: 7a159cb1-8ece-4625-8d48-6984eff236e0
status: experimental
description: >-
  PublicPolicyException means the caller attached a policy granting broad access
  and the BlockPublicPolicy guard rejected it. The guard is opt-in and defaults to
  off, so this only fires where someone deliberately turned it on — which makes
  the event an attempt that was stopped, not a misconfiguration. Treat it as a
  confirmed attempt to make a secret world-readable and investigate the caller.
references:
  - https://attack.mitre.org/techniques/T1098/
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutResourcePolicy.html
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'secretsmanager.amazonaws.com'
    eventName: 'PutResourcePolicy'
  blocked_as_public:
    errorCode: 'PublicPolicyException'
  # justified: a single documented error code that only occurs when a broad-access
  # policy was submitted and rejected — there is no benign form of this event.
  condition: selection and blocked_as_public
level: medium
---
title: Secrets Manager resource policy validated without being attached
id: b8244ad2-ba6e-4f4f-ae26-6fd97868d0a3
status: experimental
description: >-
  ValidateResourcePolicy checks a document against Secrets Manager's own policy
  validation and IAM Access Analyzer without storing it. Legitimate use is almost
  entirely inside deployment tooling; an interactive principal validating a policy
  is someone testing what will be accepted before they attach it. Low volume, so
  cheap to watch.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/userguide/cloudtrail_log_entries.html
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'secretsmanager.amazonaws.com'
    eventName: 'ValidateResourcePolicy'
  policy_admins:
    userIdentity.arn|contains:
      - ':role/SecretsPolicyAdmin'
      - ':role/iac-deploy'
  condition: selection and not policy_admins
falsepositives:
  - A policy linter or CI check running under a role not yet in policy_admins
level: medium
```

**What this rule structurally cannot do.** It cannot decide whether the document it fired
on is a backdoor. Sigma matches substrings against a raw event; deciding that a `Principal`
names an outside account, or that a `Condition` confines it, requires the document parsed
with all three of IAM's object-or-array shapes normalised. Query 2 below does that with the
shared decoder. The rule also cannot see a grant made *before* the trail's retention window,
which is why the account-wide `GetResourcePolicy` sweep in Query 3 is not optional — and it
exempts the caller, not the document, so an allowlisted deploy role attaching a hostile
grant fires nothing. **On error strings:** `PutResourcePolicy` throws
`InternalServiceError`, `InvalidParameterException`, `InvalidRequestException`,
`MalformedPolicyDocumentException`, `PublicPolicyException` and `ResourceNotFoundException`;
authorization denials use the service's common set, `AccessDeniedException` and
`NotAuthorized`, with unsuffixed `AccessDenied` still possible from an IAM-policy-evaluated
denial (rule A7).

---

### Key Investigation Queries

> Secrets Manager is regional and a resource policy is attached to a secret in one Region —
> run these in every Region that holds secrets. Extraction uses
> `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns
> ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: who attached which policy, to which secret, and what does it say

```bash
REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutResourcePolicy \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "secretsmanager.amazonaws.com") |
    {time:         .eventTime,
     caller:       .userIdentity.arn,
     role:         (.userIdentity.sessionContext.sessionIssuer.userName // "n/a — not a role session"),
     access_key:   .userIdentity.accessKeyId,
     secret:       .requestParameters.secretId,
     # RAW JSON in the client own whitespace — never decode a request parameter (A4).
     doc:          .requestParameters.resourcePolicy,
     block_public: (.requestParameters.blockPublicPolicy // false),
     error:        (.errorCode // "SUCCESS"),
     ip:           .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Every row with `error == "SUCCESS"` is a grant that is live right now unless something
later removed it. `block_public` will almost always be `false`, because that is the AWS
default and nothing sets it for you. `secret` feeds Queries 2 and 3 and the containment
steps; `caller` and `access_key` feed Query 4. A row with `error ==
"PublicPolicyException"` is a stopped attempt at a world-readable secret and is worth as
much attention as a success.

#### Query 2 — Inspect: parse each document and decide whether the Principal is external

```bash
REGION="us-east-1"
export ORG_ACCOUNTS="<your-account-id>,<other-account-id-in-your-org>"

RAW=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutResourcePolicy \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json)

if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE: lookup-events returned nothing — the call failed, the credential"
  echo "    lacks cloudtrail:LookupEvents, or the region is wrong. Not 'no grants'."
else
  # The decoder reads newline-delimited JSON with time/caller/grantee/policy_name/doc and
  # normalises Statement (object OR array), Principal (object OR bare "*") and Action
  # (string OR array) before evaluating. Do not write another parser (rule D3).
  VERDICTS=$(echo "$RAW" | jq -c '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "secretsmanager.amazonaws.com") |
      select(.errorCode == null) |
      {time:        .eventTime,
       caller:      .userIdentity.arn,
       grantee:     .requestParameters.secretId,
       policy_name: .requestParameters.secretId,
       doc:         .requestParameters.resourcePolicy}' | \
    python3 tools/decode_policy_documents.py)

  echo "$VERDICTS"
  # The decoder prints a trailing [OK] line regardless of how many findings preceded it,
  # so count the [!] lines instead of trusting that line.
  N=$(printf '%s\n' "$VERDICTS" | grep -c '^\[!\]' || true)
  if [ -z "$VERDICTS" ]; then
    echo "[!] INCONCLUSIVE: the decoder produced no output at all — check that it ran."
  elif [ "${N:-0}" -gt 0 ]; then
    echo "[FAIL] $N unconfined or external grant(s) found — every one is a live backdoor"
  else
    echo "[OK] no external or unconfined grants among the parsed documents"
  fi
fi

# Grade the ACTIONS as well — the decoder answers "who is named and is it confined", not
# "what were they given". Shape-guard Action, NotAction and Statement (rule D3).
echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
  select(.eventSource == "secretsmanager.amazonaws.com") | select(.errorCode == null) |
  . as $e | (.requestParameters.resourcePolicy | fromjson) as $p |
  ($p.Statement // [] | if type == "object" then [.] else . end)[] |
  select(.Effect == "Allow") |
  (((.Action    // []) | if type == "string" then [.] else . end) +
   ((.NotAction // []) | if type == "string" then [.] else . end)) as $acts |
  select(any($acts[]; . == "*" or . == "secretsmanager:*"
                      or (. | ascii_downcase) == "secretsmanager:putresourcepolicy")) |
  "[!] ESCALATING ACTION  \($e.eventTime)  \($e.requestParameters.secretId)  \($acts)"'
```

`[!] EXTERNAL` means the document names an account outside `ORG_ACCOUNTS` with no confining
`Condition` — a live cross-account grant. `[!] PUBLIC` means a bare `"*"` principal with no
`Condition`. `[!] ESCALATING ACTION` from the second pass means the grantee can rewrite the
document, so removing them from it does not remove them. **Read every `[i] CONFINED`
verdict's condition keys by hand before filing it as safe:** the decoder's confiner list is
shared with the role-trust dialect and includes `sts:ExternalId`, which is not a key in a
Secrets Manager authorization context at all — a statement conditioned only on it is
reported `CONFINED` when what has actually happened is that the statement can never match.
That direction fails closed rather than open, but the verdict is still wrong.

#### Query 3 — Sweep: which secrets in the account carry a resource policy right now

```bash
REGION="us-east-1"
export ORG_ACCOUNTS="<your-account-id>,<other-account-id-in-your-org>"

SECRETS=$(aws secretsmanager list-secrets --include-planned-deletion \
            --region "$REGION" --query 'SecretList[].ARN' --output text)
if [ -z "$SECRETS" ]; then
  echo "[!] INCONCLUSIVE: list-secrets returned nothing in $REGION. Either the account holds"
  echo "    no secrets or the call failed — confirm before reporting the region clean."
  exit 0
fi

CHECKED=0; WITH_POLICY=0
for S in $SECRETS; do
  CHECKED=$((CHECKED+1))
  POL=$(aws secretsmanager get-resource-policy --secret-id "$S" --region "$REGION" --output json)
  if [ -z "$POL" ]; then
    echo "[!] $S — INCONCLUSIVE: get-resource-policy returned nothing. GetResourcePolicy"
    echo "    always returns a document for a readable secret, so an empty result is a"
    echo "    failed or denied call, NOT an absent policy. Do not count this as clean."
    continue
  fi
  DOC=$(echo "$POL" | jq -r '.ResourcePolicy // ""')
  [ -z "$DOC" ] && continue                      # genuine "no policy attached"
  WITH_POLICY=$((WITH_POLICY+1))
  echo "== $S"
  jq -cn --arg s "$S" --arg d "$DOC" \
    '{time:"now", caller:"(current state)", grantee:$s, policy_name:$s, doc:$d}' | \
    python3 tools/decode_policy_documents.py
done
echo "[i] swept $CHECKED secret(s) in $REGION; $WITH_POLICY carry a resource policy"
```

This is the question no event can answer: which grants exist *now*, including ones made
before the trail's retention window. `--include-planned-deletion` matters — a secret
scheduled for deletion is excluded from `list-secrets` by default and can still carry a
grant that comes back with it if the deletion is cancelled. The `[!] INCONCLUSIVE` branch
is load-bearing: `GetResourcePolicy` returns a document for any secret the caller can read,
so an empty result is a failed call and counting it as clean is a false negative.

#### Query 4 — Was the grant exercised, and by whom

```bash
REGION="us-east-1"
SECRET="<secret-from-Query-1>"
GRANT_TIME="<time-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$GRANT_TIME" \
  --region "$REGION" --output json | \
  jq -r --arg s "$SECRET" '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "secretsmanager.amazonaws.com") |
    # secretId is caller-typed: the grant may name the secret and the read may use the ARN.
    select((.requestParameters.secretId // "") | contains($s) or ($s | contains(.))) |
    {time:           .eventTime,
     reader:         .userIdentity.arn,
     reader_account: .userIdentity.accountId,
     owner_account:  .recipientAccountId,
     # The cross-account proof: the event lands in the OWNER account with these unequal.
     cross_account:  (.userIdentity.accountId != .recipientAccountId),
     error:          (.errorCode // "SUCCESS"),
     ip:             .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Any row with `cross_account: true` and `error: "SUCCESS"` is the grant being cashed in, and
the secret's plaintext has left the account. `reader_account` is the account to name in the
notification and, if it is not yours, the account to raise with AWS. An empty result is not
reassurance on its own — a read from an account you granted could pre-date `GRANT_TIME` if
an earlier grant existed, which is what Query 3's sweep is for.

#### Query 5 — Full session reconstruction of the principal that attached the policy

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time:   .eventTime,
     event:  .eventName,
     source: .eventSource,
     target: (.requestParameters.secretId // .requestParameters.roleName
              // .requestParameters.functionName // .requestParameters.bucketName // "n/a"),
     error:  (.errorCode // "SUCCESS"),
     ip:     .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Look specifically for `UpdateSecret` on the same secret shortly **before** the
`PutResourcePolicy`: re-keying a secret from the AWS managed key to a customer-managed key
is what makes a cross-account grant usable at all, so that ordering is the fingerprint of
an actor who understands the constraint. `lambda:AddPermission`, `s3:PutBucketPolicy` and
`iam:UpdateAssumeRolePolicy` in the same session are the same technique against other
resources — route them to `../lambda.persistence.resource-policy-backdoor/`,
`../_superseded/aws.exfiltration.s3-bucket-public-exposure/` and
`../iam.persistence.role-trust-backdoor/`.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The grant is on the resource, so containing the principal does not contain the incident —
both have to happen, and in this order. **Capture every policy document before you remove
it:** `PutResourcePolicy` echoes only ARN and Name, `DeleteResourcePolicy` returns nothing,
and once the policy is gone the document exists only in CloudTrail, only for the retention
window. Removing it first is how the evidence for the notification you will have to write
gets destroyed.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being contained.

#### Step 1 — Capture the live policy documents as evidence

```bash
REGION="us-east-1"
EVIDENCE_DIR="/tmp/secret-policy-evidence"
AFFECTED_SECRETS="<secret-from-Query-1> <secret-from-Query-1>"

mkdir -p "$EVIDENCE_DIR"
CAPTURED=0
for S in $AFFECTED_SECRETS; do
  SAFE=$(echo "$S" | tr '/:' '__')
  POL=$(aws secretsmanager get-resource-policy --secret-id "$S" --region "$REGION" --output json)
  if [ -z "$POL" ]; then
    echo "[!] $S — INCONCLUSIVE: get-resource-policy returned nothing. DO NOT proceed to"
    echo "    Step 2 for this secret; removing an uncaptured policy destroys the evidence."
    continue
  fi
  DOC=$(echo "$POL" | jq -r '.ResourcePolicy // ""')
  if [ -z "$DOC" ]; then
    echo "[i] $S — no resource policy attached (nothing to capture or remove)."
    continue
  fi
  printf '%s\n' "$DOC" > "$EVIDENCE_DIR/$SAFE.json"
  CAPTURED=$((CAPTURED+1))
  echo "[OK] captured $S -> $EVIDENCE_DIR/$SAFE.json"
done
echo "[i] $CAPTURED document(s) captured. Copy $EVIDENCE_DIR off this host before Step 2."
```

#### Step 2 — Remove the grant

```bash
REGION="us-east-1"
EVIDENCE_DIR="/tmp/secret-policy-evidence"
AFFECTED_SECRETS="<secret-from-Query-1> <secret-from-Query-1>"

for S in $AFFECTED_SECRETS; do
  SAFE=$(echo "$S" | tr '/:' '__')
  if [ ! -s "$EVIDENCE_DIR/$SAFE.json" ]; then
    echo "[!] $S — SKIPPED: no captured document at $EVIDENCE_DIR/$SAFE.json. Run Step 1"
    echo "    first. DeleteResourcePolicy returns nothing and the document is not recoverable."
    continue
  fi
  aws secretsmanager delete-resource-policy --secret-id "$S" --region "$REGION" \
    && echo "[OK] removed the resource policy from $S"
done
```

> If the grant you are removing is a **legitimate** cross-account integration, removing it
> breaks the partner's access. Check the intended-grant inventory from §1 before deleting;
> where the document mixes a legitimate grantee with a hostile one, re-put a corrected
> document with `--block-public-policy` rather than deleting outright.

#### Step 3 — Deny further policy changes by the acting principal, and revoke its sessions

```bash
SUSPECT_ARN="<caller-from-Query-1>"
CUTOFF="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["secretsmanager:PutResourcePolicy","secretsmanager:DeleteResourcePolicy","secretsmanager:ValidateResourcePolicy"],"Resource":"*"}]}'

if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')          # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" \
    --policy-name "EmergencyDenySecretPolicyWrite" --policy-document "$DENY_DOC"
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
  echo "[OK] denied policy writes and revoked pre-$CUTOFF sessions for role $R"
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')         # user ARN: name = last segment
  aws iam put-user-policy --user-name "$U" \
    --policy-name "EmergencyDenySecretPolicyWrite" --policy-document "$DENY_DOC"
  KEYS=$(aws iam list-access-keys --user-name "$U" \
           --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text)
  if [ -z "$KEYS" ]; then
    echo "[!] INCONCLUSIVE: no active keys returned for $U — either none exist or the call"
    echo "    failed. Verify before treating the user as contained."
  else
    for K in $KEYS; do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled access key $K for $U"
    done
  fi
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root, federated or a"
  echo "    service principal. Contain manually; an inline policy cannot be attached to it."
fi
```

> `aws:TokenIssueTime` denies only tokens issued **before** the cutoff (rule E4). A still-
> compromised workload can assume the role again and receive a newer token this does not
> deny. It kills the leaked session; it does not gate the role.

#### Step 4 — Rotate every secret that carried an external grant

```bash
REGION="us-east-1"
AFFECTED_SECRETS="<secret-from-Query-1> <secret-from-Query-1>"

for S in $AFFECTED_SECRETS; do
  META=$(aws secretsmanager describe-secret --secret-id "$S" --region "$REGION" --output json)
  if [ -z "$META" ]; then
    echo "[!] $S — INCONCLUSIVE: describe-secret returned nothing. Rotation NOT attempted."
    continue
  fi
  ROT=$(echo "$META" | jq -r 'if has("RotationEnabled") then (.RotationEnabled|tostring) else "unset" end')
  case "$ROT" in
    true) aws secretsmanager rotate-secret --secret-id "$S" --rotate-immediately --region "$REGION" \
            && echo "[OK] $S — rotation requested (asynchronous; verify in §5)" ;;
    *)    echo "[!] $S — rotation is $ROT; no automated rotation exists. Change the credential"
          echo "    at its own system and store it with put-secret-value. Until then the value"
          echo "    the grantee may already hold is LIVE." ;;
  esac
done
```

Removing the grant stops future reads. It does nothing about a read that already happened,
and Query 4 tells you whether one did. Where `cross_account: true` appeared for any secret,
treat that secret's value as disclosed and rotate it regardless of the grant's removal — the
full procedure is in
`../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/`.

---

## 4. Eradication

### Remove Attacker Access

#### Clear every other secret carrying the same grant

Query 3's sweep is the work-list, and it has to be run in **every Region that holds
secrets**, not only the alert's Region. For each secret it flagged `[!] EXTERNAL` or
`[!] PUBLIC`, capture the document (§3 Step 1) and remove it (§3 Step 2). A grant that
pre-dates the trail's retention window will appear only here, which is why the sweep is
the authority and the event stream is not.

#### Close the re-keying path

An external grant on a secret encrypted with the AWS managed key `aws/secretsmanager` is
inert — AWS does not permit cross-account access with that key. An actor who understands
this re-keys the secret first with `UpdateSecret --kms-key-id`. Check every affected secret
for a `KmsKeyId` change in the same session (Query 5) and, where one is found, treat the
new key's policy as part of the incident: `aws kms get-key-policy` on it, and remove any
external principal from that policy too. Otherwise the grant is removed and the key that
made it usable stays.

#### Remove other resource-policy backdoors by the same principal

From Query 5, this principal's other grants against other services are the same technique:
`lambda:AddPermission` → `../lambda.persistence.resource-policy-backdoor/`,
`s3:PutBucketPolicy` → `../_superseded/aws.exfiltration.s3-bucket-public-exposure/`,
`iam:UpdateAssumeRolePolicy` → `../iam.persistence.role-trust-backdoor/`. Each has its
own playbook and its own document-shape traps; the shared decoder handles all of them.

#### Right-size `secretsmanager:PutResourcePolicy`

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# PutResourcePolicy travels inside secretsmanager:* and inside several broad managed
# policies. Very few principals should hold it; grant it to a named policy-admin role and
# to nothing else, and require --block-public-policy in the tooling that uses it.
```

#### Remove the emergency policies once clean

```bash
SUSPECT_ARN="<caller-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
  for P in EmergencyDenySecretPolicyWrite EmergencyRevokeSessions; do
    aws iam delete-role-policy --role-name "$R" --policy-name "$P"
  done
  LEFT=$(aws iam list-role-policies --role-name "$R" --query 'PolicyNames' --output json)
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  aws iam delete-user-policy --user-name "$U" --policy-name "EmergencyDenySecretPolicyWrite"
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

#### Verify no secret in the account carries an external or public grant

```bash
REGION="us-east-1"
export ORG_ACCOUNTS="<your-account-id>,<other-account-id-in-your-org>"

SECRETS=$(aws secretsmanager list-secrets --include-planned-deletion \
            --region "$REGION" --query 'SecretList[].ARN' --output text)
if [ -z "$SECRETS" ]; then
  echo "[!] INCONCLUSIVE: list-secrets returned nothing in $REGION — the call failed or the"
  echo "    account holds no secrets. Cannot certify the region clean."
  exit 1
fi

BAD=0; INCONCLUSIVE=0
for S in $SECRETS; do
  POL=$(aws secretsmanager get-resource-policy --secret-id "$S" --region "$REGION" --output json)
  if [ -z "$POL" ]; then
    echo "[!] $S — INCONCLUSIVE: get-resource-policy returned nothing (failed or denied call)."
    INCONCLUSIVE=$((INCONCLUSIVE+1)); continue
  fi
  DOC=$(echo "$POL" | jq -r '.ResourcePolicy // ""')
  [ -z "$DOC" ] && continue
  V=$(jq -cn --arg s "$S" --arg d "$DOC" \
        '{time:"now", caller:"(current state)", grantee:$s, policy_name:$s, doc:$d}' | \
      python3 tools/decode_policy_documents.py)
  if [ -z "$V" ]; then
    echo "[!] $S — INCONCLUSIVE: the decoder produced no output."
    INCONCLUSIVE=$((INCONCLUSIVE+1)); continue
  fi
  N=$(printf '%s\n' "$V" | grep -c '^\[!\]' || true)
  if [ "${N:-0}" -gt 0 ]; then
    echo "[FAIL] $S still carries an external or public grant:"
    printf '%s\n' "$V" | grep '^\[!\]'
    BAD=$((BAD+1))
  fi
done

if [ "$INCONCLUSIVE" -gt 0 ]; then
  echo "[!] INCONCLUSIVE: $INCONCLUSIVE secret(s) could not be checked — region NOT certified"
elif [ "$BAD" -gt 0 ]; then
  echo "[FAIL] $BAD secret(s) still carry an external or public grant"
else
  echo "[OK] every readable secret in $REGION is free of external and public grants"
fi
```

This assertion can fail three ways and reaches `[OK]` only when every secret was actually
read and every document actually parsed. `GetResourcePolicy` returns a document for any
secret the caller can read, so an empty result is a failed call, never an absent policy —
counting it as clean would certify a live grant. It also queries a signal the remediation
does **not** remove: the policy sweep still reports on every secret after the deletion, so
`[FAIL]` remains reachable.

#### Verify the rotated secrets actually rotated — by version id, not by value

```bash
REGION="us-east-1"
# "<secret>:<pre-incident-AWSCURRENT-version-id>" pairs, captured before §3 Step 4.
PRE_ROTATION_VERSIONS="<secret-from-Query-1>:<pre-incident-version-id>"

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
    echo "[!] $S — INCONCLUSIVE: no version carries AWSCURRENT."; FAILED=1
  elif [ "$NEW" = "$OLD" ]; then
    echo "[FAIL] $S — AWSCURRENT is still $NEW; the disclosed value is STILL LIVE."; FAILED=1
  else
    echo "[OK] $S — AWSCURRENT moved $OLD -> $NEW"
  fi
done
[ "$FAILED" -eq 0 ] && echo "[OK] every affected secret rotated" \
                    || echo "[FAIL] at least one secret is unrotated or unverified"
```

Never verify a rotation by reading the value back: the old value is not visible, so there
is nothing to compare against and the check could not fail even if rotation silently did.

#### Verify no cross-account read has occurred since the grant was removed

```bash
REGION="us-east-1"
REMOVED_AT="<iso8601-policy-removal-timestamp>"

RAW=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$REMOVED_AT" --region "$REGION" --output json)

if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE: lookup-events returned nothing — call failed or no permission."
else
  N=$(echo "$RAW" | jq '[.Events[].CloudTrailEvent | fromjson
        | select(.eventSource == "secretsmanager.amazonaws.com")
        | select(.errorCode == null)
        | select(.userIdentity.accountId != .recipientAccountId)] | length')
  if [ "$N" -eq 0 ]; then
    echo "[OK] no successful cross-account secret reads since $REMOVED_AT"
  else
    echo "[FAIL] $N successful cross-account read(s) since $REMOVED_AT — a grant remains"
    echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | select(.userIdentity.accountId != .recipientAccountId)
      | "\(.eventTime)  \(.userIdentity.arn)  \(.requestParameters.secretId)"'
  fi
fi
```

This check still emits a signal after the remediation — the trail records reads whether or
not a policy exists, and a removed grant turns a successful cross-account read into a denied
one rather than into no event at all. That is what makes `[FAIL]` reachable.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     PutResourcePolicy with errorCode absent, by a principal whose ARN"
echo "                  matches none of the policy_admins entries"
echo "MUST fire on:     a resourcePolicy string containing the token"
echo "                  secretsmanager:PutResourcePolicy or secretsmanager:* -- including"
echo "                  the pretty-printed form, because the match is on the action token"
echo "                  and not on punctuation whose spacing the client controls"
echo "MUST fire on:     PutResourcePolicy then GetSecretValue on the same secretId inside 24h"
echo "MUST NOT fire on: PutResourcePolicy by the named iac-deploy role with errorCode absent"
echo "MUST NOT fire on: DeleteResourcePolicy -- removing a grant is not establishing one"
echo "MUST NOT fire on: PutResourcePolicy carrying errorCode AccessDeniedException"
echo "EXPECTED FP, by design: the primary rule exempts the CALLER, not the DOCUMENT, so an"
echo "                  allowlisted deploy role attaching a hostile grant fires nothing."
echo "                  Query 2's parse and Query 3's sweep are what cover that gap."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the policy-admin set could attach a resource policy to a secret | `secretsmanager:PutResourcePolicy` granted broadly, usually inside a `secretsmanager:*` or a broad managed policy, rather than to one named role |
| The grant named an account outside the organization and nothing stopped it | `BlockPublicPolicy` defaults to false and was not set by the tooling; no SCP or RCP constrained the principals a secret policy may name |
| Identity-side containment left the backdoor standing | The response playbook in use assumed a compromised-principal model; nothing in it inspected resource policies |
| The rule that existed did not fire on the canonical backdoor | It required two literal substrings, one of which cannot match a pretty-printed document, and it never inspected the Principal |
| Existing external grants were not known before the incident | IAM Access Analyzer was not enabled for the account's zone of trust, so the account-wide question could only be answered by a per-secret sweep at response time |
| The blast radius depended on a KMS key nobody had checked | Whether a secret used the AWS managed key or a customer-managed key decided whether the grant was usable, and that field was not part of the secret inventory |

### Recommended Guardrails

**Constrain who may write a secret's resource policy**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Denies resource-policy writes to everything except a named policy-admin role. The
// condition value is wildcarded, so it MUST use StringNotLike, not StringNotEquals: with
// StringNotEquals a concrete ARN never equals the pattern, so the Deny matches every
// principal and nobody can manage secret policies at all -- an outage, not a bypass.
{
  "Effect": "Deny",
  "Action": [
    "secretsmanager:PutResourcePolicy",
    "secretsmanager:DeleteResourcePolicy"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/SecretsPolicyAdmin",
        "arn:aws:iam::*:role/BreakGlassResponder"
      ]
    }
  }
}
```

**Constrain who may read a secret, from outside the organization**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// RESOURCE control policy (RCP) fragment, NOT an SCP. An SCP cannot reach a principal in
// another account -- AWS: SCPs "don't affect users or roles from accounts outside the
// organization" -- so an SCP written against a foreign principal is unreachable in both
// directions. The RCP applies to the RESOURCE, which is where the grant lives.
// The PrincipalIsAWSService guard is required: without it this denies service-initiated
// access (rotation, replication, CloudFormation) and causes an outage.
{
  "Effect": "Deny",
  "Action": ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"],
  "Resource": "*",
  "Condition": {
    "StringNotEqualsIfExists": { "aws:PrincipalOrgID": "o-EXAMPLEORGID" },
    "Bool": { "aws:PrincipalIsAWSService": "false" }
  }
}
```

**Structural controls**

- **Enable IAM Access Analyzer** for the account's or organization's zone of trust. It
  reports external access granted by resource policies continuously, which converts this
  from an alert you have to catch into an inventory you can review.
- **Set `BlockPublicPolicy: true` on every `PutResourcePolicy` your tooling issues.** It is
  opt-in and off by default; the tooling is the only place it will ever be set.
- **Keep secrets on the AWS managed key `aws/secretsmanager` unless cross-account access is
  genuinely required.** That single choice makes an external grant inert, and it turns
  "someone re-keyed a secret" into a meaningful alert.
- **Manage resource policies exclusively in infrastructure-as-code**, so any out-of-band
  `PutResourcePolicy` is an incident by definition and the intended-grant inventory is the
  repository.
- **Record every intended cross-account grant** with its change record, so a responder can
  adjudicate a finding in seconds rather than by asking around.

**Detection improvements**

- Make the **Principal** the discriminator, parsed with the `Statement`/`Principal`/`Action`
  shape guards — never a substring match on punctuation whose spacing the client controls
- Alert separately on grants of `secretsmanager:PutResourcePolicy` and `secretsmanager:*`;
  they are self-perpetuating and are a different severity from a read grant
- Correlate attach-then-read grouped by the **secret**, not by the principal
- Alert on `GetSecretValue` where `userIdentity.accountId` differs from
  `recipientAccountId` — the cross-account proof, visible only in the owner account
- Watch `PublicPolicyException` and a run of `MalformedPolicyDocumentException`: both are
  attempts that did not land, and both name the caller

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098 — Account Manipulation (primary); T1555.006 — Credentials from Password Stores: Cloud Secrets Management Stores (what the grant discloses) |
| MITRE tactic | Privilege Escalation (TA0004); Persistence (TA0003) |
| Primary API | `secretsmanager:PutResourcePolicy` (optionally preceded by `ValidateResourcePolicy`, and by `UpdateSecret --kms-key-id` to make the grant usable cross-account) |
| Event source | `secretsmanager.amazonaws.com` — **management events, recorded by default**. Secrets Manager has no CloudTrail data-event resource type |
| Key discriminator | The `Principal` named in `requestParameters.resourcePolicy`, and whether a `Condition` genuinely confines it — **not** the action list |
| Field shape | `requestParameters.resourcePolicy` is a **raw JSON string** (max 20,480 chars), unlike S3's `requestParameters.bucketPolicy` which is a nested object. Never decode it — percent-encoding is a property of what IAM returns (rule A4) |
| Document-shape guards | `Statement` is an object **or** an array; `Principal` is an object **or** the bare string `"*"`; `Action` is a string **or** an array; `NotAction` grants everything except. Use `tools/decode_policy_documents.py`, which normalises all of them (rule D3) |
| Decoder caveat | Its confiner list is shared with the role-trust dialect and includes `sts:ExternalId`, which is not a key in a Secrets Manager authorization context — a statement conditioned only on it is reported `[i] CONFINED` when it can in fact never match. Read `CONFINED` verdicts by hand. It also does not grade the action list on this path; the escalating-action pass in Query 2 covers that |
| Ground-truth signal | `requestParameters.resourcePolicy` in CloudTrail is the **only** record of the grant — `PutResourcePolicy` echoes just ARN and Name, `DeleteResourcePolicy` returns nothing, and `GetResourcePolicy` answers only for grants that still exist |
| "Was it used" pivot | `GetSecretValue` on the same secret with `userIdentity.accountId != recipientAccountId`, in the **secret owner's** trail. From the calling account you see nothing |
| Cross-account preconditions | All three are required: the resource policy, an identity policy in the caller's account, and permission on the KMS key. AWS: *"you can't use the AWS managed key (`aws/secretsmanager`) for cross-account access"* — so a secret on the managed key is not readable cross-account whatever its policy says |
| Cross-account scope limit | Cross-account permission is effective only for a fixed operation list. It **includes** `GetSecretValue`, `PutSecretValue`, `PutResourcePolicy`, `DeleteSecret`, `UpdateSecret`, `RotateSecret` and `CancelRotateSecret`, and **excludes** `ListSecrets` and `BatchGetSecretValue` — an external grantee cannot enumerate or bulk-read; they must know the exact ARN |
| Escalation | AWS: a policy granting `secretsmanager:PutResourcePolicy` *"lets principals escalate existing permissions like obtaining full administrative access to secrets"*, and it works for principals in other accounts. Such a grant is self-perpetuating |
| `BlockPublicPolicy` | Optional Boolean, **default false** — AWS: *"By default, public policies aren't blocked."* When it is on and the policy is broad, the call fails with `PublicPolicyException` |
| Blast radius | Every principal the document names, in every account, holds the granted rights on that secret until the document is removed — and holds whatever the secret's plaintext grants, permanently, if they read it |
| Error strings | `InternalServiceError`, `InvalidParameterException`, `InvalidRequestException`, `MalformedPolicyDocumentException`, `PublicPolicyException`, `ResourceNotFoundException`; denials as `AccessDeniedException` / `NotAuthorized`, with unsuffixed `AccessDenied` still possible from an IAM-policy-evaluated denial (rule A7) |

**MITRE mapping note.** The source rule labels this `T1098` / `TA0004`, and unusually for
this alert set the mapping is **correct**. T1098 (*Account Manipulation*) covers actions
that preserve or extend an adversary's access, and Privilege Escalation is one of the two
tactics MITRE lists for it; Persistence is the other and applies equally here, because the
grant outlives every identity-side containment. T1555.006 is carried as a secondary for
what the grant discloses. No mapping dispute — the only correction §6 makes is to the
severity, from P3 to High.

### Residual Risk

**Anything already read stays read.** Removing the grant stops future access and does
nothing about the plaintext a grantee retrieved while it stood. Where Query 4 showed a
successful cross-account read, that secret's value is in another organisation's hands and
rotation is the only response; nothing in AWS reaches it.

**A grantee who was given `PutResourcePolicy` may have already used it elsewhere.** The
self-perpetuating grant is not limited to putting the same document back. Check whether the
external principal itself appears as the caller on any `PutResourcePolicy` in your trail —
including against secrets other than the one that alerted — before concluding the grant has
been removed rather than relocated.

**The account-wide sweep is bounded by what you can read.** Query 3 and the §5 assertion
cover the Regions you ran them in and the secrets the responder credential can read. A
secret in an unswept Region, or one whose resource policy denies your own responder role,
is outside the certification — which is why `[!] INCONCLUSIVE` blocks the `[OK]` rather
than being counted past.

**The KMS key that made the grant usable may still be shared.** If the actor re-keyed the
secret to a customer-managed key and added an external principal to that key policy,
removing the secret's resource policy leaves the key grant in place, ready for the next
resource policy. The key policy is part of this incident and is checked in §4.

**History is bounded and the document is not.** CloudTrail Event history covers 90 days;
without a trail to S3 or a Lake event data store, a grant attached before that leaves no
event at all. It will still be visible to Query 3's live sweep — but only its current form,
not who attached it or when.
