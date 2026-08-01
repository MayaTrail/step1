# Authoring rules

Every rule here comes from a defect found in review of a real playbook. They
are ordered by how often they recur, not by topic importance. The ones marked
**[HIGH-RECURRENCE]** were each missed two or more times *after* being written
down — check those explicitly before you ship.

---

## 1. CloudTrail event shape

**1.1 EC2 error codes carry a `Client.` prefix.**
`Client.InvalidInstanceID.NotFound`, not `InvalidInstanceID.NotFound`. The
unprefixed form is the *boto3* `Error.Code` you see in `attack.py`; copying it
into a CloudTrail query silently matches nothing. Use prefix-tolerant matching
(`contains` / `test()`) and tell the reader to confirm against a real event.

**1.2 Error strings are not uniform across services.**
IAM-policy denials usually surface as `AccessDenied` (no suffix);
service-evaluated denials as `AccessDeniedException`. Match **both**. SSM adds
`InvalidInstanceId`; Secrets Manager `ResourceNotFoundException`,
`DecryptionFailure`; EC2 Instance Connect `EC2InstanceStateInvalidException`.
Only EC2 core uses the `Client.` prefix.

**1.3 Create-style IAM responses NEST the object.**
```
iam:CreateAccessKey  -> responseElements.accessKey.accessKeyId   ✅
                     -> responseElements.accessKeyId             ❌ always null
iam:CreateUser       -> responseElements.user.userName
iam:CreateRole       -> responseElements.role.roleName
iam:CreateLoginProfile -> responseElements.loginProfile.userName
```
A flat path yields `null` silently and breaks every IOC and handoff built on
it. Verify nesting against an AWS CloudTrail log example before writing the
path.

**1.4 The same logical field has different keys on different events.**
`UpdateAssumeRolePolicy` stores the trust policy in `policyDocument`;
`CreateRole` in `assumeRolePolicyDocument`. `AddPermission` uses
`functionUrlAuthType`; `CreateFunctionUrlConfig` uses `authType`. Cover both,
OR'd — see 2.2.

**1.5 `lookup-events` returns ONLY management events.**
Never use it to hunt data-plane actions. Known data-plane calls:
`ses:SendEmail`/`SendRawEmail`, S3 `GetObject`/`PutObject`, Lambda `Invoke`,
DynamoDB item ops. A lookup-events query for these **always** returns zero —
never present that as "no abuse". Route to CloudWatch metrics or a data-event
trail instead.

**1.6 But do NOT over-apply 1.5 — verify per service.**
`bedrock:InvokeModel` / `Converse` / `ConverseStream` **are** CloudTrail
management events, logged by default with `userIdentity.arn`. Assuming
otherwise once inverted an entire detection thesis. What Bedrock management
events lack is token counts (→ CloudWatch `AWS/Bedrock`) and prompt content
(→ invocation logging), not the call itself.

**1.7 Lambda `Invoke` data events: match on `resources[].ARN`.**
A **synchronous** (`RequestResponse`) invoke — the default `aws lambda invoke`,
and the natural way an attacker tests a backdoor — records
`requestParameters: null`. The function identity lives only in `resources[]`.
Filtering on `requestParameters.functionName` silently drops sync invokes and
returns zero even when the function *was* invoked.

**1.8 `lookup-events AttributeKey=Username` matches the SESSION name.**
For EC2 instance-profile role sessions the session name is the **instance ID**,
so a role-name lookup returns zero events. Key on the instance ID and
post-filter `.userIdentity.sessionContext.sessionIssuer.userName`.
**[HIGH-RECURRENCE]** — this recurs in Eradication queries, not just the
headline investigation query. Check *every* role-activity query in the file.

**1.9 `eventTime` resolves to whole seconds.**
Do not claim sub-second timing. Measure events-per-one-second-bucket
(`sort | uniq -c | sort -rn`) as the scripted-vs-human signal.

**1.10 There is no `email.amazonaws.com` event source.**
SES v1 and SESv2 both log under `ses.amazonaws.com`. Do not invent
per-version sources — verify the real `eventSource`.

**1.11 Console sign-in is global, recorded in us-east-1.**
`responseElements.ConsoleLogin` is `Success`/`Failure`;
`additionalEventData.MFAUsed` is `Yes`/`No`. Root has **no** `userName`, so any
`Username` pivot is IAM-user-only and silently misses root.

---

## 2. Sigma

**2.1 Legacy aggregation syntax is invalid.**
`condition: selection | count() by X > 3` and `timeframe:` inside `detection:`
were removed from the spec. pySigma rejects them. Use a base rule plus a second
document with `correlation:` (`event_count` / `value_count`, `group-by`,
`timespan`, `condition: {gt: N}`).

**2.2 [HIGH-RECURRENCE] Two keys in one selection block are ANDed.**
If a signal spans two events with different field names, putting both keys in
one block means **no single event satisfies it and the rule never fires** — a
silent false negative, typically on a P0 rule. Split into sibling blocks and OR
them:
```yaml
  trust_update:
    requestParameters.policyDocument|contains: 'x'
  trust_create:
    requestParameters.assumeRolePolicyDocument|contains: 'x'
  condition: selection and (trust_create or trust_update)
```

**2.3 [HIGH-RECURRENCE] Selection blocks must be SIBLINGS under `detection:`.**
Nesting `success:` inside `selection:` makes it a map-valued field and breaks
the `condition:` that references it. Eyeball the indentation of every rule.

**2.4 `|count|` is not a Sigma modifier.**
Sigma cannot count array length or occurrences inside a single-event rule.
There is no such modifier and it fails conversion on every backend. Volume and
array-size logic goes in a correlation or the log-platform query. Say so
plainly — do not hedge it as "backend-dependent".

**2.5 `field: null` matches when the field is ABSENT.**
So "successful calls only" is `condition: selection and success` where
`success: {errorCode: null}` — not `and not`.

**2.6 A distinct-count base rule MUST filter to successes.**
Otherwise a probing actor hitting `AccessDenied` on 15 secrets fires the same
volume alert as a real exfiltration of 15 secrets. It also keeps the
detection's count aligned with the eradication work-list.

**2.7 `temporal_ordered` conveys ordering by its type name.**
Do not add a separate `ordered: true` key — nonstandard, may fail strict
validators. Fields are: `type`, `rules`, `group-by`, `timespan`.

**2.8 `value_count` puts `field` inside `condition`.**
```yaml
correlation:
  type: value_count
  rules: [base_rule_name]
  group-by: [userIdentity.arn]
  timespan: 10m
  condition:
    gte: 15
    field: requestParameters.secretId
```

**2.9 Correlations reference base rules by `name:`, not `id:`.**
Every referenced base rule must exist — inline it in the same file so the rule
set is deploy-complete rather than depending on a file the operator has to
find.

---

## 3. KQL

**3.1 [HIGH-RECURRENCE] `has`/`has_any` is WHOLE-TERM, not substring.**
Terms are delimited by non-alphanumerics, so `has` **never** reliably matches
CIDRs (`0.0.0.0/0`, `::/0`), paths (`/dev/tcp`), commands with spaces
(`base64 -d`), or ARNs. Always use `contains` for anything punctuated. Before
shipping, grep the KQL for `has "` and `has_any` and check every operand.
Sigma's `|contains` is already substring and is fine.

**3.2 The Sentinel `AWSCloudTrail` table uses FLATTENED columns.**
The role name is the top-level column `SessionIssuerUserName` — there is no
`UserIdentitySessionContext` blob to `parse_json`. Other real flattened
columns: `UserIdentityArn`, `UserIdentityType`, `UserIdentityAccessKeyId`,
`SessionMfaAuthenticated`, `SourceIpAddress`, `EventSource`, `EventName`,
`ErrorCode`, `AWSRegion`.
`RequestParameters` / `ResponseElements` / `AdditionalEventData` **are**
dynamic JSON and **do** need `parse_json`.
CloudWatch Logs Insights is different — it *does* use dotted paths like
`userIdentity.sessionContext.sessionIssuer.userName`.

**3.3 Watchlists are referenced via `_GetWatchlist('Name')`.**
A bare `_MyWatchlist` identifier is invalid. Use
`_GetWatchlist('InstanceRoles') | project SearchKey`. If a rule depends on a
watchlist, add "create and maintain this watchlist" to §1 Preparation.

**3.4 Label the dialect.**
Sentinel / Log Analytics KQL is **not** runnable in CloudWatch Logs Insights —
`summarize`, `make_set`, `case()`, `bin()` and the `AWSCloudTrail` table do not
exist there. Say which engine each query targets.

---

## 4. jq and shell

**4.1 `select(A[] == x or B)` drops the record when `A` is empty.**
An empty generator on one side of `or` yields zero outputs. Use
`select(any(A[]?; . == x) or B)`.

**4.2 [HIGH-RECURRENCE] Query-to-query handoffs must survive aggregation.**
The field a later step consumes must appear in the earlier query's **final**
output — including through any `jq -s 'group_by(...) | map({...})'` stage. The
classic failure: stage 1 computes `access_key`, stage 2's `map({...})` drops
it, and the placeholder in a later query can never be filled. For every
`<...-from-Query-N>`, confirm the field is in Query N's *last* jq object.

**4.3 Assumed-role ARN role name is the 2nd `/` segment.**
`arn:aws:sts::acct:assumed-role/<RoleName>/<SessionName>` → `awk -F'/' '{print $2}'`.
`$NF` gives the *session* name. IAM-user ARNs do use `$NF` — do not reuse the
user snippet for roles.

**4.4 Never put a bare `<placeholder>` in a `for ... in` word list.**
`for IID in <ids>; do` is broken shell — `<` and `>` are redirection
metacharacters and throw a syntax error when pasted. Assign to a quoted
variable first: `TARGET_IDS="<space-separated-ids>"; for IID in $TARGET_IDS`.
Quoted `X="<placeholder>"` is fine.

**4.5 Prefer `--output json | jq -r '.Events[].CloudTrailEvent | fromjson'`**
over `--output text | jq`.

**4.6 `aws ssm send-command --parameters` needs JSON form**
(`'{"commands":["..."]}'`), not shorthand, whenever the payload contains commas
or brackets.

**4.7 Default VPC Flow Log (v2) field order.**
`version account-id interface-id srcaddr dstaddr srcport dstport protocol
packets bytes start end action log-status` → field **13 = action**
(ACCEPT/REJECT), field 14 / `$NF` = log-status. Do not swap them. This only
applies to flow logs in CloudWatch Logs; if they go to S3, a
`filter-log-events` query is inapplicable — caveat it.

**4.8 `date -u -d` is GNU-only.** Not portable to BSD/macOS. Keep it consistent
across the set rather than fixing one file and diverging.

---

## 5. IAM policy inspection

**5.1 CloudTrail logs policy documents URL-ENCODED.**
`"` → `%22`, `*` → `%2A`, `:` → `%3A`, space → `%20`/`+`. So a `|contains` on
`"AWS":"*"` **never matches**. What survives verbatim: **12-digit account IDs**
and other bare alphanumerics.

Therefore: a Sigma rule can catch **known-bad account IDs**; wildcard,
arbitrary-external and structural checks **must decode** the document, which
means the log-platform query or a bash `urllib.parse.unquote` path.

Note `iam:get-role` / `list-roles` return the policy **decoded** — different
from the CloudTrail event.

**5.2 jq must guard the object-OR-array shape at BOTH levels.**
IAM allows `Statement` as a single object or an array; `Principal` as an object
or the bare string `"*"`; `Action` as a string or an array.
`any(.Statement // []; cond)` **crashes** when `Statement` is one object,
silently failing a sweep. Normalise first:
```jq
(.Statement // [] | if type=="object" then [.] else . end)
```

**5.3 IAM conditions do not wildcard with `StringEquals`.**
`*` is expanded only in the `Resource` element and in the `*Like` operators.
A `StringEquals` against `...parameter/app/*` never matches. Use `StringLike`.

**5.4 Do not use `ForAnyValue:`/`ForAllValues:` on single-valued keys.**
`ec2:InstanceType` and most request-context keys are single-valued; the set
prefix evaluates inconsistently and can fail open. Set operators are only for
multi-valued keys.

**5.5 `aws:username` is ABSENT for assumed-role principals.**
A plain `StringNotEquals` on it wrongly denies every role-based call. Use the
`...IfExists` variant or a `Null` condition.

**5.6 `BoolIfExists` on `aws:MultiFactorAuthPresent` treats an ABSENT key as
matching.** So the deny *does* fire against password-only console users. The
clause that excludes role sessions is the `PrincipalArn` condition, not the
`IfExists` operator. This one is easy to get exactly backwards.

**5.7 IAM accepts unknown actions silently.** Verify an action exists before
putting it in a deny policy — `ssm:RunCommand` is not real.

---

## 6. Detection design

**6.1 Thresholds must fire on the emulation's own baseline.**
If `attack.py` targets exactly 3 instances, a `> 3` fan-out threshold never
fires and contradicts the playbook's own "expected outcome" text. Use `>=` at
the baseline. Read the actual counts.

**6.2 Match the FULL error set the attack produces.**
A `contains: 'LimitExceeded'` guess misses `InsufficientInstanceCapacity`,
`Unsupported`, `InvalidParameterValue`. Read the emulation's exception
handling and enumerate every code.

**6.3 Never bundle a high-volume call with a rare one.**
`sts:GetCallerIdentity` is among the highest-volume calls in AWS. OR-ing it
with a rare signal buries the signal completely. The same applies to
`DescribeInstances`, `ListSecrets`, `GetParameters`, `UpdateFunctionConfiguration`.

**6.4 Never make the attacker's cleanup a trigger.**
`RemovePermission`, `DeleteLayerVersion`, `RevokeSecurityGroupIngress`,
`DeleteLoginProfile`, `DisableTrustAnchor` are teardown. Including them inverts
the signal — a *removal* is not persistence. Keep them for the forensic
timeline only.

**6.5 Count the thing that measures severity.**
Secrets disclosed, not calls. Instances read, not events. Distinct actions, not
call volume. A batch API can expose 20 items in one event.

**6.6 Beware double-counting.**
`BatchGetSecretValue` *also* emits a per-secret `GetSecretValue` entry. Summing
both double-counts ~2×. Count distinct IDs from **one** source.

**6.7 A bare `condition: selection` is acceptable only for genuinely rare
administrative writes** — `EnableSerialConsoleAccess`, `CreateTrustAnchor`,
GuardDuty finding matches. Justify it in a comment when you use it.

**6.8 HTTP 200 / absent `errorCode` is not success in the security sense.**
`GetPasswordData` returns 200 with empty `PasswordData` for Linux hosts and
hosts under ~4 minutes old. CloudTrail does not record response bodies. Never
gate destructive containment on "no errorCode".

---

## 7. Response correctness

**7.1 Check containment ordering against later steps.**
An egress-zero quarantine security group severs the SSM agent's outbound 443,
so any later `ssm send-command` remediation hangs. Sequence rotation before
isolation, or allow 443 to the SSM endpoints.

**7.2 `aws:TokenIssueTime` revokes only PRE-EXISTING tokens.**
A credential re-fetched from IMDS after the policy is applied gets a newer
timestamp and is **not** denied. It kills currently-leaked tokens; it does not
gate the role or stop fresh theft from a still-compromised host.

**7.3 Do not overstate what a cleanup step achieves.**
`ec2:delete-key-pair` removes only AWS's stored public key; the attacker's
private copy and any retrieved ciphertext stay usable forever. Rotation is the
only real revocation.

**7.4 Some things cannot be revoked directly.**
An STS federation token has no revoke API — rotating the source user's keys
does **not** stop it. Only an explicit Deny on the source IAM user works,
because permissions are evaluated per request.

**7.5 `--layers` REPLACES the whole layer list.**
`UpdateFunctionConfiguration --layers` does not remove one entry. Re-specify
every legitimate layer, or you strip the function's real dependencies while
removing the malicious one.

**7.6 Read the emulation's infra before writing Revert.**
The Secrets Manager emulations set `recovery_window_in_days=0`, so teardown
hard-deletes immediately rather than the usual 7–30 day window. Do not assume
AWS defaults.

**7.7 Disable before delete.** A deleted trust anchor, key, or user takes its
evidence with it.

**7.8 Not every caller has an access key.** If the principal was root or a
federated identity, "disable the access key" does not apply. Branch on
principal type.

---

## 8. Cross-cutting

**8.1 [HIGH-RECURRENCE] When correcting a THESIS, propagate it everywhere.**
A spine rewrite that fixes Classification, §1 and the queries but leaves the
old claim in the §6 RCA table, a §6 guardrail, two trigger-table Source
columns and a stale query cross-reference produces a self-contradictory
document. After any thesis-level correction, grep the whole file for the wrong
claim's keywords and re-check §6, all trigger-table Source columns, and every
"from Query N" reference.

**8.2 Every "from Query N" must have a Query N that produces it.**
Same class as 4.2 — trace every cross-reference to a real producing step.
Renumbering queries breaks these silently.

**8.3 Report MANIFEST mismatches, do not fix them.**
Severity (`MEDIUM` where the IR view is High) and MITRE names (upstream labels
rather than canonical MITRE) are usually out of scope. Flag them inline in the
playbook and in your summary.

**8.4 Keep house style consistent rather than fixing one file.**
The §6 policy JSON snippets use a leading `// comment` and often a bare
`Statement` fragment. That is not paste-ready JSON, but it matches the
reference playbook. Either caveat it or change all of them — never diverge a
single file.

**8.5 No vendor or product attribution** in any generated content.
