# Detection Note — T1565.001 (Data Manipulation: Stored Data Manipulation)

**Signal:** `ssm:PutParameter` with `Overwrite` set — an existing parameter's
value replaced — by a principal that does not own that configuration path.

**The API is create-OR-update, and the rule only names one half.** AWS documents
`PutParameter` as "Create or update a parameter in Parameter Store", with
`Overwrite` defaulting to `false`. Creating ten new parameters is a deployment.
Overwriting one parameter that a running application reads at boot or on refresh
is configuration poisoning: a database endpoint pointed at attacker
infrastructure, a feature flag that disables an authorisation check, an AMI ID
that a launch template consumes, a value an SSM document resolves through
`{{ssm:<name>}}` at execution time.

**What the original rule got wrong.** It counted `putparameter` events, more than
ten in five minutes, grouped by
`userIdentity.sessionContext.sessionIssuer.userName`. It calls that "excessive
parameter creation" while matching an event that is equally an update, so the
overwrite — the case with an actual victim — is the one it scores lowest, because
one is not more than ten. The group-by is also empty for IAM users:
`sessionContext` exists only for role sessions, so an IAM user's events carry a
null key and either bucket together or drop out of the aggregation entirely. The
corrected rules group by `userIdentity.arn`.

## Two proofs of overwrite, and you should read both

The request flag is the obvious one: `requestParameters.overwrite`. The response
gives an independent confirmation — `PutParameter` returns `Version`, and AWS
documents that "if you edit a parameter value, Parameter Store automatically
creates a new version". So `responseElements.version > 1` means an existing
parameter was modified whatever the request said, and it survives a client that
omitted the flag. `responseElements` here is **flat** — `version` and `tier`, no
nesting — which is worth stating because `CreateDocument` in the sibling document
playbook nests under `documentDescription` and the two are easy to conflate.

Field casing: the API Reference documents the wire spelling (`Overwrite`,
`Policies`, `Value`); AWS's published `ssm.amazonaws.com` CloudTrail examples
render request keys with a lower-case initial. The rules key on the lower-case
form; confirm against one real event.

## The value is not in the log, and you should hope it stays that way

CloudTrail records the parameter **name**, and AWS does not document whether
`requestParameters.value` is recorded for `PutParameter`. Do not build a rule that
depends on reading it. And if your trail *does* carry parameter values in
plaintext, that is a finding in its own right — your CloudTrail bucket has become
a secret store with a different, usually broader, set of readers than Parameter
Store had.

The place the previous value survives is the parameter's own version history:

```
aws ssm get-parameter-history --name <name> --with-decryption \
  --query 'Parameters[].{Version:Version,Modified:LastModifiedDate,User:LastModifiedUser,Value:Value}'
```

Parameter Store keeps the **100 most recent versions**. That is both the diff and
the clock: a principal that overwrites the same parameter a hundred times pushes
the pre-incident version out of the window and it is then gone permanently. Pull
the history before remediating, not after.

`DescribeParameters` with `Key=Path,Option=Recursive` gives `LastModifiedUser` per
parameter with no log at all — the fastest way to find everything one principal
touched under a path, and it works even when the trail window has rolled.

## Two behaviours the original rule leaves on the table

**The write API is a read oracle.** `PutParameter` without `Overwrite` against a
name that already exists returns `ParameterAlreadyExists`. A principal that holds
`ssm:PutParameter` but not `ssm:GetParameter*` can therefore enumerate which
parameter names exist by attempting to write them, one error at a time, without
ever reading a value. The `value_count` correlation in `sigma_t1565_001.yml`
counts distinct names probed this way rather than raw attempts, because ten
retries of one name is a broken script and ten distinct names is enumeration.

**An expiration policy is a delete with no delete event.** `PutParameter` accepts
a `Policies` array, and AWS documents the `Expiration` type as: "This policy
deletes the parameter after it expires. When you create the policy, you specify
the expiration date... When the expiration time is reached, Parameter Store
deletes the parameter." Parameter Store performs that deletion itself, so the
principal that armed it produces no `DeleteParameter` event at all — the
destruction happens later and is attributed to nobody. That is why the expiration
rule carries `attack.t1485` alongside `attack.t1565.001`, and why the sibling
`ssm.impact.parameter-deletion-detected` playbook cannot be relied on to catch it.

Parameter policies are an **advanced-tier** feature, which is billed, so an
expiring parameter is rare in most accounts and the rule is correspondingly quiet.

## Response levers

**`ssm:Overwrite` and `ssm:Policies` are real IAM condition keys**, both
string-valued (`"true"` / `"false"`) and used with `StringEquals` — AWS's own
policy examples use `StringEquals`, not `Bool`. A `Deny` on `ssm:PutParameter`
conditioned on `ssm:Overwrite` equal to `"true"` lets a principal create
parameters but never change one; a `Deny` conditioned on `ssm:Policies` blocks the
expiring-parameter time bomb outright. Both are exact values, so `StringEquals` is
correct here — unlike a wildcarded ARN, which needs the `*Like` operators.

**Restoring a value is not the same as restoring the system.** Writing the
known-good value back with `--overwrite` creates yet another version; the
application that already read the poisoned value keeps using it until it refreshes
or restarts. Restart or force-refresh the consumers, and say which ones in the
incident record.

**Beware the asynchronous type.** A parameter with `DataType: aws:ec2:image` is
validated asynchronously: AWS states "a successful HTTP 200 response does not
guarantee that your parameter was successfully created or updated". A successful
`PutParameter` event for one of those is not proof of state — check the parameter
itself.

**Error strings:** `ParameterAlreadyExists`, `ParameterLimitExceeded`,
`ParameterMaxVersionLimitExceeded`, `ParameterPatternMismatchException`,
`HierarchyLevelLimitExceededException`, `HierarchyTypeMismatchException`,
`InvalidAllowedPatternException`, `InvalidKeyId`, `UnsupportedParameterType`,
`PoliciesLimitExceededException`, `InvalidPolicyTypeException`,
`InvalidPolicyAttributeException`, `IncompatiblePolicyException`, `TooManyUpdates`,
`InternalServerError`. Denials are `AccessDenied` (IAM) and
`AccessDeniedException` (service-evaluated) — match both, and confirm against a
real denied event.

**GuardDuty:** no finding type specific to Parameter Store writes.

**MITRE:** the source rule labels this T1082 (*System Information Discovery*)
under TA0007. Writing a parameter discovers nothing. T1565.001 (*Data
Manipulation: Stored Data Manipulation*) under Impact (TA0040) is the mapping for
the overwrite case, which is the one with a victim. The enumeration case — the
`ParameterAlreadyExists` oracle — is genuinely Discovery, and is tagged T1526
(*Cloud Service Discovery*) on its own rule rather than folded into the main
mapping. The directory slug keeps the source's `discovery` label; §6 of
`../PLAYBOOK.md` carries the correction.

**Severity:** the source rule rates this P4. The IR assessment is **High for an
overwrite of an existing parameter by a principal outside the owning pipeline,
Medium for an expiration policy or a name-enumeration burst, Low for bulk
creation** — the source rule's single priority is right only for the case it
names and wrong for the two it does not.

## Cross-references

- `../../ssm.impact.parameter-deletion-detected/` — the destruction sibling, and the
  place to look when an expiration policy armed here has since fired. Note that
  the delete it watches for **will not appear** for a policy-driven expiry.
- `../../ssm.credential-access.high-number-of-ssm-parameters-retrieval/` — the read
  side, and the source of the shared facts about `SecureString`, the
  `PARAMETER_ARN` encryption context and the 100-version retention.
- `../../ssm.discovery.excessive-document-creation-detected/` — SSM documents resolve
  `{{ssm:<name>}}` at execution time, so a poisoned parameter changes what an
  existing, unmodified document runs.

**Files here:**

- `sigma_t1565_001.yml` — six documents: the overwrite rule (`high`), the
  expiration-policy rule (`medium`), a `value_count` correlation over distinct
  names probed through `ParameterAlreadyExists` (`medium`) with its base rule
  (`low`), and the corrected volume correlation (`low`) with its write base rule
  (`low`).
- `kql_t1565_001.kql` — one summary reading both proofs of overwrite, with the
  verdict ladder, the `get-parameter-history` recovery path, the full error set and
  the `ssm:Overwrite` / `ssm:Policies` prevention notes inline.

Full response procedure is in `../PLAYBOOK.md`.
