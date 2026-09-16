# Detection Note — T1555.006 (Credentials from Password Stores: Cloud Secrets Management Stores)

**Signal:** a principal reading SSM Parameter Store parameters **with
`WithDecryption` set**, at a volume or a scope that no configuration loader in
the account has a reason for — most sharply, a recursive `GetParametersByPath`
that returns every `SecureString` under a hierarchy in one call.

**The call is not the signal; the decryption flag is.** Reading a `String`
parameter is how nearly every application on AWS gets its configuration, and it
happens thousands of times a day. Decrypting a `SecureString` is the credential
access, because `SecureString` is where database passwords, third-party API keys
and long-lived tokens are kept. AWS states the flag's semantics plainly:
`WithDecryption` "is ignored for `String` and `StringList` parameter types" — so
its presence tells you the caller specifically wanted plaintext of encrypted
material.

**What the original rule got wrong.** It counted `GetParameter OR GetParameters`
at 50 events in five minutes and stopped there. Its own description says the
alert is for a user who "retrieves and decrypts" parameters, but `WithDecryption`
appears nowhere in the query, so an application reading fifty plaintext `String`
values at boot is scored identically to an actor decrypting fifty secrets. It
omits `GetParametersByPath`, which is the single highest-yield call in the API.
And it has no success filter, so fifty `AccessDenied` responses from a principal
probing its own permissions raise the same alert as fifty successful reads —
and the eradication work-list built from that alert would contain fifty
parameters that were never disclosed.

## `ssm:GetParameter*` is a MANAGEMENT event — the names are in your trail

This is the fact the response turns on, and it is the opposite of the reflex.
AWS: *"Systems Manager logs all control plane operations to CloudTrail as
management events."* The only Systems Manager **data** events are
`CreateControlChannel` / `OpenControlChannel` on
`AWS::SSMMessages::ControlChannel` and `RequestManagedInstanceRoleToken` on
`AWS::SSM::ManagedNode`. Parameter Store reads are not among them, so
`lookup-events` sees every one of them by default, and
`requestParameters.name` / `.names` / `.path` tells you exactly which parameters
were touched.

The consequence for the responder is direct: **do not blanket-rotate.** You can
enumerate the disclosed set and rotate precisely. A playbook that sends a team
to rotate every secret in the account because "the reads are not logged" is
acting on a false premise and will take days longer than it needs to.

Two caveats that are real:

- **CloudTrail records the parameter name, never the value.** The value lives in
  the response, and read APIs do not populate `responseElements` with it. You
  learn *what* was taken, not *what it was* — which is usually enough, because
  the name says whether it was a database password or a feature flag.
- **A trail configured `ReadWriteType: WriteOnly` drops every `Get*` event.**
  The events exist; a write-only trail throws them away. Confirm the trail's
  read/write type before concluding a principal read nothing.

## Counting events under-counts the blast radius by up to ten times

`GetParameters` accepts up to **10** names per call. `GetParametersByPath`
returns up to **10** parameters per page (`MaxResults` valid range 1–10) and
paginates with `NextToken`. A `Recursive` drain of a 500-parameter hierarchy is
50 events — under a 50-events-in-5-minutes threshold if it is spread over eleven
minutes, and in every case a poor proxy for how many secrets were exposed.

The response set is not logged, so the count has to come from somewhere else.
It comes from KMS. Parameter Store binds an encryption context to every
`SecureString` operation:

```
"PARAMETER_ARN":"arn:aws:ssm:<region>:<account>:parameter/<parameter-name>"
```

and AWS documents that the encryption context "appears in plaintext in logs,
such as AWS CloudTrail logs". So every decrypted parameter produces its own
`kms:Decrypt` event naming itself. Counting distinct
`requestParameters.encryptionContext.PARAMETER_ARN` values per caller is a count
of **secrets exposed**, not of API calls, and the set of ARNs *is* the rotation
work-list. That is what the `value_count` correlation in `sigma_t1555_006.yml`
does.

The pairing holds for both parameter tiers, by different routes: a standard
`SecureString` is encrypted directly under the KMS key, so the read calls
`Decrypt`; an advanced `SecureString` is envelope-encrypted with the AWS
Encryption SDK, and the read calls `Decrypt` on the wrapped data key — with the
same Parameter Store encryption context. Writes differ (`Encrypt` for standard,
`GenerateDataKey` for advanced) and are not part of this signal.

**Not verified:** whether the `kms:Decrypt` event raised on Parameter Store's
behalf attributes `userIdentity` to the original SSM caller or carries an
`invokedBy` marker. AWS's published `Decrypt` CloudTrail examples show only
directly invoked calls. Correlate SSM reads to KMS decrypts on
`encryptionContext.PARAMETER_ARN` and the time window, and confirm the identity
shape against one real event before keying anything on it.

## Sizing what a path drain actually returned

For `GetParametersByPath` the event carries the `path` and the `recursive` flag
and nothing about the result. To bound what was returned:

- `DescribeParameters` with `Key=Path,Option=Recursive` lists the parameters
  under that path **as they are now**, metadata only — `Name`, `Type`, `KeyId`,
  `Version`, `LastModifiedDate`, `LastModifiedUser`, never `Value`. `MaxResults`
  is 1–50 here, unlike the read APIs' 10.
- Filter that list to `Type=SecureString` for the credential subset.
- Take the KMS `PARAMETER_ARN` set as ground truth where the parameters are
  `SecureString`; use the `DescribeParameters` listing to catch plaintext
  `String` parameters that hold credentials, which KMS never sees.

The listing is **as of now**, not as of the read. If the attacker or a later
deploy added or removed parameters under that path in between, the two sets
diverge and the KMS count is the more reliable one.

## Two documented behaviours that break naive detections

**A `GetParameter` miss is not logged at all.** AWS, on `ParameterNotFound`:
*"For the `DeleteParameter` and `GetParameter` actions, if the specified
parameter doesn't exist, the `ParameterNotFound` exception is not recorded in
AWS CloudTrail event logs."* An actor guessing parameter names one at a time
generates no telemetry for the misses. There is no error-based detection for
that path.

**A `GetParameters` miss looks like success.** The plural call returns HTTP 200
with the unknown names in an `InvalidParameters` array and no `errorCode` at
all — its only documented errors are `InternalServerError` and `InvalidKeyId`.
So enumeration through the plural call is indistinguishable from legitimate
reads on error code alone.

## Response levers

**Rotation is the only revocation.** Nothing in AWS invalidates a parameter
value that has already been returned. Deleting the parameter, denying the
principal, or rotating the KMS key all leave the plaintext the actor already
holds fully usable. State that plainly to whoever is deciding scope.

**A per-parameter `Deny` does not contain a path drain — this is documented, not
theoretical.** AWS: *"If a user has access to a path, then the user can access
all levels of that path. For example, if a user has permission to access path
`/a`, then the user can also access `/a/b`. Even if a user has explicitly been
denied access in IAM for parameter `/a/b`, they can still call the
`GetParametersByPath` API operation recursively for `/a` and view `/a/b`."*
Contain by removing the `Allow` at the path, not by adding a `Deny` at the leaf.

**Encryption-context conditions only work on a customer managed key.** You can
scope `kms:Decrypt` with
`"StringLike": {"kms:EncryptionContext:PARAMETER_ARN": "arn:aws:ssm:...:parameter/app/*"}`,
but AWS states you "cannot establish access control policies for the default
`aws/ssm` KMS key". Parameters left on the default key are not protectable this
way — that is a prerequisite finding, not a tuning note.

**Error strings.** `GetParameter`: `ParameterNotFound`, `ParameterVersionNotFound`,
`InvalidKeyId`, `InternalServerError`. `GetParameters`: `InvalidKeyId`,
`InternalServerError` only. `GetParametersByPath`: `InvalidFilterKey`,
`InvalidFilterOption`, `InvalidFilterValue`, `InvalidKeyId`, `InvalidNextToken`,
`InternalServerError`. IAM denials surface as `AccessDenied` and
service-evaluated denials as `AccessDeniedException` — match both, and confirm
against a real denied event in your own trail.

**GuardDuty:** no finding type is specific to bulk Parameter Store retrieval.
`CredentialAccess:IAMUser/AnomalousBehavior` may fire on the calling identity
but is not a substitute for this rule.

**MITRE:** the source rule labels this T1552 (*Unsecured Credentials*), the
parent family. T1555.006 (*Credentials from Password Stores: Cloud Secrets
Management Stores*) is the precise mapping — Parameter Store is a managed
secrets store, and the credentials in it are not "unsecured"; they are
correctly encrypted and correctly retrieved by a principal that should not have
been able to.

**Severity:** the source rule rates this P3 with a `high` label. The IR
assessment is **High / P0 once decryption of more than a handful of
`SecureString` parameters by an unexpected principal is confirmed** — the actor
holds plaintext credentials to whatever those parameters front, and the
containment clock is set by how fast those systems can be rotated, not by
anything in AWS.

## Cross-references

- `../../ssm.impact.parameter-deletion-detected/` — the same `PARAMETER_ARN`
  encryption-context trick does **not** help there; a delete performs no
  cryptographic operation.
- `../../ssm.discovery.excessive-parameter-creation-detected/` — `PutParameter`
  with `Overwrite` is the write-side counterpart, and `LastModifiedUser` from
  `DescribeParameters` is the shared pivot.
- `../../ec2.credential-access.imds-credential-theft/` — the instance-profile
  session-name fact (`assumed-role/<Role>/<instance-id>`) applies to every query
  here that keys on `AttributeKey=Username`.

**Files here:**

- `sigma_t1555_006.yml` — five documents: the recursive decrypted path drain
  (`high`), a `value_count` correlation over distinct decrypted parameters
  (`high`) with its KMS base rule (`low`), and the corrected volume rule
  (`medium`) with its SSM base rule (`low`).
- `kql_t1555_006.kql` — the decrypted-read summary with a parameter-count lower
  bound, plus the KMS `PARAMETER_ARN` count that produces the exact rotation
  list, and the enumeration blind spots inline.

Full response procedure is in `../PLAYBOOK.md`.
