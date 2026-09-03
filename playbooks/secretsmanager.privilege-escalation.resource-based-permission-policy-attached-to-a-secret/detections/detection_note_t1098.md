# Detection Note — T1098 (Account Manipulation)

**Signal:** a resource-based permission policy is attached to a Secrets Manager secret,
granting a principal outside the secret's own identity-policy boundary the right to read
it — or to rewrite the grant.

**This is the only Secrets Manager use case where the attacker's artefact survives every
identity-side remediation.** Revoke the sessions, disable the keys, delete the inline
policies, and a resource policy naming an external account still stands: it lives on the
secret, not on the principal, and it is evaluated in the secret owner's account for a
caller the owner has no control over. It is the same shape as the Lambda and S3
resource-policy siblings — `../../lambda.persistence.resource-policy-backdoor/` and
`../../_superseded/aws.exfiltration.s3-bucket-public-exposure/` — and it shares their parsing traps
exactly.

## AWS's own escalation warning is the severity argument

From the cross-account access guide, verbatim:

> Resource-based policies granting `secretsmanager:PutResourcePolicy` permission gives
> principals, even those in other accounts, the ability to modify your resource-based
> policies. This permission lets principals escalate existing permissions like obtaining
> full administrative access to secrets.

A grant that includes `secretsmanager:PutResourcePolicy` — directly or through
`secretsmanager:*` — is self-perpetuating. Removing the grantee from the document does
not remove them, because they can put the document back. That is why it has its own rule
at `high` rather than being folded into the principal check.

## What the original rule got wrong

The rule matched `PutResourcePolicy` **AND** the literal `secretsmanager:*` **AND** the
literal `"Resource":"*"`, with no `errorCode`.

**The second substring cannot match a real policy.**
`requestParameters.resourcePolicy` is raw JSON in whatever whitespace the client sent —
percent-encoding is a property of what IAM *returns*, not of a CloudTrail request
parameter (rule A4). Anyone attaching a real policy submits it from a file, so the
document is pretty-printed and the stored string reads `"Resource": "*"` with a space.
The rule's own canonical target does not match its own pattern. Match bare action tokens,
which have no interior spacing, and do everything structural by parsing.

**ANDing the two substrings narrows the rule to the one case that barely matters.** It
fires only on a document granting every Secrets Manager action on every resource. The
actual backdoor is narrower and worse:

```json
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"AWS":"arn:aws:iam::999988887777:root"},
 "Action":"secretsmanager:GetSecretValue","Resource":"*"}]}
```

That hands a stranger the secret's plaintext, permanently, and contains neither
substring. This is defect class D-a — the technique's own canonical example does not fire
the rule that exists to catch it.

**No principal check.** The discriminator for a resource policy is *who it names*, not
what actions it lists. A same-account grant to a role you already trust is
administration; the identical action list pointed at an outside account is a backdoor.
The rule inspects the action list and never the Principal.

**Grouped by `sessionContext.sessionIssuer.userName`.** A principal using long-term IAM
user access keys does not carry session context, so the grouping key is absent for exactly
the credential type most likely to be doing this out of band (rule A5). Group on
`userIdentity.arn`.

## Parsing, and the shape guards that are not optional

Use `tools/decode_policy_documents.py` rather than writing another parser. IAM accepts
`Statement` as a single object **or** an array, `Principal` as an object **or** the bare
string `"*"`, and `Action` as a string **or** an array. Iterating a bare dict yields its
keys, so an unguarded sweep skips the statement and reports clean on exactly the grant it
exists to find (rule D3). The decoder normalises all three, and its default `auto` mode
routes any `Allow` statement carrying a `Principal` to the resource-policy evaluator,
which is the right path for a secret policy — verified against the four shapes that
matter (external account, bare `"*"` principal, same-account, org-confined wildcard).

**Two honest limits on the shared decoder for this dialect:**

1. **`sts:ExternalId` is in its confiner list and does not confine a secret.** It is an
   `sts:AssumeRole` request key and is not present in the authorization context of a
   `secretsmanager:GetSecretValue` call, so a statement conditioned only on it is
   reported `[i] CONFINED` when what has actually happened is that the statement can
   never match at all. That direction fails closed rather than open, but the verdict is
   still wrong — read any `CONFINED` verdict's condition keys by hand before filing the
   grant as safe.
2. **It does not grade the action list on the resource-policy path.** The evaluator
   answers "who is named and is it confined", not "what were they given". Pair it with an
   explicit action check for `secretsmanager:PutResourcePolicy`, `secretsmanager:*` and a
   bare `"*"`, normalising `Action` and `NotAction` through the same list guard.

And do not trust the decoder's trailing `[OK] Decode-and-parse pass complete` line as a
verdict: it prints regardless of how many findings preceded it. Count the `[!]` lines.

## The one condition that genuinely stops this

Cross-account access to a secret needs **three** things, and AWS is explicit that the
third is not optional: the resource policy, an identity policy in the caller's own
account, and permission to use the KMS key — *"you can't use the AWS managed key
(`aws/secretsmanager`) for cross-account access. Instead, you must encrypt your secret
with a KMS key that you create."*

So a secret encrypted with `aws/secretsmanager` **cannot** be read cross-account no
matter what its resource policy says. That single fact triages half of these alerts: check
`DescribeSecret`'s `KmsKeyId` first. If it is absent, the secret uses the AWS managed key
and the external grant is inert until someone also re-keys the secret — which is an
`UpdateSecret` event and a second, separate alert
(`../../secretsmanager.persistence.secret-value-replaced/`). An attacker who understands this will
re-key first; that ordering is worth hunting for on its own.

`ListSecrets` and `BatchGetSecretValue` are **not** in AWS's list of operations for which
cross-account permission is effective, so an external grantee cannot enumerate your
secrets or bulk-read them. They must know the exact ARN and fetch one at a time.

## BlockPublicPolicy defaults to off

AWS: *"By default, public policies aren't blocked."* Nothing prevents a wildcard-principal
policy unless the caller opts in, and an attacker will not. The corollary is that a
`PublicPolicyException` in your trail is unusually high-signal: it only occurs where
someone deliberately set the guard, which means the event is an attempt that was stopped,
not a misconfiguration. It has its own rule.

## Response levers

`DeleteResourcePolicy` returns nothing and `PutResourcePolicy` echoes only ARN and Name —
the request parameter in CloudTrail is the **only** record of what was granted. Capture
the document with `get-resource-policy` before removing it, or the evidence goes with the
grant. That ordering is the first step in `../PLAYBOOK.md` §3 for exactly this reason.

Removing the policy does not un-read anything already read. Rotate every secret that
carried an external grant, in the order given by `../PLAYBOOK.md` §4.

## Error strings

`PutResourcePolicy` throws `InternalServiceError`, `InvalidParameterException`,
`InvalidRequestException`, `MalformedPolicyDocumentException`, `PublicPolicyException` and
`ResourceNotFoundException`. `MalformedPolicyDocumentException` is worth watching
alongside `PublicPolicyException`: a run of malformed submissions is someone iterating on
a document they cannot get accepted. Authorization denials use the service's common set —
`AccessDeniedException` and `NotAuthorized`; unsuffixed `AccessDenied` is not in the
documented set but an IAM-policy-evaluated denial can still surface that way (rule A7).

## GuardDuty

No GuardDuty finding type is specific to attaching a Secrets Manager resource policy. IAM
Access Analyzer is the right continuous control here — it reports external access granted
by resource policies as findings, which turns this from an alert into an inventory.

## Severity

**High.** The source rule rates it P3. That is too low on two counts. The grant survives
every identity-side containment, and where it includes `PutResourcePolicy` it survives the
removal of the grant itself. AWS's own documentation describes the escalation path in
those words. The mitigating factor — that a secret on the AWS managed key cannot be read
cross-account — is a property of the secret, not of the technique, so it lowers the
severity of individual alerts and not of the class.

**MITRE:** `T1098 — Account Manipulation`, which is the source's own mapping and is correct — a resource policy on a secret grants a principal standing access it did not have. Verified live 2026-08-30.

**GuardDuty:** no finding type is specific to Secrets Manager. The adjacent ones are `UnauthorizedAccess:IAMUser/ResourceCredentialExfiltration.InsideAWS` and `.OutsideAWS`, which fire on credentials retrieved from an AWS resource and used elsewhere, and `CredentialAccess:IAMUser/AnomalousBehavior`, which is a CloudTrail-driven anomaly detector rather than a rule about secrets. Neither covers retrieval volume.

**Files here:**

- `sigma_t1098.yml` — seven documents: the principal-baseline rule (`high`, and the one
  reproduced in the playbook because it is the one that fires on the canonical backdoor),
  the policy-control/full-service grant rule (`high`), two `informational` base rules, a
  `temporal_ordered` "grant then read" correlation grouped by secret (`high`), the
  `PublicPolicyException` rule (`medium`), and `ValidateResourcePolicy` recon (`medium`).
- `kql_t1098.kql` — the same signals in Sentinel dialect, plus the cross-account read
  proof (`UserIdentityAccountId != RecipientAccountId`, visible only in the secret
  owner's trail).

Sibling notes sharing traps: `../../lambda.persistence.resource-policy-backdoor/` and
`../../_superseded/aws.exfiltration.s3-bucket-public-exposure/` for the same document-shape guards;
`../../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/`
for what happens once the grant is used.

Full response procedure is in `../PLAYBOOK.md`.
