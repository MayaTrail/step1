# Detection Note — T1552.007 (Retrieve SSM Parameters from the Parameter Store)

**Signal:** `ssm:GetParameters` / `GetParameter` with `withDecryption=true`
across a large number of distinct parameters from one principal.

**`withDecryption` is the discriminator.** A read without it returns metadata;
a read with it returns plaintext credentials. A rule that ignores this field
cannot tell the two apart and will fire on every application config read in the
account. Every rule here filters on it.

**Count parameters, not events.** `GetParameters` is a batch call that decrypts
up to 10 parameters at once, so event-counting understates exposure by up to
10x. The queries expand `requestParameters.names` and count distinct names.

**Include the singular call.** An attacker looping `GetParameter` (one name per
call) evades any `GetParameters`-only rule.

**`DescribeParameters` is context, not a trigger.** Plenty of tooling
enumerates. Use `DescribeParameters` → decrypting `GetParameters` as a
*sequence* signal; never alert on enumeration alone.

**KMS corroboration:** every SecureString decryption drives a `kms:Decrypt`
against the key backing Parameter Store. That gives an independent signal,
useful when SSM events are unavailable or an attacker throttles to stay under
the SSM threshold. Scope the KMS rule's key ARN before deploying — as shipped
it matches broadly and is `level: low` for that reason.

**A Sigma limitation, stated plainly:** counting the size of
`requestParameters.names` *within a single event* is not expressible in Sigma.
There is no `count` value-modifier in the specification — `|count|gte` does not
exist and fails conversion in pySigma for every backend. Treat
`kql_t1552_007.kql` as the real volume detection; the Sigma base rule is the
coarse "a decrypting read happened" signal.

**Error strings:** SSM errors are *not* `Client.`-prefixed the way EC2 errors
are. A denial surfaces as `AccessDeniedException`, and IAM-policy denials can
surface as `AccessDenied` — match both. A missing parameter gives
`ParameterNotFound`. Confirm the exact strings against a real event.

**MITRE note:** T1552.007 is canonically *Unsecured Credentials: Container
API*, which is a poor fit for SSM Parameter Store. The mapping is inherited
from the upstream technique catalogue and is retained for traceability.

**Severity:** the manifest rates this MEDIUM; the IR view is **High** — the
technique discloses live credential plaintext.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1552_007.yml` — three documents: the decryption base rule (`low`),
  the `value_count` volume correlation (`high`), and the KMS corroboration rule
  (`low`, scope the key ARN first).
- `kql_t1552_007.kql` — the deployable volume detection with explicit
  batch/singular normalisation.

Full response procedure is in `../PLAYBOOK.md`.
