# Detection Note — T1530 (S3 Bucket Public Exposure)

**Signal:** an S3 bucket becomes readable by principals outside the account — through a
bucket policy Allowing a wildcard principal, an ACL granting the `AllUsers` or
`AuthenticatedUsers` predefined group, or the removal of the Block Public Access
configuration that was suppressing one of those.

**Three mechanisms, one outcome, and only one of them emits an obvious event.** Every
other technique in this corpus has a single API whose completion is the compromise. This
one has three, they are independent, and the third — Block Public Access — is a *silence*
rather than a grant. That is the whole reason this playbook exists in the shape it does.

**What the original rules got wrong** — two of the seven match event names CloudTrail
never emits, one alerts on the hardening direction of its own condition, one keys on a
field that is not in the event, one matches every ACL write with no grantee check, and
none of them carries a MITRE mapping. Details below and in `../PLAYBOOK.md` §2.

## Block Public Access overrides both — and removing it grants nothing

AWS states it twice, and both halves matter:

> S3 Block Public Access settings override these policies and permissions so that you can
> limit public access to these resources.

> Block public access settings don't alter existing policies or ACLs. Therefore, removing
> a block public access setting causes a bucket or object with a public policy or ACL to
> again be publicly accessible.

So the state of a bucket is not determined by its most recent policy or ACL event:

| Bucket policy | ACL | Block Public Access | Public? |
|---|---|---|---|
| `Principal:"*"` Allow | private | enabled | **No** |
| `Principal:"*"` Allow | private | deleted | **Yes** |
| none | `AllUsers` READ | enabled | **No** |
| none | `AllUsers` READ | deleted | **Yes** |
| `Principal:"*"` with confining `Condition` | private | disabled | **No** |

Row 2 is the one that matters operationally. The exposure happens on a
`DeleteBucketPublicAccessBlock` — an event with no bucket policy in it, no ACL in it and
no grantee in it. A rule set watching `PutBucketPolicy` sees nothing at all, and the
`PutBucketPolicy` that staged the exposure may be months old and long since dispositioned
as harmless, *because at the time it was*.

The source set rates that event **P3**. GuardDuty rates the equivalent finding
(`Policy:S3/BucketBlockPublicAccessDisabled`, `Policy:S3/AccountBlockPublicAccessDisabled`)
**Low**. Two independent rule sets under-rate the same event, and both do it for the same
reason — the event does not *look* like a grant.

**Account level is not a footnote.** S3 applies "the most restrictive combination of the
access point, bucket, and account settings", so an account-level block protects every
bucket whose own block is absent, and removing it exposes all of them in one call. The
CloudTrail event names are `PutAccountPublicAccessBlock` / `DeleteAccountPublicAccessBlock`
and they must be in the rule alongside the bucket-level pair.

## The GetBucketAcl asymmetry — and it inverts the sweep

> Calls to `GetBucketAcl` and `GetObjectAcl` always return the effective permissions in
> place for the specified bucket or object. For example, suppose that a bucket has an ACL
> that grants public access, but the bucket also has the `IgnorePublicAcls` setting
> enabled. In this case, `GetBucketAcl` returns an ACL that reflects the access permissions
> that Amazon S3 is enforcing, rather than the actual ACL that is associated with the
> bucket.

With `IgnorePublicAcls` enabled the public ACL grant is **invisible to the very read meant
to find it**. The account-wide sweep reports the bucket clean, nothing is remediated, and
the grant goes live the moment Block Public Access is removed — which is this technique's
whole point. An empty `GetBucketAcl` result on a bucket with `IgnorePublicAcls: true` means
*unknown*, not *none*, and a sweep that cannot say which is reporting a false negative.

Two consequences carried into the playbook. Query 3 marks such buckets unknown rather than
clean, and where the ACL is masked the CloudTrail `PutBucketAcl` history is the only record
that the grant exists. And §5's recovery check cannot assert "no public ACL grant" from a
read taken *after* containment re-enabled `IgnorePublicAcls` — that would print a
**false `[OK]`** over a live grant, the worst failure mode available to a verification step.

`GetBucketPolicyStatus` has no documented equivalent. AWS states only that
*"`RestrictPublicBuckets` only applies to buckets that have public policies"*, which makes
policy publicness an **input** to Block Public Access enforcement rather than an output of
it. That is an argument from the enforcement model, not a documented statement that the
policy-status API is unmasked.

## Event names: the API operation name is not the eventName

This is the defect that costs the most and shows the least.

| API operation | CloudTrail eventName (bucket) | CloudTrail eventName (account) |
|---|---|---|
| `PutPublicAccessBlock` | `PutBucketPublicAccessBlock` | `PutAccountPublicAccessBlock` |
| `DeletePublicAccessBlock` | `DeleteBucketPublicAccessBlock` | `DeleteAccountPublicAccessBlock` |
| `GetPublicAccessBlock` | `GetBucketPublicAccessBlock` | `GetAccountPublicAccessBlock` |

AWS says it plainly: *"The CloudTrail event names differ from the API action name. For
example, DeletePublicAccessBlock is DeleteAccountPublicAccessBlock."* Two source rules
key on the operation name. They match nothing, forever, and the queue they feed reads as
an absence of the event rather than an absence of the rule.

## The IAM policy-document idiom does not carry over

The sibling IAM playbooks match `requestParameters.policyDocument` with `|contains`
because CloudTrail records it as a **JSON string**. S3 is different, and verified
different:

```
IAM   requestParameters.policyDocument   ->  "{\"Version\":\"2012-10-17\",...}"   (string)
S3    requestParameters.bucketPolicy     ->  { "Version": "2012-10-17", ... }      (object)
```

Three consequences. There is nothing to percent-decode and nothing to `fromjson` — the
document is already walkable, and carrying the IAM decode step over yields null. Field
paths reach inside it (`requestParameters.bucketPolicy.Statement.Principal.AWS`), so
matching is per-*field*, not per-substring. And because the object flattens to
multi-valued fields, a match across a multi-statement policy cannot prove that the
`Allow`, the wildcard `Principal` and the absent `Condition` belong to the same
statement — that needs the parse in `kql_t1530.kql` or Query 2 of the playbook.

The `Statement`-object-or-array, `Principal`-object-or-bare-`"*"` and
`Action`-string-or-array shape guards are the same ones documented in
`../../../iam.persistence.role-trust-backdoor/detections/detection_note_t1098_001.md`,
which parses trust policies with identical shape hazards; both dialects here carry them.
`tools/decode_policy_documents.py` gained a `--mode s3-bucket-policy` for this technique,
carrying S3's fixed-value requirement, the `s3:DataAccessPointArn` carve-out, the RFC1918
exclusion on `aws:SourceIp`, and by-name reporting of condition keys it does not recognise.
Its `auto` mode, which the IAM playbooks call, is unchanged and regression-checked.

## The Condition is the discriminator, not the Principal

`Principal:"*"` alone does not mean public — and the evaluation starts from the opposite
presumption to the one a reader expects. AWS: *"When evaluating a bucket policy, Amazon S3
begins by assuming that the policy is public. It then evaluates the policy to determine
whether it qualifies as non-public."* To qualify, a policy must grant access **only to
fixed values** — values containing no wildcard and no IAM policy variable — of one or more
of a set of condition keys.

**That set is an open category, not a closed list, and hard-coding it as one is its own
defect.** AWS's first entry is a category given by a single example: *"An AWS principal,
user, role, or service principal (e.g. `aws:PrincipalOrgID`)"*. The remainder is
enumerated: `aws:SourceIp` as CIDR blocks, `aws:SourceArn`, `aws:SourceVpc`,
`aws:SourceVpce`, `aws:SourceOwner`, `aws:SourceAccount`, `aws:userid`,
`s3:DataAccessPointArn`, `s3:DataAccessPointAccount`. `aws:PrincipalArn` and
`aws:PrincipalAccount` sit plainly inside that first category, but AWS does not name them —
so a detector hard-coding twelve key names diverges from S3's evaluator on any other
principal-scoping key. Report an unrecognised key by name instead of treating it as
confining; that is the direction that fails closed.

Four qualifiers, each of which inverts a naive reading:

- **The fixed-value requirement.** A listed key is not enough — the *value* must be fixed.
  `{"StringLike": {"aws:SourceVpc": "vpc-*"}}` is public;
  `{"StringEquals": {"aws:SourceVpc": "vpc-91237329"}}` is not.
- **`aws:userid` counts only outside the pattern `AROLEID:*`.** The role-session form names
  no particular session and does not confine.
- **`s3:DataAccessPointArn` is the documented exception to the fixed-value rule — and only
  for a bucket policy.** AWS: *"a bucket policy that grants access to values of
  `s3:DataAccessPointArn` that match `arn:aws:s3:us-west-2:123456789012:accesspoint/*` is
  not considered public. However, the same statement in an access point policy would render
  the access point public."* Never carry that carve-out over to an access point policy.
- **`aws:SourceIp` confines only if the range is narrow.** AWS: *"This includes values
  broader than `/8` for IPv4 and `/32` for IPv6 (excluding RFC1918 private ranges)."* So
  `0.0.0.0/0` under an `IpAddress` operator is a public policy wearing a condition block.

A `Condition` on a key S3 does not accept — `s3:prefix`, `aws:SecureTransport` — confines
nothing; reading "has a Condition" as "confined" disposes a live exposure. And the unit of
judgement is the document, not the statement: AWS's worked example concludes *"This is
because statement 3 renders the entire policy public, so `RestrictPublicBuckets` applies."*
One public statement contaminates the whole policy, so a confined statement sitting beside
a public one is no defence.

## AuthenticatedUsers is public

S3's test is group membership, not the name of the canned ACL: *"Amazon S3 considers a
bucket or object ACL public if it grants any permissions to members of the predefined
`AllUsers` or `AuthenticatedUsers` groups."* So **three** of the four canned ACLs
`PutBucketAcl` accepts are public, and one of the three does not carry the `public-`
prefix. A detector keying on that prefix misses `authenticated-read`.

AWS describes the group in body text:

> This group represents all AWS accounts. Access permission to this group allows any AWS
> account to access the resource. However, all requests must be signed (authenticated).

and separately, in a `Warning` admonition on the same page:

> When you grant access to the Authenticated Users group, any AWS authenticated user in
> the world can access your resource.

Those are two distinct blocks with two body sentences between them; they cannot be quoted
as one continuous passage. An AWS account is free to open, so treating `AuthenticatedUsers`
as a lesser finding than `AllUsers` buys the attacker one signup form. Both URIs, exactly:

```
http://acs.amazonaws.com/groups/global/AllUsers
http://acs.amazonaws.com/groups/global/AuthenticatedUsers
http://acs.amazonaws.com/groups/s3/LogDelivery        <- NOT public; do not match this one
```

They are punctuated, so **KQL must use `contains`, not `has`** — `has` is whole-term and
breaks on `://` and `/`. Sigma `|contains` is substring and is safe.

`PutBucketAcl` carries the grant in **one of three mutually exclusive request shapes**:

| Shape | Where the grant appears |
|---|---|
| Canned header | `requestParameters['x-amz-acl']`. Exactly four values — *"private \| public-read \| public-read-write \| authenticated-read"* — not the eight in the user guide's canned-ACL table, which also covers object ACLs |
| XML body | `requestParameters.AccessControlPolicy.AccessControlList.Grant[].Grantee.URI` |
| Grant headers | `x-amz-grant-read`, `-write`, `-read-acp`, `-write-acp`, `-full-control` — five of them — each naming a grantee as `uri=`, `id=` or `emailAddress=` |

AWS: *"You cannot specify access permission using both the body and the request headers"*,
and *"You can use either a canned ACL or specify access permissions explicitly. You cannot
do both."* The third shape is not a corner case: AWS's own worked example makes a bucket
world-readable with `x-amz-grant-read: uri="http://acs.amazonaws.com/groups/global/AllUsers"`
and no canned ACL and no body. **A parser checking two shapes is blind to the third**, and
the third is the one AWS publishes a world-readable example for. Both dialects here match
all three.

Two caveats on that third shape. The header names are documented on the `PutBucketAcl` API
reference, but the key CloudTrail writes a request header under in `requestParameters` is
**not** documented by AWS — not for `x-amz-grant-*` and not for `x-amz-acl` either — so
confirm the exact key against a real event before deploying. And `emailAddress=` grantees
were discontinued on 2025-10-01 and now return HTTP 405, which makes that grantee form a
historical-evidence concern rather than a live grant route.

## "Was it used" — the answer is usually that you cannot know

**`s3:GetObject` is a data-plane event.** `aws cloudtrail lookup-events` returns zero for
it, always, and CloudTrail does not log data events by default. Presenting that zero as
"no exfiltration" is the single worst error available in this playbook.

Three sources can record a read of a public object. **None is enabled by default:**

| Source | Turned on by | Records anonymous reads | Caveat |
|---|---|---|---|
| S3 server access logs | `PutBucketLogging` | **Yes**, with source IP | Best-effort; "within a few hours"; "might not be delivered at all" |
| CloudTrail data-event trail | Advanced event selector on `AWS::S3::Object` | Yes | Charged per event; only covers buckets it was configured for |
| CloudWatch `AWS/S3` request metrics | A per-bucket metrics configuration | Counts only, no identity | `BytesDownloaded` / `GetRequests`; daily *storage* metrics are always on and are a different thing |

If none of the three covered the bucket before the exposure window opened, the read record
does not exist and cannot be reconstructed. That is why
`s3_server_access_logging_disabled` ships in this file at `medium` rather than being left
to a logging playbook: disabling server access logging **before** opening a bucket is what
makes the question permanently unanswerable, and it is the one preparatory step this
technique has.

## Response levers

**`GetBucketPolicyStatus` is the best available answer to the policy question — and its
scope is an INFERENCE, not a citation.** It returns `PolicyStatus.IsPublic`: *"The policy
status for this bucket. `TRUE` indicates that this bucket is public. `FALSE` indicates that
the bucket is not public."* It applies S3's own fixed-values rule, so it resolves the
`Condition` argument that no substring rule can. But the API page's entire substantive text
is that element plus two sentences; it **never** says the operation evaluates the bucket
policy alone and **never** says it ignores ACLs, and it links to "The meaning of public",
which defines publicness for policies *and* ACLs. The policy-scoped reading rests on the
operation's name. Word it that way, and read it together with `get-public-access-block`
(bucket **and** account) and `get-bucket-acl`, which is what Recovery in the playbook does.

The page also has **no Errors section at all**, so what the API does for a bucket carrying
no policy is undocumented — do not build an assertion on `NoSuchBucketPolicy` being thrown.
Both dialects here fold an absent result and a failed call into the same `no-policy` value
rather than depending on which occurred. The combined evaluation exists as AWS Config
`S3_BUCKET_PUBLIC_READ_PROHIBITED`, which explicitly *"checks the Block Public Access
settings, the bucket policy, and the bucket access control list (ACL)"* — deploy that as
the standing control.

**Containment is `put-public-access-block`, not policy deletion.** Re-enabling the block
suppresses the policy route and the ACL route at once, without destroying the evidence of
what the policy said. Bucket-level first: AWS documents account-level settings as applying
globally but says *"The settings might not take effect in all Regions immediately or
simultaneously, but they eventually propagate to all Regions"*, and documents no such
propagation caveat at bucket level.

**Bucket policies are not versioned.** `DeleteBucketPolicy` and an overwriting
`PutBucketPolicy` both destroy the previous document, and S3 keeps no copy. The only
record of what a bucket policy said is the `requestParameters.bucketPolicy` of the
`PutBucketPolicy` event that wrote it. Capture before remediating — the same ordering, and
the same reason, as the unversioned inline-policy case in
`../../../iam.privilege-escalation.inline-policy-grant/detections/detection_note_t1098_003.md`.

**Error strings:** denials are `AccessDenied` — not `Client.`-prefixed like EC2. A
`PutBucketPolicy` refused because `BlockPublicPolicy` is enabled surfaces as an
`AccessDenied` whose message names the setting; that is a *blocked attempt* and is worth
its own low-priority queue, because it is an actor trying and failing to make a bucket
public. Codes these calls throw that are **not** denials and must not be counted as
probing: `NoSuchBucket`, `NoSuchBucketPolicy`, `MalformedPolicy`, `InvalidPolicyDocument`,
`InvalidRequest`, and `AccessControlListNotSupported` — the last returned when Object
Ownership is `BucketOwnerEnforced`, which disables ACLs entirely and is the structural fix
for the ACL route.

**The oversized-document evasion does not apply here.** A content rule can normally be
defeated by padding the document past CloudTrail's field limit: *"This field has a maximum
size of 100 KB. When the field size exceeds 100 KB, the `requestParameters` content is
omitted."* Note **omitted**, not truncated — the whole field goes, leaving no partial
artifact. An S3 bucket policy is capped at **20 KB** (*"Bucket policies are limited to 20 KB
in size."*) and an ACL at *"up to 100 grants"*, so neither can approach that threshold. No
companion rule for a missing `requestParameters` ships in this file, and that is a decision
rather than an oversight.

**MITRE:** the source alerts carry **no** ATT&CK mapping at all — not an imprecise one,
none. The files here map **T1530 (*Data from Cloud Storage*, Collection / TA0009)**, which
describes the objective the exposure serves. Two nuances worth stating rather than
smoothing over: T1530's canonical tactic is *Collection*, not Exfiltration, even though
the directory is named for the exfiltration outcome; and the Block Public Access removal is
as much **T1685 (*Disable or Modify Tools*)** as it is T1530, because what it does is disable a
preventive control. Both tags are carried on `s3_public_access_block_removed`. The
logging-disable rule carries **T1685.002 (*Disable or Modify Cloud Logs*)**.

**Severity:** the source set rates these P2/P3/P4 — the Block Public Access deletion P3,
the bucket-policy deletion P4, the ACL write P3. The IR view is **High**, P0 for any
change that leaves a bucket effectively public and P0 for the Block Public Access removal
specifically. There is no exploitation stage after the call: the bucket is on the internet
from the moment it returns 200, automated scanners find open buckets within minutes, and
every object read in that window is gone irreversibly. A P3 routes that to a queue nobody
reads overnight.

**GuardDuty:** `Policy:S3/BucketAnonymousAccessGranted` (High) and
`Policy:S3/BucketPublicAccessGranted` (High) fire on the policy and ACL routes from
CloudTrail **management** events, using automated reasoning rather than pattern matching —
genuinely stronger than any rule in this file at answering "is it public". But AWS states
of each that *"This finding will not reflect any S3 Block Public Access settings that may
have been enabled for your S3 bucket. In such cases, the `effectivePermission` value in the
finding will be marked as `UNKNOWN`."* So they cannot distinguish a staged-but-blocked grant
from a live one — and the two findings that do cover the block,
`Policy:S3/BucketBlockPublicAccessDisabled` and `Policy:S3/AccountBlockPublicAccessDisabled`,
are rated **Low**. Deploy GuardDuty and re-prioritise those two locally; do not treat it
as covering the third mechanism at the severity that mechanism deserves.

**Files here:**
- `sigma_t1530.yml` — seven documents: the bucket-policy wildcard-principal rule (`high`),
  the public-ACL rule (`high`, matching all three `PutBucketAcl` request shapes), the Block
  Public Access removal rule covering bucket and account level (`high`), two `temporal`
  correlations at `critical` — one per grant route, because a correlation with no explicit
  `condition:` requires **all** its listed rules to match, so naming both grant routes in one
  would fire only if an actor used both — the server-access-logging disable (`medium`), and
  the bucket-policy deletion (`medium`). The correlations are `temporal` and not
  `temporal_ordered` because both orderings occur and each is a completed exposure: a grant
  staged under a suppressing setting and later unblocked, and a grant refused by the block,
  unblocked, then retried. Where Block Public Access was already absent there is no second
  event and no correlation can fire — the `high` base rules are the whole signal, and must
  not be demoted or gated behind the correlations.
- `kql_t1530.kql` — all three routes unioned, with the statement-level parse of the nested
  `bucketPolicy` object and the Condition test the Sigma rules cannot express.
- The decoder is shared tooling: `tools/decode_policy_documents.py --mode s3-bucket-policy`,
  used by Query 2 of the playbook.

Full response procedure is in `../PLAYBOOK.md`.
