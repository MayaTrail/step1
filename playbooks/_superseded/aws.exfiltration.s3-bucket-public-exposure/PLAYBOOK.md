# IR Playbook: S3 Bucket Public Exposure — Internet-Readable Storage via `s3:PutBucketPolicy`, `s3:PutBucketAcl` or `s3:DeleteBucketPublicAccessBlock`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data exposure / Collection (a bucket and every object in it become readable by principals outside the account) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | **High**, P0 for any change that leaves a bucket effectively public. There is no exploitation stage after the call: the bucket is on the internet from the moment it returns 200, open-bucket scanning is continuous and automated, and every object read in the window is disclosed irreversibly — no containment step recalls a byte already served. The source alerts rate the Block Public Access deletion **P3**, the bucket-policy deletion **P4** and the ACL write **P3**, which routes a live data exposure to a queue nobody reads overnight. That disposition is the single change most worth making before any rule logic is touched, and it is not an isolated judgement: GuardDuty rates the same block-removal event **Low** while rating the policy and ACL grants **High**, so two independent rule sets under-rate the same event for the same reason — it does not *look* like a grant |
| MITRE Tactics | Collection, Exfiltration, Defense Impairment |
| MITRE Techniques | T1530 (T1685 for the Block Public Access removal, T1685.002 for the logging disable) |
| Services in Scope | S3, S3 Control (account-level Block Public Access), CloudTrail, CloudWatch, IAM, Organizations (SCP), AWS Config, IAM Access Analyzer, GuardDuty |

**What the technique does:** the actor makes a bucket readable from outside the account by one
of three independent routes. `s3:PutBucketPolicy` with an `Allow` whose `Principal` is `"*"` or
`{"AWS":"*"}` — one call, effective immediately, no approval path. `s3:PutBucketAcl` granting a
permission to the `AllUsers` or `AuthenticatedUsers` predefined group, by any of its three
mutually exclusive request shapes — a canned `x-amz-acl`, an XML grant carrying the group's
URI, or an `x-amz-grant-*` header naming the group by `uri=`. Or — the route that matters —
`s3:DeletePublicAccessBlock` on a bucket or the whole account, which grants nothing and yet
exposes everything a previously-written public policy or ACL was already asking for.

**Why this is potent, and why the usual reflexes miss it.** Block Public Access
**overrides** a public bucket policy and a public ACL, and removing it **does not touch
either**. AWS: *"Block public access settings don't alter existing policies or ACLs.
Therefore, removing a block public access setting causes a bucket or object with a public
policy or ACL to again be publicly accessible."* So the natural reflex — read the bucket
policy events — fails twice over: there is no policy event in the exposure window, because
the policy was written earlier and correctly dispositioned as harmless at the time, and the
`PutBucketPolicy` you eventually find says nothing about whether the bucket is public *now*.
The second reflex, `lookup-events` for `GetObject`, returns zero — not because nothing was
read, but because object reads are **data-plane** and CloudTrail does not log them by
default.

**The bucket is effectively public, and that is a state, not an event.** The discriminator
is `GetBucketPolicyStatus.IsPublic` true, or an ACL granting a global group, or a Block
Public Access configuration that no longer blocks — with no confining `Condition` pinning
the grant to fixed values. The source alerts reach for this through event names and get two
of them wrong: they match `DeletePublicAccessBlock` and `PutPublicAccessBlock`, which are
**API operation** names, while CloudTrail emits `DeleteBucketPublicAccessBlock` and
`PutBucketPublicAccessBlock` (§2). Those rules match nothing, forever.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail capturing S3 **management** events. These are **regional** — a
  bucket's `PutBucketPolicy` lands in the bucket's Region and an account-level Block Public
  Access call wherever the caller addressed the S3 Control endpoint, so sweep every Region you
  operate in rather than pinning `us-east-1` as you would for IAM
- `PutBucketPolicy` carries `requestParameters.bucketName` and `.bucketPolicy` — a **nested
  JSON object**, not the JSON string IAM's `.policyDocument` is; nothing to percent-decode
  and nothing to `fromjson`, so the IAM idiom does not carry over
- `PutBucketAcl` carries the grant in **one of three mutually exclusive shapes**:
  `requestParameters['x-amz-acl']` (four accepted values, three of them public — the fourth,
  `authenticated-read`, has no `public-` prefix); `...AccessControlList.Grant[].Grantee.URI`;
  or one of five `x-amz-grant-*` headers naming the group by `uri=`. `Put*PublicAccessBlock`
  carries `requestParameters.PublicAccessBlockConfiguration.` plus the four booleans. All of
  these return **`responseElements: null`** — the whole event is in the request
- **A CloudTrail data-event trail, or S3 server access logging, on every bucket holding
  sensitive data.** `s3:GetObject` is data-plane; without one, "was anything read" has no
  answer and cannot acquire one later. Server access logs are the only source recording
  **anonymous** reads with a source IP — best-effort, and AWS states a record "might not be
  delivered at all"
- AWS Config `S3_BUCKET_PUBLIC_READ_PROHIBITED`, the only evaluation that *"checks the Block
  Public Access settings, the bucket policy, and the bucket access control list (ACL)"*
  together, plus GuardDuty S3 Protection

**Alerting (must be pre-configured)**
- **Block Public Access deleted, or written with any of its four settings false, at bucket or account level → P0**
- **A bucket policy `Allow` whose `Principal` carries a wildcard, with no confining `Condition` → P0**
- **A bucket ACL granting `AllUsers` or `AuthenticatedUsers`, by grantee URI, by a public canned `x-amz-acl` (including `authenticated-read`), or by an `x-amz-grant-*` header → P0**
- **One principal writing a public policy or ACL and removing Block Public Access within 24 hours, in either order → P1**
- **`GetBucketPolicyStatus.IsPublic` true for a bucket not on the public-by-design allowlist → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under
  investigation; `jq`; `python3` and the kit's
  `tools/decode_policy_documents.py --mode s3-bucket-policy` for the statement-level parse
- An out-of-account evidence location — bucket policies are **not versioned**, so the
  document you overwrite is gone

**Known IOC Baselines**
- The **public-by-design allowlist**: every bucket deliberately internet-readable, with the
  ticket that authorised it. Without it every finding needs adjudicating from scratch
- Which principals may call `s3:PutBucketPolicy`, `s3:PutBucketAcl` and
  `s3:PutBucketPublicAccessBlock` — in most accounts one IaC role and one break-glass role
- Your account ID, every account ID in the organisation, and your `aws:PrincipalOrgID`, so a
  `Principal` or `Condition` value naming an outsider is recognisable on sight

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `DeleteBucketPublicAccessBlock` / `DeleteAccountPublicAccessBlock`, or `Put*PublicAccessBlock` with any of the four settings `false` | CloudTrail (management) | T1530, T1685 |
| P0 | `PutBucketPolicy` whose `Allow` statement carries a wildcard `Principal` and no confining `Condition` | CloudTrail (management) | T1530 |
| P0 | `PutBucketAcl` granting `AllUsers` / `AuthenticatedUsers` by grantee URI, by a public canned `x-amz-acl` (including `authenticated-read`), or by an `x-amz-grant-*` header | CloudTrail (management) | T1530 |
| P1 | One principal writes a public policy or ACL and removes Block Public Access within 24 hours, in either order | CloudTrail (management) | T1530 |
| P1 | `GetBucketPolicyStatus.IsPublic` true for a bucket not on the public-by-design allowlist | AWS Config / scheduled state check | T1530 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `PutBucketLogging` with no `LoggingEnabled` element — server access logging turned off | CloudTrail (management) | T1685.002 |
| P2 | `DeleteBucketPolicy` where the deleted document carried an explicit `Deny` | CloudTrail (management) | T1530 |
| P2 | `PutBucketPolicy` denied with `AccessDenied` naming `BlockPublicPolicy` — an attempt to make a bucket public that the block refused | CloudTrail (management) | T1530 |

### Detection Rule Quality Notes

Two of the seven source rules match event names CloudTrail does not emit, one inverts its own
condition, one keys on a field that is not in the event, and one matches every ACL write blind.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `eventName:"DeletePublicAccessBlock"` (P3) and `eventName:"PutPublicAccessBlock"` (P4), and the second rule's condition `NOT (RestrictPublicBuckets:false OR BlockPublicPolicy:false OR BlockPublicAcls:false OR IgnorePublicAcls:false)` | Those are **API operation** names; CloudTrail emits `Delete`/`PutBucketPublicAccessBlock` at bucket level and `Delete`/`PutAccountPublicAccessBlock` at account level, a difference AWS documents explicitly. Both rules match nothing, forever, and the empty queue reads as an absence of the event rather than of the rule — for the event that most often turns a latent misconfiguration into a live exposure. Even with the name corrected, that condition fires only when **none** of the four is false: it alerts on somebody turning protection *on* and is silent when they turn it off. Its `eventSource:"s3.amazonaws.com"AND` also lacks whitespace before the operator, so whether it parses depends on the engine | Match all four CloudTrail event names, at bucket **and** account level — S3 takes the most restrictive combination of the two, so an account-level removal exposes every bucket relying on it. Alert when **any** of the four settings is `false`, ORed and never ANDed; treat all-four-true as an informational configuration record |
| `requestParameters.bucketPolicy.bucket_made_public:true` (P2) | Not a field CloudTrail writes. The verified `requestParameters` for `PutBucketPolicy` is `{Host, bucketName, bucketPolicy, policy}`, where `bucketPolicy` is the nested policy object. The one rule claiming to detect a public bucket policy depends either on a platform enrichment — doing nothing wherever that enrichment is absent — or on nothing at all. It carries no `errorCode` filter, so a denied attempt scores identically to a completed exposure | Read the document structurally: an `Allow` whose `Principal` carries a wildcard, absent a `Condition` on a key S3 accepts as making the policy non-public. Filter to `errorCode: null`; split denials into their own low-priority queue |
| `eventName:"PutBucketAcl"` with no grantee inspection (P3), and `AuthenticatedUsers` in no rule at all | Fires on every ACL write including `--acl private` and log-delivery grants, so the dominant benign case shares a priority with granting `AllUsers` READ, and a rule firing on the remediation as loudly as on the exposure gets muted within a week. Meanwhile the set never mentions `AuthenticatedUsers`, of which AWS warns *"When you grant access to the Authenticated Users group, any AWS authenticated user in the world can access your resource"* — and an AWS account is free to open, so treating it as a lesser case buys the attacker one signup form | Require an `AllUsers` **or** `AuthenticatedUsers` grantee, at the same level, keyed on group membership rather than the `public-` prefix: S3 *"considers a bucket or object ACL public if it grants any permissions to members of the predefined `AllUsers` or `AuthenticatedUsers` groups"*, so `authenticated-read` is public too. Match **all three** request shapes — canned header, XML body, `x-amz-grant-*` headers; covering fewer gives a false-negative rate set by how the operator invoked the API, and AWS's own worked example uses the third. `s3/LogDelivery` deliberately excluded — it is not public |
| `eventName:"putbucketlogging"`, lowercased (P2) | CloudTrail emits `PutBucketLogging`. On a keyword-mapped field this matches nothing; on an analysed field it matches. A rule whose firing depends on the index mapping of one field is not a rule | Exact casing. The `NOT _exists_` test on `BucketLoggingStatus.LoggingEnabled` is otherwise correct — the disable really is expressed as that element's absence |
| No rule ties the three mechanisms together, and none carries a MITRE mapping | A bucket with a `Principal:"*"` policy under an enabled block is **not** public and correctly does not alert; the same bucket becomes public on a later block removal with no policy event at all. Nothing connects the two, so the staged exposure is invisible as a sequence | Two `temporal` correlations grouped by `userIdentity.arn` at `critical` — one per grant route, kept separate because a correlation with no explicit `condition:` requires **all** its listed rules to match, so one naming both routes would fire only if an actor used both. `temporal`, not `temporal_ordered`: a grant can be staged under a suppressing setting and unblocked later, or refused by the block, unblocked and retried, and both orders end in a public bucket. Where the block was already absent no second event exists and the `high` base rules are the whole signal — plus the standing state check on `GetBucketPolicyStatus`. All rules tagged `attack.t1530`, with `attack.t1685` on the block removal |

**Recommended detection — a bucket policy granting a wildcard principal.**

```yaml
# S3 Bucket Public Exposure (T1530)
#
# Public read reaches a bucket by three routes and the source rules cover one of them
# badly. Two of the seven rules match event names CloudTrail does not emit: the API
# operations are PutPublicAccessBlock / DeletePublicAccessBlock, but the CloudTrail
# eventNames are PutBucketPublicAccessBlock / DeleteBucketPublicAccessBlock at bucket
# level and PutAccountPublicAccessBlock / DeleteAccountPublicAccessBlock at account
# level. A rule keyed on the API name never fires. The rule that does carry a correct
# name inverts its own condition and alerts on the HARDENING direction. The bucket-policy
# rule keys on `requestParameters.bucketPolicy.bucket_made_public`, which is not a field
# CloudTrail writes. The ACL rule matches every PutBucketAcl by name with no grantee
# check at all.
#
# The distinguishing property of this technique: Block Public Access OVERRIDES both a
# public bucket policy and a public ACL, and removing it does not touch either. So a
# bucket carrying a `Principal:"*"` policy under an enabled PAB is not public, and the
# same bucket becomes public the instant DeleteBucketPublicAccessBlock runs — with no
# policy or ACL event in that window. Any rule set that watches only PutBucketPolicy
# misses the most common real exposure. The three rules below cover all three routes and
# two `temporal` correlations tie the grant to the unblock in EITHER order, because both
# orders occur and each is a completed exposure.
#
# What these rules CANNOT do: prove that an Allow, a wildcard Principal and the absence
# of a Condition sit in the SAME statement — CloudTrail records bucketPolicy as a nested
# object, so a multi-statement policy flattens to multi-valued fields and the match is
# per-document, not per-statement. A Condition confining the policy to fixed values of
# the keys S3 accepts makes a `Principal:"*"` policy non-public. Treat a hit as the
# trigger for the decode in `kql_t1530.kql` or Query 2 of the playbook, not as a
# disposition.
#
# And they cannot be checked against current state by reading the ACL back. AWS: "Calls to
# GetBucketAcl and GetObjectAcl always return the effective permissions in place for the
# specified bucket or object... In this case, GetBucketAcl returns an ACL that reflects the
# access permissions that Amazon S3 is enforcing, rather than the actual ACL that is
# associated with the bucket." So with IgnorePublicAcls enabled a public ACL grant is
# INVISIBLE to the read that is meant to find it, and goes live the moment the block is
# removed. The CloudTrail PutBucketAcl event is then the only record that the grant exists.
# See `detection_note_t1530.md`.
title: S3 bucket policy granting a wildcard principal
id: 3f8b2c17-9d4a-4e61-8b05-c7a1e2f60d93
name: s3_bucket_policy_public_principal
status: experimental
description: >-
  A bucket policy was written whose Allow statement names a wildcarded principal. Under
  S3's own definition a policy is non-public only when it grants to fixed values, so any
  wildcard in Principal makes the bucket public unless a confining Condition applies.
references:                                                                       # retrieved 2026-08-27
  - https://attack.mitre.org/techniques/T1530/
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html
tags:
  - attack.collection
  - attack.t1530
  - attack.exfiltration
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName: 'PutBucketPolicy'
  allow_effect:
    requestParameters.bucketPolicy.Statement.Effect: 'Allow'
  # `\*` is an ESCAPED literal asterisk; a bare `*` is a Sigma wildcard and would match every
  # policy ever written. `|contains` is deliberate — AWS treats a principal that is not a FIXED
  # value as public, so `arn:aws:iam::*:root` counts too. Principal is the bare string "*" OR
  # the object {"AWS":"*"}: different flattened paths that cannot co-occur in one statement, so
  # sibling blocks ORed in the condition, never two keys in one block.
  principal_bare:
    requestParameters.bucketPolicy.Statement.Principal|contains: '\*'
  principal_aws:
    requestParameters.bucketPolicy.Statement.Principal.AWS|contains: '\*'
  success:
    errorCode: null
  condition: selection and allow_effect and (principal_bare or principal_aws) and success
falsepositives:
  - A deliberately public static-website or public-dataset bucket; filter those names once
    they are on the allowlist.
  - A policy confined by a Condition on a key S3 accepts as making it non-public, pinned to
    a FIXED value — one carrying no wildcard and no IAM policy variable. AWS gives that set
    as an OPEN category ("An AWS principal, user, role, or service principal (e.g.
    aws:PrincipalOrgID)") plus aws:SourceArn, aws:SourceVpc, aws:SourceVpce, aws:SourceOwner,
    aws:SourceAccount, aws:userid outside AROLEID:*, s3:DataAccessPointArn,
    s3:DataAccessPointAccount and aws:SourceIp at /8 or narrower excluding RFC1918 ranges.
    Do not hard-code that as a closed key list. Also a multi-statement policy whose Allow and
    wildcard Principal sit in different statements — though one public statement renders the
    whole policy public, so a confined statement beside a public one is no defence. All are
    invisible to a field match; the rule over-matches rather than under-matches and the
    decode resolves it.
level: high
---
# The ACL route. Independent of the policy route and of Block Public Access removal: a
# bucket with no policy at all is public the moment an ACL grants AllUsers READ.
#
# AuthenticatedUsers is included deliberately and is NOT a lesser case. S3's own test is
# group membership, not the name of the canned ACL: "Amazon S3 considers a bucket or
# object ACL public if it grants any permissions to members of the predefined AllUsers or
# AuthenticatedUsers groups." So a detector keyed on the `public-` PREFIX misses
# authenticated-read, which grants READ to AuthenticatedUsers. AWS body text on that
# group: "This group represents all AWS accounts. Access permission to this group allows
# any AWS account to access the resource. However, all requests must be signed
# (authenticated)." And, in a separate Warning admonition on the same page: "When you
# grant access to the Authenticated Users group, any AWS authenticated user in the world
# can access your resource." An AWS account is free to create, so the practical exposure
# is the same as AllUsers with one extra step.
#
# PutBucketAcl carries the grant in ONE OF THREE mutually exclusive request shapes:
#   1. the canned header requestParameters['x-amz-acl'];
#   2. the XML body under AccessControlPolicy.AccessControlList.Grant[].Grantee.URI;
#   3. explicit x-amz-grant-* headers naming a grantee as `uri=`, `id=` or
#      `emailAddress=` — five of them: -read, -write, -read-acp, -write-acp,
#      -full-control.
# AWS: "You cannot specify access permission using both the body and the request headers",
# and "You can use either a canned ACL or specify access permissions explicitly. You
# cannot do both." Shape 3 is not a corner case: AWS's own worked example makes a bucket
# world-readable with it and no canned ACL and no body —
#   x-amz-grant-read: uri="http://acs.amazonaws.com/groups/global/AllUsers"
# A rule checking two shapes is blind to the third. All three are matched, as sibling
# blocks ORed in the condition.
#
# CAVEAT on shape 3, and it is the reason this block is worth reading before deploying:
# the five header NAMES are from the PutBucketAcl API reference, but the key CloudTrail
# writes them under in requestParameters is not documented by AWS for any request header,
# including x-amz-acl. Confirm the exact key against a real PutBucketAcl event in your own
# trail and adjust if it differs. The field paths here are the header names verbatim.
#
# The URIs are punctuated (scheme, slashes) — this is `|contains`, which is substring in
# Sigma. The KQL companion uses `contains` for the same reason; `has` is whole-term and
# would never match them.
title: S3 bucket ACL granting a public predefined group
id: 5c1a7e04-2b83-4f57-9a6d-18e0b4c39f27
name: s3_bucket_acl_public_grant
status: experimental
description: >-
  A bucket ACL was written that grants a permission to the AllUsers or AuthenticatedUsers
  predefined group — by grantee URI in the XML body, by a public canned-ACL header, or by
  an explicit x-amz-grant-* header naming the group by uri=. Any of the three makes the
  bucket readable outside the account unless Block Public Access is suppressing ACLs.
references:
  - https://attack.mitre.org/techniques/T1530/                                    # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html       # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html         # retrieved 2026-08-27
tags:
  - attack.collection
  - attack.t1530
  - attack.exfiltration
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName: 'PutBucketAcl'
  acl_grantee_uri:
    requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI|contains:
      - 'acs.amazonaws.com/groups/global/AllUsers'
      - 'acs.amazonaws.com/groups/global/AuthenticatedUsers'
  # x-amz-acl on PutBucketAcl accepts exactly four values — "private | public-read |
  # public-read-write | authenticated-read" — not the eight in the user guide's canned-ACL
  # table, which covers object ACLs and CreateBucket too. THREE of the four are public.
  # Enumerated, never prefix-matched: `public-` would silently drop authenticated-read.
  acl_canned_public:
    'requestParameters.x-amz-acl':
      - 'public-read'
      - 'public-read-write'
      - 'authenticated-read'
  # Shape 3. A LIST of maps is ORed. The five grant headers are independent and a request
  # normally carries one or two, so they must never be ANDed into a single map — that
  # would require all five on one event and the block would never match.
  acl_grant_header:
    - 'requestParameters.x-amz-grant-read|contains':
        - 'acs.amazonaws.com/groups/global/AllUsers'
        - 'acs.amazonaws.com/groups/global/AuthenticatedUsers'
    - 'requestParameters.x-amz-grant-write|contains':
        - 'acs.amazonaws.com/groups/global/AllUsers'
        - 'acs.amazonaws.com/groups/global/AuthenticatedUsers'
    - 'requestParameters.x-amz-grant-read-acp|contains':
        - 'acs.amazonaws.com/groups/global/AllUsers'
        - 'acs.amazonaws.com/groups/global/AuthenticatedUsers'
    - 'requestParameters.x-amz-grant-write-acp|contains':
        - 'acs.amazonaws.com/groups/global/AllUsers'
        - 'acs.amazonaws.com/groups/global/AuthenticatedUsers'
    - 'requestParameters.x-amz-grant-full-control|contains':
        - 'acs.amazonaws.com/groups/global/AllUsers'
        - 'acs.amazonaws.com/groups/global/AuthenticatedUsers'
  success:
    errorCode: null
  condition: selection and (acl_grantee_uri or acl_canned_public or acl_grant_header) and success
falsepositives:
  - None benign that are also unintentional. A public ACL is always a deliberate act;
    the question is whether the actor was authorised, not whether the grant is real.
  - Log-delivery grants use the s3/LogDelivery URI, not the global groups, and do not
    match — in the body, in x-amz-acl, or in an x-amz-grant-write header. AWS's own
    header example carries a LogDelivery grant and an AllUsers grant on the same request;
    only the AllUsers half matches, which is the intended behaviour.
level: high
---
# The Block Public Access route — the one the source set rates P3/P4 and the one that
# most often turns a latent misconfiguration into a live exposure.
#
# AWS: "Block public access settings don't alter existing policies or ACLs. Therefore,
# removing a block public access setting causes a bucket or object with a public policy
# or ACL to again be publicly accessible." No PutBucketPolicy and no PutBucketAcl occurs
# in that window. This is the event.
#
# Account level is covered alongside bucket level. S3 applies "the most restrictive
# combination" of account and bucket settings, so an account-level removal exposes every
# bucket that was relying on it and has no bucket-level block of its own — one call,
# whole-account blast radius.
#
# eventSource carries both values. AWS documents the account-level operations on the
# Amazon S3 CloudTrail events page (so `s3.amazonaws.com`), while the request itself is
# addressed to the S3 Control endpoint. ORing both costs nothing and fails safe;
# confirm which your own trail carries and prune the other.
title: S3 Block Public Access removed or weakened
id: 9e6d0b45-4c72-4a18-b3f9-6d20a5e81c34
name: s3_public_access_block_removed
status: experimental
description: >-
  The S3 Block Public Access configuration was deleted, or written with at least one of
  its four settings false, at bucket or account level. Any existing public bucket policy
  or public ACL becomes effective immediately, with no policy or ACL event of its own.
references:
  - https://attack.mitre.org/techniques/T1530/                                                     # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html   # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html           # retrieved 2026-08-27
tags:
  - attack.collection
  - attack.t1530
  - attack.defense-impairment
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection_delete:
    eventSource:
      - 's3.amazonaws.com'
      - 's3-control.amazonaws.com'
    eventName:
      - 'DeleteBucketPublicAccessBlock'
      - 'DeleteAccountPublicAccessBlock'
  selection_put:
    eventSource:
      - 's3.amazonaws.com'
      - 's3-control.amazonaws.com'
    eventName:
      - 'PutBucketPublicAccessBlock'
      - 'PutAccountPublicAccessBlock'
  # A LIST of maps is ORed. The four settings are independent and any one of them going
  # false weakens the block, so they must never be ANDed into a single map — that is the
  # shape of the source rule's inverted condition, which fires only when none is false
  # and therefore alerts on somebody turning protection ON.
  pab_weakened:
    - requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls: false
    - requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls: false
    - requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy: false
    - requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets: false
  success:
    errorCode: null
  condition: (selection_delete or (selection_put and pab_weakened)) and success
falsepositives:
  - A bucket being deliberately opened for static-website hosting or a public dataset.
    That is a change-managed event with a ticket; treat an unticketed one as an incident.
  - An account bootstrap that sets three of four settings. Alert, then baseline the
    intended combination per account rather than suppressing the rule.
level: high
---
# A completed exposure: one principal both created a public grant and removed the block
# that would have held it. Either half alone is already `high` above; together they are a
# finished job, and there is no configuration in which the pair is an accident.
#
# WHY TWO CORRELATIONS, NOT ONE OVER THREE RULES. A correlation with no explicit
# `condition:` requires ALL of its listed rules to match. One document naming the policy
# rule, the ACL rule and the block-removal rule would therefore fire only if an actor used
# BOTH grant routes AND unblocked — never on the canonical single-route sequence. That is a
# rule that cannot fire, not a strict one. One correlation per grant route.
#
# WHY `temporal` AND NOT `temporal_ordered`. Both orderings occur, and each is a completed
# exposure. Block Public Access is four independent settings, and they split by function:
# BlockPublicAcls and BlockPublicPolicy govern whether a new public grant is ACCEPTED,
# IgnorePublicAcls and RestrictPublicBuckets govern whether an existing one is ENFORCED.
#   * GRANT then UNBLOCK — the bucket had BlockPublicPolicy false and RestrictPublicBuckets
#     true (or BlockPublicAcls false and IgnorePublicAcls true), so the public document was
#     accepted and stored while being suppressed. Removing the enforcing half makes a
#     document written days or months earlier live, with no grant event in that window.
#   * UNBLOCK then GRANT — the bucket had the accepting half enabled, so the first attempt
#     was REFUSED: an AccessDenied naming BlockPublicPolicy, which is the P2 blocked-attempt
#     row in the playbook's own trigger table. The actor removes the block and retries. This
#     ordering is what the block's own enforcement PRODUCES, and `temporal_ordered` in the
#     grant-then-unblock direction is precisely blind to it.
# `temporal` covers both directions in one document. Ordering is not the discriminator here
# — co-occurrence by one principal is — and the exposure time is recovered from Query 1's
# timeline, not from the correlation.
#
# NEITHER CORRELATION IS THE FLOOR. Where Block Public Access was already absent, a single
# grant is live on arrival: one event, no second half, and no correlation can fire. The
# `high` base rules above are the entire signal for that case, which is the common one on an
# account with no account-level block. Do not gate them behind these correlations and do not
# demote them once these are deployed.
#
# Grouped by userIdentity.arn, not by bucket name: an account-level Block Public Access
# removal carries no bucketName, so grouping on the bucket silently drops the whole-account
# case — the worst one. The cost is that the two halves may touch DIFFERENT buckets, which
# is why the playbook rates this P1 and routes it to Query 3 for confirmation rather than
# treating it as a disposition.
#
# 24h timespan, tuning basis: this is not a rate threshold, it is a staging window. The two
# halves are separate deliberate acts and an actor holding both permissions has no reason to
# wait; a legitimate open-a-bucket change lands both inside one change window. 24h is one
# working day — wide enough to survive an approval step between the halves, narrow enough
# that two unrelated changes by one principal rarely collide. Widen it if your change process
# routinely spans days. Derived from technique behaviour, not from an observed baseline;
# baseline against your own account before deploying.
title: S3 bucket policy made public and Block Public Access removed by the same principal
id: b47c9a28-0e51-4d36-95f7-2af6c1038be5
status: experimental
description: >-
  Within 24 hours one principal both wrote a bucket policy granting a wildcard principal
  and removed or weakened Block Public Access, in either order. The block was the only
  thing holding the exposure back; the bucket is public now.
references:
  - https://attack.mitre.org/techniques/T1530/                                                     # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html   # retrieved 2026-08-27
tags:
  - attack.collection
  - attack.t1530
  - attack.exfiltration
correlation:
  type: temporal
  rules:
    - s3_bucket_policy_public_principal
    - s3_public_access_block_removed
  group-by:
    - userIdentity.arn
  timespan: 24h
level: critical
---
# The ACL twin of the correlation above. Separate document for the reason given there: one
# correlation naming both grant routes would require BOTH to have happened. Also `temporal`,
# and the ACL route makes the reverse ordering even plainer — with BlockPublicAcls enabled a
# public PutBucketAcl is refused outright, so unblock-then-grant is the only order available
# to an actor who meets the block first.
title: S3 bucket ACL made public and Block Public Access removed by the same principal
id: e91f36b2-7d58-4c04-a6b3-15c8079de24f
status: experimental
description: >-
  Within 24 hours one principal both granted a bucket ACL to AllUsers or AuthenticatedUsers
  and removed or weakened Block Public Access, in either order. Same completed exposure as
  its policy twin, by the mechanism a bucket-policy rule never sees.
references:
  - https://attack.mitre.org/techniques/T1530/                              # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html  # retrieved 2026-08-27
tags:
  - attack.collection
  - attack.t1530
  - attack.exfiltration
correlation:
  type: temporal
  rules:
    - s3_bucket_acl_public_grant
    - s3_public_access_block_removed
  group-by:
    - userIdentity.arn
  timespan: 24h
level: critical
---
# Not an exposure event — an evidence-destruction event, and it is scoped here because
# server access logs are one of only three places a read of a public object can be
# recorded, and the only one that records ANONYMOUS reads by IP. Disabling it before
# opening the bucket is what makes "was it used" permanently unanswerable.
#
# The disable is expressed as an ABSENCE: PutBucketLogging with a BucketLoggingStatus
# that carries only its xmlns and no LoggingEnabled child. `field: null` in Sigma matches
# when the field is ABSENT, which is exactly the shape needed — this is `and` a null
# match, not `and not`.
title: S3 server access logging disabled on a bucket
id: c02f5d76-8a34-4b90-a1e7-53bd9f2470ac
name: s3_server_access_logging_disabled
status: experimental
description: >-
  PutBucketLogging was called with no LoggingEnabled element, which turns server access
  logging off for the bucket. Object-level reads of that bucket stop being recorded
  anywhere unless a CloudTrail data-event trail also covers it.
references:
  - https://attack.mitre.org/techniques/T1685/002/                              # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html       # retrieved 2026-08-27
tags:
  - attack.defense-impairment
  - attack.t1685.002
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName: 'PutBucketLogging'
  logging_removed:
    requestParameters.BucketLoggingStatus.LoggingEnabled: null
  success:
    errorCode: null
  condition: selection and logging_removed and success
falsepositives:
  - Retiring a bucket, or moving log delivery to a CloudTrail data-event trail. Both are
    ticketed; correlate against the change record rather than suppressing.
level: medium
---
# Deleting a bucket policy usually REDUCES access, which is why the source set rates it
# P4 — and why it is kept at `medium` here rather than promoted. It is in scope for one
# reason: an explicit Deny is also a bucket policy. A policy whose only job was to deny
# non-TLS access, or to fence the bucket to aws:PrincipalOrgID, is the control keeping
# that bucket private, and DeleteBucketPolicy removes it in one call with no record of
# what it said.
#
# Bucket policies are NOT versioned and DeleteBucketPolicy is not reversible from S3. The
# only copy of the deleted document is the requestParameters of the PutBucketPolicy event
# that last wrote it, so this alert's value is that it starts the clock on recovering that
# event before CloudTrail retention ages it out.
title: S3 bucket policy deleted
id: 7a35e918-6c40-42db-8f13-9e04c7d5b6a1
name: s3_bucket_policy_deleted
status: experimental
description: >-
  A bucket policy was deleted. Where that policy carried an explicit Deny — non-TLS
  access, an organisation fence, a public-access guard — its removal widens access, and
  the deleted document is recoverable only from the earlier PutBucketPolicy event.
references:
  - https://attack.mitre.org/techniques/T1530/                                          # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketPolicy.html          # retrieved 2026-08-27
tags:
  - attack.collection
  - attack.t1530
  - attack.defense-impairment
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName: 'DeleteBucketPolicy'
  success:
    errorCode: null
  condition: selection and success
falsepositives:
  - Decommissioning a bucket, or replacing a policy where DeleteBucketPolicy is followed
    within seconds by PutBucketPolicy on the same bucket. Check for the pairing first.
level: medium
```

Reproduced byte-for-byte from the first rule document of `detections/sigma_t1530.yml` (its
leading comment block is not repeated — §2 says the same in prose). Six further documents
ship: the public-ACL rule covering all three request shapes (`high`), the Block Public Access
removal rule at bucket and account level (`high`), two `temporal` correlations at `critical` —
one per grant route, in either order — the server-access-logging disable (`medium`) and the
bucket-policy deletion (`medium`). **Deploy the file, not this excerpt.**

**What these rules structurally cannot do.** Four questions decide whether a bucket is public
and none is a field-match question. Do the `Allow`, the wildcard `Principal` and the absence
of a confining `Condition` belong to the **same statement** — and is that `Condition` on a key
S3 accepts, pinned to a value carrying no wildcard and no policy variable? Both need
decode-and-parse: Query 2, and the statement walk in `detections/kql_t1530.kql`. Is the grant
suppressed right now by a Block Public Access setting written at another time by another call?
That is in no single event; it needs Query 3. And is there a public ACL grant **at all** —
because AWS documents that with `IgnorePublicAcls` enabled `GetBucketAcl` returns *"an ACL
that reflects the access permissions that Amazon S3 is enforcing, rather than the actual ACL
that is associated with the bucket"*, so the state check that would answer it reports clean on
exactly the latent grant it exists to find, and the `PutBucketAcl` event is then the only
record that the grant exists. **Treat a rule hit as the trigger for Query 3, not as a
disposition.** (No companion rule for a missing `requestParameters` ships: CloudTrail omits
that field only above **100 KB**, while a bucket policy is capped at 20 KB and an ACL at 100
grants. Reasoning in `detections/detection_note_t1530.md`.)

---

### Key Investigation Queries

> **S3 management events are regional — run these in the bucket's Region**, and repeat for every Region you operate in, since an account-level Block Public Access call lands wherever the caller addressed the S3 Control endpoint. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: who exposed which bucket, by which of the three mechanisms

```bash
REGION="us-east-1"; WINDOW="7 days ago"
for EV in PutBucketPolicy DeleteBucketPolicy PutBucketAcl PutBucketLogging \
          PutBucketPublicAccessBlock DeleteBucketPublicAccessBlock \
          PutAccountPublicAccessBlock DeleteAccountPublicAccessBlock; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d "$WINDOW" +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson | (.requestParameters // {}) as $rp |
    # Statement is an object OR an array, Principal an object OR bare "*", Principal.AWS a
    # string OR an array. Iterating a bare object yields its KEYS, so an unguarded sweep
    # skips the statement and reports clean on the policy it exists to find.
    ([ ($rp.bucketPolicy.Statement // [] | if type=="object" then [.] else . end)[]
       | select(.Effect == "Allow") | (.Principal // empty)
       | (if type == "string" then . else (.AWS // empty) end)
       | (if type == "array" then .[] else . end) ]
     | map(select(tostring | test("\\*"))) | unique) as $wild |
    ([ ($rp.AccessControlPolicy.AccessControlList.Grant // [] | if type=="object" then [.] else . end)[]
       | select((.Grantee.URI // "") | test("groups/global/(AllUsers|AuthenticatedUsers)"))
       | "\((.Grantee.URI | split("/") | last))=\(.Permission)" ]) as $acl |
    {time: .eventTime, event: .eventName,
     caller_arn: (.userIdentity.arn // "unknown"),   # feeds SUSPECT_ARN in Containment Step 3
     access_key: .userIdentity.accessKeyId,          # feeds ACCESS_KEY_ID in Query 5
     bucket: ($rp.bucketName // "ACCOUNT-LEVEL"),    # feeds BUCKET in Queries 2-4
     wildcard_principals: $wild, acl_public_grants: $acl,
     canned_acl: ($rp["x-amz-acl"] // null),
     # Third PutBucketAcl shape. Matched by key PREFIX, not by five hard-coded names:
     # AWS documents the header names but not the key CloudTrail files them under.
     grant_headers: [$rp | to_entries[] | select(.key | ascii_downcase | startswith("x-amz-grant-"))
                     | select((.value | tostring) | test("groups/global/(AllUsers|AuthenticatedUsers)"))
                     | "\(.key)=\(.value)"],
     pab: ($rp.PublicAccessBlockConfiguration // null),
     logging_on: (if .eventName == "PutBucketLogging"
                  then (($rp.BucketLoggingStatus.LoggingEnabled // null) != null) else null end),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Read it as a timeline per `bucket`, not per event. A non-empty `wildcard_principals`,
`acl_public_grants`, `canned_acl` or `grant_headers` with `error: "SUCCESS"` is a grant —
`canned_acl: "authenticated-read"` included, which is public despite the name. A `pab` object with any
value `false`, or a `Delete*PublicAccessBlock` row, is the **moment the grant took effect** —
possibly days later, and the row to treat as the exposure time. `bucket: "ACCOUNT-LEVEL"` means
the block went for the whole account, so the blast radius is every bucket without one of its
own; `logging_on: false` before an exposure is preparation. Rows with an `error` are blocked
attempts — count them per `caller_arn`, never as exposures. Record `bucket`, `caller_arn`,
`access_key` and the `time`.

#### Query 2 — Inspect: parse the policy documents statement by statement

`requestParameters.bucketPolicy` is a nested object, so the shared decoder receives it directly
— no decode step. `--mode s3-bucket-policy` applies S3's own definition, which starts from the
opposite presumption to a reader's: S3 *"begins by assuming that the policy is public"*, and a
grant escapes that only under a `Condition` on a key S3 accepts, pinned to a **fixed value**
— one carrying no wildcard and no IAM policy variable.

```bash
REGION="us-east-1"; WINDOW="7 days ago"; KIT="<path-to-playbook-authoring-kit>"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy \
  --start-time "$(date -u -d "$WINDOW" +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -c '.Events[].CloudTrailEvent | fromjson | select(.errorCode == null) |
    {time: .eventTime, caller: .userIdentity.arn, grantee: .requestParameters.bucketName,
     policy_name: "bucket-policy", doc: .requestParameters.bucketPolicy}' | \
  python3 "$KIT/tools/decode_policy_documents.py" --mode s3-bucket-policy
```

`[!] PUBLIC READ` / `WRITE` / `READ+WRITE` is a live exposure and grades the damage.
`[!] PUBLIC ADMIN` is worse — anonymous callers may rewrite the bucket's own policy, ACL or
block, so re-enabling the block is not sufficient and the statement must go. `[!] BROAD SRCIP`
is the trap: an `aws:SourceIp` `Condition` looks confining, but S3 evaluates values broader
than `/8` as public anyway, RFC1918 ranges excepted. `[!] NOTACTION` grants every S3 action
except those listed. `Condition present but NOT confining` names the keys that failed and why —
unlisted, or listed with a wildcarded or policy-variable value. Read those names: S3's list is
an **open category** whose first entry is given only by example, so a key the tool does not
recognise may still be one S3 accepts. `[i] CONFINED` names the keys making the grant
non-public — read the values, because the tool checks the key, not whether the account ID
inside it is yours, and one `[!]` condemns the document: *"statement 3 renders the entire
policy public"*.

#### Query 3 — Sweep: which buckets are effectively public right now

The authoritative check, and the one no single event answers: any one mechanism suffices and the
account-level block overrides them all.

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
# Account level first: S3 applies the MOST RESTRICTIVE combination of account and bucket
# settings, so all-four-true here makes every per-bucket answer below moot.
ACC=$(aws s3control get-public-access-block --account-id "$ACCOUNT_ID" \
        --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null)
if [ -z "$ACC" ]; then echo "[!] No ACCOUNT-level public access block — every bucket is on its own"
elif echo "$ACC" | jq -e 'to_entries | all(.value == true)' >/dev/null
     then echo "[OK] Account-level block fully enabled — overrides any weaker bucket setting"
else echo "[!] Account-level block is PARTIAL: $(echo "$ACC" | jq -c .)"; fi

MASKED=0; UNREAD=0
for B in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  # IsPublic via jq, not --output text: the CLI renders a boolean as the capitalised
  # "True"/"False", so a test against "true" never matches and the sweep would print a
  # false clean result for a public bucket.
  # The API reference has NO Errors section, so what a policy-less bucket returns is
  # undocumented — an absent result and a failed call both fold to no-policy here rather
  # than resting on NoSuchBucketPolicy being thrown.
  ISPUB=$(aws s3api get-bucket-policy-status --bucket "$B" --output json 2>/dev/null \
          | jq -r '.PolicyStatus.IsPublic // "no-policy"'); ISPUB="${ISPUB:-no-policy}"
  # Captured raw, then parsed. GetBucketAcl has no "not configured" case — every bucket has
  # an ACL — so an empty result is a call that did not run: UNKNOWN, never clean. Without
  # this the sweep under-reports silently and cannot claim account-wide coverage.
  ACLR=$(aws s3api get-bucket-acl --bucket "$B" --output json 2>/dev/null)
  [ -z "$ACLR" ] && { UNREAD=$((UNREAD+1)); echo "[!] $B — get-bucket-acl returned nothing (no permission, wrong Region, throttled); state UNKNOWN"; continue; }
  ACL=$(printf '%s' "$ACLR" \
        | jq -r '[.Grants[]? | select((.Grantee.URI // "") | test("groups/global/(AllUsers|AuthenticatedUsers)"))
                 | "\((.Grantee.URI | split("/") | last))=\(.Permission)"] | join(",")')
  PAB=$(aws s3api get-public-access-block --bucket "$B" --output json 2>/dev/null \
        | jq -c '.PublicAccessBlockConfiguration // empty'); BLOCKED="no"
  [ -n "$PAB" ] && echo "$PAB" | jq -e 'to_entries | all(.value == true)' >/dev/null && BLOCKED="yes"
  # GetBucketAcl returns EFFECTIVE permissions, so IgnorePublicAcls=true hides the grant this
  # sweep exists to find. An empty ACL result under it is UNKNOWN, never clean.
  IGN=$(printf '%s' "$PAB" | jq -r '.IgnorePublicAcls // false' 2>/dev/null)
  ACL_STATE="${ACL:-none}"
  [ -z "$ACL" ] && [ "$IGN" = "true" ] && { ACL_STATE="UNKNOWN-masked"; MASKED=$((MASKED+1)); }
  { [ "$ISPUB" = "true" ] || [ -n "$ACL" ]; } && echo "[!] $B policy_public=$ISPUB acl_public='$ACL_STATE' bucket_block=${PAB:-ABSENT} fully_blocked=$BLOCKED"
done
[ "$MASKED" -gt 0 ] && echo "[!] $MASKED bucket(s) run IgnorePublicAcls=true, so GetBucketAcl returned enforced permissions and their ACL state is UNKNOWN, not clean — resolve from the PutBucketAcl history in Query 1, or remove the mechanism with BucketOwnerEnforced"
[ "$UNREAD" -gt 0 ] \
  && echo "[!] $UNREAD bucket(s) could not be read at all — this sweep is NOT account-wide and must not be reported as one" \
  || echo "[OK] Effective-public sweep complete over every bucket list-buckets returned"
```

Every per-bucket `[!]` line is a bucket carrying a public grant. `fully_blocked=yes` means it
is suppressed for now — a **latent** exposure one `DeleteBucketPublicAccessBlock` from live,
for the §6 findings; `fully_blocked=no` is live. `no-policy` means no policy status came back,
distinct from `false`. **`acl_public='UNKNOWN-masked'` and the `MASKED` count are not clean
results**: the ACL question is unanswered there, and answering it needs Query 1's
`PutBucketAcl` history, because the read cannot see past `IgnorePublicAcls`. A non-zero
`UNREAD` count means the sweep is not account-wide and may not be reported as one. Reconcile
the rest against the §1 allowlist.

#### Query 4 — Was it used: prove nothing was read, or prove you cannot know

**`s3:GetObject` is data-plane.** `lookup-events` returns zero for it always, and that zero
is evidence of no logging, not of no exfiltration. This checks whether any of the three
sources that *can* record a read covered this bucket **before** the exposure window.

```bash
BUCKET="<bucket-from-Query-1>"; EXPOSED_AT="<time-from-Query-1>"
REGION="us-east-1"; SOURCES=0
# 1. Server access logs — the ONLY source that records anonymous reads with a source IP.
LOGDEST=$(aws s3api get-bucket-logging --bucket "$BUCKET" \
            --query 'LoggingEnabled.TargetBucket' --output text 2>/dev/null)
if [ -n "$LOGDEST" ] && [ "$LOGDEST" != "None" ]; then
  echo "[OK] Server access logs -> s3://$LOGDEST — search REST.GET.OBJECT since $EXPOSED_AT"; SOURCES=$((SOURCES+1))
else echo "[!] Server access logging OFF for $BUCKET — no anonymous-read record from this source"; fi
# 2. A CloudTrail data-event trail covering this bucket's objects. Both selector styles
#    name the resource type the same way, so one string test covers classic and advanced.
for T in $(aws cloudtrail list-trails --query 'Trails[].TrailARN' --output text); do
  aws cloudtrail get-event-selectors --trail-name "$T" --region "$REGION" --output json 2>/dev/null \
    | grep -q 'AWS::S3::Object' && { echo "[OK] Trail $T logs S3 object data events"; SOURCES=$((SOURCES+1)); }
done
# 3. CloudWatch request metrics, which exist only where a per-bucket metrics configuration was
#    created — the always-on daily STORAGE metrics cannot answer this.
for FID in $(aws s3api list-bucket-metrics-configurations --bucket "$BUCKET" \
               --query 'MetricsConfigurationList[].Id' --output text 2>/dev/null); do
  aws cloudwatch get-metric-statistics --namespace AWS/S3 --metric-name BytesDownloaded \
    --dimensions Name=BucketName,Value="$BUCKET" Name=FilterId,Value="$FID" \
    --start-time "$EXPOSED_AT" --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --period 3600 \
    --statistics Sum --region "$REGION" --output json \
    | jq -r --arg f "$FID" '.Datapoints|sort_by(.Timestamp)[]|"\($f) \(.Timestamp) Bytes=\(.Sum)"'
  SOURCES=$((SOURCES+1))
done
[ "$SOURCES" -eq 0 ] && \
  echo "[!] NO read-recording source covered $BUCKET before $EXPOSED_AT — whether objects were read is UNANSWERABLE and cannot be reconstructed. Report it as unknown, not as none." || \
  echo "[OK] $SOURCES read-recording source(s) available — the read question is answerable"
```

`SOURCES=0` is the normal outcome on an unprepared account and it is the finding, not a gap in the
procedure — say "unknown" in the report. Where a source exists, a `BytesDownloaded` sum far above
baseline or `REST.GET.OBJECT` entries with requester `-` (anonymous) are the evidence.

#### Query 5 — Session reconstruction: everything that principal did

```bash
REGION="us-east-1"; ACCESS_KEY_ID="<access-key-from-Query-1>"; EXPOSED_AT="<time-from-Query-1>"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg t "$EXPOSED_AT" '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     phase: (if .eventTime > $t then "AFTER-EXPOSURE" else "before" end),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | jq -s 'sort_by(.time)'
```

Keyed on the access key, not a role name — `AttributeKey=Username` matches the *session* name,
so a role-name lookup returns zero. Look for the other routes the same principal opened:
`PutBucketWebsite` and `PutBucketCors` (plain HTTP), `PutBucketReplication` into another
account, `CreateAccessPoint`, further `Delete*PublicAccessBlock` calls. Re-run Query 3 after.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Re-enabling Block Public Access suppresses the policy route and the ACL route in one call
without destroying either document — the fastest containment and the one that preserves the
evidence. Logging goes in the same step and ahead of it, because the exposure continues while
you work and only server access logs record who takes advantage of it.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being contained.

#### Step 1 — Restore logging, then re-enable Block Public Access at both levels

```bash
BUCKET="<bucket-from-Query-1>"; REGION="us-east-1"; LOG_BUCKET="<your-log-destination-bucket>"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
# Logging first: the exposure continues while you work and this is the only source that
# records who takes advantage of it. It records reads FROM NOW ON and recovers nothing from
# the window, and AWS delivers these best-effort "within a few hours".
CURRENT=$(aws s3api get-bucket-logging --bucket "$BUCKET" \
            --query 'LoggingEnabled.TargetBucket' --output text 2>/dev/null)
if [ -z "$CURRENT" ] || [ "$CURRENT" = "None" ]; then
  aws s3api put-bucket-logging --bucket "$BUCKET" --region "$REGION" \
    --bucket-logging-status "{\"LoggingEnabled\":{\"TargetBucket\":\"$LOG_BUCKET\",\"TargetPrefix\":\"$BUCKET/\"}}" \
    && echo "[OK] Server access logging re-enabled on $BUCKET -> s3://$LOG_BUCKET"
else echo "[i] Logging already enabled on $BUCKET -> $CURRENT"; fi
# Check before blocking: this breaks a bucket deliberately serving a public static website.
aws s3api get-bucket-website --bucket "$BUCKET" >/dev/null 2>&1 && \
  echo "[!] $BUCKET has a website configuration — confirm against the §1 allowlist BEFORE blocking"

aws s3api put-public-access-block --bucket "$BUCKET" --region "$REGION" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  && echo "[OK] Block Public Access re-enabled on $BUCKET — public policy and ACL now suppressed"

aws s3control put-public-access-block --account-id "$ACCOUNT_ID" \
  --public-access-block-configuration \
    '{"BlockPublicAcls": true, "IgnorePublicAcls": true, "BlockPublicPolicy": true, "RestrictPublicBuckets": true}' \
  && echo "[OK] Account-level Block Public Access enabled for $ACCOUNT_ID"
```

> Bucket level first because it is the fast path and AWS documents no propagation delay for
> it, while of account-level settings AWS says "The settings might not take effect in all
> Regions immediately or simultaneously, but they eventually propagate to all Regions" —
> the durable control, not the urgent one. Do the
> account level even for a one-bucket incident: S3 takes the most restrictive combination of
> the two, so it holds when the next bucket is created without one. Neither call deletes the
> policy or the ACL, which is why Step 3 can still read them. `RestrictPublicBuckets=true`
> still lets principals inside the owning account manage the bucket and `BlockPublicAcls=true`
> rejects only *public* ACLs, so this locks nobody out and Step 2's `--acl private` succeeds.

#### Step 2 — Capture both documents, then remove the public grant

```bash
BUCKET="<bucket-from-Query-1>"
EVIDENCE="/tmp/ir-s3-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$EVIDENCE"
# Bucket policies are NOT versioned. Overwriting or deleting one destroys the only copy.
aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text \
  > "$EVIDENCE/bucket-policy.json" 2>/dev/null || rm -f "$EVIDENCE/bucket-policy.json"
aws s3api get-bucket-acl --bucket "$BUCKET" --output json > "$EVIDENCE/bucket-acl.json" 2>/dev/null
echo "[OK] Captured current policy and ACL to $EVIDENCE"
# Strip only the public statements: deleting the whole policy would also remove any explicit
# Deny it carried, and a TLS fence or an organisation fence is a bucket policy too.
if [ -s "$EVIDENCE/bucket-policy.json" ]; then
  jq '(.Statement) |= (if type=="object" then [.] else . end)
      | .Statement |= map(select((.Effect != "Allow")
          or (((.Principal // "") | tostring | test("\\*")) | not)))' \
     "$EVIDENCE/bucket-policy.json" > "$EVIDENCE/bucket-policy.cleaned.json"
  if [ "$(jq '.Statement | length' "$EVIDENCE/bucket-policy.cleaned.json")" -gt 0 ]; then
    aws s3api put-bucket-policy --bucket "$BUCKET" --policy "file://$EVIDENCE/bucket-policy.cleaned.json" \
      && echo "[OK] Public statements removed from $BUCKET policy; the rest is intact"
  else
    aws s3api delete-bucket-policy --bucket "$BUCKET" \
      && echo "[OK] Every statement was public — policy deleted (captured in $EVIDENCE)"
  fi
else echo "[i] $BUCKET has no bucket policy — the exposure was the ACL or the block"; fi
# ACLs back to owner-only. AccessControlListNotSupported means Object Ownership is
# BucketOwnerEnforced, ACLs are already disabled, and there is nothing to fix.
aws s3api put-bucket-acl --bucket "$BUCKET" --acl private 2>/dev/null \
  && echo "[OK] Bucket ACL reset to private" \
  || echo "[i] put-bucket-acl refused — ACLs are disabled on $BUCKET (BucketOwnerEnforced)"
```

#### Step 3 — Contain the principal that exposed the bucket

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"; NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REVOKE_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$NOW"'"}}}]}'
DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:PutBucketPolicy","s3:DeleteBucketPolicy","s3:PutBucketAcl","s3:PutBucketPublicAccessBlock","s3:PutAccountPublicAccessBlock","s3:PutBucketOwnershipControls","s3:PutBucketWebsite","s3:PutBucketLogging"],"Resource":"*"}]}'
if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')        # user ARN: name = LAST segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive \
      && echo "[OK] Disabled key $K for $U"
  done
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyS3Exposure" \
    --policy-document "$DENY_DOC" && echo "[OK] Denied further S3 exposure calls by user $U"
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')         # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document "$REVOKE_DOC" && echo "[OK] Revoked sessions for role $R"
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyS3Exposure" \
    --policy-document "$DENY_DOC" && echo "[OK] Denied further S3 exposure calls by role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

> `aws:TokenIssueTime` denies only tokens issued **before** the cutoff; one re-fetched
> afterwards is unaffected. Disable, do not delete — an inactive key stays enumerable and
> keeps its creation metadata.

---

## 4. Eradication

### Remove Attacker Access

#### Confirm every flagged bucket is non-public, then close the other routes

Work Query 3's full `[!]` list, not the bucket that raised the alert: an actor who found one
writable bucket policy usually tried several, and a bucket showing `fully_blocked=yes` with a
public grant survives this incident untouched. Then, from Query 5's `AFTER-EXPOSURE` rows:

- **Website and CORS configurations** — `delete-bucket-website`, `delete-bucket-cors`. A
  website configuration serves objects over plain HTTP and makes the bucket findable; the
  policy you just cleaned does not affect it
- **Replication rules** — `get-bucket-replication`. A rule copying objects into another
  account keeps exfiltrating after every control here is restored, to a destination outside
  your reach entirely
- **Access points** — `aws s3control list-access-points --account-id <id>`; each carries its
  own policy and block settings, evaluated separately from the bucket's
- **Objects written while the bucket was publicly writable** — if Query 2 said `PUBLIC WRITE`
  or `READ+WRITE`, treat every object created in the window as attacker-supplied

#### Right-size the permission that made this possible

Enumerate what grants the exposure permissions on the acting principal —
`aws iam list-role-policies` / `list-attached-role-policies` for a role, `list-user-policies` /
`list-attached-user-policies` for a user. The durable fix is not removing `s3:PutBucketPolicy`:
it is denying `s3:PutBucketPublicAccessBlock` and `s3:PutAccountPublicAccessBlock` at the
**organisation** level so no policy written inside the account re-opens the route, plus
`BucketOwnerEnforced` ownership so the ACL mechanism stops existing (§6). Then remove the
emergency policies:

```bash
RN="<suspect-role-name>"
aws iam delete-role-policy --role-name "$RN" --policy-name "EmergencyRevokeSessions" 2>/dev/null
aws iam delete-role-policy --role-name "$RN" --policy-name "EmergencyDenyS3Exposure"  2>/dev/null
# Step 3 uses put-user-policy when the principal was an IAM USER — that path needs the
# user-side removal, which delete-role-policy does not cover.
aws iam delete-user-policy --user-name "<suspect-user-name>" --policy-name "EmergencyDenyS3Exposure" 2>/dev/null
# D-0: assert, do not announce. delete-*-policy exits 0 whether or not anything was
# there, so re-list and confirm absence; a listing failure is INCONCLUSIVE, never [OK].
LEFT=0; UNK=0
for RN in "<grantor-role-name>" "<grantee-role-name>"; do
  L=$(aws iam list-role-policies --role-name "$RN" --query 'PolicyNames[]' --output text 2>/dev/null)
  if [ -z "$L" ] && ! aws iam get-role --role-name "$RN" >/dev/null 2>&1; then UNK=$((UNK+1)); continue; fi
  printf '%s' "$L" | tr '\t' '\n' | grep -qE '^Emergency' && { echo "[FAIL] $RN still carries an Emergency* policy"; LEFT=$((LEFT+1)); }
done
U=$(aws iam list-user-policies --user-name "<grantor-user-name>" --query 'PolicyNames[]' --output text 2>/dev/null)
printf '%s' "$U" | tr '\t' '\n' | grep -qE '^Emergency' && { echo "[FAIL] grantor user still carries an Emergency* policy"; LEFT=$((LEFT+1)); }
[ "$UNK" -gt 0 ] && echo "[!] $UNK principal(s) could not be listed — INCONCLUSIVE, not clean"
{ [ "$LEFT" -eq 0 ] && [ "$UNK" -eq 0 ]; } && echo "[OK] No Emergency* policy remains on any contained principal"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the bucket is not public by any of the three mechanisms

```bash
BUCKET="<bucket-from-Query-1>"; FAILS=0; UNRESOLVED=0
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
# Each configuration is captured ONCE, with stderr, and every verdict below is read out of
# the captured text. No branch may let a call that did not run — no permission, wrong
# Region, throttled — reach an [OK]: "could not check" prints [!] and is counted, never
# folded into "clean".
BPAB=$(aws s3api get-public-access-block --bucket "$BUCKET" --output json 2>&1)
APAB=$(aws s3control get-public-access-block --account-id "$ACCOUNT_ID" --output json 2>&1)
PS=$(aws s3api get-bucket-policy-status --bucket "$BUCKET" --output json 2>&1)
ACLR=$(aws s3api get-bucket-acl --bucket "$BUCKET" --output json 2>&1)
# 1. POLICY. Require a real boolean. The API reference has NO Errors section, so what a
# policy-less bucket returns is undocumented — anything that is not true/false is an open
# question settled by reading the policy itself, never by assuming NoSuchBucketPolicy.
case "$(printf '%s' "$PS" | jq -r '.PolicyStatus.IsPublic' 2>/dev/null)" in
  true)  echo "[FAIL] $BUCKET bucket policy is still public (IsPublic=true)"; FAILS=$((FAILS+1)) ;;
  false) echo "[OK] Bucket policy is not public (IsPublic=false)" ;;
  *)     echo "[!] INCONCLUSIVE — no IsPublic came back for $BUCKET: $(printf '%s' "${PS:-<empty>}" | head -1)"
         echo "    get-bucket-policy says: $(aws s3api get-bucket-policy --bucket "$BUCKET" --output json 2>&1 | head -1) — no policy at all cannot be public by this route, an authorization error means the check never ran. Decide which; do not record it as clean"
         UNRESOLVED=$((UNRESOLVED+1)) ;;
esac
# 2. ACL. Containment Step 1 re-enabled IgnorePublicAcls, and GetBucketAcl returns EFFECTIVE
# permissions — so a zero here is masked, not clean, and printing [OK] on it would be a
# false pass over a live grant.
ACL=$(printf '%s' "$ACLR" | jq -r '[.Grants[]? | select((.Grantee.URI // "") | test("groups/global/(AllUsers|AuthenticatedUsers)"))] | length' 2>/dev/null)
IGN=$(printf '%s' "$BPAB" | jq -r '.PublicAccessBlockConfiguration.IgnorePublicAcls' 2>/dev/null)
OWN=$(aws s3api get-bucket-ownership-controls --bucket "$BUCKET" \
        --query 'OwnershipControls.Rules[0].ObjectOwnership' --output text 2>/dev/null)
if [ -z "$ACL" ]; then
  echo "[!] INCONCLUSIVE — get-bucket-acl returned no ACL for $BUCKET: $(printf '%s' "${ACLR:-<empty>}" | head -1)"
  UNRESOLVED=$((UNRESOLVED+1))
elif [ "$ACL" -ne 0 ]; then
  echo "[FAIL] $ACL public ACL grant(s) still enforced on $BUCKET"; FAILS=$((FAILS+1))
elif [ "$OWN" = "BucketOwnerEnforced" ]; then
  echo "[OK] ACLs disabled on $BUCKET (BucketOwnerEnforced) — the ACL route does not exist"
elif [ "$IGN" = "true" ]; then
  echo "[!] No public ACL grant is ENFORCED, but IgnorePublicAcls masks GetBucketAcl, so a suppressed grant reads exactly like none. Confirm Step 2's put-bucket-acl --acl private succeeded, or set BucketOwnerEnforced. Do not record this as clean"
  UNRESOLVED=$((UNRESOLVED+1))
elif [ "$IGN" = "false" ]; then
  echo "[OK] No ACL grant to AllUsers or AuthenticatedUsers, and IgnorePublicAcls is off so none is being masked"
else
  echo "[!] INCONCLUSIVE — no public grant is enforced, but the bucket's IgnorePublicAcls value did not come back, so whether one is masked is unknown: $(printf '%s' "${BPAB:-<empty>}" | head -1)"
  UNRESOLVED=$((UNRESOLVED+1))
fi
# 3. BLOCK PUBLIC ACCESS, both scopes, from the two configurations captured separately above.
# Selecting one by the other call's exit status would report the ACCOUNT setting as the
# BUCKET's whenever the bucket has none. Absent and unreadable both fail — the safe direction.
for SCOPE in bucket account; do
  [ "$SCOPE" = "bucket" ] && CFG="$BPAB" || CFG="$APAB"
  if printf '%s' "$CFG" | jq -e '.PublicAccessBlockConfiguration | to_entries | all(.value == true)' >/dev/null 2>&1; then
    echo "[OK] $SCOPE-level Block Public Access has all four settings true"
  elif printf '%s' "$CFG" | jq -e '.PublicAccessBlockConfiguration' >/dev/null 2>&1; then
    echo "[FAIL] $SCOPE-level Block Public Access is PARTIAL: $(printf '%s' "$CFG" | jq -c '.PublicAccessBlockConfiguration')"; FAILS=$((FAILS+1))
  else
    echo "[FAIL] $SCOPE-level Block Public Access is absent or unreadable: $(printf '%s' "${CFG:-<empty>}" | head -1)"; FAILS=$((FAILS+1))
  fi
done
[ "$FAILS" -eq 0 ] && [ "$UNRESOLVED" -eq 0 ] \
  && echo "[OK] $BUCKET is not publicly accessible by any mechanism" \
  || echo "[FAIL] $FAILS unremediated exposure(s), $UNRESOLVED unresolved question(s) on $BUCKET"
```

> `GetBucketPolicyStatus` is the best answer available for the **policy** mechanism — it
> applies S3's own fixed-values rule and so resolves the `Condition` question no field match
> can. Two limits, both of the documentation rather than of the API. That it is scoped to
> the policy alone is an **inference from its name**: the page never says it evaluates the
> policy alone and never says it ignores ACLs. And it has no Errors section, so its
> behaviour on a policy-less bucket is undocumented — hence the `[!] INCONCLUSIVE` branch
> rather than an assertion about `NoSuchBucketPolicy`. AWS documents no Block Public Access
> masking of this call, unlike `GetBucketAcl`. Hence all three checks — and every one of
> them can print `[FAIL]`, while a call that did not run reaches `[!]`, never `[OK]`.

Then re-run **Query 3** — every remaining `[!]` must be on the §1 allowlist, and any that is
not, including a latent one with `fully_blocked=yes`, is unremediated. Re-run **Query 4**: if it
prints `SOURCES=0`, the report must say whether objects were read is **unknown and
unrecoverable**, not that none were — `lookup-events` for `GetObject` returns zero either way.

#### Confirm the corrected detection fires

```bash
echo "MUST fire (errorCode absent, eventSource s3.amazonaws.com):"
echo '  1. PutBucketPolicy, requestParameters.bucketPolicy a nested OBJECT = {"Statement":'
echo '     [{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"..."}]}  ->'
echo '     s3_bucket_policy_public_principal, high. Repeat with "Principal":{"AWS":"*"}:'
echo "     firing on one shape only is a false negative decided by the client."
echo "  2. PutBucketAcl, SEPARATELY in each of its three request shapes: Grantee.URI ="
echo "     .../groups/global/AllUsers; x-amz-acl = authenticated-read, which is public"
echo "     despite carrying no 'public-' prefix; and x-amz-grant-read naming the same group"
echo "     by uri=, which is AWS's own worked example and uses neither other shape ->"
echo "     s3_bucket_acl_public_grant, high, on ALL THREE."
echo "  3. DeleteBucketPublicAccessBlock, and PutBucketPublicAccessBlock with BlockPublicPolicy"
echo "     =false -> s3_public_access_block_removed, high. Repeat both at ACCOUNT level."
echo "  4. s3_bucket_policy_public_principal and s3_public_access_block_removed by one ARN"
echo "     within 24h -> the temporal correlation, critical — and again in the REVERSE"
echo "     order, which must fire too: BlockPublicPolicy refuses a public policy outright,"
echo "     so unblock-then-grant is the order the block's own enforcement produces."
echo "MUST NOT fire:"
echo "  1. DeletePublicAccessBlock / PutPublicAccessBlock — API operation names, not CloudTrail"
echo "     event names; firing here means matching an event production never emits."
echo "  2. PutBucketPublicAccessBlock with all four settings TRUE — protection being enabled."
echo "  3. PutBucketAcl with x-amz-acl=private, or Grantee.URI .../groups/s3/LogDelivery."
echo "  4. Any of the above with errorCode=AccessDenied — that is the P2 queue, never a P0."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could make a bucket internet-readable in one call, and removing Block Public Access exposed a policy written long before | `s3:PutBucketPolicy` / `s3:PutBucketAcl` / `s3:PutBucketPublicAccessBlock` held outside the IaC pipeline with no SCP capping what they confer; and the block was carrying the security of the bucket while the underlying policy stayed public, so a suppressed misconfiguration was treated as a fixed one |
| The exposure raised no high-priority alert, and ACLs were still enabled on the bucket | Two rules matched API operation names CloudTrail does not emit, one alerted on the hardening direction of its own condition, and the block removal was rated P3; separately, Object Ownership was not `BucketOwnerEnforced`, so a second exposure mechanism existed alongside the policy — one `get-bucket-policy` does not show |
| Whether objects were read could not be established, and nobody could say which other buckets were public | No data-event trail, server access logging or request-metrics configuration covered the bucket before the window — object reads are data-plane and leave no default record — and no standing effective-state evaluation or public-by-design allowlist existed |

### Recommended Guardrails

**Fence the Block Public Access controls at the organisation level**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["s3:PutAccountPublicAccessBlock", "s3:PutBucketPublicAccessBlock"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/BreakGlassAdmin", "arn:aws:iam::*:role/iac-deploy"] }
  }
}
```

> `aws:PrincipalArn` carries a `*`, so the operator must be `ArnNotLike`. `StringNotEquals`
> does not expand `*` and on a `Deny` fails **closed** — every principal denied and S3
> administration stops working; `Deny` with `StringEquals` on a wildcarded value fails the
> other way and permits everything it was written to deny. `s3:PutBucketPublicAccessBlock` is
> the permission for **both** the PUT and the DELETE — there is no separate delete action.

Pair it with a second `Deny` of the same shape on `s3:PutBucketAcl` and
`s3:PutBucketOwnershipControls`: the first closes the ACL route, the second stops anyone
re-enabling ACLs once `BucketOwnerEnforced` is set.

**Structural controls**
- **Account-level Block Public Access with all four settings true, in every account** — the only
  control covering buckets nobody has thought about yet, and S3 takes the most restrictive
  combination, so it holds where a bucket's own setting is weaker
- **Object Ownership = `BucketOwnerEnforced` on every bucket**, disabling ACLs entirely:
  `PutBucketAcl` then returns `AccessControlListNotSupported` and one mechanism stops existing
- **Server access logging or a data-event trail on every sensitive bucket**, decided before an
  incident or not at all; and a public-by-design allowlist beside it, one ticket per entry

**Detection improvements**
- Deploy the corrected event names: Block Public Access is four distinct CloudTrail names and
  a rule missing any of them has a blind spot
- Run AWS Config `S3_BUCKET_PUBLIC_READ_PROHIBITED` as the standing state check — the only
  evaluation covering block, policy and ACL together — and re-prioritise GuardDuty's
  `Policy:S3/BucketBlockPublicAccessDisabled` and `Policy:S3/AccountBlockPublicAccessDisabled`
  above their default **Low**

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1530 — Data from Cloud Storage |
| MITRE tactic | Collection (TA0009); the block removal is also T1685 — Disable or Modify Tools (Defense Impairment, TA0112), the logging disable T1685.002 |
| Primary API | `s3:PutBucketPolicy` \| `s3:PutBucketAcl` \| `s3:PutPublicAccessBlock` / `s3:DeletePublicAccessBlock` at bucket **or** account scope |
| Event source | `s3.amazonaws.com`. AWS documents the account-level calls on the S3 CloudTrail events page, but never states their `eventSource`, and the request itself goes to the S3 Control endpoint — so the shipped rules OR `s3-control.amazonaws.com` alongside it and tell the deployer to confirm which their own trail carries. **Regional**: query the bucket's Region and sweep every Region for account-level calls |
| CloudTrail event names | `PutBucketPolicy`, `DeleteBucketPolicy`, `PutBucketAcl`, `PutBucketLogging`, `Put`/`DeleteBucketPublicAccessBlock`, `Put`/`DeleteAccountPublicAccessBlock`. **The event name is not the API operation name** — the operations are `PutPublicAccessBlock` / `DeletePublicAccessBlock` |
| Key discriminator | The bucket is **effectively** public: `GetBucketPolicyStatus.IsPublic` true, or an `AllUsers`/`AuthenticatedUsers` ACL grant, or a Block Public Access configuration that no longer blocks — with no `Condition` pinning the grant to fixed values. Not the event name |
| Ground truth | `GetBucketPolicyStatus` + `GetBucketAcl` + `GetPublicAccessBlock` at bucket **and** account scope; AWS Config `S3_BUCKET_PUBLIC_READ_PROHIBITED` evaluates all three together. **`GetBucketAcl` is not ground truth under `IgnorePublicAcls`** — AWS documents it as returning *"the effective permissions"*, so a suppressed public grant reads identically to none, and the `PutBucketAcl` event is the only record it exists. `GetBucketPolicyStatus` has no documented equivalent, and that it is policy-scoped is an inference from its name, not a documented claim |
| "Was it used" pivot | **Data-plane** — `s3:GetObject` never appears in `lookup-events`. S3 server access logs (the only anonymous-read record; best-effort, hours), a CloudTrail data-event trail, or CloudWatch `AWS/S3 BytesDownloaded`. **None is enabled by default**; if none covered the bucket beforehand the answer is unknown, permanently |
| Field shapes | `requestParameters.bucketPolicy` is a nested **object** (IAM's `policyDocument` is a string). `PutBucketAcl` carries the grant in exactly one of **three** mutually exclusive shapes — `x-amz-acl` (four values, three public), `AccessControlPolicy...Grant[]`, or one of five `x-amz-grant-*` headers. The header names are documented; the `requestParameters` key CloudTrail files them under is not, for any header. All these calls return `responseElements: null` |
| Blast radius | Every object in the bucket, for the whole exposure window, to anyone on the internet — plus write and delete if the grant included them, and the bucket's own access controls if it granted `s3:PutBucketPolicy` or `s3:PutBucketAcl`. An **account-level** block removal applies that to every bucket lacking its own block |
| Error strings | `AccessDenied` on denial — not `Client.`-prefixed like EC2; a `PutBucketPolicy` blocked by `BlockPublicPolicy` is an `AccessDenied` naming the setting. Non-denial codes: `NoSuchBucket`, `NoSuchBucketPolicy`, `MalformedPolicy`, `InvalidPolicyDocument`, `InvalidRequest`, `AccessControlListNotSupported` (ACLs disabled by `BucketOwnerEnforced`) |
| Reversal semantics | Re-enabling the block is immediate at bucket level and suppresses both other mechanisms without deleting either document; account-level settings may "not take effect in all Regions immediately". Bucket policies are **not versioned** — an overwrite or delete destroys the only copy. Sibling: `../../iam.privilege-escalation.inline-policy-grant/`, same unversioned-document evidence problem and the same shape guards |

**MITRE mapping note:** the source alerts carry **no** ATT&CK mapping at all — not an
imprecise one, none, visible as the `mitre: none` line on every entry of
`_source/original_rules.yml`. **T1530 (*Data from Cloud Storage*)** is what these files carry
and it is right for the objective. Two nuances worth stating rather than smoothing over:
T1530's canonical tactic is **Collection**, not Exfiltration, even though the directory is
named for the exfiltration outcome — the technique is obtaining the data, and the transfer
off-platform is T1537/T1567 territory; and the Block Public Access removal is as much **T1685
(*Impair Defenses*)** as T1530, because it disables a preventive control rather than granting
anything, so both tags ship on that rule. A mapping-precision note — although here the absence
of any mapping is itself the defect.

### Residual Risk

**Every byte already served is gone.** Re-enabling the block stops the next read and recalls
nothing. If the bucket held credentials, tokens, customer records or source code, treat them as
disclosed and rotate or notify regardless of whether a read was recorded — §5's `[OK]` lines
attest only that the bucket is closed now.

**"No evidence of access" is almost never a finding here.** Object reads are data-plane and
none of the three recording sources is on by default, so the usual outcome is that the
question is unanswerable rather than answered in the negative. A `lookup-events` query for
`GetObject` returns zero whether the bucket was scraped completely or never touched, and
citing that zero as reassurance is the most damaging use this playbook has.

**The other buckets stay latent, and some of them are invisible.** Query 3's
`fully_blocked=yes` lines carry a public policy or ACL the block is suppressing; they raise no
alert until somebody removes a block, at which point they go live at once. Worse for the ACL
route: `GetBucketAcl` returns *"the effective permissions"*, so wherever `IgnorePublicAcls` is
enabled a public grant is invisible to the sweep meant to find it, and the honest output is
`UNKNOWN-masked` rather than clean. Those buckets are remediable only from the `PutBucketAcl`
history or by setting `BucketOwnerEnforced`, which removes the mechanism instead of hiding it.
Stripping the grants is the fix — leaving them and trusting the block reproduces exactly the
condition that caused this incident. And an object copied out during the
window, by an anonymous reader or a replication rule into another account, is outside every
control restored here.
