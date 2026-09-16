# Detection Note — T1098 (SNS topic opened for public publish)

**Signal:** an SNS access policy that allows a publish-granting action to `Principal: "*"`
with no principal-scoping `Condition`, letting any caller on the internet inject messages
into a topic and reach every endpoint it fans out to.

**The wildcard principal is not the finding — the missing Condition is.** This is the one
fact that separates a usable rule from a muted one. AWS's own default topic policy, the
one the console writes for every topic you create by hand, is
`"Principal": {"AWS": "*"}` over eight SNS actions *including* `SNS:Publish`, made safe by
a `Condition` confining the caller to the topic owner (`AWS:SourceOwner`) or to a named
source ARN. So `Principal: *` is the normal shape, present on a large fraction of the
topics in any account, and a rule that alerts on it alerts on everything. The
discriminating field is the `Condition` element of the same statement.

**What the original rule got wrong**

1. **It cannot fire.** It phrase-matched the policy against
   `Principal:{AWS:*},Action:SNS:Publish`. CloudTrail carries
   `requestParameters.attributes.Policy` as a **raw JSON string** — per the corrected A4,
   request parameters are raw and percent-encoding is a response-side IAM property that
   does not apply here at all — so the bytes on the wire are `"Principal":{"AWS":"*"}`,
   with quotes, in whatever key order and whitespace the client sent. The literal in the
   rule occurs in no real event.
2. **Wrong event-name case.** It matched `eventName:"createtopic"`. CloudTrail writes
   `CreateTopic`.
3. **One write path out of three.** Only `CreateTopic` was covered. A topic created
   correctly and opened a minute later by `SetTopicAttributes` with `AttributeName=Policy`
   produced no matching event, and `AddPermission` produced none either.
4. **No Condition test.** Had the phrase matched, it would have fired on every
   console-created topic in the account, because the default policy contains both the
   wildcard principal and `SNS:Publish`.
5. **Wrong tactic.** The rule is mapped to Collection (T1213). Publishing is a write.
   Nothing is collected by granting publish rights; messages flow *in*. See the mapping
   note below.

## The action set, and the two shapes a token match misses

`"Action": "SNS:Publish"` is the obvious form and both shipped rules match it. Two others
grant publish and carry no `:Publish` substring:

- **A service or global wildcard** — `"sns:*"` or `"*"`. Matched by the `':*"'` and
  `'"Action":"*"'` members of the `publish_action` block.
- **`NotAction`.** An `Allow` with `NotAction` grants everything *except* what it lists,
  so a public statement with `"NotAction": ["sns:DeleteTopic"]` grants publish, subscribe
  and policy rewrite to the internet while containing no action token at all. The
  `'"NotAction"'` member exists for exactly this, and the KQL treats it as the highest
  verdict.

`"Action": ["*"]` — the array form of the global wildcard — is **not** matched by the
Sigma rules, because the only substring that would catch it, `"*"`, also occurs inside
`"AWS":"*"` and would make the block match every public policy regardless of action. The
KQL catches it with `set_has_element(Actions, "*")`, and so does the decoder pass in
§2 Query 2 of the playbook. This is a known, deliberate gap in the streaming rule.

## Shape guards, and the one the shared decoder does not carry

IAM accepts `Statement` as a single object or an array, `Principal` as an object or the
bare string `"*"`, and `Action` as a string or an array. `tools/decode_policy_documents.py`
normalises all three and is the right tool to run over the collected policies —
`as_principals()` handles the bare-string form that an unguarded sweep iterates
character by character.

**But its `auto` mode does not recognise `aws:SourceOwner` as a confining condition key.**
`TRUST_CONFINERS` carries `aws:sourcearn`, `aws:sourceaccount`, `aws:principalorgid` and
`aws:sourcevpce`, and `S3_PUBLIC_CONFINERS` carries `aws:sourceowner` — but the trust path
that a `Principal`-bearing SNS statement routes to does not. It also does not carry the
SNS-specific `sns:Protocol` / `sns:Endpoint` keys. The consequence is concrete: the
decoder prints `[!] PUBLIC` on the AWS default SNS topic policy. Use it for the shape-safe
verdict, then re-read every `[!] PUBLIC` line for those keys before acting. The decoder
also never reports the `Action` set, so it cannot tell a public *publish* grant from a
public *subscribe* grant — that split is what the playbook's `jq` pass adds.

## "Was it used" — and why the obvious pivot returns zero

`sns:Publish` and `sns:PublishBatch` are CloudTrail **data** events. The published event
carries `"eventCategory": "Data"` and `"managementEvent": false`, the resource type is
`AWS::SNS::Topic`, and data events are off by default. On a default trail
`lookup-events` returns zero `Publish` records forever, and that zero is "not logged",
never "not abused". The pivot is the CloudWatch metric `AWS/SNS`
`NumberOfMessagesPublished` on dimension `TopicName`, compared across the grant.

Even with a data-event trail, `requestParameters.message`, `.subject` and
`.messageAttributes` are recorded as the literal `HIDDEN_DUE_TO_SECURITY_REASONS`. What
was injected is not recoverable from CloudTrail under any configuration.

## Response levers

**Error strings:** SNS does not use `AccessDenied`. A denied call surfaces as **`AuthorizationError`** (403).
The full set `CreateTopic` can throw is `AuthorizationError`, `ConcurrentAccess`,
`InternalError`, `InvalidParameter`, `InvalidSecurity`, `StaleTag`, `TagLimitExceeded`,
`TagPolicy`, `TopicLimitExceeded`; `SetTopicAttributes` throws `AuthorizationError`,
`InternalError`, `InvalidParameter`, `InvalidSecurity`, `NotFound`. An over-large or
malformed policy is rejected as `InvalidParameter` — there is no `LimitExceeded` on this
path. Confirm against a real denied event before building on any of these.

**No oversized-document companion rule ships.** CloudTrail omits `requestParameters` only
above 100 KB. AWS publishes no explicit size quota for the SNS *access* policy — the
nearest documented SNS policy-document cap is 30,720 characters, and that is on
`DataProtectionPolicy`, a different attribute. No documented SNS policy path approaches
100 KB, so there is no size-based evasion route to detect; the useful fact is the error
string above, not a rule.

**GuardDuty:** There is no GuardDuty finding type specific to an SNS topic policy grant.
`Policy:S3/BucketAnonymousAccessGranted` has no SNS equivalent. Do not list GuardDuty as
a detection source for this use case.

**MITRE:** The source rule maps this to **T1213 (Data from Information Repositories)** under
Collection. That is wrong in direction: granting publish rights lets an outsider *write*
to the topic. Nothing is read and nothing is collected. The shipped mapping is
**T1098 — Account Manipulation** for the grant itself, consistent with how this corpus
maps every other AWS resource-policy backdoor, plus **T1565.002 — Data Manipulation:
Transmitted Data Manipulation** for the consequence, since the attacker is inserting
records into a live message stream that downstream consumers trust. T1213 is the correct
mapping for the sibling use case,
`sns.collection.sns-topic-was-created-with-public-subscribe-permissions`, where data does
flow outward. The directory name preserves the source rule's tactic label; the playbook
and these rules carry the corrected one.

**Severity:** **High.** A single event puts an internet-reachable write path into a message bus that
fans out to Lambda, SQS, HTTPS endpoints, email and SMS subscribers — each of which
processes the message as if it came from inside the account. The source rule rates it P3.
That is too low: P3 implies triage-when-convenient, and this exposure is live from the
moment the policy is stored, with no confirmation step and no rate limit beyond the
account's publish quota. It is not P0 only because the attacker gains no credential and
no path to the control plane; the damage is bounded by what the subscribers do with a
message.

**Files here:**

- `sigma_t1098.yml` — four documents: `sns_public_publish_at_create` (high, the CreateTopic
  path), `sns_public_publish_via_set_attributes` (high, the SetTopicAttributes path the
  original rule missed), `sns_topic_policy_write_unexpected_principal` (low, base rule)
  and a `value_count` correlation over it (medium, scripted policy sweep).
- `kql_t1098.kql` — the authoritative version: parses the policy and judges each
  statement on its **own** Condition, which the Sigma document-wide substring test cannot.

Full response procedure is in `../PLAYBOOK.md`. The read-side sibling is
`../../sns.collection.sns-topic-was-created-with-public-subscribe-permissions/`; the
broader policy-change signal, including the `AddPermission` path, is
`../../sns.persistence.topic-policy-modified/`.

Full response procedure is in `../PLAYBOOK.md`.
