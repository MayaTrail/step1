# Detection Note — T1213 (SNS topic opened for public subscribe)

**Signal:** an SNS access policy that allows a subscribe-granting action to
`Principal: "*"` with no principal-scoping `Condition`, letting any caller on the internet
attach their own endpoint and receive every message the topic carries from then on.

**A subscription outlives the grant, and that is what separates this from its publish-side
sibling.** Removing the public statement does not detach anything already attached. The
obvious fix — rewrite the policy — leaves a confirmed rogue subscriber receiving traffic
indefinitely, and nothing in the topic's configuration flags it as unauthorised. Eradication
is therefore an enumerate-and-delete over `ListSubscriptionsByTopic`, not a policy edit, and
the policy edit is only what stops the *next* subscriber.

**The moment a subscription goes live is invisible.** AWS documents that
`ConfirmSubscription` and `Unsubscribe`, when invoked in unauthenticated mode, "will not be
logged to CloudTrail" — and the emailed or POSTed confirmation link *is* unauthenticated
mode. Every `http`, `https`, `email` and `email-json` subscription is confirmed that way. So
the `Subscribe` call is the last observable event; whether the subscription became active is
answerable only by enumerating the live list. The same gap runs the other way: with
`AuthenticateOnUnsubscribe` left at its default of false, an unauthenticated *unsubscribe*
also succeeds and is also unlogged, so an actor holding a confirmation token can silently
detach your legitimate subscribers.

**What the original rule got wrong**

1. **It cannot fire.** It phrase-matched `Principal:{AWS:*},Action:[SNS:Subscribe]`.
   CloudTrail carries `requestParameters.attributes.Policy` as a **raw JSON string** — per
   the corrected A4, request parameters are raw and percent-encoding is a response-side IAM
   property that does not apply here — so the real bytes are `"Principal":{"AWS":"*"}`, with
   quotes, in client-chosen key order and whitespace.
2. **Wrong event-name case** — `eventName:"createtopic"`; CloudTrail writes `CreateTopic`.
3. **`CreateTopic` only.** A topic created correctly and opened later by
   `SetTopicAttributes` with `AttributeName=Policy` produced no matching event.
4. **No `Condition` test.** Had the phrase matched, it would have fired on every
   console-created topic, because AWS's default topic policy carries both the wildcard
   principal and `SNS:Subscribe`.
5. **It stops at the grant.** Nothing in the rule set looks at `Subscribe` itself, so the
   exercise of the grant — the part that actually moves data — was undetected.

## The action set, and the two shapes a token match misses

`"Action": "SNS:Subscribe"` is the obvious form. Two others grant subscribe and carry no
`:Subscribe` substring: a **service or global wildcard** (`"sns:*"`, `"*"`, in scalar or
array form), and **`NotAction`** — an `Allow` with `NotAction` grants everything except what
it lists, so a public statement with `"NotAction": ["sns:DeleteTopic"]` hands the internet
subscribe, publish and policy rewrite while containing no action token at all. Both shipped
rules and the KQL cover all three; `NotAction` is graded as the widest verdict.

`SNS:Receive` is matched as well. It is a legacy action token that appears in older
hand-written topic policies alongside `SNS:Subscribe`. **Not verified:** the current AWS
Service Authorization Reference page did not render its full action list on retrieval, so
whether `sns:Receive` is still a recognised IAM action is unconfirmed. Matching it costs
nothing — the failure direction is an extra look at a policy — but do not cite it as current.

## Shape guards, and the gap in the shared decoder

IAM accepts `Statement` as a single object or an array, `Principal` as an object or the bare
string `"*"`, and `Action` as a string or an array.
`tools/decode_policy_documents.py` normalises all three and is the right tool for the
who-holds-it question.

**But its `auto` mode does not recognise `aws:SourceOwner` as a confining condition key.**
`TRUST_CONFINERS` — the tuple the trust path consults, and a `Principal`-bearing SNS
statement routes to the trust path — carries `aws:sourcearn`, `aws:sourceaccount`,
`aws:principalorgid` and `aws:sourcevpce`, but not `aws:sourceowner`, and not the
SNS-specific `sns:Protocol` / `sns:Endpoint`. AWS's default SNS topic policy is confined by
`AWS:SourceOwner`, so the decoder prints `[!] PUBLIC` on the single most common legitimate
shape in any account. The decoder also never reports the `Action` set, so it cannot tell a
public *subscribe* grant from a public *publish* grant. `tools/sns_topic_policy_grade.py`
exists for both gaps and carries a self-test pinning the default-policy case.

## "Was it used" — this one has a real answer

Unlike the publish side, `Subscribe` **is** a CloudTrail management event and is on by
default, so `lookup-events` answers directly. Corroborate three ways, because each is
incomplete alone:

- `Subscribe` events in the window — shows intent, but not whether confirmation happened.
- `aws sns list-subscriptions-by-topic` — the authoritative live list, and the only source
  that survives the unlogged-confirmation gap. `SubscriptionArn` of `PendingConfirmation`
  marks one that never completed.
- CloudWatch `AWS/SNS` `NumberOfNotificationsDelivered` on dimension `TopicName` — volume
  delivered. Message bodies appear in no CloudTrail record at any configuration.

Do not rely on `responseElements.subscriptionArn == "pending confirmation"` as proof a
subscription is inactive: AWS returns that literal only when `ReturnSubscriptionArn` is
false, which is merely the default. A caller passing `true` gets a real ARN back for an
unconfirmed subscription.

## Response levers

**Error strings:** SNS does not use `AccessDenied`; a denied call is **`AuthorizationError`** (403).
`Subscribe` throws `AuthorizationError`, `FilterPolicyLimitExceeded`, `InternalError`,
`InvalidParameter`, `InvalidSecurity`, `NotFound`, `ReplayLimitExceeded` and
`SubscriptionLimitExceeded`. `CreateTopic` throws `AuthorizationError`, `ConcurrentAccess`,
`InternalError`, `InvalidParameter`, `InvalidSecurity`, `StaleTag`, `TagLimitExceeded`,
`TagPolicy`, `TopicLimitExceeded`; `SetTopicAttributes` throws `AuthorizationError`,
`InternalError`, `InvalidParameter`, `InvalidSecurity`, `NotFound`. An over-large or
malformed policy is rejected as `InvalidParameter` — there is no `LimitExceeded` here.
Confirm against a real denied event before building on any of these.

**No oversized-document companion rule ships.** CloudTrail omits `requestParameters` only
above 100 KB. AWS publishes no size quota for the SNS *access* policy; the nearest documented
SNS policy cap is 30,720 characters and it applies to `DataProtectionPolicy`, a different
attribute. No documented SNS policy path approaches 100 KB, so there is no size-based evasion
route to detect.

**GuardDuty:** No GuardDuty finding type is specific to an SNS topic-policy grant or to a rogue SNS
subscription. Do not list GuardDuty as a detection source for this use case.

**MITRE:** **T1213 — Data from Information Repositories** is retained as primary and is defensible
here: the grant produces a standing read of a message stream the organisation treats as an
internal channel, and the data flows outward. That is genuinely collection, unlike the
publish-side sibling, whose T1213 mapping is wrong in direction and is corrected to T1098 /
T1565.002 in `../../sns.collection.sns-topic-was-created-with-public-publish-permissions/`.
**T1098 — Account Manipulation** is carried as a second tag for the policy write itself,
matching how this corpus maps every other AWS resource-policy backdoor.

**Severity:** **High.** A single event creates a standing, unauthenticated read of everything the topic
carries, and the read survives the obvious remediation. The source rule rates it P3, which
is too low for a condition whose exploitation window opens immediately and whose evidence of
exploitation — the confirmation — is never logged. It is not P0 only because the actor gains
no credential and no control-plane path, and because the sensitivity ceiling is whatever the
topic actually carries: an alarm-notification topic and a customer-PII fan-out topic produce
the same event and warrant very different responses. Triage on the topic's content, not on
the event.

**Files here:**

- `sigma_t1213.yml` — four documents: `sns_public_subscribe_at_create` (high),
  `sns_public_subscribe_via_set_attributes` (high, the path the original rule missed),
  `sns_subscribe_offaccount_endpoint` (medium, the exercise) and a `temporal_ordered`
  correlation tying the grant to its exercise (high). The correlation groups on
  `requestParameters.topicArn`, which both component rules emit — the `CreateTopic` rule is
  deliberately excluded because it carries the ARN in `responseElements` and would silently
  never group.
- `kql_t1213.kql` — the authoritative version: parses the policy, judges each statement on
  its **own** `Condition`, and joins the grants to the subscriptions that followed them.

Full response procedure is in `../PLAYBOOK.md`. The write-side sibling is
`../../sns.collection.sns-topic-was-created-with-public-publish-permissions/`; the broader
policy-change signal, including the `AddPermission` path, is
`../../sns.persistence.topic-policy-modified/`.

Full response procedure is in `../PLAYBOOK.md`.
