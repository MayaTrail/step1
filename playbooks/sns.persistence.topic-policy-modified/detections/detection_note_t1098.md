# Detection Note — T1098 (Account Manipulation)

**Signal:** a topic's access policy changing **after** the topic was created.

## The name and the logic describe different features

The rule is called *SNS Access Policy Has Changed*. It matches `PutDataProtectionPolicy`.

A data protection policy audits, de-identifies or denies sensitive data inside message **bodies**. It
decides how much of a message a receiver sees. It has nothing to do with who may publish or
subscribe.

## And the feature it matches is closed

AWS: *"Amazon SNS message data protection is no longer available to new customers."*

Most accounts cannot call the API at all, so this rule has never fired and never will — while the
rule list reports the access policy as covered. That is worse than the equivalent DynamoDB
name/logic mismatch, where the named thing was at least covered elsewhere.

## The access policy has three paths and two are uncovered

| Path | Covered in the source set |
|---|---|
| `CreateTopic` with `Attributes.Policy` | Yes — two sibling rules |
| `SetTopicAttributes` with `AttributeName=Policy` | **No** |
| `AddPermission` | **No** |

`AddPermission` is the one to expect. It "adds a statement to a topic's access control policy,
granting access for the specified AWS accounts", taking an account id and an action name — no JSON
document, no policy syntax. Opening an existing topic to another account is two parameters.

A topic made public after creation therefore produces no alert anywhere in the source set.

## Response levers

**`SetTopicAttributes` replaces the document.** A principal is added by appearing and removed by being
left out, so the event carries the new policy and never says what changed. Diffing against a baseline
is the only way to see a removal.

**Look for a `Subscribe` after the grant.** Opening a topic is preparation; a subscription to an
endpoint outside the account is the exfiltration channel actually being built.

**Publish access is the other direction.** A granted `sns:Publish` lets an actor inject messages into
whatever consumes the topic — which, for an alerting topic, means fabricated notifications.

**MITRE:** `T1098 — Account Manipulation` for the grant, consistent with
`../../sns.collection.sns-topic-was-created-with-public-publish-permissions/`; `T1213 — Data from
Information Repositories` for the subscribe side, consistent with the subscribe sibling. Both verified
live 2026-08-31.

**GuardDuty:** no finding type covers SNS topic policy changes.

**Files here:**
- `sigma_t1098.yml` — five documents: `AddPermission` naming an external account (high), a replaced
  policy with a wildcard principal (critical), `sns_topic_policy_changed` as the informational base
  rule, the data protection policy correctly described (medium), and a three-topics correlation (high).
- `kql_t1098.kql` — covers all three access-policy paths, tests the submitted document for wildcards
  and external accounts, and rates a grant followed by a subscription above either alone.

Full response procedure is in `../PLAYBOOK.md`.
