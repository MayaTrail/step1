# Amazon SNS — verified service behaviour

Audited 2026-08-31 against AWS documentation. Every claim below is quoted or directly derived from
a cited page. Shared by the `sns.*` playbooks authored against it; do not restate it in each one.

Sources:
- https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html
- https://docs.aws.amazon.com/sns/latest/api/API_AddPermission.html
- https://docs.aws.amazon.com/sns/latest/api/API_DeleteTopic.html
- https://docs.aws.amazon.com/sns/latest/api/API_PutDataProtectionPolicy.html
- https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html

---

## 1. Three different calls change a topic's access policy

| Call | How |
|---|---|
| `CreateTopic` | `Attributes.Policy` at creation time |
| `SetTopicAttributes` | `AttributeName=Policy`, `AttributeValue=<full JSON document>` |
| `AddPermission` | Names accounts and actions directly; SNS composes the statement for you |

`AddPermission` is the one to expect from an actor: it "adds a statement to a topic's access control
policy, granting access for the specified AWS accounts" and takes an account id and an action name
rather than a policy document. Making a topic readable by another account is two parameters.

`SetTopicAttributes` with `AttributeName=Policy` **replaces** the whole document, so a principal is
removed by being left out.

Two rules in this source set match `CreateTopic` with a public policy. Neither of the other two calls
is matched anywhere, so a topic made public *after* creation is not detected at all.

## 2. `PutDataProtectionPolicy` is not the access policy, and the feature is closed

A data protection policy audits, de-identifies or denies sensitive data inside message **bodies**. It
has nothing to do with who may publish or subscribe.

AWS also states: "**Amazon SNS message data protection is no longer available to new customers.**"

So a rule named for the access policy that matches `PutDataProtectionPolicy` is watching a different
feature — and one that most accounts cannot use at all, which is why it never fired and never will.

## 3. `DeleteTopic` takes the subscriptions and cannot fail

AWS: "Deletes a topic **and all its subscriptions**. Deleting a topic might prevent some messages
previously sent to the topic from being delivered to subscribers."

And: "This action is **idempotent**, so deleting a topic that does not exist does not result in an
error."

Two consequences. Recovery is not "recreate the topic" — every subscription is gone and each one has
to be recreated and, for email and HTTPS endpoints, **re-confirmed by the subscriber**. And a
successful `DeleteTopic` in CloudTrail is not evidence that the topic existed, so an actor can sweep
guessed ARNs and every call returns success.

Recreating a topic with the same name is also not instant: SNS returns a stale-tag error for a while
after a resource with that ARN is deleted.

## 4. CloudWatch never tells you the notification went nowhere

The sentence that makes topic deletion a defence-impairment technique rather than an outage:

> "CloudWatch doesn't test or validate the actions that you specify, nor does it detect any Amazon EC2
> Auto Scaling or Amazon SNS errors resulting from an attempt to invoke nonexistent actions. Make sure
> that your alarm actions exist."

An alarm whose action points at a deleted topic still evaluates, still transitions to `ALARM`, and
still reports itself as healthy in the console. The notification is simply dropped, silently, with no
error anywhere.

The same holds for anything else publishing to the topic — GuardDuty finding notifications, Config
rules, Security Hub, Budgets. Deleting one topic can therefore remove several independent alerting
paths at once without producing a single error.

## 5. Event-name casing in this source set

Sibling rules in this source set match `createtopic` and `settopicattributes` in lowercase. CloudTrail
emits `CreateTopic` and `SetTopicAttributes`; on a case-sensitive field the lowercase forms match
nothing. Same defect class as `dynamodb.md` §5.

The two rules authored here — `PutDataProtectionPolicy` and `DeleteTopic` — are correctly cased, and
are the exception rather than the rule.

## MITRE currency, verified 2026-08-31

| ID | Name | Status |
|---|---|---|
| T1098 | Account Manipulation | live |
| T1213 | Data from Information Repositories | live |
| T1685 | Disable or Modify Tools | live |
| T1489 | Service Stop | live |
| T1485 | Data Destruction | live |

