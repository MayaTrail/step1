# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Immediate rule over a query string |
| Scope captured | One rule: SNS Access Policy Has Changed |
| Retrieved | 2026-08-31 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

## The rule's name and its logic describe different features

It is called *SNS Access Policy Has Changed* and it matches `PutDataProtectionPolicy`.

A data protection policy audits, de-identifies or denies sensitive data inside message **bodies**. It
has nothing to do with who may publish to or subscribe to a topic. The access policy is set by
`SetTopicAttributes` with `AttributeName=Policy`, or composed by `AddPermission`, or supplied as an
attribute at `CreateTopic`.

**And the feature the rule does match is closed.** AWS: "Amazon SNS message data protection is no
longer available to new customers." In most accounts the API cannot be called at all, so the rule has
never fired and never will — while the rule list reports the access policy as covered.

This is the same defect class as the DynamoDB *Multiple Update Operation Performed* rule, which
matches `UpdateTable` rather than `UpdateItem`, but with a worse consequence: there, the named thing
was covered elsewhere. Here it is not covered at all.

## What is actually uncovered

Two sibling rules in this source set match `CreateTopic` carrying a public policy — see
`../../sns.collection.sns-topic-was-created-with-public-publish-permissions/` and
`../../sns.collection.sns-topic-was-created-with-public-subscribe-permissions/`. Both are creation-time
only.

Neither of the two post-creation paths is matched anywhere in the source set:

- **`SetTopicAttributes` with `AttributeName=Policy`** replaces the entire document, so principals are
  removed by being left out and added by appearing.
- **`AddPermission`** is simpler still: it "adds a statement to a topic's access control policy,
  granting access for the specified AWS accounts", taking an account id and an action name rather than
  a policy document. Making a topic readable by another account is two parameters and no JSON.

An actor who makes an existing topic public produces no alert. That is the gap this playbook fills,
and `AddPermission` is the call to expect.

## Merge test — applied, not assumed

`PutDataProtectionPolicy` is kept in this playbook rather than given its own, and it is not merged
away either.

**Same asset?** Yes — the policy documents attached to one topic.
**Same response?** Yes — read the current policies, diff against the baseline, revert the change,
identify who was granted what in between.
**Same decision?** Yes — was an external principal granted access to messages.

They differ in *which* messages: the access policy decides who receives them, the data protection
policy decides how much of each message is visible to a receiver. Removing the latter unredacts
message bodies for everyone already subscribed, which is a real disclosure and belongs beside the
former rather than in a directory of its own.

**MITRE:** `T1098 — Account Manipulation` for the grant that preserves access, consistent with
`../../sns.collection.sns-topic-was-created-with-public-publish-permissions/`; `T1213 — Data from
Information Repositories` for the subscribe side, consistent with the subscribe sibling. Both verified
live 2026-08-31. The source's `T1098/TA0003` is kept for the technique and the tactic is right.

**Tier:** 1, on criterion 2 of `07-TIERS.md` — *the response has ordering that can go wrong*.

Service ground truth for the `sns.*` playbooks authored against it is in `../../_ground-truth/sns.md`,
audited 2026-08-31. §1 covers the three access-policy paths; §2 covers the data-protection confusion.
