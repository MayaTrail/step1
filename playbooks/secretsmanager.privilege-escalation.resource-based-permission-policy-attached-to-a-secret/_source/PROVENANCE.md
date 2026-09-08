# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, type, threshold, window, group-by keys and MITRE labels |
| Scope captured | One alert — the resource-policy rule this playbook is written against |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alert captured

| Alert | Priority | Type | Source MITRE label | Threshold | Window | Group-by |
|-------|----------|------|--------------------|-----------|--------|----------|
| Resource Based Permission Policy Attached to a Secret | P3 | threshold | T1098 / TA0004 | 0 | 10m | `userIdentity.sessionContext.sessionIssuer.userName` |

## No merge

One source rule, one use case, one playbook — the default in `07-TIERS.md`. Neither merge
test applies.

Test 1 fails on both halves. No sibling alert in the set observes `PutResourcePolicy`, so
there is no rule with the identical event shape to be a threshold variant of. And the
response is unlike every neighbour's: this is the only Secrets Manager use case whose
artefact is not on a principal, so containment is "remove a document from a resource"
rather than "revoke a principal's sessions", and eradication has to sweep every other
secret for the same grant.

Test 2 fails because this is not a flow rule and composes nothing.

| Considered | Verdict |
|------------|---------|
| `../../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/` | **Separate.** Related as cause to effect — a resource policy is one way a principal comes to be able to read secrets — but the observable, the containment and the evidence limits all differ. The grant is the thing to remove here; the plaintext is the thing to rotate there. Cross-referenced in both directions |
| `../../secretsmanager.persistence.secret-value-replaced/` | **Separate.** `UpdateSecret` appears in this playbook only as the *enabling* step for a cross-account grant — re-keying a secret from the AWS managed key to a customer-managed one is what makes an external grant usable at all. That is a cross-reference, not a merge: different event, different response |

## Tier

**Tier 1 (full).** Earned on test 1 of `07-TIERS.md` — *account takeover is reachable in
one further hop* — and test 3 — *the blast radius is not in the event, and getting it
after containment is impossible*.

Test 1: AWS documents the escalation in its own words — *"Resource-based policies granting
`secretsmanager:PutResourcePolicy` permission gives principals, even those in other
accounts, the ability to modify your resource-based policies. This permission lets
principals escalate existing permissions like obtaining full administrative access to
secrets."* A grant that includes that action is self-perpetuating: removing the grantee
from the document does not remove them. And what the grant discloses is a secret's
plaintext, which routinely includes AWS credentials — the further hop.

Test 3: the blast radius is the **set of principals now holding access**, and it exists in
exactly one place — the policy document. `PutResourcePolicy` echoes only ARN and Name;
`DeleteResourcePolicy` returns nothing at all. Once the policy is removed, the document
survives only in the CloudTrail request parameter, and only for the trail's retention
window. The account-wide form of the question — *which other secrets already carry a
foreign grant* — is not derivable from any event and requires a `GetResourcePolicy` sweep
over every secret in every Region, which is a §2 query rather than a lookup.

Test 4 partially applies and is worth naming: the remediation is `DeleteResourcePolicy`,
which destroys the only live copy of the evidence. That is why §3's first containment step
captures the document before removing it, rather than after.

## The source rule's MITRE label

Recorded in the extract as `T1098/TA0004`, and this one is **correct** — unusually for
this alert set. T1098 (*Account Manipulation*) covers actions that preserve or extend an
adversary's access, and TA0004 (Privilege Escalation) is one of the two tactics MITRE
lists for it. The playbook keeps it as primary and adds T1555.006 as a secondary for what
the grant actually discloses. §6 records the reasoning; there is no mapping dispute here.

## Directory naming

The slug preserves the source rule's own tactic label (`privilege-escalation`) so the
register stays navigable against the alert set, and here the source label and the corrected
mapping agree.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals
are packaged in a proprietary format whose scaffolding — payload field lists, entity
labels, product-specific field prefixes, internal enums and packaging metadata —
identifies the source on sight while bearing on nothing about whether the rules are
correct. What is retained is the complete detection logic: name, priority, type, MITRE
label, the query verbatim, threshold, window and group-by.

One de-identification artefact is worth flagging for the reader of the extract: the source
query carries an internal role-name exclusion, which the extractor leaves in place because
it is detection logic rather than packaging. It is a tuning exclusion for a monitoring
role, not a security-relevant condition, and the shipped rules replace it with a named
`policy_admins` allowlist.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS
documentation only — a deployed rule travels outside the organisation that wrote it, and
an internal path is not resolvable to whoever receives it.

## A note on the file's shape

`threshold: 0.0  window: 10m` puts two mapping keys on one line and is therefore not
strictly parseable YAML — a corpus-wide property of the extractor's output format, left
alone rather than fixed here so this technique does not diverge from the rest (rule E5).
The file is read by people and diffed against the shipped rules; nothing parses it.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.
