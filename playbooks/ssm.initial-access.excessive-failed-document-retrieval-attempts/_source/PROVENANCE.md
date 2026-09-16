# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, threshold, window, group-by keys and MITRE labels |
| Scope captured | One alert — the failed-retrieval volume rule this playbook is written against |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alert captured

| Alert | Priority | Source MITRE label | Threshold | Window | Group-by |
|-------|----------|--------------------|-----------|--------|----------|
| Excessive Failed Document Retrieval Attempts | P2 | T1110 / TA0001 | 10 | 5m | `userIdentity.sessionContext.sessionIssuer.userName` |

The `errorCode:"AccessDenied"` clause is preserved verbatim in the extract's query
line, because §2 of `../PLAYBOOK.md` argues that this specific literal is the
rule's central defect and the claim has to be checkable rather than taken on the
playbook's word.

## No merge

One source rule, one use case, one playbook — the default in `07-TIERS.md`.
Neither merge test applies. The closest sibling is
`ssm.discovery.excessive-document-creation-detected`, which touches the same
resource type, but reading and authoring a document are different observables with
different responses: enumeration is answered by scoping read permissions and
checking what the documents disclosed, while authoring is answered by cancelling
dispatch, capturing content and deleting. They cross-reference each other rather
than merging.

## Tier

**Tier 2 (lean).** None of the five Tier-1 tests applies. No account takeover is
one hop away — a document name is not a credential and a successful read grants
nothing the principal did not already hold. The response has no ordering hazard:
nothing is severed and nothing races. The blast radius is in the events plus the
document contents, both retrievable at leisure. Nothing in the remediation destroys
evidence. Test 5 — a structural blind spot worth a page — is the near miss: the
enumerator who *has* `ssm:GetDocument` produces no errors at all and is invisible
to every error-based rule. That is a real gap, but it is covered by a second
correlation in the shipped rules and explained in three paragraphs, not a page.

## The source rule's MITRE label

Recorded in the extract as `T1110/TA0001` and disputed in §6 of `../PLAYBOOK.md`.
Nothing is being brute-forced: `GetDocument` takes a document name, not a
credential, and a correct guess grants no access the caller did not already have.
The behaviour is enumeration of a cloud service's contents — T1526 (*Cloud Service
Discovery*) under Discovery (TA0007). The mislabel has an operational cost, not
just a taxonomic one: a "brute force" alert routes to a credential-stuffing
runbook and the responder looks for a compromised password that does not exist.
The label is carried in `original_rules.yml` so the dispute is checkable against
the extract.

## Directory naming

The slug preserves the source rule's own tactic label (`initial-access`) so the
register stays navigable against the alert set, even though §6 disputes it. The
same convention is applied across all five Systems Manager use cases; where the
source label and the corrected mapping agree — `ssm.credential-access.*` and
`ssm.impact.*` — nothing needs saying.

## Attribution and de-identification

**No source, vendor, product or repository is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim"
instruction (workflow step 0) deliberately. The originals are packaged in a
proprietary format whose scaffolding — payload field lists, entity labels,
product-specific field prefixes, internal enums and packaging metadata —
identifies the source on sight while bearing on nothing about whether the rules
are correct. What is retained is the complete detection logic: name, priority,
type, MITRE label, the Lucene query verbatim, threshold, window and group-by.
Every claim in the "Detection Rule Quality Notes" table in `../PLAYBOOK.md` §2 is
checkable against it.

One shared extractor change was needed for this alert family and is carried
corpus-wide: the extractor's alert-name prefix list had no entry for this service,
so the service-name prefix survived into the extract where every sibling family
has it stripped. The entry was added; the change is additive and regenerates every
existing extract unchanged.

The shipped `references:` blocks in `detections/` cite public MITRE and AWS
documentation only — a deployed rule travels outside the organisation that wrote
it, and an internal path is not resolvable to whoever receives it.

## A note on the file's shape

`threshold: 10.0  window: 5m` puts two mapping keys on one line and is therefore
not strictly parseable YAML — a corpus-wide property of the extractor's output
format, left alone rather than fixed here so this technique does not diverge from
the rest (rule E5). The file is read by people and diffed against the shipped
rules; nothing parses it.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.
