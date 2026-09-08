# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The single ECS Exec alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| Command Executed Inside a Container | P2 | per-event | T1078/TA0001 |

## Tier decision — promoted to Tier 1

This use case ships a **full (Tier 1) playbook**, promoted under `07-TIERS.md`. Three of the
five promotion tests apply, and they are named rather than gestured at:

**Test 1 — account takeover is reachable in one further hop.** The session runs as `root`
inside a container that holds an AWS identity. The task role's temporary credentials are
readable from the ECS container credentials endpoint, and AWS documents them as valid for six
hours and rotated automatically. A task role carrying IAM, Secrets Manager or broad data
permissions makes one `ExecuteCommand` the last step before the account.

**Test 3 — the blast radius is not in the event, and getting it after containment is
impossible.** `ExecuteCommand` carries `cluster`, `command`, `container`, `interactive` and
`task`, and no role. Establishing what the container could reach requires task → task
definition → `taskRoleArn` → attached policies, and the first hop is time-bounded: AWS states
stopped tasks appear in results *"for at least one hour"*. Stop the task before resolving its
definition and the blast radius may be unrecoverable — which is why the evidence query precedes
every containment step in §3.

**Test 5 — the detection has a structural blind spot worth a page of honesty.** For an
interactive session CloudTrail records the shell binary and nothing typed inside it, and the
session transcript is not produced by default: `logging: DEFAULT` means "use the task
definition's `awslogs` driver", and without one "the output won't be logged". Even a correct
`OVERRIDE` fails silently on an image lacking `script` and `cat`. Separately, a session opened
via `ssm:StartSession` produces no `ecs.amazonaws.com` event at all.

Test 2 (ordering that can go wrong) also holds — disabling ECS Exec does not affect running
tasks, and session revocation must precede stopping the task — but three tests are already more
than the threshold, and Test 2 is documented in §3 rather than claimed here.

## Merge decision — no merge

**One source rule, one playbook.** Neither of `07-TIERS.md`'s two merge tests is met:

| Candidate | Test 1 — same observable, same response, differing only in threshold? | Test 2 — pure composition of shipped building blocks? | Verdict |
|-----------|------|------|---------|
| Any other rule in the ECS source set | **No.** No other rule in the set touches `ExecuteCommand`, the task role, or the SSM data path. This is the only credential-access use case among the seven | No | **Separate** |
| `../../ec2.credential-access.imds-credential-theft/` | **No.** Different endpoint (`169.254.170.2` versus `169.254.169.254`), different identity (task role versus instance profile), different session-name shape (task ID versus instance ID) and different controls — IMDSv2 has no bearing on the ECS endpoint. Cross-referenced, not merged | No | **Separate** |

## A finding about the source rule, not about the technique

The alert's query requires `userIdentity.accountId:"anonymous"`. CloudTrail documents
`accountId` as *"the account that owns the entity that granted permissions for the request"* and
enumerates no `anonymous` value; ECS has no unauthenticated API surface, since `ExecuteCommand`
is a SigV4-signed call authorised by IAM. **The conjunct is never satisfied, so the rule has
never fired and cannot.** It is reported here because a rule that is inert produces no errors and
no alerts, which is indistinguishable from an account in which nobody uses ECS Exec — the
failure is invisible from inside the alerting platform, which is exactly the class this corpus
keeps finding in its own output.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| The source set's `RegisterTaskDefinition with Resource-Intensive Parameters` alert | **Separate, and out of scope for this batch.** It matches only `cpu`/`memory` digit counts and never inspects `image`, `command` or `taskRoleArn`, so the persistence path a task definition provides is uncovered by it. Recorded as a gap in `../PLAYBOOK.md` §6 |
| An `ssm:StartSession` rule | **Not a source rule.** AWS documents the direct SSM path as producing no ECS-side log, and the source set has no SSM-side alert to merge. It is carried as a P3 trigger row and as a containment control, and its absence from detection is stated as a gap rather than hidden |

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project
— including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals
are packaged in a proprietary format whose scaffolding — payload field lists, entity
labels, product-specific field prefixes, internal enums and packaging metadata —
identifies the source on sight while bearing on nothing about whether the rules are
correct. What is retained is the complete detection logic: name, priority, type, MITRE
label, the query verbatim, threshold, window and group-by.

No substitution was needed in this extract.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS
documentation only — a deployed rule travels outside the organisation that wrote it, and
an internal path is not resolvable to whoever receives it.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.
