# Detection Note — T1496 (Resource Hijacking) / T1078.004 (Valid Accounts: Cloud Accounts)

**Signal:** one principal driving unusual model-invocation volume, reaching an unusual number of
distinct models, or invoking from a Region the organisation does not use.

**The source rule is a building block with no logic**, so there is nothing here to correct. All four
Bedrock entries in the pack are CloudWatch metric alarms for cost and availability — no query, no
threshold, no grouping. This playbook is a new security use case rather than a corrected rule, and
the §2 table says that rather than manufacturing defects in an empty rule.

**Why the exposure is worth a detection of its own.** A credential carrying `bedrock:InvokeModel`
spends money at the account owner's expense and produces text on demand. It slips past three
categories of control at once: nothing is exfiltrated, so data-loss tooling sees nothing; no
instance is launched, so compute-abuse tooling sees nothing; and the cost lands in a service most
accounts do not have a budget alarm on. The first indication is frequently the bill.

## Model breadth fires earlier than volume, and on far less traffic

A legitimate workload uses one model, or a small fixed set chosen at design time and changed by a
deployment. A credential that has just been picked up gets tried against everything it can reach —
to find which models are enabled in which Regions, and which gives the most capable output.

So `dcount(modelId)` per principal is the better of the two signals: it fires within a handful of
calls, where a volume threshold needs the abuse to already be expensive. The Region rule is the same
logic one level up — model access is enabled per Region and per model, so an actor exploring a
credential spreads across Regions, and a Region nobody operates in is a Region nobody watches.

## Two planes, and most accounts have only one

**Model invocation logging is disabled by default.** AWS: *"Model invocation logging is disabled by
default."* Without it there is no record of the prompt or the response anywhere, and no token
counts — which are the cost measure.

CloudTrail's `bedrock-runtime` data events give the principal, the model, the Region and the source
address, and never the content. Both views are shipped, with the CloudTrail one in the KQL's second
section, because assuming the invocation log exists would make the whole playbook inapplicable to
the common case.

Neither can be applied retroactively, so the preparation item in §1 is the one that decides what an
incident will look like.

## `identity.arn` is the actor field; `requestMetadata` is not

AWS: `identity.arn` is *"captured automatically"*, and `requestMetadata` is *"the only field
supplied by the caller"*. Caller-supplied means **attacker-supplied when the caller is the
attacker** — so it must never be a grouping key, a filter, or a trust signal in a security rule. The
KQL projects it and uses it for nothing, which is the only safe handling.

The grouping in the KQL strips the session name from an assumed-role ARN so a role's sessions group
together, while the full ARN stays available for the pivot into CloudTrail.

## Response levers

**Revoking is the containment and it is ordinary.** This is a credential-misuse incident: the
credential is an access key or a role session, and
`../../ec2.credential-access.imds-credential-theft/` §3 covers the case where there is no IAM
object behind it. Nothing about Bedrock changes that procedure.

**Quantify the spend from token counts where they exist**, and from Cost Explorer where they do not.
`inputTokenCount` and `outputTokenCount` are per invocation in the model invocation log; with
CloudTrail alone the call count is the only volume figure available and the cost question goes to
billing.

**Output vastly exceeding input is content production**, not an application answering questions —
short prompts producing long generations is the shape of a credential resold for generation
capacity rather than used against your data. It is a soft signal and it is in the KQL verdict for
that reason.

**One documented gap that is not configurable.** AWS: invocation logging covers the
`bedrock-runtime` endpoint, and *"calls made through other endpoints... are not currently captured
by invocation logging."* A caller reaching the same models by another endpoint produces no
invocation log at all.

**MITRE:** the source maps this to nothing. `T1496 — Resource Hijacking` for the outcome,
`T1526 — Cloud Service Discovery` for the model-breadth rule, and `T1078.004 — Valid Accounts:
Cloud Accounts` for the unused-Region rule. All verified live 2026-08-30.

**Severity:** high for model breadth and for sustained volume, medium for an unexpected Region —
which is rated lower only because a legitimate team adopting a new model produces it, and that is
common enough to be a real explanation rather than a rare one.

**GuardDuty:** no coverage. There is no finding type for Bedrock usage, and GuardDuty's credential
findings — the `UnauthorizedAccess:IAMUser/*` family — key on anomalous API behaviour generally
rather than on model invocation. A stolen credential used *only* for Bedrock may produce nothing.

**Files here:**
- `sigma_t1496.yml` — four documents: `bedrock_new_principal_invocation` (informational base rule),
  an `event_count` correlation on volume per principal (high), a `value_count` correlation on
  distinct models per principal (high), and `bedrock_unexpected_region_invocation` (medium).
- `kql_t1496.kql` — the invocation-log view with token counts and Region comparison, plus the
  CloudTrail-only view in a commented section for accounts without invocation logging.

Full response procedure is in `../PLAYBOOK.md`.
