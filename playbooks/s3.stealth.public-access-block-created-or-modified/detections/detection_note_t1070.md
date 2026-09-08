# Detection Note — T1070 (Indicator Removal)

**Signal:** Block Public Access being **enabled** — which is a good thing happening, and is
therefore only a finding when it is the closing half of a pair.

## The source rule cannot fire, and how it fails is the interesting part

It matches `eventName:"PutPublicAccessBlock"`. That is the SDK operation name; CloudTrail emits
`PutBucketPublicAccessBlock` for a bucket and `PutAccountPublicAccessBlock` for the account.

What makes this worth more than a one-line fix: a **different rule in the same source pack** matches
`PutBucketPublicAccessBlock` correctly, and a **third** matches `DeletePublicAccessBlock` and also
cannot fire. Three rules, one operation family, two different naming conventions, no consistency
between them. The lesson is not "the pack gets event names wrong" — it is that getting one right
predicts nothing, and each name has to be checked against AWS's own event list individually.

## `NOT (flag:false)` is not `all four true`

All four flags are `Required: No`. A request carrying only `BlockPublicPolicy: true` satisfies the
source rule's condition while saying nothing about the other three, and AWS does not document
whether an omitted flag is cleared or preserved. So the rule reports a partial hardening as a
hardening, and the resulting configuration is not derivable from the event at all — only
`get-public-access-block` gives it. `s3_pab_partial_hardening` catches that shape at low, because it
is compliance drift rather than attack: a control that looks applied and may not be.

## Response levers

**The finding is the window, not the event.** By the time this correlation fires the configuration
is already correct, so there is nothing to contain — a responder who reaches for the containment
reflex here will find nothing to do and conclude it was a false positive. The work is
reconstructing what happened between the two halves: how long the guardrail was down, whether the
bucket carried a public policy at the time, and what the principal did in between.

**A state-based review will show nothing, by construction.** AWS Config, a compliance scan, and a
bucket-by-bucket audit all read the *current* configuration, and the current configuration is fine.
This is the case those controls structurally cannot see, which is the argument for keeping the
event history long enough to reconstruct it.

**Whether the bucket was actually public during the window is a separate question.** A lowered flag
only matters if a public policy or ACL existed at the time. `get-bucket-policy-status` answers that
for now, not for then; reconstructing "then" needs the `PutBucketPolicy` / `PutBucketAcl` history
over the same interval, which is why the query pulls those events alongside.

**Do not tune this by shortening the timespan.** The 24-hour window is what makes the pair
detectable; a short one removes the deliberate case and keeps the noisy infrastructure-rebuild case.
Allowlist the provisioning role on the base rules instead.

**MITRE:** the source maps this rule to **nothing**. `T1070 — Indicator Removal` for restoring the
expected configuration to conceal that it changed, with `T1530` on the weakening half. Both verified
live 2026-08-30.

**GuardDuty:** `Policy:S3/BucketBlockPublicAccessDisabled` and `Policy:S3/AccountBlockPublicAccessDisabled` cover the weakening half. Nothing in GuardDuty covers the restoration, or pairs the two — the pair is what this directory adds.

**Files here:**
- `sigma_t1070.yml` — four documents: `s3_pab_hardened` (informational, change accounting and
  correlation component), `s3_pab_weakened_any` (informational base rule),
  `s3_pab_partial_hardening` (low), and a `temporal_ordered` correlation for lowered-then-restored
  by the same principal (high). Only the correlation is routable.
- `kql_t1070.kql` — computes the window length between the weakening and the restoration, and rates
  on whether the bucket was changed in between.

Full response procedure is in `../PLAYBOOK.md`.
