# Provenance

**Use case:** Flow Alert - Possible Smishing Observed
**Retrieved:** 2026-08-29
**Extract:** `original_rules.yml` — de-identified, logic-only, produced by the shared
extractor. It contains **three** entries: the flow rule and the two building blocks it
composes, because a flow whose stages are not reproduced is not auditable. Name, priority,
type, ATT&CK mapping, query verbatim, threshold, window, group-by and the flow's stage
composition are kept; all platform scaffolding is stripped. No source, vendor, product or
repository is named here or in any shipped file.

## Merge decision — NOT merged, and test 2 was the one to check

`07-TIERS.md` test 2 exists for exactly this shape: *"A FLOW/correlation rule that is purely
the composition of building blocks you are already shipping, adding no new observable. It
becomes a correlation document inside the existing playbook's Sigma, not a playbook of its
own."*

**Its precondition is not met.** The two building blocks this flow composes — an SNS SMS
enumeration by a previously unseen principal, and a publish to a topic — are **not** among
the seven use cases in scope, so there is no existing playbook for the correlation to move
into. Test 2 relocates a flow into a sibling; it does not delete one that has no sibling.
The flow therefore stays its own use case, and the building blocks ship as **named base rule
documents inside this playbook's Sigma**, which is the shape test 2 would have produced
anyway had a host existed.

That is also the right outcome on the merits. The flow adds an observable neither block
carries alone: a principal that has never touched SMS configuration doing so and then
sending. And correcting it required replacing both of its stages — the second one
(`Publish`) cannot fire on a default trail at all — so what ships here is not a composition
of the shipped blocks but a different correlation over management events that actually exist.

**Test 1** does not apply: there is no sibling rule with the same observable.

## Tier

Tier 2 (lean), with Tier-1 promotion test 5 ("the detection has a structural blind spot
worth a page of honesty") explicitly considered. It is met in substance — AWS does not log
`AWS::SNS::PhoneNumber` to CloudTrail at all, so the sending step of this technique is
invisible by design — but the honesty it requires fits in this playbook's §1, §2 and Residual
Risk without a Tier-1 rewrite, and the response itself is short. Held at Tier 2; the blind
spot is documented in three places rather than expanded into a page.

## Siblings

No SNS sibling shares this observable. The nearest related use case is
`sns.persistence.topic-policy-modified`, because a topic policy opened for public
publish is a second route to the same outbound-SMS abuse when the topic carries SMS
subscriptions.

**Merge test — applied, not assumed. Three source rules, one use case.** Two are building blocks
(`SNS Enumerated by Previously Unseen User`, `SNS Topic Was Published`) and the third is the flow
that correlates them. That is a base-rule-plus-correlation structure, which is the shape authoring
rule **B1** requires — legacy in-rule aggregation is invalid and volume or sequence logic belongs in
a correlation document over named base rules. Splitting the components into their own playbooks
would leave two directories whose rules must never be routed on their own, and a third that cannot
function without them.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
