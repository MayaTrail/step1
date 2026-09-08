# Detection Note — T1584.001 (Compromise Infrastructure: Domains)

**Signal:** the transfer lock came off a registered domain, and — in the ordered pair that
matters — the transfer authorization code was retrieved afterwards.

**This is the only technique in the Route 53 corpus with no recovery path.** A deleted zone can
be rebuilt. A poisoned record can be corrected. A domain that has completed a transfer to
another registrar is gone: no AWS API reaches it, AWS's escalation route is a support case, and
AWS states plainly that it holds no information — *"When you transfer a domain to another
registrar, all status updates go to the new registrar, so Route 53 has no information about why
a transfer failed."* The remaining levers are the registry's transfer-dispute process and
ICANN's, both outside AWS. That asymmetry is why the lock event alone is rated high and is not
gated behind a confirming second event.

**What the original rule got wrong** — three things, and the first two are structural.

*It waits for an event that will never be written.* Its flow is `DisableDomainTransferLock` →
`TransferDomainToAnotherAwsAccount`. The second is the **account-to-account move inside AWS**
(operation type `INTERNAL_TRANSFER_OUT_DOMAIN`). The registrar transfer-out — the irreversible
one — is executed at the gaining registrar. AWS's documented procedure ends: *"Use the process
that is provided by the new registrar to request a transfer of the domain."* No API call, no
event, in any account. The rule cannot fire on the scenario its own title names.

*It may not fire at all.* AWS documents that registrar actions appear in CloudTrail with a
lowercase first letter — *"`UpdateDomainContact` appears as `updateDomainContact` in the logs"* —
and its published sample event confirms it. The source rule matches `DisableDomainTransferLock`
exactly. Whether the convention is still current has not been re-confirmed against a recent
event, which is exactly why every rule here matches both forms rather than picking one.

*Its one-hour window is a fraction of the process.* A registrar transfer runs for days. AWS
emails the registrant a link to approve or reject, and *"If you don't take action, the transfer
will proceed automatically on the specified date."* An hour is not a correlation window for
that; the corrected pair uses 24h, and the direct rules use none.

## The veto can be redirected, and the log will not say where

The approval email goes to the registrant contact, and that contact is changeable through
`UpdateDomainContact` — whose content CloudTrail explicitly does not log
(*"Personally-identifying contact information is not logged in the request"*). So the attacker
can move the veto out of your reach, and the trail records that a redirection occurred while
being structurally incapable of recording its destination. `route53_domain_registration_altered`
fires on that change for exactly this reason: it is the one event that turns a slow, reversible
process into a silent one.

## Live state beats the log here

`aws route53domains list-operations --type TRANSFER_OUT_DOMAIN` is the definitive answer to
"is a transfer actually in flight", and it is live state rather than a log. `OperationType` is a
closed enum containing both `TRANSFER_OUT_DOMAIN` and `INTERNAL_TRANSFER_OUT_DOMAIN`, so the
operations list distinguishes the two paths that CloudTrail conflates and cannot see
respectively. `list-domains` returns a per-domain `TransferLock` boolean, and an account holds
at most 20 registered domains (50 on accounts predating March 2021) — so a complete account-wide
lock assertion is one cheap call. That bound is why §3 of the playbook can re-lock everything
rather than triaging one domain.

## Response levers

**Error strings:** `AccessDenied` and `AccessDeniedException` (both forms — the registrar API
uses the exception suffix on some operations), `TLDRulesViolation` (*"The top-level domain does
not support this operation"*), `UnsupportedTLD`, `DuplicateRequest` (*"The request is already in
progress for the domain"*), `OperationLimitExceeded`, `InvalidInput`. A `TLDRulesViolation` or
`UnsupportedTLD` refusal is still intent observed — the registry declined, not the account.

**A credential may be sitting in your trail.** UNVERIFIED and worth acting on anyway: AWS
publishes no statement about whether `RetrieveDomainAuthCode`'s `responseElements` carries the
authorization code in CloudTrail. The service model marks `DomainAuthCode` `sensitive`, but that
trait governs SDK logging, not CloudTrail. Treat the trail as **possibly** holding a live
transfer credential and restrict read access accordingly. Do not assert either way.

**14 days, not 60.** AWS's transfer-out page states the post-registration restriction as 14 days
and presents it as a *typical registrar requirement* rather than a Route 53 guarantee. Any
longer figure belongs to registry or ICANN policy, not to AWS behaviour, and is not written as
one anywhere in these files.

**MITRE:** T1584.001 — Compromise Infrastructure: Domains, verified live 2026-08-30. The source
carries bare `T1584`; the sub-technique names registration hijacking exactly and cites AWS
Route 53. `T1078` secondary for the IaaS-platform half.

**Severity:** high for the direct rules, critical for the ordered pair. Nothing in this service
outranks losing the domain, because every certificate, every email address and every published
URL depends on it.

**GuardDuty:** no coverage. There is no finding namespace whose resource is a registered domain
or a hosted zone; Route 53 appears in GuardDuty only as a *data source* feeding EC2 and EKS
findings. These rules are the only control and there is nothing to defer to. AWS Config does not
help either — `AWS::Route53Domains::*` is not a recorded resource type, so there is no
configuration history of a lock being turned off. A scheduled `list-domains` snapshot is the
substitute, and §1 asks for it.

**Files here:**
- `sigma_t1584_001.yml` — six documents: `route53_domain_transfer_lock_disabled` (high),
  `route53_domain_auth_code_retrieved` (high), an ordered correlation at critical,
  `route53_domain_transferred_to_another_account` (high),
  `route53_domain_registration_altered` (medium) and `route53_domain_change_refused` (medium).
- `kql_t1584_001.kql` — the registrar timeline per principal, with the ordered pair as a second
  view and the two live-state commands the log cannot replace.

Full response procedure is in `../PLAYBOOK.md`.
