# Detection Note — T1685 (Disable or Modify Tools) / T1588.004 (Digital Certificates)

**Signal:** a CAA record — the only DNS-level control over which certificate authorities may
issue for a name — was created or replaced in a hosted zone.

**Fixing the DNS record is not the remediation, and treating it as one is the mistake this note
exists to prevent.** CAA is read by a CA at issuance time and by nobody afterwards. RFC 8659 §1
is explicit: *"A set of CAA records describes only current grants of authority to issue
certificates for the corresponding DNS domain name... it is possible that a certificate that is
not conformant with the CAA records currently published was conformant with the CAA records
published at the time that the certificate was issued. **Relying Parties MUST NOT use CAA records
as part of certificate validation.**"* A certificate obtained while the policy was weak stays
valid, trusted, and completely unaffected by restoring the record. The eradication phase is
certificate-transparency review and revocation; the DNS change only closes the window.

**What the original rule got wrong** — it matches `CREATE` or `UPSERT` on a CAA record and
nothing else. That is the right event and it is only half a detection.

*It cannot say whether the change was permissive.* Authorisations in CAA are **additive**, and
AWS supplies the example itself: publishing `0 issue ";"` and `0 issue "ca.example.net"` together
means *"a CA that is using the value ca.example.net can issue the certificate"*. The attacker's
change is an addition, the record still exists afterwards, and it looks like ordinary
certificate-management traffic. The corrected set inverts the test — enumerate the organisation's
own CAs, and alert on a CAA value that names none of them.

*It reads the batch, not the change.* `changes[]` is an array and one event carries many changes
of many types. Two keys in one Sigma block are ANDed across the whole batch, so `type: CAA` and
`action: CREATE` can be satisfied by two *different* elements. That approximation is kept
deliberately — the alternative loses the distinction from the deletion use case — and it is
stated in the rule header, in §2 of the playbook, and resolved by `mv-expand` in the KQL rather
than left for an analyst to discover.

*It cannot see a bulk rewrite.* CloudTrail's contract is omit-not-truncate: *"When the field size
exceeds 100 KB, the `requestParameters` content is omitted."* There is no partial-array case, so
a CAA change buried in an oversized batch presents as **zero** changes and every type-matching
rule reports clean. `route53_change_parameters_omitted` exists solely to cover that blind spot,
and it treats absence as a signal rather than as a parsing gap.

## The two mechanics that make this quiet

**Tree-climbing means a permissive subdomain record beats a strict apex.** RFC 8659 §3: *"The
search for a CAA RRset climbs the DNS name tree from the specified label up to, but not
including, the DNS root '.' until a CAA RRset is found."* A nearer RRset shadows a further one.
Publish `0 issue "attacker-ca.example"` at `pay.example.com` and the deny-all at `example.com`
no longer governs that name — while the apex record, the thing anyone would review, is untouched.
No log query can resolve this, because it needs the *current* state of every ancestor name;
Query 2 of the playbook walks `ListResourceRecordSets` per zone and compares each CAA name
against the apex.

**The window is at least eight hours and the TTL extends it.** CA/Browser Forum Baseline
Requirements v2.2.9 (6 August 2026) §4.2.2.1: *"If the CA issues a certificate after processing a
CAA record, it MUST do so within the TTL of the CAA record, or 8 hours, whichever is greater."*
So a CAA record whose TTL was raised shortly before it was weakened is a deliberate extension of
the exploit window and a signal in its own right — which is why TTL is projected in the KQL and
carries its own trigger row rather than being discarded as metadata.

Two smaller traps in the same direction. An RRset containing only `iodef` tags, or only tags the
CA does not recognise, **does not restrict issuance** (RFC 8659 §3) — a deny-all can be removed
while leaving a record in place. And a *malformed* issue-value forbids issuance while a *missing*
record permits it, so CAA fails closed on syntax and open on absence; making the record
unreachable is equivalent to deleting it.

## Response levers

**`UPSERT` destroys the prior value and nothing records it.** The event carries only the new
values and Route 53 keeps no record-set version history, so "what was the policy before?" is
answerable only from IaC state, from an earlier `ChangeResourceRecordSets` that set it, or from
passive DNS. `DELETE` is the opposite: the API demands an exact match of every existing value, so
a `DELETE` event's `resourceRecords` **is** the removed record and is genuinely usable for
restoration. Recovery steps are written to that asymmetry rather than assuming it uniformly.

**Error strings:** the set for `ChangeResourceRecordSets` is closed — `NoSuchHostedZone`,
`NoSuchHealthCheck`, `InvalidChangeBatch`, `InvalidInput`, `PriorRequestNotComplete` — plus the
IAM forms `AccessDenied` / `AccessDeniedException`. Throttling is code `Throttling`, message
*"Rate exceeded"*. Batches are transactional (*"either makes all or none of the changes"*), so a
failed event changed nothing and `PriorRequestNotComplete` in a burst is evidence of scripted
volume against one zone.

**Regionality.** `route53.amazonaws.com` events carry `awsRegion: us-east-1` and AWS states the
console rule outright. A `lookup-events` call in any other Region returns zero, and that zero is
`[!] INCONCLUSIVE`, never clean. Every query in this playbook pins `us-east-1`.

**MITRE:** T1685 primary (the only live IaaS-platform technique covering removal of a
preventative control), T1588.004 for the objective, T1608.003 for the stage that follows. The
source's `T1596` is Reconnaissance and does not describe this at all.

**Severity:** high for a CAA change; critical when the published value names no approved CA. The
ceiling is a valid, publicly trusted certificate for a domain the organisation owns, which
defeats TLS as an identity control for everything served under that name.

**GuardDuty:** no coverage. There is no finding namespace whose resource is a hosted zone; Route
53 appears in GuardDuty only as a *data source* feeding EC2 and EKS findings. AWS Config records
`AWS::Route53::HostedZone`, which makes a before-and-after record-set comparison possible and is
the single highest-value preparation item here — but there is **no** Config managed rule for CAA
content, so the comparison is yours to run.

**Files here:**
- `sigma_t1685.yml` — four documents: `route53_caa_record_changed` (high),
  `route53_caa_unapproved_authority` (critical), `route53_change_parameters_omitted` (medium)
  and `route53_caa_change_refused` (medium).
- `kql_t1685.kql` — the element-level view via `mv-expand`, with the issuance-window calculation
  and the omitted-parameters case surfaced before the expand can drop it.

Full response procedure is in `../PLAYBOOK.md`.
