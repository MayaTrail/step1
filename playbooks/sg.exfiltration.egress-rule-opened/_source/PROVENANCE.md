# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Immediate rules over query strings |
| Scope captured | Two rules: Egress Rule Was Added, Egress Rule Was Revoked — both shipped as building blocks |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously two of six rules folded into
`aws.initial-access.sg-remote-management-open`, whose other four are ingress and became
`../../sg.initial-access.remote-management-open/`. Egress is separated because it is a different
tactic — an outbound path is an exfiltration route, not an entry point — with a different response
and, as it turns out, an inverted baseline.

**Merge test — applied, not assumed.** The two egress rules become one use case: `Authorize` and
`Revoke` on the same resource, where the revoke exists only as the first half of the pair that
matters. Splitting them would leave a directory containing a rule that must never be routed alone.

**Both source rules are building blocks, so neither is rated at all.** An unrestricted outbound path
is the same class of finding as an open ingress rule, and the pack carries it as accounting.

**But the obvious correction would be wrong, and this is the finding.** AWS: *"When you first create
a security group, it has an outbound rule that allows all outbound traffic from the resource. You can
remove the rule and add outbound rules that allow specific outbound traffic only. If your security
group has no outbound rules, no outbound traffic is allowed."*

So the default is **already fully open outbound**. `AuthorizeSecurityGroupEgress` opening
`0.0.0.0/0` is frequently not a weakening — it is tooling restating a state that was never removed.
Rating it high would produce a stream of alerts about groups being returned to their birth
configuration. What actually matters is the **re-widening** of a group somebody deliberately
narrowed, which is only visible as a sequence: a revoke, then an authorize. That correlation is the
routable output here, and the single event ships at medium.

**The larger finding is an absence that no rule can carry.** A group nobody ever hardened has
unrestricted egress and generates no event, because nothing happened. That is the common case, it is
invisible to every detection by construction, and it is answered by
`describe-security-group-rules` as a posture question rather than by a rule.

**Two request shapes, as with ingress.** The flat form cannot express IPv6, so both are matched.
See `../../_ground-truth/sg.md` §1.

**And a cross-account referenced group produces no event for its owner.** AWS: *"When a referenced
security group is owned by another account, the owner account does not receive CloudTrail events for
these actions."* An egress rule pointing at a security group in another account is invisible to that
account entirely. Stated as a gap rather than closed.

**MITRE:** the source maps these rules to **nothing**. `T1686.001 — Disable or Modify System
Firewall: Cloud Firewall`, verified live 2026-08-30.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `sg.*` playbook is in `../../_ground-truth/sg.md`, audited 2026-08-30.
