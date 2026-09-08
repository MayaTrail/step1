# Detection Note — T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)

**Signal:** a DNS query returned an address in `169.254.0.0/16` — the link-local range that serves
EC2 instance metadata, ECS task metadata and EKS Pod Identity credentials.

**This is DNS rebinding, and it defeats hostname allowlists specifically.** An application that
fetches a user-supplied URL and validates the *hostname* against an allowlist is doing the right
thing and still loses: the name passes validation, and then resolves to the metadata endpoint. The
fetch reaches `169.254.169.254` and returns role credentials. The defence that fails here is the
one most teams implement first.

**What the original rule got wrong** — the string is right and everything around it is not.

*It is a free-text match, so the field is lost.* `"169.254.169.254"` anywhere in the record covers
two unrelated events: in `rdata` it is rebinding, and in `query_name` it is somebody looking up the
literal address as a name. Those have different severities and different responses, and the rule
reports them identically.

*`AND _exists_:query_name` is a check that cannot fail.* Every Resolver query log record carries a
`query_name`; it is the name that was asked for. The clause narrows nothing and only makes the rule
look more specific than it is.

*It names one address out of three that matter.* `169.254.170.2` serves ECS task metadata and
task-role credentials; `169.254.170.23` serves EKS Pod Identity credentials. Both are reached by
the identical primitive and neither is matched. The corrected rule takes the whole link-local
prefix.

*And it stops at metadata.* Any public name resolving to private space is the same primitive
pointed at something else — an internal admin panel, a database, the Kubernetes API server. That
ships as its own rule at medium, tuned by **zone** rather than by address range, because
split-horizon DNS and private hosted zones answer into RFC 1918 legitimately.

## The caching limitation, and why it does not apply here

AWS: *"VPC Resolver query logging logs only unique queries, not queries that VPC Resolver is able
to respond to from the cache."* That makes volume reasoning about stable domains meaningless
across this whole log source — "how many times did this host resolve example.com" is unanswerable.

**Rebinding is the exception, and by construction.** The technique depends on a very short TTL so
the second resolution returns a different answer, which means every rebinding query is a cache miss
and every one is logged. The completeness this rule enjoys is not typical of rules over this
source, and it is worth knowing which side of that line any given rule sits on.

## `firewall_rule_action` is not a verdict

AWS populates the DNS Firewall fields *"only if DNS Firewall found a match for a rule with action
set to alert or block"*. So an empty `firewall_rule_action` means **no match** — never "allowed by
policy". Reading it as approval is the most common misuse of this field, and it is why the KQL
projects it and never filters on it.

## Response levers

**The DNS log proves a resolution and nothing more.** It does not prove anything connected. And for
the IMDS case there is no network record at either layer: VPC flow logs explicitly do not capture
*"Traffic to and from 169.254.169.254 for instance metadata"*, so the connection that follows the
resolution is invisible in both sources. The evidence that the attack worked is the resulting role
session appearing in CloudTrail from an address that is not the instance —
`../../ec2.credential-access.imds-credential-theft/` is the playbook for that, and this one's
job is to hand over cleanly rather than duplicate it.

**IMDSv2 is the fix and it is a configuration change, not a detection.** The rebinding fetch is an
unauthenticated `GET`; IMDSv2 requires a token from a prior `PUT` carrying a header the forged
request cannot set. A hop limit above 1 reopens the path for containers.
`../../vpc.initial-access.possible-ssrf-attempt-hit-to-169254169254/` covers the enforcement sweep.

**`srcids.instance` may name something you cannot look up.** AWS: *"If you see an instance ID in
Route 53 VPC Resolver query logs which is not visible in your account, it might be because the DNS
query originated from either AWS CloudShell, AWS Lambda, Amazon EKS, or Fargate console."* An empty
`describe-instances` for one of these is not evidence the record is wrong.

**MITRE:** the source carries bare `T1552`. `T1552.005` names the cloud instance metadata API
exactly and carries the IaaS platform. `T1590.002 — Gather Victim Network Information: DNS` is
carried by the private-address rule, which observes internal-naming reconnaissance rather than
credential access. Both verified live 2026-08-30.

**Severity:** critical for a link-local answer — no legitimate public name resolves there — and
medium for a private-space answer outside the known internal zones.

**GuardDuty:** `UnauthorizedAccess:EC2/MetadataDNSRebind` covers exactly this, and it consumes
Route 53 Resolver query logs as its data source. It is genuinely complementary rather than
redundant: GuardDuty applies its own logic to the same records, and these rules give you the raw
resolution and the tuning surface. Where both are available, a GuardDuty finding plus this rule
firing is strong corroboration; GuardDuty silent while this fires is worth reading, because the
finding requires the Resolver logs to be reaching it.

**Files here:**
- `sigma_t1552_005.yml` — three documents: `r53dns_rebind_to_metadata` (critical),
  `r53dns_rebind_to_private` (medium, tuned by zone), `r53dns_firewall_action` (medium).
- `kql_t1552_005.kql` — grouped by which credential endpoint the answer names, with the firewall
  action projected and never used as a filter.

Full response procedure is in `../PLAYBOOK.md`.
