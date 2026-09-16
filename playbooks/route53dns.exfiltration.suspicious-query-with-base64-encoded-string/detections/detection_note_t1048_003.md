# Detection Note — T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol) / T1071.004 (DNS)

**Signal:** one source resolving a large number of **distinct** names under a single registered
domain, with labels at the protocol maximum.

**Cardinality is the measurement, not lexical pattern matching.** The payload *is* the subdomain,
so a tunnel produces a new name every query regardless of the alphabet — base64, base32, hex or a
custom encoding all look the same at this level. Any rule that matches a specific encoding is one
encoder change away from silence; a rule that counts distinct names is not.

**What the original rule got wrong** — it looks for a character DNS does not carry.

It matches base64 **padding**: a name ending in `=` or `==`, or containing them before a dot. But
`=` is not part of the DNS preferred syntax — RFC 1035 gives letters, digits and hyphens — and that
is exactly why every tool that puts base64 into DNS strips the padding first. So the rule matches
essentially nothing a working tunnel produces. What it does match is malformed queries, which is a
different and much less interesting population.

*And it has no grouping.* With a threshold of zero and no `group_by`, every individual match is an
alert with no actor, no domain and no aggregation — nothing to act on even when it fires.

## The structural signals that do work

DNS labels are at most **63 octets** and a full name at most **255**. An encoder maximising payload
per query pushes against both, so:

- **Distinct subdomains under one registered domain** — the strongest signal, and the one this
  playbook is built on.
- **Label length at or near 63** — a component, weak alone, because CDNs and object storage embed
  hashes in hostnames constantly.
- **`TXT` or `NULL` query type** — TXT carries the most response payload and is the standard
  downstream channel; NULL has essentially no legitimate modern use. Also weak alone: SPF, DKIM,
  DMARC and domain verification are all TXT and are constant.
- **`NXDOMAIN` ratio** — a nameserver answering only for encoded names produces these steadily. Also
  produced by search-domain suffixing, which is endemic on Kubernetes nodes.
- **`transport` of TCP** — unusual for ordinary lookups, used for larger exchanges.

Each component is deliberately shipped at low or informational. The finding is the combination, and
the correlation is where it lives.

## The caching limitation cuts in this rule's favour

AWS: *"VPC Resolver query logging logs only unique queries, not queries that VPC Resolver is able to
respond to from the cache."* Across this log source that is a serious constraint — "how many times
did this host resolve example.com" is unanswerable, because the log holds cache misses.

**Tunnelling is the exception, by construction.** A new name per query means a cache miss per
query, so the cardinality count is close to complete. It is worth knowing which side of that line a
rule sits on: most rules over Resolver logs are measuring cache misses and pretending otherwise;
this one is measuring what it claims to.

## A stated approximation in the registered-domain extraction

Taking the last two labels as the registered domain is wrong for multi-part public suffixes — for
`example.co.uk` it yields `co.uk` and merges unrelated domains. A public-suffix list is the correct
tool. Where one is unavailable, the error direction is **merging**, which inflates cardinality and
produces false positives rather than misses. That is the safe direction and it is stated in the
query rather than left to be discovered.

## Response levers

**The domain is the thing to block**, at the DNS Firewall, across every associated VPC at once.
Blocking the source host stops one victim; blocking the domain stops the channel.

**You cannot state how much data left.** The names carry the payload in encoded form and the log
carries the names, so the data is present in principle — but decoding needs the encoding and the
framing, which the log does not carry. Treat the distinct-name count as a lower bound on the
exchange and do not put a byte figure in the incident.

**`firewall_rule_action` is not a verdict.** AWS populates it only when DNS Firewall matched a rule
with an alert or block action, so its absence means no match — never "allowed by policy".

**`srcids.instance` may name something you cannot look up.** AWS: it *"might be because the DNS
query originated from either AWS CloudShell, AWS Lambda, Amazon EKS, or Fargate console"*. An empty
`describe-instances` is expected for those, not evidence of a bad record.

**MITRE:** `T1048.003` refines the source's bare `T1048` — the exfiltration is over an unencrypted
non-C2 protocol, which is what DNS is. `T1071.004 — Application Layer Protocol: DNS` covers the
command-and-control direction, because a tunnel carries traffic both ways and the log cannot say
which mattered. `T1568.001` on the NXDOMAIN component. All verified live 2026-08-30.

**Severity:** high for the cardinality correlation, medium for NXDOMAIN volume, low and
informational for the components. The components are not intended to alert.

**GuardDuty:** `Trojan:EC2/DNSDataExfiltration` covers this and consumes Route 53 Resolver query
logs as its data source — genuinely complementary, since it applies its own modelling to the same
records while these rules give the raw cardinality and the tuning surface. Note the dependency: if
Resolver query logging is not associated with the VPC, GuardDuty's DNS findings do not fire either,
so `../../route53dns.stealth.no-logs-from-amazon-route53-dns-query/` is upstream of both.

**Files here:**
- `sigma_t1048_003.yml` — four documents: `r53dns_oversized_label` (low base rule), a `value_count`
  correlation on distinct names per source (high), `r53dns_payload_query_type` (informational
  component) and `r53dns_nxdomain_volume` (medium component).
- `kql_t1048_003.kql` — cardinality per registered domain with label length, query type, NXDOMAIN
  ratio and transport folded into one verdict, and the public-suffix approximation stated.

Full response procedure is in `../PLAYBOOK.md`.
