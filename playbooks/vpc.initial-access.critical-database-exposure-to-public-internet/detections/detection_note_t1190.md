# Detection Note — T1190 (Exploit Public-Facing Application)

**Signal:** an inbound TCP flow from a public address to a database port, accepted.

**Accepted is the entire signal, and it is a configuration fact rather than a traffic fact.** One
accepted flow proves the security group permits it, the network ACL permits it, and a route
exists. That remains true between alerts, which is why the corrected rules fire once per exposed
(host, port) and route to a security-group fix rather than paging per packet. There is no
architecture in which a datastore is intended to be internet-reachable, so the rule needs no
baseline and no threshold — one match is the finding.

**What the original rule got wrong** — the decisive one is a string case.

*`NOT action:"reject"` excludes nothing.* AWS documents exactly two values, `ACCEPT` and `REJECT`,
both uppercase. On a case-sensitive backend the negation never matches, so refused connections
pass the filter and the rule fires on blocked internet scanning exactly as it fires on a live
exposure — at P1. The internet scans every address continuously, so this is not a rare
misclassification; it is the common case, and it trains an on-call to dismiss the alert that
matters. The corrected rule matches `ACCEPT` positively, which cannot fail in that direction.

*It cannot tell inbound from outbound.* Without `flow-direction`, a host in the VPC connecting out
to an external database on 3306 matches identically to the internet connecting in. Those are
different incidents with different responses — one is an exposure, the other is possible
exfiltration or a rogue dependency.

*Its port list has three ports that are not databases and omits the ones most often exposed.*
`3303`, `3309` and `5429` are not database ports in common deployment, and `5429` is one digit
from `5439` (Redshift). MongoDB, Redis, Memcached, OpenSearch and Cassandra are absent — and
several of those historically shipped with no authentication enabled, which makes TCP
establishment equivalent to access.

*A threshold of zero grouped by source and destination pages per client.* A genuinely exposed
production database produces thousands of alerts an hour. The rule that fires most is the rule
that gets muted first.

## Two planes, shipped together, answering different questions

Flow logs prove the reachability was *exercised*. CloudTrail's `AuthorizeSecurityGroupIngress`
proves *who created it*, and fires at the moment of creation rather than when somebody finds it.
Neither answers the other's question. The CloudTrail rule is deliberately broader than the port
list — it matches any world-open ingress — because narrowing it to database ports would miss a
wide range that happens to cover them, and the port is in the same request for triage to read.

Note the nesting on that event: the CIDR sits at
`requestParameters.ipPermissions.items.ipRanges.items.cidrIp`, inside a list of permissions each
carrying its own list of ranges. A rule reading a flat `cidrIp` matches nothing, and the IPv6
form is a separate field.

## Response levers

**An accepted flow is not proof of authentication** — with two exceptions that matter. A flow log
is a 5-tuple counter, so an ACCEPT to 3306 means TCP was established and nothing more; database
audit logs are the only source that can say whether a login succeeded. But for Redis and Memcached
in their default configurations there is no authentication step, so establishment *is* access.
Treat those two as compromised on reachability alone.

**The `bytes` column may be structurally empty.** AWS: *"Flow logs for VPC BPA do not include
`bytes` even if you include the `bytes` field in your flow log."* In a VPC with Block Public
Access enabled, every volume figure in this playbook is zero regardless of what transferred, and a
small number there is not evidence of a small transfer.

**Field versions decide whether these rules work at all.** `flow-direction` is version 5,
`pkt-srcaddr` and `pkt-dstaddr` are version 3, and the default format is version 2. AWS states the
format cannot be changed after the subscription is created — it must be deleted and recreated. A
rule deployed against a default-format subscription is silent, not noisy. Behind a Network Load
Balancer, the version 2 fallback names the load balancer's interface rather than the database, so
the alert points at the wrong host.

**Absence is not evidence.** `log-status: SKIPDATA` means AWS dropped records *"because of an
internal capacity constraint, or an internal error"*. Filter to `OK` before claiming a port was
never reached.

**MITRE:** `T1190` primary, the source's own mapping and correct. `T1595 — Active Scanning` on the
probe rules, which observe reconnaissance rather than exploitation. Verified live 2026-08-30.

**Severity:** critical for an accepted connection, low for a refused one, medium for one source
probing many ports. The gap between critical and low is exactly the string case the source rule
gets wrong.

**GuardDuty:** partial. `UnauthorizedAccess:EC2/RDPBruteForce` and `.../SSHBruteForce` cover
remote-access ports rather than databases, and `Recon:EC2/PortProbeUnprotectedPort` fires on
probing of an unprotected port — the closest coverage, and it is a *probe* finding, not an
exposure finding. GuardDuty consumes flow logs as a data source and inherits their limitations.

**Files here:**
- `sigma_t1190.yml` — four documents: `vpc_db_exposed_to_internet` (critical),
  `vpc_db_probed_from_internet` (low base rule), a `value_count` correlation on ports probed per
  source (medium), and `ec2_sg_database_port_opened_publicly` (high, CloudTrail logsource).
- `kql_t1190.kql` — one row per exposed (host, port) with the engine named, plus the
  security-group query in a commented second section.

Full response procedure is in `../PLAYBOOK.md`.
