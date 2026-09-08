# Detection Note — T1190 (Exploit Public-Facing Application) / T1046 (Network Service Discovery)

**Signal:** an application-tier interface opening connections it has no reason to open — to
internal management and database ports, or to an unusual number of distinct internal addresses.

**The rule this replaces cannot fire.** It matches `dstaddr: 169.254.169.254` in VPC Flow Logs,
and AWS's flow log limitations page lists *"Traffic to and from `169.254.169.254` for instance
metadata"* among the traffic that is not captured. This is not a tuning problem, a coverage gap or
a field-name error. There is no configuration under which the record exists. The rule reports
clean in every account forever, which is materially worse than having no rule: it occupies the
slot a working detection would fill, and a coverage review reads it as satisfied.

**What is visible is more useful than what was intended.** Only the link-local metadata address is
excluded from flow logs. An SSRF primitive that can reach `169.254.169.254` can also reach the
database subnet, the Redis node, the internal admin panel and the Kubernetes API server — and
every one of those flows is recorded. Detecting the primitive by its network behaviour catches the
attacker whether they went for credentials or for the data directly, and it works on an instance
where IMDSv2 already defeated the metadata half.

## Three disjoint views, named so nobody builds a fourth

The metadata half of this technique is covered elsewhere and is not restated here.
`../../ec2.credential-access.imds-credential-theft/` detects the stolen role session being
used from somewhere the instance is not, in CloudTrail.
`../../waf.credential-access.crs-ssrf-ec2-metadata/` detects the inbound request carrying the
metadata signature, in web ACL logs. This is the network view. A responder working an SSRF
incident should expect to open all three; each says what it cannot see and points at the one that
can.

## The field-availability trap, which turns these rules silent rather than noisy

`flow-direction` is a **version 5** field. `pkt-srcaddr` and `pkt-dstaddr` are **version 3**. The
default flow-log format is version 2 and contains none of them, and AWS states the format is fixed
for the life of the subscription: *"After you create a flow log, you can't change its
configuration or the flow log record format... Instead, you can delete the flow log and create a
new one with the required configuration."*

So field selection is a preparation decision that cannot be corrected during an incident, and a
rule deployed against a default-format subscription does not misfire — it produces nothing. The
required custom format is in §1 of the playbook, and the KQL carries a `Degraded` column that
marks rows read from the version 2 fallback so a responder knows which view they are looking at.

**`pkt-dstaddr`, not `dstaddr`, and this decides whether the fan-out rule works at all.** AWS: if
traffic is sent to an interface and the destination is not one of that interface's addresses, the
log shows *"the primary private IPv4 address"*. Behind a NAT gateway or on an EKS node ENI, every
destination collapses to one value — and a rule counting distinct destinations then counts one,
forever.

## Response levers

**`protocol` is an IANA number.** 6 is TCP, 17 UDP, 1 ICMP. A rule written as `protocol: "TCP"`
matches nothing, and this is a common enough error to be worth stating in every VPC rule file.

**`REJECT` is not only a policy denial.** AWS: the traffic *"was not allowed by the security groups
or network ACLs, **or packets arrived after the connection was closed**"*. So ordinary TCP teardown
races appear as rejections, and a scan rule keyed on raw REJECT volume counts them. The KQL reads
the accept-to-reject *ratio* rather than the count for this reason.

**Absence is not evidence.** `log-status` carries `SKIPDATA` when AWS *"skipped"* records
*"because of an internal capacity constraint, or an internal error"*, and `NODATA` when the
interface was idle. A window with no matching flow may mean the flow did not happen, or that the
records were dropped, or that the interface was quiet. Filter to `log-status == "OK"` before
making any negative claim, and state the filter when you make one.

**Windows must exceed the aggregation interval.** The default maximum aggregation interval is 10
minutes — 1 minute on Nitro-attached interfaces — and delivery is *"about 5 minutes"* to CloudWatch
Logs and *"about 10 minutes"* to S3, best effort. A 5-minute threshold window on a default
subscription sees zero buckets or one, and any count tuned against it is meaningless. 30 minutes
is the shipped value, with a note that it can be shortened only on a 1-minute subscription.

**MITRE:** `T1190` primary — the source's own mapping, and correct, because the SSRF is the
exploitation of the public-facing application. `T1046` is what the firing rules actually observe,
and `T1552.005` names the objective. All verified live 2026-08-30.

**Severity:** high for backend-port access from an application tier, medium for fan-out alone. The
ceiling is whatever the reachable backends hold, plus the instance profile's permissions if the
metadata half also succeeded — and the metadata half leaves no network trace at all.

**GuardDuty:** partial and worth having. `UnauthorizedAccess:EC2/MetadataDNSRebind` and the
`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.*` family cover the credential outcome,
not the internal probing. GuardDuty consumes VPC flow logs as a data source, so it inherits the
same not-logged list — it cannot see the metadata request either. Treat it as corroboration of the
outcome, never as coverage of the technique.

**Files here:**
- `sigma_t1190.yml` — four documents: `vpc_apptier_internal_probe` (high), `vpc_egress_tcp_flow`
  (informational base rule), a `value_count` correlation on distinct destinations (medium), and
  `ec2_imds_weakened` (medium, CloudTrail logsource — the control-plane precondition).
- `kql_t1190.kql` — the network view with a `Degraded` column for version 2 fallback, plus the
  CloudTrail metadata-options query in a commented second section.

Full response procedure is in `../PLAYBOOK.md`.
