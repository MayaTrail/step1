# Detection Note — T1021 (Remote Services) / T1133 (External Remote Services)

**Signal:** an accepted inbound TCP flow from a public address to SSH, RDP, VNC, WinRM or telnet.

**The exposure is the finding; reputation is a prioritiser.** That ordering is the whole
correction. The source rule will not fire unless the source address carries a high-confidence
threat-intel score, which puts an enrichment lookup in front of the only fact that matters — a
remote-administration service is reachable from the entire internet. Every address is unreported
on its first day. Attackers rent fresh addresses precisely because they are unreported. And the
reputation field lives in an enrichment pipeline rather than in the flow log, so if that pipeline
is not configured, or its schema changes, the rule reports clean forever with nothing to indicate
why. A detection whose base case depends on an optional pipeline has a silent off switch.

The corrected set separates them: `vpc_remote_service_from_internet` at high, needing no
enrichment, and `vpc_remote_service_from_known_bad` at critical layered on top. An empty reputation
column means *not enriched*, never *not malicious*, and the KQL says so on the row.

**What else the original rule got wrong**

*Its port list is three ports.* 22, 3389 and 5900. Missing: **5985 and 5986** — WinRM, the standard
Windows remote-management transport and the one least likely to be watched; **23**, still present
on appliances; **5901–5903**, because 5900 covers VNC display `:0` only; and **2222**, an
alternate SSH port chosen precisely because rules list 22.

*It uses geo-enrichment as a direction proxy.* `is_local` on source and destination stands in for
`flow-direction`, a version 5 field. Behind a NAT gateway or load balancer, the version 2 address
fields hold *"the primary private IPv4 address"* of the interface, so the enrichment classifies
the wrong address — and the rule concludes the source is internal and stays quiet.

*It groups by source with a threshold of zero.* Defensible when a reputation gate keeps volume
down; unusable the moment the gate is removed, which is what the correction does. The corrected
rules group by target and port, so one exposure is one row regardless of how many clients found it.

## What an accepted flow does and does not prove

It proves TCP was established: the security group, the network ACL and the route all permit it.
It does **not** prove anyone authenticated. `sshd` and the Windows event log answer that, and they
are on the host.

The only proxy available in flow logs is packet volume, and it is a real one: a refused login
closes in a handful of packets, while an interactive session does not. The KQL reads
`Packets > 100` on an accepted flow as "somebody stayed" and labels it as an inference rather than
a finding. Treat a sustained session as host compromise pending the host's own logs, not after
them — the host logs may also be the first thing an intruder edits.

## Response levers

**Field versions decide whether these rules work.** `flow-direction` is version 5;
`pkt-srcaddr`/`pkt-dstaddr` are version 3; the default format is version 2. AWS states the format
is fixed for the life of the subscription — it must be deleted and recreated. A rule deployed
against a default-format subscription is silent, not noisy, and the KQL carries a `Degraded`
column marking rows read from the version 2 fallback.

**`REJECT` is not purely blocked attacks.** AWS documents it as covering security-group and NACL
denials *"or packets arrived after the connection was closed"*, so ordinary teardown races appear
as rejections. The refused-connection rule ships at low for that reason and feeds a correlation on
*distinct ports per source* rather than on volume — port breadth is what separates somebody
mapping your admin surface from somebody scanning the internet's.

**Absence is not evidence.** `log-status: SKIPDATA` means AWS dropped records *"because of an
internal capacity constraint, or an internal error"*. Filter to `OK` before claiming a port was
never reached, and say that you did.

**MITRE:** `T1021 — Remote Services` from the source, kept, with `T1133 — External Remote
Services` added because the observable is an externally-facing service being reached rather than
movement between internal hosts. `T1595 — Active Scanning` on the refusal rules. All verified live
2026-08-30.

**Severity:** high for an accepted connection from outside the admin allowlist, critical when a
reputation hit accompanies it, medium for admin-surface enumeration, low for background refusals.

**GuardDuty:** genuinely useful here, and it is the one place in this service where it is.
`UnauthorizedAccess:EC2/SSHBruteForce` and `UnauthorizedAccess:EC2/RDPBruteForce` cover repeated
failed authentication against these exact ports, which is the half flow logs cannot see. Treat
GuardDuty and these rules as complementary: GuardDuty says somebody is trying to log in, these say
the port should not have been reachable in the first place.

**Files here:**
- `sigma_t1021.yml` — four documents: `vpc_remote_service_from_internet` (high, no enrichment
  required), `vpc_remote_service_from_known_bad` (critical, the reputation prioritiser),
  a `value_count` correlation on distinct ports per source (medium), and
  `vpc_remote_service_refused` (low base rule).
- `kql_t1021.kql` — one row per exposed (host, port) with the service named, reputation as an
  optional left-outer column, and packet volume read as a session-sustained proxy.

Full response procedure is in `../PLAYBOOK.md`.
