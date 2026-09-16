# Detection Note — T1552.005 / T1190 (EC2 Instance Metadata Credential Theft)

**Signal:** an EC2 instance-profile role session — one whose role session name is an
instance ID — making AWS API calls from an address that instance cannot originate from.

**The theft leaves no trace; only the use does.** This is the property that shapes
everything else in this directory. Reaching `169.254.169.254` from inside an instance is a
link-local HTTP request that never crosses a network boundary AWS logs. It produces no
CloudTrail event, and VPC Flow Logs document "Traffic to and from `169.254.169.254` for
instance metadata" as traffic they do not capture. There is no query, in any dialect,
against any AWS log source, that observes the credential being taken. Every technique whose
playbook says "then look for the API call that did it" has a starting point; this one does
not, and a detection strategy that assumes otherwise is looking at an empty log and
concluding nothing happened.

**What the original rules got wrong** — the five source alerts split into two families and
fail in two different ways.

The **flow-log alert** matches `destination_ip:"169.254.169.254" AND action:"ACCEPT"`
against VPC Flow Logs. That traffic is on the documented list of what flow logs do not
capture. The alert is not noisy, not imprecise, and not in need of tuning: it **cannot
fire**. It has presumably sat at zero since the day it was deployed, and zero from a
deployed rule reads as absence of the technique.

> **Two facts for anyone tempted to salvage it by parsing flow logs directly.** The
> default (version 2) record is
> `version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes
> start end action log-status` — **field 13 is `action`** (`ACCEPT`/`REJECT`) and **field
> 14 is `log-status`** (`OK`/`NODATA`/`SKIPDATA`). Swapping them is the common error, and
> it silently inverts the filter. `pkt-srcaddr`/`pkt-dstaddr`, which would be the fields
> to reach for if the destination were rewritten in transit, are **version 3** and
> require a custom format. Second, a `filter-log-events` query is **only** applicable if
> the flow logs ship to CloudWatch Logs; if they ship to **S3** — which is the common
> configuration and the one this source rule's own pipeline implies — that query has
> nothing to run against and the data must be read with Athena or an object scan instead.
> Neither fact rescues the rule: the records it needs are not written at all.

The **four web-ACL alerts** match Core-Rule-Set labels for a metadata-SSRF signature in the
URI path, query arguments, body and cookie. Three problems. They split one actor across
four separate P2s keyed on client address, so a probe that tries three request components
arrives as three unrelated alerts. They gate on the request having been **allowed** — but
all four Core-Rule-Set rules carry a default action of Block, so in the default
configuration the alerts are silent, and a terminated attempt produces no alert at all,
which means the attacker becomes invisible exactly when the control worked. The corrected
rule treats `BLOCK`, `CAPTCHA` and `CHALLENGE` alike: AWS documents CAPTCHA and Challenge
as terminating whenever the request carries no valid token, so a challenged request did
not reach the origin and must not be reported as though it had. And they observe an
attempt rather than an outcome: a signature in an inbound request says nothing about
whether a credential was actually retrieved, which is decided by the target instance's IMDS
configuration and is not visible in a web-ACL log.

Neither family observes a stolen credential in use. That is the gap
`sigma_t1552_005.yml` exists to close.

## The role session name is the instance ID

This is the load-bearing mechanic, and it is what makes the technique detectable at all.

When a role is assumed through an EC2 instance profile, AWS documents `aws:userid` as
`{role-id}:{ec2-instance-id}`, where the generic assumed-role form is
`{role-id}:{caller-specified-role-name}`. The session name is not chosen by a caller; it is
the instance ID. Combined with the standard assumed-role ARN shape, that gives:

```
arn:aws:sts::<account>:assumed-role/<RoleName>/i-0123456789abcdef0
                                    ^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^
                                    role name    the instance, named
```

So every event a stolen instance credential produces carries, in its own identity, the
single host it was supposed to be used from. Compare that against `sourceIPAddress` and the
discriminator falls out: **an instance-profile session used from an address that is not its
instance's egress address.**

> **Cite this carefully.** The `aws:userid` mapping is documented on the IAM policy
> variables page. The literal ARN string above is *derived* from that plus the standard
> assumed-role ARN format — it is not quoted verbatim from any AWS page.
>
> **The instance identity role matches these rules. It is a different principal, but not a
> different shape.** AWS's sample `RequestManagedInstanceRoleToken` event carries
> `userIdentity.arn` = `arn:aws:sts::123456789012:assumed-role/aws:ec2-instance/i-02854e4bEXAMPLE`
> — an `sts` assumed-role ARN, not the `iam` role ARN that appears under `sessionIssuer`.
> Against `':assumed-role/[^/]+/i-[0-9a-f]{8,17}$'`, `[^/]+` matches `aws:ec2-instance` and
> the session name is a real instance ID, so it matches. An instance with **no instance
> profile at all** can therefore raise `imds_v1_credential_delivery`. That is kept rather
> than filtered: the rule's claim — IMDSv1 handed out a credential on that host — is true
> in that case too. What changes is the response. An `aws:ec2-instance` session has no
> instance profile to replace, so Containment Step 1 has nothing to act on, and the finding
> is an IMDSv2-enforcement work item rather than a credential-theft incident. Sort on the
> role name (`sessionIssuer.userName` = `aws:ec2-instance`) before dispositioning.

**CloudTrail has no dedicated instance-ID field.** There is no documented `ec2InstanceId`
under `userIdentity` or `sessionContext`. Parsing the last `/` segment of the ARN is the
only route, which means the parsing has to be right — see below.

## `AttributeKey=Username` matches the session name — so it matches the instance ID

The AWS CLI documents `Username` as "A user name or role name of the requester that called
the API in the event returned." For an assumed-role session what is actually indexed is the
**session name**, which for an instance-profile session is the instance ID. A
`lookup-events` keyed on the **role name** therefore returns **zero events** — not few,
zero — and every conclusion built on that zero is wrong.

```
WRONG   AttributeKey=Username,AttributeValue=MyInstanceRole      -> 0 events, always
RIGHT   AttributeKey=Username,AttributeValue=i-0123456789abcdef0
        then post-filter .userIdentity.sessionContext.sessionIssuer.userName == "MyInstanceRole"
```

This applies to **every** role-activity query, including the ones buried in Eradication and
Recovery. A verification block built on the broken lookup returns zero, concludes "no
remaining activity", and prints `[OK]` while the credential is live — a false `[OK]` on a
containment assertion, which is the worst failure mode available. Every such check in
`../PLAYBOOK.md` treats an empty result as `[!] inconclusive` rather than as `[OK]`, for
exactly this reason. The same trap in a different shape is described in the
`iam_inline_escalation_primitive_granted` note, where reusing the IAM-user ARN idiom on an
assumed-role ARN compares a session name against a role name.

Note also that AWS's own wording is ambiguous — it says "user name **or role name**". The
behaviour above is the house rule and it is what the queries are built on, but the two
readings disagree, so no query in this directory is allowed to rest on a bare zero.

## Two source addresses, one session

A session with one credential egresses through one address. That gives a threshold with a
real baseline rather than an invented one: `value_count` of distinct `sourceIPAddress`
grouped by `userIdentity.arn`, `gt: 1`, over an hour. It fires on the *first* off-instance
use rather than the second.

The known legitimate exception is a fleet that reaches some services through a VPC
interface endpoint (call carries the instance's **private** address) and others over NAT
(call carries the NAT **public** address). Two addresses, nothing wrong. The fix is **not**
to raise the threshold — that hides the attack too. It is to put both address sets in the
egress allowlist and let the allowlist rule do the alerting, with the count rule demoted to
a hunting query. That is why the two ship as separate documents at different levels.

## `ec2RoleDelivery` — how the credential was obtained

`userIdentity.sessionContext.ec2RoleDelivery` is `1.0` when the credential was handed out
by IMDSv1 and `2.0` when it came from the newer scheme. It is the only CloudTrail field
that says anything about the retrieval path, and it matters because the classic SSRF is an
unadorned `GET`: IMDSv2 requires a `PUT` to `/latest/api/token` carrying an
`X-aws-ec2-metadata-token-ttl-seconds` header first, and a forged GET cannot supply the
token that returns. A `1.0` delivery on a fleet believed to enforce IMDSv2 is an unenforced
instance or a pre-enforcement credential, and either is exposure.

**It serialises as a string, and it is a direct child of `sessionContext`.** AWS's sample
event carries `"ec2RoleDelivery": "2.0"` — quoted, and a sibling of `sessionIssuer` and
`attributes` rather than a member of `attributes`. The rule's `'1.0'` string match is
correct as written; the `NumericLessThan` in AWS's `ec2:RoleDelivery` example policies is
the policy-evaluation context and says nothing about the event's JSON type. What is still
unverified is the *Sentinel column*: `ec2RoleDelivery` is not one of the flattened
`AWSCloudTrail` columns, so `kql_t1552_005.kql` leaves a placeholder rather than inventing
a name.

## The blind spot: a credential used from inside the fleet's own egress set

Everything above discriminates on *where the call came from*, so it fails wherever the
attacker's address is one the fleet already uses. A credential lifted onto a second
compromised instance in the same VPC, or onto anything egressing through the same NAT
gateway, is inside the allowlist by construction: `imds_role_session_offnet` is silent
because `fleet_egress` matches, the distinct-address correlation is silent because the
count stays at one, and GuardDuty
`InstanceCredentialExfiltration.InsideAWS` is silent because it fires on an address or VPC
endpoint "owned by a **different** AWS account". Three controls, one shared assumption,
and same-account lateral movement defeats all three at once. It is the largest gap in this
directory's thesis and it is not closable by tuning.

The closure is IAM-side. AWS documents an SCP that denies unless
`aws:Ec2InstanceSourceVpc` equals `${aws:SourceVpc}` **and**
`aws:Ec2InstanceSourcePrivateIPv4` equals `${aws:VpcSourceIp}` — the VPC and the primary
ENI private address the credential was *delivered* to, compared against where the request
*arrived* from. A credential moved to another instance in the same VPC fails the second
comparison. Both keys are in the request context whenever the requester signs with an EC2
role credential. `ec2:SourceInstanceARN` on the role's permissions policy does the same
job per instance. Costs and deployment order are in `../PLAYBOOK.md` §6.

## Response levers

**Prevention beats detection here, and by a wide margin.** Detection tells you a credential
already left. Two AWS-documented deny policies stop it being useful at all:

```
ec2:MetadataHttpTokens != "required"   on ec2:RunInstances   -> no instance launches without IMDSv2
ec2:RoleDelivery       <  2.0          on "*"                -> any request signed with an
                                                                IMDSv1-retrieved EC2 role
                                                                credential is rejected outright
```

The second is the strongest single control for this technique. Both use ordinary
non-wildcarded values, so `StringNotEquals` and `NumericLessThan` are correct operators
here — the `*Like` requirement bites only when the compared value contains a wildcard.

**`ec2:SourceInstanceARN` binds a credential to one host.** AWS's example attaches it to
the role's *permissions* policy with `ArnEquals`, and documents that "if the same IAM role
is associated with another instance, the other instance cannot perform any of these
actions." A credential used off-instance has no such key in its request context at all, so
the `Allow` does not apply and the call fails closed. It is the only control that makes a
stolen credential worthless rather than merely noticeable. Its cost is a per-instance
policy, which does not fit a shared-role fleet. Use in a **trust** policy is not documented
and should not be assumed. For a shared-role fleet the per-instance equivalent is
`aws:VpcSourceIp` compared against `aws:Ec2InstanceSourcePrivateIPv4` (above), not
`aws:SourceIp` — AWS documents `aws:SourceIp` as absent from the request context when the
requester uses a VPC endpoint, so in an `Allow` it fails **closed** on endpoint-routed
traffic. That is an outage, not a bypass, but it is still the wrong key.

**Revocation ordering is inverted relative to most techniques.** An `aws:TokenIssueTime`
deny revokes only tokens issued *before* the cutoff. If the host is still compromised, the
attacker's next SSRF simply fetches a **newer** credential, which the deny does not cover.
Cut the instance's ability to mint credentials first — replace the instance profile — and
revoke sessions second. Reversing those two steps produces a revocation that looks
successful and achieves nothing.

**Replace the instance profile; do not disassociate it.** `disassociate-iam-instance-profile`
also severs the SSM agent's credentials, so any later `send-command` for forensic
collection hangs. `replace-iam-instance-profile-association` onto a quarantine profile
holding only SSM permissions cuts the blast radius while keeping the response channel —
but the quarantine role is then reachable by the same primitive that took the first one,
so it must hold nothing beyond SSM. **Two exceptions.** Where **Default Host Management
Configuration** is enabled, SSM Agent registers through the *instance identity role*, not
an instance profile; `disassociate` does not sever the channel and no quarantine profile is
needed. And neither command touches code execution on the host, which is what keeps
re-minting whatever role IMDS will hand out.

**Error strings:** EC2 carries a `Client.` prefix — `Client.InvalidInstanceID.NotFound` —
and the unprefixed form is the boto3 error code, which matches nothing in CloudTrail. IAM
policy denials on the stolen credential's calls surface as `AccessDenied`; service-evaluated
denials as `AccessDeniedException`. Match both, prefix-tolerantly, and confirm against a
real denied event in your own trail. A VPC endpoint policy violation is its own code,
`VpceAccessDenied`.

**MITRE:** the four web-ACL alerts tag **T1552.005**, three of them at the sub-technique and
one at the bare parent **T1552** — an inconsistency within one set of four siblings. The
flow-log alert tags **T1190**. Both mappings are addressed in `../PLAYBOOK.md` §6; in short,
the web-ACL alerts observe exploitation of a public-facing application whose *objective* is
the metadata API and should carry **both** T1190 and T1552.005, while the flow-log alert has
the pair exactly backwards — what it purports to observe is the metadata API access itself,
which is T1552.005 and not T1190 at all. This directory carries both tags on the inbound
rule and T1552.005 alone on the credential-use rules.

**Severity:** the source rates all five **P2**. IR view **High**, P0 for confirmed
off-instance use. A P2 for "an attacker holds your instance role's credentials and is using
them from their own infrastructure" routes a live credential compromise to a queue nobody
reads overnight.

**GuardDuty:** unusually for this corpus, there are finding types for exactly this, and
they are genuinely first-class rather than generic anomaly detectors:

- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` — a host outside
  AWS used credentials created on an EC2 instance. Default severity **High**.
- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` — credentials used
  from an address or VPC endpoint owned by a **different AWS account**. Default severity
  **High**, downgraded to **Medium** when the calling account is affiliated with yours.
  VPC-endpoint detection covers only services supporting network activity events for VPC
  endpoints.
- The resource-credential equivalents are **not symmetric**, and three files here
  previously said they were. `ResourceCredentialExfiltration.OutsideAWS` covers "an AWS
  resource (a Lambda function or Amazon ECS task)" — both.
  `ResourceCredentialExfiltration.InsideAWS` covers "an AWS Amazon ECS task" **only**;
  there is no Lambda InsideAWS finding.
- `UnauthorizedAccess:EC2/MetadataDNSRebind` — an instance resolving a domain to
  `169.254.169.254`, the DNS-rebinding route to the same objective. Default severity
  **High**, sourced from DNS logs.
- There is **no** GuardDuty finding type for IMDSv1 usage or IMDS configuration.

**Do not treat GuardDuty as the control.** It documents that once it observes continued
activity from a remote account or external source, its model learns that as expected
behaviour and **stops generating the finding** for that source. An attacker using stolen
credentials steadily from one address is precisely the pattern that gets learned. The
finding is at its most valuable on first occurrence and least reliable on the hundredth —
the opposite of how a control should degrade. Both AWS-documented architectural false
positives are worth suppressing deliberately rather than by muting: hub-and-spoke transit
gateway egress VPCs for InsideAWS, and on-premises gateway egress, Outposts and VPC VPN for
OutsideAWS.

**Files here:**
- `sigma_t1552_005.yml` — five documents: instance credentials used outside the fleet's
  egress addresses (`high`), the instance-profile session base rule (`low`) with its
  distinct-source-address correlation (`medium`), IMDSv1 credential delivery (`medium`),
  and the corrected inbound metadata-SSRF rule (`medium`) that replaces the source set's
  four component-split alerts with one.
- `kql_t1552_005.kql` — the egress-allowlist reconstruction against a `FleetEgress`
  watchlist, plus commented companions for IMDSv1 delivery and for web-ACL attempts, and
  the GuardDuty and prevention guidance the queries cannot express.

Full response procedure is in `../PLAYBOOK.md`.
