# IR Playbook: EC2 Instance Metadata Credential Theft — Role Credentials Harvested from `169.254.169.254` and Used Off-Host

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential access / Unsecured credentials (an instance-profile role's temporary credentials are read out of the metadata service and used from somewhere that is not the instance) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | **High**, P0 once off-instance use is confirmed. The attacker holds a working AWS credential carrying every permission the instance profile grants, usable from their own infrastructure, and it self-renews for as long as they retain the SSRF primitive or code execution on the host. Unlike a stolen access key there is nothing to disable — the credential is a short-lived session with no IAM object behind it — and the reflexive `aws:TokenIssueTime` deny is defeated by a single re-fetch. Severity tracks the profile's permissions, so a role holding `iam:*` or broad S3 access makes this account-level rather than host-level. The source rules rate all five signals **P2**, which routes a live credential compromise to a queue nobody reads overnight |
| MITRE Tactics | Credential Access, Initial Access |
| MITRE Techniques | T1552.005, T1190 |
| Services in Scope | EC2 (IMDS + instance profiles), IAM, STS, CloudTrail, CloudWatch, GuardDuty, VPC, WAF, plus every service reachable by the instance profile role |

**What the technique does:** the actor gets code execution on an EC2 instance, or an SSRF primitive
in an application on it, and issues an HTTP request to `169.254.169.254`. Two calls:
`GET /latest/meta-data/iam/security-credentials/` returns the instance profile's role name, and
`.../security-credentials/<role-name>` returns JSON carrying `AccessKeyId`, `SecretAccessKey`,
`Token` and `Expiration`. The actor signs AWS API requests with those from their own machine —
nothing is installed, nothing is modified, and the instance keeps working. Under IMDSv2 the plain
`GET` fails, because it needs a token from a prior `PUT` presented in a header a forged request
cannot set (full handshake in §6).

**Why this is potent, and why the usual reflexes miss it.** The theft produces **no AWS telemetry
whatsoever** — no CloudTrail event, and VPC Flow Logs document "Traffic to and from
`169.254.169.254` for instance metadata" as traffic they explicitly do not capture, so the
responder queries a log documented not to contain the answer and reads the empty result as absence.
The second reflex, disabling the leaked credential, has nothing to act on: an instance-profile
session is an `ASIA...` credential with no IAM object behind it. The third, an

**Detection is the session's own name against the address it came from, not any event name.** An
EC2 instance-profile session carries the **instance ID as its role session name**, so every event a
stolen credential produces names, in its own ARN, the single host it may originate from; the
discriminator is that session calling from an address the instance cannot egress through. The source
rules never reach it: four watch inbound requests for a signature — an attempt, not an outcome — and
the fifth watches a flow log for traffic flow logs do not record (§2).

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail. The stolen credential can call **any** service, so a
  management-only trail is blind to an actor reading S3 objects — `GetObject` is a **data** event.
  Enable data events on what the profile can reach, or "what did they take" is unanswerable there
- Every event carries `userIdentity.arn` as `arn:aws:sts::<acct>:assumed-role/<Role>/<instance-id>`,
  `userIdentity.sessionContext.sessionIssuer.userName` (the bare **role** name),
  `userIdentity.accessKeyId` (the `ASIA...` session key), `sourceIPAddress`, and for endpoint-routed
  calls `vpcEndpointId` / `vpcEndpointAccountId`. There is **no** documented `ec2InstanceId` field —
  the instance ID exists only as the last `/` segment of the ARN
- `userIdentity.sessionContext.ec2RoleDelivery` is `1.0` for an IMDSv1-issued credential and `2.0`
  for IMDSv2 — the only field saying how the credential was obtained. `sourceIPAddress` is **not
  always an address**: AWS services appear as a DNS name and AWS-originated events as
  `AWS Internal/<n>`, so address comparisons must exclude those forms
- CloudWatch `AWS/EC2` metrics **`MetadataNoToken`** (IMDS accessed without a token, i.e. IMDSv1)
  and **`MetadataNoTokenRejected`** (IMDSv1 attempted after it was disabled), per instance
- GuardDuty in every region — one of the few techniques with finding types naming it directly. Web
  ACL logging with the managed Core Rule Set: `labels` carries
  `awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_*`, `action` the terminating action
- **VPC Flow Logs do not help here and must not be relied on** for IMDS access

**Alerting (must be pre-configured)**
- **An instance-profile role session used from an address outside the fleet's egress set → P0**
- **GuardDuty `InstanceCredentialExfiltration.OutsideAWS` or `.InsideAWS` → P0**
- **One instance-profile session used from more than one source address within an hour → P1**
- **A Core Rule Set `EC2MetaDataSSRF_*` label on a request no terminating action stopped → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under
  investigation and specifically **not** an instance-profile role
- `jq`; a pre-created **quarantine instance profile** holding only `AmazonSSMManagedInstanceCore`,
  so the compromised profile can be *replaced* rather than removed and the SSM channel survives.
  Check first whether **Default Host Management Configuration** is on in the region
  (`aws ssm get-service-setting --setting-id arn:aws:ssm:<region>:<acct>:servicesetting/ssm/managed-instance/default-ec2-instance-management-role`):
  under DHMC the agent authenticates through the instance identity role, no quarantine profile is
  needed, and §3 Step 1 inverts
- The regions in use, and an out-of-band way to reach the instance if SSM is lost

**Known IOC Baselines**
- **The fleet's egress address set** — the VPC CIDRs instances hold private addresses in
  (endpoint-routed calls) **and** every NAT / egress-firewall Elastic IP (public-endpoint-routed).
  Both sets; the rules are unusable without it, and in Sentinel it is the `FleetEgress` watchlist
- Which instances legitimately still allow IMDSv1, and why, each with an expiry date
- Every account ID in the organisation, so a GuardDuty `InsideAWS` finding naming an outside
  account is recognisable on sight

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Instance-profile role session (`.../i-*`) calling from an address outside the fleet's egress set | CloudTrail (management **and** data events) | T1552.005 |
| P0 | GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` or `.InsideAWS` | GuardDuty | T1552.005 |
| P1 | One instance-profile session used from more than one distinct source address within an hour | CloudTrail (management **and** data events) | T1552.005 |
| P1 | Core Rule Set `EC2MetaDataSSRF_*` label on a request no terminating action stopped — it reached the application | Web ACL logs | T1190, T1552.005 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `userIdentity.sessionContext.ec2RoleDelivery` = `1.0` on a fleet believed to enforce IMDSv2 | CloudTrail (management **and** data events) | T1552.005 |
| P2 | `MetadataNoToken` > 0 on an instance that permits IMDSv1 and holds an instance profile | CloudWatch (`AWS/EC2`) | T1552.005 |
| P2 | GuardDuty `UnauthorizedAccess:EC2/MetadataDNSRebind` — instance resolving a domain to `169.254.169.254` | GuardDuty (DNS logs) | T1552.005 |
| P3 | Core Rule Set `EC2MetaDataSSRF_*` label terminated by `BLOCK`, `CAPTCHA` or `CHALLENGE` — attribution only | Web ACL logs | T1190 |

### Detection Rule Quality Notes

One of the five source rules cannot fire at all; the other four fire on an attempt, split one
actor four ways, and are silent in the default configuration.

| Issue | Impact | Correction |
|-------|--------|-----------|
| The flow-log rule matches `destination_ip:"169.254.169.254" AND action:"ACCEPT"` against VPC Flow Logs | AWS documents that traffic as something flow logs **do not capture**. The rule is not noisy or imprecise — it is **inert**, and has returned zero since deployment. A deployed rule sitting at zero reads as absence of the technique, the most expensive failure mode available for a control nobody re-examines | Delete it; no flow-log signal for IMDS access exists at any tuning. Detect the credential's *use* instead: an instance-profile session calling from outside the fleet's egress set |
| Neither family observes the outcome — four rules watch inbound HTTP, one watches a link-local hop | A signature in a request says nothing about whether a credential was retrieved; that is decided by the target's `HttpTokens` setting, invisible in a web-ACL log. Conversely a credential stolen through code execution produces no inbound signature and evades all five | Detect on session identity: the role session name of an instance-profile session **is** the instance ID, so the ARN names the one host the session may originate from. Compare it against `sourceIPAddress` |
| The four web-ACL rules gate on `action:"ALLOW"` | All four Core Rule Set `EC2MetaDataSSRF_*` rules default to **Block**, so these alerts never fire in the default configuration — only while the rule group is overridden to Count. And a blocked attempt raises nothing, so the attacker is invisible precisely when the control worked | Match the label and make the terminating action the **discriminator, not the filter**: P1 when the request reached the application, P3 for attribution when it did not. AWS documents `CAPTCHA` and `CHALLENGE` as terminating whenever the request carries no valid token, so all three stop the request and only a non-terminating outcome is "reached" |
| One alert per request component — URI path, query args, body, cookie — each P2 grouped by client address | An actor probing three components arrives as three unrelated P2s with no indication they are one incident. Analyst time goes on re-correlating what the rule set decomposed | One rule across all four labels, grouped by client address. The component is output context, not rule identity |
| No rule inspects `ec2RoleDelivery`, and none counts source addresses per session | The two strongest CloudTrail-side discriminators are unused. `ec2RoleDelivery` = `1.0` says the credential came from the IMDSv1 path an SSRF can actually reach; two addresses on one session in an hour contradicts the one-instance-one-egress baseline | Ship both: a rule on `ec2RoleDelivery`, and a `value_count` correlation on distinct `sourceIPAddress` per session |
| All five rated P2, `threshold: 0.0` over a 5–15 minute window | "Fire on every occurrence" is right only for a rare event. Applied to web-ACL signature hits, which internet-facing applications collect continuously from background scanning, it produces the volume that gets a rule muted — and muting takes the rare true positive with it. Meanwhile a live credential compromise is rated the same as the noise | Credential-use signals are P0/P1 and rare by construction. Keep the inbound-attempt signal at P1/P3, with the terminating action deciding which |

**Recommended detection — an instance-profile credential in use somewhere its instance is not.**

```yaml
# EC2 Instance Metadata Credential Theft (T1552.005)
#
# The source set is five alerts across two telemetry families, and the two fail
# differently. The four web-ACL alerts match a Core-Rule-Set label for an EC2 metadata
# SSRF signature in the URI path, query arguments, body or cookie of an inbound request.
# They fire on an ATTEMPT, split one actor across four separate P2s keyed on client IP,
# and gate on the request having been ALLOWED — but all four Core-Rule-Set rules carry
# a default action of Block, so in the default configuration the alerts are silent and a
# blocked attempt produces no record anywhere. The flow-log alert matches
# `destination_ip:"169.254.169.254" AND action:"ACCEPT"`, and VPC Flow Logs document
# "Traffic to and from 169.254.169.254 for instance metadata" as traffic they do not
# capture. That alert cannot fire. It is not noisy or imprecise; it is inert.
#
# The deeper problem is that neither family observes the technique's outcome. The metadata
# fetch is a link-local HTTP call inside one instance: it produces no CloudTrail event, no
# flow-log record, and no AWS telemetry of any kind. What IS observable is what the stolen
# credential does next. An EC2 instance-profile session carries the instance ID as its role
# session name, so the ground truth for theft is a session whose ARN says `.../i-0abc...`
# making calls from an address that instance cannot originate from. That is the rule below.
#
# Two further CloudTrail facts do work the source rules never attempt.
# `userIdentity.sessionContext.ec2RoleDelivery` is `1.0` when the credential came from
# IMDSv1 and `2.0` when it came from IMDSv2 — the classic SSRF GET only yields a credential
# on the `1.0` path, so a `1.0` delivery on a fleet believed to enforce IMDSv2 is itself a
# finding. And a legitimate instance session egresses from exactly one address, so the
# count of distinct source addresses per session is a threshold with a real baseline.
title: EC2 instance-profile credentials used from outside the fleet's egress addresses
id: 916f13c1-1b08-4bfd-b6b5-3679c681fc14
name: imds_role_session_offnet
status: experimental
description: >-
  An EC2 instance-profile role session made an AWS API call from a source address the
  fleet cannot originate from. The role session name of an instance-profile session is
  the EC2 instance ID, so this identifies a credential that has left the instance it was
  minted for and is being used elsewhere.
references:
  - https://attack.mitre.org/techniques/T1552/005/                                              # retrieved 2026-08-27
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html  # retrieved 2026-08-27
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html          # retrieved 2026-08-27
  - https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html            # retrieved 2026-08-27
tags:
  - attack.credential-access
  - attack.t1552.005
logsource:
  product: aws
  service: cloudtrail
detection:
  # The role SESSION NAME of an instance-profile session is the instance ID. No
  # eventName/eventSource filter: the stolen credential works against any service.
  selection:
    userIdentity.arn|re: ':assumed-role/[^/]+/i-[0-9a-f]{8,17}$'
  # DEPLOYER MUST POPULATE — placeholders, not a working allowlist. Needs BOTH the VPC
  # CIDRs instances hold private addresses in and every NAT / egress-firewall Elastic IP.
  fleet_egress:
    sourceIPAddress|cidr:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  # sourceIPAddress is not always an address — AWS services appear as a DNS name and
  # AWS-originated events as `AWS Internal/<n>`, neither of which cidr can evaluate.
  aws_internal:
    sourceIPAddress|contains:
      - '.amazonaws.com'
      - 'AWS Internal'
  condition: selection and not fleet_egress and not aws_internal
falsepositives:
  - An egress path missing from the allowlist — an added NAT gateway, a transit route, a
    reassigned Elastic IP. The dominant false positive, and a maintenance problem.
  - An operator debugging with credentials copied off a host. Indistinguishable here, and
    an incident until proven otherwise.
level: high
---
# Base rule for the distinct-source-address correlation below. Deliberately carries NO
# errorCode filter, which is a considered departure from the usual "count only successes"
# rule: this correlation counts distinct SOURCE ADDRESSES for one session, not distinct
# objects acted on. A stolen credential probing its own reach from the attacker's address
# collects AccessDenied, and those denials are the earliest and cleanest evidence the
# credential left the instance. Filtering them out would remove the signal. The correlation
# is levelled `medium` rather than `high` partly for that reason.
#
# It DOES carry the `aws_internal` exclusion, and that is load-bearing rather than
# cosmetic. The correlation counts distinct values of `sourceIPAddress`, and that field
# is not always an address: a call an AWS service makes onward with this same session
# records the service's DNS name, and AWS-originated events record `AWS Internal/<n>`.
# Without this block one real address plus one service form is two distinct values, which
# reaches `gt: 1` on an instance that never left its own egress path.
title: EC2 instance-profile role session activity
id: 1062fec7-f8ba-4f23-89a6-6ae27e1d1306
name: imds_role_session
status: experimental
description: Base rule — correlation component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html  # retrieved 2026-08-27
tags:
  - attack.credential-access
  - attack.t1552.005
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.arn|re: ':assumed-role/[^/]+/i-[0-9a-f]{8,17}$'
  aws_internal:
    sourceIPAddress|contains:
      - '.amazonaws.com'
      - 'AWS Internal'
  # justified: base rule feeding the value_count correlation below. There is no
  # discriminator on a single event here — the signal is the distinct-address count
  # computed across the window, which cannot be expressed on one event by construction.
  condition: selection and not aws_internal
level: low
---
# Threshold basis, stated so a deployer can adjust it knowingly. There is no emulation
# behind this number. It comes from the technique's own baseline: one instance egresses to
# AWS through one address at a time, so an uncompromised instance-profile session shows
# exactly ONE distinct sourceIPAddress and `gt: 1` fires on the first off-instance use.
# The number is deliberately at the baseline rather than above it — a threshold of `gt: 2`
# would require the attacker to use the credential from two addresses before alerting.
#
# The known legitimate exception is a fleet that reaches some services through a VPC
# interface endpoint (private address) and others through NAT (public address). That
# session shows two addresses with nothing wrong. If that describes your fleet, do not
# raise the threshold — that hides the attack too. Add the endpoint-routed addresses to
# the first rule's `fleet_egress` allowlist and treat THAT rule as the alerting one, using
# this correlation as a hunting query. Grouping additionally by `vpcEndpointId` separates
# the two paths cleanly where your backend supports grouping on a field absent from some
# events; that behaviour is backend-specific and is not assumed here.
title: One EC2 instance-profile session used from more than one source address
id: 7ca5b637-2479-4080-a72c-2426067d4114
status: experimental
description: >-
  A single EC2 instance-profile role session made API calls from more than one distinct
  source address within an hour. An instance egresses through one address, so a second
  address on the same session means the credential is in use somewhere other than the
  instance it was issued to.
references:
  - https://attack.mitre.org/techniques/T1552/005/  # retrieved 2026-08-27
tags:
  - attack.credential-access
  - attack.t1552.005
correlation:
  type: value_count
  rules:
    - imds_role_session
  group-by:
    - userIdentity.arn
  timespan: 1h
  field: sourceIPAddress
  condition:
    gt: 1
falsepositives:
  - A fleet that reaches some AWS services over a VPC interface endpoint and others over
    NAT. Both paths are legitimate and show different addresses. See the threshold note
    above — the fix is the allowlist in the first rule, not a higher count here.
  - An instance that changed egress path mid-window, such as a NAT gateway failover or an
    Elastic IP reassociation.
level: medium
---
# The IMDSv1-vs-IMDSv2 discriminator, which the source rules do not use and which is the
# only CloudTrail field that says anything about HOW the credential was obtained.
# `ec2RoleDelivery` is documented as `1.0` when the credential was provided by IMDSv1 and
# `2.0` when provided by the newer scheme. The classic SSRF against the metadata service
# is an unadorned GET, and an unadorned GET only returns a credential when IMDSv1 is
# available — IMDSv2 requires a PUT to `/latest/api/token` carrying an
# `X-aws-ec2-metadata-token-ttl-seconds` header first, and a forged GET cannot supply the
# resulting token. So on a fleet believed to enforce IMDSv2, a `1.0` delivery is either an
# instance that was missed by enforcement or a credential minted before it was applied,
# and both are exposure regardless of whether this particular session is malicious.
#
# SERIALISATION IS A STRING, and the field is a DIRECT CHILD of `sessionContext` — a
# sibling of `sessionIssuer` and `attributes`, not nested inside `attributes`. AWS's own
# sample event for `RequestManagedInstanceRoleToken` carries `"ec2RoleDelivery": "2.0"`,
# quoted. The string match below is therefore correct as written. (The IAM condition key
# `ec2:RoleDelivery` is compared with `NumericLessThan` in AWS's example policies; that is
# the policy-evaluation context and says nothing about the event's JSON type.)
#
# THIS RULE ALSO MATCHES THE INSTANCE IDENTITY ROLE, and that is a deliberate acceptance
# rather than an oversight. Its session ARN is
# `arn:aws:sts::<account>:assumed-role/aws:ec2-instance/<instance-id>` — AWS's own sample
# event — so it fires this rule and the ARN regex in the rules above: `[^/]+` matches
# `aws:ec2-instance` and the session name is a real instance ID. An instance with NO
# instance profile attached can therefore appear here. That is still a true statement of
# what the rule claims to detect — IMDSv1 handed a credential out on that host — so the
# signal is kept rather than filtered. What it changes is triage: an
# `aws:ec2-instance` session has no instance profile to replace, so Containment Step 1
# has nothing to act on and the finding is an IMDSv2-enforcement work item, not a
# credential-theft incident. Sort on the role name before dispositioning.
title: EC2 role credentials delivered by IMDSv1
id: e73dab62-a68c-404a-b1c6-042f12e3742c
name: imds_v1_credential_delivery
status: experimental
description: >-
  A request was signed with EC2 role credentials that the metadata service handed out over
  IMDSv1 — an instance-profile session, or the instance identity role `aws:ec2-instance`.
  On a fleet that enforces IMDSv2 this cannot happen, so it identifies either an unenforced
  instance or a credential that predates enforcement — and IMDSv1 is the version a
  server-side request forgery can actually reach.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html  # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ExamplePolicies_EC2.html                    # retrieved 2026-08-27
tags:
  - attack.credential-access
  - attack.t1552.005
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.sessionContext.ec2RoleDelivery: '1.0'
  # justified: the field has exactly two documented values and one of them is the finding.
  # There is nothing further to filter on — no principal, content or volume condition
  # would sharpen it, and adding one would only narrow a signal that is already specific.
  condition: selection
falsepositives:
  - A fleet that has not finished migrating to IMDSv2. Expect volume proportional to how
    much of the estate is unenforced; use it as a migration work-list first and promote it
    to an alert once `MetadataNoToken` reads zero fleet-wide.
  - An SDK or agent too old to negotiate IMDSv2 running on an instance where IMDSv2 is
    optional rather than required.
level: medium
---
# The corrected inbound-attempt rule, replacing four separate alerts with one.
#
# Three corrections. First, the four source alerts split the same actor across four P2s
# keyed on client IP — one per request component — so an actor probing the URI path, the
# query string and the body appears as three unrelated alerts. They are one rule.
# Second, the source alerts require the request to have been ALLOWED. All four
# Core-Rule-Set rules carry a default action of Block, so in the default configuration the
# alerts never fire, and a blocked attempt leaves no alert at all — the attacker is
# invisible precisely when the control worked. This matches on the label and treats the
# terminating action as the discriminator, so it fires only when the request reached the
# application while a terminated attempt remains available in the logs for attribution.
# Third, one of the four source alerts carries the parent technique where its siblings
# carry the sub-technique; the mapping here is uniform and dual, because the observed
# event is exploitation of a public-facing application whose objective is the metadata API.
#
# LABEL CASING IS NOT A DEFECT IN THE SOURCE RULES, and it is worth recording why, because
# it looks like one. The Core-Rule-Set RULE names are screaming-case (`EC2MetaDataSSRF_BODY`)
# while the LABELS those rules emit are camel-case
# (`awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_Body`). Labels are documented as
# case-sensitive. The source rules match the label form, which is correct. A deployer who
# copies the rule name out of the managed-rule-group documentation into a label match gets
# zero forever.
#
# INSPECTION LIMIT, the analogue of an oversized document defeating a content rule: the
# body variant only inspects the request body up to the protection pack's body size limit
# and handles oversize content with `Continue`, so a metadata SSRF payload placed beyond
# that limit is never labelled and no rule keyed on the label can see it. There is no
# label to alert on for that case; the coverage gap is real and is carried in the playbook
# rather than papered over here.
#
# LOGSOURCE: web-ACL logs have no standard Sigma logsource. `product: aws, service: waf`
# is this corpus's convention and needs a field mapping in your pipeline. `labels` is
# documented as an array of objects carrying a `name`; `action` is the terminating action.
title: Inbound request carrying an EC2 metadata SSRF signature reached the application
id: a58b50a7-c61f-45f1-82d9-213ba9502afe
name: waf_imds_ssrf_not_blocked
status: experimental
description: >-
  A web request whose URI path, query arguments, body or cookie carried a signature for
  reaching the EC2 instance metadata service was evaluated and not terminated by BLOCK,
  CAPTCHA or CHALLENGE, so it reached the application. This is the attempt, not the compromise — whether a credential was
  actually retrieved is decided by the instance's IMDS configuration and is not visible
  here.
references:
  - https://attack.mitre.org/techniques/T1552/005/                                        # retrieved 2026-08-27
  - https://attack.mitre.org/techniques/T1190/                                            # retrieved 2026-08-27
  - https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html  # retrieved 2026-08-27
  - https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-label-requirements.html       # retrieved 2026-08-27
tags:
  - attack.credential-access
  - attack.initial-access
  - attack.t1552.005
  - attack.t1190
logsource:
  product: aws
  service: waf
detection:
  # Camel-case suffixes: these are LABEL names, not rule names, and labels are
  # case-sensitive. Matched as substrings so the full managed-rule-group namespace prefix
  # does not have to be reproduced.
  selection:
    labels.name|contains:
      - 'EC2MetaDataSSRF_URIPath'
      - 'EC2MetaDataSSRF_QueryArguments'
      - 'EC2MetaDataSSRF_Body'
      - 'EC2MetaDataSSRF_Cookie'
  # AWS: "The CAPTCHA and Challenge actions are terminating when the web request doesn't
  # contain a valid token." A terminated request did NOT reach the application, so all
  # three belong in the same exclusion; treating only BLOCK as terminating reports a
  # challenged request as having reached the origin.
  terminated:
    action:
      - 'BLOCK'
      - 'CAPTCHA'
      - 'CHALLENGE'
  condition: selection and not terminated
falsepositives:
  - A security scanner or an authorised penetration test. Both produce genuine signatures
    and are separated by source address and schedule, not by rule logic.
  - An application that legitimately carries a link-local address in a parameter — rare,
    but it exists in network-management tooling. Confirm against the request itself.
  - The managed rule group running in Count mode during tuning, which makes every
    signature reach the application by design. Fix the mode; do not tune out the rule.
level: medium
```

Reproduced byte-for-byte from the first rule document of `detections/sigma_t1552_005.yml`, which
also ships the session base rule (`low`) and its distinct-source-address correlation (`medium`), the
IMDSv1 credential-delivery rule (`medium`) and the corrected inbound metadata-SSRF rule (`medium`).
**Deploy the file, not this excerpt.**

**What these rules structurally cannot do — the in-fleet blind spot first, because it is the largest
gap in this thesis.** Every rule here discriminates on *where the call came from*, so all of them
fail together once the attacker's address is one the fleet already uses. A credential lifted onto a
second compromised instance in the same VPC, or onto anything egressing through the same NAT
gateway, is inside `fleet_egress` by construction: the `high` rule is silent, `DistinctIPs` stays at
1 so the correlation is silent, and GuardDuty `InstanceCredentialExfiltration.InsideAWS` is silent
because it fires only on an address or VPC endpoint owned by a **different** AWS account. Three
controls, one shared assumption. Nothing detective closes it; the control is source pinning in IAM
(§6) — `ec2:SourceInstanceARN` per instance, or `aws:Ec2InstanceSourcePrivateIPv4` against
`${aws:VpcSourceIp}` for a shared role. Until one is deployed, same-VPC lateral use is undetected,
not absent.

**They also match the instance identity role, deliberately.** Its session ARN is
`arn:aws:sts::<acct>:assumed-role/aws:ec2-instance/<instance-id>` — AWS's own sample event — so
`[^/]+` matches `aws:ec2-instance` and the session name is a real instance ID: an instance with no
instance profile at all can raise `imds_v1_credential_delivery`. What the rule claims is still true
there (IMDSv1 handed out a credential on that host), so the signal is kept rather than filtered, but
there is no profile to replace and the finding is IMDSv2-enforcement work. Sort on
`sessionIssuer.userName` before dispositioning.

Beyond that they cannot see a credential stolen but **not yet used**, cannot see a data-plane call
unless data events are enabled, and are only as good as the egress allowlist — miss a NAT gateway
and they false-positive, allowlist a broad CIDR and they go silent.

---

### Key Investigation Queries

> Instance-profile credentials work in **every** region, so Queries 3, 4 and 5 iterate regions
> deliberately. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`;
> **`lookup-events` returns ≤50 events per page**, so paginate on `NextToken` or use your log
> platform. **A zero-row result is never `[OK]`** — these queries key on a session name, and a wrong
> one returns zero silently.

#### Query 1 — Reconstruct: everything the instance's role session did, and from where

```bash
REGION="us-east-1"
INSTANCE_ID="<instance-id>"          # e.g. i-0123456789abcdef0
WINDOW="24 hours ago"

# AttributeKey=Username matches the SESSION name, which here is the instance ID. A lookup
# keyed on the ROLE name returns zero events, always, and that zero looks clean. The role
# is recovered per event from sessionIssuer.userName instead.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$INSTANCE_ID" \
  --start-time "$(date -u -d "$WINDOW" +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    (.userIdentity.arn // "") as $arn |
    {time: .eventTime, event: .eventName, source: .eventSource,
     caller_arn: $arn,
     role: (.userIdentity.sessionContext.sessionIssuer.userName // "UNKNOWN"),
     instance_id: ($arn | split("/") | last),
     access_key: .userIdentity.accessKeyId,      # feeds ACCESS_KEY_ID in Query 5
     imds_version: (.userIdentity.sessionContext.ec2RoleDelivery // "not-recorded"),
     ip: .sourceIPAddress,
     vpc_endpoint: (.vpcEndpointId // "-"),
     agent: .userAgent,
     error: (.errorCode // "SUCCESS")}' | \
  jq -s 'sort_by(.time)'
```

Read `ip` first: every distinct value is a place this credential was used. Record `instance_id`,
`role`, `access_key`, `caller_arn` and the earliest `time` — Queries 2 and 5 and all of Containment
consume them. `imds_version` `1.0` means the credential came out of IMDSv1, the path an SSRF can
reach; `2.0` means genuine code execution. `AccessDenied` clustered on one `ip` is the actor mapping
the role's reach and usually **precedes** the successful calls. **An empty result does not mean the
credential was unused** — it is also what a mistyped instance ID looks like. A `role` of
`aws:ec2-instance` is the instance identity role, not a profile (§2).

#### Query 2 — Ground truth: which of those addresses is actually the instance's

```bash
REGION="us-east-1"
INSTANCE_ID="<instance-id-from-Query-1>"
OBSERVED_IPS="<space-separated-ip-values-from-Query-1>"   # quoted first: a bare <...> in a
                                                          # for-list is a shell syntax error

# A call to a public regional endpoint leaves through NAT and carries the NAT public address;
# a call through a VPC interface endpoint carries the instance's PRIVATE address. Both are
# legitimate, so both go in the set. Note describe-nat-gateways takes --filter, SINGULAR.
OWN_IPS=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" --output json | \
          jq -r '.Reservations[].Instances[] |
            (.PrivateIpAddress // empty), (.PublicIpAddress // empty),
            (.NetworkInterfaces[]?.Association.PublicIp // empty)')
NAT_IPS=$(aws ec2 describe-nat-gateways --region "$REGION" \
            --filter Name=state,Values=available --output json | \
          jq -r '.NatGateways[].NatGatewayAddresses[].PublicIp // empty')

EGRESS=$(printf '%s\n%s\n' "$OWN_IPS" "$NAT_IPS" | sed '/^$/d' | sort -u)
echo "[i] Fleet egress set for $INSTANCE_ID:"; echo "$EGRESS" | sed 's/^/    /'

OFFNET=0
for IP in $OBSERVED_IPS; do
  case "$IP" in
    *.amazonaws.com|*"AWS Internal"*) echo "[i] $IP is a service-principal call, not an address" ;;
    *) if echo "$EGRESS" | grep -qxF "$IP"; then echo "[OK] $IP is an egress address for the instance"
       else echo "[!] $IP is NOT an egress address for $INSTANCE_ID — credential used off-instance"
            OFFNET=$((OFFNET+1)); fi ;;
  esac
done
[ "$OFFNET" -gt 0 ] && echo "[!] $OFFNET off-instance address(es) — THEFT CONFIRMED, go to Containment" \
                    || echo "[i] No off-instance address in the set checked — not proof of innocence"
```

Any `[!]` ends the identification phase: the credential is off the host. The negative is far weaker
than it looks — it covers only the addresses *Query 1 returned, in this region, in this window*, a
management-only trail says nothing about data-plane calls, and an address inside the fleet's own
egress set is indistinguishable from the instance's own (§2).

#### Query 3 — Sweep: every instance in the account from which this would still work

The account-wide hunt is a **configuration** sweep, not a log sweep: an instance that permits IMDSv1
and holds an instance profile is one SSRF away from the same incident, and unlike the log side this
question has a complete and cheap answer.

```bash
REGIONS="us-east-1 eu-west-1"        # every region you operate in

for R in $REGIONS; do
  echo "== $R =="
  aws ec2 describe-instances --region "$R" \
    --filters Name=metadata-options.http-tokens,Values=optional \
              Name=metadata-options.http-endpoint,Values=enabled \
              Name=instance-state-name,Values=running \
    --output json 2>/dev/null | \
    jq -r '.Reservations[].Instances[] |
      select(.IamInstanceProfile != null) |
      "[!] \(.InstanceId) HttpTokens=\(.MetadataOptions.HttpTokens // "?") " +
      "endpoint=\(.MetadataOptions.HttpEndpoint // "?") " +
      "hop=\(.MetadataOptions.HttpPutResponseHopLimit // "?") " +
      "profile=\(.IamInstanceProfile.Arn) public=\(.PublicIpAddress // "none")"'
done
echo "[OK] IMDSv1-permitting instance sweep complete"
```

Every `[!]` is an instance where a plain `GET` to `169.254.169.254` returns working credentials, and
two filters carry that claim. `select(.IamInstanceProfile != null)` drops instances with no profile,
which have nothing to leak. `http-endpoint=enabled` drops instances with IMDS switched off entirely,
where `http-tokens` retains its last value and still reads `optional` — without it a hardened
instance is reported as a finding. A `hop` above 1 is a softer, second finding: it lets a container
or proxied request one hop away reach IMDS, and it is also what containerised workloads need (§6).

#### Query 4 — Inspect what CloudTrail does not log: was the IMDSv1 path in use?

```bash
REGION="us-east-1"; INSTANCE_ID="<instance-id-from-Query-1>"

# The fetch is in no log. This metric is the closest thing: a nonzero Sum means IMDS was
# accessed WITHOUT a token, i.e. over IMDSv1, on this instance.
NOTOKEN=$(aws cloudwatch get-metric-statistics --namespace AWS/EC2 \
  --metric-name MetadataNoToken --dimensions Name=InstanceId,Value="$INSTANCE_ID" \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 3600 --statistics Sum --region "$REGION" \
  --query 'Datapoints[?Sum>`0`]' --output json | jq 'length')
[ "${NOTOKEN:-0}" -gt 0 ] && echo "[!] $INSTANCE_ID: $NOTOKEN hour(s) of IMDSv1 access — the SSRF-reachable path was in use" \
                          || echo "[i] $INSTANCE_ID: no IMDSv1 access recorded — theft, if any, used IMDSv2 (real code execution)"
```

Pull GuardDuty alongside it — `aws guardduty list-findings --detector-id <id> --finding-criteria`
filtered to `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`, `.InsideAWS` and
`UnauthorizedAccess:EC2/MetadataDNSRebind`, **per region**, because the finding lands where the
credential was used, not where the instance runs.

`MetadataNoToken` is a **usage** metric, not an attack metric — an old SDK drives it too — and its
silence is the informative half: zero across the window means a forged plain `GET` obtained nothing,
narrowing the intrusion to genuine code execution. **GuardDuty's silence proves nothing**, for two
documented reasons: once it sees continued activity from a remote source its model learns it as
expected and stops generating the finding, and `.InsideAWS` fires only when the calling account
differs from the instance's own.

#### Query 5 — Session reconstruction: everything done with the stolen credential, all regions

```bash
ACCESS_KEY_ID="<access-key-from-Query-1>"
REGIONS="us-east-1 eu-west-1"
FIRST_SEEN="<time-from-Query-1>"     # ISO8601, earliest event in Query 1

for R in $REGIONS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$R" --output json 2>/dev/null | \
    jq -r --arg r "$R" --arg t "$FIRST_SEEN" '.Events[].CloudTrailEvent | fromjson |
      {time: .eventTime, region: $r, event: .eventName, source: .eventSource,
       ip: .sourceIPAddress,
       phase: (if .eventTime >= $t then "AFTER-FIRST-SEEN" else "before" end),
       error: (.errorCode // "SUCCESS")}'
done | jq -s 'sort_by(.time)'
```

The **"was it used"** pivot, covering **one** session key. The credential self-renews and each
renewal is a new `ASIA...` key, so a single pass is a lower bound — re-run per key until it
converges. Rows creating something durable (`CreateAccessKey`, `CreateUser`, `CreateRole`,
`UpdateAssumeRolePolicy`, `PutUserPolicy`, `CreateLoginProfile`) matter most: IAM objects, not
sessions, they outlive every containment step below. `lookup-events` is management-only, so
data-plane calls **will not appear at all**.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The ordering is inverted relative to most credential incidents, and getting it wrong produces a
revocation that looks successful and achieves nothing. **Cut the instance's ability to mint new
credentials first, then revoke the existing ones** — reversed, the next IMDS request returns a
credential too new for the deny to cover.

> Run every command under the **break-glass responder credentials** from §1 — never under an
> instance-profile role, and specifically not under the role being contained. Before relying on
> any query above, confirm the trail is still recording — `aws cloudtrail get-trail-status --name
> <trail> --query IsLogging` must return `True`; if the stolen role could call
> `cloudtrail:StopLogging`, restart it first and treat the gap as permanently lost.

#### Step 1 — Stop the bleeding: replace the instance profile, do not remove it

```bash
REGION="us-east-1"
INSTANCE_ID="<instance-id-from-Query-1>"
QUARANTINE_PROFILE="<quarantine-instance-profile-name>"   # SSM-only, pre-created in §1

ASSOC_ID=$(aws ec2 describe-iam-instance-profile-associations --region "$REGION" \
             --filters Name=instance-id,Values="$INSTANCE_ID" \
             --query 'IamInstanceProfileAssociations[?State==`associated`].AssociationId | [0]' \
             --output text 2>/dev/null)

if [ -n "$ASSOC_ID" ] && [ "$ASSOC_ID" != "None" ]; then
  aws ec2 replace-iam-instance-profile-association --region "$REGION" \
    --association-id "$ASSOC_ID" --iam-instance-profile Name="$QUARANTINE_PROFILE" && \
    echo "[OK] $INSTANCE_ID now holds $QUARANTINE_PROFILE — IMDS can no longer mint the compromised role"
else
  echo "[!] No associated instance profile on $INSTANCE_ID — already replaced, or the instance ID is wrong. Re-read Query 1's instance_id field"
fi
```

> **Replace, do not `disassociate-iam-instance-profile`.** Disassociating removes the instance's
> credentials entirely, severing the SSM agent — every later `ssm send-command` then hangs. This
> **breaks the application** on that instance: an intended trade. It does **not** invalidate
> credentials the attacker already holds — that is Step 2.
>
> **And it hands the attacker the quarantine role.** IMDS now mints *that* role, reachable by the
> same primitive that took the first one, and `AmazonSSMManagedInstanceCore` is the responder's own
> forensic channel. Step 3 closes the IMDS route but runs *after* this step, and does nothing about
> code execution on the host, which §4 keeps in scope. So: the quarantine profile carries
> `AmazonSSMManagedInstanceCore` and nothing else, ever; assume the attacker holds it from the
> moment this command returns; treat SSM output from this host as attacker-influenced.
>
> **Under Default Host Management Configuration this instruction inverts.** With DHMC on, SSM Agent
> authenticates through the *instance identity role*, so `disassociate-iam-instance-profile` does
> not sever the agent and there is nothing to preserve by replacing. Disassociate instead — it
> leaves IMDS with no instance-profile role to mint at all. Check the setting first (§1).

#### Step 2 — Revoke the sessions already issued, now that no new ones can be minted

```bash
ROLE_NAME="<role-from-Query-1>"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$NOW"'"}}}]}' && \
    echo "[OK] Revoked all sessions for role $ROLE_NAME issued before $NOW"
else
  echo "[!] Role $ROLE_NAME not found — confirm the value came from Query 1's role field (sessionIssuer.userName), not from the ARN's last segment, which is the instance ID"
fi
```

> This works **only because Step 1 already ran** — in the other order a single re-fetch defeats it.
> It does not gate the role: other instances carrying this profile still mint fresh, non-denied
> credentials, which is why Eradication enumerates them.

#### Step 3 — Restore known-good metadata configuration on the instance

```bash
REGION="us-east-1"; INSTANCE_ID="<instance-id-from-Query-1>"

aws ec2 modify-instance-metadata-options --instance-id "$INSTANCE_ID" --region "$REGION" \
  --http-tokens required --http-endpoint enabled --http-put-response-hop-limit 1 && \
  echo "[OK] $INSTANCE_ID now requires IMDSv2 with a hop limit of 1"
```

`--http-tokens required` makes the plain `GET` return `401 - Unauthorized`, closing the SSRF path; a
hop limit of 1 stops a container or proxied request one hop away reaching IMDS. **It does not fix
the SSRF, does not invalidate stolen credentials, and does not stop code execution on the host using
IMDSv2 properly.** Two live costs here: an SDK too old to negotiate IMDSv2 loses credentials, and
**a hop limit of 1 breaks containers** — AWS documents 2 as the container value, so use
`--http-put-response-hop-limit 2` if this host runs any. A containment decision either way; see §6
before setting the account default.

#### Step 4 — Contain the acting principal and isolate the host

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REVOKE_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$NOW"'"}}}]}'

if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')     # role ARN: name = 2nd segment. $NF is
                                                        # the session name (the instance ID).
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document "$REVOKE_DOC" && echo "[OK] Revoked sessions for role $R"
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')    # user ARN: name = LAST segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] Disabled key $K for $U"
  done
  echo "[!] An IAM USER ARN here means the pivot left the instance-profile path — treat as a separate credential incident"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

Network isolation is last and **sequencing-sensitive**: an egress-zero quarantine security group
severs the SSM agent's outbound 443, so collection must run **before** isolation or the group must
permit 443 to the SSM endpoints. Collect volatile evidence first — the SSRF's location lives in the
application log, nowhere in AWS.

---

## 4. Eradication

### Remove Attacker Access

#### Every other instance holding the same instance profile is in scope

Step 2 covered sessions issued before the cutoff, but every other instance carrying this profile
mints fresh, non-denied credentials on demand. The role is not contained until each is assessed.

```bash
REGIONS="us-east-1 eu-west-1"        # every region you operate in
ROLE_NAME="<role-from-Query-1>"

# Instance profiles are GLOBAL (one IAM call) but the association API is REGIONAL, so the
# second half must loop or the role is declared contained on the strength of one region.
PROFILE_ARNS=$(aws iam list-instance-profiles-for-role --role-name "$ROLE_NAME" \
                 --query 'InstanceProfiles[].Arn' --output text 2>/dev/null | tr '\t' '\n')
echo "[i] Instance profiles carrying $ROLE_NAME:"; echo "$PROFILE_ARNS" | sed 's/^/    /'

for R in $REGIONS; do
  echo "== $R =="
  # No server-side filter for the profile ARN on this call, so match client-side.
  aws ec2 describe-iam-instance-profile-associations --region "$R" \
    --filters Name=state,Values=associated --output json 2>/dev/null | \
    jq -r --arg arns "$PROFILE_ARNS" --arg r "$R" '
      ($arns | split("\n") | map(select(length > 0))) as $want |
      .IamInstanceProfileAssociations[] |
      select(.IamInstanceProfile.Arn as $a | $want | index($a)) |
      "[!] \($r) \(.InstanceId) still carries \(.IamInstanceProfile.Arn)"'
done
echo "[OK] Shared-profile enumeration complete for $ROLE_NAME across: $REGIONS"
```

Each `[!]` is an instance that can hand out the same role. Enforce IMDSv2 on all of them (Step 3's
command) before removing the emergency deny, or its expiry returns the fleet to the state that
produced the incident.

#### Fix the SSRF, or the containment is temporary

Enforcing IMDSv2 closes the metadata route, not the vulnerability that reached it. Use the request
URI in the web-ACL log, whose label names the component that carried the payload, to locate the
vulnerable parameter. **No matching label does not mean there was no SSRF:** the body variant
inspects only up to the protection pack's size limit and handles oversize content with `Continue`,
so a payload beyond it is never labelled — and code execution produces no inbound signature at all.

#### Remove the persistence the stolen credential established

From Query 5's `AFTER-FIRST-SEEN` rows, in order of how long each outlives the session:

- **Access keys** created in the window — `aws iam update-access-key --status Inactive`, then delete
  once documented. The real persistence: long-lived IAM objects, unaffected by everything in §3
- **Login profiles** — `aws iam delete-login-profile` for any created then. **New users and roles**:
  a role trusting an outside account is a full re-entry path, and is the role-trust-backdoor playbook
- **Policies written in the window** — `../iam.privilege-escalation.inline-policy-grant/` inline,
  `../_superseded/aws.privilege-escalation.iam-managed-policy-escalation/` managed
- **Anything read** — Secrets Manager values, SSM parameters and KMS-decryptable ciphertext are
  **management** events and appear in Query 5 by name, so the exact list is recoverable rather than
  needing a blanket rotation. S3 object reads are data events and do not appear

#### Right-size the instance profile role

`aws iam list-attached-role-policies` and `list-role-policies` print the blast radius of this
incident — every permission there was the attacker's. The durable fix is not removing what the
workload needs; it is scoping the role so a credential is worthless off the instance (§6).

#### Remove emergency policies once clean

```bash
ROLE_NAME="<role-from-Query-1>"
aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "EmergencyRevokeSessions" 2>/dev/null
# Step 4 uses the IAM-user path when the pivot left the instance-profile route entirely.
aws iam delete-user-policy --user-name "<pivoted-user-name>" --policy-name "EmergencyRevokeSessions" 2>/dev/null
# D-0: assert, do not announce. delete-*-policy exits 0 whether or not anything was
# there, so re-list and confirm absence; a listing failure is INCONCLUSIVE, never [OK].
LEFT=0; UNK=0
for RN in "<grantor-role-name>" "<grantee-role-name>"; do
  L=$(aws iam list-role-policies --role-name "$RN" --query 'PolicyNames[]' --output text 2>/dev/null)
  if [ -z "$L" ] && ! aws iam get-role --role-name "$RN" >/dev/null 2>&1; then UNK=$((UNK+1)); continue; fi
  printf '%s' "$L" | tr '\t' '\n' | grep -qE '^Emergency' && { echo "[FAIL] $RN still carries an Emergency* policy"; LEFT=$((LEFT+1)); }
done
U=$(aws iam list-user-policies --user-name "<grantor-user-name>" --query 'PolicyNames[]' --output text 2>/dev/null)
printf '%s' "$U" | tr '\t' '\n' | grep -qE '^Emergency' && { echo "[FAIL] grantor user still carries an Emergency* policy"; LEFT=$((LEFT+1)); }
[ "$UNK" -gt 0 ] && echo "[!] $UNK principal(s) could not be listed — INCONCLUSIVE, not clean"
{ [ "$LEFT" -eq 0 ] && [ "$UNK" -eq 0 ]; } && echo "[OK] No Emergency* policy remains on any contained principal"
```

Restore the real instance profile with `replace-iam-instance-profile-association` only after
Recovery's checks pass — the quarantine profile is what stops the instance re-issuing the role while
the application fix is in flight.

---

## 5. Recovery

### Restore Clean State

#### Verify IMDSv2 is enforced and no token-less access has occurred since

```bash
REGION="us-east-1"; INSTANCE_ID="<instance-id-from-Query-1>"
CONTAINED_AT="<iso8601-containment-timestamp>"

OPTS=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
         --query 'Reservations[0].Instances[0].MetadataOptions' --output json)
TOKENS=$(echo "$OPTS" | jq -r '.HttpTokens'); HOP=$(echo "$OPTS" | jq -r '.HttpPutResponseHopLimit')
[ "$TOKENS" = "required" ] && echo "[OK] $INSTANCE_ID requires IMDSv2" \
                           || echo "[FAIL] $INSTANCE_ID HttpTokens=$TOKENS, expected required"
[ "$HOP" = "1" ] && echo "[OK] $INSTANCE_ID hop limit is 1" \
                 || echo "[FAIL] $INSTANCE_ID hop limit is $HOP, expected 1"

# NOT MetadataNoToken. AWS documents the two metrics as mutually exclusive per instance:
# with IMDSv1 disabled it stops emitting, so querying it here returns zero by construction
# and the [FAIL] branch is unreachable. Post-enforcement the informative metric is the
# rejection counter — nonzero means an IMDSv1 caller is still resident and being refused.
RAW=$(aws cloudwatch get-metric-statistics --namespace AWS/EC2 \
        --metric-name MetadataNoTokenRejected \
        --dimensions Name=InstanceId,Value="$INSTANCE_ID" \
        --start-time "$CONTAINED_AT" --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --period 3600 --statistics Sum --region "$REGION" --output json)

# Never collapse an API failure into the pass value: no output is INCONCLUSIVE, not clean.
if [ -z "$RAW" ]; then
  echo "[!] MetadataNoTokenRejected returned nothing — API error, wrong region, or the"
  echo "    break-glass principal lacks cloudwatch:GetMetricStatistics. INCONCLUSIVE."
else
  N=$(printf '%s' "$RAW" | jq '[.Datapoints[]? | select(.Sum > 0)] | length')
  [ "$N" -eq 0 ] && echo "[OK] No rejected IMDSv1 attempt on $INSTANCE_ID since $CONTAINED_AT" \
                 || echo "[!] $N hour(s) with rejected IMDSv1 attempts — an IMDSv1 caller is still resident on the host"
fi
```

#### Verify the role session is no longer being used off-instance

```bash
REGION="us-east-1"
INSTANCE_ID="<instance-id-from-Query-1>"
ROLE_NAME="<role-from-Query-1>"
CONTAINED_AT="<iso8601-containment-timestamp>"

# Keyed on the INSTANCE ID, because Username matches the session name. Keyed on the role
# name it returns zero unconditionally, which is why zero rows is inconclusive, not clean.
EVENTS=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$INSTANCE_ID" \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -c --arg role "$ROLE_NAME" '[.Events[].CloudTrailEvent | fromjson |
     select(.userIdentity.sessionContext.sessionIssuer.userName == $role) |
     {time: .eventTime, event: .eventName, ip: .sourceIPAddress}]')

TOTAL=$(echo "$EVENTS" | jq 'length')
if [ "$TOTAL" -eq 0 ]; then
  echo "[!] Zero events for $INSTANCE_ID since $CONTAINED_AT — INCONCLUSIVE, not clean."
  echo "    Confirm the instance ID is right and the lookup is keyed on it, not on the role name;"
  echo "    a role-name lookup returns zero for every instance-profile session that ever ran."
else
  echo "[i] $TOTAL post-containment event(s); review the ip field against §1's egress set:"
  echo "$EVENTS" | jq -r '.[] | "    \(.time) \(.event) from \(.ip)"'
fi
```

Then re-run Query 3 account-wide and expect zero `[!]` lines: a profile-bearing instance still
permitting IMDSv1 is the precondition for this incident, so any remainder is unremediated.

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rules MUST fire on:"
echo '  userIdentity.arn = "arn:aws:sts::111122223333:assumed-role/AppServerRole/i-0123456789abcdef0"'
echo '  sourceIPAddress  = "203.0.113.77"   (an address in NO fleet-egress CIDR)'
echo "  -> imds_role_session_offnet, high. ANY eventName and ANY eventSource: the rule filters on"
echo "     neither, and a version that does is the original defect reborn."
echo '  Second event, same ARN, from "10.0.4.19" within the hour -> the value_count correlation'
echo "     fires medium on two distinct addresses for one session."
echo
echo "The rules MUST NOT fire on:"
echo '  1. The same ARN from "10.0.4.19" alone — the instance calling through a VPC interface'
echo "     endpoint with its own private address. In fleet_egress, so silent."
echo '  2. sourceIPAddress = "ec2.amazonaws.com" or "AWS Internal/3" — excluded by aws_internal'
echo "     in BOTH the headline rule and the correlation's base rule, for two different"
echo "     reasons. In the headline rule a cidr match cannot evaluate a DNS name, so these"
echo "     would score as off-net. In the base rule, value_count counts DISTINCT"
echo "     sourceIPAddress values, so one real address plus one service form is two and"
echo "     gt: 1 fires on a session that never left its own egress path."
echo '  3. ".../assumed-role/DeployRole/jenkins-build-42" from any address — a human or pipeline'
echo "     session. The session name is not an instance ID, so the regex does not match."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| An application on the instance could be induced to request an arbitrary URL | No egress allow-list or URL validation in the application; SSRF treated as an application-quality bug rather than a cloud-credential exposure |
| That request returned working role credentials | IMDSv1 still permitted on an instance holding an instance profile. `HttpTokens=optional` was the launch default and no SCP required `required` |
| The credentials worked from the attacker's own infrastructure | The role's policies carried no condition binding them to the instance, the VPC or any source. A credential valid from anywhere is a credential worth stealing |
| The theft was not detected | Deployed rules watched an inbound signature and a flow log that does not record metadata traffic. Nothing watched the credential being used — the only observable stage |
| The blast radius was the whole role | One shared instance profile across a fleet, scoped to what the most demanding workload needed rather than to what each instance needed |
| Revocation was attempted before the source was cut | `aws:TokenIssueTime` was applied while the host could still reach IMDS, so the next fetch produced a credential the deny did not cover |

### Recommended Guardrails

**Deny the IMDSv1 path — at launch, on modification, and on use**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{ "Sid": "RequireImdsV2", "Effect": "Deny",
  "Action": "ec2:RunInstances", "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": { "StringNotEquals": { "ec2:MetadataHttpTokens": "required" } } },
{ "Sid": "DenyIMDSv1HttpTokensModification", "Effect": "Deny",
  "Action": "ec2:ModifyInstanceMetadataOptions", "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": { "StringNotEquals": { "ec2:Attribute/HttpTokens": "required" },
                 "Null": { "ec2:Attribute/HttpTokens": false } } },
{ "Sid": "RequireAllEc2RolesToUseV2", "Effect": "Deny",
  "Action": "*", "Resource": "*",
  "Condition": { "NumericLessThan": { "ec2:RoleDelivery": "2.0" } } }
```

`StringNotEquals` and `NumericLessThan` are the right operators — the values are literal, and the
`*Like` requirement bites only when a `*` appears in the value. The `Null` clause is load-bearing:
without it the second statement also denies calls that omit the attribute entirely. The third is the
strongest single control here: it turns the technique off rather than making it visible, and applies
safely account-wide because absent EC2 role credentials the key is missing and the statement has no
effect. Deploy it **after** `MetadataNoToken` reads zero fleet-wide — before that it breaks every
IMDSv1 workload at once.

**Bind the credential to where it was delivered — the only control that closes §2's blind spot**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Per instance, on the ROLE's permissions policy (not its trust policy):
{ "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::app-bucket/*"],
  "Condition": { "ArnEquals": { "ec2:SourceInstanceARN":
    "arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0" } } }

// Shared role — SCP fragment, the form AWS publishes:
{ "Sid": "CredentialMustBeUsedWhereItWasDelivered", "Effect": "Deny",
  "Action": "*", "Resource": "*",
  "Condition": {
    "StringNotEquals": { "aws:Ec2InstanceSourcePrivateIPv4": "${aws:VpcSourceIp}" },
    "Null": { "ec2:SourceInstanceARN": "false" },
    "BoolIfExists": { "aws:ViaAWSService": "false" } } }
```

`ec2:SourceInstanceARN` is populated only for a request made from an EC2 instance using the instance
profile, so off-instance the key is absent, the `Allow` does not apply, and the call fails closed.
AWS: "If the same IAM role is associated with another instance, the other instance cannot perform
any of these actions" — which is exactly the in-fleet case §2 cannot see. Its cost is a per-instance
policy. The shared-role form compares the private address the credential was **delivered** to
against where the request **arrived** from, so a credential moved to a second instance in the same
VPC fails; `Null` scopes it to EC2 role credentials and `aws:ViaAWSService` exempts forward access
sessions, which do not carry the originating VPC context. Pair it with the same test on
`aws:Ec2InstanceSourceVpc` against `${aws:SourceVpc}` — private addresses are not globally unique
and AWS is explicit that the VPC key must accompany the IP key. **Its cost is architectural:**
`aws:VpcSourceIp` exists only for VPC-endpoint-routed requests, so as written this denies everything
egressing through NAT. Deploy it only on a fleet already reaching AWS over interface endpoints;
`aws:SourceVpc` / `aws:SourceVpce` is the coarser fallback. Trust-policy use is not documented.

Do **not** substitute `aws:SourceIp`, and state its failure direction correctly, because the
intuitive reading is backwards. AWS documents the key as present "except when the requester uses a
VPC endpoint". In an `Allow`, an absent key means the condition does not match, the `Allow` does not
apply, and endpoint-routed traffic fails **closed** — an outage, not a bypass. `aws:VpcSourceIp` is
AWS's documented replacement and is present exactly when `aws:SourceIp` is not.

**Structural controls**
- **Set the account-level IMDS default** per region with `aws ec2 modify-instance-metadata-defaults
  --http-tokens required --http-put-response-hop-limit <n>`, plus `--http-tokens-enforced enabled`
  if launches should fail rather than default. **Choose `<n>` deliberately — it applies to every
  future launch in that region.** AWS's own instruction uses `2` "if your instances will host
  containers" and `-1` (no preference) otherwise, and documents that "in a container environment, a
  hop limit of `1` can cause issues": a container reaching IMDS through the host spends the extra
  hop. A hop limit of `1` is the stronger control against a proxied SSRF **and breaks every
  containerised workload launched afterwards**, silently, at credential-fetch time. Use `1` only
  where nothing is containerised. Auto Scaling groups need these options in a **launch template**
  referenced by a **specific version**, or new instances do not get them
- **One instance profile per workload** — the blast radius here is exactly the role's policy list
- **Treat SSRF as a credential-exposure class**: an outbound allow-list in the application stops the
  request before IMDS ever sees it

**Detection improvements**
- Deploy the credential-**use** rules and delete the flow-log rule outright — it cannot fire, and a
  rule sitting at zero reads as coverage
- Own and review the fleet-egress allowlist whenever NAT gateways, zones or transit routes change
- Alert on `ec2RoleDelivery` = `1.0` as a migration work-list, promoted once `MetadataNoToken` is
  zero fleet-wide; route both `InstanceCredentialExfiltration` types to P0 as corroboration, never
  as the control

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1552.005 — Unsecured Credentials: Cloud Instance Metadata API (with T1190 — Exploit Public-Facing Application — for the SSRF delivery) |
| MITRE tactic | Credential Access (TA0006); Initial Access (TA0001) for the delivery |
| Event source | **None for the theft** — no CloudTrail event, and on the documented list of traffic VPC Flow Logs do not capture. Downstream use carries the called service's own `eventSource`, management **or** data plane depending on the call, so a management-only trail misses `s3:GetObject` |
| Key discriminator | An instance-profile role session — `userIdentity.arn` ending `assumed-role/<Role>/i-*`, whose last `/` segment IS the instance ID — used from a `sourceIPAddress` that is not one of that instance's egress addresses. Not any event name. `sessionContext.ec2RoleDelivery` is `1.0` for IMDSv1, `2.0` for IMDSv2; there is no `ec2InstanceId` field |
| Field-shape traps | `AttributeKey=Username` matches the **session name** — for an instance-profile session, the **instance ID**; a role-name lookup returns zero forever. Assumed-role ARN: role name is the **2nd** `/` segment, `$NF` is the session name. `sourceIPAddress` may be a DNS name or `AWS Internal/<n>` |
| "Was it used" pivot | Session reconstruction by `accessKeyId`, per region. Covers **one** session key; the credential self-renews and each renewal has its own key, so repeat until it converges |
| Blast radius | Every permission the instance profile role holds, exercisable from anywhere, self-renewing while the host stays compromised. Every other instance sharing the profile is equally exposed |
| Revocation semantics | No key to disable, no session to terminate individually. `aws:TokenIssueTime` revokes only tokens issued **before** the cutoff, so it works **only after** the instance profile is replaced |
| Error strings | `AccessDenied` / `AccessDeniedException` on the stolen credential's denied calls; `VpceAccessDenied` for a VPC endpoint policy violation; EC2's own errors carry a `Client.` prefix (`Client.InvalidInstanceID.NotFound`) |
| GuardDuty | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` (High); `.InsideAWS` (High; Medium if the calling account is affiliated) — and `.InsideAWS` fires **only when the calling account differs from the instance's**, so same-account lateral use raises nothing. The resource equivalents are not symmetric: `ResourceCredentialExfiltration.OutsideAWS` covers a Lambda function **or** an ECS task, `.InsideAWS` covers an **ECS task only**. Also `UnauthorizedAccess:EC2/MetadataDNSRebind` (High). No finding type for IMDSv1 usage |

**MITRE mapping note.** The source set carries two mappings and, against what each rule actually
observes, one is imprecise and the other inverted. The four web-ACL rules tag **T1552.005** — three
at the sub-technique, one at the bare parent `T1552`, an inconsistency within one set of siblings.
T1552.005 states the attacker's *objective*, but what the rule observes is an inbound request
exploiting an application into issuing one it should not: **T1190**. Both tags belong, and this
directory's inbound rule carries both. The flow-log rule tags **T1190**, wrong in both directions:
what it purports to observe is a host reaching the metadata API — T1552.005 exactly, and not T1190
at all, because nothing public-facing is exploited where a flow record would be written. That is
compounded by the rule being unable to fire, and **that part is an operational defect rather than a
mapping-precision note** — the one finding here worth raising even if nothing else changed.

### Residual Risk

**Every credential already copied stays valid until it expires, and you cannot enumerate them.**
Instance-profile credentials rotate automatically, with new ones available before the old expire, so
an attacker who held the primitive for any length of time holds a series of overlapping credentials
rather than one. AWS documents no fixed lifetime and this playbook asserts none. Query 5 covers the
keys you know about; one you never saw used is invisible and stays usable until its own expiry, and
Step 2's deny reaches it only if it was issued before the cutoff.

**Everything the role could read is disclosed, and for object data you cannot know what.** Secrets
Manager values, SSM parameters and KMS-decryptable ciphertext must be rotated regardless of whether
Query 5 shows them read — enumerable, but only within retention and only for the keys you found. S3
object reads are data events and absent entirely from a management-only trail. IAM objects the
credential created — an access key, a login profile, a role with an external trust — survive the
profile replacement, the revocation and the IMDSv2 enforcement, because none reference the session
that created them. Enforcing IMDSv2 leaves the SSRF itself intact: the same primitive still reaches
internal APIs, databases and other link-local addresses.

**Containment gave the attacker the quarantine role, and Step 3 does not take it back.** Between
Step 1 and Step 3 the host still holds the SSRF or code execution, so IMDS hands out whatever
profile is attached — now the quarantine profile, whose `AmazonSSMManagedInstanceCore` is the
channel the response itself runs on. Step 3 closes IMDS to a forged `GET` but not to code executing
as the application user, and §4 keeps that code execution explicitly in scope. Assume the quarantine
role is compromised from Step 1 onward, keep it to SSM and nothing else, and do not treat SSM output
from this host as trusted evidence.

**A credential used from inside the fleet's own egress set is undetected, not absent** — the largest
residual gap, unchanged by every step above, and set out in full in §2. Nothing detective closes it;
only the §6 source-pinning controls do. Until one is deployed, a second compromised host in the same
VPC is a blind spot you are choosing to keep.

**Detection stays blind to the interval between theft and use.** Nothing here observes a credential
taken and not yet used, and nothing can — the fetch produces no telemetry and an idle credential is
indistinguishable from the instance's own. That interval belongs to the attacker, and it is why a
confirmed SSRF justifies treating the role as compromised without waiting for off-instance use.
