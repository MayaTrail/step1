# IR Playbook: DNS Rebinding to the Metadata Service — a name resolving into `169.254.0.0/16`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential access (a DNS answer points a trusted fetcher at the instance metadata endpoint, defeating hostname validation) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical when the answer is link-local. No legitimate public name resolves into `169.254.0.0/16`, and the range serves EC2 instance metadata, ECS task-role credentials and EKS Pod Identity credentials. The blast radius is whatever the resulting role permits. |
| MITRE Tactics | Credential Access |
| MITRE Techniques | T1552.005 |
| Services in Scope | Route 53 Resolver, EC2 (instance metadata options), ECS, EKS, IAM, STS, CloudTrail, GuardDuty |

**What the technique does:** the attacker controls a domain and points it at `169.254.169.254`.
They then get an application to fetch a URL on that domain — a webhook target, an image importer, a
PDF renderer, a link preview service. The application validates the *hostname* against an
allowlist, which passes, and then resolves it, which returns the metadata address. The fetch goes
to the credential endpoint and comes back with an `AccessKeyId`, a `SecretAccessKey` and a
`Token`. **The hostname allowlist is not bypassed; it is satisfied.**

**Why the usual reflexes miss it.** The defence most teams build is exactly the one this defeats,
so a code review of the fetcher looks clean. And the network evidence does not exist: VPC flow logs
explicitly do not capture *"Traffic to and from `169.254.169.254` for instance metadata"*, so the
connection that follows the resolution is invisible at the network layer. The Resolver query log is
the only AWS record that the redirection ever happened.

**Detection thesis:** read `rdata`, not the query name. A DNS answer inside `169.254.0.0/16` has no
benign explanation for a public name, needs no threshold, and is complete in this log source —
rebinding requires a short TTL, so every such query is a cache miss and every one is recorded.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **Route 53 Resolver query logging enabled and associated with every VPC.** It is opt-in per VPC:
  a configuration is created and then *associated*, and a VPC that was never associated produces
  nothing. `../route53dns.stealth.no-logs-from-amazon-route53-dns-query/` covers its absence.
- **CloudTrail management events for `ec2.amazonaws.com`** — `ModifyInstanceMetadataOptions` is the
  control that decides whether the rebind achieves anything.
- **GuardDuty enabled**, which consumes these same logs and produces
  `UnauthorizedAccess:EC2/MetadataDNSRebind` from them.
- **The list of internal domain suffixes** — private hosted zones, service-discovery namespaces,
  the corporate internal domain. This is the tuning surface for the private-address rule and it
  must exist before the rule is deployed, not after it is noisy.

**Alerting (must be pre-configured)**
- **A DNS answer (`rdata`) beginning `169.254.` → P0**
- **A public name resolving to RFC 1918 or loopback space outside the known internal zones → P1**
- **`ModifyInstanceMetadataOptions` setting `httpTokens` to `optional` or `httpPutResponseHopLimit` above 1 → P1**
- **A DNS Firewall `BLOCK` action on a name that also resolved into link-local or private space → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any instance role under
  investigation; `jq`; `dig` for confirming what a name currently answers.
- The application's list of fetcher endpoints — which services take a URL from user input. This
  turns "some host resolved a bad name" into "this feature was abused".

**Known IOC Baselines**
- Which instances still permit IMDSv1, as a standing inventory. A rebind against an IMDSv2-only
  instance fails, and knowing which is which turns a P0 into a P2 in one lookup.
- Which fetchers are allowed to resolve external names at all. A service that should only ever
  reach internal names resolving an unknown external domain is a finding before the answer matters.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `rdata` beginning `169.254.` — the link-local range serving IMDS, ECS task metadata and EKS Pod Identity | Resolver query logs | T1552.005 |
| P0 | GuardDuty `UnauthorizedAccess:EC2/MetadataDNSRebind` | GuardDuty | T1552.005 |
| P1 | A public name resolving to RFC 1918 or loopback space outside the known internal zones | Resolver query logs | T1590.002 |
| P1 | `ModifyInstanceMetadataOptions` with `httpTokens: optional` or `httpPutResponseHopLimit` > 1 | CloudTrail (`ec2`) | T1552.005 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `firewall_rule_action: BLOCK` on a name that also resolved into private space | Resolver query logs | T1071.004 |
| P2 | One `srcids.instance` resolving an unusual number of distinct external registered domains | Resolver query logs | T1590.002 |
| P3 | An instance-profile session appearing in CloudTrail from an address outside the fleet's egress — this technique's outcome, detected by `../ec2.credential-access.imds-credential-theft/` | CloudTrail | T1552.005 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Free-text match on the address, so the field is lost | `169.254.169.254` in `rdata` is DNS rebinding; in `query_name` it is somebody looking up an IP as a name. Different severity, different response, and the rule reports them identically — so the interesting case is diluted by the boring one | Match `rdata` specifically. `query_name` is projected for context and is not a trigger |
| `AND _exists_:query_name` | Every Resolver query log record carries a `query_name` — it is the name that was asked for. The clause narrows nothing and lends the rule an appearance of specificity it does not have | Removed. The `rdata` prefix test is the whole rule |
| Names one address out of three | `169.254.170.2` serves ECS task metadata and task-role credentials; `169.254.170.23` serves EKS Pod Identity credentials. Both are reached by the identical primitive and neither matches | Match the `169.254.` prefix, and name which endpoint was hit in the verdict |
| Stops at the metadata service | Any public name resolving to private space is the same primitive aimed at an internal admin panel, a database or the Kubernetes API server | A second rule at medium, tuned by **zone suffix** rather than address range — because private hosted zones answer into RFC 1918 by design |
| `group_by: srcids.instance` without qualification | AWS: *"If you see an instance ID... which is not visible in your account, it might be because the DNS query originated from either AWS CloudShell, AWS Lambda, Amazon EKS, or Fargate console."* So the grouping key can name something no API resolves, and an empty `describe-instances` reads as a fabricated record | The field is used and the caveat carried in the rule and the note, so an unresolvable instance ID is expected rather than alarming |
| No use of the DNS Firewall fields | They are the only place AWS states a verdict in this log source, and their **absence** is routinely misread as approval | A companion rule on `BLOCK`/`ALERT`, with the semantics stated: empty means no match, never allowed |

**Recommended detection — read the answer, not the question.**

```yaml
# A DNS answer pointing inside the VPC — DNS rebinding toward the metadata service (T1552.005)
#
# THE SOURCE RULE SEARCHES THE WHOLE RECORD FOR A STRING, AND THE FIELD IT LANDS IN IS THE WHOLE
# MEANING. `"169.254.169.254" AND _exists_:query_name` is a free-text match. That literal can
# appear in two fields and they are unrelated events:
#
#   rdata = 169.254.169.254      -> A DOMAIN THE ATTACKER CONTROLS RESOLVED TO THE METADATA
#                                   ADDRESS. This is DNS rebinding: a browser, a webhook fetcher
#                                   or an SSRF-capable service resolves an ordinary-looking name
#                                   and connects to the link-local metadata endpoint, bypassing
#                                   any allowlist that checks the hostname rather than the answer.
#                                   This is the attack.
#   query_name contains the IP   -> somebody looked up the literal address as a name. Malformed,
#                                   occasionally a scanner, rarely interesting.
#
# The rules below read `rdata` specifically, and the query_name case is not shipped at all.
#
# `AND _exists_:query_name` IS A CHECK THAT CANNOT FAIL. Every Resolver query log record carries a
# query_name — it is the name that was asked for. The clause narrows nothing and contributes
# nothing except the appearance of specificity.
#
# THE ADDRESS SET IS WIDER THAN ONE ADDRESS. 169.254.169.254 is the instance metadata endpoint,
# but 169.254.170.2 serves ECS task metadata and task-role credentials, and 169.254.170.23 serves
# EKS Pod Identity credentials. A rule naming only the first misses two credential endpoints that
# are reached the same way. The whole 169.254.0.0/16 link-local range is matched below by prefix.
#
# AND REBINDING IS NOT ONLY ABOUT METADATA. Any public name resolving to a private address is the
# same primitive pointed somewhere else — the internal admin panel, the database, the Kubernetes
# API. That case ships as its own rule at a lower level, because the ceiling is lower and the
# false-positive surface is real: split-horizon DNS and internal service discovery do this
# legitimately.
#
# THE CACHE LIMITATION DOES NOT HURT HERE, AND THAT IS WORTH KNOWING. AWS logs only unique queries,
# not cache hits — which ruins volume reasoning about stable domains. Rebinding depends on a very
# short TTL by construction, so every rebinding query is a cache miss and every one is logged.
#
# firewall_rule_action IS NOT A VERDICT. AWS populates it "only if DNS Firewall found a match for a
# rule with action set to alert or block", so an empty value means no match — never "allowed by
# policy". It is projected for context and never used as a filter.
title: DNS answer resolved to the instance metadata address range
id: 4b17e920-6c53-48da-95f7-2e0863bc471d
name: r53dns_rebind_to_metadata
status: experimental
description: >-
  A DNS query returned an address in 169.254.0.0/16 — the link-local range that serves EC2 instance
  metadata, ECS task metadata and EKS Pod Identity credentials. Unless the queried name is itself a
  known internal service using link-local addressing, this is DNS rebinding: a name the attacker
  controls answering with an address that reaches a credential endpoint, so that a fetcher which
  validated the hostname connects somewhere else entirely. It needs no threshold and no baseline;
  no legitimate public name resolves into this range.
references:
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs-format.html
  - https://attack.mitre.org/techniques/T1552/005/
tags:
  - attack.credential-access
  - attack.t1552.005
logsource:
  product: aws
  service: route53resolver
detection:
  metadata_answer:
    rdata|startswith: '169.254.'
  condition: metadata_answer
falsepositives:
  - >-
    A container platform or agent that publishes its own link-local service name in internal DNS.
    Rare, nameable, and it should be excluded by query_name rather than by weakening the rdata
    test — the answer is the signal and the name is the exception.
level: critical
---
title: Public domain name resolved to a private address
id: c8203e5f-71b4-40a9-86d2-5f97e14ab630
name: r53dns_rebind_to_private
status: experimental
description: >-
  A DNS query returned an RFC 1918 or loopback address. This is the same rebinding primitive
  pointed at something other than the metadata service — an internal admin panel, a database, the
  Kubernetes API server. It ships lower than the metadata rule because the false-positive surface
  is genuinely large: split-horizon DNS, internal service discovery and private hosted zones all
  answer this way by design. The tuning surface is the ZONE, not the address range, which is why
  the filter below excludes internal domain suffixes rather than internal address space.
references:
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs-format.html
  - https://attack.mitre.org/techniques/T1590/002/
tags:
  - attack.reconnaissance
  - attack.t1590.002
logsource:
  product: aws
  service: route53resolver
detection:
  private_answer:
    rdata|startswith:
      - '10.'
      - '192.168.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.2'
      - '172.30.'
      - '172.31.'
      - '127.'
  # POPULATE BEFORE DEPLOYING with the domain suffixes this organisation resolves privately —
  # private hosted zones, service-discovery namespaces, the corporate internal domain. This is the
  # entire tuning surface and it is a short, stable list. Leaving it empty makes the rule report
  # every internal lookup once, which is how the list gets built.
  internal_zones:
    query_name|endswith:
      - '.internal'
      - '.local'
      - '.compute.internal'
      - '.example.internal'
  condition: private_answer and not internal_zones
falsepositives:
  - >-
    A private hosted zone or service-discovery namespace missing from internal_zones. Expect a
    burst on first deployment; enumerate them once and the rule goes quiet. If it does not go
    quiet, the finding is that public names in this estate resolve to private space.
level: medium
---
title: DNS Firewall blocked or alerted on a query
id: 9f4a6d81-30c7-4e52-b019-72c58ae3f04b
name: r53dns_firewall_action
status: experimental
description: >-
  DNS Firewall matched a rule with an alert or block action. Shipped as a companion because the
  firewall fields are the only place in this log source where AWS states a verdict, and because
  their ABSENCE is routinely misread — AWS populates firewall_rule_action "only if DNS Firewall
  found a match for a rule with action set to alert or block", so an empty value means no match
  and never "allowed by policy". A blocked query is a stopped attempt, which is still intent
  observed and still tells you a host is trying.
references:
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-rule-groups.html
  - https://attack.mitre.org/techniques/T1071/004/
tags:
  - attack.command-and-control
  - attack.t1071.004
logsource:
  product: aws
  service: route53resolver
detection:
  firewall_matched:
    firewall_rule_action:
      - 'BLOCK'
      - 'ALERT'
  condition: firewall_matched
falsepositives:
  - >-
    A domain list that is broader than intended — ad and tracker lists in particular generate
    steady volume from ordinary browsing. Tune by rule group rather than by muting the rule, and
    keep the block action separate from the alert action in routing.
level: medium
```

What this set structurally cannot do: it cannot tell you whether anything connected to the answer.
A DNS log records a resolution, not a session — and for the IMDS case there is no network record at
either layer, because flow logs do not capture that traffic. It cannot name the process that asked;
`srcids.instance` reaches a host at best. And it cannot tell you the firewall allowed anything,
because an empty `firewall_rule_action` means no match.

---

### Key Investigation Queries

> Queries 1 and 2 read the Resolver query logs, most often through CloudWatch Logs Insights over
> the configured log group. Field names are the log-record names from
> `../_ground-truth/route53dns.md` §3. Queries 3 and 4 read the EC2 and CloudTrail APIs.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: what resolved where, and from which host

```bash
REGION="us-east-1"
LOG_GROUP="/aws/route53/resolver-query-logs"
START=$(date -u -v-7d +%s 2>/dev/null || date -u -d '7 days ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string 'fields @timestamp, query_name, query_type, rdata, rcode, srcaddr,
                         srcids.instance, vpc_id, firewall_rule_action, transport
                  | filter rdata like /^169\.254\./
                  | sort @timestamp asc
                  | limit 500')

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'
```

`query_name` is the domain the attacker controls — record it, because it identifies the campaign
and is the thing to block at the DNS Firewall. `rdata` names which credential endpoint was
targeted: `169.254.169.254` is EC2 instance metadata, `169.254.170.2` is ECS task metadata and
`169.254.170.23` is EKS Pod Identity. `srcids.instance` is the host whose fetcher was abused, and
an ID that `describe-instances` cannot resolve is expected — AWS documents CloudShell, Lambda, EKS
and Fargate as producing exactly that.

#### Query 2 — Sweep: is anything else resolving into space it should not

```bash
REGION="us-east-1"
LOG_GROUP="/aws/route53/resolver-query-logs"
START=$(date -u -v-7d +%s 2>/dev/null || date -u -d '7 days ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string 'fields @timestamp, query_name, rdata, srcids.instance, vpc_id
                  | filter rdata like /^(10\.|192\.168\.|127\.|172\.(1[6-9]|2[0-9]|3[01])\.)/
                  | filter query_name not like /\.internal$|\.local$|\.compute\.internal$/
                  | stats count() as queries, count_distinct(rdata) as answers
                          by query_name, `srcids.instance`
                  | sort queries desc
                  | limit 200')

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'
```

Two shapes matter here. A name with **many distinct answers** over a short period is classic
rebinding — the point of the technique is that the answer changes between the validation and the
fetch. A name with one stable private answer is more likely a private hosted zone missing from the
internal-zone list, which is a tuning finding rather than an incident.

#### Query 3 — Inspect: did the rebind reach anything that would answer

```bash
REGION="us-east-1"
INSTANCE="<instance-from-Query-1>"

echo "== can this host's metadata service be reached by an unauthenticated GET =="
aws ec2 describe-instances --instance-ids "$INSTANCE" --region "$REGION" --output json 2>/dev/null | \
  jq -r '.Reservations[].Instances[] |
    "tokens=\(.MetadataOptions.HttpTokens)  hop=\(.MetadataOptions.HttpPutResponseHopLimit)  endpoint=\(.MetadataOptions.HttpEndpoint)  profile=\(.IamInstanceProfile.Arn // "<none>")"' \
  || echo "[i] instance not found — expected if the query came from Lambda, Fargate, EKS or CloudShell"

echo
echo "[i] HttpTokens=required means IMDSv2 only: the rebind fetch is an unauthenticated GET and"
echo "    fails. HttpTokens=optional means it succeeded. That single field is the difference"
echo "    between a P0 and a P2 here, and it is worth checking before anything else."

echo
echo "== what does the name answer right now =="
NAME="<query_name-from-Query-1>"
dig +short A "$NAME" 2>/dev/null || echo "[!] dig unavailable"
echo "[i] A rebinding domain answers differently on each lookup by design. A benign-looking answer"
echo "    now is not evidence the earlier one was wrong — the log is the record, not the live DNS."
```

#### Query 4 — Full session reconstruction of the role that could have been taken

```bash
REGION="us-east-1"
ROLE_NAME="<role-name-from-Query-3>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$ROLE_NAME" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     arn: .userIdentity.arn, ip: .sourceIPAddress,
     error: (.errorCode // "SUCCESS")}' | \
  jq -s 'group_by(.ip) | map({ip: .[0].ip, calls: length, sources: (map(.src) | unique)})'
```

This is the decisive question and the DNS log cannot answer it. If the role's session appears from
an address that is not the instance and not the fleet's NAT egress, the credentials left the host —
and the incident becomes the one in `../ec2.credential-access.imds-credential-theft/`, which
has the full procedure for a credential with no IAM object behind it.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Close the metadata path first — it is the thing that turns a DNS answer into a credential. Then
block the name, then establish whether it already worked.

> Run every command under the **break-glass responder credentials** from §1, never under the
> instance's own role.

#### Step 1 — Enforce IMDSv2 on the affected host

```bash
REGION="us-east-1"
INSTANCE="<instance-from-Query-1>"

CURRENT=$(aws ec2 describe-instances --instance-ids "$INSTANCE" --region "$REGION" --output json 2>/dev/null | \
  jq -r '.Reservations[].Instances[].MetadataOptions.HttpTokens // "unknown"')
if [ "$CURRENT" = "required" ]; then
  echo "[OK] $INSTANCE already requires IMDSv2 — the rebind fetch could not have retrieved credentials"
elif [ "$CURRENT" = "unknown" ]; then
  echo "[!] $INSTANCE not found — the query may have come from Lambda, Fargate, EKS or CloudShell."
  echo "    Those have their own credential endpoints (169.254.170.2, 169.254.170.23) and their own"
  echo "    controls; identify the workload before assuming EC2 semantics."
else
  aws ec2 modify-instance-metadata-options --instance-id "$INSTANCE" \
    --http-tokens required --http-put-response-hop-limit 1 --http-endpoint enabled \
    --region "$REGION" --output json | \
    jq -r '"[OK] \(.InstanceId): tokens=\(.InstanceMetadataOptions.HttpTokens) hop=\(.InstanceMetadataOptions.HttpPutResponseHopLimit)"'
fi
```

`HttpTokens: required` is the fix, and it is a one-call fix. Note that it can break an application
that reads metadata over IMDSv1 — during an active incident that is usually the right trade, and it
should be stated in the incident rather than discovered.

#### Step 2 — Block the name at the DNS Firewall

```bash
REGION="us-east-1"
DOMAIN_LIST_ID="<ir-block-domain-list-id>"
NAME="<query_name-from-Query-1>"

if aws route53resolver get-firewall-domain-list --firewall-domain-list-id "$DOMAIN_LIST_ID" \
     --region "$REGION" >/dev/null 2>&1; then
  aws route53resolver update-firewall-domains --firewall-domain-list-id "$DOMAIN_LIST_ID" \
    --operation ADD --domains "$NAME" --region "$REGION" --output json | \
    jq -r '"[OK] \(.Name): \(.Status) — \(.StatusMessage // "domain added")"'
else
  echo "[FAIL] domain list $DOMAIN_LIST_ID not found — create an IR block list in §1, not now."
  echo "       A DNS Firewall rule group with a BLOCK action, associated with every VPC, is the"
  echo "       fastest containment for this technique and it cannot be built during the incident."
fi
```

Blocking the name stops further resolutions across every associated VPC at once. It does not
retract credentials already retrieved — that is Step 3.

#### Step 3 — Revoke the role's sessions, in the right order

```bash
ROLE_NAME="<role-name-from-Query-3>"

if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name AWSRevokeOlderSessions \
    --policy-document file:///tmp/revoke.json \
    && echo "[OK] sessions issued before now are denied on $ROLE_NAME"
  echo "[!] This is defeated by a single re-fetch. Step 1 must be complete first, or the attacker"
  echo "    simply asks the metadata service for a fresh credential."
fi
```

#### Step 4 — Find the fetcher

The DNS query came from a host, and something on that host resolved an attacker-controlled name.
That something is a feature which takes a URL from user input. Identify it from the application's
own logs at the timestamp in Query 1, because the network telemetry stops at the resolution — and
the feature, not the host, is what will be abused again tomorrow.

---

## 4. Eradication

### Remove Attacker Access

#### Enforce IMDSv2 across the fleet, not just the affected host

```bash
REGION="us-east-1"
aws ec2 describe-instances --region "$REGION" --output json | \
  jq -r '.Reservations[].Instances[]
         | select(.State.Name == "running")
         | select(.MetadataOptions.HttpTokens != "required" or .MetadataOptions.HttpPutResponseHopLimit > 1)
         | "aws ec2 modify-instance-metadata-options --instance-id \(.InstanceId) --http-tokens required --http-put-response-hop-limit 1 --region '"$REGION"'"'
```

Emitted as commands rather than executed. An application that reads metadata over IMDSv1 stops
working the moment `required` is set, and turning that into an outage during an active incident
helps nobody — but the list is the eradication backlog and it should be worked immediately after.

#### Fix the fetcher

The durable fix is in the application: resolve the name once, validate the **resolved address**
against a deny list of link-local and private ranges, and connect to that address rather than
re-resolving. Validating the hostname alone is the defence this technique exists to defeat.

#### Right-size the instance profile

The credentials are worth stealing for what they permit. Compare the role's policies against the
calls the workload actually makes, from Query 4's `sources` list over a normal week.

#### Remove emergency policies once clean

Delete `AWSRevokeOlderSessions` once the host is rebuilt and the fetcher fixed, and decide
deliberately whether the IR domain-list entry stays.

---

## 5. Recovery

### Restore Clean State

#### Verify no host can serve credentials to an unauthenticated GET

```bash
REGION="us-east-1"
WEAK=$(aws ec2 describe-instances --region "$REGION" --output json | \
  jq -r '[.Reservations[].Instances[]
         | select(.State.Name == "running")
         | select(.MetadataOptions.HttpTokens != "required" or .MetadataOptions.HttpPutResponseHopLimit > 1)
         | .InstanceId] | length')
[ "$WEAK" -eq 0 ] && echo "[OK] every running instance requires IMDSv2 with hop limit 1" \
                  || echo "[FAIL] $WEAK instance(s) would still answer a rebound fetch"
```

#### Verify Resolver query logging still covers every VPC

```bash
REGION="us-east-1"
COVERED=$(aws route53resolver list-resolver-query-log-config-associations --region "$REGION" \
  --output json | jq -r '[.ResolverQueryLogConfigAssociations[] | select(.Status == "ACTIVE") | .ResourceId] | unique | .[]')
for V in $(aws ec2 describe-vpcs --region "$REGION" --output json | jq -r '.Vpcs[].VpcId'); do
  echo "$COVERED" | grep -qx "$V" && echo "[OK]   $V has an active query log association" \
                                  || echo "[FAIL] $V has NO query logging — this detection is blind there"
done
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire at critical on:"
echo "  rdata=169.254.169.254  query_name=cdn.attacker.example  (any query_type)"
echo "and MUST fire equally on:"
echo "  rdata=169.254.170.23   — EKS Pod Identity, which the source rule does not match"
echo "The rule MUST NOT fire on:"
echo "  query_name=169.254.169.254.nip.io with rdata=203.0.113.5"
echo "  (the literal address in the NAME, not the answer — the case the source rule conflates)"
echo "  rdata=10.0.1.20 with query_name=db.prod.internal  (an internal zone on the allowlist)"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A fetcher resolved an attacker-controlled name and connected to the answer | The application validated the hostname and not the resolved address — the defence this technique is designed to defeat |
| The metadata service answered an unauthenticated request | `HttpTokens` left at `optional`, so IMDSv1 was available |
| The detection could not distinguish rebinding from a malformed lookup | The rule matched the address as free text rather than reading `rdata` |
| Two credential endpoints were not covered at all | The rule named `169.254.169.254` only; ECS task metadata and EKS Pod Identity live at other link-local addresses |
| There was no fast way to block the name | No DNS Firewall rule group with a block list existed and associated with the VPCs |

### Recommended Guardrails

**Make IMDSv2 mandatory at launch**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["ec2:RunInstances"],
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": { "StringNotEquals": { "ec2:MetadataHttpTokens": "required" } }
}
```

**Protect the query logging that makes this visible**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["route53resolver:DeleteResolverQueryLogConfig",
             "route53resolver:DisassociateResolverQueryLogConfig"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Validate the **resolved address**, not the hostname, in every service that fetches a user-supplied
  URL — and connect to the address you validated rather than re-resolving. This is the only fix
  that closes the technique rather than detecting it.
- Stand up a DNS Firewall rule group with an incident block list, associated with every VPC, before
  it is needed. It is the fastest containment available for this technique and it cannot be created
  during the incident.
- Set `HttpPutResponseHopLimit: 1` unless a container platform requires 2 — and where it does,
  record that the exposure is being accepted.
- Associate Resolver query logging with every VPC, and alert on a VPC without an association. It is
  opt-in per VPC, so coverage is a standing question rather than a one-time setup.

**Detection improvements**
- Read the answer field, not the record. This rule is the clearest example in the corpus of a
  free-text match losing the entire meaning of a finding.
- Match the whole link-local prefix rather than one address. Three credential endpoints live there
  and they are reached identically.
- Never treat an empty `firewall_rule_action` as approval. AWS populates it only on a match, so its
  absence means the firewall did not match — not that it allowed.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1552.005 — Unsecured Credentials: Cloud Instance Metadata API |
| MITRE tactic | Credential Access (TA0006) |
| Primary API | None — the technique is a DNS answer plus an HTTP fetch. The AWS-visible control is `ec2:ModifyInstanceMetadataOptions` |
| Event source | Route 53 Resolver query logs; `ec2.amazonaws.com` in CloudTrail for the metadata options |
| Key discriminator | `rdata` beginning `169.254.` — no public name resolves into link-local space legitimately, so no baseline is needed |
| Ground-truth signal | The query log record itself. Rebinding requires a short TTL, so every such query is a cache miss and is logged — unusually complete for this source |
| "Was it used" pivot | **Not in DNS, and not in flow logs either** — flow logs do not capture metadata traffic. The proof is the role session appearing in CloudTrail from an address that is not the instance |
| Blast radius | Everything the instance profile, ECS task role or EKS Pod Identity role permits |
| Error strings | Not applicable. `rcode` describes the DNS response; `NOERROR` is the normal case for a successful rebind |

**MITRE mapping note:** the source carries bare `T1552 — Unsecured Credentials`. `T1552.005` names
the cloud instance metadata API exactly and carries the IaaS platform, so the sub-technique is
strictly better. `T1590.002 — Gather Victim Network Information: DNS` is carried by the
private-address rule, which observes reconnaissance of internal naming rather than credential
access, and `T1071.004` by the DNS Firewall companion. All verified live 2026-08-30.

### Residual Risk

The DNS log proves a resolution and never a connection, and for the metadata case there is no
network record at either layer — flow logs explicitly do not capture that traffic — so whether the
fetch happened is not answerable from AWS at all. If the instance permitted IMDSv1 during the
window, treat the role as compromised on that basis alone rather than waiting for confirmation that
cannot arrive. Credentials already retrieved self-renew for as long as the fetcher remains abusable,
so the revoke in §3 is worth nothing until the metadata options are fixed. And a rebinding domain
answers differently on each lookup by design: a benign answer when you check it now is not evidence
that the logged answer was wrong.
