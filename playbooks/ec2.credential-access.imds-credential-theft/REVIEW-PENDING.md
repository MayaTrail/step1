# Review findings still to fold — EC2 IMDS credential theft

Independent review complete. **B1 and B2 folded** (see below). Everything else is open.
Do not mark this technique `[x]` until the should-fixes are addressed.

## Folded already

- **B1 — false `[OK]` on a post-containment assertion.** The Recovery check queried
  `MetadataNoToken` for the window *after* Step 3 set `HttpTokens=required`. AWS documents
  the two metrics as **mutually exclusive per instance**: with IMDSv1 disabled,
  `MetadataNoToken` stops emitting entirely, so the count was zero by construction and the
  `[FAIL]` branch was unreachable. Now uses `MetadataNoTokenRejected` — nonzero means an
  IMDSv1 caller is still resident and being refused — and an empty API response reports
  `[!] INCONCLUSIVE` instead of collapsing into the pass value.
- **B2 — the KQL egress allowlist could not match a CIDR** while the file's own header
  instructed the deployer to load VPC CIDRs into it. `set_has_element` is exact string
  equality, so every ordinary endpoint-routed call scored as off-net and drew the P0
  verdict. Now `ipv4_is_in_any_range`, which accepts CIDRs and bare addresses. Note the
  Sigma rule already used `|cidr` correctly — the two shipped files had disagreed on the
  watchlist's shape.

## Open — should-fix

1. **The correlation's base rule lacks the `aws_internal` exclusion.** `imds_role_session`
   carries only the ARN regex, so the `value_count` over distinct `sourceIPAddress` counts
   `ec2.amazonaws.com` and `AWS Internal/3` as distinct addresses and reaches `gt: 1` on
   one real IP plus one service form. §5's near-miss #2 asserts the rules must not fire on
   those — true for the headline rule, false for the correlation. Same issue in the KQL's
   `dcount(SourceIpAddress)`.
2. **The instance *identity* role ARN matches the regex** —
   `arn:aws:sts::<acct>:assumed-role/aws:ec2-instance/i-…` — because `[^/]+` matches
   `aws:ec2-instance` and the session name is a real instance ID. So an instance with **no
   instance profile at all** fires `imds_v1_credential_delivery`, contradicting Query 3's
   stated logic and the rule's own description. The detection note currently claims these
   do not match; that reassurance is wrong. Add a negated filter block or say plainly that
   they match and why that is acceptable.
3. **Containment Step 1 hands the attacker the quarantine role** — IMDS now mints *that*
   role, reachable by the same primitive, and `AmazonSSMManagedInstanceCore` carries the
   responder's own forensic channel. Step 3 closes the route but runs afterwards and does
   nothing against code execution, which §4 keeps in scope. Say so in Step 1's blockquote
   and in Residual Risk. Also: with **Default Host Management Configuration** enabled, SSM
   Agent authenticates via the instance identity role, so `disassociate` does not sever it
   and the quarantine profile is unnecessary — that inverts the section's instruction for
   a growing share of fleets.
4. **Eradication's shared-profile sweep is single-region** while everything else loops
   `$REGIONS`. Instance profiles are global; the association API is regional. The
   section's own claim that the role is not contained until each instance is assessed is
   unmet outside `us-east-1`.
5. **Query 3 flags instances that cannot serve credentials.** The filter matches
   `http-tokens=optional` without checking `http-endpoint=enabled`, so instances with IMDS
   switched off entirely appear as findings. Add the filter or surface `HttpEndpoint`.
6. **§6 states the `aws:SourceIp` failure direction backwards** — the D-e error. In an
   `Allow` with the key absent, the condition does not match, the `Allow` does not apply,
   and endpoint-routed traffic fails **closed** (an outage), not open. The conclusion is
   right, the reasoning is inverted. AWS's documented replacement, `aws:VpcSourceIp`, is
   not mentioned and is the finer-grained option for a shared-role fleet.
7. **Account-wide hop limit of 1 is recommended without its cost.** AWS's own instruction
   for that command uses `--http-put-response-hop-limit 2` and documents why: containers
   on the instance need the extra hop. Setting the account default to 1 breaks every
   containerised workload on every future launch. The benefit is stated twice, the cost
   nowhere — against the register rule to state what a step does not fix.
8. **`ResourceCredentialExfiltration.InsideAWS` is ECS-only**, not "Lambda and ECS" —
   three files say otherwise. `.OutsideAWS` does cover both.
9. **The WAF rule fires on CAPTCHA and CHALLENGE and calls them "reached the
   application."** Both are terminating actions when the request carries no valid token.
   Make the `blocked` filter a list: `['BLOCK', 'CAPTCHA', 'CHALLENGE']`.
10. **No coverage statement for an attacker inside the fleet's egress set.** A credential
    used from another compromised instance in the same VPC, or anything egressing via the
    same NAT, is inside `fleet_egress` → the `high` rule is silent; `DistinctIPs` stays 1
    → the correlation is silent; GuardDuty `InsideAWS` fires only for a *different*
    account. **This is the largest blind spot in the detection thesis** and belongs in §2's
    "what it structurally cannot do" and in Residual Risk.

## Resolved by the review — update the shipped caveats

**`ec2RoleDelivery` serialisation is a STRING.** AWS's own sample event carries
`"ec2RoleDelivery": "2.0"`, quoted, as a direct child of `sessionContext`. The Sigma
`'1.0'` string match is therefore correct. Delete the "confirm against a real event"
caveat at `sigma_t1552_005.yml`, the detection note and the KQL — but **keep** the Sentinel
column placeholder, which remains genuinely unverified.

## Length verdict

Reviewer's judgement: **not splitting is correct, but the overrun is padding.** §2 is at
parity with the largest sibling (269 vs 273), so the queries are not the problem. The
excess is §6 and §4, and it is measurable repetition: the flow-log inertness claim is
restated **seven** times, the session-name-is-instance-ID fact nine, `TokenIssueTime`
semantics eight. F4 requires propagating a thesis correction; it does not require
restating it in every section. ~50 lines of named, non-load-bearing cuts are listed in the
review, landing at sibling parity (~730).
