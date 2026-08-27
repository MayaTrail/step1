# Detection Note: ALB Backdoor Verification via HTTP Probe (Step 3)

**Technique:** T1556 - Modify Authentication Process  
**Attack Step:** Step 3 - A/B verification of the conditional auth bypass  
**Audit Visible:** No - HTTP requests to the ALB generate no CloudTrail events

## Why No Audit Log Events

The attacker sends two HTTPS GET requests directly to the ALB DNS name:

1. Request WITH `X-Bypass-Auth: <secret>` header -> expects HTTP 200 from backend Lambda
2. Request WITHOUT the header -> expects HTTP 302 redirect to Cognito hosted UI

Both are data-plane HTTP calls. ALB handles them without calling any AWS management
API, so no CloudTrail management events are emitted.

## Detection Alternatives

### ALB Access Logs (Primary - Highest Fidelity)

ALB access logs record every request including headers forwarded to the backend and
the OIDC context headers ALB sets after Cognito authentication succeeds.

**Signal 1 - Successful 200 without OIDC context headers:**
A request that receives HTTP 200 from a Cognito-protected target group but whose log
line shows no `x-amzn-oidc-accesstoken`, `x-amzn-oidc-identity`, or
`x-amzn-oidc-data` headers being forwarded indicates the Cognito step was skipped.

**Signal 2 - Custom bypass header in 200 response path:**
If the access log format includes `custom_header` or the request headers field, the
`X-Bypass-Auth` header value will appear in log lines corresponding to 200 responses,
providing direct evidence of the backdoor header being used.

**Signal 3 - Source IP with no prior OAuth redirect:**
A source IP receiving a 200 from a Cognito-protected target without a preceding 302
to the Cognito hosted UI domain (`*.auth.<region>.amazoncognito.com`) within the same
session is anomalous. Correlate access log source IPs with redirect sequences.

### VPC Flow Logs (Supporting)

VPC flow logs capture connection-level metadata (source IP, destination port, bytes,
packets) but not HTTP headers or response codes.

**Signal:** An external IP establishing a TCP connection to the ALB on port 443 and
receiving a successful response (connection not immediately RST'd) without the
typical redirect-then-auth traffic pattern. Low specificity on its own; combine with
ALB access log correlation.

### GuardDuty Findings (Opportunistic)

If the attacker's egress IP is present in GuardDuty threat intel feeds:
- `UnauthorizedAccess:IAMUser/MaliciousIPCaller` - triggered if the same IP that
  created the bypass rule (CreateRule CloudTrail event) also makes calls to other
  AWS services.
- `UnauthorizedAccess:EC2/MaliciousIPCaller.Custom` - if custom threat lists are
  loaded and contain the attacker IP.

GuardDuty does NOT generate findings for direct HTTP requests to an ALB.

### AWS WAF (If Deployed in Front of ALB)

If AWS WAF is associated with the ALB, WAF logs include full request headers and
allow/block decisions. A custom WAF rule matching on the `X-Bypass-Auth` header
would both block the bypass and generate a log event.

**Recommended WAF rule (detection/block):**  
Match `X-Bypass-Auth` header presence on protected paths -> COUNT (for alerting) or
BLOCK (for prevention) with a log event written to the WAF log group.

### CloudWatch Metrics + Alarms (Rate-Based)

ALB emits `HTTPCode_Target_2XX_Count` and `HTTPCode_ELB_5XX_Count` metrics per
target group. A sudden increase in 2XX responses on a Cognito-protected target group
that has historically served only authenticated users (after business hours, or from
new source IPs) is a weak but automatable signal.

## Recommended Remediation Verification

After detecting and removing the injected rule, confirm remediation via:
- CloudTrail `DeleteRule` event by the responder's principal
- Re-run of the A/B HTTP probe confirming the 200 is now replaced by a 302 redirect
- ALB access logs showing the next unauthenticated request receiving 302 as expected
