# Detection Note: T1090 - Proxy (Lambda Function URL as C2 Relay)

**Execution plane:** data_plane
**Audit visible:** No - proxy forwarding through a Lambda Function URL is HTTP data-plane
traffic. Neither the inbound request to the Function URL nor the outbound relay to upstream
C2 infrastructure appears in CloudTrail. The emulation does not perform real proxy forwarding
(the echo stub stands in), so no real upstream connection is made.

## Why no SIGMA/KQL rule

HTTP relay traffic routed through a Lambda Function URL generates no CloudTrail event.
The documented TI behavior (HazyBeacon routes all C2 commands through the Lambda relay to
obscure the true C2 IP behind a legitimate AWS domain) operates entirely on the data plane.
CloudTrail cannot detect this; it has no visibility into the payload or destination of Lambda
invocations via Function URL.

## Detection alternatives

### VPC Flow Logs - Lambda ENI outbound (real attack, not this emulation)
- In a real HazyBeacon deployment where the relay Lambda is VPC-attached, VPC flow logs
  would show: Lambda ENI source IP -> external C2 IP on port 443. The external IP, if in
  a threat-intel feed, would trigger GuardDuty Backdoor:Lambda/C2ActivityB.
- In this emulation the Lambda has no VPC attachment, so this vector is not applicable
  but represents the real-world detection path.

### GuardDuty - Backdoor:Lambda/C2ActivityB
- GuardDuty evaluates Lambda network destinations against threat-intel feeds. If the
  upstream C2 IP (behind the relay) is known-malicious, this finding fires.
- In the emulation, the Lambda echo stub makes no outbound connections, so this finding
  will not be generated. In a live HazyBeacon operation this is the primary automated
  detection.

### DNS analysis
- The *.lambda-url.*.on.aws domain pattern is a known HazyBeacon IOC (documented TI).
  DNS-layer filtering or threat-intel matching on this subdomain pattern in DNS query logs
  can identify C2 channel setup before data is transacted.
- Caveat: *.on.aws is a legitimate AWS domain used by many non-malicious applications.
  Matching on the full subdomain pattern (randomized prefix) is not practical without
  correlating against newly-created Lambda Function URLs in the account.

### AWS WAF / Network Firewall (preventive, not detective)
- AWS Network Firewall or WAF rules on the VPC cannot block Lambda Function URL traffic
  since the URLs are served from AWS infrastructure outside the customer VPC. This is
  a fundamental limitation of the Lambda-as-proxy technique.

### Lambda CloudWatch Logs - outbound request patterns
- If the Lambda function logs the destination of relay requests (real attack), CloudWatch
  Logs Insights can surface the upstream C2 IP:
  `fields @message | filter @message like /forwarding/ | stats count by destination_ip`
- The HazyBeacon echo stub in this emulation logs no destination (there is none).

## IOC from emulation
- Lambda function 'UpdateWorker' acting as HTTP relay (data plane only)
- *.lambda-url.*.on.aws used as C2 proxy domain - documented HazyBeacon TI IOC
- VPC flow logs would show Lambda ENI outbound in real attack scenario
