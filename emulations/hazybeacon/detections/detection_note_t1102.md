# Detection Note: T1102 - Web Service (Lambda URL as C2 Channel)

**Execution plane:** data_plane
**Audit visible:** No - invoking a Lambda Function URL via HTTP POST is not a CloudTrail
management event. The HTTP call hits Lambda's data plane directly; no API-level log entry
appears in CloudTrail for the invocation itself.

## Why no SIGMA/KQL rule

Lambda Function URL invocations are data-plane traffic (HTTP/S to *.lambda-url.*.on.aws).
They do not generate CloudTrail control-plane events. The C2 channel activation in step 10
(HTTP POST to the Function URL) is invisible to CloudTrail unless Lambda data events are
explicitly enabled for the specific function ARN via a CloudTrail trail - and even then the
event logged is the Lambda invocation record, not the HTTP payload.

## Detection alternatives

### Lambda CloudWatch Logs
- The Lambda function (UpdateWorker echo stub) writes an invocation record to its CloudWatch
  Log Group (/aws/lambda/UpdateWorker) for every request. Log entries include: request ID,
  source IP visible in requestContext.http.sourceIp within the event JSON, HTTP method,
  path, and response latency.
- Alert on: invocations from IP ranges not matching lab egress IPs, unusual invocation
  frequency, or invocations arriving outside business hours.

### VPC Flow Logs (hazybeacon-flow-log)
- If the Lambda function is attached to a VPC (the HazyBeacon relay was not, but a
  hardened variant may be), outbound HTTPS connections from the Lambda ENI to external
  IPs appear in VPC Flow Logs. In the emulation, the Lambda has no VPC attachment,
  so flow logs will not capture its traffic.
- For real HazyBeacon deployments that do use a VPC-attached relay, flow logs showing
  Lambda ENI -> external IP on port 443 are a strong indicator.

### DNS query logs
- CloudWatch Route 53 DNS Resolver query logs (if enabled): DNS resolution for
  *.lambda-url.*.on.aws from lab hosts. An internal host resolving a Lambda URL
  subdomain that it should not know about is suspicious.
- In the emulation, the attack.py script resolves the Function URL from the attacker
  host, not from a compromised internal host, so this applies primarily to the real
  attack scenario where a compromised workstation connects to the relay.

### AWS CloudTrail - Lambda data events (partial coverage)
- Enable CloudTrail data events for Lambda to capture Invoke API calls via SDK/CLI.
  Note: Function URL invocations are NOT captured this way; only SDK/CLI
  `lambda:InvokeFunction` calls are. The Function URL traffic bypasses this.

## IOCs from emulation
- HTTPS POST to *.lambda-url.*.on.aws from lab egress IP (logged in emulation output)
- Lambda CloudWatch Logs showing invocation record with HTTP status 200 and canned response
- Lambda Function URL invoked without AWS SigV4 authentication (AuthType: NONE confirmed)
