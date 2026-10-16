# Detection Note: T1190 - SSRF IMDSv1 Role-Name Probe and Credential Harvest (Steps 1 & 2)

## Technique
MITRE ATT&CK T1190 - Exploit Public-Facing Application  
Sub-technique: Server-Side Request Forgery (SSRF) targeting EC2 Instance Metadata Service (IMDSv1)

## Why No Audit Log Events
These two steps operate entirely on the **data plane**:

1. **Step 1 (Role-Name Probe):** The attacker sends an HTTP GET to the victim EC2's Flask proxy
   (`/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`) from a remote
   IP. The EC2 application process makes an outbound link-local HTTP request to the IMDS endpoint.
   IMDSv1 requires no token preflight (http_tokens=optional), so the response returns the attached
   IAM role name. This is a pure network/HTTP exchange — no IAM API is called, no CloudTrail event
   is emitted.

2. **Step 2 (Credential Harvest):** A second SSRF request appends the discovered role name
   (`/latest/meta-data/iam/security-credentials/<role-name>`) to retrieve the full credential
   document (AccessKeyId, SecretAccessKey, Token, Expiration). Again, IMDS credential delivery
   is a local kernel/hypervisor mechanism — not an IAM API call — and generates no CloudTrail event.

## Detection Alternatives

### 1. VPC Flow Logs (Best Available Signal)
- **What to look for:** Flow log entries showing the EC2 instance's ENI making outbound TCP
  connections to `169.254.169.254:80`. Under normal operation, most application instances have
  no legitimate reason to connect to IMDS repeatedly in short succession.
- **Alert pattern:** Multiple ACCEPT flows from instance ENI to `169.254.169.254` within a
  short time window, especially correlated with inbound HTTP traffic from external IPs on port 8080.
- **Log source:** `flowlog-bucket` S3 bucket (as configured in this emulation's Pulumi infra).
- **Limitation:** VPC Flow Logs capture 5-tuple metadata only — they confirm a connection occurred
  but cannot inspect the HTTP path or response body.

### 2. EC2 Instance Metadata Detailed Logging (CloudWatch / application logs)
- **What to look for:** The Flask `/fetch` handler logs the proxied URL. If application-level
  logging is enabled and shipped to CloudWatch Logs, queries searching for
  `169.254.169.254` in the log group for the victim EC2 will surface both SSRF requests.
- **CloudWatch Insights query:**
  ```
  fields @timestamp, @message
  | filter @message like /169\.254\.169\.254/
  | sort @timestamp desc
  | limit 50
  ```
- **Limitation:** Depends on the application logging the outbound URL — attacker can probe
  endpoints that don't log request targets.

### 3. GuardDuty Finding (Triggered in Step 3, Covers Step 2 Retroactively)
- **Finding type:** `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`
- **When it fires:** GuardDuty detects this in Step 3 / Step 4 when the stolen credentials are
  used from a non-EC2 IP address. The finding description references the instance role and the
  originating IMDS delivery, providing retroactive confirmation that credential harvest occurred.
- This is the highest-confidence detection signal for the full SSRF -> credential-use chain,
  though it fires on the *use* of harvested credentials rather than the harvest itself.

### 4. IMDSv2 Enforcement (Preventive Control)
- **Control:** Set `HttpTokens=required` on all EC2 instances (IMDSv2 enforcement). IMDSv2
  requires a PUT preflight to obtain a session token before any GET to IMDS. A server-side
  proxy vulnerability (SSRF) typically cannot follow the two-step IMDSv2 exchange, blocking
  credential harvest entirely.
- **Detection value:** If IMDSv2 is enforced and a probe still appears in VPC flow logs or
  application logs, it indicates an attacker is attempting IMDSv2-aware exploitation.
- **AWS Config rule:** `ec2-imdsv2-check` (managed rule) flags non-compliant instances.

### 5. Network-Level Anomaly Detection
- **Proxy / WAF:** If an application-layer load balancer or WAF sits in front of the Flask
  app, requests to `/fetch` with `url=http://169.254.` in the query string can be blocked
  and alerted as SSRF attempts. AWS WAF custom rules can match this pattern.
- **Host-based:** An EDR or eBPF-based runtime security tool (e.g., Falco, Sysdig) on the
  EC2 host can detect when the web server process opens a TCP socket to `169.254.169.254`.
  Falco rule example:
  ```yaml
  - rule: IMDS access from web process
    desc: Web server process connected to EC2 instance metadata endpoint
    condition: >
      evt.type = connect and
      fd.sip = "169.254.169.254" and
      proc.name in (python3, python, gunicorn, flask)
    output: >
      IMDS connection from web process (proc=%proc.name pid=%proc.pid
      ip=%fd.sip user=%user.name)
    priority: WARNING
  ```

## Summary of Detection Coverage

| Signal | Latency | Fidelity | Requires |
|--------|---------|----------|---------|
| VPC Flow Logs | Near-real-time | Low (no path info) | Flow log export to S3/CW |
| Application logs | Real-time | High (full URL) | App-level logging |
| GuardDuty ExfilOutsideAWS | Minutes | High | GD enabled + creds used externally |
| WAF SSRF rule | Real-time | High (blocks) | WAF in front of app |
| Falco/eBPF host rule | Real-time | High | Agent on EC2 host |
| IMDSv2 enforcement | N/A (preventive) | Absolute | HttpTokens=required on instance |
