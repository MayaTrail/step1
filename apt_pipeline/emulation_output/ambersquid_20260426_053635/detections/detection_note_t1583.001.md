# Detection Note: T1583.001 - Acquire Infrastructure: Domains
# AMBERSQUID: Amplify subdomain acquisition as attacker callback infrastructure

## Execution Plane
Control plane - but generates NO dedicated CloudTrail events for domain acquisition.
AMBERSQUID does not register domains through AWS Route 53 or any directly observable
API. Instead, amplifyapp.com subdomains (e.g. master.d19tgz4vpyd5.amplifyapp.com)
are automatically assigned by AWS Amplify as a side-effect of CreateApp calls made
in victim accounts during prior campaigns. The attacker uses victim-account Amplify
capacity to stage their own callback infrastructure at no cost.

## First Observable Event
The closest CloudTrail proxy is the `amplify:CreateApp` event in T1059.009
(Cloud API execution phase). The assigned `defaultDomain` in the CreateApp
responseElements contains the acquired amplifyapp.com subdomain.
See: sigma_t1583.001.yml / kql_t1583.001.kql

## Detection Alternatives (in priority order)

### 1. CloudTrail Proxy - Amplify CreateApp + responseElements Domain Extraction
Extract `responseElements.app.defaultDomain` from Amplify CreateApp events in
CloudTrail and correlate against threat intel IOC domain lists.

```kql
AWSCloudTrail
| where EventSource == "amplify.amazonaws.com"
| where EventName == "CreateApp"
| extend AssignedDomain = tostring(parse_json(ResponseElements).app.defaultDomain)
| where AssignedDomain != ""
| project TimeGenerated, AssignedDomain, UserIdentityArn, SourceIpAddress
// Feed AssignedDomain list to PassiveDNS / threat intel correlation
```

AMBERSQUID IOC domain: `master.d19tgz4vpyd5.amplifyapp.com`

### 2. PassiveDNS / External Threat Intel
Monitor PassiveDNS feeds (VirusTotal, Shodan, Censys, Farsight DNSDB) for:
  - New A/CNAME records pointing to `*.amplifyapp.com` domains
  - DNS queries from corporate egress IPs to `amplifyapp.com` subdomains
  - Certificate Transparency logs (crt.sh) for new `*.amplifyapp.com` certificates
    indicating freshly created Amplify apps

These feeds detect the attacker's use of the domain before any victim-side
CloudTrail event is available.

### 3. GuardDuty - DNS Finding
If a victim EC2 or ECS task resolves an AMBERSQUID-controlled amplifyapp.com domain:
  - Finding: `Backdoor:EC2/C&CActivity.B!DNS` (if domain is in GuardDuty threat intel)
  - Finding: `UnauthorizedAccess:EC2/MaliciousIPCaller` (if IP is flagged)

GuardDuty threat intel feeds include known C2 domains. AMBERSQUID's Amplify domain
may or may not be in the feed depending on reporting lag after campaigns are disclosed.

### 4. AWS Amplify Access Logs / Web Application Firewall
If AMBERSQUID uses the Amplify domain as a webhook or callback:
  - Amplify access logs (via CloudWatch) capture inbound HTTP requests
  - WAF logs capture anomalous access patterns from external attacker infrastructure
  - Look for POST requests to Amplify endpoints from ECS task source IPs

### 5. Network Proxy / DNS Sinkhole
Enterprise DNS sinkholes and secure web gateways with threat intel feeds can:
  - Block outbound DNS queries to known attacker `amplifyapp.com` subdomains
  - Log and alert on resolution attempts regardless of success/failure
  - Detect HTTP(S) connections to `amplifyapp.com` from ECS task ENI IP ranges

## AMBERSQUID-Specific IOCs for This Technique
- Known attacker domain: `master.d19tgz4vpyd5.amplifyapp.com`
- Domain pattern: `master.<random>.amplifyapp.com` (Amplify default branch naming)
- Infrastructure provider: AWS Amplify (attacker acquires domains in victim accounts)
- No registration cost: amplifyapp.com is a free AWS-assigned subdomain
- Multi-account acquisition: AMBERSQUID creates Amplify apps in each victim account,
  acquiring a new subdomain per account — defenders should monitor their own account's
  Amplify app creation rate (> 5 apps within 10 minutes is anomalous)
