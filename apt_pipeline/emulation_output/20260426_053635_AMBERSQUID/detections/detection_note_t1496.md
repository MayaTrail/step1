# Detection Note: T1496 - Resource Hijacking
# AMBERSQUID: SRBMiner-MULTI cryptomining targeting ZEPHYR, TRX, RVN, XMR

## Execution Plane
Data plane — container-internal cryptocurrency mining generates NO CloudTrail events.
The miner process, pool connections, and hash submissions are invisible to CloudTrail.
SRBMiner-MULTI execution is entirely within the ECS container runtime.

## Detection Alternatives (in priority order)

### 1. GuardDuty - Cryptocurrency Mining Findings (HIGHEST PRIORITY)
GuardDuty provides purpose-built findings for cryptomining in AWS:

  - **CryptoCurrency:EC2/BitcoinTool.B** — DNS queries or network connections to known
    cryptocurrency mining pool domains/IPs. Covers 2miners.com, c3pool.com, nanopool.org.
  - **CryptoCurrency:EC2/BitcoinTool.B!DNS** — DNS-based detection variant.
  - **CryptoCurrency:Runtime/BitcoinTool.B** — Runtime agent detection (ECS/EC2 with
    GuardDuty runtime monitoring enabled).
  - **UnauthorizedAccess:EC2/MaliciousIPCaller** — ECS task communicating with known
    malicious IP in GuardDuty threat intel feed.

GuardDuty threat intel is continuously updated with mining pool IPs and domains.
AMBERSQUID mining pools blocked in this lab — GuardDuty findings would not fire
without actual outbound connections, but would fire in real attack scenario.

### 2. VPC Flow Logs - Outbound Mining Pool Connections
Mining pool TCP connections are detectable in VPC Flow Logs attached to the ECS task ENI.

Known AMBERSQUID mining pool ports (all blocked by ambersquid-task-sg in lab):
  - 3333 (default Stratum protocol)
  - 4444 (nanopool XMR)
  - 5555 (alternate Stratum)
  - 7777 (c3pool)
  - 8888 (alternate)
  - 9999 (alternate)
  - 14444 (2miners ZEPHYR)
  - 45560 (alternate)

Sentinel KQL for VPC Flow Log mining detection:
```kql
// Requires AzureNetworkAnalytics_CL or VPC Flow Logs ingested via S3 -> Sentinel
// Substitute with your actual VPC Flow Log table name
VPCFlowLogs
| where DestinationPort in (3333, 4444, 5555, 7777, 8888, 9999, 14444, 45560)
| where Action == "ACCEPT"
| where Direction == "egress"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, Protocol, Bytes
| sort by TimeGenerated desc
```

### 3. DNS Query Logs - Mining Pool Domain Resolution
Route 53 Resolver query logging (if enabled) captures DNS queries from ECS tasks:
  - 2miners.com subdomains (zeph.2miners.com, trx.2miners.com)
  - c3pool.com subdomains
  - nanopool.org subdomains

```kql
// Route53ResolverQueryLogs ingested via S3
Route53ResolverQueryLogs
| where QueryName has_any ("2miners.com", "c3pool.com", "nanopool.org", "moneroocean.stream")
| project TimeGenerated, QueryName, QueryType, ResolverIP, SrcAddr
| sort by TimeGenerated desc
```

### 4. CloudWatch Container Insights - CPU Anomaly
Cryptomining produces sustained near-100% CPU utilization. CloudWatch metrics for
ECS tasks (if Container Insights enabled) can detect this:
  - Metric: ECS/ContainerInsights CpuUtilized
  - Alarm: CpuUtilized > 90% for ECS task for > 5 minutes
  - Combined with: NetworkRxBytes and NetworkTxBytes spike to external IPs

### 5. AWS Cost Anomaly Detection
AMBERSQUID scale (30 Fargate tasks x 16 regions) produces immediate cost spikes.
AWS Cost Anomaly Detection (free service) alerts on unexpected spend increases.
Configure thresholds for:
  - Amazon ECS Fargate spend
  - Amazon SageMaker compute spend
  - Amazon EC2 spend (if ASG instances launched)
Detection lag: ~24 hours for anomaly to surface in billing data.

### 6. AWS Trusted Advisor / Security Hub
  - Security Hub control: ECS.1 - ECS task definitions should not have elevated privileges
  - Security Hub control: ECS.2 - ECS services should not have public IP addresses automatically assigned
  - Trusted Advisor: EC2 instances with high utilization (billing anomaly signal)

## AMBERSQUID-Specific IOCs for This Technique
- Miner binary: SRBMiner-MULTI (UPX-packed ELF)
- Mining algorithms: ZEPHYR, TRX (Tron), RVN (Ravencoin), XMR (Monero)
- Mining pools: 2miners.com, c3pool.com, nanopool.org
- Crypto wallets:
  - ZEPHYR: ZEPHYR2vyrpcg2e2sJaA88EM6aGaLCBdiYfiHffrs5b3Fa4p1qpoEPH4UabmhJr5YYF7CxJykLTJmESQWaB9ARNuhb6jvptapVq3v
  - TRX: TFrQ7u9spKk8MBgX6Bze3oxPbs3Yh1tAsq
  - RVN: RNu4dQGeFDSPP5iHthijkfnzgxcW2nPde9
  - XMR (multiple): 89v8xC6Mu2tX27WZKhefTuSnN7f3JMHQSAuoD7ZRe1bV2wfExSTDZe4JwaM4qpjKAoWbAbbnqLBmGCFECiwnXdfSKHt85H3
  - XMR (alt): 8B7ommXjcEpTAHKFFyci1v5ADrqvEbphhHrzbBfJgvqjecbik7vcLonh8rYSstbBxgD8AccrJYEukDaXZB8ns3kTLiXL8BN
  - XMR (alt): 837MGitRYxgEV158RDenxVUfb5mN6qzz78Z1WeaDoiqC4K7H8Pj556vHJoVXL2MCJ5WCGVZTBiRmqJFxeJG3WSQmGKhPC31
  - Monero Ring (hex): Q010500bc3733dbd0576ca26a8595d59b577a4d1e09c019856abfa103b8f08ec0ed36735e0e2f35
  - Monero Ring (hex): Q01050074da7be4fe8216f789041227c08ccbf310617362641336e1f282c398937635a5d3ebbdbf
  - Monero Ring (hex): 007DE31E4FD8213FBCE3586A3D2260C962142BBC605BB41C41
- ECS task: ambersquid-ecs-cluster, ambersquid-task-definition
- Container command in real attack: SRBMiner-MULTI --algorithm ZEPHYR --pool [pool] --wallet [wallet]
