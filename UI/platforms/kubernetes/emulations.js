/* ══════════════════════════════════════════
   MayaTrail — Kubernetes APT Emulations Data
   ══════════════════════════════════════════ */

window.MayaTrail = window.MayaTrail || {};
window.MayaTrail.platforms = window.MayaTrail.platforms || {};
window.MayaTrail.platforms.k8s = window.MayaTrail.platforms.k8s || {};

window.MayaTrail.platforms.k8s.emulations = [
  {
    id: 'teamtnt-k8s',
    name: 'TeamTNT \u2014 Kubernetes Cryptojacking',
    origin: 'unknown',
    originLabel: 'UNKNOWN',
    tags: ['Cryptomining', 'Kubelet Exploit', 'Secret Theft', 'DaemonSet Abuse', 'Container Escape'],
    techniqueCount: 13,
    severity: 'HIGH',
    aliases: 'TeamTNT \u00b7 Chimaera',
    attribution: 'Financially Motivated \u2014 Cryptojacking Group',
    activeSince: '2019 \u2014 Present',
    targets: 'Cloud Infrastructure, Kubernetes Clusters, Docker Hosts',
    incidents: ['Mass K8s Dashboard Exploitation (2020)', 'Chimaera Credential Harvesting (2021)', 'AWS Credential Theft via K8s (2022)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1190', name: 'Exploit Exposed K8s Dashboard' },
          { id: 'T1133', name: 'Kubelet API Access (10250)' },
          { id: 'T1078', name: 'Anonymous Kubelet Auth' }
        ]
      },
      {
        phase: 2, name: 'Execution & Persistence',
        techniques: [
          { id: 'T1610', name: 'Deploy Crypto-Mining Pod' },
          { id: 'T1053.007', name: 'CronJob for Persistence' },
          { id: 'T1059.004', name: 'Shell Exec in Container' }
        ]
      },
      {
        phase: 3, name: 'Credential Access',
        techniques: [
          { id: 'T1552.007', name: 'K8s Secrets & ServiceAccount Tokens' },
          { id: 'T1552.005', name: 'Cloud Metadata Token Theft' },
          { id: 'T1003', name: 'Credential Dumping from etcd' }
        ]
      },
      {
        phase: 4, name: 'Lateral Movement & Impact',
        techniques: [
          { id: 'T1611', name: 'Container Escape to Host' },
          { id: 'T1496', name: 'Resource Hijacking (XMRig)' },
          { id: 'T1021', name: 'SSH to Other Nodes' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', platform: 'K8s Dashboard', description: 'Targeting exposed Kubernetes dashboard with default creds' },
      { id: 'T1133', name: 'External Remote Services', tactic: 'Initial Access', platform: 'Kubelet', description: 'Accessing exposed kubelet API on port 10250' },
      { id: 'T1610', name: 'Deploy Container', tactic: 'Execution', platform: 'Kubernetes', description: 'Deploying XMRig miner pods via K8s API' },
      { id: 'T1053.007', name: 'Container Orchestration Job', tactic: 'Persistence', platform: 'Kubernetes', description: 'Creating CronJobs for mining persistence' },
      { id: 'T1552.007', name: 'Container API', tactic: 'Credential Access', platform: 'Kubernetes', description: 'Reading K8s secrets and service account tokens' },
      { id: 'T1611', name: 'Escape to Host', tactic: 'Privilege Escalation', platform: 'Container', description: 'Breaking out of container to access host node' },
      { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact', platform: 'Kubernetes', description: 'Deploying crypto miners consuming cluster resources' }
    ],
    references: [
      { icon: '\ud83d\udd2c', title: 'TeamTNT: Kubernetes Attack Campaign Analysis', source: 'Aqua Security \u00b7 2022', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83d\udd2c', title: 'Chimaera: Large-Scale Credential Theft from K8s', source: 'AT&T Alien Labs \u00b7 2021', type: 'REPORT', color: 'var(--orange)' },
      { icon: '\ud83d\uddc2\ufe0f', title: 'MITRE ATT&CK for Containers', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'var(--purple)' }
    ]
  },
  {
    id: 'hildegard-k8s',
    name: 'Hildegard \u2014 Advanced K8s Attack',
    origin: 'unknown',
    originLabel: 'UNKNOWN',
    tags: ['Kubelet Exploit', 'Container Escape', 'tmate Reverse Shell', 'IRC Botnet', 'Multi-stage'],
    techniqueCount: 15,
    severity: 'CRITICAL',
    aliases: 'Hildegard \u00b7 TeamTNT Variant',
    attribution: 'TeamTNT Subgroup \u2014 Advanced Capabilities',
    activeSince: '2021 \u2014 Present',
    targets: 'Kubernetes Clusters, Cloud Infrastructure, ML Workloads',
    incidents: ['Hildegard Campaign Discovery (2021)', 'Multi-Stage K8s Attack with IRC C2 (2021)', 'Cloud Provider K8s Service Targeting (2022)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1133', name: 'Kubelet RCE (10250)' },
          { id: 'T1190', name: 'Exploit Vulnerable K8s Workload' }
        ]
      },
      {
        phase: 2, name: 'Execution & Evasion',
        techniques: [
          { id: 'T1059.004', name: 'Bash Shell via Kubelet' },
          { id: 'T1610', name: 'Deploy Malicious Container' },
          { id: 'T1027', name: 'Obfuscated Payloads (Base64)' }
        ]
      },
      {
        phase: 3, name: 'Persistence & C2',
        techniques: [
          { id: 'T1053.007', name: 'K8s CronJob Persistence' },
          { id: 'T1219', name: 'tmate Reverse Shell' },
          { id: 'T1071.001', name: 'IRC C2 Channel' }
        ]
      },
      {
        phase: 4, name: 'Lateral Movement',
        techniques: [
          { id: 'T1611', name: 'Container Escape to Node' },
          { id: 'T1552.007', name: 'K8s API Token Theft' },
          { id: 'T1021', name: 'SSH to Cluster Nodes' }
        ]
      },
      {
        phase: 5, name: 'Impact',
        techniques: [
          { id: 'T1496', name: 'Monero Mining (XMRig)' },
          { id: 'T1530', name: 'Cloud Storage Data Theft' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1133', name: 'External Remote Services', tactic: 'Initial Access', platform: 'Kubelet', description: 'Remote code execution via exposed kubelet API' },
      { id: 'T1610', name: 'Deploy Container', tactic: 'Execution', platform: 'Kubernetes', description: 'Deploying attacker containers with elevated privileges' },
      { id: 'T1027', name: 'Obfuscated Files', tactic: 'Defense Evasion', platform: 'Container', description: 'Base64-encoded payloads to evade detection' },
      { id: 'T1219', name: 'Remote Access Software', tactic: 'Command and Control', platform: 'Container', description: 'Using tmate for persistent reverse shell access' },
      { id: 'T1611', name: 'Escape to Host', tactic: 'Privilege Escalation', platform: 'Container', description: 'Mounting host filesystem for container escape' },
      { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact', platform: 'Kubernetes', description: 'Deploying Monero miners across all cluster nodes' }
    ],
    references: [
      { icon: '\ud83d\udd2c', title: 'Hildegard: New TeamTNT Cryptojacking Campaign Targeting Kubernetes', source: 'Unit 42 / Palo Alto Networks \u00b7 2021', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83d\uddc2\ufe0f', title: 'MITRE ATT&CK Containers Matrix', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'var(--purple)' }
    ]
  },
  {
    id: 'cr8escape-k8s',
    name: 'cr8escape \u2014 Container Runtime Exploit',
    origin: 'unknown',
    originLabel: 'UNKNOWN',
    tags: ['CRI-O Exploit', 'Container Breakout', 'Node Compromise', 'CVE-2022-0811', 'Kernel Escape'],
    techniqueCount: 9,
    severity: 'CRITICAL',
    aliases: 'cr8escape',
    attribution: 'Exploit-Based \u2014 CVE-2022-0811 Attack Chain',
    activeSince: '2022 \u2014 Present',
    targets: 'CRI-O Based Kubernetes Clusters, OpenShift',
    incidents: ['CVE-2022-0811 Discovery and PoC (2022)', 'CRI-O Container Escape in the Wild (2022)', 'OpenShift Cluster Takeover (2023)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1190', name: 'Exploit Vulnerable Pod Workload' },
          { id: 'T1610', name: 'Deploy Malicious Container' }
        ]
      },
      {
        phase: 2, name: 'Container Escape',
        techniques: [
          { id: 'T1611', name: 'CRI-O CVE-2022-0811 Escape' },
          { id: 'T1068', name: 'Kernel Parameter Manipulation' }
        ]
      },
      {
        phase: 3, name: 'Node Compromise',
        techniques: [
          { id: 'T1059.004', name: 'Host Shell Access' },
          { id: 'T1552.001', name: 'Node Credential Files' },
          { id: 'T1552.007', name: 'Kubelet Credentials' }
        ]
      },
      {
        phase: 4, name: 'Cluster Takeover',
        techniques: [
          { id: 'T1078', name: 'Node ServiceAccount Abuse' },
          { id: 'T1098', name: 'RBAC ClusterRoleBinding' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1611', name: 'Escape to Host', tactic: 'Privilege Escalation', platform: 'CRI-O', description: 'Exploiting CVE-2022-0811 to escape container to node' },
      { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation', platform: 'Linux Kernel', description: 'Manipulating kernel parameters via CRI-O vulnerability' },
      { id: 'T1552.007', name: 'Container API', tactic: 'Credential Access', platform: 'Kubelet', description: 'Stealing kubelet credentials from compromised node' },
      { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence', platform: 'Kubernetes', description: 'Creating ClusterRoleBinding for cluster-admin access' }
    ],
    references: [
      { icon: '\ud83d\udd2c', title: 'cr8escape: CVE-2022-0811 CRI-O Container Escape', source: 'CrowdStrike \u00b7 2022', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83c\udfdb\ufe0f', title: 'CVE-2022-0811: CRI-O Arbitrary Code Execution', source: 'NVD / NIST \u00b7 2022', type: 'CVE', color: 'var(--red)' }
    ]
  },
  {
    id: 'siloscape-k8s',
    name: 'Siloscape \u2014 Windows Container Escape',
    origin: 'unknown',
    originLabel: 'UNKNOWN',
    tags: ['Windows Container', 'Server Silo Escape', 'Backdoor K8s', 'Tor C2', 'IRC Bot'],
    techniqueCount: 10,
    severity: 'HIGH',
    aliases: 'Siloscape',
    attribution: 'Unknown \u2014 First Known Windows Container Escape Malware',
    activeSince: '2021 \u2014 Present',
    targets: 'Windows Kubernetes Clusters, AKS, Windows Server Containers',
    incidents: ['First Windows Container Escape Malware (2021)', 'AKS Cluster Backdooring (2021)', 'Kubernetes Cluster Compromise via Windows Nodes (2022)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1190', name: 'Exploit Vulnerable Windows Web App' },
          { id: 'T1059.001', name: 'PowerShell Execution in Container' }
        ]
      },
      {
        phase: 2, name: 'Container Escape',
        techniques: [
          { id: 'T1611', name: 'Windows Server Silo Escape' },
          { id: 'T1068', name: 'Exploit CExecSvc Impersonation' }
        ]
      },
      {
        phase: 3, name: 'Persistence & C2',
        techniques: [
          { id: 'T1610', name: 'Deploy Backdoor Containers' },
          { id: 'T1090.003', name: 'Tor Proxy for C2' },
          { id: 'T1071.001', name: 'IRC C2 Communication' }
        ]
      },
      {
        phase: 4, name: 'Cluster Compromise',
        techniques: [
          { id: 'T1552.007', name: 'K8s API Credentials Theft' },
          { id: 'T1136.003', name: 'Create K8s ServiceAccount' },
          { id: 'T1098', name: 'RBAC Role Escalation' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1611', name: 'Escape to Host', tactic: 'Privilege Escalation', platform: 'Windows Container', description: 'Escaping Windows Server Silo to access host node' },
      { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation', platform: 'Windows', description: 'Exploiting CExecSvc to impersonate SYSTEM' },
      { id: 'T1610', name: 'Deploy Container', tactic: 'Execution', platform: 'Kubernetes', description: 'Deploying backdoor containers across the cluster' },
      { id: 'T1090.003', name: 'Multi-hop Proxy', tactic: 'Command and Control', platform: 'Tor', description: 'Using Tor network for anonymous C2 communication' },
      { id: 'T1552.007', name: 'Container API', tactic: 'Credential Access', platform: 'Kubernetes', description: 'Stealing K8s credentials from compromised node' }
    ],
    references: [
      { icon: '\ud83d\udd2c', title: 'Siloscape: First Known Malware Targeting Windows Containers', source: 'Unit 42 / Palo Alto Networks \u00b7 2021', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83d\uddc2\ufe0f', title: 'MITRE ATT&CK Containers Matrix: Windows', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'var(--purple)' }
    ]
  },
  {
    id: 'scarleteel-k8s',
    name: 'Scarleteel \u2014 Cloud-K8s Cross-Layer Attack',
    origin: 'unknown',
    originLabel: 'UNKNOWN',
    tags: ['Cross-Layer Attack', 'IAM Credential Theft', 'Terraform Abuse', 'Jupyter Exploit', 'Multi-Cloud Pivot'],
    techniqueCount: 14,
    severity: 'CRITICAL',
    aliases: 'SCARLETEEL \u00b7 SCARLETEEL 2.0',
    attribution: 'Unknown \u2014 Sophisticated Cloud-Native Attack Group',
    activeSince: '2023 \u2014 Present',
    targets: 'Kubernetes Workloads, Cloud Accounts, ML Infrastructure',
    incidents: ['Scarleteel K8s-to-Cloud Attack (2023)', 'Scarleteel 2.0 Enhanced Campaign (2023)', 'Jupyter-to-Cloud Credential Theft (2024)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1190', name: 'Exploit Vulnerable K8s Workload' },
          { id: 'T1610', name: 'Deploy via Misconfigured Admission' }
        ]
      },
      {
        phase: 2, name: 'Credential Access',
        techniques: [
          { id: 'T1552.007', name: 'K8s ServiceAccount Token' },
          { id: 'T1552.005', name: 'Cloud Metadata IAM Creds' },
          { id: 'T1552.001', name: 'Terraform State Files' }
        ]
      },
      {
        phase: 3, name: 'Cloud Lateral Movement',
        techniques: [
          { id: 'T1078.004', name: 'Use Stolen Cloud IAM Creds' },
          { id: 'T1580', name: 'Cloud Infrastructure Discovery' },
          { id: 'T1530', name: 'Access Cloud Storage' }
        ]
      },
      {
        phase: 4, name: 'Persistence & Impact',
        techniques: [
          { id: 'T1098', name: 'Create IAM Persistence' },
          { id: 'T1496', name: 'Cryptomining on Cloud Compute' },
          { id: 'T1537', name: 'Data Transfer to External Acct' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', platform: 'Kubernetes', description: 'Exploiting vulnerable Jupyter or web workloads in K8s' },
      { id: 'T1552.007', name: 'Container API', tactic: 'Credential Access', platform: 'Kubernetes', description: 'Stealing mounted ServiceAccount tokens' },
      { id: 'T1552.005', name: 'Cloud Instance Metadata', tactic: 'Credential Access', platform: 'AWS/GCP', description: 'Accessing IMDS from pods to get cloud IAM credentials' },
      { id: 'T1552.001', name: 'Credentials In Files', tactic: 'Credential Access', platform: 'Terraform', description: 'Extracting secrets from Terraform state files in S3' },
      { id: 'T1078.004', name: 'Valid Cloud Accounts', tactic: 'Lateral Movement', platform: 'AWS/GCP', description: 'Using stolen IAM credentials to access cloud services' },
      { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact', platform: 'Cloud', description: 'Deploying miners on stolen cloud compute resources' }
    ],
    references: [
      { icon: '\ud83d\udd2c', title: 'SCARLETEEL: Operation Leveraging Kubernetes to Steal Cloud Credentials', source: 'Sysdig TRT \u00b7 2023', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83d\udd2c', title: 'SCARLETEEL 2.0: Enhanced Cloud-Native Attack Campaign', source: 'Sysdig TRT \u00b7 2023', type: 'REPORT', color: 'var(--orange)' },
      { icon: '\ud83d\uddc2\ufe0f', title: 'MITRE ATT&CK for Containers', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'var(--purple)' }
    ]
  }
];
