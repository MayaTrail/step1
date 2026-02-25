/* ══════════════════════════════════════════
   MayaTrail — GCP APT Emulations Data
   ══════════════════════════════════════════ */

window.MayaTrail = window.MayaTrail || {};
window.MayaTrail.platforms = window.MayaTrail.platforms || {};
window.MayaTrail.platforms.gcp = window.MayaTrail.platforms.gcp || {};

window.MayaTrail.platforms.gcp.emulations = [
  {
    id: 'apt41-gcp',
    name: 'APT41 \u2014 Winnti / Double Dragon',
    origin: 'china',
    originLabel: 'CHINA',
    tags: ['Cloud Functions', 'GCS Exfiltration', 'IAM Escalation', 'GCE Metadata', 'Pub/Sub Abuse'],
    techniqueCount: 16,
    severity: 'CRITICAL',
    aliases: 'Winnti \u00b7 Barium \u00b7 Wicked Panda',
    attribution: 'MSS \u2014 Chinese Ministry of State Security',
    activeSince: '2012 \u2014 Present',
    targets: 'Technology, Gaming, Healthcare, Government',
    incidents: ['US State Government GCP Breach (2021)', 'ShadowPad Campaign (2017)', 'Multi-Cloud Espionage (2023)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1190', name: 'Exploit Public-Facing App Engine' },
          { id: 'T1078.004', name: 'Valid Cloud Accounts (GCP)' },
          { id: 'T1195.002', name: 'Supply Chain via Cloud Build' }
        ]
      },
      {
        phase: 2, name: 'Persistence & Execution',
        techniques: [
          { id: 'T1098', name: 'Service Account Key Creation' },
          { id: 'T1059.004', name: 'Cloud Functions Shell Exec' },
          { id: 'T1136.003', name: 'Create GCP IAM Account' }
        ]
      },
      {
        phase: 3, name: 'Privilege Escalation',
        techniques: [
          { id: 'T1548.005', name: 'Org Policy Abuse' },
          { id: 'T1078', name: 'Service Account Impersonation' },
          { id: 'T1580', name: 'Cloud Infrastructure Discovery' }
        ]
      },
      {
        phase: 4, name: 'Defense Evasion & Exfiltration',
        techniques: [
          { id: 'T1562.008', name: 'Disable Cloud Audit Logging' },
          { id: 'T1530', name: 'Data from GCS Buckets' },
          { id: 'T1537', name: 'Transfer to External Project' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', platform: 'App Engine/GCE', description: 'Exploiting vulnerable web apps on App Engine or GCE' },
      { id: 'T1078.004', name: 'Valid Cloud Accounts', tactic: 'Initial Access', platform: 'GCP IAM', description: 'Stolen service account keys or OAuth tokens' },
      { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence', platform: 'GCP IAM', description: 'Creating new service account keys for persistence' },
      { id: 'T1136.003', name: 'Create Cloud Account', tactic: 'Persistence', platform: 'GCP IAM', description: 'Creating rogue service accounts in project' },
      { id: 'T1548.005', name: 'Abuse Elevation Control', tactic: 'Privilege Escalation', platform: 'GCP IAM', description: 'Binding Owner role to compromised account' },
      { id: 'T1562.008', name: 'Disable Cloud Logging', tactic: 'Defense Evasion', platform: 'Cloud Logging', description: 'Modifying log sinks or disabling audit logs' },
      { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection', platform: 'GCS', description: 'Bulk download from Cloud Storage buckets' },
      { id: 'T1537', name: 'Transfer to Cloud Account', tactic: 'Exfiltration', platform: 'GCS', description: 'Cross-project bucket replication to attacker project' }
    ],
    references: [
      { icon: '\ud83c\udfdb\ufe0f', title: 'CISA: APT41 Activity Targeting US State Governments via GCP', source: 'CISA \u00b7 2022', type: 'ADVISORY', color: 'var(--red)' },
      { icon: '\ud83d\udd2c', title: 'APT41 Multi-Cloud Campaigns: GCP TTPs Analysis', source: 'Mandiant \u00b7 2023', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83d\uddc2\ufe0f', title: 'MITRE ATT&CK \u2014 APT41 Group Profile (G0096)', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'var(--purple)' }
    ]
  },
  {
    id: 'scattered-spider-gcp',
    name: 'Scattered Spider \u2014 UNC3944 / Octo Tempest',
    origin: 'financial',
    originLabel: 'FINANCIAL',
    tags: ['Social Engineering', 'Workspace Abuse', 'MFA Bypass', 'IAM Pivoting', 'Identity Federation'],
    techniqueCount: 12,
    severity: 'HIGH',
    aliases: 'UNC3944 \u00b7 Octo Tempest \u00b7 0ktapus',
    attribution: 'Financially Motivated \u2014 English-speaking Threat Group',
    activeSince: '2022 \u2014 Present',
    targets: 'Telecom, BPO, Technology, Crypto',
    incidents: ['MGM Resorts Breach (2023)', 'Caesars Entertainment (2023)', 'Okta Customer Support (2023)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1566.004', name: 'Spearphishing Voice (Vishing)' },
          { id: 'T1078.004', name: 'Compromised Google Workspace' },
          { id: 'T1621', name: 'MFA Fatigue / Push Bombing' }
        ]
      },
      {
        phase: 2, name: 'Credential Access',
        techniques: [
          { id: 'T1528', name: 'Steal OAuth Tokens' },
          { id: 'T1552.001', name: 'Credentials in GCS Files' }
        ]
      },
      {
        phase: 3, name: 'Discovery & Lateral Movement',
        techniques: [
          { id: 'T1087.004', name: 'GCP Project Discovery' },
          { id: 'T1580', name: 'Cloud Infrastructure Enum' },
          { id: 'T1550.001', name: 'Application Access Token Reuse' }
        ]
      },
      {
        phase: 4, name: 'Impact',
        techniques: [
          { id: 'T1530', name: 'Data from GCS' },
          { id: 'T1486', name: 'Data Encrypted for Impact' },
          { id: 'T1657', name: 'Financial Theft' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1566.004', name: 'Spearphishing Voice', tactic: 'Initial Access', platform: 'Any', description: 'Social engineering IT help desk for password resets' },
      { id: 'T1621', name: 'Multi-Factor Auth Request Generation', tactic: 'Credential Access', platform: 'Google Workspace', description: 'MFA push-bombing to gain Workspace access' },
      { id: 'T1528', name: 'Steal Application Access Token', tactic: 'Credential Access', platform: 'GCP OAuth', description: 'Harvesting OAuth tokens from compromised sessions' },
      { id: 'T1087.004', name: 'Cloud Account Discovery', tactic: 'Discovery', platform: 'GCP IAM', description: 'Enumerating projects, service accounts, and roles' },
      { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection', platform: 'GCS', description: 'Accessing sensitive data in GCS buckets' },
      { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', platform: 'GCP', description: 'Ransomware deployment via compromised admin access' }
    ],
    references: [
      { icon: '\ud83d\udd2c', title: 'Scattered Spider: Cloud-Native Threat Actor Analysis', source: 'CrowdStrike \u00b7 2023', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83c\udfdb\ufe0f', title: 'CISA: Scattered Spider Advisory (AA23-320A)', source: 'CISA / FBI \u00b7 2023', type: 'ADVISORY', color: 'var(--red)' }
    ]
  },
  {
    id: 'apt29-gcp',
    name: 'APT29 \u2014 Cozy Bear / GCP Operations',
    origin: 'russia',
    originLabel: 'RUSSIA',
    tags: ['Token Theft', 'Metadata Abuse', 'Cross-Cloud Pivot', 'Workspace Phishing', 'Data Exfil'],
    techniqueCount: 13,
    severity: 'HIGH',
    aliases: 'Midnight Blizzard \u00b7 Nobelium \u00b7 IRON HEMLOCK',
    attribution: 'SVR \u2014 Russian Foreign Intelligence',
    activeSince: '2008 \u2014 Present',
    targets: 'Government, Defense, Technology, Think Tanks',
    incidents: ['SolarWinds Multi-Cloud Pivot (2020)', 'Google Workspace Targeting (2022)', 'Diplomatic Entity Campaign (2023)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1566.001', name: 'Spearphishing Google Workspace' },
          { id: 'T1078.004', name: 'Valid Cloud Accounts' }
        ]
      },
      {
        phase: 2, name: 'Credential Access',
        techniques: [
          { id: 'T1552.005', name: 'GCE Instance Metadata' },
          { id: 'T1528', name: 'Steal OAuth/Service Account Token' },
          { id: 'T1110.003', name: 'Password Spraying Workspace' }
        ]
      },
      {
        phase: 3, name: 'Discovery & Escalation',
        techniques: [
          { id: 'T1087.004', name: 'Cloud Account Discovery' },
          { id: 'T1580', name: 'GCP Infrastructure Recon' },
          { id: 'T1548.005', name: 'IAM Role Binding Escalation' }
        ]
      },
      {
        phase: 4, name: 'Defense Evasion',
        techniques: [
          { id: 'T1562.008', name: 'Disable Audit Logging' },
          { id: 'T1078', name: 'Valid Accounts Persistence' }
        ]
      },
      {
        phase: 5, name: 'Exfiltration',
        techniques: [
          { id: 'T1530', name: 'Data from GCS' },
          { id: 'T1567', name: 'Exfiltration via Google APIs' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1566.001', name: 'Spearphishing Link', tactic: 'Initial Access', platform: 'Workspace', description: 'Phishing targeting Google Workspace admins' },
      { id: 'T1552.005', name: 'Cloud Instance Metadata', tactic: 'Credential Access', platform: 'GCE', description: 'SSRF to GCE metadata endpoint for token theft' },
      { id: 'T1528', name: 'Steal Application Access Token', tactic: 'Credential Access', platform: 'GCP OAuth', description: 'Stealing service account tokens from metadata' },
      { id: 'T1548.005', name: 'Abuse Elevation Control', tactic: 'Privilege Escalation', platform: 'GCP IAM', description: 'Binding roles.owner to compromised service account' },
      { id: 'T1562.008', name: 'Disable Cloud Logging', tactic: 'Defense Evasion', platform: 'Cloud Logging', description: 'Removing audit log sinks' },
      { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection', platform: 'GCS', description: 'Exfiltrating sensitive GCS bucket content' }
    ],
    references: [
      { icon: '\ud83c\udfdb\ufe0f', title: 'NCSC: APT29 Cloud Targeting Advisory', source: 'UK NCSC / CISA \u00b7 2024', type: 'ADVISORY', color: 'var(--red)' },
      { icon: '\ud83d\udd2c', title: 'APT29 Cross-Cloud Lateral Movement TTPs', source: 'Google TAG \u00b7 2023', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83d\uddc2\ufe0f', title: 'MITRE ATT&CK \u2014 APT29 Group Profile (G0016)', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'var(--purple)' }
    ]
  },
  {
    id: 'teamtnt-gcp',
    name: 'TeamTNT \u2014 Cloud Cryptojacking',
    origin: 'unknown',
    originLabel: 'UNKNOWN',
    tags: ['Cryptomining', 'GKE Targeting', 'Metadata Theft', 'Container Escape', 'Credential Harvesting'],
    techniqueCount: 10,
    severity: 'HIGH',
    aliases: 'TeamTNT \u00b7 Chimaera',
    attribution: 'Financially Motivated \u2014 Cryptojacking Group',
    activeSince: '2019 \u2014 Present',
    targets: 'Cloud Infrastructure, Kubernetes, Docker Hosts',
    incidents: ['Mass GKE Cryptojacking Campaign (2021)', 'Chimaera Campaign (2021)', 'Credential Harvesting at Scale (2022)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1190', name: 'Exploit Exposed GKE Dashboard' },
          { id: 'T1133', name: 'External Remote Services (Kubelet)' }
        ]
      },
      {
        phase: 2, name: 'Execution & Persistence',
        techniques: [
          { id: 'T1610', name: 'Deploy Crypto-Mining Container' },
          { id: 'T1053.007', name: 'Container Orchestration Job' },
          { id: 'T1059.004', name: 'Unix Shell in Pod' }
        ]
      },
      {
        phase: 3, name: 'Credential Access',
        techniques: [
          { id: 'T1552.005', name: 'GCE Metadata Credential Theft' },
          { id: 'T1552.007', name: 'Container API Credentials' }
        ]
      },
      {
        phase: 4, name: 'Impact',
        techniques: [
          { id: 'T1496', name: 'Resource Hijacking (Cryptomining)' },
          { id: 'T1530', name: 'Steal GCS Data' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', platform: 'GKE', description: 'Targeting exposed Kubernetes dashboards and kubelets' },
      { id: 'T1610', name: 'Deploy Container', tactic: 'Execution', platform: 'GKE', description: 'Deploying XMRig crypto miner containers' },
      { id: 'T1552.005', name: 'Cloud Instance Metadata', tactic: 'Credential Access', platform: 'GCE', description: 'Stealing GCP credentials from metadata endpoint' },
      { id: 'T1552.007', name: 'Container API', tactic: 'Credential Access', platform: 'GKE', description: 'Accessing K8s secrets and service account tokens' },
      { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact', platform: 'GCE/GKE', description: 'Deploying crypto miners consuming GCE resources' }
    ],
    references: [
      { icon: '\ud83d\udd2c', title: 'TeamTNT Cloud Targeting: GCP and Kubernetes Attack Analysis', source: 'Aqua Security \u00b7 2022', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83d\udd2c', title: 'Chimaera Campaign: Credential Theft at Cloud Scale', source: 'AT&T Alien Labs \u00b7 2021', type: 'REPORT', color: 'var(--orange)' }
    ]
  },
  {
    id: 'lapsus-gcp',
    name: 'LAPSUS$ \u2014 DEV-0537',
    origin: 'financial',
    originLabel: 'FINANCIAL',
    tags: ['Workspace Compromise', 'Okta Abuse', 'Source Code Theft', 'SIM Swapping', 'Insider Recruitment'],
    techniqueCount: 11,
    severity: 'HIGH',
    aliases: 'DEV-0537 \u00b7 Strawberry Tempest',
    attribution: 'Financially Motivated \u2014 Teenage Threat Group',
    activeSince: '2021 \u2014 2023',
    targets: 'Technology, Gaming, Telecom, Government',
    incidents: ['Okta Breach via GCP (2022)', 'Samsung Source Code Leak (2022)', 'Nvidia 1TB Theft (2022)', 'Microsoft DevOps Breach (2022)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1078.004', name: 'Purchased Google Workspace Creds' },
          { id: 'T1566.004', name: 'SIM Swapping / Vishing' },
          { id: 'T1199', name: 'Trusted Relationship (Okta)' }
        ]
      },
      {
        phase: 2, name: 'Privilege Escalation',
        techniques: [
          { id: 'T1548.005', name: 'Admin Role Self-Assignment' },
          { id: 'T1098', name: 'Account Manipulation' }
        ]
      },
      {
        phase: 3, name: 'Collection',
        techniques: [
          { id: 'T1213.003', name: 'Cloud Source Repos Access' },
          { id: 'T1530', name: 'GCS Source Code Buckets' },
          { id: 'T1119', name: 'Automated Collection Scripts' }
        ]
      },
      {
        phase: 4, name: 'Exfiltration & Impact',
        techniques: [
          { id: 'T1567', name: 'Exfiltration Over Web Service' },
          { id: 'T1491.002', name: 'Defacement (Telegram Leaks)' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1078.004', name: 'Valid Cloud Accounts', tactic: 'Initial Access', platform: 'GCP/Workspace', description: 'Purchasing credentials on criminal marketplaces' },
      { id: 'T1199', name: 'Trusted Relationship', tactic: 'Initial Access', platform: 'Okta/GCP', description: 'Abusing Okta integration to access GCP' },
      { id: 'T1548.005', name: 'Abuse Elevation Control', tactic: 'Privilege Escalation', platform: 'GCP IAM', description: 'Self-granting Owner role in GCP projects' },
      { id: 'T1213.003', name: 'Code Repositories', tactic: 'Collection', platform: 'Cloud Source Repos', description: 'Cloning source code repositories' },
      { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration', platform: 'Any', description: 'Exfiltrating data via Telegram and public file shares' }
    ],
    references: [
      { icon: '\ud83d\udd2c', title: 'DEV-0537 Criminal Actor: LAPSUS$ TTP Analysis', source: 'Microsoft MSTIC \u00b7 2022', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83c\udfdb\ufe0f', title: 'CSRB Review: Lapsus$ and Related Threat Groups', source: 'DHS Cyber Safety Review Board \u00b7 2023', type: 'ADVISORY', color: 'var(--red)' }
    ]
  }
];
