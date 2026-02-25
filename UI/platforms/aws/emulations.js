/* ══════════════════════════════════════════
   MayaTrail — AWS APT Emulations Data
   ══════════════════════════════════════════ */

window.MayaTrail = window.MayaTrail || {};
window.MayaTrail.platforms = window.MayaTrail.platforms || {};
window.MayaTrail.platforms.aws = window.MayaTrail.platforms.aws || {};

window.MayaTrail.platforms.aws.emulations = [
  {
    id: 'apt29-aws',
    name: 'APT29 \u2014 Cozy Bear / Midnight Blizzard',
    origin: 'russia',
    originLabel: 'RUSSIA',
    tags: ['Initial Access', 'Credential Access', 'OAuth Abuse', 'S3 Exfiltration', 'IAM Escalation'],
    techniqueCount: 14,
    severity: 'HIGH',
    aliases: 'Midnight Blizzard \u00b7 Nobelium \u00b7 IRON HEMLOCK',
    attribution: 'SVR \u2014 Russian Foreign Intelligence',
    activeSince: '2008 \u2014 Present',
    targets: 'Government, Defense, Healthcare, Tech',
    incidents: ['SolarWinds (2020)', 'DNC Breach (2016)', 'USAID Campaign (2021)', 'Microsoft Corporate Breach (2024)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1566.001', name: 'Spearphishing Link' },
          { id: 'T1078.004', name: 'Valid Cloud Accounts' },
          { id: 'T1190', name: 'Exploit Public-Facing App' }
        ]
      },
      {
        phase: 2, name: 'Credential Access',
        techniques: [
          { id: 'T1528', name: 'Steal App Access Token' },
          { id: 'T1552.005', name: 'Cloud Instance Metadata' },
          { id: 'T1110.003', name: 'Password Spraying' }
        ]
      },
      {
        phase: 3, name: 'Discovery & Escalation',
        techniques: [
          { id: 'T1087.004', name: 'Cloud Account Discovery' },
          { id: 'T1580', name: 'Cloud Infrastructure Discovery' },
          { id: 'T1548.005', name: 'Abuse Elevation Control' }
        ]
      },
      {
        phase: 4, name: 'Defense Evasion',
        techniques: [
          { id: 'T1562.008', name: 'Disable Cloud Logging' },
          { id: 'T1078', name: 'Valid Accounts' }
        ]
      },
      {
        phase: 5, name: 'Exfiltration',
        techniques: [
          { id: 'T1530', name: 'Data from Cloud Storage' },
          { id: 'T1041', name: 'Exfiltration Over C2' },
          { id: 'T1537', name: 'Transfer to Cloud Account' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1566.001', name: 'Spearphishing Link', tactic: 'Initial Access', platform: 'Any', description: 'OAuth phishing to harvest tokens' },
      { id: 'T1078.004', name: 'Valid Cloud Accounts', tactic: 'Initial Access', platform: 'AWS IAM', description: 'Stolen/purchased cloud credentials' },
      { id: 'T1528', name: 'Steal App Access Token', tactic: 'Credential Access', platform: 'AWS SSO', description: 'OAuth 2.0 Device Authorization flow abuse' },
      { id: 'T1552.005', name: 'Cloud Instance Metadata', tactic: 'Credential Access', platform: 'EC2 IMDS', description: 'SSRF to IMDSv1 endpoint' },
      { id: 'T1087.004', name: 'Cloud Account Discovery', tactic: 'Discovery', platform: 'AWS IAM', description: 'Enumerate users, roles, and policies' },
      { id: 'T1580', name: 'Cloud Infrastructure Discovery', tactic: 'Discovery', platform: 'Multi', description: 'DescribeInstances, ListBuckets, etc.' },
      { id: 'T1548.005', name: 'Abuse Elevation Control', tactic: 'Privilege Escalation', platform: 'AWS IAM', description: 'iam:PassRole + iam:AttachRolePolicy' },
      { id: 'T1562.008', name: 'Disable Cloud Logging', tactic: 'Defense Evasion', platform: 'CloudTrail', description: 'StopLogging on CloudTrail trails' },
      { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection', platform: 'S3', description: 'Bulk S3 GetObject across buckets' },
      { id: 'T1537', name: 'Transfer to Cloud Account', tactic: 'Exfiltration', platform: 'S3', description: 'Cross-account S3 replication to attacker' }
    ],
    references: [
      { icon: '\u{1f3db}\ufe0f', title: 'CISA Alert AA21-148A \u2014 Sophisticated Spearphishing Campaign', source: 'CISA \u00b7 US Cybersecurity & Infrastructure Security Agency \u00b7 2021', type: 'ADVISORY', color: 'var(--red)' },
      { icon: '\u{1f52c}', title: 'Midnight Blizzard: Guidance for responders on nation-state attack', source: 'Microsoft MSTIC \u00b7 2024', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\u{1f5c2}\ufe0f', title: 'MITRE ATT&CK \u2014 APT29 Group Profile (G0016)', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'var(--purple)' },
      { icon: '\u{1f4ca}', title: 'APT29 Cloud Targeting: SolarWinds Supply Chain Attack Analysis', source: 'Mandiant / Google Cloud Intelligence \u00b7 2021', type: 'CASE STUDY', color: 'var(--orange)' },
      { icon: '\u{1f4dd}', title: 'OAuth 2.0 Device Authorization Grant Attack Scenarios in AWS', source: 'Volexity Research \u00b7 2023', type: 'RESEARCH', color: 'var(--green)' }
    ]
  },
  {
    id: 'apt41-aws',
    name: 'APT41 \u2014 Winnti / Double Dragon',
    origin: 'china',
    originLabel: 'CHINA',
    tags: ['Persistence', 'Lateral Movement', 'Supply Chain', 'EC2 Abuse', 'Lambda Hijacking'],
    techniqueCount: 18,
    severity: 'CRITICAL',
    aliases: 'Winnti \u00b7 Barium \u00b7 Wicked Panda',
    attribution: 'MSS \u2014 Chinese Ministry of State Security',
    activeSince: '2012 \u2014 Present',
    targets: 'Technology, Gaming, Healthcare, Telecom',
    incidents: ['ShadowPad Campaign (2017)', 'CCleaner Supply Chain (2017)', 'US State Government Breach (2021)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1190', name: 'Exploit Public-Facing Application' },
          { id: 'T1195.002', name: 'Supply Chain Compromise' },
          { id: 'T1078.004', name: 'Valid Cloud Accounts' }
        ]
      },
      {
        phase: 2, name: 'Execution & Persistence',
        techniques: [
          { id: 'T1059.004', name: 'Unix Shell Commands' },
          { id: 'T1136.003', name: 'Create Cloud Account' },
          { id: 'T1098', name: 'Account Manipulation' }
        ]
      },
      {
        phase: 3, name: 'Privilege Escalation',
        techniques: [
          { id: 'T1548.005', name: 'Abuse Elevation Control' },
          { id: 'T1078', name: 'Valid Accounts Persistence' },
          { id: 'T1580', name: 'Cloud Infrastructure Discovery' }
        ]
      },
      {
        phase: 4, name: 'Lateral Movement',
        techniques: [
          { id: 'T1021.004', name: 'SSH Lateral Movement' },
          { id: 'T1537', name: 'Transfer to Cloud Account' }
        ]
      },
      {
        phase: 5, name: 'Impact & Exfiltration',
        techniques: [
          { id: 'T1530', name: 'Data from Cloud Storage' },
          { id: 'T1567', name: 'Exfiltration Over Web Service' },
          { id: 'T1496', name: 'Resource Hijacking' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', platform: 'EC2/ECS', description: 'Exploiting vulnerable web apps on EC2' },
      { id: 'T1195.002', name: 'Supply Chain Compromise', tactic: 'Initial Access', platform: 'CodePipeline', description: 'Injecting malicious code via CI/CD pipeline' },
      { id: 'T1136.003', name: 'Create Cloud Account', tactic: 'Persistence', platform: 'AWS IAM', description: 'Creating rogue IAM users for persistence' },
      { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence', platform: 'AWS IAM', description: 'Adding access keys to existing users' },
      { id: 'T1548.005', name: 'Abuse Elevation Control', tactic: 'Privilege Escalation', platform: 'AWS IAM', description: 'Attaching AdministratorAccess to compromised role' },
      { id: 'T1021.004', name: 'SSH Lateral Movement', tactic: 'Lateral Movement', platform: 'EC2', description: 'Using stolen SSH keys to move between instances' },
      { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection', platform: 'S3', description: 'Downloading sensitive data from S3 buckets' },
      { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact', platform: 'EC2/Lambda', description: 'Deploying crypto miners on compromised instances' }
    ],
    references: [
      { icon: '\u{1f3db}\ufe0f', title: 'FBI Flash: APT41 Targeting State & Local Governments', source: 'FBI Cyber Division \u00b7 2022', type: 'ADVISORY', color: 'var(--red)' },
      { icon: '\u{1f52c}', title: 'APT41: A Dual Espionage and Cyber Crime Operation', source: 'Mandiant \u00b7 2019', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\u{1f5c2}\ufe0f', title: 'MITRE ATT&CK \u2014 APT41 Group Profile (G0096)', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'var(--purple)' }
    ]
  },
  {
    id: 'lazarus-aws',
    name: 'Lazarus Group \u2014 HIDDEN COBRA',
    origin: 'nk',
    originLabel: 'DPRK',
    tags: ['Financial Crime', 'Ransomware', 'Defense Evasion', 'Lambda Abuse', 'KMS Ransomware'],
    techniqueCount: 11,
    severity: 'HIGH',
    aliases: 'HIDDEN COBRA \u00b7 Zinc \u00b7 Diamond Sleet',
    attribution: 'RGB \u2014 North Korean Reconnaissance General Bureau',
    activeSince: '2009 \u2014 Present',
    targets: 'Financial, Crypto, Aerospace, Defense',
    incidents: ['Sony Pictures Hack (2014)', 'Bangladesh Bank Heist (2016)', 'WannaCry Ransomware (2017)', 'Ronin Bridge ($625M Theft, 2022)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1566.001', name: 'Spearphishing Link' },
          { id: 'T1078.004', name: 'Valid Cloud Accounts' }
        ]
      },
      {
        phase: 2, name: 'Execution & Persistence',
        techniques: [
          { id: 'T1059.004', name: 'Unix Shell via Lambda' },
          { id: 'T1098', name: 'Account Manipulation' },
          { id: 'T1136.003', name: 'Create Cloud Account' }
        ]
      },
      {
        phase: 3, name: 'Defense Evasion',
        techniques: [
          { id: 'T1562.008', name: 'Disable Cloud Logging' },
          { id: 'T1070.004', name: 'File Deletion' },
          { id: 'T1027', name: 'Obfuscated Files' }
        ]
      },
      {
        phase: 4, name: 'Impact',
        techniques: [
          { id: 'T1486', name: 'Data Encrypted for Impact (KMS)' },
          { id: 'T1530', name: 'Data from Cloud Storage' },
          { id: 'T1657', name: 'Financial Theft' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1566.001', name: 'Spearphishing Link', tactic: 'Initial Access', platform: 'Any', description: 'Fake job offer emails targeting crypto engineers' },
      { id: 'T1078.004', name: 'Valid Cloud Accounts', tactic: 'Initial Access', platform: 'AWS IAM', description: 'Stolen credentials from social engineering' },
      { id: 'T1059.004', name: 'Unix Shell', tactic: 'Execution', platform: 'Lambda', description: 'Deploying malicious Lambda functions' },
      { id: 'T1562.008', name: 'Disable Cloud Logging', tactic: 'Defense Evasion', platform: 'CloudTrail', description: 'Deleting CloudTrail logs to cover tracks' },
      { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', platform: 'S3/KMS', description: 'Re-encrypting S3 objects with attacker-controlled KMS key' },
      { id: 'T1657', name: 'Financial Theft', tactic: 'Impact', platform: 'Multi', description: 'Targeting cryptocurrency wallets and DeFi protocols' }
    ],
    references: [
      { icon: '\u{1f3db}\ufe0f', title: 'CISA Alert AA22-108A \u2014 TraderTraitor: North Korean State-Sponsored APT', source: 'CISA \u00b7 2022', type: 'ADVISORY', color: 'var(--red)' },
      { icon: '\u{1f52c}', title: 'Lazarus Group Cloud Operations: AWS and Crypto Targeting', source: 'CrowdStrike Intelligence \u00b7 2023', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\u{1f5c2}\ufe0f', title: 'MITRE ATT&CK \u2014 Lazarus Group Profile (G0032)', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'var(--purple)' }
    ]
  },
  {
    id: 'apt33-aws',
    name: 'APT33 \u2014 Elfin / Refined Kitten',
    origin: 'iran',
    originLabel: 'IRAN',
    tags: ['Spearphishing', 'Wiper', 'RDS Targeting', 'Cloud Recon', 'Destructive Ops'],
    techniqueCount: 9,
    severity: 'MEDIUM',
    aliases: 'Elfin \u00b7 Refined Kitten \u00b7 Peach Sandstorm',
    attribution: 'IRGC \u2014 Islamic Revolutionary Guard Corps',
    activeSince: '2013 \u2014 Present',
    targets: 'Energy, Aerospace, Defense, Government',
    incidents: ['Shamoon Wiper Attacks (2012, 2016)', 'Aerospace Sector Campaign (2017)', 'Password Spray Campaign (2023)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1566.002', name: 'Spearphishing Attachment' },
          { id: 'T1110.003', name: 'Password Spraying' }
        ]
      },
      {
        phase: 2, name: 'Discovery',
        techniques: [
          { id: 'T1580', name: 'Cloud Infrastructure Discovery' },
          { id: 'T1087.004', name: 'Cloud Account Discovery' },
          { id: 'T1526', name: 'Cloud Service Discovery' }
        ]
      },
      {
        phase: 3, name: 'Collection & Exfiltration',
        techniques: [
          { id: 'T1530', name: 'Data from Cloud Storage' },
          { id: 'T1213.003', name: 'Code Repositories' }
        ]
      },
      {
        phase: 4, name: 'Impact',
        techniques: [
          { id: 'T1485', name: 'Data Destruction' },
          { id: 'T1561.002', name: 'Disk Structure Wipe' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1566.002', name: 'Spearphishing Attachment', tactic: 'Initial Access', platform: 'Any', description: 'Macro-laced documents targeting oil sector employees' },
      { id: 'T1110.003', name: 'Password Spraying', tactic: 'Credential Access', platform: 'AWS IAM', description: 'Mass password spraying against AWS console logins' },
      { id: 'T1580', name: 'Cloud Infrastructure Discovery', tactic: 'Discovery', platform: 'Multi', description: 'Enumerating EC2, RDS, S3 via stolen creds' },
      { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection', platform: 'S3/RDS', description: 'Targeting database snapshots and S3 backups' },
      { id: 'T1485', name: 'Data Destruction', tactic: 'Impact', platform: 'S3/RDS', description: 'Deleting S3 objects and RDS snapshots' }
    ],
    references: [
      { icon: '\u{1f3db}\ufe0f', title: 'CISA Alert: Iranian Government Cyber Actors Targeting Key Sectors', source: 'CISA \u00b7 2023', type: 'ADVISORY', color: 'var(--red)' },
      { icon: '\u{1f52c}', title: 'Peach Sandstorm Password Spray Campaigns', source: 'Microsoft Threat Intelligence \u00b7 2023', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\u{1f5c2}\ufe0f', title: 'MITRE ATT&CK \u2014 APT33 Group Profile (G0064)', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'var(--purple)' }
    ]
  },
  {
    id: 'fin7-aws',
    name: 'FIN7 \u2014 Carbon Spider / Sangria Tempest',
    origin: 'russia',
    originLabel: 'RUSSIA',
    tags: ['Payment Card', 'POS Systems', 'Credential Dump', 'EKS Targeting', 'SSM Abuse'],
    techniqueCount: 13,
    severity: 'HIGH',
    aliases: 'Carbon Spider \u00b7 Sangria Tempest \u00b7 ELBRUS',
    attribution: 'Financially Motivated \u2014 Russia-based Cybercrime',
    activeSince: '2013 \u2014 Present',
    targets: 'Retail, Hospitality, Financial Services',
    incidents: ['Hundreds of POS Breaches (2015-2018)', 'Ransomware Pivot (2020)', 'Supply Chain Attacks via Kaseya (2021)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1566.001', name: 'Spearphishing Link' },
          { id: 'T1190', name: 'Exploit Public-Facing Application' }
        ]
      },
      {
        phase: 2, name: 'Persistence & Execution',
        techniques: [
          { id: 'T1098', name: 'Account Manipulation' },
          { id: 'T1059.001', name: 'PowerShell Execution' },
          { id: 'T1053.007', name: 'Container Orchestration Job' }
        ]
      },
      {
        phase: 3, name: 'Credential Access',
        techniques: [
          { id: 'T1552.001', name: 'Credentials in Files' },
          { id: 'T1552.005', name: 'Cloud Instance Metadata' },
          { id: 'T1003', name: 'OS Credential Dumping' }
        ]
      },
      {
        phase: 4, name: 'Lateral Movement & Collection',
        techniques: [
          { id: 'T1021.004', name: 'SSH via SSM' },
          { id: 'T1530', name: 'Data from Cloud Storage' }
        ]
      },
      {
        phase: 5, name: 'Impact',
        techniques: [
          { id: 'T1486', name: 'Data Encrypted for Impact' },
          { id: 'T1567', name: 'Exfiltration Over Web Service' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1566.001', name: 'Spearphishing Link', tactic: 'Initial Access', platform: 'Any', description: 'Fake business inquiry emails with malicious links' },
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', platform: 'EC2/EKS', description: 'Targeting misconfigured web applications' },
      { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence', platform: 'AWS IAM', description: 'Creating persistent access via IAM key rotation' },
      { id: 'T1552.005', name: 'Cloud Instance Metadata', tactic: 'Credential Access', platform: 'EC2 IMDS', description: 'Extracting IAM role credentials from metadata' },
      { id: 'T1053.007', name: 'Container Orchestration Job', tactic: 'Execution', platform: 'EKS', description: 'Deploying malicious workloads in EKS clusters' },
      { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', platform: 'S3/EBS', description: 'Ransomware deployment encrypting cloud storage' }
    ],
    references: [
      { icon: '\u{1f3db}\ufe0f', title: 'DOJ Indictment: FIN7 Members Charged with Attacking 100+ Companies', source: 'US Department of Justice \u00b7 2018', type: 'ADVISORY', color: 'var(--red)' },
      { icon: '\u{1f52c}', title: 'FIN7 Evolution: From POS to Ransomware and Cloud', source: 'Mandiant \u00b7 2022', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\u{1f5c2}\ufe0f', title: 'MITRE ATT&CK \u2014 FIN7 Group Profile (G0046)', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'var(--purple)' }
    ]
  }
];
