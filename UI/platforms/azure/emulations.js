/* ══════════════════════════════════════════
   MayaTrail — Azure APT Emulations Data
   ══════════════════════════════════════════ */

window.MayaTrail = window.MayaTrail || {};
window.MayaTrail.platforms = window.MayaTrail.platforms || {};
window.MayaTrail.platforms.azure = window.MayaTrail.platforms.azure || {};

window.MayaTrail.platforms.azure.emulations = [
  {
    id: 'apt29-azure',
    name: 'APT29 \u2014 Midnight Blizzard / Azure Ops',
    origin: 'russia',
    originLabel: 'RUSSIA',
    tags: ['Entra ID', 'OAuth Abuse', 'Token Theft', 'Mailbox Exfiltration', 'Tenant Compromise'],
    techniqueCount: 16,
    severity: 'CRITICAL',
    aliases: 'Midnight Blizzard \u00b7 Nobelium \u00b7 IRON HEMLOCK',
    attribution: 'SVR \u2014 Russian Foreign Intelligence',
    activeSince: '2008 \u2014 Present',
    targets: 'Government, Technology, Defense, Diplomatic',
    incidents: ['Microsoft Corporate Breach (2024)', 'SolarWinds Azure AD Pivot (2020)', 'HPE Email Compromise (2024)', 'US Government Email Access (2023)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1078.004', name: 'Valid Azure AD Accounts' },
          { id: 'T1110.003', name: 'Password Spraying Entra ID' },
          { id: 'T1566.001', name: 'OAuth Consent Phishing' }
        ]
      },
      {
        phase: 2, name: 'Credential Access',
        techniques: [
          { id: 'T1528', name: 'Steal OAuth Access Token' },
          { id: 'T1098.003', name: 'Add Azure AD App Credentials' },
          { id: 'T1552.005', name: 'Azure IMDS Token Theft' }
        ]
      },
      {
        phase: 3, name: 'Persistence & Escalation',
        techniques: [
          { id: 'T1098.001', name: 'App Registration Manipulation' },
          { id: 'T1136.003', name: 'Create Cloud Account' },
          { id: 'T1548.005', name: 'Entra ID Role Assignment' }
        ]
      },
      {
        phase: 4, name: 'Defense Evasion',
        techniques: [
          { id: 'T1562.008', name: 'Disable Azure AD Logging' },
          { id: 'T1550.001', name: 'Application Access Token Reuse' }
        ]
      },
      {
        phase: 5, name: 'Collection & Exfiltration',
        techniques: [
          { id: 'T1114.002', name: 'Remote Email Collection (Exchange Online)' },
          { id: 'T1530', name: 'Data from Azure Storage' },
          { id: 'T1567', name: 'Exfiltration via Graph API' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1110.003', name: 'Password Spraying', tactic: 'Credential Access', platform: 'Entra ID', description: 'Distributed password spray against Azure AD tenant' },
      { id: 'T1528', name: 'Steal Application Access Token', tactic: 'Credential Access', platform: 'Entra ID', description: 'Stealing OAuth tokens from compromised apps' },
      { id: 'T1098.003', name: 'Additional Cloud Credentials', tactic: 'Persistence', platform: 'Entra ID', description: 'Adding credentials to existing app registrations' },
      { id: 'T1098.001', name: 'Additional Cloud Roles', tactic: 'Persistence', platform: 'Entra ID', description: 'Granting app permissions to access mailboxes' },
      { id: 'T1136.003', name: 'Create Cloud Account', tactic: 'Persistence', platform: 'Entra ID', description: 'Creating rogue service principals' },
      { id: 'T1562.008', name: 'Disable Cloud Logging', tactic: 'Defense Evasion', platform: 'Azure Monitor', description: 'Disabling Unified Audit Log or diagnostic settings' },
      { id: 'T1114.002', name: 'Remote Email Collection', tactic: 'Collection', platform: 'Exchange Online', description: 'Using Graph API to read mailboxes of executives' },
      { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection', platform: 'Azure Blob', description: 'Accessing Azure Blob Storage with stolen tokens' }
    ],
    references: [
      { icon: '\ud83c\udfdb\ufe0f', title: 'Microsoft: Midnight Blizzard Corporate Email Breach Analysis', source: 'Microsoft Security \u00b7 2024', type: 'ADVISORY', color: 'var(--red)' },
      { icon: '\ud83d\udd2c', title: 'CISA Emergency Directive ED 24-02: Midnight Blizzard Azure Compromise', source: 'CISA \u00b7 2024', type: 'ADVISORY', color: 'var(--red)' },
      { icon: '\ud83d\uddc2\ufe0f', title: 'MITRE ATT&CK \u2014 APT29 Group Profile (G0016)', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'var(--purple)' }
    ]
  },
  {
    id: 'storm0558-azure',
    name: 'Storm-0558 \u2014 Azure AD Token Forging',
    origin: 'china',
    originLabel: 'CHINA',
    tags: ['MSA Key Abuse', 'Token Forging', 'Exchange Online', 'Entra ID Bypass', 'Government Targeting'],
    techniqueCount: 12,
    severity: 'CRITICAL',
    aliases: 'Storm-0558',
    attribution: 'PRC State-Sponsored \u2014 Chinese Espionage Group',
    activeSince: '2021 \u2014 Present',
    targets: 'Government Agencies, Diplomatic Entities',
    incidents: ['US Government Email Breach (2023)', '25+ Organizations Compromised via Forged Tokens (2023)', 'State Department Email Access (2023)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1078.004', name: 'Forged Azure AD Tokens' },
          { id: 'T1199', name: 'MSA Consumer Key Abuse' }
        ]
      },
      {
        phase: 2, name: 'Credential Forging',
        techniques: [
          { id: 'T1606.002', name: 'Forge SAML/OAuth Tokens' },
          { id: 'T1528', name: 'Steal Application Access Token' }
        ]
      },
      {
        phase: 3, name: 'Lateral Movement',
        techniques: [
          { id: 'T1550.001', name: 'Application Access Token Reuse' },
          { id: 'T1021.007', name: 'Cloud API Lateral Movement' }
        ]
      },
      {
        phase: 4, name: 'Collection & Exfiltration',
        techniques: [
          { id: 'T1114.002', name: 'Exchange Online Email Access' },
          { id: 'T1530', name: 'Azure Blob Data Access' },
          { id: 'T1567', name: 'Exfiltration Over Web Service' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1078.004', name: 'Valid Cloud Accounts', tactic: 'Initial Access', platform: 'Entra ID', description: 'Using forged authentication tokens to access Azure' },
      { id: 'T1606.002', name: 'SAML Tokens', tactic: 'Credential Access', platform: 'Entra ID', description: 'Forging SAML tokens using stolen MSA consumer key' },
      { id: 'T1199', name: 'Trusted Relationship', tactic: 'Initial Access', platform: 'Azure', description: 'Exploiting MSA key trust to forge enterprise tokens' },
      { id: 'T1550.001', name: 'Application Access Token', tactic: 'Lateral Movement', platform: 'Exchange Online', description: 'Reusing forged tokens across multiple tenants' },
      { id: 'T1114.002', name: 'Remote Email Collection', tactic: 'Collection', platform: 'Exchange Online', description: 'Accessing government official email via OWA/EWS' }
    ],
    references: [
      { icon: '\ud83c\udfdb\ufe0f', title: 'CISA: Storm-0558 Azure AD Token Forging Advisory', source: 'CISA \u00b7 2023', type: 'ADVISORY', color: 'var(--red)' },
      { icon: '\ud83d\udd2c', title: 'Microsoft: Storm-0558 Investigation and Response', source: 'Microsoft Security Blog \u00b7 2023', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83d\udcdd', title: 'CSRB Review: Storm-0558 Cloud Security Failures', source: 'DHS Cyber Safety Review Board \u00b7 2024', type: 'REVIEW', color: 'var(--orange)' }
    ]
  },
  {
    id: 'muddywater-azure',
    name: 'MuddyWater \u2014 Mercury / Mango Sandstorm',
    origin: 'iran',
    originLabel: 'IRAN',
    tags: ['Exchange Exploit', 'PowerShell Abuse', 'Azure VM Hijack', 'Entra ID Recon', 'Proxy Tunneling'],
    techniqueCount: 10,
    severity: 'HIGH',
    aliases: 'Mercury \u00b7 Mango Sandstorm \u00b7 Static Kitten',
    attribution: 'MOIS \u2014 Iranian Ministry of Intelligence',
    activeSince: '2017 \u2014 Present',
    targets: 'Government, Telecom, Oil & Gas, IT Sector',
    incidents: ['Middle East Government Exchange Breaches (2022)', 'Turkish Government Targeting (2022)', 'Israeli IT Sector Campaign (2023)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1190', name: 'Exploit Exchange Server (ProxyShell)' },
          { id: 'T1566.001', name: 'Spearphishing with Azure Lures' }
        ]
      },
      {
        phase: 2, name: 'Execution & Persistence',
        techniques: [
          { id: 'T1059.001', name: 'PowerShell in Azure VM' },
          { id: 'T1098', name: 'Azure AD Account Manipulation' },
          { id: 'T1136.003', name: 'Create Azure AD Account' }
        ]
      },
      {
        phase: 3, name: 'Discovery & Collection',
        techniques: [
          { id: 'T1087.004', name: 'Azure AD Enumeration' },
          { id: 'T1530', name: 'Azure Storage Access' },
          { id: 'T1114.002', name: 'Exchange Mailbox Access' }
        ]
      },
      {
        phase: 4, name: 'Exfiltration',
        techniques: [
          { id: 'T1567', name: 'Exfiltration via Cloud Service' },
          { id: 'T1071.001', name: 'Web Protocol C2' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', platform: 'Exchange', description: 'Exploiting ProxyShell/ProxyLogon vulnerabilities on Exchange' },
      { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', platform: 'Azure VM', description: 'Remote PowerShell execution on compromised Azure VMs' },
      { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence', platform: 'Entra ID', description: 'Adding credentials to Azure AD application registrations' },
      { id: 'T1087.004', name: 'Cloud Account Discovery', tactic: 'Discovery', platform: 'Entra ID', description: 'Enumerating Azure AD users, groups, and roles' },
      { id: 'T1114.002', name: 'Remote Email Collection', tactic: 'Collection', platform: 'Exchange', description: 'Accessing email via EWS after Exchange exploitation' }
    ],
    references: [
      { icon: '\ud83d\udd2c', title: 'Mercury/MuddyWater Azure Campaigns', source: 'Microsoft MSTIC \u00b7 2022', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83c\udfdb\ufe0f', title: 'CISA: Iranian State Actors Exploiting Microsoft Exchange', source: 'CISA \u00b7 2022', type: 'ADVISORY', color: 'var(--red)' }
    ]
  },
  {
    id: 'lapsus-azure',
    name: 'LAPSUS$ \u2014 DEV-0537 / Azure DevOps',
    origin: 'financial',
    originLabel: 'FINANCIAL',
    tags: ['Azure DevOps', 'MFA Fatigue', 'Entra ID Abuse', 'Source Code Theft', 'SIM Swap'],
    techniqueCount: 11,
    severity: 'HIGH',
    aliases: 'DEV-0537 \u00b7 Strawberry Tempest',
    attribution: 'Financially Motivated \u2014 Teenage Threat Group',
    activeSince: '2021 \u2014 2023',
    targets: 'Technology, Gaming, Telecom',
    incidents: ['Microsoft Azure DevOps Breach (2022)', 'Okta Admin Console Access (2022)', 'Nvidia VPN Compromise (2022)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1078.004', name: 'Purchased Azure AD Creds' },
          { id: 'T1621', name: 'MFA Fatigue / Push Bombing' },
          { id: 'T1566.004', name: 'SIM Swap / Vishing' }
        ]
      },
      {
        phase: 2, name: 'Privilege Escalation',
        techniques: [
          { id: 'T1548.005', name: 'Global Admin Role Assignment' },
          { id: 'T1098', name: 'Azure AD App Permission Grants' }
        ]
      },
      {
        phase: 3, name: 'Collection',
        techniques: [
          { id: 'T1213.003', name: 'Azure DevOps Repos Access' },
          { id: 'T1530', name: 'Azure Blob Storage Access' },
          { id: 'T1119', name: 'Automated Repo Cloning' }
        ]
      },
      {
        phase: 4, name: 'Exfiltration & Impact',
        techniques: [
          { id: 'T1567', name: 'Exfiltration via Telegram' },
          { id: 'T1491.002', name: 'Public Data Leak' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1078.004', name: 'Valid Cloud Accounts', tactic: 'Initial Access', platform: 'Entra ID', description: 'Purchasing employee credentials from initial access brokers' },
      { id: 'T1621', name: 'Multi-Factor Auth Request Generation', tactic: 'Credential Access', platform: 'Entra ID', description: 'Spamming MFA prompts until user approves' },
      { id: 'T1548.005', name: 'Abuse Elevation Control', tactic: 'Privilege Escalation', platform: 'Entra ID', description: 'Self-assigning Global Administrator role' },
      { id: 'T1213.003', name: 'Code Repositories', tactic: 'Collection', platform: 'Azure DevOps', description: 'Cloning source code from Azure DevOps repos' },
      { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration', platform: 'Any', description: 'Leaking stolen data on Telegram channels' }
    ],
    references: [
      { icon: '\ud83d\udd2c', title: 'DEV-0537 Criminal Actor: Azure Operations Analysis', source: 'Microsoft MSTIC \u00b7 2022', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83c\udfdb\ufe0f', title: 'CSRB Review: LAPSUS$ and Related Threat Groups', source: 'DHS Cyber Safety Review Board \u00b7 2023', type: 'ADVISORY', color: 'var(--red)' }
    ]
  },
  {
    id: 'peachsandstorm-azure',
    name: 'Peach Sandstorm \u2014 APT33 / Elfin',
    origin: 'iran',
    originLabel: 'IRAN',
    tags: ['Password Spray', 'Key Vault Access', 'Azure VM Abuse', 'Entra ID Targeting', 'Defense Sector'],
    techniqueCount: 9,
    severity: 'MEDIUM',
    aliases: 'APT33 \u00b7 Elfin \u00b7 Refined Kitten',
    attribution: 'IRGC \u2014 Islamic Revolutionary Guard Corps',
    activeSince: '2013 \u2014 Present',
    targets: 'Defense, Satellite, Pharmaceutical, Government',
    incidents: ['Defense Industrial Base Password Spray (2023)', 'Satellite Tech Targeting (2023)', 'Azure Key Vault Exfiltration Attempt (2023)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1110.003', name: 'Password Spraying Entra ID' },
          { id: 'T1078.004', name: 'Valid Azure AD Accounts' }
        ]
      },
      {
        phase: 2, name: 'Discovery & Recon',
        techniques: [
          { id: 'T1087.004', name: 'Azure AD Enumeration' },
          { id: 'T1580', name: 'Azure Infrastructure Discovery' },
          { id: 'T1526', name: 'Cloud Service Discovery' }
        ]
      },
      {
        phase: 3, name: 'Collection',
        techniques: [
          { id: 'T1555.006', name: 'Azure Key Vault Secrets' },
          { id: 'T1530', name: 'Azure Blob Storage Data' }
        ]
      },
      {
        phase: 4, name: 'Persistence & Impact',
        techniques: [
          { id: 'T1098', name: 'Azure AD Account Manipulation' },
          { id: 'T1136.003', name: 'Create Azure Service Principal' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1110.003', name: 'Password Spraying', tactic: 'Credential Access', platform: 'Entra ID', description: 'Large-scale password spray against defense sector Azure tenants' },
      { id: 'T1087.004', name: 'Cloud Account Discovery', tactic: 'Discovery', platform: 'Entra ID', description: 'Enumerating users and their role assignments' },
      { id: 'T1555.006', name: 'Cloud Secrets Management Stores', tactic: 'Credential Access', platform: 'Key Vault', description: 'Accessing Azure Key Vault to steal secrets and certificates' },
      { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection', platform: 'Azure Blob', description: 'Downloading sensitive files from Azure Storage accounts' },
      { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence', platform: 'Entra ID', description: 'Creating persistent access via app registrations' }
    ],
    references: [
      { icon: '\ud83d\udd2c', title: 'Peach Sandstorm: Password Spray and Azure Targeting', source: 'Microsoft Threat Intelligence \u00b7 2023', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83c\udfdb\ufe0f', title: 'CISA: Iranian APT Actors Targeting Defense Industrial Base', source: 'CISA \u00b7 2023', type: 'ADVISORY', color: 'var(--red)' }
    ]
  }
];
