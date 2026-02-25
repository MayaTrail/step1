/* ══════════════════════════════════════════
   MayaTrail — AI/ML APT Emulations Data
   ══════════════════════════════════════════ */

window.MayaTrail = window.MayaTrail || {};
window.MayaTrail.platforms = window.MayaTrail.platforms || {};
window.MayaTrail.platforms.ai = window.MayaTrail.platforms.ai || {};

window.MayaTrail.platforms.ai.emulations = [
  {
    id: 'apt41-ai',
    name: 'APT41 \u2014 AI Model Theft Campaign',
    origin: 'china',
    originLabel: 'CHINA',
    tags: ['Model Theft', 'Training Data Exfil', 'SageMaker Abuse', 'Vertex AI', 'IP Theft'],
    techniqueCount: 14,
    severity: 'CRITICAL',
    aliases: 'Winnti \u00b7 Barium \u00b7 Wicked Panda',
    attribution: 'MSS \u2014 Chinese Ministry of State Security',
    activeSince: '2012 \u2014 Present',
    targets: 'AI Research Labs, Tech Companies, Semiconductor, Biotech',
    incidents: ['AI Research Lab Targeting (2023)', 'Model Weight Exfiltration Campaign (2024)', 'GPU Cluster Compromise for Training (2024)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1078.004', name: 'Stolen ML Engineer Credentials' },
          { id: 'T1190', name: 'Exploit Jupyter Notebook Server' },
          { id: 'T1195.002', name: 'Supply Chain via ML Pipeline' }
        ]
      },
      {
        phase: 2, name: 'Discovery & Recon',
        techniques: [
          { id: 'T1580', name: 'ML Infrastructure Discovery' },
          { id: 'T1526', name: 'Model Registry Enumeration' },
          { id: 'T1087.004', name: 'Cloud ML Service Account Discovery' }
        ]
      },
      {
        phase: 3, name: 'Collection',
        techniques: [
          { id: 'T1530', name: 'Model Weights from Cloud Storage' },
          { id: 'T1119', name: 'Automated Model Collection' },
          { id: 'T1213', name: 'Training Dataset Access' }
        ]
      },
      {
        phase: 4, name: 'Exfiltration',
        techniques: [
          { id: 'T1567', name: 'Exfiltration via Cloud API' },
          { id: 'T1537', name: 'Transfer Model to External Account' },
          { id: 'T1041', name: 'Exfiltration Over C2 Channel' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1078.004', name: 'Valid Cloud Accounts', tactic: 'Initial Access', platform: 'AWS/GCP', description: 'Compromised ML engineer credentials for SageMaker/Vertex' },
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', platform: 'JupyterHub', description: 'Exploiting exposed Jupyter notebook servers' },
      { id: 'T1195.002', name: 'Supply Chain Compromise', tactic: 'Initial Access', platform: 'ML Pipeline', description: 'Injecting malicious code into ML training pipelines' },
      { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection', platform: 'S3/GCS', description: 'Downloading model weights and training datasets' },
      { id: 'T1119', name: 'Automated Collection', tactic: 'Collection', platform: 'Model Registry', description: 'Scripted download of model artifacts from MLflow/SageMaker' },
      { id: 'T1537', name: 'Transfer to Cloud Account', tactic: 'Exfiltration', platform: 'Multi-Cloud', description: 'Copying model files to attacker-controlled cloud storage' }
    ],
    references: [
      { icon: '\ud83c\udfdb\ufe0f', title: 'FBI Advisory: PRC State-Sponsored Actors Targeting AI Research', source: 'FBI Cyber Division \u00b7 2024', type: 'ADVISORY', color: 'var(--red)' },
      { icon: '\ud83d\udd2c', title: 'APT41 AI Sector Targeting: Model Theft TTPs', source: 'Mandiant \u00b7 2024', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83d\uddc2\ufe0f', title: 'MITRE ATLAS \u2014 ML Attack Techniques Matrix', source: 'MITRE ATLAS \u00b7 atlas.mitre.org', type: 'MITRE', color: 'var(--purple)' }
    ]
  },
  {
    id: 'scattered-spider-ai',
    name: 'Scattered Spider \u2014 AI Platform Social Engineering',
    origin: 'financial',
    originLabel: 'FINANCIAL',
    tags: ['API Key Theft', 'Jupyter Abuse', 'GPU Cryptomining', 'MFA Bypass', 'Engineer Targeting'],
    techniqueCount: 11,
    severity: 'HIGH',
    aliases: 'UNC3944 \u00b7 Octo Tempest \u00b7 0ktapus',
    attribution: 'Financially Motivated \u2014 English-speaking Threat Group',
    activeSince: '2022 \u2014 Present',
    targets: 'AI Companies, Cloud Providers, Tech Companies',
    incidents: ['AI Platform Engineer Vishing Campaign (2023)', 'GPU Cluster Hijacking for Crypto (2024)', 'LLM API Key Theft and Resale (2024)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1566.004', name: 'Vishing AI Engineers' },
          { id: 'T1621', name: 'MFA Fatigue Attack' },
          { id: 'T1078.004', name: 'Stolen Cloud Credentials' }
        ]
      },
      {
        phase: 2, name: 'Credential Harvesting',
        techniques: [
          { id: 'T1552.001', name: 'API Keys in Notebooks' },
          { id: 'T1528', name: 'Steal LLM API Tokens' },
          { id: 'T1552.005', name: 'ML Instance Metadata' }
        ]
      },
      {
        phase: 3, name: 'Resource Abuse',
        techniques: [
          { id: 'T1496', name: 'GPU Cluster Cryptomining' },
          { id: 'T1610', name: 'Deploy Mining Container on ML Cluster' }
        ]
      },
      {
        phase: 4, name: 'Impact',
        techniques: [
          { id: 'T1657', name: 'Financial Theft via API Resale' },
          { id: 'T1486', name: 'Ransomware on ML Infrastructure' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1566.004', name: 'Spearphishing Voice', tactic: 'Initial Access', platform: 'Any', description: 'Social engineering help desk to reset ML engineer passwords' },
      { id: 'T1552.001', name: 'Credentials In Files', tactic: 'Credential Access', platform: 'Jupyter', description: 'Harvesting API keys from Jupyter notebooks and .env files' },
      { id: 'T1528', name: 'Steal Application Access Token', tactic: 'Credential Access', platform: 'LLM APIs', description: 'Stealing OpenAI, Anthropic, and other LLM API keys' },
      { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact', platform: 'GPU Cluster', description: 'Using stolen GPU access for cryptomining operations' },
      { id: 'T1657', name: 'Financial Theft', tactic: 'Impact', platform: 'Any', description: 'Reselling stolen LLM API access on dark web' }
    ],
    references: [
      { icon: '\ud83d\udd2c', title: 'Scattered Spider: AI Infrastructure Targeting TTPs', source: 'CrowdStrike \u00b7 2024', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83c\udfdb\ufe0f', title: 'FBI: Cybercriminals Targeting AI Companies', source: 'FBI IC3 \u00b7 2024', type: 'ADVISORY', color: 'var(--red)' }
    ]
  },
  {
    id: 'dprk-ai',
    name: 'DPRK IT Workers \u2014 AI Supply Chain Infiltration',
    origin: 'nk',
    originLabel: 'DPRK',
    tags: ['Insider Threat', 'Model Poisoning', 'Pipeline Backdoor', 'Fake Identity', 'Supply Chain'],
    techniqueCount: 12,
    severity: 'CRITICAL',
    aliases: 'DPRK IT Workers \u00b7 Nickel Academy',
    attribution: 'RGB \u2014 North Korean Reconnaissance General Bureau',
    activeSince: '2020 \u2014 Present',
    targets: 'AI Startups, Research Labs, Fortune 500 AI Teams',
    incidents: ['DPRK IT Worker Infiltration of AI Companies (2023-2024)', 'Training Data Poisoning Campaign (2024)', 'Model Pipeline Backdoor Discovery (2024)'],
    attackPath: [
      {
        phase: 1, name: 'Initial Access',
        techniques: [
          { id: 'T1199', name: 'Insider Access via Fake Identity' },
          { id: 'T1078.004', name: 'Legitimate Employee Credentials' }
        ]
      },
      {
        phase: 2, name: 'Persistence & Tampering',
        techniques: [
          { id: 'T1195.002', name: 'ML Pipeline Backdoor' },
          { id: 'T1059.006', name: 'Python Script Injection' },
          { id: 'T1098', name: 'Account Manipulation for Persistence' }
        ]
      },
      {
        phase: 3, name: 'Collection & Model Poisoning',
        techniques: [
          { id: 'T1530', name: 'Access Training Datasets' },
          { id: 'T1565.001', name: 'Training Data Manipulation' },
          { id: 'T1119', name: 'Automated Model Artifact Collection' }
        ]
      },
      {
        phase: 4, name: 'Exfiltration',
        techniques: [
          { id: 'T1567', name: 'Exfiltration via Cloud Storage' },
          { id: 'T1048', name: 'Exfiltration Over Alternative Protocol' },
          { id: 'T1041', name: 'Exfiltration Over C2' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1199', name: 'Trusted Relationship', tactic: 'Initial Access', platform: 'Any', description: 'Gaining employment with stolen/fake identities' },
      { id: 'T1195.002', name: 'Supply Chain Compromise', tactic: 'Initial Access', platform: 'ML Pipeline', description: 'Backdooring training pipelines and CI/CD' },
      { id: 'T1059.006', name: 'Python', tactic: 'Execution', platform: 'ML Infrastructure', description: 'Injecting malicious Python into training scripts' },
      { id: 'T1565.001', name: 'Stored Data Manipulation', tactic: 'Impact', platform: 'Training Data', description: 'Poisoning training data to introduce model backdoors' },
      { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection', platform: 'S3/GCS', description: 'Downloading proprietary training datasets' },
      { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration', platform: 'Any', description: 'Exfiltrating model IP to DPRK-controlled servers' }
    ],
    references: [
      { icon: '\ud83c\udfdb\ufe0f', title: 'FBI/CISA: DPRK IT Workers Targeting US Tech Companies', source: 'CISA \u00b7 2024', type: 'ADVISORY', color: 'var(--red)' },
      { icon: '\ud83d\udd2c', title: 'North Korean Fake IT Workers: AI Sector Deep Dive', source: 'Mandiant \u00b7 2024', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83d\udcdd', title: 'MITRE ATLAS: AI Supply Chain Attack Patterns', source: 'MITRE ATLAS \u00b7 2024', type: 'RESEARCH', color: 'var(--purple)' }
    ]
  },
  {
    id: 'prc-llm',
    name: 'PRC-linked \u2014 LLM Prompt Injection & Data Extraction',
    origin: 'china',
    originLabel: 'CHINA',
    tags: ['Prompt Injection', 'Data Extraction', 'API Abuse', 'Safety Bypass', 'Adversarial ML'],
    techniqueCount: 10,
    severity: 'HIGH',
    aliases: 'PRC LLM Threat Actors',
    attribution: 'PRC State-Linked \u2014 Multiple Groups',
    activeSince: '2023 \u2014 Present',
    targets: 'LLM Providers, AI-Integrated Applications, RAG Systems',
    incidents: ['Systematic LLM Training Data Extraction (2024)', 'Multi-Provider API Key Abuse Campaign (2024)', 'RAG System Prompt Injection at Scale (2024)'],
    attackPath: [
      {
        phase: 1, name: 'Reconnaissance',
        techniques: [
          { id: 'T1595.002', name: 'API Endpoint Scanning' },
          { id: 'T1592', name: 'Model Architecture Fingerprinting' }
        ]
      },
      {
        phase: 2, name: 'Initial Exploitation',
        techniques: [
          { id: 'T1190', name: 'Prompt Injection Attack' },
          { id: 'T1059', name: 'Adversarial Input Execution' },
          { id: 'T1078.004', name: 'Stolen API Keys' }
        ]
      },
      {
        phase: 3, name: 'Data Extraction',
        techniques: [
          { id: 'T1119', name: 'Automated Data Extraction' },
          { id: 'T1530', name: 'RAG Knowledge Base Access' },
          { id: 'T1005', name: 'System Prompt Extraction' }
        ]
      },
      {
        phase: 4, name: 'Impact',
        techniques: [
          { id: 'T1565', name: 'Model Output Manipulation' },
          { id: 'T1496', name: 'Compute Resource Abuse' }
        ]
      }
    ],
    mitreMappings: [
      { id: 'T1595.002', name: 'Vulnerability Scanning', tactic: 'Reconnaissance', platform: 'LLM APIs', description: 'Probing LLM endpoints for injection vulnerabilities' },
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', platform: 'LLM Apps', description: 'Prompt injection to bypass safety guardrails' },
      { id: 'T1119', name: 'Automated Collection', tactic: 'Collection', platform: 'LLM APIs', description: 'Automated extraction of training data via crafted prompts' },
      { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection', platform: 'RAG Systems', description: 'Extracting private documents from RAG knowledge bases' },
      { id: 'T1565', name: 'Data Manipulation', tactic: 'Impact', platform: 'LLM Apps', description: 'Manipulating model outputs via adversarial inputs' }
    ],
    references: [
      { icon: '\ud83d\udd2c', title: 'ATLAS: Adversarial Machine Learning Threat Landscape', source: 'MITRE ATLAS \u00b7 2024', type: 'REPORT', color: 'var(--cyan)' },
      { icon: '\ud83d\udcdd', title: 'OWASP Top 10 for LLM Applications', source: 'OWASP \u00b7 2024', type: 'RESEARCH', color: 'var(--orange)' },
      { icon: '\ud83c\udfdb\ufe0f', title: 'NIST AI Risk Management Framework', source: 'NIST \u00b7 2024', type: 'FRAMEWORK', color: 'var(--green)' }
    ]
  }
];
