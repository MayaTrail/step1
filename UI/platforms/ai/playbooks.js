/* ══════════════════════════════════════════
   MayaTrail — AI/ML IR Playbooks Data
   ══════════════════════════════════════════ */

window.MayaTrail.platforms.ai = window.MayaTrail.platforms.ai || {};

window.MayaTrail.platforms.ai.playbooks = [
  // [0] APT41 AI Model Theft Playbook
  {
    steps: [
      {
        title: 'Detect Anomalous Model Registry Access',
        body: 'Monitor for unusual access patterns to model registries (SageMaker Model Registry, Vertex AI Model Registry, MLflow). Check for bulk model download operations, access from unusual IPs, or downloads of model artifacts that exceed normal ML engineer activity.',
        code: 'aws cloudtrail lookup-events \\\n  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeModel \\\n  --start-time 2024-01-01T00:00:00Z\n# Also check SageMaker-specific logs:\naws sagemaker list-model-packages \\\n  --sort-by CreationTime --sort-order Descending'
      },
      {
        title: 'Contain Compromised ML Credentials',
        body: 'Immediately revoke API keys and access tokens for compromised ML engineer accounts. Disable SageMaker/Vertex AI execution roles associated with the compromise. Rotate all secrets in ML pipeline configurations.',
        code: 'aws iam list-access-keys --user-name ml-engineer\naws iam update-access-key --access-key-id AKIA... --status Inactive\naws sagemaker stop-notebook-instance \\\n  --notebook-instance-name compromised-notebook'
      },
      {
        title: 'Assess Model & Data Exposure',
        body: 'Determine which model weights and training datasets were accessed. Check cloud storage access logs for bulk downloads of model artifacts (.pt, .onnx, .safetensors files). Verify if proprietary training data was exfiltrated.',
        code: 'aws s3api list-objects-v2 --bucket ml-models-bucket \\\n  --query "Contents[?contains(Key, \'.safetensors\') || contains(Key, \'.pt\')]"\naws cloudtrail lookup-events \\\n  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject'
      },
      {
        title: 'Check ML Pipeline Integrity',
        body: 'APT41 targets CI/CD pipelines. Review all training pipeline configurations for unauthorized modifications. Check for injected code in preprocessing scripts, modified training hyperparameters, or backdoored model evaluation code.',
        code: 'aws sagemaker list-pipeline-executions \\\n  --pipeline-name production-training-pipeline\naws sagemaker describe-pipeline-execution \\\n  --pipeline-execution-arn arn:aws:sagemaker:...'
      },
      {
        title: 'Deploy Model Access Controls',
        body: 'Implement IAM policies restricting model artifact access to approved roles only. Enable S3 Object Lock on model storage buckets. Implement model signing to verify integrity. Set up CloudWatch alarms for unusual SageMaker API patterns.'
      },
      {
        title: 'Post-Incident Hardening',
        body: 'Enable VPC-only access for all SageMaker notebooks and endpoints. Implement network segmentation for ML infrastructure. Deploy DLP policies to detect model weight exfiltration. Schedule re-emulation to validate controls.'
      }
    ]
  },
  // [1] Scattered Spider AI Platform Playbook
  {
    steps: [
      {
        title: 'Detect Social Engineering Against ML Teams',
        body: 'Review identity provider logs for password resets and MFA changes affecting ML engineering team members. Check for help desk tickets requesting credential resets for accounts with access to GPU clusters or ML platforms.',
        code: 'gcloud logging read \\\n  "protoPayload.serviceName=\\"login.googleapis.com\\"" \\\n  --project=ai-platform-project --freshness=7d'
      },
      {
        title: 'Audit API Key Exposure in Notebooks',
        body: 'Scan all Jupyter notebooks for hardcoded API keys, access tokens, and credentials. Check .env files, notebook outputs, and git history for leaked secrets. Use secret scanning tools across notebook repositories.',
        code: '# Scan for exposed secrets in notebook files\nfind /workspace -name "*.ipynb" -exec grep -l "sk-\\|AKIA\\|AIza" {} \\;\nfind /workspace -name ".env" -exec cat {} \\;'
      },
      {
        title: 'Detect GPU Cluster Cryptomining',
        body: 'Check GPU utilization patterns for signs of cryptomining. Look for unexpected CUDA processes, XMRig signatures, or connections to known mining pool domains. Compare GPU costs against expected training workloads.',
        code: 'nvidia-smi --query-gpu=name,utilization.gpu,memory.used \\\n  --format=csv -l 5\n# Check for mining processes:\nps aux | grep -i "xmrig\\|minergate\\|cryptonight"'
      },
      {
        title: 'Revoke Stolen LLM API Keys',
        body: 'Immediately rotate all LLM API keys (OpenAI, Anthropic, Cohere, etc.) that may have been exposed. Monitor API usage dashboards for anomalous request patterns. Check if stolen keys are being resold on dark web forums.'
      },
      {
        title: 'Implement Secret Management',
        body: 'Migrate all API keys to secrets managers (AWS Secrets Manager, GCP Secret Manager). Implement pre-commit hooks to prevent secrets in notebooks. Deploy automated secret rotation. Enforce short-lived tokens for ML workloads.',
        code: 'aws secretsmanager create-secret \\\n  --name ai/openai-api-key \\\n  --secret-string "sk-..." \\\n  --tags Key=team,Value=ml-engineering'
      }
    ]
  },
  // [2] DPRK IT Workers AI Playbook
  {
    steps: [
      {
        title: 'Detect Insider Threat Indicators',
        body: 'Monitor for unusual after-hours access to model repositories and training pipelines. Check for large data transfers from ML storage to personal cloud accounts. Review VPN usage patterns for connections from flagged geographic regions.',
        code: 'aws cloudtrail lookup-events \\\n  --lookup-attributes AttributeKey=Username,AttributeValue=suspect-user \\\n  --start-time 2024-01-01T00:00:00Z \\\n  --max-results 200'
      },
      {
        title: 'Verify Employee Identity',
        body: 'DPRK IT workers use stolen or fabricated identities. Cross-reference employee profiles with identity verification services. Check for inconsistencies in background checks, work patterns, and communication behaviors. Verify physical location matches claimed location.'
      },
      {
        title: 'Audit ML Pipeline for Backdoors',
        body: 'Review all code commits by the suspected insider. Check training scripts for injected backdoor triggers. Verify model evaluation scripts have not been modified to hide poisoned behavior. Run integrity checks on training data.',
        code: 'git log --author="suspect-user" --all --oneline\ngit diff HEAD~100..HEAD -- "*.py" "*.yaml" "*.json"\n# Check for data poisoning indicators:\npython -c "import hashlib; print(hashlib.sha256(open(\'training_data.csv\',\'rb\').read()).hexdigest())"'
      },
      {
        title: 'Check for Training Data Poisoning',
        body: 'Compare model performance metrics before and after the insider access period. Run anomaly detection on training datasets to identify injected samples. Test model behavior with known backdoor trigger inputs.',
        code: '# Model integrity check\npython evaluate_model.py --model production-v2 --test-set backdoor-triggers.json\npython compare_metrics.py --baseline v1-metrics.json --current v2-metrics.json'
      },
      {
        title: 'Contain & Remediate',
        body: 'Immediately revoke all access for the confirmed insider. Preserve all artifacts (code, models, data) for forensic analysis. Retrain affected models from verified clean datasets. Report to FBI IC3 per DPRK IT worker advisory.'
      },
      {
        title: 'Strengthen Insider Threat Program',
        body: 'Implement enhanced identity verification for ML engineering hires. Enforce code review requirements for all pipeline changes. Deploy behavioral analytics on ML infrastructure access. Implement data loss prevention for model artifacts.'
      }
    ]
  },
  // [3] PRC LLM Prompt Injection Playbook
  {
    steps: [
      {
        title: 'Detect Prompt Injection Patterns',
        body: 'Monitor LLM API logs for inputs matching known prompt injection patterns. Look for unusual token counts, encoded payloads, or inputs designed to extract system prompts. Set up rate limiting and anomaly detection on API endpoints.',
        code: '# Check API logs for injection patterns\ngrep -i "ignore previous\\|system prompt\\|you are now\\|jailbreak" \\\n  /var/log/llm-api/requests.log | tail -100\n# Check for data extraction attempts\ngrep "repeat all\\|dump your\\|list all documents" \\\n  /var/log/llm-api/requests.log'
      },
      {
        title: 'Block Malicious API Consumers',
        body: 'Identify API keys or IP addresses generating prompt injection attacks. Implement rate limiting and IP blocking. Deploy WAF rules to filter known prompt injection payloads before they reach the model.',
        code: 'aws wafv2 create-ip-set --name blocked-ips \\\n  --scope REGIONAL --ip-address-version IPV4 \\\n  --addresses "1.2.3.4/32" "5.6.7.0/24"'
      },
      {
        title: 'Audit RAG Knowledge Base Exposure',
        body: 'Determine if prompt injection successfully extracted data from RAG knowledge bases. Review vector database query logs for unusual patterns. Check if private documents were leaked through model responses.',
        code: '# Check vector DB access patterns\npython audit_rag_access.py \\\n  --start-date 2024-01-01 \\\n  --end-date 2024-02-01 \\\n  --flag-anomalies'
      },
      {
        title: 'Assess System Prompt Exposure',
        body: 'Test if system prompts were successfully extracted by adversarial inputs. Review model outputs for instances where system instructions or internal configurations were leaked. Update system prompts if exposed.'
      },
      {
        title: 'Deploy Input/Output Guardrails',
        body: 'Implement input sanitization layers to detect and block prompt injection. Deploy output filtering to prevent leakage of system prompts and private data. Add canary tokens to RAG documents to detect unauthorized access.',
        code: '# Deploy guardrail configuration\npython deploy_guardrails.py \\\n  --input-filter prompt_injection_detector \\\n  --output-filter pii_redactor \\\n  --canary-tokens enabled'
      },
      {
        title: 'Continuous Red Teaming',
        body: 'Establish regular red team exercises against LLM applications. Run OWASP LLM Top 10 assessments quarterly. Implement automated adversarial testing in CI/CD. Schedule MayaTrail AI emulation re-runs after each model update.'
      }
    ]
  }
];
