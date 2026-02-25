/* ══════════════════════════════════════════
   MayaTrail — AI/ML Detections & Guardrails
   ══════════════════════════════════════════ */

window.MayaTrail.platforms.ai = window.MayaTrail.platforms.ai || {};

window.MayaTrail.platforms.ai.detections = {
  ruleCount: 87,
  formats: 'SIGMA \u00b7 Python \u00b7 YARA',
  rules: [
    {
      title: 'SIGMA Rule \u2014 Suspicious Model Weight Download',
      code: 'title: Bulk ML Model Weight Download from Cloud Storage\nstatus: experimental\ndescription: Detects bulk download of model weight files (.pt, .onnx, .safetensors) which may indicate model theft\nreferences:\n  - https://atlas.mitre.org/techniques/AML.T0044\ntags:\n  - attack.collection\n  - attack.t1530\n  - atlas.aml.t0044\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  selection:\n    eventName: GetObject\n    eventSource: s3.amazonaws.com\n    requestParameters.key|endswith:\n      - ".pt"\n      - ".pth"\n      - ".onnx"\n      - ".safetensors"\n      - ".bin"\n      - ".h5"\n  timeframe: 1h\n  condition: selection | count() by sourceIPAddress > 20\nfalsepositives:\n  - Model deployment pipelines\n  - Scheduled model sync operations\nlevel: high'
    },
    {
      title: 'Python \u2014 Anomalous LLM API Usage Pattern Detector',
      code: '#!/usr/bin/env python3\n"""MayaTrail AI Detection: Anomalous LLM API Usage Pattern"""\nimport json\nfrom datetime import datetime, timedelta\nfrom collections import defaultdict\n\ndef detect_anomalous_api_usage(api_logs, window_hours=1, threshold_multiplier=3.0):\n    """Detect anomalous API usage patterns that may indicate\n    prompt injection, data extraction, or API key abuse."""\n    \n    hourly_counts = defaultdict(lambda: defaultdict(int))\n    token_counts = defaultdict(lambda: defaultdict(int))\n    \n    for log in api_logs:\n        api_key = log["api_key_prefix"]\n        hour = log["timestamp"][:13]\n        hourly_counts[api_key][hour] += 1\n        token_counts[api_key][hour] += log.get("total_tokens", 0)\n    \n    alerts = []\n    for api_key, hours in hourly_counts.items():\n        values = list(hours.values())\n        if len(values) < 24:\n            continue\n        avg = sum(values[:-1]) / len(values[:-1])\n        current = values[-1]\n        if current > avg * threshold_multiplier:\n            alerts.append({\n                "type": "ANOMALOUS_API_USAGE",\n                "api_key_prefix": api_key,\n                "current_rate": current,\n                "baseline_avg": round(avg, 1),\n                "severity": "HIGH",\n                "mitre_technique": "T1119"\n            })\n    return alerts'
    },
    {
      title: 'YARA Rule \u2014 ML Model Exfiltration Artifact Detection',
      code: 'rule ModelExfiltrationArtifact {\n    meta:\n        description = "Detects compressed archives containing ML model weights"\n        author = "MayaTrail Detection Engineering"\n        severity = "HIGH"\n        mitre_technique = "T1530"\n        mitre_atlas = "AML.T0044"\n    \n    strings:\n        $safetensors_header = { 7B 22 5F 5F 6D 65 74 61 64 61 74 61 5F 5F 22 }\n        $pytorch_magic = { 50 4B 03 04 }  // ZIP (PyTorch .pt files)\n        $onnx_header = { 08 00 12 }\n        $hdf5_magic = { 89 48 44 46 0D 0A 1A 0A }\n        \n        $model_path1 = "model.safetensors" ascii\n        $model_path2 = "pytorch_model.bin" ascii\n        $model_path3 = "model.onnx" ascii\n        $config_json = "config.json" ascii\n        $tokenizer = "tokenizer.json" ascii\n    \n    condition:\n        (any of ($safetensors_header, $pytorch_magic, $onnx_header, $hdf5_magic))\n        and (2 of ($model_path*, $config_json, $tokenizer))\n        and filesize > 100MB\n}'
    }
  ]
};

window.MayaTrail.platforms.ai.guardrails = {
  excluded: [
    'Production inference endpoints (tag: env=production)',
    'Production model registry (approved models only)',
    'Customer-facing RAG knowledge bases',
    'GPU clusters running active training jobs',
    'Production LLM API keys and endpoints'
  ],
  schedule: 'Monday \u2013 Friday  |  02:00 \u2013 06:00 UTC  |  Auto-pause on model deployment',
  scopeLimits: [
    'No access to production model weights or training data',
    'Training pipelines in read-only mode during emulation',
    'GPU allocation limited to sandbox cluster only',
    'No modification of production LLM guardrail configurations',
    'Automatic rollback if model performance degradation detected',
    'Prompt injection tests limited to sandboxed model endpoints only'
  ]
};
