/* ══════════════════════════════════════════
   MayaTrail — GCP Detections & Guardrails
   ══════════════════════════════════════════ */

window.MayaTrail.platforms.gcp = window.MayaTrail.platforms.gcp || {};

window.MayaTrail.platforms.gcp.detections = {
  ruleCount: 156,
  formats: 'SIGMA \u00b7 Chronicle YARA-L \u00b7 BigQuery SQL',
  rules: [
    {
      title: 'SIGMA Rule \u2014 Suspicious Service Account Key Creation',
      code: 'title: GCP Service Account Key Creation by Non-Automation Principal\nstatus: experimental\ndescription: Detects creation of service account keys by human users, which may indicate persistence setup\nreferences:\n  - https://attack.mitre.org/techniques/T1098/\ntags:\n  - attack.persistence\n  - attack.t1098\nlogsource:\n  product: gcp\n  service: cloudaudit\ndetection:\n  selection:\n    protoPayload.methodName: google.iam.admin.v1.CreateServiceAccountKey\n  filter:\n    protoPayload.authenticationInfo.principalEmail|endswith:\n      - "@system.gserviceaccount.com"\n      - "gserviceaccount.com"\n  condition: selection and not filter\nfalsepositives:\n  - Legitimate key rotation by human admins\n  - Emergency break-glass procedures\nlevel: high'
    },
    {
      title: 'Chronicle YARA-L \u2014 Privilege Escalation via Role Binding',
      code: 'rule gcp_privilege_escalation_role_binding {\n  meta:\n    author = "MayaTrail Detection Engineering"\n    description = "Detects when a user grants themselves or others Owner/Editor role at project or org level"\n    severity = "CRITICAL"\n    mitre_attack_tactic = "Privilege Escalation"\n    mitre_attack_technique = "T1548.005"\n\n  events:\n    $iam_event.metadata.event_type = "AUDIT_LOG"\n    $iam_event.metadata.product_name = "Google Cloud IAM"\n    $iam_event.target.resource.attribute.labels["method"] = /SetIamPolicy/\n    $iam_event.security_result.action = "ALLOW"\n    (\n      $iam_event.target.resource.attribute.labels["role"] = "roles/owner" or\n      $iam_event.target.resource.attribute.labels["role"] = "roles/editor"\n    )\n\n  match:\n    $iam_event over 5m\n\n  outcome:\n    $risk_score = 90\n\n  condition:\n    $iam_event\n}'
    },
    {
      title: 'BigQuery SQL \u2014 Anomalous GCE Metadata Access Detection',
      code: 'SELECT\n  timestamp,\n  jsonPayload.connection.src_ip AS source_ip,\n  jsonPayload.connection.dest_ip AS dest_ip,\n  jsonPayload.connection.dest_port AS dest_port,\n  resource.labels.subnetwork_name AS subnet,\n  resource.labels.project_id AS project\nFROM\n  `project.dataset.compute_googleapis_com_vpc_flows_*`\nWHERE\n  _TABLE_SUFFIX >= FORMAT_DATE("%Y%m%d", DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY))\n  AND jsonPayload.connection.dest_ip = "169.254.169.254"\n  AND jsonPayload.connection.dest_port = 80\nGROUP BY 1, 2, 3, 4, 5, 6\nHAVING COUNT(*) > 50\nORDER BY timestamp DESC\nLIMIT 100\n-- High frequency metadata access may indicate SSRF or credential theft'
    }
  ]
};

window.MayaTrail.platforms.gcp.guardrails = {
  excluded: [
    'projects/prod-* (all production projects)',
    'gs://prod-data-* (production GCS buckets)',
    'Service accounts with roles/owner binding',
    'GKE clusters in production namespace',
    'Cloud SQL instances tagged env=production'
  ],
  schedule: 'Monday \u2013 Friday  |  02:00 \u2013 06:00 UTC  |  Auto-pause on SCC findings',
  scopeLimits: [
    'Maximum 5 concurrent API calls per emulation',
    'No modifications to Organization Policies',
    'GCE instances limited to e2-micro in sandbox project',
    'No IAM role changes at organization level',
    'Automatic rollback if Security Command Center CRITICAL finding detected'
  ]
};
