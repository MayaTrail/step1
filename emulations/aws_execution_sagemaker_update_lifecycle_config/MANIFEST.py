"""
MANIFEST for the Malicious Script Execution via SageMaker Lifecycle Config atomic emulation.

Migrated from Stratus Red Team `aws.execution.sagemaker-update-lifecycle-config`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_execution_sagemaker_update_lifecycle_config',
 'display_name': 'Malicious Script Execution via SageMaker Lifecycle Config',
 'description': 'Simulates an attacker backdooring a SageMaker Notebook Instance lifecycle '
                'configuration with a malicious OnStart shell script that downloads and executes a '
                'payload on every notebook restart.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['SageMaker'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Execution', 'SageMaker'],
 'technique_count': 1,
 'severity': 'MEDIUM',
 'aliases': 'aws.execution.sagemaker-update-lifecycle-config',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with SageMaker access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Execution',
                  'techniques': [{'id': 'T1059',
                                  'name': 'Malicious Script Execution via SageMaker Lifecycle '
                                          'Config'}]}],
 'mitre_mappings': [{'id': 'T1059',
                     'name': 'Malicious Script Execution via SageMaker Lifecycle Config',
                     'tactic': 'Execution',
                     'platform': 'AWS SageMaker',
                     'description': 'CloudTrail sagemaker:UpdateNotebookInstanceLifecycleConfig '
                                    'with a base64-encoded OnStart script from an unexpected '
                                    'principal'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Malicious Script Execution via SageMaker Lifecycle '
                          'Config',
                 'source': 'Stratus Red Team · stratus-red-team.cloud',
                 'type': 'REFERENCE',
                 'color': 'cyan', 'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.sagemaker-update-lifecycle-config/'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1059',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple', 'url': 'https://attack.mitre.org/techniques/T1059/'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
