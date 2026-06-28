"""
MANIFEST for the Overwrite Lambda Function Code atomic emulation.

Migrated from Stratus Red Team `aws.persistence.lambda-overwrite-code`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_persistence_lambda_overwrite_code',
 'display_name': 'Overwrite Lambda Function Code',
 'description': "Simulates an attacker overwriting a Lambda function's code with a malicious "
                'payload using lambda:UpdateFunctionCode, replacing legitimate business logic with '
                'attacker-controlled code.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['Lambda'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Persistence', 'Lambda'],
 'technique_count': 1,
 'severity': 'MEDIUM',
 'aliases': 'aws.persistence.lambda-overwrite-code',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with Lambda access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Persistence',
                  'techniques': [{'id': 'T1525', 'name': 'Overwrite Lambda Function Code'}]}],
 'mitre_mappings': [{'id': 'T1525',
                     'name': 'Overwrite Lambda Function Code',
                     'tactic': 'Persistence',
                     'platform': 'AWS Lambda',
                     'description': 'lambda:UpdateFunctionCode from an unexpected principal or at '
                                    'an unusual time — especially if the update replaces '
                                    'legitimate code'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Overwrite Lambda Function Code',
                 'source': 'Stratus Red Team · stratus-red-team.cloud',
                 'type': 'REFERENCE',
                 'color': 'cyan', 'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-overwrite-code/'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1525',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple', 'url': 'https://attack.mitre.org/techniques/T1525/'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
