"""
MANIFEST for the Backdoor Lambda Function via Resource Policy atomic emulation.

Migrated from Stratus Red Team `aws.persistence.lambda-backdoor-function`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_persistence_lambda_backdoor_function',
 'display_name': 'Backdoor Lambda Function via Resource Policy',
 'description': 'Simulates an attacker adding a resource-based policy to an existing Lambda '
                'function, granting an external AWS account (193672423079) the ability to invoke '
                'it — establishing a persistent execution backdoor.',
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
 'aliases': 'aws.persistence.lambda-backdoor-function',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with Lambda access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Persistence',
                  'techniques': [{'id': 'T1098',
                                  'name': 'Backdoor Lambda Function via Resource Policy'}]}],
 'mitre_mappings': [{'id': 'T1098',
                     'name': 'Backdoor Lambda Function via Resource Policy',
                     'tactic': 'Persistence',
                     'platform': 'AWS Lambda',
                     'description': 'lambda:AddPermission granting cross-account or wildcard '
                                    'invoke access to a Lambda function'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Backdoor Lambda Function via Resource Policy',
                 'source': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-backdoor-function/',
                 'type': 'REFERENCE',
                 'color': 'cyan'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1098',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
