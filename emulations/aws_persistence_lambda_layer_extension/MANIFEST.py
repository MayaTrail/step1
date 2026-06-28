"""
MANIFEST for the Persist via Lambda Layer atomic emulation.

Migrated from Stratus Red Team `aws.persistence.lambda-layer-extension`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_persistence_lambda_layer_extension',
 'display_name': 'Persist via Lambda Layer',
 'description': 'Simulates an attacker publishing a malicious Lambda layer and attaching it to a '
                'legitimate function, injecting code that executes alongside every function '
                "invocation without modifying the function's own code.",
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
 'aliases': 'aws.persistence.lambda-layer-extension',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with Lambda access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Persistence',
                  'techniques': [{'id': 'T1525', 'name': 'Persist via Lambda Layer'}]}],
 'mitre_mappings': [{'id': 'T1525',
                     'name': 'Persist via Lambda Layer',
                     'tactic': 'Persistence',
                     'platform': 'AWS Lambda',
                     'description': 'lambda:PublishLayerVersion followed by '
                                    'lambda:UpdateFunctionConfiguration adding an unexpected layer '
                                    '— especially a newly created layer from an unknown '
                                    'principal'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Persist via Lambda Layer',
                 'source': 'Stratus Red Team · stratus-red-team.cloud',
                 'type': 'REFERENCE',
                 'color': 'cyan', 'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-layer-extension/'},
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
