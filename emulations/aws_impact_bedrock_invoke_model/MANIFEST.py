"""
MANIFEST for the Invoke Bedrock Model for Resource Exhaustion atomic emulation.

Migrated from Stratus Red Team `aws.impact.bedrock-invoke-model`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_impact_bedrock_invoke_model',
 'display_name': 'Invoke Bedrock Model for Resource Exhaustion',
 'description': 'Simulates an attacker invoking Amazon Bedrock foundation models in a loop to '
                'exhaust quota and generate unexpected costs — analogous to cryptomining but '
                'targeting LLM inference billing.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['Bedrock'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Impact', 'Bedrock'],
 'technique_count': 1,
 'severity': 'HIGH',
 'aliases': 'aws.impact.bedrock-invoke-model',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with Bedrock access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Impact',
                  'techniques': [{'id': 'T1496',
                                  'name': 'Invoke Bedrock Model for Resource Exhaustion'}]}],
 'mitre_mappings': [{'id': 'T1496',
                     'name': 'Invoke Bedrock Model for Resource Exhaustion',
                     'tactic': 'Impact',
                     'platform': 'AWS Bedrock',
                     'description': 'bedrock:InvokeModel called at high volume or from an '
                                    'unexpected principal; sudden spike in Bedrock spend in cost '
                                    'explorer'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Invoke Bedrock Model for Resource Exhaustion',
                 'source': 'Stratus Red Team · stratus-red-team.cloud',
                 'type': 'REFERENCE',
                 'color': 'cyan', 'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.bedrock-invoke-model/'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1496',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple', 'url': 'https://attack.mitre.org/techniques/T1496/'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
