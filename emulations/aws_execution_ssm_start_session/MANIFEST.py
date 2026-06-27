"""
MANIFEST for the Open SSM Sessions to Multiple EC2 Instances atomic emulation.

Migrated from Stratus Red Team `aws.execution.ssm-start-session`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_execution_ssm_start_session',
 'display_name': 'Open SSM Sessions to Multiple EC2 Instances',
 'description': 'Simulates an attacker opening SSM interactive sessions to multiple EC2 instances '
                'in rapid succession, using ssm:StartSession as an alternative to SSH that leaves '
                'fewer network traces.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['SSM'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Execution', 'SSM'],
 'technique_count': 1,
 'severity': 'MEDIUM',
 'aliases': 'aws.execution.ssm-start-session',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with SSM access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Execution',
                  'techniques': [{'id': 'T1021.004',
                                  'name': 'Open SSM Sessions to Multiple EC2 Instances'}]}],
 'mitre_mappings': [{'id': 'T1021.004',
                     'name': 'Open SSM Sessions to Multiple EC2 Instances',
                     'tactic': 'Execution',
                     'platform': 'AWS SSM',
                     'description': 'ssm:StartSession called on multiple instances in rapid '
                                    'succession from unexpected principals — especially combined '
                                    'with ssm:TerminateSession'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Open SSM Sessions to Multiple EC2 Instances',
                 'source': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.ssm-start-session/',
                 'type': 'REFERENCE',
                 'color': 'cyan'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1021.004',
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
