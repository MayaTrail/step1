"""
MANIFEST for the Execute Commands on EC2 Instances via SSM atomic emulation.

Migrated from Stratus Red Team `aws.execution.ssm-send-command`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_execution_ssm_send_command',
 'display_name': 'Execute Commands on EC2 Instances via SSM',
 'description': 'Simulates an attacker using SSM SendCommand to execute arbitrary shell commands '
                'across multiple EC2 instances using the AWS-RunShellScript document — no SSH or '
                'direct network access required.',
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
 'aliases': 'aws.execution.ssm-send-command',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with SSM access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Execution',
                  'techniques': [{'id': 'T1651',
                                  'name': 'Execute Commands on EC2 Instances via SSM'}]}],
 'mitre_mappings': [{'id': 'T1651',
                     'name': 'Execute Commands on EC2 Instances via SSM',
                     'tactic': 'Execution',
                     'platform': 'AWS SSM',
                     'description': 'ssm:SendCommand in CloudTrail, especially with '
                                    'AWS-RunShellScript document targeting multiple instances'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Execute Commands on EC2 Instances via SSM',
                 'source': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.ssm-send-command/',
                 'type': 'REFERENCE',
                 'color': 'cyan'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1651',
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
