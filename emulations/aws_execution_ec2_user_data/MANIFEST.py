"""
MANIFEST for the Execute Malicious Code via EC2 User Data atomic emulation.

Migrated from Stratus Red Team `aws.execution.ec2-user-data`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_execution_ec2_user_data',
 'display_name': 'Execute Malicious Code via EC2 User Data',
 'description': 'Simulates an attacker stopping an EC2 instance, replacing its user-data script '
                'with a malicious shell script (C2 callback), then restarting it — causing the '
                'malicious code to execute as root on the next boot.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['EC2'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Execution', 'EC2'],
 'technique_count': 1,
 'severity': 'MEDIUM',
 'aliases': 'aws.execution.ec2-user-data',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with EC2 access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Execution',
                  'techniques': [{'id': 'T1059',
                                  'name': 'Execute Malicious Code via EC2 User Data'}]}],
 'mitre_mappings': [{'id': 'T1059',
                     'name': 'Execute Malicious Code via EC2 User Data',
                     'tactic': 'Execution',
                     'platform': 'AWS EC2',
                     'description': 'ec2:ModifyInstanceAttribute with attribute=userData on a '
                                    'stopped instance, especially when followed by '
                                    'ec2:StartInstances'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Execute Malicious Code via EC2 User Data',
                 'source': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.ec2-user-data/',
                 'type': 'REFERENCE',
                 'color': 'cyan'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1059',
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
