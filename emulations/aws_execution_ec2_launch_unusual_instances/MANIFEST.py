"""
MANIFEST for the Launch Unusual EC2 Instance Types for Cryptomining atomic emulation.

Migrated from Stratus Red Team `aws.execution.ec2-launch-unusual-instances`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_execution_ec2_launch_unusual_instances',
 'display_name': 'Launch Unusual EC2 Instance Types for Cryptomining',
 'description': 'Simulates an attacker launching GPU or compute-optimized EC2 instances (p2.xlarge '
                'or similar) associated with cryptocurrency mining, triggering GuardDuty findings '
                'and unexpected cost spikes.',
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
 'aliases': 'aws.execution.ec2-launch-unusual-instances',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with EC2 access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Execution',
                  'techniques': [{'id': 'T1204.003',
                                  'name': 'Launch Unusual EC2 Instance Types for Cryptomining'}]}],
 'mitre_mappings': [{'id': 'T1204.003',
                     'name': 'Launch Unusual EC2 Instance Types for Cryptomining',
                     'tactic': 'Execution',
                     'platform': 'AWS EC2',
                     'description': 'ec2:RunInstances with unusual instance types (GPU, '
                                    'high-compute) not in baseline; GuardDuty '
                                    'CryptoCurrency:EC2/BitcoinTool.B if mining traffic detected'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Launch Unusual EC2 Instance Types for Cryptomining',
                 'source': 'Stratus Red Team · stratus-red-team.cloud',
                 'type': 'REFERENCE',
                 'color': 'cyan', 'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.ec2-launch-unusual-instances/'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1204.003',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple', 'url': 'https://attack.mitre.org/techniques/T1204/003/'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
