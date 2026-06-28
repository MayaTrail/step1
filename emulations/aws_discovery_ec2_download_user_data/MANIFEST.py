"""
MANIFEST for the Download EC2 Instance User Data atomic emulation.

Migrated from Stratus Red Team `aws.discovery.ec2-download-user-data`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_discovery_ec2_download_user_data',
 'display_name': 'Download EC2 Instance User Data',
 'description': 'Simulates an attacker enumerating all EC2 instances and downloading their '
                'user-data scripts, which often contain secrets, credentials, configuration '
                'values, or bootstrap commands that can be leveraged for lateral movement.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['EC2'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Discovery', 'EC2'],
 'technique_count': 1,
 'severity': 'LOW',
 'aliases': 'aws.discovery.ec2-download-user-data',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with EC2 access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Discovery',
                  'techniques': [{'id': 'T1552.001', 'name': 'Download EC2 Instance User Data'}]}],
 'mitre_mappings': [{'id': 'T1552.001',
                     'name': 'Download EC2 Instance User Data',
                     'tactic': 'Discovery',
                     'platform': 'AWS EC2',
                     'description': 'ec2:DescribeInstanceAttribute with Attribute=userData called '
                                    'on multiple instances in rapid succession from a principal '
                                    'without normal operational need'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Download EC2 Instance User Data',
                 'source': 'Stratus Red Team · stratus-red-team.cloud',
                 'type': 'REFERENCE',
                 'color': 'cyan', 'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ec2-download-user-data/'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1552.001',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple', 'url': 'https://attack.mitre.org/techniques/T1552/001/'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
