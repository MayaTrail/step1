"""
MANIFEST for the Enumerate AWS Environment from EC2 Instance atomic emulation.

Migrated from Stratus Red Team `aws.discovery.ec2-enumerate-from-instance`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_discovery_ec2_enumerate_from_instance',
 'display_name': 'Enumerate AWS Environment from EC2 Instance',
 'description': 'Simulates an attacker using SSM to run a series of AWS CLI discovery commands '
                'from a compromised EC2 instance, using its attached IAM role to enumerate VPCs, '
                'instances, buckets, and IAM users.',
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
 'aliases': 'aws.discovery.ec2-enumerate-from-instance',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with EC2 access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Discovery',
                  'techniques': [{'id': 'T1580',
                                  'name': 'Enumerate AWS Environment from EC2 Instance'}]}],
 'mitre_mappings': [{'id': 'T1580',
                     'name': 'Enumerate AWS Environment from EC2 Instance',
                     'tactic': 'Discovery',
                     'platform': 'AWS EC2',
                     'description': 'Rapid ec2:Describe*, s3:ListBuckets, iam:ListUsers called '
                                    'from an EC2 instance role — especially if the instance is not '
                                    'a known bastion or operations server'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Enumerate AWS Environment from EC2 Instance',
                 'source': 'Stratus Red Team · stratus-red-team.cloud',
                 'type': 'REFERENCE',
                 'color': 'cyan', 'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ec2-enumerate-from-instance/'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1580',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple', 'url': 'https://attack.mitre.org/techniques/T1580/'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
