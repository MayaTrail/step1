import type { Guardrails } from '@/types'

export const awsGuardrails: Guardrails = {
  excluded: [
    'prod-* (all production buckets)',
    'arn:aws:iam::*:role/ProductionRole',
    'RDS instances tagged Environment=Production',
    'arn:aws:lambda:*:*:function:prod-*',
    'arn:aws:eks:*:*:cluster/production-*',
  ],
  schedule: 'Monday – Friday  |  02:00 – 06:00 UTC  |  Auto-pause on incidents',
  scopeLimits: [
    'Maximum 10 concurrent API calls per emulation',
    'No data modification in S3 buckets tagged critical=true',
    'EC2 instance launches limited to t3.micro in sandbox VPC',
    'No IAM policy changes in production accounts',
    'Automatic rollback if GuardDuty CRITICAL finding detected',
  ],
}
