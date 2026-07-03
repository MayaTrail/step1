/**
 * AWS service reference catalogue.
 *
 * The emulations touch a bounded set of AWS services. Their MANIFEST
 * `mitre_mappings[].platform` strings are free-form and composite
 * (e.g. "AWS S3 / Secrets Manager", "Container / EC2", "AWS EC2 IMDS"), so
 * `servicesForPlatform` resolves those strings to the canonical entries below.
 * Summaries are factual service descriptions, not per-run data.
 */

export interface AwsService {
  label: string
  category: string
  summary: string
}

interface CatalogEntry extends AwsService {
  /** Lowercase substrings matched against a platform string. */
  aliases: string[]
}

// Order matters: more specific entries (EC2 IMDS) precede generic ones (EC2)
// so the resolver can drop the generic when the specific already matched.
const CATALOG: CatalogEntry[] = [
  { label: 'IAM', category: 'Identity', aliases: ['iam'],
    summary: 'Identity and Access Management — the users, roles, and policies that govern every AWS action.' },
  { label: 'STS', category: 'Identity', aliases: ['sts'],
    summary: 'Security Token Service — issues the temporary, assumable credentials behind role assumption.' },
  { label: 'EC2 IMDS', category: 'Compute', aliases: ['imds'],
    summary: 'Instance Metadata Service — serves an instance role’s credentials to code running on the instance.' },
  { label: 'EC2', category: 'Compute', aliases: ['ec2'],
    summary: 'Elastic Compute Cloud — virtual machines and the instance roles attached to them.' },
  { label: 'Lambda', category: 'Compute', aliases: ['lambda'],
    summary: 'Serverless functions — a common execution and persistence foothold via the function role.' },
  { label: 'ECS', category: 'Compute', aliases: ['ecs', 'fargate'],
    summary: 'Elastic Container Service (including Fargate) — runs containers under task execution roles.' },
  { label: 'SageMaker', category: 'Compute', aliases: ['sagemaker'],
    summary: 'Managed ML notebooks and compute — abused for cryptomining and arbitrary code execution.' },
  { label: 'S3', category: 'Storage', aliases: ['s3'],
    summary: 'Object storage — a frequent target for data discovery and exfiltration.' },
  { label: 'Secrets Manager', category: 'Storage', aliases: ['secrets manager', 'secretsmanager'],
    summary: 'Stores and rotates secrets — a prime credential-theft target.' },
  { label: 'CloudTrail', category: 'Logging', aliases: ['cloudtrail'],
    summary: 'Records the account’s API activity — attackers disable it to blind detection.' },
  { label: 'GuardDuty', category: 'Security', aliases: ['guardduty'],
    summary: 'Threat-detection service — attackers probe or attempt to evade its findings.' },
  { label: 'SES', category: 'Messaging', aliases: ['ses'],
    summary: 'Simple Email Service — abused to send phishing or spam from a trusted domain.' },
  { label: 'Route 53', category: 'Networking', aliases: ['route53', 'route 53'],
    summary: 'DNS service — abused for domain hijacking and staging attacker infrastructure.' },
  { label: 'CodeCommit', category: 'Developer', aliases: ['codecommit'],
    summary: 'Managed Git repositories — abused to implant malicious build sources.' },
  { label: 'CodeBuild', category: 'Developer', aliases: ['codebuild'],
    summary: 'Managed build service — abused to run attacker code inside CI.' },
  { label: 'Amplify', category: 'Developer', aliases: ['amplify'],
    summary: 'App hosting and build service — abused to acquire callback subdomains and run builds.' },
]

/**
 * Resolve the AWS services named in a MANIFEST platform string.
 *
 * Scans for each catalogue entry's aliases, so composite strings resolve to
 * multiple services. When the specific EC2 IMDS entry matches, the generic EC2
 * entry is dropped to avoid redundancy. Returns [] when nothing matches (e.g.
 * "AWS multi-service"); callers fall back to the raw platform label.
 */
export function servicesForPlatform(platform: string): AwsService[] {
  const haystack = platform.toLowerCase()
  const matched = CATALOG.filter((entry) => entry.aliases.some((alias) => haystack.includes(alias)))
  const hasImds = matched.some((entry) => entry.label === 'EC2 IMDS')
  return matched
    .filter((entry) => !(hasImds && entry.label === 'EC2'))
    .map(({ label, category, summary }) => ({ label, category, summary }))
}
