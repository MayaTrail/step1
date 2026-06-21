/**
 * Canonical attack-surface taxonomy for the Platform Overview.
 *
 * Defines the *universe* of cloud services grouped by category, so the Attack
 * Surface Coverage section can show which services the platform's emulations
 * exercise (covered) versus which exist but aren't yet exercised (not covered).
 *
 * Emulations declare a flat `services` list in their MANIFEST; the categorisation
 * lives here in one place rather than being authored per emulation. Service names
 * must match the MANIFEST `services` entries exactly (e.g. "IAM", "EC2").
 *
 * AWS only for now — keyed by platform so other platforms can add their own
 * taxonomy as content arrives.
 */
import type { PlatformId } from '@/types'

export interface SurfaceCategory {
  /** Display name, e.g. "Identity". */
  name: string
  /** Canonical services in this category (the universe to measure coverage against). */
  services: string[]
}

export const ATTACK_SURFACE: Partial<Record<PlatformId, SurfaceCategory[]>> = {
  aws: [
    { name: 'Identity', services: ['IAM', 'STS', 'Cognito'] },
    { name: 'Compute', services: ['EC2', 'Lambda'] },
    { name: 'Storage', services: ['S3', 'Secrets Manager', 'EBS'] },
    { name: 'Containers', services: ['ECS', 'EKS', 'ECR'] },
    { name: 'Networking', services: ['VPC', 'ELB', 'Route53'] },
    { name: 'Databases', services: ['RDS', 'DynamoDB'] },
    { name: 'Management', services: ['CloudTrail', 'CloudFormation'] },
  ],
}

/** Return the taxonomy for a platform, or an empty list if none is defined. */
export function attackSurfaceFor(platform: PlatformId): SurfaceCategory[] {
  return ATTACK_SURFACE[platform] ?? []
}
