# Detection Note: T1685.002 (Delete Route53 Resolver Query Log Config)

**Signal:** `route53resolver:DeleteResolverQueryLogConfig` or
`route53resolver:DisassociateResolverQueryLogConfig` outside the IaC destroy
pipeline.

**Include the disassociate.** Deleting the config and detaching it from the VPC
produce the same blind spot. An attacker only needs
`DisassociateResolverQueryLogConfig` — it leaves the config object intact (so a
"does the config still exist" check passes) while DNS queries from the target
VPC stop being logged. Rules that only watch the delete miss this.

## Field shape

```
DeleteResolverQueryLogConfig        requestParameters.resolverQueryLogConfigId
DisassociateResolverQueryLogConfig  requestParameters.resolverQueryLogConfigId
                                    requestParameters.resourceId  (the VPC)
```

The delete event does **not** name the VPCs that were associated — only the
config id. To enumerate impact, correlate with prior
`AssociateResolverQueryLogConfig` events or a Config snapshot.

## The visibility gap this opens

DNS query logging is the primary signal for:

- DNS-tunnelled C2 and exfiltration (high query volume, long TXT records,
  encoded subdomains)
- Lookups to newly-registered or known-bad domains
- Beaconing cadence to a resolver

With it gone for a VPC, those detections are blind until the config is
recreated and re-associated.

## Response

1. Recreate and re-associate the query log config immediately.
2. Treat the gap as unmonitored for DNS; pull VPC Flow Logs and any host
   resolver logs for that window as a partial substitute.
3. Revoke the acting principal's sessions and review its other recent activity.

**MITRE:** T1685.002 (*Disable or Modify Tools: Disable or Modify Cloud Log*).
**Severity:** manifest MEDIUM; IR view HIGH when paired with other activity.
**GuardDuty:** no finding type for the deletion itself.
