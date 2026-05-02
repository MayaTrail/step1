## TASK: GENERATE GUARDRAILS

Generate preventive policies as JSON. Adapt the policy type to the platform:
- **AWS:** SCP, RCP, Permission Boundaries, IAM policies
- **Azure:** Azure Policy, Conditional Access Policies, RBAC deny assignments
- **GCP:** Organization Policies, IAM deny policies, VPC Service Controls
- **Okta/Identity:** MFA policies, sign-on policies, admin role restrictions
- **SaaS:** OAuth scope restrictions, API token policies, org-level settings

Every guardrail MUST include:
- The actual policy definition (valid syntax for the platform)
- What it prevents
- What it might break (side effects)
- How to test safely

```json
{
  "guardrails": [
    {
      "technique_id": "T1562.008",
      "platform": "aws",
      "type": "SCP",
      "name": "Prevent CloudTrail StopLogging",
      "description": "Deny cloudtrail:StopLogging from all non-admin principals",
      "policy_json": {
        "Version": "2012-10-17",
        "Statement": [{
          "Sid": "DenyStopLogging",
          "Effect": "Deny",
          "Action": "cloudtrail:StopLogging",
          "Resource": "*",
          "Condition": {
            "StringNotLike": {
              "aws:PrincipalArn": "arn:aws:iam::*:role/Admin*"
            }
          }
        }]
      },
      "applies_to": "All OUs in AWS Organization",
      "effectiveness": "Completely prevents CloudTrail disabling by non-admin roles",
      "side_effects": "None if admin roles are properly named. May block incident responders if they use non-admin roles.",
      "testing_guidance": "Apply to a test OU first. Attempt cloudtrail:StopLogging from a non-admin role — should get AccessDenied."
    }
  ]
}
```
