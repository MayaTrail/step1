"""
Tenant credential resolution.

Every MayaTrail task that touches a customer account does it by assuming a role
that customer created, never with stored keys. Two roles exist: the emulation
role, which performs the writes an emulation needs, and the Scout audit role,
which is read-only and exists so IAM-graph scanning does not widen the
emulation grant. Both come through assume_role_arn(); the session name is the
caller's to choose, so a tenant reading their own CloudTrail can tell a
read-only scan apart from an emulation.
"""

import boto3

# One hour: long enough for a full emulation deploy and attack cycle, and for
# a GAAD collection on a large account, without minting credentials that
# outlive the task that holds them.
DEFAULT_SESSION_SECONDS = 3600

# The 900-second AWS minimum, for connect-time verification. AssumeRole is
# rejected outright when DurationSeconds exceeds the role's MaxSessionDuration,
# so asking for the shortest possible session is what makes verification work
# against a role whose owner capped it — and a security team provisioning a
# read-only auditor role is exactly the owner who caps it. AWSConnectorView
# has always used 900 here for this reason; nothing about verification needs
# a credential that outlives the request.
VERIFY_SESSION_SECONDS = 900


def assume_role_arn(
    role_arn: str,
    session_name: str,
    duration_seconds: int = DEFAULT_SESSION_SECONDS,
) -> dict[str, str]:
    """
    Assume a tenant role via STS and return temporary credentials.

    Credentials are never stored in the database — they are generated per task
    invocation and discarded when the task completes.

    Args:
        role_arn: The tenant role to assume.
        session_name: STS session name, which appears in the tenant's
            CloudTrail. Identify the caller here.
        duration_seconds: Session lifetime. The default suits a task that
            holds the credentials for its whole run; pass
            VERIFY_SESSION_SECONDS for a single connect-time call, so a role
            with a short MaxSessionDuration still verifies.

    Returns:
        Dict with keys: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
        AWS_SESSION_TOKEN.

    Raises:
        botocore.exceptions.ClientError: if the role cannot be assumed, or if
            duration_seconds exceeds the role's MaxSessionDuration.
    """
    sts = boto3.client("sts")
    assumed = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=duration_seconds,
    )
    creds = assumed["Credentials"]
    return {
        "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
        "AWS_SESSION_TOKEN": creds["SessionToken"],
    }


def probe_account_authorization_details(creds: dict[str, str]) -> None:
    """
    Confirm a set of credentials can actually read account-wide IAM.

    Assumability is not the question the Scout connection needs answered. A
    role can be assumable and still unable to read IAM, and Scout responds to
    that by silently enumerating only the caller's own identity — which
    produces a scan with no findings, which reads as a clean account. Probing
    at connect time puts that failure in front of the person pasting the ARN,
    who can fix it.

    Args:
        creds: The dict returned by assume_role_arn().

    Returns:
        None on success.

    Raises:
        botocore.exceptions.ClientError: if the role cannot call
            iam:GetAccountAuthorizationDetails.
    """
    iam = boto3.client(
        "iam",
        aws_access_key_id=creds["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=creds["AWS_SECRET_ACCESS_KEY"],
        aws_session_token=creds["AWS_SESSION_TOKEN"],
    )
    # One user is enough to prove the permission; Filter keeps a large account
    # from paying for a page of everything just to answer yes or no.
    iam.get_account_authorization_details(Filter=["User"], MaxItems=1)
