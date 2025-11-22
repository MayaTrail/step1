# import pulumi and pulumi_aws
import os
import pulumi
import pulumi_aws as aws
from simulations import attach_role_policy

def create_dummies(type: str) -> aws.iam.User | aws.iam.Role | ValueError:
    """
    create IAM user and role with no policies attached
    """
    if type.lower() == "user":
        # create an aws resource (iam user)
        user_object = aws.iam.User("mayatrail-test-user",
            name="mayatrail-test",
            path="/",
            tags={
                "test-key": "test-value",
            }
        )
        return user_object
    elif type.lower() == "role":
        # assume role policy document assings to the trust relationship of a role
        # keys naming convention should be strict as per AWS trust relationship document
        role_object = aws.iam.Role("mayatrail-test-role",
            assume_role_policy=
            """
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": "arn:aws:iam::104266513052:user/mayatrail-test"
                            },
                            "Action": "sts:AssumeRole"
                        }
                    ]
                }
            """,
            tags = {"Environment": "dev"},
            description = "this role has been created using pulumi",
            max_session_duration = 3600 # session will only be up for 5 min.
        )   
        return role_object
    else:
        raise ValueError("Invalid type\nValid types are 'user' and 'role'")

def attach_policies(type: str, obj: aws.iam.User | aws.iam.Role, policy_statements: list[dict]) -> aws.iam.UserPolicyAttachment | aws.iam.RolePolicyAttachment | ValueError:
    """
    attach policies to the user or role
    """
    if policy_statements is None:
        raise ValueError("Policy statements is required") 

    # get_policy_document is a data source function, it doesn't create an resource on AWS
    policy_document = aws.iam.get_policy_document(
        statements=policy_statements
    )
    # create policy on aws and get arn
    policy_object = aws.iam.Policy("mayatrail-role-policy" if type=="role" else "mayatrail-user-policy",
        policy=policy_document.json
    )

    if type.lower() == "user":
        # attach policy to user
        aws.iam.UserPolicyAttachment("mayatrail-test-user-policy-attachment",
            policy_arn=policy_object.arn,
            user=obj.name
        )
    elif type.lower() == "role":
        # attach policy to role
        aws.iam.RolePolicyAttachment("mayatrail-test-role-policy-attachment",
            policy_arn=policy_object.arn,
            role=obj.name
        )
    else:
        ValueError("Invalid type\nValid types are 'user' and 'role'")

# create dummy user and role
user_object = create_dummies(type="user")
role_object = create_dummies(type="role")

# attach policies to user and role
# user - IAM full access
# role - AttachRolePolicy

# keys naming convention here shouldn't be strict and can be used in lowercase.
attach_policies(type="user", obj=user_object, policy_statements=[
    {
        "effect": "Allow",
        "actions": ["iam:*"],
        "resources": ["*"]
    },
    {
        "effect": "Allow",
        "actions": ["sts:AssumeRole"],
        "resources": role_object.arn
    }
])

attach_policies(type="role", obj=role_object, policy_statements=[
    {
        "effect": "Allow",
        "actions": ["iam:AttachRolePolicy"],
        "resources": ["*"]
    }
])

# Get access key and secret of a user and assign them to environment variable
access_key_obj = aws.iam.AccessKey("mayatrail-test-access-key",
    user=user_object.name
)

pulumi.export("username", user_object.name)
pulumi.export("role_arn", role_object.arn)

def setup_and_run_simulation(args):
    access_key_id, secret_key, role_arn, role_name = args
    
    os.environ.update({
        "AWS_ACCESS_KEY_ID": access_key_id,
        "AWS_SECRET_ACCESS_KEY": secret_key
    })
    role_creds = attach_role_policy.get_role_creds(role_arn=role_arn)
    # re-assign the role creds in os.environ
    os.environ.update({
        "AWS_ACCESS_KEY_ID": role_creds["AWS_ACCESS_KEY_ID"],
        "AWS_SECRET_ACCESS_KEY": role_creds["AWS_SECRET_ACCESS_KEY"],
        "AWS_SESSION_TOKEN": role_creds["AWS_SESSION_TOKEN"]
    })
    attach_role_policy.attach_policy(role_name=role_name)

# output.apply() to unwrap pulumi output values | normal os.environ won't work
# access_key_obj contain async values not normal plain strings
role_creds = pulumi.Output.all(
    access_key_obj.id, 
    access_key_obj.secret, 
    role_object.arn,
    role_object.name
).apply(setup_and_run_simulation)

pulumi.export("role_credentials", role_creds)