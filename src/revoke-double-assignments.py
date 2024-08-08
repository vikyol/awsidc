import boto3

def get_identity_store_id(instance_arn):
    sso_client = boto3.client('sso-admin')
    
    # Retrieve the Identity Store ID using the instance ARN
    response = sso_client.list_instances()
    for instance in response['Instances']:
        if instance['InstanceArn'] == instance_arn:
            return instance['IdentityStoreId']
    
    raise ValueError(f"No Identity Store ID found for instance ARN: {instance_arn}")


def get_user_name(identity_store_id, user_id):
    identitystore_client = boto3.client('identitystore')
    try:
        user = identitystore_client.describe_user(
            IdentityStoreId=identity_store_id,
            UserId=user_id
        )
        return user['UserName']
    except identitystore_client.exceptions.ResourceNotFoundException:
        return ""

def revoke_direct_assignments_from_group_members(instance_arn, account_id, group_id):
    """
    Revokes all direct permission set assignments from the members of a specified group
    in AWS Identity Center (formerly AWS SSO). The function first retrieves the members of the group,
    then checks their direct assignments for each permission set assigned to the group, and revokes them.

    Args:
        instance_arn (str): The ARN of the AWS Identity Center instance.
        account_id (str): The AWS account ID.
        group_id (str): The ID of the group from which to revoke direct member assignments.

    Returns:
        None
    """
    sso_client = boto3.client('sso-admin')
    identitystore_client = boto3.client('identitystore')
    store_id = get_identity_store_id(instance_arn)

    # Step 1: Get all members of the group
    group_members = []
    paginator = identitystore_client.get_paginator('list_group_memberships')
    for page in paginator.paginate(GroupId=group_id, IdentityStoreId=store_id):
        for membership in page['GroupMemberships']:
            group_members.append(membership['MemberId'])

    # Step 2: Revoke any direct assignments from group members
    for member_id in group_members:
        paginator = sso_client.get_paginator('list_account_assignments_for_principal')
        for page in paginator.paginate(
            InstanceArn=instance_arn,
            Filter={
                'AccountId':account_id
            },
            PrincipalType='USER',
            PrincipalId=member_id['UserId']
        ):
            for assignment in page['AccountAssignments']:
                if assignment['PrincipalType'] == 'USER':
                    # Revoke the direct assignment
                    sso_client.delete_account_assignment(
                        InstanceArn=instance_arn,
                        TargetId=account_id,
                        TargetType='AWS_ACCOUNT',
                        PrincipalType='USER',
                        PrincipalId=member_id['UserId'],
                        PermissionSetArn=assignment['PermissionSetArn']
                    )
                    print(f"Revoked permission set {assignment['PermissionSetArn']} from user {get_user_name(store_id, member_id['UserId'])}")
