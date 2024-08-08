import boto3
from botocore.exceptions import ClientError
import json
from users import *
from utils import *


def get_account_name(account_id):
    """
    Retrieves the name of an AWS account given its account ID.
    
    Args:
    - account_id (str): The AWS account ID.
    
    Returns:
    - str: The name of the AWS account, or None if not found.
    """
    # Initialize a session using the default profile or environment variables
    client = boto3.client('organizations')
    
    try:
        # Describe the account using the provided account ID
        response = client.describe_account(AccountId=account_id)
        
        # Extract the account name from the response
        account_name = response['Account']['Name']
        return account_name
    
    except client.exceptions.AccountNotFoundException:
        print(f"Account with ID {account_id} not found.")
        return None
    except Exception as e:
        print(f"An error occurred while fetching the account name: {e}")
        return None


def list_permission_sets_for_account(instance_arn, account_id):
    """
    Retrieves a list of detailed permission set objects for a given AWS Identity Center (formerly AWS SSO) instance 
    and AWS account. Each permission set object includes information such as the Permission Set ARN, name, 
    and description.

    Args:
        instance_arn (str): The Amazon Resource Name (ARN) of the AWS Identity Center instance.
        account_id (str): The AWS account ID for which to retrieve the permission sets.

    Returns:
        list: A list of dictionaries where each dictionary represents a detailed permission set object.
              Each dictionary typically contains keys like 'PermissionSetArn', 'Name', 'Description', etc.

    Example:
        >>> list_permission_sets_for_account('arn:aws:sso:::instance/ssoins-1234567890abcdef', '123456789012')
        [
            {
                'PermissionSetArn': 'arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-abc123def456ghi789',
                'Name': 'AdministratorAccess',
                'Description': 'Provides full access to AWS services'
            },
            {
                'PermissionSetArn': 'arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-xyz987uvw654rst321',
                'Name': 'ReadOnlyAccess',
                'Description': 'Provides read-only access to AWS services'
            }
        ]
    """    
    sso_client = boto3.client('sso-admin')

    # List all permission sets for the instance
    permission_sets = []
    paginator = sso_client.get_paginator('list_permission_sets')
    for page in paginator.paginate(InstanceArn=instance_arn):
        permission_sets.extend(page['PermissionSets'])

    # Prepare a list to hold detailed permission sets with their assignments
    detailed_permission_sets = []

    # Loop through each permission set and retrieve its account assignments
    for permission_set_arn in permission_sets:
        paginator = sso_client.get_paginator('list_account_assignments')
        for page in paginator.paginate(
            InstanceArn=instance_arn,
            AccountId=account_id,
            PermissionSetArn=permission_set_arn
        ):
            for assignment in page['AccountAssignments']:
                # Describe the permission set to get its details
                response = sso_client.describe_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn
                )

                permission_set_details = response['PermissionSet']
                permission_set_details['Assignments'] = []

                # Add the assignment details (user or group)
                permission_set_details['Assignments'].append({
                    'PrincipalName': get_principal_name(get_identity_store_id(instance_arn), assignment['PrincipalId'], assignment['PrincipalType']),
                    'PrincipalType': assignment['PrincipalType'],
                    'PrincipalId': assignment['PrincipalId'],
                    'AccountId': assignment['AccountId']
                })

                detailed_permission_sets.append(permission_set_details)

    return detailed_permission_sets


def get_permission_sets(instance_arn):
    """
    Retrieves a list of all permission sets in the AWS Identity Center instance.

    Args:
        instance_arn (str): The Amazon Resource Name (ARN) of the AWS Identity Center instance.

    Returns:
        list: A list of dictionaries where each dictionary represents a detailed permission set object.
              Each dictionary typically contains keys like 'PermissionSetArn', 'Name', 'Description', etc.
    """
    sso_admin_client = boto3.client('sso-admin')
    permission_sets = []
    paginator = sso_admin_client.get_paginator('list_permission_sets')
    
    for page in paginator.paginate(InstanceArn=instance_arn):
        permission_sets.extend(page['PermissionSets'])
    
    return permission_sets


def get_permission_set_arn(instance_arn, permission_set_name):
    sso_client = boto3.client('sso-admin')

    # List all permission sets for the provided instance
    paginator = sso_client.get_paginator('list_permission_sets')
    for page in paginator.paginate(InstanceArn=instance_arn):
        for permission_set_arn in page['PermissionSets']:
            # Describe each permission set to find the name
            response = sso_client.describe_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            )
            if response['PermissionSet']['Name'] == permission_set_name:
                return permission_set_arn

    return None  # Return None if the permission set name is not found



def list_account_assignments(instance_arn, account_id):
    sso_admin_client = boto3.client('sso-admin')
    
    # Retrieve Identity Store ID
    instances = sso_admin_client.list_instances()
    identity_store_id = instances['Instances'][0]['IdentityStoreId']
    
    permission_sets = []
    
    # List all permission sets for the account
    permission_sets_paginator = sso_admin_client.get_paginator('list_permission_sets_provisioned_to_account')
    for page in permission_sets_paginator.paginate(
        InstanceArn=instance_arn,
        AccountId=account_id
    ):
        for permission_set_arn in page['PermissionSets']:
            permission_sets.append(permission_set_arn)

    account_assignments = []
    
    # List the account assignments for each permission set
    for permission_set_arn in permission_sets:
        paginator = sso_admin_client.get_paginator('list_account_assignments')
        for page in paginator.paginate(
            InstanceArn=instance_arn,
            AccountId=account_id,
            PermissionSetArn=permission_set_arn
        ):
            for assignment in page['AccountAssignments']:
                principal_id = assignment['PrincipalId']
                principal_name = get_principal_name(identity_store_id, principal_id, assisnment['PrincipalType'])
                account_assignments.append({
                    'PrincipalName': principal_name,
                    'PrincipalId': principal_id,
                    'PermissionSetArn': permission_set_arn
                })
    
    return account_assignments


def get_account_assignments(instance_arn, account_id, permission_set_arn):
    sso_admin_client = boto3.client('sso-admin')
    paginator = sso_admin_client.get_paginator('list_account_assignments')

    assignments = []
    for page in paginator.paginate(
        InstanceArn=instance_arn,
        AccountId=account_id,
        PermissionSetArn=permission_set_arn
    ):
        assignments.extend(page['AccountAssignments'])
    
    return assignments


def assign_users_to_permission_set(instance_arn, account_id, permission_set_arn, user_ids):
    sso_client = boto3.client('sso-admin')

    for user_id in user_ids:
        try:
            response = sso_client.create_account_assignment(
                InstanceArn=instance_arn,
                TargetId=account_id,
                TargetType='AWS_ACCOUNT',
                PermissionSetArn=permission_set_arn,
                PrincipalType='USER',
                PrincipalId=user_id
            )
            print(f"Successfully assigned user {user_id} to permission set {permission_set_arn} in account {account_id}")
        except ClientError as e:
            print(f"Failed to assign user {user_id} to permission set {permission_set_arn} in account {account_id}: {e}")


def assign_principal_to_permission_set(instance_arn, account_id, principal_id, principal_type, permission_set_arn):
    """
    Assigns a permission set to a principal (user or group) in AWS Identity Center (formerly AWS SSO) for a specified AWS account.
    
    Args:
    - instance_arn (str): The ARN of the AWS Identity Center instance.
    - account_id (str): The AWS account ID where the permission set will be assigned.
    - principal_id (str): The ID of the user or group in AWS Identity Center.
    - principal_type (str): The type of the principal, either 'USER' or 'GROUP'.
    - permission_set_arn (str): The ARN of the permission set to assign.
    
    Returns:
    - str: The status of the assignment operation.
    """
    client = boto3.client('sso-admin')
    
    if principal_type not in ['USER', 'GROUP']:
        raise ValueError("principal_type must be either 'USER' or 'GROUP'.")

    try:
        # Create the assignment for the principal (user or group)
        response = client.create_account_assignment(
            InstanceArn=instance_arn,
            TargetId=account_id,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=permission_set_arn,
            PrincipalType=principal_type,
            PrincipalId=principal_id
        )
        
        # Check the status of the operation
        status = response['AccountAssignmentCreationStatus']['Status']
        return status
    
    except Exception as e:
        print(f"An error occurred while assigning the permission set: {e}")
        return None


def revoke_permission_set_assignment(instance_arn, account_id, principal_id, principal_type, permission_set=None):
    """
    Revokes the permission set assigned to a user or group in AWS Identity Center. 
    Revokes all permission sets if the permission_set is not set.
    
    Args:
    - instance_arn (str): The ARN of the AWS Identity Center instance.
    - account_id (str): The AWS account ID where the permission set is assigned.
    - principal_id (str): The ID of the user or group whose permissions are to be revoked.
    - principal_type (str): The type of the principal, either 'USER' or 'GROUP'.
    - permission_set (str): The ARN of a permission set (None = all permission sets).
    
    Returns:
    - None
    """    
    sso_admin_client = boto3.client('sso-admin')
   
    permission_sets = []
    if permission_set == None:
        # Get all permission sets
        permission_sets = get_permission_sets(instance_arn)
    else:
        permission_sets.append(permission_set)
            
    
    for permission_set_arn in permission_sets:
        assignments = get_account_assignments(instance_arn, account_id, permission_set_arn)
        for assignment in assignments:
            if assignment['PrincipalId'] == principal_id and assignment['PrincipalType'] == principal_type:
                sso_admin_client.delete_account_assignment(
                    InstanceArn=instance_arn,
                    TargetId=account_id,
                    TargetType='AWS_ACCOUNT',
                    PermissionSetArn=permission_set_arn,
                    PrincipalType=principal_type,
                    PrincipalId=principal_id
                )
                #print(f"Removed permission set {permission_set_arn} assignment for {principal_id} from the account {account_id}")
    

def revoke_all_permissions(instance_arnr, account_id, principal_id, principal_type):
    """
    Revokes all permission sets assigned to a user or group in AWS Identity Center.
    
    Args:
    - instance_arn (str): The ARN of the AWS Identity Center instance.
    - account_id (str): The AWS account ID where the permission set is assigned.
    - principal_id (str): The ID of the user or group whose permissions are to be revoked.
    - principal_type (str): The type of the principal, either 'USER' or 'GROUP'.
    
    Returns:
    - None
    """
    client = boto3.client('sso-admin')

    try:
        # List all permission sets for the account
        paginator = client.get_paginator('list_account_assignments')
        for page in paginator.paginate(
            InstanceArn=instance_arn,
            AccountId=account_id,
            PrincipalType=principal_type,
            PrincipalId=principal_id
        ):
            for assignment in page['AccountAssignments']:
                permission_set_arn = assignment['PermissionSetArn']
                
                # Revoke the permission set assignment
                revoke_permission_set_assignment(
                    instance_arn,
                    account_id,
                    principal_id,
                    principal_type,
                    permission_set_arn
                )
                print(f"Revoked permission set {permission_set_arn} from {principal_type.lower()} {principal_id}.")
    
    except Exception as e:
        print(f"An error occurred while revoking permission sets: {e}")


def get_identity_store_id(instance_arn):
    """
    Returns the identity store ID associated with an AWS Identity Center Instance

    Args:
        - instance_arn (str): The ARN of the AWS Identity Center instance.

    Returns:
        - str (identity store ID)
    """
    sso_client = boto3.client('sso-admin')
    
    # Retrieve the Identity Store ID using the instance ARN
    response = sso_client.list_instances()
    for instance in response['Instances']:
        if instance['InstanceArn'] == instance_arn:
            return instance['IdentityStoreId']
    
    raise ValueError(f"No Identity Store ID found for instance ARN: {instance_arn}")


def cleanup_orphaned_assignments(instance_arn, account_id):
    """
    Cleans up orphaned assignments in AWS Identity Center for a given AWS account. 
    Orphaned assignments occur when a permission set is assigned to a principal (user or group) that no longer exists 
    or is no longer valid. This function identifies such orphaned assignments and revokes them.

    Args:
        instance_arn (str): The Amazon Resource Name (ARN) of the AWS Identity Center instance.
        account_id (str): The AWS account ID for which to clean up orphaned assignments.
    """
    sso_client = boto3.client('sso-admin')
    identitystore_client = boto3.client('identitystore')
    
    # Retrieve the Identity Store ID
    identity_store_id = get_identity_store_id(instance_arn)

    # Get the list of all users in the Identity Store
    user_ids = set()
    paginator = identitystore_client.get_paginator('list_users')
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        for user in page['Users']:
            user_ids.add(user['UserId'])

    # Get the list of all permission sets
    permission_sets = []
    paginator = sso_client.get_paginator('list_permission_sets')
    for page in paginator.paginate(InstanceArn=instance_arn):
        permission_sets.extend(page['PermissionSets'])

    # Loop over each permission set to clean up orphaned assignments for the specific account
    for permission_set_arn in permission_sets:
        paginator = sso_client.get_paginator('list_account_assignments')
        for page in paginator.paginate(
            InstanceArn=instance_arn,
            AccountId=account_id,
            PermissionSetArn=permission_set_arn
        ):
            for assignment in page['AccountAssignments']:
                if assignment['PrincipalType'] == 'USER' and assignment['PrincipalId'] not in user_ids:
                    # Orphaned assignment found, remove it
                    print(f"Removing orphaned assignment for account {account_id}: {assignment}")
                    sso_client.delete_account_assignment(
                        InstanceArn=instance_arn,
                        PermissionSetArn=permission_set_arn,
                        PrincipalType=assignment['PrincipalType'],
                        PrincipalId=assignment['PrincipalId'],
                        TargetId=account_id,
                        TargetType='AWS_ACCOUNT'
                    )

    print(f"Orphaned assignments cleanup complete for account {account_id}.")


def cleanup_orphaned_assignments_for_all_accounts(instance_arn):
    """
    Cleans up orphaned assignments in all the accounts in an AWS organizations. 
    Orphaned assignments occur when a permission set is assigned to a principal (user or group) that no longer exists 
    or is no longer valid.

    Args:
        instance_arn (str): The Amazon Resource Name (ARN) of the AWS Identity Center instance.
    """  
    org_client = boto3.client('organizations')
    
    # Get the list of all accounts in the organization
    accounts = []
    paginator = org_client.get_paginator('list_accounts')
    for page in paginator.paginate():
        accounts.extend(page['Accounts'])

    # Apply cleanup for each account
    for account in accounts:
        account_id = account['Id']
        print(f"Starting cleanup for account {account_id} ({account['Name']})...")
        cleanup_orphaned_assignments(instance_arn, account_id)

    print("Orphaned assignments cleanup complete for all accounts.")


def process_batch_permissions(instance_arn, file_name):
    """
    Assigns or revokes permissions according to the configuration.

    Args:
        instance_arn (str): The Amazon Resource Name (ARN) of the AWS Identity Center instance.
        file_name (str): The name of the file that holds permission sets assignments/revocations according to the metadata.

    Metadata:
    {
        "assign": [
            {
                "accountId": "100000000001",  # Type: String, Description: AWS Account ID where permissions are to be assigned
                "permissionSet": "Administrator",  # Type: String, Description: Name of the permission set to be assigned
                "users": [
                    "user1@aws.com",  # Type: String, Description: Email addresses or usernames of users to whom the permission set will be assigned
                    "user2@aws.com"  # Type: String, Description: Another user email or username
                ],
                "groups": [
                    "groupName"  # Type: String, Description: Names of groups to which the permission set will be assigned
                ]
            }
        ],
        "revoke": [
            {
                "accountId": "100000000000",  # Type: String, Description: AWS Account ID where permissions are to be revoked
                "permissionSet": "Administrator",  # Type: String, Description: Name of the permission set to be revoked
                "users": [
                    "user3@aws.com"  # Type: String, Description: Email addresses or usernames of users from whom the permission set will be revoked
                ],
                "groups": [
                    "groupName"  # Type: String, Description: Names of groups from which the permission set will be removed
                ]
            }
        ]
    }
    """
    data = load_json(file_name)
    if not data:
        print("Nothing to process, quitting...")
        return

    # Accessing specific parts of the JSON data
    assign_data = data.get('assign', [])
    revoke_data = data.get('revoke', [])
    

    for assignment in assign_data:
        permission_set_arn = get_permission_set_arn(instance_arn, assignment['permissionSet'])
        account_id = assignment['accountId']
        account_name = get_account_name(account_id)
        
        users = assignment.get('users', [])
        principal_type = 'USER'
        if len(users) > 0:
            print(f"Assigning the following users {assignment['permissionSet']}({permission_set_arn}) in {account_name} ({account_id})")
        for user in users:
            print(f"    - {user}")
            user_id = get_identity_center_user_id(get_identity_store_id(instance_arn), user)
            if user_id:
                assign_principal_to_permission_set(instance_arn, account_id, user_id, principal_type, permission_set_arn)
            

        groups = assignment.get('groups', [])
        principal_type = 'GROUP'
        if len(groups) > 0:
            print(f"Assigning the following groups {assignment['permissionSet']}({permission_set_arn}) in account {account_name} {account_id})")
        for group in groups:
            print(f"    - {group}")
            group_id = get_group_id_by_name(get_identity_store_id(instance_arn), group)
            assign_principal_to_permission_set(instance_arn, account_id, group_id, principal_type, permission_set_arn)
    
    # Process all permission sets to be revoked
    for revocation in revoke_data:
        permission_set_arn = get_permission_set_arn(instance_arn, revocation['permissionSet'])
        account_id = revocation['accountId']
        account_name = get_account_name(account_id)
        
        users = revocation.get('users', [])
        if len(users) > 0:
            principal_type = 'USER'
            print(f"Revoking the permission set assignment {revocation['permissionSet']} ({permission_set_arn}) in account {account_name} ({account_id}) for the following users:")

            for user in users:
                print(f"    - {user}")
                user_id = get_identity_center_user_id(get_identity_store_id(instance_arn), user)
                if user_id:
                    revoke_permission_set_assignment(instance_arn, account_id, user_id, principal_type, permission_set_arn)
            

        groups = revocation.get('groups', [])
        if len(groups) > 0:
            principal_type = 'GROUP'
            print(f"Revoking the following permission set assignment {revocation['permissionSet']} ({permission_set_arn}) in account {account_name} ({account_id}) for the following groups")
            for group in groups:
                print(f"    - {group}")
                group_id = get_group_id_by_name(get_identity_store_id(instance_arn), group)
                revoke_permission_set_assignment(instance_arn, account_id, group_id, principal_type, permission_set_arn)
