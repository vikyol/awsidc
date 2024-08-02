import boto3
import argparse
import sys
import os
import json

def get_identity_center_user_id(identity_store_id, username):
    """
    Retrieves the AWS Identity Center (formerly AWS SSO) UserId for a given username.
    
    Args:
    - identity_store_id (str): The ID of the Identity Store associated with your AWS Identity Center instance.
    - username (str): The username in AWS Identity Center.
    
    Returns:
    - str: The UserId of the user, or None if not found.
    """
    # Initialize a session using the default profile or environment variables
    client = boto3.client('identitystore')
    
    try:
        # Search for the user using the username
        response = client.list_users(
            IdentityStoreId=identity_store_id,
            Filters=[{
                'AttributePath': 'UserName',
                'AttributeValue': username
            }]
        )
        
        # Check if the user is found and return the UserId
        if response['Users']:
            user_id = response['Users'][0]['UserId']
            return user_id
        else:
            print(f"User with username '{username}' not found.")
            return None
    
    except Exception as e:
        print(f"An error occurred while fetching the user ID: {e}")
        return None



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


def get_permission_sets(instance_arn):
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



def get_principal_name(identity_store_id, user_id):
    identitystore_client = boto3.client('identitystore')
    try:
        response = identitystore_client.describe_user(
            IdentityStoreId=identity_store_id,
            UserId=user_id
        )
        return response['UserName']
    except identitystore_client.exceptions.ResourceNotFoundException:
        return "Unknown"

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
                principal_name = get_principal_name(identity_store_id, principal_id)
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


"""
Reads a list of user emails from a specified file.

Args:
- file_path (str): The path to the file containing user emails.

Returns:
- List[str]: A list of user emails.
"""
def get_users_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            # Read all lines from the file and strip any leading/trailing whitespace
            users = [line.strip() for line in file if line.strip()]
        return users
    except FileNotFoundError:
        print(f"Error: The file at {file_path} was not found.")
        return []
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        return []


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


def remove_user_permission_sets(instance_arn, account_id, user_id, permission_set=None):
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
            if assignment['PrincipalId'] == user_id and assignment['PrincipalType'] == 'USER':
                sso_admin_client.delete_account_assignment(
                    InstanceArn=instance_arn,
                    TargetId=account_id,
                    TargetType='AWS_ACCOUNT',
                    PermissionSetArn=permission_set_arn,
                    PrincipalType='USER',
                    PrincipalId=user_id
                )
                print(f"Removed permission set {permission_set_arn} for user {user_id} from account {account_id}")
    


def load_json(file_path):
    """
    Loads JSON data from a specified file.
    
    Args:
    - file_path (str): The path to the JSON file.
    
    Returns:
    - dict: The parsed JSON data as a dictionary.
    """
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        print(f"Error: The file at {file_path} was not found.")
        return {}
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON from {file_path}: {e}")
        return {}
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return {}

def user_exists(identity_store_id, user_id):
    identitystore_client = boto3.client('identitystore')
    try:
        identitystore_client.describe_user(
            IdentityStoreId=identity_store_id,
            UserId=user_id
        )
        return True
    except identitystore_client.exceptions.ResourceNotFoundException:
        return False

def get_identity_store_id(instance_arn):
    sso_client = boto3.client('sso-admin')
    
    # Retrieve the Identity Store ID using the instance ARN
    response = sso_client.list_instances()
    for instance in response['Instances']:
        if instance['InstanceArn'] == instance_arn:
            return instance['IdentityStoreId']
    
    raise ValueError(f"No Identity Store ID found for instance ARN: {instance_arn}")

def cleanup_orphaned_assignments(instance_arn, account_id):
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


def process_batch_permissions(instance_arn, data):
    # Accessing specific parts of the JSON data
    assign_data = data.get('assign', [])
    revoke_data = data.get('revoke', [])
    

    for assignment in assign_data:
        permission_set = get_permission_set_arn(instance_arn, assignment['permissionSet'])
        accountId = assignment['accountId']
        accountName = get_account_name(accountId)
        user_ids = []
        
        users = assignment.get('users', [])
        if len(users) > 0:
            print(f"Assigning the following users {assignment['permissionSet']}({permission_set}) in {accountName} ({accountId})")
        for user in users:
            print(f"    - {user}")
            user_id = get_identity_center_user_id(get_identity_store_id(instance_arn), user)
            if user_id:
                user_ids.append(user_id)
            
        assign_users_to_permission_set(instance_arn, accountId, permission_set, user_ids)

        groups = assignment.get('groups', [])
        if len(groups) > 0:
            print(f"Assigning the following groups {assignment['permissionSet']}({permission_set}) in account {accountName} {accountId})")
        for group in groups:
            print(f"    - {group}")
            #assign_groups_to_permission_set(instance_arn, assignment['account_id'], permission_set, user)
    
    # Process all permission sets to be revoked
    for revocation in revoke_data:
        permission_set = get_permission_set_arn(instance_arn, revocation['permissionSet'])
        account_id = revocation['accountId']
        account_name = get_account_name(account_id)
        
        users = revocation.get('users', [])
        if len(users) > 0:
            print(f"Revoking the following users {revocation['permissionSet']}({permission_set}) in {account_name} ({account_id})")
        for user in users:
            print(f"    - {user}")
            user_id = get_identity_center_user_id(get_identity_store_id(instance_arn), user)
            if user_id:
                remove_user_permission_sets(instance_arn, account_id, user_id, permission_set)
            

        groups = revocation.get('groups', [])
        if len(groups) > 0:
            print(f"Assigning the following groups {revocation['permissionSet']}({permission_set}) in account {account_name} {account_id})")
        for group in groups:
            print(f"    - {group}")
            #assign_groups_to_permission_set(instance_arn, account_id, permission_set, group)


def main():
    parser = argparse.ArgumentParser(description = 'Manage AWS Permissions')
    parser.add_argument(
        '--instance_arn',
        action = 'store',
        help = 'The ARN of the IAM Identity Center instance under which the operation will be executed.',
        default = os.environ.get("SSO_INSTANCE_ARN", "")
    )
    parser.add_argument(
        '--account_id',
        action = 'store',
        help = 'The ID of the target AWS account.'
    )
    parser.add_argument(
        '--username',
        action = 'store',
        help = 'The user whose access will be updated or revoked.'
    )
    parser.add_argument(
        '--assign',
        action = 'store_true',
        help = 'Assigns the specified permission set to a user in an account.'
    )
    parser.add_argument(
        '--remove',
        action = 'store_true',
        help = 'Removes permission sets assigned to a user from an account.'
    )
    parser.add_argument(
        '--all',
        action = 'store_true',
        help = 'Removes all permission sets for a username from an account.'
    )
    parser.add_argument(
        '--permission_set',
        action = 'store',
        help = 'The name of the permission set. Add or remove the permission set for a username to/from an account.'
    )
    parser.add_argument(
        '--file',
        action = 'store',
        help = 'The name of the permission set. Add or remove the permission set for a username to/from an account.'
    )
    parser.add_argument(
        '--cleanup',
        action = 'store_true',
        help = '"Clean up orphaned users from AWS Identity Center by removing users who no longer have associated accounts or roles."'
    )


    # Parse the arguments
    args = parser.parse_args()
   # Check if --remove is provided
    if args.assign or args.remove or args.cleanup:
        # Enforce that --account_id and --username are required
        if not args.account_id:
            parser.error("Target account ID is missinig. Please provide it with --account_id")
   # Check if --remove is provided
    if args.remove:
        if not (args.all or args.file or args.permission_set):
            parser.error(f"Usage: python {sys.argv[0]} --remove [--all | --file <file_name> | --permission_set <name>]")
    
    
    if args.remove and args.all:
        user_id = get_identity_store_id(args.username)
        remove_user_permission_sets(args.instance_arn, args.account_id, user_id)
    elif args.remove and args.permission_set:
        user_id = get_identity_store_id(args.username)
        permission_set_arn = get_permission_set_arn(instance_arn, args.permission_set)
        remove_user_permission_sets(args.instance_arn, args.account_id, user_id, permission_set_arn)
    elif args.cleanup:
        csleanup_orphaned_assignments(args.instance_arn, args.account_id) 
    elif args.assign:
        users = get_users_from_file(args.file)
        if len(users) > 0:
            assign_users_to_permission_set(args.instance_arn, account_id, permission_set_arn, user_ids)
    elif args.file:
        data = load_json(args.file)
        if data:
            process_batch_permissions(args.instance_arn, data)

        
     

if __name__ == "__main__":
    main()

