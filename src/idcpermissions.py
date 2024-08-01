import boto3
import argparse
import sys
import os

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


def remove_user_permission_sets(instance_arn, account_id, username, permission_set=None):
    identitystore_client = boto3.client('identitystore')
    sso_admin_client = boto3.client('sso-admin')
    
    # Get Identity Store ID
    instances = sso_admin_client.list_instances()
    identity_store_id = instances['Instances'][0]['IdentityStoreId']
    
    # Get User ID
    response = identitystore_client.list_users(
        IdentityStoreId=identity_store_id,
        Filters=[
            {
                'AttributePath': 'UserName',
                'AttributeValue': username
            }
        ]
    )
    user_id = response['Users'][0]['UserId']
    
    permission_sets = []
    if permission_set == None:
        # Get all permission sets
        permission_sets = get_permission_sets(instance_arn)
    else:
        ps_arn = get_permission_set_arn(instance_arn, permission_set)
        if ps_arn:
            print(f"Permission set arn: {ps_arn}")
            permission_sets.append(ps_arn)
        else:
            sys.exit(f"Permission set cannot be found: {permission_set}")
            
    
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
                print(f"Removed permission set {permission_set_arn} for user {username} from account {account_id}")
    


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
        remove_user_permission_sets(args.instance_arn, args.account_id, args.username)
    elif args.remove and args.permission_set:
        remove_user_permission_sets(args.instance_arn, args.account_id, args.username, args.permission_set)
    elif args.cleanup:
        cleanup_orphaned_assignments(args.instance_arn, args.account_id) 
     

if __name__ == "__main__":
    main()

