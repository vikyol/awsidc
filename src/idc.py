import boto3
import argparse
import sys
import os
import csv
from users import *
from utils import *
from permissions import *

def main():
    parser = argparse.ArgumentParser(
        description = 'Manage AWS Permissions',
        usage=(
            "%(prog)s --instance_arn <arn>\n" 
            "         --list --account_id <accountID> | [--out <out.csv>]\n"
            "         --remove --account_id <accountID> --username <username>\n"
            "         --assign --account_id <accountID> --file <file_name> --permission_set <permissionSet>\n"
            "         --cleanup [--account_id <accountID> | --all]\n"
            "         --find_users <users>"
        )
    )
    parser.add_argument(
        '--instance_arn',
        action = 'store',
        help = 'The ARN of the IAM Identity Center instance under which the operation will be executed.',
        default = os.environ.get("SSO_INSTANCE_ARN", "")
    )
    parser.add_argument(
        '--list',
        action = 'store_true',
        help = 'Export all permission sets for a given account ID',
    )
    parser.add_argument(
        '--find_users',
        action = 'store',
        help = 'Given a comma-separated list of users, return a list of IdC usernames',
        metavar='USERS'
    )
    parser.add_argument(
        '--account_id',
        action = 'store',
        help = 'The ID of the target AWS account.',
        metavar='AWS_ACCOUNT_ID'
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
        '--batch',
        action = 'store_true',
        help = 'Assign or revoke permissions according to an input file.'
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
        help = 'The name of the input file.',
        metavar='INPUT_FILE_NAME'
    )
    parser.add_argument(
        '--out',
        action = 'store',
        help = 'The name of the output file.',
        metavar='OUTPUT_FILE_NAME'
    )
    parser.add_argument(
        '--cleanup',
        action = 'store_true',
        help = "Clean up orphaned users from AWS Identity Center by removing users who no longer have associated accounts or roles."
    )


    # Parse the arguments
    args = parser.parse_args()

    idc_store_id = get_identity_store_id(args.instance_arn)

   # Check if --remove is provided
    if args.assign or args.remove or args.cleanup:
        # Enforce that --account_id and --username are required
        if not args.account_id:
            parser.error("Target account ID is missinig. Please provide it with --account_id")
   # Check if --remove is provided
    if args.remove:
        if not (args.username or args.all or args.file or args.permission_set):
            parser.error(f"Usage: python {sys.argv[0]} --remove [--all | --file <file_name> | --permission_set <name>]")
   # Check if --list is provided
    if args.list:
        if not (args.account_id):
            parser.error(f"Usage: python {sys.argv[0]} --list [--account_id <accountID>]")
    
    
    if args.list:
        permission_sets = list_permission_sets_for_account(args.instance_arn, args.account_id)

        if args.out:
            with open(args.out, 'w', newline='') as csvfile:
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow(["PrincipalName", "PermissionSetName", "PrincipalType", "PrincipalId", "AccountId"])
                for ps in permission_sets:
                    for assignment in ps.get('Assignments', []):
                        csvwriter.writerow([assignment['PrincipalName'], ps['Name'], assignment['PrincipalType'], assignment['PrincipalId'], assignment['AccountId']])
            print(f"Output written to {args.out}")
        else:
            print("PrincipalName,PermissionSetName,PrincipalType,PrincipalId,AccountId")
            for ps in permission_sets:
                for assignment in ps.get('Assignments', []):
                    print(f"{assignment['PrincipalName']},{ps['Name']},{assignment['PrincipalType']},{assignment['PrincipalId']},{assignment['AccountId']}")
    elif args.assign:
        user_ids = []
        permission_set_arn = get_permission_set_arn(args.instance_arn, args.permission_set)
        if args.file:
            users = get_users_from_file(args.file)
            for user in users:
                user_ids.append(get_identity_center_user_id(idc_store_id, user))

            print(user_ids)
            if len(user_ids) > 0:
                assign_users_to_permission_set(args.instance_arn, args.account_id, permission_set_arn, user_ids)
        elif args.username:
            user_ids.append(get_identity_center_user_id(idc_store_id, args.username))
            print(user_ids)
            assign_users_to_permission_set(args.instance_arn, args.account_id, permission_set_arn, user_ids)
    elif args.remove:
        if args.all:
            user_id = get_identity_center_user_id(args.instance_arn, args.username)
            revoke_all_permissions(args.instance_arn, args.account_id, user_id, 'USER')
        elif args.permission_set:
            user_id = get_identity_center_user_id(args.instance_arn, args.username)
            permission_set_arn = get_permission_set_arn(args.instance_arn, args.permission_set)
            revoke_permission_set_assignment(instance_arn, account_id, user_id, 'USER', permission_set_arn)
    elif args.cleanup:
        if args.account_id:
            cleanup_orphaned_assignments(args.instance_arn, args.account_id) 
        elif args.all:
            cleanup_orphaned_assignments_for_all_accounts(args.instance_arn, args.account_id) 
        else:
            print("Required arguments [--account | --all]")
    elif args.batch:
        process_batch_permissions(args.instance_arn, args.file)
    elif args.find_users:
        usernames = find_users_by_displayname(idc_store_id, args.find_users)
    
        for user in usernames:
            print(f"{user['UserName']}")

        
if __name__ == "__main__":
    main()
