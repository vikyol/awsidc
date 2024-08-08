import boto3

def find_users_by_displayname(identity_store_id, displaynames):
    """
    Retrieves the Identity Center (AWS SSO) usernames of users based on a comma-separated list
    of first and last names by filtering the list of users using their display names.

    Args:
        identity_store_id (str): The ID of the Identity Store associated with AWS Identity Center.
        name_surname_pairs (str): A comma-separated string of name and surname pairs (e.g., "John Doe,Jane Smith").

    Returns:
        list: A list of dictionaries containing the name, surname, and corresponding Identity Center usernames.
    """
    identitystore_client = boto3.client('identitystore')
    
    # Fetch all users using pagination
    users = []
    paginator = identitystore_client.get_paginator('list_users')
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        users.extend(page['Users'])
    
    # Process the name and surname pairs
    results = []
    pairs = [pair.strip() for pair in displaynames.split(',')]
    
    for pair in pairs:
        if ' ' not in pair:
            print(f"Invalid name-surname pair: {pair}")
            continue
        
        first_name, last_name = pair.split(' ', 1)
        
        # Filter users by display name containing both first name and last name
        for user in users:
            display_name = user.get('DisplayName', '').lower()
            if first_name.lower() in display_name and last_name.lower() in display_name:
                results.append({
                    'FirstName': first_name,
                    'LastName': last_name,
                    'UserName': user.get('UserName'),
                    'DisplayName': display_name
                })
    
    return results


def get_principal_name(identity_store_id, principal_id, principal_type):
    """
    Retrieves the name of a principal (user or group) from AWS Identity Center
    using the provided Identity Store ID, principal ID, and principal type.

    Args:
        identity_store_id (str): The ID of the Identity Store associated with AWS Identity Center.
        principal_id (str): The unique identifier of the principal (user or group).
        principal_type (str): The type of the principal. Valid values are "USER" or "GROUP".

    Returns:
        str: The name of the principal (UserName for a user or DisplayName for a group).
    
    Raises:
        ValueError: If an invalid `principal_type` is provided.
        identitystore_client.exceptions.ResourceNotFoundException: If the principal_id cannot be found
    
    Example:
        >>> get_principal_name('d-1234567890', 'group-5678', 'GROUP')
        'Admins'
    """    
    identitystore_client = boto3.client('identitystore')

    if principal_type == 'USER':
        try:
            response = identitystore_client.describe_user(
                IdentityStoreId=identity_store_id,
                UserId=principal_id
            )
            return response['UserName']
        except identitystore_client.exceptions.ResourceNotFoundException:
            return "Unknown"
    elif principal_type == 'GROUP':
        try:
            response = identitystore_client.describe_group(
                IdentityStoreId=identity_store_id,
                GroupId=principal_id
            )
            return response['DisplayName']
        except identitystore_client.exceptions.ResourceNotFoundException:
            return "Unknown"


def get_group_id_by_name(identity_store_id, group_name):
    """
    Fetches the group ID from AWS Identity Center (formerly AWS SSO) based on the group name.
    
    Args:
    - identity_store_id (str): The ID of the AWS Identity Center (SSO) Identity Store.
    - group_name (str): The name of the group whose ID you want to retrieve.
    
    Returns:
    - str: The ID of the group if found, otherwise None.
    """
    client = boto3.client('identitystore')

    try:
        # Paginate through groups to find the matching group name
        paginator = client.get_paginator('list_groups')
        for page in paginator.paginate(IdentityStoreId=identity_store_id):
            for group in page['Groups']:
                if group['DisplayName'] == group_name:
                    return group['GroupId']
        
        print(f"Group '{group_name}' not found.")
        return None
    
    except Exception as e:
        print(f"An error occurred while fetching the group ID: {e}")
        return None


def user_exists(identity_store_id, user_id):
    """
    Checks whether the user_id exists in the identity store
    
    Args:
    - identity_store_id (str): The ID of the Identity Store associated with your AWS Identity Center instance.
    - user_id (str): The ID of a user in AWS Identity Center.
    
    Returns:
    - bool: true if the user found, false otherwise
    """
    identitystore_client = boto3.client('identitystore')
    try:
        identitystore_client.describe_user(
            IdentityStoreId=identity_store_id,
            UserId=user_id
        )
        return True
    except identitystore_client.exceptions.ResourceNotFoundException:
        return False


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

# Test
def main():
    identity_store_id = ""
    display_names = ""  # Comma-separated lift of "name surname" or "surname name" 

    usernames = find_users_by_displayname(identity_store_id, display_names)
    
    for user in usernames:
        print(f"{user['UserName']}")

if __name__ == "__main__":
    main()

