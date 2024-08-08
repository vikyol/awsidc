import json

def get_users_from_file(file_path):
    """
    Reads a list of user emails from a specified file.

    Args:
    - file_path (str): The path to the file containing user emails.

    Returns:
    - List[str]: A list of user emails.
    """
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
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON from {file_path}: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None