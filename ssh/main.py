import os
import sys
import time
import re
from collections import defaultdict 
import time

# This script needs to be run as root to be able to read all user's .ssh directories
def check_root():
    if os.geteuid() != 0:
        print("This script must be run as root.", file=sys.stderr)
        sys.exit(1)

# Get list of all home directories from /etc/passwd
def list_home_dirs():
    with open('/etc/passwd', 'r') as passwd_file:
        home_dirs = [line.split(':')[5] for line in passwd_file]
    return home_dirs

# Function 1: Find_ssh_private_keys
def find_ssh_private_keys(home_dirs):
    # result = True: not exist any anonmyous activities
    result = True
    for dir in home_dirs:
        # Check if the .ssh directory exists
        ssh_dir = os.path.join(dir, ".ssh")
        if os.path.exists(ssh_dir) and os.path.isdir(ssh_dir):
            # Find all files in the .ssh directory that contain the word "PRIVATE"
            private_files = []
        
            for root, _, files in os.walk(ssh_dir):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    with open(file_path, "r") as file:
                        contents = file.read()
                        if "PRIVATE" in contents:
                            private_files.append(file_path)

            if private_files:
                result = False
                print(f"ALERT: User with home directory {dir} has files in their .ssh directory that are likely private keys:")
                for file in private_files:
                    print(file)
    if (result):
        print("No anonymous activities here!")
    return result


# Function 2: Find authorized_key2
def find_ssh_authorized_keys2_search(home_dirs):
    # result = True: not exist any anonmyous activities
    result = True
    for dir in home_dirs:
        authorized_keys2_path = os.path.join(dir, '.ssh', 'authorized_keys2')
        if os.path.isfile(authorized_keys2_path):
            result = False
            print(f'ALERT: An authorized_keys2 file was found at: {authorized_keys2_path}.')
    
    if (result):
        print("No anonymous activities here!")
    return result


# Function 3: Check duplicated key in authorized_keys file
def find_ssh_authorized_keys_duplicates(home_dirs):
    for dir in home_dirs:
        # result = True: not exist any anonmyous activities
        result = True
        authorized_keys_path = os.path.join(dir, '.ssh', 'authorized_keys')

        if os.path.isfile(authorized_keys_path):
            print(f"Processing {authorized_keys_path}.")

            # Read the authorized_keys file and count duplicates (read line)
            keys = defaultdict(int)
            with open(authorized_keys_path, 'r') as auth_keys_file:
                for line in auth_keys_file:
                    if (line.strip() != ""):
                        keys[line] += 1

            # Print duplicate keys and their counts
            for key, count in keys.items():
                if count > 1:
                    result = False
                    print(f"ALERT: {key.strip()} is duplicated {count} times")
    if (result):
        print("No anonymous activities here!")
    return result


# Function 4: Check excessive key in authorized_keys file (10 keys here)
def find_ssh_authorized_keys_excessive(home_dirs):
    # result = True: not exist any anonmyous activities
    result = True

    MAX_KEY = 10
    
    for dir in home_dirs:
        authorized_keys_path = os.path.join(dir, '.ssh', 'authorized_keys')

        if os.path.isfile(authorized_keys_path):
            print(f"Processing {authorized_keys_path}.")

            count_key = 0
            # Count the number of key (line)
            with open(authorized_keys_path, 'r') as auth_keys_file:
                for line in auth_keys_file:
                    if (line.strip() != ""):
                        count_key += 1
        
            if (count_key > MAX_KEY):
                result = False
                print(f"ALERT: User with home directory {dir} has {count_key} keys in the authorized_keys file")
            else: 
                print(f"User with home directory {dir} has {count_key} keys, under the max number of key")
    
    if (result):
        print("No anonymous activities here!")
    return result

# Function 5: Check for option set in authorized_keys file
def find_ssh_authorized_keys_options_search(home_dirs):
    # result = True: not exist any anonmyous activities
    result = True
    for dir in home_dirs:
        authorized_keys_path = os.path.join(dir, '.ssh', 'authorized_keys')

        if os.path.isfile(authorized_keys_path):
            print(f"Processing {authorized_keys_path}.")
            with open(authorized_keys_path, 'r') as auth_keys_file:
                options_set = []

                for line in auth_keys_file:
                    if re.search(r'^(command|environment|agent-forwarding|port-forwarding|user-rc|X11-forwarding|.*,\s*(command|environment|agent-forwarding|port-forwarding|user-rc|X11-forwarding))', line):
                        options_set.append(line.strip())

                if options_set:
                    result = False
                    print(f"ALERT: User with home directory {dir} has options set in their authorized_keys file:")
                    print("\n".join(options_set))
    
    if (result):
        print("No anonymous activities here!")
    return result


# Function 6: Check for the modification of authorized_keys file in a limited time (24h here)
def find_ssh_authorized_keys_modified_24hrs(home_dirs):
    # result = True: not exist any anonmyous activities
    result = True

    # 24 hours in seconds. Adjust to suit.
    SECONDS_LIMIT = 86400  # 24 hours in seconds
    now = int(time.time())

    for dir in home_dirs:
        authorized_keys_path = os.path.join(dir, ".ssh", "authorized_keys")
        if os.path.exists(authorized_keys_path) and os.path.isfile(authorized_keys_path):
            # Get the last modification time of the file
            mtime = int(os.path.getmtime(authorized_keys_path))

            # Calculate the difference in seconds between now and the file's mtime
            diff = now - mtime

            # If the file was modified in the last 24 hours (86400 seconds)
            if diff <= SECONDS_LIMIT:
                result = False
                print(f"User with home directory {dir} has modified their authorized_keys file in the last 24 hours.")
    
    if (result):
        print("No anonymous activities here!")
    return result



if __name__ == '__main__':
    # This script needs to be run as root to be able to read all user's .ssh directories
    check_root()

    # Get list of all home directories from /etc/passwd
    home_dirs = list_home_dirs()


    # Function 1: Check find_ssh_private_keys
    print("Check for find_ssh_private_keys: ")
    result1 = find_ssh_private_keys(home_dirs)
    print("-----------------------------------------------------------")
    
    # Function 2: Find ssh_authorized_keys2
    print("Find ssh_authorized_keys2: ")
    result2 = find_ssh_authorized_keys2_search(home_dirs)
    print("-----------------------------------------------------------")

    # Function 3: Check duplicated key in authorized_keys file
    print("Check duplicated key in authorized_keys file: ")
    result3 = find_ssh_authorized_keys_duplicates(home_dirs)
    print("-----------------------------------------------------------")

    # Function 4: Check excessive key in authorized_keys file (10 keys here)
    print("Check excessive key in authorized_keys file (10 keys here)")
    result4 = find_ssh_authorized_keys_excessive(home_dirs)
    print("-----------------------------------------------------------")

    # Function 5: Check for option set in authorized_keys file
    print("Check for option set in authorized_keys file")
    result5 = find_ssh_authorized_keys_options_search(home_dirs)
    print("-----------------------------------------------------------")

    # Function 6: Check for the modification of authorized_keys file in a limited time (24h here)
    print("ALERT: Check for the modification of authorized_keys file in a limited time (24h here)")
    result6 = find_ssh_authorized_keys_modified_24hrs(home_dirs)
    print("-----------------------------------------------------------")
    
    if (result1 & result2 & result3 & result4 & result5 & result6):
        print("Check SSH done: No anonymous activities!")
    else:
        print("Check SSH done: Find some anonymous activities above")