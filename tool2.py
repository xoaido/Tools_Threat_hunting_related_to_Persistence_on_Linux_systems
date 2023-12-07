# Check whether directories containing modules have write permissions for Group or Other
# If the module directory is not found, it can be a potential malicious kernel module 
import subprocess
import re

# Use the lsmod command to list all modules
lsmod_output = subprocess.check_output("lsmod", shell=True, text=True)

# Split the output into lines and remove the first line (header)
lsmod_lines = lsmod_output.splitlines()[1:]

# Find module names from the remaining lines
module_names = [line.split()[0] for line in lsmod_lines]

# Iterate through each module name and use the modinfo command to get information
print("List of suspicious modules:")
for module_name in module_names:
    try:
        modinfo_output = subprocess.check_output(f"modinfo {module_name}", shell=True, text=True)

        # Use regular expression to find the "filename" field
        filename_match = re.search(r'filename:\s+(?P<filename>.+)', modinfo_output)
        if filename_match:
            module_directory = "/".join(filename_match.group("filename").split("/")[:-1])

            # Use the ls -ld command to get information about the directory permissions
            ls_output = subprocess.check_output(f"ls -ld {module_directory}", shell=True, text=True)

            # Check if Group and Other have Write permission
            if "w" in ls_output[5] or "w" in ls_output[8]:
                # If there is no Write permission, print the information
                print(f"Module: {module_name}")
                print(f"Module Directory: {module_directory}")
                print(f"Directory Permissions: {ls_output.split()[0]}")
                print("=" * 80)  # Separator between modules
        else:
            print(f"Cannot find filename for module {module_name}")
    except subprocess.CalledProcessError as e:
        print(f"Potentially malicious kernel module: {module_name}")
