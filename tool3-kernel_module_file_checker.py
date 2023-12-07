import os
import subprocess
import platform
import re

# The root directory to start the search
root_dir = "/"

# Directories to be excluded from the search
excluded_dir = "/usr/lib/modules"

# Function to check if a file is a kernel module
def is_kernel_module(file_path):
    return file_path.endswith(".ko")

# Function to check if the kernel version is greater than 2.6
def is_kernel_version_supported():
    kernel_version_str = platform.uname().release
    match = re.match(r'^(\d+\.\d+)', kernel_version_str)
    if match:
        kernel_version_numeric = match.group(1)
        major_version, minor_version = map(int, kernel_version_numeric.split('.')[:2])
        return major_version > 2 or (major_version == 2 and minor_version >= 6)
    return False

# Function to check the file type using the 'file' command
def check_file_type(file_path):
    try:
        result = subprocess.check_output(["file", file_path], stderr=subprocess.STDOUT, universal_newlines=True)
        return result
    except subprocess.CalledProcessError as e:
        return e.output

# Start searching for .ko or .o files depending on the kernel version
print("Listing all suspected kernel module files on the system:")
for foldername, subfolders, filenames in os.walk(root_dir):
    # Check if the current folder is in the excluded list
    if excluded_dir in foldername:
        continue
    for filename in filenames:
        file_path = os.path.join(foldername, filename)
        if is_kernel_version_supported():
            if is_kernel_module(filename):
                file_info = check_file_type(file_path)
                if "ELF" in file_info:
                    print(f"{file_path}")
        else:
            if filename.endswith(".o"):
                print(f"{file_path}")
