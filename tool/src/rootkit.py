import subprocess
import re
import platform
import mmap
import os
import binascii
import colorama

def rootkitScanner():
    # Check for root privileges
     if os.geteuid() != 0:
          print("\nThis script must be run as root.")
          return
    print("\n[*]----------------------[[ RootKit Scan ]]----------------------[*]")
    # Check the loaded modules using the lsmod command, then compare them with the 
    #normal modules in the whitelist, identifying suspiciously loaded modules
    # Run the lsmod command and save the result to the output variable
    output = subprocess.check_output(["lsmod"]).decode("utf-8")

    # Split the result into lines
    lines = output.split('\n')

    # Read the list of modules from the module_list.txt file
    with open("module_list.txt", "r") as file:
        excluded_modules = [line.strip() for line in file]

    # Create an array to store module names
    module_names = []

    # Iterate through the lines and filter out modules not in the excluded_modules list
    for line in lines:
        columns = line.split()
        if len(columns) >= 1:
            module_name = columns[0]
            if module_name not in excluded_modules:
                module_names.append(module_name)

    # Print the list of module names
    print("\n----------Here are the suspicious modules:----------")
    for module in module_names:
        print(" + ",module)
    # Check whether directories containing modules have write permissions for Group or Other
    # If the module directory is not found, it can be a potential malicious kernel module 

    # Use the lsmod command to list all modules
    lsmod_output = subprocess.check_output("lsmod", shell=True, text=True)

    # Split the output into lines and remove the first line (header)
    lsmod_lines = lsmod_output.splitlines()[1:]

    # Find module names from the remaining lines
    module_names = [line.split()[0] for line in lsmod_lines]

    # Iterate through each module name and use the modinfo command to get information
    print("\n Info of suspicious modules:\n")
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
                    print(f"\n Module: {module_name}")
                    print(f"\n Module Directory: {module_directory}")
                    print(f"\n Directory Permissions: {ls_output.split()[0]}")
            else:
                print(f"\n Cannot find filename for module {module_name}")
        except subprocess.CalledProcessError as e:
            print(f"\n Potentially malicious kernel module: {module_name}")

    print("=" * 80)  # Separator between modules
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
    print("\n----------Listing all suspected kernel module files on the system:----------")
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
                        print(f"\n + {file_path}")
            else:
                if filename.endswith(".o"):
                    print(f"\n + {file_path}")

    def find_tainted_modules():
        try:
            # Run the 'dmesg' command and capture its output
            result = subprocess.run(['dmesg'], capture_output=True, text=True)

            # Check if the command was successful (return code 0)
            if result.returncode == 0:
                # Split the output into lines and iterate through them
                for line in result.stdout.splitlines():
                    # Check if the line contains the specified text
                    if "loading out-of-tree module taints kernel" in line:
                        # Split the line into fields and print the second field
                        fields = line.split()
                        module_name = fields[2].rstrip(':')
                        formatted_output = f"\n Suspicious kernel module loaded: {module_name}"
                        print(formatted_output)
            else:
                # Print an error message if the command failed
                print(f"\n Error running 'dmesg': {result.stderr}")
        except Exception as e:
            print(f"\n An error occurred: {e}")

    # Call the function to extract and print the second field from matching lines
    find_tainted_modules()

    def run_journalctl():
        try:
            # Run the journalctl command and capture the output
            result = subprocess.run(['journalctl'], capture_output=True, text=True, check=True)

            # Use regular expression to find lines containing "insmod" and extract PWD and Module
            matches = re.finditer(r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<hostname>\w+) (?P<process>\w+)\[(?P<pid>\d+)\]:\s+(?P<user>\w+) : TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<command_user>\w+) ; COMMAND=/usr/sbin/insmod (?P<module>.+)', result.stdout)

            # Print the header
            print("\n Suspicious insmod activity found:")

            # Print PWD and Module for each match
            for match in matches:
                print(f"\n + PWD: {match['pwd']}")
                print(f"\n + Module: {match['module']}")
                print()

        except subprocess.CalledProcessError as e:
            # Handle the case where the command returns a non-zero exit code
            print(f"\n Error running journalctl: {e}")
    run_journalctl()

    def process_file(file_path):
        try:
            # Check the size of the file
            file_size = os.path.getsize(file_path)

            if file_size == 0:
                return

            with open(file_path, "rb") as f:
                file_size_standard_io = 0
                for line in f:
                    output = line
                    file_size_standard_io += len(output)

                map = mmap.mmap(f.fileno(), 0, access=mmap.PROT_READ)
                file_size_mmap = map.size()
                file_seek = 0
                while file_seek < file_size_mmap:
                    output = map.readline()
                    file_seek += len(output)

                if file_size_standard_io != file_size_mmap:
                    print("\n********************************************************************************************")
                    print(f"  ALERT: {file_path}. File has cloaked data.")
                    print("********************************************************************************************\n\n")
                    return True  # Return True if there is a file with mismatched size
        except FileNotFoundError:
            pass
        return False  # Return False if no files have an error

    def process_directory(directory_path):
        for root, dirs, files in os.walk(directory_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                process_file(file_path)

    def run():
        folder_path = '/etc'  # Path to the directory to be checked
        any_mismatch = False  # Variable to check if any files have mismatched sizes

        for root, dirs, files in os.walk(folder_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                if process_file(file_path):
                    any_mismatch = True  # If there is a file with mismatched size, set any_mismatch to True

        if not any_mismatch:
            print(colorama.Fore.LIGHTGREEN_EX + "\nOK: All files have matching sizes.\n\n" + colorama.Fore.RESET)
    run()
