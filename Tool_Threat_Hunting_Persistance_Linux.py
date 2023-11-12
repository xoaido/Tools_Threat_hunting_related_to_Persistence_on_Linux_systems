# Library imports
import math
import sys
import os
import re
import time
import subprocess
from collections import defaultdict
import argparse

def sshScanner(keys, hours):

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


    # Function 4: Check excessive key in authorized_keys file
    def find_ssh_authorized_keys_excessive(home_dirs, keys):
        # result = True: not exist any anonmyous activities
        result = True

        MAX_KEY = keys
        
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
    def find_ssh_authorized_keys_args_search(home_dirs):
        # result = True: not exist any anonmyous activities
        result = True
        for dir in home_dirs:
            authorized_keys_path = os.path.join(dir, '.ssh', 'authorized_keys')

            if os.path.isfile(authorized_keys_path):
                print(f"Processing {authorized_keys_path}.")
                with open(authorized_keys_path, 'r') as auth_keys_file:
                    args_set = []

                    for line in auth_keys_file:
                        if re.search(r'^(command|environment|agent-forwarding|port-forwarding|user-rc|X11-forwarding|.*,\s*(command|environment|agent-forwarding|port-forwarding|user-rc|X11-forwarding))', line):
                            args_set.append(line.strip())

                    if args_set:
                        result = False
                        print(f"ALERT: User with home directory {dir} has args set in their authorized_keys file:")
                        print("\n".join(args_set))
        
        if (result):
            print("No anonymous activities here!")
        return result


    # Function 6: Check for the modification of authorized_keys file in a limited time (24h here)
    def find_ssh_authorized_keys_modified_24hrs(home_dirs, hours):
        # result = True: not exist any anonmyous activities
        result = True

        # hours to seconds. Adjust to suit.
        SECONDS_LIMIT = hours * 60 * 60 # hours in seconds
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

 
    # This script needs to be run as root to be able to read all user's .ssh directories
    check_root()
    # Get list of all home directories from /etc/passwd
    home_dirs = list_home_dirs()
    print("\n[*]----------------------[[ SSH Scan ]]----------------------[*]")

    # Function 1: Check find_ssh_private_keys
    print("\n[[ Check for find_ssh_private_keys ]]")
    result1 = find_ssh_private_keys(home_dirs)
    print("-----------------------------------------------------------")
    
    # Function 2: Find ssh_authorized_keys2
    print("\n[[ Find ssh_authorized_keys2 ]]")
    result2 = find_ssh_authorized_keys2_search(home_dirs)
    print("-----------------------------------------------------------")

    # Function 3: Check duplicated key in authorized_keys file
    print("\n[[ Check duplicated key in authorized_keys file ]]")
    result3 = find_ssh_authorized_keys_duplicates(home_dirs)
    print("-----------------------------------------------------------")

    # Function 4: Check excessive key in authorized_keys file (default: 10 keys here)
    print("\n[[ Check excessive key in authorized_keys file ({0} keys here) ]]".format(keys))
    result4 = find_ssh_authorized_keys_excessive(home_dirs, keys)
    print("-----------------------------------------------------------")

    # Function 5: Check for option set in authorized_keys file
    print("\n[[ Check for option set in authorized_keys file ]]")
    result5 = find_ssh_authorized_keys_args_search(home_dirs)
    print("-----------------------------------------------------------")

    # Function 6: Check for the modification of authorized_keys file in a limited time (default: 24h here)
    print("\n[[ Check for the modification of authorized_keys file in a limited time {0}h ]]".format(hours))
    result6 = find_ssh_authorized_keys_modified_24hrs(home_dirs, hours)
    print("-----------------------------------------------------------")
    
    if (result1 & result2 & result3 & result4 & result5 & result6):
        print("\n==> Check SSH done: No anonymous activities!")
    else:
        print("\n==> Check SSH done: Find some anonymous activities above")    


def crontabScanner():
    print("\n[*]----------------------[[ CronTab Scan ]]----------------------[*]")
    # Chạy lệnh crontab -l để lấy nội dung crontab hiện tại
    try:
        crontab_output = subprocess.check_output(["crontab", "-l"], stderr=subprocess.STDOUT, text=True)
        # print("Nội dung crontab:")
        # print(crontab_output)
        # Tìm các dòng lập lịch chứa các ký tự đặc biệt hoặc chuỗi cụ thể
        lines = crontab_output.split('\n')
        
        # Tạo từ điển để lưu trữ các danh sách tương ứng và thông báo
        matched_lines = {
            "is_long": {"message": "Very long strings, which may indicate encoding:", "lines": []},
            "is_malicious": {"message": "Malicious code often exists in this directory:", "lines": []},
            "is_common_command": {"message": "These are commonly used commands to connect to the internet:", "lines": []},
            "is_encoded": {"message": "Insert and encode commands:", "lines": []},
            "is_shell_related": {"message": "Used to run a shell on the system", "lines": []}
        }

        for line in lines:
            is_malicious = False
            is_common_command = False
            is_long = False
            is_encoded = False
            is_shell_related = False
            # Kiểm tra độ dài dòng lập lịch
            if len(line) > 200:
                is_long = True

            # Kiểm tra nếu dòng lập lịch chứa "/tmp"
            if "/tmp" in line:
                is_malicious = True

            # Kiểm tra nếu dòng lập lịch chứa các lệnh "curl", "@", "dig", "http?://*", "nc", "wget"
            if re.search(r'(curl|@|dig|http\?://\*|nc |wget)', line):
                is_common_command = True

            # Kiểm tra nếu dòng lập lịch chứa ký tự mã hóa như "^M" hoặc "base64"
            if re.search(r'(\^M|base64)', line):
                is_encoded = True

            if re.search(r'(\|*sh|\*sh -c)', line):
                is_shell_related = True

            # Nếu có bất kỳ dấu hiệu nào được nhận diện, thêm dòng vào danh sách tương ứng
            if is_long:
                matched_lines["is_long"]["lines"].append(line)
            if is_malicious:
                matched_lines["is_malicious"]["lines"].append(line)
            if is_common_command:
                matched_lines["is_common_command"]["lines"].append(line)
            if is_encoded:
                matched_lines["is_encoded"]["lines"].append(line)
            if is_shell_related:
                matched_lines["is_shell_related"]["lines"].append(line)

        # In tất cả các danh sách tương ứng
        for key, value in matched_lines.items():
            if value["lines"]:
                print(f"{value['message']}")
                for line in value["lines"]:
                    print(line)
                    print("--------------------------------------------------------------")
                print()

    except subprocess.CalledProcessError as e:
        print(f"Lỗi: {e.returncode}\n{e.output}")



def rootkitScanner():
    print("\n[*]----------------------[[ RootKit Scan ]]----------------------[*]")
    # Chạy câu lệnh lsmod và lưu kết quả vào biến output
    output = subprocess.check_output(["lsmod"]).decode("utf-8")

    # Chia kết quả thành các dòng
    lines = output.split('\n')

    # Đọc danh sách module từ tệp module_list.txt
    with open("module_list.txt", "r") as file:
        excluded_modules = [line.strip() for line in file]

    # Tạo một mảng để lưu trữ tên module
    module_names = []

    # Lặp qua các dòng và lọc ra các module không có trong danh sách excluded_modules
    for line in lines:
        columns = line.split()
        if len(columns) >= 1:
            module_name = columns[0]
            if module_name not in excluded_modules:
                module_names.append(module_name)

    # In danh sách tên module
    print("\n[[ Đây là các module bất thường ]]")
    for module in module_names:
        print(module)
    # Sử dụng lệnh lsmod để liệt kê tất cả các module
    lsmod_output = subprocess.check_output("lsmod", shell=True, text=True)

    # Chia đầu ra thành từng dòng và loại bỏ dòng đầu tiên (tiêu đề)
    lsmod_lines = lsmod_output.splitlines()[1:]

    # Tìm tên module từ dòng còn lại
    module_names = [line.split()[0] for line in lsmod_lines]

    # Duyệt qua từng tên module và sử dụng lệnh modinfo để lấy thông tin
    print("\n[[ Danh sách các module đáng ngờ ]]")
    for module_name in module_names:
        try:
            modinfo_output = subprocess.check_output(f"modinfo {module_name}", shell=True, text=True)

            # Sử dụng biểu thức chính quy để tìm trường "filename"
            filename_match = re.search(r'filename:\s+(?P<filename>.+)', modinfo_output)
            if filename_match:
                module_directory = "/".join(filename_match.group("filename").split("/")[:-1])

                # Sử dụng lệnh ls -ld để lấy thông tin về quyền của thư mục
                ls_output = subprocess.check_output(f"ls -ld {module_directory}", shell=True, text=True)

                # Sử dụng biểu thức chính quy mới để trích xuất tên Owner và Group từ kết quả ls
                owner_group_match = re.search(r'\s(\w+)\s(\w+)\s\d+ \w+ \d+:\d+.*$', ls_output)
                if owner_group_match:
                    owner = owner_group_match.group(1)
                    group = owner_group_match.group(2)
                    
                    # Kiểm tra xem Owner hoặc Group có giá trị "root" hay không
                    if owner != "root" and group != "root":
                        # Nếu không phải "root", thì in thông tin
                        print(f"Module: {module_name}")
                        print(f"Module Directory: {module_directory}")
                        print(f"Directory Permissions: {ls_output.split()[0]}")
                        print("=" * 80)  # Dấu phân cách giữa các module
            else:
                print(f"Không thể tìm thấy filename cho module {module_name}")
        except subprocess.CalledProcessError as e:
            print(f"Không thể lấy thông tin cho module {module_name}: {e}")

    # Đọc nội dung của tệp /etc/modules-load.d/modules.conf
    print("\n[[ Kiểm tra file /etc/modules ]]")
    modules_conf_path = '/etc/modules-load.d/modules.conf'
    try:
        with open(modules_conf_path, 'r') as modules_file:
            modules_content = modules_file.read()
            print(f"\n[[ Contents of {modules_conf_path} ]]\n{modules_content}")
    except FileNotFoundError:
        print(f"File {modules_conf_path} not found.")
    except PermissionError:
        print(f"Permission denied to access {modules_conf_path}.")
    except Exception as e:
        print(f"An error occurred while reading {modules_conf_path}: {e}")

    # Liệt kê nội dung của thư mục /etc/systemd/system/
    systemd_directory = "/etc/systemd/system/"
    ls_command = f"ls -la {systemd_directory}"
    try:
        result = subprocess.run(ls_command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"\n[[ Nội dung của {systemd_directory} ]]\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing 'ls' command: {e}")
    except Exception as e:
        print(f"An error occurred while listing {systemd_directory}: {e}")

    # Thực hiện câu lệnh systemctl list-unit-files --type=service | grep enable
    try:
        systemctl_command = "systemctl list-unit-files --type=service | grep enable"
        result = subprocess.run(systemctl_command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"\n[[ Hiển thị danh sách các service có trên hệ thống và đang được enable ]]\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing 'systemctl' command: {e}")
    except Exception as e:
        print(f"An error occurred while running 'systemctl' command: {e}")

    # Thực hiện câu lệnh find / -path /usr/lib/modules -prune -o -type f -name "*.ko" -exec file {} \;
    # Thư mục gốc để bắt đầu tìm kiếm
    root_dir = "/"

    # Thư mục bạn muốn loại trừ khỏi tìm kiếm
    excluded_dir = "/usr/lib/modules"

    # Hàm kiểm tra tệp có phải là tệp kernel module hay không
    def is_kernel_module(file_path):
        return file_path.endswith(".ko")

    # Hàm thực hiện kiểm tra loại tệp sử dụng lệnh 'file'
    def check_file_type(file_path):
        try:
            result = subprocess.check_output(["file", file_path], stderr=subprocess.STDOUT, universal_newlines=True)
            return result
        except subprocess.CalledProcessError as e:
            return e.output

    # Bắt đầu tìm kiếm tệp .ko
    print("\n[[ Liệt kê tất cả các file .ko nghi ngờ trên hệ thống ]]")
    for foldername, subfolders, filenames in os.walk(root_dir):
        # Kiểm tra xem thư mục hiện tại có nằm trong danh sách loại trừ không
        if excluded_dir in foldername:
            continue
        for filename in filenames:
            file_path = os.path.join(foldername, filename)
            if is_kernel_module(filename):
                file_info = check_file_type(file_path)
                if "ELF" in file_info:
                    print(f"{file_path}")

def loginshellScanner():
    print("\n[*]----------------------[[ LoginShell Scan ]]----------------------[*]")
    print("\n[[ Detect directory ]]\n")
    # List of suspicious patterns for commands
    suspicious_command_patterns = [
        r"rm\s+.*",
        r"mv\s+.*",
        r"cp\s+.*",
        r"wget\s+.*",
        r"curl\s+.*",
        r"git\s+.*",
        r"chmod\s+.*",
        r"chown\s+.*",
        r"ln\s+.*",
        r"echo\s+.*>\s+.*",
        r"touch\s+.*",
        r"cat\s+.*>>\s+.*",
        r"nc\s+-lvp\s+.*" ,
        r"mkfs\s+.*",
        r"mknod\s+.*",
        r"tar\s+.*",
        # Add other persistent attack patterns here
    ]

    # List of suspicious patterns for encoding
    suspicious_encoding_patterns = [
        r"base64\s+.*",
        r"gzip\s+.*",
        r"bzip2\s+.*",
        r"openssl\s+.*",
        r"xxd\s+.*",
        r"uudecode\s+.*",
        # Add other encoding patterns here
        r"tar\s+.*",
        r"zip\s+.*",
        r"7z\s+.*",
        r"rot13\s+.*",
        r"yenc\s+.*",
        r"bzcat\s+.*",
        r"unzip\s+.*",
        r"gunzip\s+.*",
        r"taz\s+.*",
        r"shar\s+.*",
        r"rar\s+.*",
        r"lzma\s+.*",
        r"lzcat\s+.*",
        r"lzop\s+.*",
        r"lzopcat\s+.*",
        # Add more encoding patterns here
    ]

    # Kết hợp các mẫu nghi ngờ từ hai danh sách thành một danh sách duy nhất
    suspicious_patterns = suspicious_command_patterns + suspicious_encoding_patterns

    # Thực hiện phân tích và phát hiện các tệp script trong thư mục /etc/profile.d/
    script_directory = "/etc/profile.d/"
    script_files = [f for f in os.listdir(script_directory) if os.path.isfile(os.path.join(script_directory, f))]

    # Phân tích mã nguồn của từng tệp script
    for script_file in script_files:
        script_path = os.path.join(script_directory, script_file)
        suspicious_commands = []  # Danh sách lệnh nghi ngờ được tìm thấy trong tệp script
        encoded_chars = []  # Danh sách ký tự được mã hóa được tìm thấy trong tệp script
        try:
            # Đọc nội dung của tệp script
            with open(script_path, 'r', encoding='latin-1') as f:
                script_code = f.read()

                # Kiểm tra các lệnh nghi ngờ trong mã nguồn script
                for pattern in suspicious_command_patterns:
                    if re.search(pattern, script_code):
                        suspicious_commands.append(pattern)

                # Phát hiện ký tự được mã hóa trong mã nguồn script
                for pattern in suspicious_encoding_patterns:
                    encoded_chars += re.findall(pattern, script_code)

        except FileNotFoundError:
            print(f"File not found: {script_path}")
        except UnicodeDecodeError:
            print(f"Unable to decode file: {script_path}")

        # In kết quả cho mỗi tệp script
        print(f"Script file: {script_file}")
        print("-------------------")
        if suspicious_commands:
            print("Suspicious commands found:")
            for command in suspicious_commands:
                print(command)
        else:
            print("No suspicious commands found")

        if encoded_chars:
            print("Encoded characters found:")
            for encoded_char in encoded_chars:
                print(encoded_char)
        else:
            print("No encoded characters found")

        print("-------------------")

    print("\n[[ Check file ]]\n")
    # Danh sách các mẫu nghi ngờ cho các lệnh
    suspicious_command_patterns = [
        r"rm\s+.*",
        r"mv\s+.*",
        r"cp\s+.*",
        r"wget\s+.*",
        r"curl\s+.*",
        r"git\s+.*",
        r"chmod\s+.*",
        r"chown\s+.*",
        r"ln\s+.*",
        r"echo\s+.*>\s+.*",
        r"touch\s+.*",
        r"cat\s+.*>>\s+.*",
        r"nc\s+-lvp\s+.*" ,
        r"dd\s+.*",
        r"mkfs\s+.*",
        r"mknod\s+.*",
        r"tar\s+.*",
        # Add other persistent attack patterns here
    ]

    # List of suspicious patterns for encoding
    suspicious_encoding_patterns = [
        r"base64\s+.*",
        r"gzip\s+.*",
        r"bzip2\s+.*",
        r"openssl\s+.*",
        r"xxd\s+.*",
        r"uudecode\s+.*",
        # Add other encoding patterns here
        r"tar\s+.*",
        r"zip\s+.*",
        r"7z\s+.*",
        r"rot13\s+.*",
        r"yenc\s+.*",
        r"bzcat\s+.*",
        r"unzip\s+.*",
        r"gunzip\s+.*",
        r"taz\s+.*",
        r"shar\s+.*",
        r"rar\s+.*",
        r"lzma\s+.*",
        r"lzcat\s+.*",
        r"lzop\s+.*",
        r"lzopcat\s+.*",
        # Add more encoding patterns here
    ]

    # Kết hợp các mẫu nghi ngờ
    suspicious_patterns = suspicious_command_patterns + suspicious_encoding_patterns

    # Hàm kiểm tra tệp tin để tìm lệnh nghi ngờ và ký tự mã hóa
    def check_file(file):
        suspicious_commands = []  # Danh sách các lệnh nghi ngờ
        try:
            with open(file, 'r') as f:  # Mở tệp tin để đọc
                lines = f.readlines()  # Đọc từng dòng trong tệp tin
                for line_number, line in enumerate(lines, start=1):
                    if not line.strip().startswith("#"):  # Bỏ qua các dòng bắt đầu bằng "#"
                        for pattern in suspicious_command_patterns:
                            if re.search(pattern, line):  # Tìm kiếm mẫu lệnh nghi ngờ trong dòng
                                suspicious_commands.append((line_number, line.strip()))  # Thêm lệnh nghi ngờ vào danh sách
                                break

                        # Phát hiện ký tự đã được mã hóa
                        encoded_chars = re.findall(r"\\x[0-9a-fA-F]{2}", line)
                        if encoded_chars:
                            suspicious_commands.append((line_number, f"Có ký tự mã hóa: {', '.join(encoded_chars)}"))

            if not suspicious_commands:
                print("Không tìm thấy lệnh nghi ngờ hoặc ký tự đã mã hóa")
        except FileNotFoundError:
            print(f"Tệp tin không tồn tại: {file}")

        return suspicious_commands


    # Hàm kiểm tra danh sách các tệp tin để tìm lệnh nghi ngờ và ký tự mã hóa
    def check_files(files):
        for file in files:
            print(f"Đang kiểm tra tệp tin: {file}")
            print("-------------------")
            suspicious_commands = check_file(file)  # Kiểm tra từng tệp tin
            for line_number, command in suspicious_commands:
                print(f"Dòng {line_number}: {command}")  # In ra dòng chứa lệnh nghi ngờ
            print("-------------------")

    # Danh sách các tệp tin cụ thể của người dùng
    user_files = [
        "/root/.bash_profile",
        "/root/.bash_login",
        "/root/.profile",
        "/root/.bashrc",
        "/root/.bash_logout"
    ]

    # Danh sách các tệp tin hệ thống (yêu cầu quyền root)
    system_files = [
        "/etc/bash.bashrc",
        "/etc/bash.bash_logout",
        "/etc/profile"
    ]

    # Kiểm tra các tệp tin cụ thể của người dùng
    check_files(user_files)

    # Kiểm tra các tệp tin hệ thống
    check_files(system_files)


def webshellScanner(path, valid_regex):
    # Smallest filesize to checkfor in bytes.  
    smallest = 8
    # Instantiate the Generator Class used for searching, opening, and reading files
    locator = SearchFile()
    tests = []
    # Error on an invalid path
    if os.path.exists(path) == False:
       parser.error("Invalid path")
    if valid_regex == False:
       valid_regex = re.compile('(\.php|\.asp|\.aspx|\.scath|\.bash|\.zsh|\.csh|\.tsch|\.pl|\.py|\.txt|\.cgi|\.cfm|\.htaccess)$')
    else:        
       try:
          valid_regex = re.compile(valid_regex)
       except:
          parser.error("Invalid regular expression")
    tests.append(LanguageIC())
    tests.append(Entropy())
    tests.append(LongestWord())
    tests.append(SignatureNasty())
    tests.append(SignatureSuperNasty())
    # Grab the file and calculate each test against file
    fileCount = 0
    fileIgnoreCount = 0
    for data, filename in locator.search_file_path(path, valid_regex, smallest):
        if data:
               for test in tests:
                   calculated_value = test.calculate(data, filename)
               fileCount = fileCount + 1
    # Print some stats
    print("\n[*]----------------------[[ WebShell Scan ]]----------------------[*]")
    print("\n[[ Total files scanned: %i ]]" % (fileCount))
    print("\n[[ Total files ignored: %i ]]" % (fileIgnoreCount))
 

    # Print top rank lists
    rank_list = {}
    for test in tests:
        test.sort()
        test.printer(10)
        for file in test.results:
            rank_list[file["filename"]] = rank_list.setdefault(file["filename"], 0) + file["rank"]

    rank_sorted = sorted(list(rank_list.items()), key=lambda x: x[1])

    print("\n[[ Top cumulative ranked files ]]")
    count = 10
    if (count > len(rank_sorted)): count = len(rank_sorted)
    for x in range(count):
        print(' {0:>7}        {1}'.format(rank_sorted[x][1], rank_sorted[x][0]))
class LanguageIC:
   """Class that calculates a file's Index of Coincidence as
   as well as a a subset of files average Index of Coincidence.
   """
   def __init__(self):
       """Initialize results arrays as well as character counters."""
       self.char_count =  defaultdict(int)
       self.total_char_count = 0
       self.results = []
       self.ic_total_results = ""

   def calculate_char_count(self,data):
       """Method to calculate character counts for a particular data file."""
       if not data:
           return 0
       for x in range(256):
           char = chr(x)
           charcount = data.count(char)
           self.char_count[char] += charcount
           self.total_char_count += charcount
       return

   def calculate_IC(self):
       """Calculate the Index of Coincidence for the self variables"""
       total = 0
       for val in list(self.char_count.values()):

           if val == 0:
               continue
           total += val * (val-1)

       try:
           ic_total =      float(total)/(self.total_char_count * (self.total_char_count - 1))
       except:
           ic_total = 0
       self.ic_total_results = ic_total
       return

   def calculate(self,data,filename):
       """Calculate the Index of Coincidence for a file and append to self.ic_results array"""
       
       if not data:
           return 0
       char_count = 0
       total_char_count = 0

       for x in range(256):
           char = chr(x)
           charcount = data.count(char)
           char_count += charcount * (charcount - 1)
           total_char_count += charcount

       ic = float(char_count)/(total_char_count * (total_char_count - 1))
       self.results.append({"filename":filename, "value":ic})
       # Call method to calculate_char_count and append to total_char_count
       self.calculate_char_count(data)
       return ic

   def sort(self):
       self.results.sort(key=lambda item: item["value"])
       self.results = resultsAddRank(self.results)

   def printer(self, count):
       """Print the top signature count match files for a given search"""
       # Calculate the Total IC for a Search
       self.calculate_IC()
       print("\n[[ Average IC for Search ]]")
       print(self.ic_total_results)
       print("\n[[ Top %i lowest IC files ]]" % (count))
       if (count > len(self.results)): count = len(self.results)
       for x in range(count):
           print(' {0:>7.4f}        {1}'.format(self.results[x]["value"], self.results[x]["filename"]))
       return

class Entropy:
   """Class that calculates a file's Entropy."""

   def __init__(self):
       """Instantiate the entropy_results array."""
       self.results = []

   def calculate(self,data,filename):
       """Calculate the entropy for 'data' and append result to entropy_results array."""

       if not data:
           return 0
       entropy = 0
       self.stripped_data =data.replace(' ', '')
       for x in range(256):
           p_x = float(self.stripped_data.count(chr(x)))/len(self.stripped_data)
           if p_x > 0:
               entropy += - p_x * math.log(p_x, 2)
       self.results.append({"filename":filename, "value":entropy})
       return entropy

   def sort(self):
       self.results.sort(key=lambda item: item["value"])
       self.results.reverse()
       self.results = resultsAddRank(self.results)

   def printer(self, count):
       """Print the top signature count match files for a given search"""
       print("\n[[ Top %i entropic files for a given search ]]" % (count))
       if (count > len(self.results)): count = len(self.results)
       for x in range(count):
           print(' {0:>7.4f}        {1}'.format(self.results[x]["value"], self.results[x]["filename"]))
       return

class LongestWord:
   """Class that determines the longest word for a particular file."""
   def __init__(self):
       """Instantiate the longestword_results array."""
       self.results = []

   def calculate(self,data,filename):
       """Find the longest word in a string and append to longestword_results array"""
       if not data:
           return "", 0
       longest = 0
       longest_word = ""
       words = re.split("[\s,\n,\r]", data)
       if words:
           for word in words:
               length = len(word)
               if length > longest:
                   longest = length
                   longest_word = word
       self.results.append({"filename":filename, "value":longest})
       return longest

   def sort(self):
       self.results.sort(key=lambda item: item["value"])
       self.results.reverse()
       self.results = resultsAddRank(self.results)

   def printer(self, count):
       """Print the top signature count match files for a given search"""
       print("\n[[ Top %i longest word files ]]" % (count))
       if (count > len(self.results)): count = len(self.results)
       for x in range(count):
           print(' {0:>7}        {1}'.format(self.results[x]["value"], self.results[x]["filename"]))
       return

class SignatureNasty:
   """Generator that searches a given file for nasty expressions"""

   def __init__(self):
       """Instantiate the results array."""
       self.results = []

   def calculate(self, data, filename):
       if not data:
           return "", 0
       # Lots taken from the wonderful post at http://stackoverflow.com/questions/3115559/exploitable-php-functions
       valid_regex = re.compile('(eval\(|file_put_contents|base64_decode|python_eval|exec\(|passthru|popen|proc_open|pcntl|assert\(|system\(|shell)', re.I)
       matches = re.findall(valid_regex, data)
       self.results.append({"filename":filename, "value":len(matches)})
       return len(matches)

   def sort(self):
       self.results.sort(key=lambda item: item["value"])
       self.results.reverse()
       self.results = resultsAddRank(self.results)

   def printer(self, count):
       """Print the top signature count match files for a given search"""
       print("\n[[ Top %i signature match counts ]]" % (count))
       if (count > len(self.results)): count = len(self.results)
       for x in range(count):
           print(' {0:>7}        {1}'.format(self.results[x]["value"], self.results[x]["filename"]))
       return

class SignatureSuperNasty:
   """Generator that searches a given file for SUPER-nasty expressions (These are almost always bad!)"""

   def __init__(self):
       """Instantiate the results array."""
       self.results = []

   def calculate(self, data, filename):
       if not data:
           return "", 0
       valid_regex = re.compile('(@\$_\[\]=|\$_=@\$_GET|\$_\[\+""\]=)', re.I)
       matches = re.findall(valid_regex, data)
       self.results.append({"filename":filename, "value":len(matches)})
       return len(matches)

   def sort(self):
       self.results.sort(key=lambda item: item["value"])
       self.results.reverse()
       self.results = resultsAddRank(self.results)

   def printer(self, count):
       """Print the top signature count match files for a given search"""
       print("\n[[ Top %i SUPER-signature match counts (These are usually bad!) ]]" % (count))
       if (count > len(self.results)): count = len(self.results)
       for x in range(count):
           print(' {0:>7}        {1}'.format(self.results[x]["value"], self.results[x]["filename"]))
       return

def resultsAddRank(results):
   rank = 1
   offset = 1
   previousValue = False
   newList = []
   for file in results:
       if (previousValue and previousValue != file["value"]):
           rank = offset
       file["rank"] = rank
       newList.append(file)
       previousValue = file["value"]
       offset = offset + 1
   return newList

class SearchFile:
   """Generator that searches a given filepath with an optional regular
   expression and returns the filepath and filename"""
   def search_file_path(self, path, valid_regex, smallest):
       for root, dirs, files in os.walk(path):
           for file in files:
               filename = os.path.join(root, file)
               if not os.path.exists(filename):
                 continue;
               if (valid_regex.search(file) and os.path.getsize(filename) > smallest):
                   try:
                       data = open(root + "/" + file, 'rb').read()
                       data = data.decode('utf-8')
                   except:
                       data = False
                       print("Could not read file :: %s/%s" % (root, file))
                   yield data, filename

if __name__ == "__main__":
   """Parse all the args"""

   timeStart = time.process_time()

   print("""

                                   )                                
  *   )   )                 )   ( /(               )                
` )  /(( /( (     (    ) ( /(   )\())  (        ( /((        (  (   
 ( )(_))\()))(   ))\( /( )\()) ((_)\  ))\  (    )\())\  (    )\))(  
(_(_()|(_)\(()\ /((_)(_)|_))/   _((_)/((_) )\ )(_))((_) )\ )((_))\  
|_   _| |(_)((_|_))((_)_| |_   | || (_))( _(_/(| |_ (_)_(_/( (()(_) 
  | | | ' \| '_/ -_) _` |  _|  | __ | || | ' \))  _|| | ' \)) _` |  
  |_| |_||_|_| \___\__,_|\__|  |_||_|\_,_|_||_| \__||_|_||_|\__, |  
                                                            |___/   

   """)

   parser = argparse.ArgumentParser()

   parser.add_argument("-a", "--all",
                     action="store_true",
                     dest="is_all",
                     default=False,
                     help="Run all scanner",)
   parser.add_argument("-s", "--ssh",
                     action="store_true",
                     dest="is_ssh",
                     default=False,
                     help="Run ssh scanner",)
   parser.add_argument("-r", "--rootkit",
                     action="store_true",
                     dest="is_rootkit",
                     default=False,
                     help="Run rootkit scanner",)
   parser.add_argument("-c", "--crontab",
                     action="store_true",
                     dest="is_crontab",
                     default=False,
                     help="Run crontab scanner",)
   parser.add_argument("-l", "--loginshell",
                     action="store_true",
                     dest="is_loginshell",
                     default=False,
                     help="Run login shell scanner",)
   parser.add_argument("-w", "--webshell",
                     action="store_true",
                     dest="is_webshell",
                     default=False,
                     help="Run web web shell scanner",)
   parser.add_argument("--dir",
                     action="store",
                     dest="directories",
                     default="",
                     help="Specify the directories to scan web shell",)
   parser.add_argument("--regex",
                     action="store",
                     dest="regex",
                     default=False,
                     nargs="*",
                     help="Specify the filename regex to scan web shell",)
   parser.add_argument("--hours",
                     action="store",
                     dest="hours",
                     default=24,
                     help="Number of hours to scan ssh",)
   parser.add_argument("--keys",
                     action="store",
                     dest="keys",
                     default=10,
                     help="Number of keys to scan ssh",)
   args = parser.parse_args()
   # Error on invalid number of arguments
   if args == None:
       parser.print_help()
       sys.exit(1)

   valid_regex = ""
   path = ""
   if args.is_all:
       hours = args.hours
       keys = args.keys
       path = args.directories
       valid_regex = args.regex
       sshScanner(keys, hours)
       crontabScanner()
       rootkitScanner()
       loginshellScanner()
       webshellScanner(path, valid_regex)
   else:
       if args.is_ssh:
          hours = args.hours
          keys = args.keys
          sshScanner(keys, hours)
       if args.is_rootkit:
           rootkitScanner()
       if args.is_crontab:
           crontabScanner()
       if args.is_loginshell:
           loginshellScanner()
       if args.is_webshell:
           path = args.directories
           valid_regex = args.regex
           webshellScanner(path, valid_regex)


   timeFinish = time.process_time()
   print("\n[[ Scan Time: %f seconds ]]" % (timeFinish - timeStart))

