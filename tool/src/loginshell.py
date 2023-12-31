import os
import re
import colorama
def loginshellScanner():
    # Check for root privileges
    if os.geteuid() != 0:
        print("\nThis script must be run as root.")
        return
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
        r"nc\s+-lvp\s+.*",
        r"dd\s+.*",
        r"mkfs\s+.*",
        r"mknod\s+.*",
        r"tar\s+.*",
        r"sudo\s+.*",
        r"shutdown\s+.*",
        r"reboot\s+.*",
        r"kill\s+.*",
        r"pkill\s+.*",
        #r"ps\s+.*",
        #r"top\s+.*",
        r"ifconfig\s+.*",
        r"iptables\s+.*",
        r"useradd\s+.*",
        r"userdel\s+.*",
        r"groupadd\s+.*",
        r"groupdel\s+.*",
        r"passwds+.*",
        r"su\s+.*",
        r"sudoers\s+.*",
        r"visudo\s+.*",
        r"crontab\s+.*",
        #r"at\s+.*",
        r"systemctl\s+.*",
        r"journalctl\s+.*",
        r"service\s+.*",
        r"init\s+.*",
        r"ssh\s+.*",
        r"scp\s+.*",
        r"rsync\s+.*",
        r"ftp\s+.*",
        r"telnet\s+.*",
        r"nmap\s+.*",
        r"tcpdump\s+.*",
        r"wireshark\s+.*",
        r"traceroute\s+.*",
        r"ping\s+.*",
        r"whois\s+.*",
        r"nslookup\s+.*",
        r"dig\s+.*",
        r"host\s+.*",
        r"curl\s+--proxy\s+.*",
        r"wget\s+--proxy\s+.*",
        # Add other suspicious command patterns here
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

    # Combine the suspicious patterns
    suspicious_patterns = suspicious_command_patterns + suspicious_encoding_patterns

    # Define the comment pattern
    comment_pattern = r"^\s*#.*"

    # Perform identification and analysis of script files in /etc/profile.d/
    script_directory = "/etc/profile.d/"
    script_files = [f for f in os.listdir(script_directory) if os.path.isfile(os.path.join(script_directory, f))]

    # Store the results for each script file
    results = []

    # Analyze the source code of each script file
    for script_file in script_files:
        script_path = os.path.join(script_directory, script_file)

        # Check if the file has a valid extension
        file_extension = os.path.splitext(script_file)[1]
        if file_extension not in ['.sh', '.csh', '.bash', '.ksh', '.zsh']:
            print(f"File {script_file} has an invalid extension.")
            continue

        suspicious_commands = []
        encoded_chars = []
        try:
            with open(script_path, 'r', encoding='latin-1') as f:
                script_lines = f.read().splitlines()
                script_code = ""
                for line in script_lines:
                    if not re.match(comment_pattern, line):
                        script_code += line + "\n"

                # Check for suspicious commands
                for pattern in suspicious_command_patterns:
                    matches = re.findall(pattern, script_code)
                    if matches:
                        for match in matches:
                            suspicious_commands.append(match.strip())

                # Detect encoded characters
                for pattern in suspicious_encoding_patterns:
                    encoded_chars += re.findall(pattern, script_code)

        except FileNotFoundError:
            results.append((script_file, "File not found"))
        except UnicodeDecodeError:
            results.append((script_file, "Unable to decode file"))

        # Store the results for each script file
        if suspicious_commands or encoded_chars:
            results.append((script_file, suspicious_commands, encoded_chars))

    # Print the results for each script file
    if results:
        print("Suspicious files:")
        for result in results:
            script_file, suspicious_commands, encoded_chars = result
            print(f"Script file: {script_file}")
            print("-------------------")
            if suspicious_commands:
                print("Suspicious commands found:")
                for command in suspicious_commands:
                    print(f"Command: {command}")
            if encoded_chars:
                print("Encoded characters found:")
                for encoded_char in encoded_chars:
                    print(encoded_char)
            print("-------------------")
    else:
        print(colorama.Fore.LIGHTGREEN_EX + "===> No suspicious files found" + colorama.Fore.RESET)

    print("\n[[ Check file ]]\n")
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
        #r"cat\s+.*>>\s+.*",
        r"nc\s+-lvp\s+.*",
        r"dd\s+.*",
        r"mkfs\s+.*",
        r"mknod\s+.*",
        r"tar\s+.*", 
        #r"sudo\s+.*",
        r"shutdown\s+.*",
        r"reboot\s+.*",
        r"kill\s+.*",
        r"pkill\s+.*",
        #r"ps\s+.*",
        r"top\s+.*",
        r"ifconfig\s+.*",
        r"iptables\s+.*",
        r"useradd\s+.*",
        r"userdel\s+.*",
        r"groupadd\s+.*",
        r"groupdel\s+.*",
        r"passwds+.*",
        r"su\s+.*",
        r"sudoers\s+.*",
        r"visudo\s+.*",
        r"crontab\s+.*",
        #r"at\s+.*",
        r"systemctl\s+.*",
        r"journalctl\s+.*",
        r"service\s+.*",
        r"ssh\s+.*",
        r"scp\s+.*",
        r"rsync\s+.*",
        r"ftp\s+.*",
        r"telnet\s+.*",
        r"nmap\s+.*",
        r"tcpdump\s+.*",
        r"wireshark\s+.*",
        r"traceroute\s+.*",
        r"ping\s+.*",
        r"whois\s+.*",
        r"nslookup\s+.*",
        r"dig\s+.*",
        r"host\s+.*",
        r"curl\s+--proxy\s+.*",
        r"wget\s+--proxy\s+.*",
        # Add other suspicious command patterns here
    ]

    # List of suspicious patterns for encoding
    suspicious_encoding_patterns = [
        r"base64\s+.*",
        r"gzip\s+.*",
        r"bzip2\s+.*",
        r"openssl\s+.*",
        r"xxd\s+.*",
        r"uudecode\s+.*",
        # Add other suspicious encoding patterns here
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

    # Combine the suspicious patterns
    suspicious_patterns = suspicious_command_patterns + suspicious_encoding_patterns

    # Function to check a file for suspicious commands, encoded characters, and non-.sh file calls
    def check_file(file):
        suspicious_commands = []
        non_sh_calls = []
        try:
            with open(file, 'r') as f:
                lines = f.readlines()
                for line_number, line in enumerate(lines, start=1):
                    if not line.strip().startswith("#"):
                        is_suspicious = False
                        for pattern in suspicious_patterns:
                            if re.search(pattern, line):
                                suspicious_commands.append((line_number, line.strip()))
                                is_suspicious = True
                                break

                        # Detect encoded characters
                        encoded_chars = re.findall(r"\\x[0-9a-fA-F]{2}", line)
                        if encoded_chars and not is_suspicious:
                            suspicious_commands.append((line_number, f"Encoded characters found: {', '.join(encoded_chars)}"))

                        # Check for non-.sh file calls
                        matches = re.findall(r"\b(\w+\.\w+)\b", line)
                        for match in matches:
                            if not match.endswith(".sh"):
                                non_sh_calls.append((line_number, line.strip()))
                                break

            if suspicious_commands or non_sh_calls:
                print(f"Check suspicious files: {file}")
                print("-------------------")
                if non_sh_calls:
                    print("Non-.sh file calls:")
                    for line_number, command in non_sh_calls:
                        print(f"Line {line_number}: {command}")
                    print("-------------------")
                if suspicious_commands:
                    print("Suspicious commands or encoded characters:")
                    for line_number, command in suspicious_commands:
                        print(f"Line {line_number}: {command}")
                    print("-------------------")
                return True  # Return True if suspicious commands or non-.sh file calls are found
        except FileNotFoundError:
            pass

        return False  # Return False if no suspicious commands or non-.sh file calls are found

    # Function to check a list of files for suspicious commands, encoded characters, and non-.sh file calls
    def check_files(files):
        suspicious_files_found = False  # Flag to track if any suspicious files are found
        for file in files:
            if check_file(file):
                suspicious_files_found = True

        if not suspicious_files_found:
            print(colorama.Fore.LIGHTGREEN_EX + "===> No suspicious files found" + colorama.Fore.RESET)

    # List of user-specific files 
    user_files = [
        "/root/.bash_profile",
        "/root/.bash_login",
        "/root/.profile",
        "/root/.bashrc",
        "/root/.bash_logout"
    ]

    # List of system-wide files 
    system_files = [
        "/etc/bash.bashrc",
        "/etc/bash.bash_logout",
        "/etc/profile",
        "/etc/shells",
        "/etc/bashrc",
        "/etc/zsh/zprofile",
        "/etc/zsh/zshrc",
        "/etc/zsh/zlogin",
        "/etc/zsh/zlogout",
        "/etc/csh.cshrc",
        "/etc/csh.login"
    ]


    # Check user-specific files and system-wide files
    check_files(user_files + system_files)
