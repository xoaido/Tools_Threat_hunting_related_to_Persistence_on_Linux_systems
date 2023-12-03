import re

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

        if not suspicious_commands and not non_sh_calls:
            print("No suspicious commands, encoded characters, or non-.sh file calls found")
        else:
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
    except FileNotFoundError:
        print(f"File not found: {file}")

    return suspicious_commands

# Function to check a list of files for suspicious commands, encoded characters, and non-.sh file calls
def check_files(files):
    for file in files:
        print(f"Checking file: {file}")
        print("-------------------")
        suspicious_commands = check_file(file)
        print("-------------------")


# List of user-specific files (đã có trong đoạn mã)
user_files = [
    "/root/.bash_profile",
    "/root/.bash_login",
    "/root/.profile",
    "/root/.bashrc",
    "/root/.bash_logout"
]

# List of system-wide files (đã có trong đoạn mã)
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

# Check user-specific files
check_files(user_files)

# Check system-wide files
check_files(system_files)
