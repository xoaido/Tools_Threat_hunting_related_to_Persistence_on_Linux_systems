import os
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
    print("No suspicious files found")
