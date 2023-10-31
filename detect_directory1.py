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
