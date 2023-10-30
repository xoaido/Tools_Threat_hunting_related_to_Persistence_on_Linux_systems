import re

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
    r"dd\s+.*",
    r"mkfs\s+.*",
    r"mknod\s+.*",
    r"tar\s+.*",
    # Thêm các mẫu tấn công khác ở đây
]

# Danh sách các mẫu nghi ngờ cho mã hóa
suspicious_encoding_patterns = [
    r"base64\s+.*",
    r"gzip\s+.*",
    r"bzip2\s+.*",
    r"openssl\s+.*",
    r"xxd\s+.*",
    r"uudecode\s+.*",
    # Thêm các mẫu mã hóa khác ở đây
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
