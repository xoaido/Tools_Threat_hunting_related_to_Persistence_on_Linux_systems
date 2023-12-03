#Kiểm tra các file .o hoặc .ko trên hệ thống
#Cập nhật hàm kiểm tra phiên bản hiện tại của Linux dựa vào đó tìm file .o hay .ko

import os
import subprocess
import platform
import re

# Thư mục gốc để bắt đầu tìm kiếm
root_dir = "/"

# Thư mục bạn muốn loại trừ khỏi tìm kiếm
excluded_dir = "/usr/lib/modules"

# Hàm kiểm tra tệp có phải là tệp kernel module hay không
def is_kernel_module(file_path):
    return file_path.endswith(".ko")

# Hàm kiểm tra phiên bản kernel có lớn hơn 2.6 hay không
def is_kernel_version_supported():
    kernel_version_str = platform.uname().release
    match = re.match(r'^(\d+\.\d+)', kernel_version_str)
    if match:
        kernel_version_numeric = match.group(1)
        major_version, minor_version = map(int, kernel_version_numeric.split('.')[:2])
        return major_version > 2 or (major_version == 2 and minor_version >= 6)
    return False

# Hàm thực hiện kiểm tra loại tệp sử dụng lệnh 'file'
def check_file_type(file_path):
    try:
        result = subprocess.check_output(["file", file_path], stderr=subprocess.STDOUT, universal_newlines=True)
        return result
    except subprocess.CalledProcessError as e:
        return e.output

# Bắt đầu tìm kiếm tệp .ko hoặc .o tùy thuộc vào phiên bản kernel
print("Liệt kê tất cả các file kernel module nghi ngờ trên hệ thống:")
for foldername, subfolders, filenames in os.walk(root_dir):
    # Kiểm tra xem thư mục hiện tại có nằm trong danh sách loại trừ không
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
