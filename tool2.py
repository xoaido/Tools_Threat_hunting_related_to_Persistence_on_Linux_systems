#Kiểm tra xem các directory chứa module có quyền write cho Group hoặc Other không

import subprocess
import re

# Sử dụng lệnh lsmod để liệt kê tất cả các module
lsmod_output = subprocess.check_output("lsmod", shell=True, text=True)

# Chia đầu ra thành từng dòng và loại bỏ dòng đầu tiên (tiêu đề)
lsmod_lines = lsmod_output.splitlines()[1:]

# Tìm tên module từ dòng còn lại
module_names = [line.split()[0] for line in lsmod_lines]

# Duyệt qua từng tên module và sử dụng lệnh modinfo để lấy thông tin
print("Danh sách các module đáng ngờ:")
for module_name in module_names:
    try:
        modinfo_output = subprocess.check_output(f"modinfo {module_name}", shell=True, text=True)

        # Sử dụng biểu thức chính quy để tìm trường "filename"
        filename_match = re.search(r'filename:\s+(?P<filename>.+)', modinfo_output)
        if filename_match:
            module_directory = "/".join(filename_match.group("filename").split("/")[:-1])

            # Sử dụng lệnh ls -ld để lấy thông tin về quyền của thư mục
            ls_output = subprocess.check_output(f"ls -ld {module_directory}", shell=True, text=True)

            # Kiểm tra xem Group và Other có quyền Write hay không
            if "w" in ls_output[5] or "w" in ls_output[8]:
                # Nếu không có quyền Write, thì in thông tin
                print(f"Module: {module_name}")
                print(f"Module Directory: {module_directory}")
                print(f"Directory Permissions: {ls_output.split()[0]}")
                print("=" * 80)  # Dấu phân cách giữa các module
        else:
            print(f"Không thể tìm thấy filename cho module {module_name}")
    except subprocess.CalledProcessError as e:
        print(f"Không thể lấy thông tin cho module {module_name}: {e}")
