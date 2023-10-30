import subprocess
import os

# Đọc nội dung của tệp /etc/modules-load.d/modules.conf
print("Kiểm tra file /etc/modules:")
modules_conf_path = '/etc/modules-load.d/modules.conf'
try:
    with open(modules_conf_path, 'r') as modules_file:
        modules_content = modules_file.read()
        print(f"Contents of {modules_conf_path}:\n{modules_content}")
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
    print(f"Nội dung của {systemd_directory}:\n{result.stdout}")
except subprocess.CalledProcessError as e:
    print(f"Error executing 'ls' command: {e}")
except Exception as e:
    print(f"An error occurred while listing {systemd_directory}: {e}")

# Thực hiện câu lệnh systemctl list-unit-files --type=service | grep enable
try:
    systemctl_command = "systemctl list-unit-files --type=service | grep enable"
    result = subprocess.run(systemctl_command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"Hiển thị danh sách các service có trên hệ thống và đang được enable:\n{result.stdout}")
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
print("Liệt kê tất cả các file .ko nghi ngờ trên hệ thống:")
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
