#Kiểm tra các module được load sử dụng câu lệnh lsmod, sau đó so sánh với các module bình thường trong danh sách whitelist, từ đó cho biết module nào đáng ngờ đang được load
import subprocess

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
print("Đây là các module bất thường:")
for module in module_names:
    print(module)
