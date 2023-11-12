import subprocess
import re

def crontabScanner():
    print("\n[*]----------------------[[ CronTab Scan ]]----------------------[*]")
    # Chạy lệnh crontab -l để lấy nội dung crontab hiện tại
    try:
        crontab_output = subprocess.check_output(["crontab", "-l"], stderr=subprocess.STDOUT, text=True)
        # print("Nội dung crontab:")
        # print(crontab_output)
        # Tìm các dòng lập lịch chứa các ký tự đặc biệt hoặc chuỗi cụ thể
        lines = crontab_output.split('\n')
        
        # Tạo từ điển để lưu trữ các danh sách tương ứng
        matched_lines = {
            "is_long": [],
            "is_malicious": [],
            "is_common_command": [],
            "is_encoded": [],
            "is_shell_related": []
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
                matched_lines["is_long"].append(line)
            if is_malicious:
                matched_lines["is_malicious"].append(line)
            if is_common_command:
                matched_lines["is_common_command"].append(line)
            if is_encoded:
                matched_lines["is_encoded"].append(line)
            if is_shell_related:
                matched_lines["is_shell_related"].append(line)

        # In tất cả các danh sách tương ứng
        for key, value in matched_lines.items():
            if value:
                print(f"{key.capitalize()}:")
                for line in value:
                    print(f"  {line}")
                    print("-------------------")
                print()

    except subprocess.CalledProcessError as e:
        print(f"Lỗi: {e.returncode}\n{e.output}")

# Gọi hàm để kiểm tra crontab
crontabScanner()
