import subprocess
import re

# Chạy lệnh crontab -l để lấy nội dung crontab hiện tại
try:
    crontab_output = subprocess.check_output(["crontab", "-l"], stderr=subprocess.STDOUT, text=True)
    print("Nội dung crontab:")
    print(crontab_output)

    # Tìm các dòng lập lịch chứa các ký tự đặc biệt hoặc chuỗi cụ thể
    lines = crontab_output.split('\n')
    
    for line in lines:
        is_malicious = False
        is_common_command = False
        is_long = False
        is_encoded = False

        # Kiểm tra độ dài dòng lập lịch
        if len(line) > 100:
            is_long = True

        # Kiểm tra nếu dòng lập lịch chứa "/tmp"
        if "/tmp" in line:
            is_malicious = True

        # Kiểm tra nếu dòng lập lịch chứa các lệnh "curl", "@", "dig", "http?://*", "nc", "wget"
        if re.search(r'(curl|@|dig|http\?://\*|nc|wget)', line):
            is_common_command = True

        # Kiểm tra nếu dòng lập lịch chứa ký tự mã hóa như "^M" hoặc "base64"
        if re.search(r'(\^M|base64)', line):
            is_encoded = True

        if is_long:
            print("Dòng lập lịch có độ dài trên 100 ký tự:")
            print(line)
        elif is_malicious:
            print("Malicious code often exists in this directory:")
            print(line)
        elif is_common_command:
            print("These are commonly used commands to connect to the internet:")
            print(line)
        elif is_encoded:
            print("Dòng lập lịch chứa ký tự mã hóa:")
            print(line)
        else:
            print("Dòng lập lịch chứa ký tự đặc biệt hoặc chuỗi cụ thể:")
            print(line)

except subprocess.CalledProcessError as e:
    print(f"Lỗi: {e.returncode}\n{e.output}")
