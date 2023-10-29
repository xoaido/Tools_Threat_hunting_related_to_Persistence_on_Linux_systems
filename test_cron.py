import subprocess
import re

# Chạy lệnh crontab -l để lấy nội dung crontab hiện tại
try:
    crontab_output = subprocess.check_output(["crontab", "-l"], stderr=subprocess.STDOUT, text=True)
    print("Nội dung crontab:")
    print(crontab_output)

    # Tìm các dòng lập lịch chứa các ký tự đặc biệt hoặc chuỗi cụ thể
    lines = crontab_output.split('\n')
    pattern = r'(/tmp/\*|curl|@|dig|http\?://\*|nc|\^M|base64|\*sh|\*sh -c)'
    # Tìm độ dài của command

    for line in lines:
        if re.search(pattern, line):
            # Kiểm tra nếu dòng lập lịch chứa "/tmp"
            if "/tmp" in line:
                print("Malicious code often exists in this directory:")
                print(line)
            else:
                print("Dòng lập lịch nghi ngờ")
                print(line)
except subprocess.CalledProcessError as e:
    print(f"Lỗi: {e.returncode}\n{e.output}")
