#Kiểm tra xem các file trong /etc có chứa dữ liệu bị ẩn (cloaked data) hay không

import mmap
import os
import binascii

def process_file(file_path):
    try:
        # Kiểm tra dung lượng của tệp
        file_size = os.path.getsize(file_path)

        if file_size == 0:
            return

        with open(file_path, "r+b") as f:
            file_size_standard_io = 0
            for line in f:
                output = line
                file_size_standard_io += len(output)

            with open(file_path, "r+b") as f:
                map = mmap.mmap(f.fileno(), 0, access=mmap.PROT_READ)
                file_size_mmap = map.size()
                file_seek = 0
                while file_seek < file_size_mmap:
                    output = map.readline()
                    file_seek += len(output)

            if file_size_standard_io != file_size_mmap:
                print("\n********************************************************************************************")
                print("ALERT: {file_path}. File has cloaked data.")
                print("********************************************************************************************\n\n")
                return True  # Trả về True nếu có file có kích thước không khớp
    except FileNotFoundError:
        pass
    return False  # Trả về False nếu không có file nào bị lỗi

def process_directory(directory_path):
    for root, dirs, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            process_file(file_path)

def main():
    folder_path = '/etc'  # Đường dẫn đến thư mục cần kiểm tra
    any_mismatch = False  # Biến để kiểm tra xem có file nào có kích thước không khớp không

    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            if process_file(file_path):
                any_mismatch = True  # Nếu có file có kích thước không khớp, đặt any_mismatch thành True

    if not any_mismatch:
        print("\nOK: All files have matching sizes.\n\n")

if __name__ == '__main__':
    main()
