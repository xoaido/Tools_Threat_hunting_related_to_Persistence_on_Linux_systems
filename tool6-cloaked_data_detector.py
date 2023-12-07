import mmap
import os
import binascii

def process_file(file_path):
    try:
        # Check the size of the file
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
                print(f"ALERT: {file_path}. File has cloaked data.")
                print("********************************************************************************************\n\n")
                return True  # Return True if there is a file with mismatched size
    except FileNotFoundError:
        pass
    return False  # Return False if no files have an error

def process_directory(directory_path):
    for root, dirs, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            process_file(file_path)

def main():
    folder_path = '/etc'  # Path to the directory to be checked
    any_mismatch = False  # Variable to check if any files have mismatched sizes

    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            if process_file(file_path):
                any_mismatch = True  # If there is a file with mismatched size, set any_mismatch to True

    if not any_mismatch:
        print("\nOK: All files have matching sizes.\n\n")

if __name__ == '__main__':
    main()
