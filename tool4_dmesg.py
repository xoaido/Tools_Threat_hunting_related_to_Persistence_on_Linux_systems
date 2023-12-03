#Tìm kiếm các module nghi ngờ được load, sử dụng file log dmesg

import subprocess

def find_tainted_modules():
    try:
        # Run the 'dmesg' command and capture its output
        result = subprocess.run(['dmesg'], capture_output=True, text=True)

        # Check if the command was successful (return code 0)
        if result.returncode == 0:
            # Split the output into lines and iterate through them
            for line in result.stdout.splitlines():
                # Check if the line contains the specified text
                if "loading out-of-tree module taints kernel" in line:
                    # Split the line into fields and print the second field
                    fields = line.split()
                    result = fields[2].rstrip(':')
                    formatted_output = f"Suspicious kernel module loaded: {result}"
                    print(formatted_output)
        else:
            # Print an error message if the command failed
            print(f"Error running 'dmesg': {result.stderr}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Call the function to extract and print the second field from matching lines
find_tainted_modules()
