import os
import re
import colorama

def crontabScanner():
     print("\n[*]----------------------[[ CronTab Scan ]]---------------------------[*]")
     def get_username_from_path(path):
     # This function takes a path and returns the username from the path
          return os.path.basename(path)

     def print_user_header(username):
          print(f"\n[*]----------------------[[ User: {username} ]]----------------------[*]")

     def print_category_header(category_message):
          print(f"\n{colorama.Fore.LIGHTRED_EX}======> {category_message}{colorama.Fore.RESET}")

     def print_cron_line(line):
          print(f"Cron: {line}")
          print("--------------------------------------------------------------")

     
     # Check for root privileges
     if os.geteuid() != 0:
          print("This script requires root privileges. Please run it with sudo or as root.")
          return

     # List of paths containing cron files
     cron_paths = ["/etc/crontab"]
     
     user_cron_dir = "/var/spool/cron/crontabs"
     # Get a list of all users in the /var/spool/cron/crontabs directory
     users = [f for f in os.listdir(user_cron_dir) if os.path.isfile(os.path.join(user_cron_dir, f))]
     
     # Add cron paths for each user to the list
     cron_paths.extend([os.path.join(user_cron_dir, user) for user in users])
     # Add paths for files in /etc/cron.d
     etc_cron_d_dir = "/etc/cron.d"
     etc_cron_d_files = [f for f in os.listdir(etc_cron_d_dir) if os.path.isfile(os.path.join(etc_cron_d_dir, f))]

     # Add cron paths for each file in /etc/cron.d to the list
     cron_paths.extend([os.path.join(etc_cron_d_dir, file) for file in etc_cron_d_files])

     # Variable to check if there is any abnormal scheduling
     is_abnormal_schedule = False

     for cron_path in cron_paths:
          try:
                username = get_username_from_path(cron_path)
                print_user_header(username)

                with open(cron_path, 'r') as file:
                     crontab_output = file.read()
                     
                lines = crontab_output.split('\n')
                shell_count = 0  # Count of occurrences of SHELL=/bin/sh

                for line in lines:
                     # Skip lines starting with "#"
                     if line.startswith("#"):
                          continue

                     # Check if the cron line contains the configuration SHELL=/bin/sh
                     if "SHELL=/bin/sh" in line:
                          shell_count += 1

                          # If it appears a second time, issue a warning
                          if shell_count > 1:
                                print_category_header("Multiple SHELL=/bin/sh configurations:")
                                print(f"Number of SHELL=/bin/sh lines: {shell_count}")
                                is_abnormal_schedule = True
                                continue # Continue checking the next lines

                          continue  # Skip the common SHELL configuration line
                    #  is_malicious = False
                     is_common_command = False
                     is_long = False
                     is_encoded = False
                     is_shell_related = False
                     
                    #  # Check if the cron line contains "/tmp"
                    #  if "/tmp" in line:
                    #       is_malicious = True

                     # Check the length of the cron line
                     if len(line) > 200:
                          is_long = True

                     # Check if the cron line contains common commands like "curl", "@", "dig", "http?://*", "nc", "wget"
                     if re.search(r'(curl|@|dig|git|http[s]?|nc\s|wget)', line):
                          is_common_command = True

                     # Check if the cron line contains encoding characters like "^M" or "base64"
                     if re.search(r'(\^M|base64)', line):
                          is_encoded = True
                     #Check if the cron string contains any of the listed executable file extensions or not
                     if re.search(r'(\|*sh|\*sh -c|\.php|\.asp|\.aspx|\.scath|\.bash|\.zsh|\.csh|\.tsch|\.pl|\.py|\.txt|\.cgi|\.cfm|\.htaccess)', line):
                          is_shell_related = True
                    # Check if the cron line contains an invalid schedule (e.g., 30/2, 31/2)
                     
                     # If any indicators are identified, print information for each type
                     if is_long:
                          print_category_header("Very long strings, which may indicate encoding:")
                          print_cron_line(line)
                          is_abnormal_schedule = True
                    #  if is_malicious:
                    #       print_category_header("Malicious code often exists in this directory:")
                    #       print_cron_line(line)
                    #       is_abnormal_schedule = True
                     if is_common_command:
                          print_category_header("These are commonly used commands to connect to the internet:")
                          print_cron_line(line)
                          is_abnormal_schedule = True
                     if is_encoded:
                          print_category_header("Insert and encode commands:")
                          print_cron_line(line)
                          is_abnormal_schedule = True
                     if is_shell_related:
                          print_category_header("Used to run a shell on the system")
                          print_cron_line(line)
                          is_abnormal_schedule = True

                
          except FileNotFoundError:
                print(f"File not found: {cron_path}")
          if not is_abnormal_schedule:
               print(colorama.Fore.LIGHTGREEN_EX + "==> Crontab does not have threat" + colorama.Fore.RESET)
     # Check and report if there is no abnormal scheduling
     if is_abnormal_schedule:
          print(colorama.Fore.LIGHTRED_EX + "==> Check Crontab done: Crontab does have threat" + colorama.Fore.RESET)
     else:
          print(colorama.Fore.LIGHTGREEN_EX + "==> Check Crontab done: Crontab does not have threat" + colorama.Fore.RESET)
