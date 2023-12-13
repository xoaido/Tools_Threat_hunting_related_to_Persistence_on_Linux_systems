# Tools: Threat hunting related to Persistence on Linux systems
Our product is an automated threat hunting tool designed for systems without a SIEM (Security Information and Event Management) system. 
It conducts scans on all systems connected to the identified techniques within its code. Operating independently of any monitoring system, 
the tool examines relevant files for anonymous information and promptly alerts the end user.

Basing on MITRE framework, we selected the 'Persistence' tactic as our initial focus, recognizing its significance as one of the most 
dangerous and critical steps in the progression of an attack. From that tactic, we develop 5 technique in this tool.
- SSH Deamon (T1098.004)
- Scheduled Task / Job: Cron (T1053.003)
- Login Shell (T1546.004)
- Malicious Loadable Kernel Modules (T1547.006 -LKMs)
- Webshells (T1505.003)

# Require
- This tool is only used for Linux system such as: Kali, Ubuntu, ...
- Python3 is required to running this tool.

# Install and Using this tool
- Download code from this Github repo
- This is the detail instrction to using this tool by terminal: 

usage: hunthreat.py [-h] [-a] [-s] [-r] [-c] [-l] [-w] [--dir DIRECTORIES]
                    [--regex REGEX] [--hours HOURS] [--keys KEYS]

options:
  -h, --help         show this help message and exit
  -a, --all          Run all scanner
  -s, --ssh          Run ssh scanner
  -r, --rootkit      Run rootkit scanner
  -c, --crontab      Run crontab scanner
  -l, --loginshell   Run login shell scanner
  -w, --webshell     Run web web shell scanner
  --dir DIRECTORIES  Specify the directories to scan web shell
  --regex REGEX      Specify the filename regex to scan web shell
  --hours HOURS      Number of hours to scan ssh
  --keys KEYS        Number of keys to scan ssh


Note: 
  When conducting Web Shell and SSH scans, you have more than one option. If you solely utilise the -r or -s option, the scan will default to the following information:

  --dir DIRECTORIES: The default specifies the directories for scan web shell: /var/www
  --regex REGEX: The default specify filename extension regex for scan web shell: (\.php|\.asp|\.aspx|\.scath|\.bash|\.zsh|\.csh|\.tsch|\.pl|\.py|\.txt|\.cgi|\.cfm|\.htaccess)
  -- hours HOURS: The default interval for checking the last modification of the authorized_keys file is set to 24 hours.
  -- keys KEYS: The default number of keys that exist in file authorized_keys is 10 keys.
   
