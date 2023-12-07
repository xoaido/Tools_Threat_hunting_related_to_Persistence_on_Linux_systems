import subprocess
import re

def run_journalctl():
    try:
        # Run the journalctl command and capture the output
        result = subprocess.run(['journalctl'], capture_output=True, text=True, check=True)

        # Use regular expression to find lines containing "insmod" and extract PWD and Module
        matches = re.finditer(r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<hostname>\w+) (?P<process>\w+)\[(?P<pid>\d+)\]:\s+(?P<user>\w+) : TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<command_user>\w+) ; COMMAND=/usr/sbin/insmod (?P<module>.+)', result.stdout)

        # Print the header
        print("Suspicious insmod activity found:")

        # Print PWD and Module for each match
        for match in matches:
            print(f"PWD: {match['pwd']}")
            print(f"Module: {match['module']}")
            print()

    except subprocess.CalledProcessError as e:
        # Handle the case where the command returns a non-zero exit code
        print(f"Error running journalctl: {e}")

if __name__ == "__main__":
    run_journalctl()
