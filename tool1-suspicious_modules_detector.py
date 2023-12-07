# Check the loaded modules using the lsmod command, then compare them with the 
#normal modules in the whitelist, identifying suspiciously loaded modules
import subprocess

# Run the lsmod command and save the result to the output variable
output = subprocess.check_output(["lsmod"]).decode("utf-8")

# Split the result into lines
lines = output.split('\n')

# Read the list of modules from the module_list.txt file
with open("module_list.txt", "r") as file:
    excluded_modules = [line.strip() for line in file]

# Create an array to store module names
module_names = []

# Iterate through the lines and filter out modules not in the excluded_modules list
for line in lines:
    columns = line.split()
    if len(columns) >= 1:
        module_name = columns[0]
        if module_name not in excluded_modules:
            module_names.append(module_name)

# Print the list of module names
print("Here are the suspicious modules:")
for module in module_names:
    print(module)
