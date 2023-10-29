Function 1: Finding Private Keys (Check find_ssh_private_keys)
    In particular, private keys in a user's home directory on a shared system is a major risk. If any account gets compromised, 
attackers will immediately search for private SSH keys lying about for all users.
The keys may be encrypted, but still it would be worth asking if the user requires their private key to be on a system, especially 
if that system is shared with multiple users.
   This function find the private key in folder .ssh of all home directories


Function 2: SSH authorized_keys2 Files (Find authorized_key2)
    There is an SSH authorized_keys2 file that works like authorized_keys but is deprecated. If this file exists, it may still allow 
login on older servers. Its presence is almost always a malicious attempt to conceal access.If you see this file in a user's home 
directory you should be asking some pointed questions. If the user doesn't know why the file is there then the system should be immediately
investigated.
    This function helps you to find authorized_keys2 file in folder .ssh of all home directories


Function 3: Duplicate Keys (Check duplicated key in authorized_keys file)
    A duplicate SSH key present in authorized_keys is what happens when a key is present two or more times. What that means is if 
you delete a key with the intent of disallowing future logins, the unnoticed duplicates will still allow the key holder to login to the host.
This may happen because of some mistakes below: 
- User pastes in a key that is already present but they didn't know.
- A system automation tool managing key files makes an error and inserts a key one or more times.
- A backup is restored that has an old authorized_keys file with a duplicate key present.
- A piece of malware inserts a backdoor key one or more times because they are not checking if they have already dropped their key.

   Duplicate keys are a unique threat because unlike changing a password, removing a key may not prevent login if it still remains. Because 
of the difficulty in spotting this kind of situation it must be automated.
   This function helps you to check whether your keys are duplicated by counting the appearance of them in file authorized_keys


Function 4: Excessive Keys (Check excessive key in authorized_keys file (10 keys here))
    Users that have too many keys in the authorized_keys file are another potential attack vector. This causes a multitude of problems,
the main one being that many people can log in as the same username and this makes auditing much harder.
What is an excessive number of keys? Well, we think one key for one user is the limit. But in reality it just depends on your organization.
We have seen usernames with nearly a hundred keys that allowed people to login as them. We chose the maximun number of keys here is: 10, you
can decide base on your organization.
    This function will search all local users home directories for authorized_keys files that have 10 or more keys present as a starting point.



Function 5: SSH Key Options (Check for option set in authorized_keys file)
    These options in particular need to be closely watched in this function:
    - agent-forwarding - Can allow someone controlling the remote system to impersonate the user logging in and it should be configured correctly to be secure.
    - command - Can allow someone to run commands as the user when they login with this key.
    - environment - Can allow setting of environment variables for the user logging in with the key. This can cause security issues if the remote server allows them to be passed into the terminal session.
    - port-forwarding - Can allow client system to forward ports bypassing firewalls and network controls.
    - user-rc - Can allow system to run ~/.ssh/rc upon login to execute commands as the user.
    - X11-forwarding - Permits X11 protocol to be forwarded over SSH, again bypassing firewall and network controls.
    In this function, we check file authorized_keys to find options that may expose risks by using Regex


Function 6: Check for the modification of authorized_keys file in a limited time (24h here) (Optional)
    In this function, we chose 24h as limited time to check whether authorized_keys file changed. You can set up base on your organization.
