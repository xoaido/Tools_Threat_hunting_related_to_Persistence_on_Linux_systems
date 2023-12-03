# Tools_Threat_hunting_related_to_Persistence_on_Linux_systems
You can read in links doc: https://docs.google.com/document/d/1x0k5LNzymP6upbX_BO9sqeR7BNSIZC9ib_GhcMPm4N8/edit
We utilise tools to track jobs scheduled using Cron on the system. By analysing cron files and examining scheduled tasks, we can detect suspicious Persistence-related activities such as the creation of new unauthorised jobs or the modification of existing jobs.
Detection method: 
Scheduled processes that have the following statements are considered dangerous:
Malicious code often exists in this directory ( /tmp/* )
These are commonly used commands to connect to the internet:( Curl, @, dig, http?://*, nc, wget)
Used to run a shell on the system( *|*sh, *sh -c )
Insert and encode commands(base64, ^M^M)
Search for very long strings, which may indicate encoding. 


Rootkit Example (For Educational Purpose Only):
https://github.com/MatthiasCr/LKM-Rootkit<br>
https://github.com/m0nad/Diamorphine<br>
https://github.com/f0rb1dd3n/Reptile<br>
