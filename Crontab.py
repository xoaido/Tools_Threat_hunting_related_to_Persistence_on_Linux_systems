import math
import sys
import os
import re
import csv
import zlib
import time
from collections import defaultdict
from optparse import OptionParser

#
# Globals
#
   
# Smallest filesize to checkfor in bytes.  
SMALLEST = 60
def resultsAddRank(results):
   rank = 1
   offset = 1
   previousValue = False
   newList = []
   for file in results:
       if (previousValue and previousValue != file["value"]):
           rank = offset
       file["rank"] = rank
       newList.append(file)
       previousValue = file["value"]
       offset = offset + 1
   return newList

class SignatureNasty:
   """Generator that searches a given file for nasty expressions"""

   def __init__(self):
       """Instantiate the results array."""
       self.results = []
   
   def calculate(self, data, filename):
       file_path = "/etc/crontab"
       try:
           with open(file_path, 'r') as file:
               data = file.read()
               if not data:
                   return 0
               valid_regex = re.compile('(/tmp/*|curl|@|dig|http?://*|nc|^M|base64|*sh|*sh -c)', re.I)
               matches = re.findall(valid_regex, data)
               self.results.append({"filename": file_path, "value": len(matches)})
               return len(matches)
       except Exception as e:
           return f"Error: {str(e)}"

   def sort(self):
       self.results.sort(key=lambda item: item["value"])
       self.results.reverse()
       self.results = resultsAddRank(self.results)

   def printer(self, count):
       """Print the top signature count match files for a given search"""
       print("\n[[ Top %i signature match counts ]]" % (count))
       if (count > len(self.results)): count = len(self.results)
       for x in range(count):
           a=0
           print(a)
           print(' {0:>7}        {1}'.format(self.results[x]["value"], self.results[x]["filename"]))
           a+=1
       return
if __name__ == "__main__":
    result = SignatureNasty()
    result.printer(10)