import os
import re
import math
import gzip
import colorama
import json
import requests
from time import sleep
from collections import defaultdict
from requests.packages.urllib3.exceptions import InsecureRequestWarning

def webshellScanner(path, valid_regex, api):
    # Smallest filesize to checkfor in bytes.
    smallest = 8
    # Instantiate the Generator Class used for searching, opening, and reading files
    locator = SearchFile()
    tests = []
    if path == "":
        path = "/var/www"
    # Error on an invalid path
    if os.path.exists(path) == False:
        os.error("Invalid path")
    if valid_regex == "":
        valid_regex = re.compile(
            "(\.php|\.asp|\.aspx|\.bash|\.zsh|\.csh|\.tsch|\.pl|\.py|\.txt|\.cgi|\.cfm|\.htaccess)$"
        )
    else:
        try:
            valid_regex = re.compile(valid_regex)
        except:
            os.error("Invalid regular expression")
    tests.append(LanguageIC())
    tests.append(Entropy())
    tests.append(LongestWord())
    tests.append(Signature())
    tests.append(SuperSignature())
    tests.append(SignatureInLog())
    # Grab the file and calculate each test against file
    fileCount = 0
    for data, filename in locator.search_file_path(path, valid_regex, smallest):
        if data:
            for test in tests:
                calculated_value = test.calculate(data, filename)
            fileCount = fileCount + 1
    # Print some stats
    print("\n[*]-------------------------[[ WebShell Scan ]]-------------------------[*]")
    print("\n[[ Total files scanned: %i ]]" % (fileCount))

    # Print top rank lists
    rank_list = {}
    for test in tests:
        test.sort()
        test.printer(10)
        for file in test.results:
            rank_list[file["filename"]] = (
                rank_list.setdefault(file["filename"], 0) + file["rank"]
            )

    rank_sorted = sorted(list(rank_list.items()), key=lambda x: x[1])

    print(
        colorama.Fore.LIGHTRED_EX
        + "\n[[ Top cumulative ranked files ]]"
        + colorama.Fore.RESET
    )
    count = 10
    if count > len(rank_sorted):
        count = len(rank_sorted)
    for x in range(count):
        print(" {0:>7}        {1}".format(x + 1, rank_sorted[x][0]))

    if api == True:
        if isConnectedWithInternet():
            print(
                colorama.Fore.LIGHTYELLOW_EX
                + "\n[[ Decode shell ]]"
                + colorama.Fore.RESET
            )
            for x in range(count):
                servicer = Servicer(rank_sorted[x][0])
                data = servicer.unphp()
                print(f"------File: {rank_sorted[x][0]}------")
                for key, value in data.items():
                    if key in ["md5", "functions", "variables", "eval_count"]:
                        print(" +",key, ": ", value, "\n")
            print(
                colorama.Fore.LIGHTYELLOW_EX
                + "\n[[ VirusTotal ]]"
                + colorama.Fore.RESET
            )
            for x in range(count//2):
                servicer = Servicer(rank_sorted[x][0])
                response = servicer.virustotal()
                if response:
                    print(
                        " {0:>7}           {1}".format(
                            colorama.Fore.RED
                            + colorama.Style.BRIGHT
                            + "Detected"
                            + colorama.Fore.RESET,
                            rank_sorted[x][0],
                        )
                    )
                else:
                    print(
                        " {0:>7}         {1}".format(
                            colorama.Fore.GREEN
                            + colorama.Style.BRIGHT
                            + "Undetected"
                            + colorama.Fore.RESET,
                            rank_sorted[x][0],
                        )
                    )

        else:
            print("NO INTERNET")


class LanguageIC:
    """Class that calculates a file's Index of Coincidence as
    as well as a subset of files average Index of Coincidence.
    """

    def __init__(self):
        """Initialize results arrays as well as character counters."""
        self.char_count = defaultdict(int)
        self.total_char_count = 0
        self.results = []
        self.ic_total_results = ""

    def calculate_char_count(self, data):
        """Method to calculate character counts for a particular data file."""
        if not data:
            return 0
        for x in range(256):
            char = chr(x)
            charcount = data.count(char)
            self.char_count[char] += charcount
            self.total_char_count += charcount
        return

    def calculate_IC(self):
        """Calculate the Index of Coincidence for the self variables"""
        total = 0
        for val in list(self.char_count.values()):

            if val == 0:
                continue
            total += val * (val - 1)

        try:
            ic_total = float(total) / (
                self.total_char_count * (self.total_char_count - 1)
            )
        except:
            ic_total = 0
        self.ic_total_results = ic_total
        return

    def calculate(self, data, filename):
        """Calculate the Index of Coincidence for a file and append to self.ic_results array"""

        if not data:
            return 0
        char_count = 0
        total_char_count = 0

        for x in range(256):
            char = chr(x)
            charcount = data.count(char)
            char_count += charcount * (charcount - 1)
            total_char_count += charcount

        ic = float(char_count) / (total_char_count * (total_char_count - 1))
        self.results.append({"filename": filename, "value": ic})
        # Call method to calculate_char_count and append to total_char_count
        self.calculate_char_count(data)
        return ic

    def sort(self):
        self.results.sort(key=lambda item: item["value"])
        # Check if there are at least 11 elements in the array
        if len(self.results) >= 11:
            # Loop through elements from index 10 to the end and set their values to 0
            for i in range(10, len(self.results)):
                self.results[i]["value"] = 0
        self.results = resultsAddRank(self.results)

    def printer(self, count):
        """Print the top signature count match files for a given search"""
        # Calculate the Total IC for a Search
        self.calculate_IC()
        print("\n[[ Average IC for Search ]]")
        print(self.ic_total_results)
        print("\n[[ Top %i lowest IC files ]]" % (count))
        if count > len(self.results):
            count = len(self.results)
        for x in range(count):
            print(
                " {0:>7.4f}        {1}".format(
                    self.results[x]["value"], self.results[x]["filename"]
                )
            )
        return


class Entropy:
    """Class that calculates a file's Entropy."""

    def __init__(self):
        """Instantiate the entropy_results array."""
        self.results = []

    def calculate(self, data, filename):
        """Calculate the entropy for 'data' and append result to entropy_results array."""

        if not data:
            return 0
        entropy = 0
        self.stripped_data = data.replace(" ", "")
        for x in range(256):
            p_x = float(self.stripped_data.count(chr(x))) / len(self.stripped_data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        self.results.append({"filename": filename, "value": entropy})
        return entropy

    def sort(self):
        self.results.sort(key=lambda item: item["value"])
        self.results.reverse()
        # Check if there are at least 11 elements in the array
        if len(self.results) >= 11:
            # Loop through elements from index 10 to the end and set their values to 0
            for i in range(10, len(self.results)):
                self.results[i]["value"] = 0
        self.results = resultsAddRank(self.results)

    def printer(self, count):
        """Print the top signature count match files for a given search"""
        print("\n[[ Top %i entropic files for a given search ]]" % (count))
        if count > len(self.results):
            count = len(self.results)
        for x in range(count):
            print(
                " {0:>7.4f}        {1}".format(
                    self.results[x]["value"], self.results[x]["filename"]
                )
            )
        return


class LongestWord:
    """Class that determines the longest word for a particular file."""

    def __init__(self):
        """Instantiate the longestword_results array."""
        self.results = []

    def calculate(self, data, filename):
        """Find the longest word in a string and append to longestword_results array"""
        if not data:
            return "", 0
        longest = 0
        longest_word = ""
        words = re.split("[\s,\n,\r]", data)
        if words:
            for word in words:
                length = len(word)
                if length > longest:
                    longest = length
                    longest_word = word
        self.results.append({"filename": filename, "value": longest})
        return longest

    def sort(self):
        self.results.sort(key=lambda item: item["value"])
        self.results.reverse()
        # Check if there are at least 11 elements in the array
        if len(self.results) >= 11:
            # Loop through elements from index 10 to the end and set their values to 0
            for i in range(10, len(self.results)):
                self.results[i]["value"] = 0
        self.results = resultsAddRank(self.results)

    def printer(self, count):
        """Print the top signature count match files for a given search"""
        print("\n[[ Top %i longest word files ]]" % (count))
        if count > len(self.results):
            count = len(self.results)
        for x in range(count):
            print(
                " {0:>7}        {1}".format(
                    self.results[x]["value"], self.results[x]["filename"]
                )
            )
        return


class Signature:
    """Generator that searches a given file for nasty expressions"""

    def __init__(self):
        """Instantiate the results array."""
        self.results = []

    def calculate(self, data, filename):
        if not data:
            return "", 0
        valid_regex = re.compile(
            "(eval\(|file_put_contents|preg_replace|base64_decode|python_eval|exec\(|passthru|popen|proc_open|AddType|pcntl|assert\(|system\(|shell)",
            re.I,
        )
        matches = re.findall(valid_regex, data)
        self.results.append({"filename": filename, "value": len(matches)})
        return len(matches)

    def sort(self):
        self.results.sort(key=lambda item: item["value"])
        self.results.reverse()
        # Check if there are at least 11 elements in the array
        if len(self.results) >= 11:
            # Loop through elements from index 10 to the end and set their values to 0
            for i in range(10, len(self.results)):
                self.results[i]["value"] = 0
        self.results = resultsAddRank(self.results)

    def printer(self, count):
        """Print the top signature count match files for a given search"""
        print("\n[[ Top %i signature match counts ]]" % (count))
        if count > len(self.results):
            count = len(self.results)
        for x in range(count):
            print(
                " {0:>7}        {1}".format(
                    self.results[x]["value"], self.results[x]["filename"]
                )
            )
        return


class SuperSignature:
    """Generator that searches a given file for SUPER-nasty expressions (These are almost always bad!)"""

    def __init__(self):
        """Instantiate the results array."""
        self.results = []

    def calculate(self, data, filename):
        if not data:
            return "", 0
        # Detect the use of `` outside quotes.
        string = "".join(data.split("\n"))
        count = 0
        qt, sq, sb, bs = None, False, False, ""
        for i, r in enumerate(string):
            if r in ['"', "'"]:
                if not sq:
                    sq, qt = True, r
                else:
                    if qt == r:
                        if string[i - 1] != "\\":
                            sq, qt = False, None
            elif r == "`":
                if not sq:
                    if sb:
                        count += 1
                        bs, sb = "", False
                    else:
                        sb = True
            if sb and r != "`":
                bs += r
        valid_regex = re.compile('(@\$_\[\]=|\$_=@\$_GET|\$_\[\+""\]=)', re.I)
        matches = re.findall(valid_regex, data)
        self.results.append({"filename": filename, "value": len(matches) + count})
        return len(matches) + count

    def sort(self):
        self.results.sort(key=lambda item: item["value"])
        self.results.reverse()
        # Check if there are at least 11 elements in the array
        if len(self.results) >= 11:
            # Loop through elements from index 10 to the end and set their values to 0
            for i in range(10, len(self.results)):
                self.results[i]["value"] = 0
        self.results = resultsAddRank(self.results)

    def printer(self, count):
        """Print the top signature count match files for a given search"""
        print(
            "\n[[ Top %i SUPER-signature match counts (These are usually bad!) ]]"
            % (count)
        )
        if count > len(self.results):
            count = len(self.results)
        for x in range(count):
            print(
                " {0:>7}        {1}".format(
                    self.results[x]["value"], self.results[x]["filename"]
                )
            )
        return


class SignatureInLog:
    """Generator that searches a given log file for nasty expressions"""

    def __init__(self):
        """Instantiate the results array."""
        self.results = []

    def calculate(self, data, filename):
        path = "/var/log/apache2"
        file_name = os.path.basename(filename)
        files = os.listdir(path)
        valid_regex = re.compile(
            "(system|exec|shell_exec|passthru|popen|proc_open)",
            re.I,
        )
        count = 0
        for file in files:
            if "access" in file:
                # Open file log
                # Unzip with file .gz
                if file.endswith(".gz"):
                    with gzip.open(path + "/" + file, "rb") as f:
                        lines = f.readlines()
                else:
                    # Open file
                    with open(path + "/" + file, "rb") as f:
                        lines = f.readlines()

                for line in lines:
                    line = line.decode("utf-8")
                    uri = line.split('"')[1]
                    status = line.split('"')[2].split()[0]
                    if (status == "200") and ("?" in uri) and (file_name in uri):
                        query = uri.split("?", 1)[1]

                        matches = re.findall(valid_regex, query)
                        count += len(matches)
        self.results.append({"filename": filename, "value": count})

        return count

    def sort(self):
        self.results.sort(key=lambda item: item["value"])
        self.results.reverse()
        self.results = resultsAddRank(self.results)

    def printer(self, count):
        """Print the top signature count match files for a given search"""
        print(
            "\n[[ Top %i signature match counts in log access (High possibility of bad!) ]]"
            % (count)
        )
        if count > len(self.results):
            count = len(self.results)
        for x in range(count):
            print(
                " {0:>7}        {1}".format(
                    self.results[x]["value"], self.results[x]["filename"]
                )
            )
        return


class Servicer:
    """Servicer class services the use of external services (APIs)."""

    # Suppress only the InsecureRequestWarning from urllib3 needed for disabling SSL warnings
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def __init__(self, file):
        try:
            self.file = open(file, "rb")
        except:
            self.file = False
            print("Could not read file: {file}")
        self.config = json.load(open("config.js", "r"))

    # Service Provider: <https://www.unphp.net>
    # Returns decoded and de-obfuscated script
    def unphp(self):
        apikey = self.config["UnPHP_apikey"]
        if apikey == "":
            return False
        try:
            r = requests.post(
                "https://www.unphp.net/api/v2/post",
                files={"file": self.file},
                data={"api_key": apikey},
                verify=False
            )
            data = r.json()
            if data["result"] == "error":
                return False
            return data
            sleep(2)
        except requests.ConnectionError as e:
            print(f"ConnectionError: {e}")
            return False

    # Service Provider: <https://virustotal.com>
    def virustotal(self):
        apikey = self.config["VirusTotal_apikey"]
        if apikey == "":
            return False
        try:
            r = requests.post(
                "https://www.virustotal.com/vtapi/v2/file/scan",
                files={"file": self.file},
                data={"apikey": apikey},
                verify=False
            )
            data = r.json()
            if data["response_code"] == 0:
                return False
            sleep(30)
            request = requests.get(
                "https://www.virustotal.com/vtapi/v2/file/report",
                params={"apikey": apikey, "resource": data["resource"]},
                verify=False
            )
            try:
                report = request.json()
            except:
                return False
            if report["response_code"] == 0 or report["positives"] == 0:
                return False
            return report
        except requests.ConnectionError as e:
            print(f"ConnectionError: {e}")
            return False


def resultsAddRank(results):
    rank = 1
    offset = 1
    previousValue = False
    newList = []
    for file in results:
        if previousValue and previousValue != file["value"]:
            rank = offset
        file["rank"] = rank
        newList.append(file)
        previousValue = file["value"]
        offset = offset + 1
    return newList


class SearchFile:
    """Generator that searches a given filepath with an optional regular
    expression and returns the filepath and filename"""

    def search_file_path(self, path, valid_regex, smallest):
        for root, dirs, files in os.walk(path):
            for file in files:
                filename = os.path.join(root, file)
                if not os.path.exists(filename):
                    continue
                if valid_regex.search(file) and os.path.getsize(filename) > smallest:
                    try:
                        data = open(root + "/" + file, "rb").read()
                        data = data.decode("utf-8")
                    except:
                        data = False
                        print("Could not read file :: %s/%s" % (root, file))
                    yield data, filename


def isConnectedWithInternet():
    timeout = 3
    url = "https://8.8.8.8"
    try:
        request = requests.head(url, timeout=timeout)
        return True
    except (requests.ConnectionError, requests.Timeout) as exception:
        return False
