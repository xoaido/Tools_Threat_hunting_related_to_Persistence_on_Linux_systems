# Library imports
import argparse
from src.ssh import*
from src.crontab import*
from src.webshell import*
from src.rootkit import*
from src.loginshell import*

def main():

      """Parse all the args"""

      timeStart = time.process_time()

      print(colorama.Fore.LIGHTBLUE_EX + """

                                      )                                
     *   )   )                 )   ( /(               )                
   ` )  /(( /( (     (    ) ( /(   )\())  (        ( /((        (  (   
    ( )(_))\()))(   ))\( /( )\()) ((_)\  ))\  (    )\())\  (    )\))(  
   (_(_()|(_)\(()\ /((_)(_)|_))/   _((_)/((_) )\ )(_))((_) )\ )((_))\  
   |_   _| |(_)((_|_))((_)_| |_   | || (_))( _(_/(| |_ (_)_(_/( (()(_) 
     | | | ' \| '_/ -_) _` |  _|  | __ | || | ' \))  _|| | ' \)) _` |  
     |_| |_||_|_| \___\__,_|\__|  |_||_|\_,_|_||_| \__||_|_||_|\__, |  
                                                               |___/   

      """ + colorama.Fore.RESET)

      parser = argparse.ArgumentParser()

      parser.add_argument("-a", "--all",
                        action="store_true",
                        dest="is_all",
                        default=False,
                        help="Run all scanner",)
      parser.add_argument("-s", "--ssh",
                        action="store_true",
                        dest="is_ssh",
                        default=False,
                        help="Run ssh scanner",)
      parser.add_argument("-r", "--rootkit",
                        action="store_true",
                        dest="is_rootkit",
                        default=False,
                        help="Run rootkit scanner",)
      parser.add_argument("-c", "--crontab",
                        action="store_true",
                        dest="is_crontab",
                        default=False,
                        help="Run crontab scanner",)
      parser.add_argument("-l", "--loginshell",
                        action="store_true",
                        dest="is_loginshell",
                        default=False,
                        help="Run login shell scanner",)
      parser.add_argument("-w", "--webshell",
                        action="store_true",
                        dest="is_webshell",
                        default=False,
                        help="Run web web shell scanner",)
      parser.add_argument("--dir",
                        action="store",
                        dest="directories",
                        default="",
                        help="Specify the directories to scan web shell",)
      parser.add_argument("--regex",
                        action="store",
                        dest="regex",
                        default="",
                        #nargs='+',
                        help="Specify the filename regex to scan web shell",)
      parser.add_argument("--hours",
                        action="store",
                        dest="hours",
                        type=int,
                        default=24,
                        help="Number of hours to scan ssh",)
      parser.add_argument("--keys",
                        action="store",
                        dest="keys",
                        type=int,
                        default=10,
                        help="Number of keys to scan ssh",)
      args = parser.parse_args()
      # Error on invalid number of arguments
      if args == None:
          parser.print_help()
          sys.exit(1)

      valid_regex = ""
      path = ""
      if args.is_all:
          hours = args.hours
          keys = args.keys
          path = args.directories
          valid_regex = args.regex
          sshScanner(keys, hours)
          crontabScanner()
          rootkitScanner()
          loginshellScanner()
          webshellScanner(path, valid_regex)
      else:
          if args.is_ssh:
             hours = args.hours
             keys = args.keys
             sshScanner(keys, hours)
          if args.is_rootkit:
              rootkitScanner()
          if args.is_crontab:
              crontabScanner()
          if args.is_loginshell:
              loginshellScanner()
          if args.is_webshell:
              path = args.directories
              valid_regex = args.regex
              webshellScanner(path, valid_regex)


      timeFinish = time.process_time()
      print("\n[[ Scan Time: %f seconds ]]" % (timeFinish - timeStart))

if __name__ == "__main__":
   main()

