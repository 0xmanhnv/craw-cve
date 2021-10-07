import argparse
from datetime import date
import warnings
from searchengine import search
from update import update
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

#start without warning
warnings.filterwarnings("ignore")

#create argument
parser = argparse.ArgumentParser(description='CVE')
parser.add_argument("-k",help='Keyword. Example: -k Linux)',default='')
parser.add_argument("-d",help='Last Modified Date. Example: - d 2022-02-22 (default is today)',default=str(date.today()))
parser.add_argument("-u",help='Download and update Data',action='store_true')
args = parser.parse_args()

#main
if args.u:
    update()
else:
    dte=args.d
    key=args.k
    print('searching....')
    print('Key: '+key)
    print('Last Modified Date: '+dte)
    search(dte,key)