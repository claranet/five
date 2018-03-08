from five.log import Log
log = Log(logfile='./debug.log', console=True, level='INFO')

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from five.utils import import_conf
from five.bigip import Bigip
from five.infra import Infra
from five.archi import Archi
from five.ltm import *
