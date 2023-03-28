import logging

import requests
from netscanner.utils import load_env

session = requests.Session()
logging.getLogger("scapy").setLevel(logging.ERROR)


load_env()
