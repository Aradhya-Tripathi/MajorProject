import os

import requests

from netscanner.utils import load_env

load_env()

session = requests.Session()


def abuse(src: str) -> int:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": os.getenv("AbuseIPDb-Key")}
    params = {"ipAddress": src}

    response = session.get(url=url, headers=headers, params=params)
    return response.json()


def ip_details(ip: str) -> dict[str, str]:
    response = session.get(
        f"https://ip.city/api.php?ip={ip}&key={os.getenv('IP.City-Key')}"
    )
    return response.json()
