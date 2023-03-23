import os

import requests
from rich import print as pprint

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
    ).json()

    if response["status"] == "Error":
        pprint(
            "[red]Initial attempt to find location failed trying redundant method..."
        )
        return redundant_api_ip_details(ip=ip)

    response["ip"] = ip
    return response


def redundant_api_ip_details(ip: str) -> dict[str, str]:
    response = session.get(f"https://ipapi.co/{ip}/json/")

    if not response.ok:
        pprint("[red]Redundant method failed location could not be found.")

    response = response.json()
    return dict(
        ip=ip,
        countryName=response.get("country_name"),
        city=response.get("city"),
        region=response.get("region"),
        organisation=response.get("org"),
        lat=response.get("latitude"),
        long=response.get("longitude"),
    )
