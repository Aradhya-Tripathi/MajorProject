import os
import socket
import struct

import pymongo
import requests
from rich.progress import track

from renderer import console
from netscanner.utils import load_env

load_env()

session = requests.Session()
storage = pymongo.MongoClient(os.getenv("ip2location"))


def abuse(src: str) -> int:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": os.getenv("AbuseIPDb-Key")}
    params = {"ipAddress": src}

    response = session.get(url=url, headers=headers, params=params)
    return response.json()


def primary_details_source(ip_list: list[str]) -> dict[str, str]:
    intermediate_node_details = {}
    unanswered = []

    for ip in track(
        ip_list,
        description="[cyan]Querying location databases...",
        console=console,
        show_speed=False,
        transient=False,
    ):
        look_ip = int(struct.unpack("!L", socket.inet_aton(ip))[0])
        answer = storage.ip2location.ipinfo.find_one(
            {
                "ip_to": {"$gte": look_ip},
                "ip_from": {"$lte": look_ip},
            },
            {
                "_id": 0,
                "country_name": 1,
                "city_name": 1,
                "region_name": 1,
                "latitude": 1,
                "longitude": 1,
                "zip_code": "$field8",
            },
        )
        if not answer:
            unanswered.append(ip)
        else:
            intermediate_node_details[ip] = answer

    if unanswered:
        redundant_api_ip_details(
            ip_list=unanswered, intermediate_node_details=intermediate_node_details
        )
    return intermediate_node_details


def redundant_api_ip_details(
    ip_list: list[str], intermediate_node_details: dict[str, str]
) -> dict[str, str]:
    console.print(
        "[red][bold]Some IP locations were not found in the databases querying esternal services..."
    )
    response = session.post(
        "http://ip-api.com/batch", json=[{"query": ip} for ip in ip_list]
    )

    if not response.ok:
        console.print(
            "Redundant method failed location could not be found.", style="bold red"
        )
        exit(-1)

    response = response.json()
    console.print("[green]Found results using external services!")
    for idx, res in enumerate(response, start=0):
        intermediate_node_details[ip_list[idx]] = dict(
            country_name=res.get("country"),
            region_name=res.get("regionName"),
            city_name=res.get("city"),
            latitude=res.get("lat"),
            longitude=res.get("lon"),
            field8=res.get("zip"),
        )
