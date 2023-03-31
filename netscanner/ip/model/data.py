import os
import socket
import struct

import pymongo
from rich.progress import track

from netscanner.ip.utils import redundant_api_ip_details
from netscanner.renderer import console

storage = pymongo.MongoClient(os.getenv("ip2location"))


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
