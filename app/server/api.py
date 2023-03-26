from netscanner.ip.navigator import Navigator
from functools import lru_cache


@lru_cache(maxsize=512)
def classify_ip(ip_address: str):
    classification_result = Navigator(
        ip=ip_address
    ).abuse_ip_classification_on_single_address()
    score = classification_result["abuseConfidenceScore"]

    return [
        [
            f"Safe ({score})" if score < 50 else f"Unsafe {(score)}",
            classification_result["countryCode"],
            classification_result["isp"],
            classification_result["isPublic"],
        ]
    ]


@lru_cache(maxsize=512)
def traceroute(destination_ip: str):
    route_details, _ = Navigator(ip=destination_ip).trace_packet_route()
    return [list(key.values()) for key in route_details.values()]
