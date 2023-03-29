from functools import lru_cache

from netscanner.ip.navigator import Navigator
from netscanner.ip.utils import ABUSEIP_UNWANTED


@lru_cache(maxsize=512)
def classify_ip(ip_address: str):
    navigator = Navigator(ip=ip_address)
    classification_result = navigator.abuse_ip_address_classification()
    score = classification_result["abuseConfidenceScore"]

    return [
        [
            navigator.ip,
            f"Safe ({score})" if score < 50 else f"Unsafe {(score)}",
            classification_result["countryCode"],
            classification_result["isp"],
            classification_result["isPublic"],
        ]
    ]


def prune_network_classification(
    intermediate_node_details: dict[str, str]
) -> dict[str, str]:
    for value in intermediate_node_details.values():
        for unwanted in ABUSEIP_UNWANTED:
            del value[unwanted]

    return intermediate_node_details


def render_df(route_details: dict[str, str]):
    def mod(key, values):
        mod_list = []
        mod_list.append(key)
        mod_list.extend(list(values.values()))
        return mod_list

    return [mod(key=key, values=values) for key, values in route_details.items()]


def traceroute(destination_ip: str):
    navigator = Navigator(ip=destination_ip)
    route_details, _ = navigator.trace_packet_route()
    return render_df(route_details=route_details)


def traceroute_and_classify(destination_ip: str):
    navigator = Navigator(ip=destination_ip)
    route_details = navigator.abuse_ip_intermediate_node_classification()
    return render_df(route_details=route_details)


def network_traffic_classification(sniff_count: int):
    packet_details = Navigator().abuse_ip_sniff_and_classify(sniff_count=sniff_count)
    return render_df(route_details=prune_network_classification(packet_details))
