from functools import lru_cache

from netscanner.ip.navigator import Navigator


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


def render_traceroute_df(route_details: dict[str, str]):
    def mod(key, values):
        mod_list = []
        mod_list.append(key)
        mod_list.extend(list(values.values()))
        return mod_list

    return [mod(key=key, values=values) for key, values in route_details.items()]


def traceroute(destination_ip: str):
    navigator = Navigator(ip=destination_ip)
    route_details, _ = navigator.trace_packet_route()
    return render_traceroute_df(route_details=route_details)


def traceroute_and_classify(destination_ip: str):
    navigator = Navigator(ip=destination_ip)
    route_details = navigator.abuse_ip_intermediate_node_classification()
    return render_traceroute_df(route_details=route_details)


def network_traffic_classification(sniff_count: int):
    ...
