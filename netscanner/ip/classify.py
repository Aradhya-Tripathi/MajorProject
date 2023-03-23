from rich import print as pprint
from rich.console import Group
from rich.panel import Panel
from scapy import all

from netscanner.ip.external import abuse
from netscanner.sniff.sniff import Sniffer


def classify_request(request_to: str):
    sniffer = Sniffer(
        sniff_count=1,
        bp_filters=f"ip and src {request_to}",
        verbose=True,
        send_request=True,
    )
    packets = sniffer.observe()
    data = abuse(packets[0][all.IP].src).get("data", None)

    if not data:
        raise Exception(
            f"Details about this Ip address {request_to} not found in the database!"
        )

    panels = Group(
        *[
            f"[cyan]Confidance Score: [bold red] {data['abuseConfidenceScore']} [bold red]UNSAFE"
            if data["abuseConfidenceScore"] > 50
            else f"[cyan]Confidance Score: [bold green] {data['abuseConfidenceScore']} [bold green]SAFE",
            f"[cyan]Is a Public IP: [green]{data['isPublic']}",
            f"[cyan]Internet Service Provider: [green]{data['isp']}",
            f"[cyan]Domain: [green]{data['domain']}",
            f"[cyan]Usage of this domain: [green]{data['usageType']}",
        ]
    )

    pprint(Panel(panels, title="[red]IP address details"))
