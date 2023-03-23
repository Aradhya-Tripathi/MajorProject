import socket

from rich import print as pprint
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from scapy import all as modules

from netscanner.ip.external import abuse, primary_details_source
from netscanner.ip.utils import public_ip
from netscanner.sniff.sniff import Sniffer


class Navigator:
    __slots__ = (
        "intermediate_node_details",
        "intermediate_node_addresses",
        "packets",
        "classification_result",
        "ip",
        "_console",
    )

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self._console = Console()

    def trace_packet_route(self, verbose: bool = False) -> None:
        """Perform a tcp syn flag trace, aquires intermediate route IPs,
        utilizing external API for IP geo location returns dict of location and IP details"""
        with self._console.status(
            f"[cyan]Packets being transfered to [bold]{self.ip}...",
            spinner="bouncingBall",
        ):
            ans, _ = modules.sr(
                modules.IP(dst=self.ip, ttl=(1, 30)) / modules.TCP(flags="S"),
                inter=0.2,
                retry=2,
                timeout=1,
                verbose=verbose,
            )

        pprint("[magenta]Sent and received packets.")
        # Here we want to look at the recieved packet's source IP address as that will
        # tell us the IP address of the router which sent the packet.
        self.intermediate_node_addresses = [received.src for _, received in ans]

        if verbose:
            for idx, address in enumerate(self.intermediate_node_addresses, start=1):
                pprint(f"{idx}. {address}")
        # Reduce list for plotting and ease of api calls.
        # After the destination is reached we terminate the list.
        try:
            self.intermediate_node_addresses = self.intermediate_node_addresses[
                : self.intermediate_node_addresses.index(socket.gethostbyname(self.ip))
                + 1
            ]
        except ValueError:
            raise ConnectionError(f"Packet failed to reach {self.ip}")

        self.intermediate_node_addresses[0] = public_ip(show=False)

        with self._console.status(
            "Finding location of source IP of the responding nodes...\n",
            spinner="earth",
        ):
            self.intermediate_node_details = primary_details_source(
                ip_list=self.intermediate_node_addresses
            )

        self.foramt_traced_route()

    def foramt_traced_route(self) -> None:
        table = Table(
            title=f"[green]Path taken by packets to reach {self.ip}",
        )

        table.add_column("Country", justify="center", style="cyan", no_wrap=True)
        table.add_column("City", style="magenta")
        table.add_column("Region", justify="center", style="green")
        table.add_column("IP", justify="center", style="cyan")
        table.add_column("Latitude", justify="center", style="cyan")
        table.add_column("Longitude", justify="center", style="cyan")

        for ip, detail in self.intermediate_node_details.items():
            table.add_row(
                detail["country_name"],
                detail["city_name"],
                detail["region_name"],
                ip,
                str(detail["latitude"]),
                str(detail["longitude"]),
            )

        pprint(table)

    def classify_request(self):
        sniffer = Sniffer(
            sniff_count=1,
            bp_filters=f"ip and src {self.ip}",
            verbose=True,
            send_request=True,
        )
        self.packets = sniffer.observe()
        self.classification_result = abuse(self.packets[0][modules.IP].src).get(
            "data", None
        )

        if not self.classification_result:
            raise Exception(
                f"Details about this Ip address {self.ip} not found in the database!"
            )

        panels = Group(
            *[
                f"[cyan]Confidance Score: [bold red] {self.classification_result['abuseConfidenceScore']} [bold red]UNSAFE"
                if self.classification_result["abuseConfidenceScore"] > 50
                else f"[cyan]Confidance Score: [bold green] {self.classification_result['abuseConfidenceScore']} [bold green]SAFE",
                f"[cyan]Is a Public IP: [green]{self.classification_result['isPublic']}",
                f"[cyan]Internet Service Provider: [green]{self.classification_result['isp']}",
                f"[cyan]Domain: [green]{self.classification_result['domain']}",
                f"[cyan]Usage of this domain: [green]{self.classification_result['usageType']}",
            ]
        )

        pprint(Panel(panels, title="[red]IP address details"))
