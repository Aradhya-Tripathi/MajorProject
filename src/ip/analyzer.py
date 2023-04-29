import ipaddress
import socket

from scapy import all as modules

from src.ip.classification.abuseip_classification import AbuseIPClassification
from src.ip.model.data import primary_details_source
from src.ip.utils import public_ip
from cli.renderer import console


class NetworkAnalyzer:
    """
    Currently all APIs only support iPv4.
    """

    def __init__(self, ip: str = None, verbose: bool = False) -> None:
        self.ip = self.get_ip_address(ip=ip)
        self.verbose = verbose

    def get_ip_address(self, ip: str) -> str:
        try:
            ip = ipaddress.IPv4Address(socket.gethostbyname(ip))
        except (ipaddress.AddressValueError, socket.gaierror):
            raise ConnectionError(f"Invalid IP address or domain name: {ip}")

        if ip.is_loopback or not ip.is_global:
            raise Exception(
                "Please enter a global IP address and not a loopback address"
            )

        return str(ip)

    def trace_packet_route(self) -> tuple[dict[str:str], list]:
        """Perform a tcp syn flag trace, aquires intermediate route IPs,
        utilizing external API for IP geo location returns dict of location and IP details.
        """
        with console.status(
            f"Packets being transfered to [bold]{self.ip}...",
            spinner="bouncingBall",
            spinner_style="cyan",
            verbose=self.verbose,
        ):
            ans, _ = modules.sr(
                modules.IP(dst=self.ip, ttl=(1, 30)) / modules.TCP(flags="S"),
                inter=0.2,
                retry=2,
                timeout=1,
                verbose=False,
            )
        # Here we want to look at the recieved packet's source IP address as that will
        # tell us the IP address of the router which sent the packet.
        packets = [received_packet for _, received_packet in ans]
        intermediate_node_addresses = [received.src for _, received in ans]
        # Reduce list for plotting and ease of api calls.
        # After the destination is reached we terminate the list.
        try:
            intermediate_node_addresses = intermediate_node_addresses[
                : intermediate_node_addresses.index(socket.gethostbyname(self.ip)) + 1
            ]
        except ValueError:
            raise ConnectionError(f"Packet failed to reach {self.ip}")

        intermediate_node_addresses[0] = public_ip(show=False)
        intermediate_node_details = primary_details_source(
            ip_list=intermediate_node_addresses
        )
        return intermediate_node_details, packets

    def abuse_ip_address_classification(self) -> dict[str, str]:
        console.print(
            "Classifying packets using the AbuseIP...",
            style="info",
            verbose=self.verbose,
        )
        return AbuseIPClassification(address=self.ip).detect()

    def abuse_ip_intermediate_node_classification(self) -> dict[str, str]:
        """Classifies individual intermediate node's when tracing packet route.
        Using threading to send bulk classification requests."""
        intermediate_node_details, _ = self.trace_packet_route()
        packet_srcs = list(intermediate_node_details.keys())

        with console.status(
            "[cyan]Classifying intermediate nodes using AbuseIP...",
            spinner="earth",
            verbose=self.verbose,
        ):
            results = AbuseIPClassification(address=packet_srcs).detect()

        # Update existing results in intermediate node details fetched internally/externally,
        # with the classification from abuse IP.
        for idx, result in enumerate(results, start=0):
            intermediate_node_details[packet_srcs[idx]].update(
                {
                    "Classification": f"Safe {result['abuseConfidenceScore']}"
                    if result["abuseConfidenceScore"] < 50
                    else f"Unsafe {result['abuseConfidenceScore']}",
                    "Usage": result["usageType"],
                    "ISP": result["isp"],
                }
            )

        return intermediate_node_details


if __name__ == "__main__":
    NetworkAnalyzer("facebook.com").abuse_ip_address_classification()
