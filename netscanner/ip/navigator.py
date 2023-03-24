import socket

from scapy import all as modules

from netscanner.ip import console
from netscanner.ip.external import abuse, primary_details_source
from netscanner.ip.utils import public_ip, trackcalls


class Navigator:
    __slots__ = (
        "intermediate_node_details",
        "packets",
        "classification_result",
        "ip",
        "packets",
    )

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.packets = []

    @trackcalls
    def trace_packet_route(self) -> None:
        """Perform a tcp syn flag trace, aquires intermediate route IPs,
        utilizing external API for IP geo location returns dict of location and IP details.
        """
        with console.status(
            f"[cyan]Packets being transfered to [bold]{self.ip}...",
            spinner="bouncingBall",
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
        self.packets = [received_packet for _, received_packet in ans]
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
        self.intermediate_node_details = primary_details_source(
            ip_list=intermediate_node_addresses
        )

    @trackcalls
    def abuse_ip_classification_on_single_address(self):
        console.print("\n\nClassifying packets using the AbuseIP...\n\n", style="cyan")
        self.classification_result = abuse(self.ip).get("data", None)
        if not self.classification_result:
            raise Exception(
                f"Details about this Ip address {self.ip} not found in the database!"
            )

    @trackcalls
    def abuse_ip_classification_on_network_topology(self):
        """
        Using threading to send classification requests.
        """
        self.trace_packet_route()
        from concurrent.futures import ThreadPoolExecutor

        def _classify(ip: str):
            return abuse(ip).get("data")

        packet_srcs = [packet.src for packet in self.packets]
        packet_srcs[0] = public_ip(show=False)
        with console.status(
            "[cyan]Classifying intermediate nodes using AbuseIP...", spinner="earth"
        ):
            with ThreadPoolExecutor() as executor:
                results = executor.map(_classify, packet_srcs)

        for idx, result in enumerate(results, start=0):
            self.intermediate_node_details[packet_srcs[idx]].update(
                {
                    "Classification": "Safe"
                    if result["abuseConfidenceScore"] < 50
                    else "Unsafe"
                }
            )


if __name__ == "__main__":
    Navigator("103.146.202.146").abuse_ip_classification_on_network_topology()
