import socket
from concurrent.futures import ThreadPoolExecutor

from rich import print as pprint
from scapy import all

from netscanner.ip.external import ip_details


def trace_packet_route(destination: str, verbose: bool = False):
    """Perform a tcp syn flag trace"""
    pprint(f"[cyan]Packets being transfered to [bold]{destination}...")

    ans, _ = all.sr(
        all.IP(dst=destination, ttl=(1, 30)) / all.TCP(flags="S"),
        inter=0.2,
        retry=2,
        timeout=1,
        verbose=verbose,
    )

    # Here we want to look at the recieved packet's source IP address as that will
    # tell us the IP address of the router which sent the packet.
    intermediate_route_addresses = [received.src for _, received in ans]

    if verbose:
        for idx, address in enumerate(intermediate_route_addresses, start=1):
            pprint(f"{idx}. {address}")
    # Reduce list for plotting and ease of api calls.
    # After the destination is reached we terminate the list.
    intermediate_route_addresses = intermediate_route_addresses[
        : intermediate_route_addresses.index(socket.gethostbyname(destination))
    ]

    with ThreadPoolExecutor() as executor:
        results = executor.map(ip_details, intermediate_route_addresses)
