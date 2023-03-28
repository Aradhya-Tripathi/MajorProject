from functools import lru_cache

import typer

from renderer import (
    render_classification_panel,
    render_table_with_details,
    render_network_classification,
)

app = typer.Typer()
VERBOSE = True
######################## Sniff Command ########################


@app.command(
    name="sniff",
    epilog="Runs a packet sniffer with the given details and shows packet details",
)
def sniff(
    bp_filters: str = None,
    sniff_count: int = 0,
    extra_questions: str = None,
    send_request: bool = False,
    only_inbound: bool = False,
):
    from netscanner.sniff.sniff import Sniffer

    if extra_questions:
        extra_questions = extra_questions.strip().split(",")

    Sniffer(
        sniff_count=sniff_count,
        bp_filters=bp_filters,
        extra_questions=extra_questions,
        send_request=send_request,
        only_inbound=only_inbound,
        verbose=VERBOSE,
    )


######################## IP action commands ########################


@lru_cache(maxsize=512)
@app.command()
def ip_address_classification(request_to: str):
    from netscanner.ip.navigator import Navigator

    classification_results = Navigator(
        ip=request_to, verbose=VERBOSE
    ).abuse_ip_address_classification()

    render_classification_panel(classification_result=classification_results)


@app.command()
def traceroute(destination: str):
    from netscanner.ip.navigator import Navigator

    intermediate_node_details, _ = Navigator(
        ip=destination, verbose=VERBOSE
    ).trace_packet_route()

    render_table_with_details(intermediate_node_details=intermediate_node_details)


@app.command()
def intermediate_node_classification(destination: str):
    from netscanner.ip.navigator import Navigator

    intermediate_node_details = Navigator(
        ip=destination, verbose=VERBOSE
    ).abuse_ip_intermediate_node_classification()

    render_table_with_details(intermediate_node_details=intermediate_node_details)


@app.command()
def network_traffic_classification(sniff_count: int = 10, connection_type: str = "tcp"):
    from netscanner.ip.navigator import Navigator

    classified_packets = Navigator(verbose=False).abuse_ip_sniff_and_classify(
        sniff_count=sniff_count, connection_type=connection_type
    )
    render_network_classification(intermediate_node_details=classified_packets)


@app.command()
def private_ip():
    from netscanner.ip.utils import private_ip

    private_ip(verbose=VERBOSE)


@app.command()
def public_ip():
    from netscanner.ip.utils import public_ip

    public_ip()


@app.command()
def get_ip_address(domain: str):
    from netscanner.ip.navigator import Navigator

    print(Navigator(ip=domain).ip)


if __name__ == "__main__":
    app()
