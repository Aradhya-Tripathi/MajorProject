import logging

import typer

logging.getLogger("scapy").setLevel(logging.ERROR)
from renderer import render_classification_panel, render_table_with_details

app = typer.Typer()

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
):
    from netscanner.sniff.sniff import Sniffer

    if extra_questions:
        extra_questions = extra_questions.strip().split(",")

    Sniffer(
        sniff_count=sniff_count,
        bp_filters=bp_filters,
        extra_questions=extra_questions,
        send_request=send_request,
    )


######################## IP action commands ########################


@app.command()
def classify(request_to: str):
    from netscanner.ip.navigator import Navigator

    classification_results = Navigator(
        ip=request_to
    ).abuse_ip_classification_on_single_address()
    render_classification_panel(classification_result=classification_results)


@app.command()
def traceroute(destination: str):
    from netscanner.ip.navigator import Navigator

    intermediate_node_details, _ = Navigator(ip=destination).trace_packet_route()
    render_table_with_details(intermediate_node_details=intermediate_node_details)


@app.command()
def classify_topology(destination: str):
    from netscanner.ip.navigator import Navigator

    intermediate_node_details = Navigator(
        ip=destination
    ).abuse_ip_classification_on_network_topology()
    render_table_with_details(intermediate_node_details=intermediate_node_details)


@app.command()
def private_ip():
    from netscanner.ip.utils import private_ip

    private_ip()


@app.command()
def public_ip():
    from netscanner.ip.utils import public_ip

    public_ip()


if __name__ == "__main__":
    app()
