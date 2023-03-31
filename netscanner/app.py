from functools import lru_cache

import typer

from netscanner.renderer import (
    render_classification_panel,
    render_table_with_details,
    render_network_classification,
)

app = typer.Typer(no_args_is_help=True)
utility = typer.Typer()
classify = typer.Typer()
app.add_typer(utility, name="utils")
app.add_typer(classify, name="classify")

VERBOSE = False
######################## Sniff Command ########################


@app.command()
def sniff(
    bp_filters: str = None,
    sniff_count: int = 0,
    extra_questions: str = None,
    send_request: bool = False,
    only_inbound: bool = False,
    verbose: bool = VERBOSE,
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
        verbose=verbose,
    )


@app.command()
def traceroute(destination: str, verbose: bool = VERBOSE):
    from netscanner.ip.navigator import Navigator

    intermediate_node_details, _ = Navigator(
        ip=destination, verbose=verbose
    ).trace_packet_route()

    render_table_with_details(intermediate_node_details=intermediate_node_details)


######################## IP action commands ########################


@lru_cache(maxsize=512)
@classify.command()
def ip_address(request_to: str, verbose: bool = VERBOSE):
    from netscanner.ip.navigator import Navigator

    classification_results = Navigator(
        ip=request_to, verbose=verbose
    ).abuse_ip_address_classification()

    render_classification_panel(classification_result=classification_results)


@classify.command()
def intermediate_node(destination: str, verbose: bool = VERBOSE):
    from netscanner.ip.navigator import Navigator

    intermediate_node_details = Navigator(
        ip=destination, verbose=verbose
    ).abuse_ip_intermediate_node_classification()

    render_table_with_details(intermediate_node_details=intermediate_node_details)


@classify.command()
def network_traffic(
    sniff_count: int = 10, connection_type: str = "tcp", verbose: bool = VERBOSE
):
    from netscanner.ip.navigator import Navigator

    classified_packets = Navigator(verbose=verbose).abuse_ip_sniff_and_classify(
        sniff_count=sniff_count, connection_type=connection_type
    )
    render_network_classification(intermediate_node_details=classified_packets)


@utility.command()
def private_ip():
    from netscanner.ip.utils import private_ip

    private_ip()


@utility.command()
def public_ip():
    from netscanner.ip.utils import public_ip

    public_ip()


@utility.command()
def get_ip_address(domain: str):
    from netscanner.ip.navigator import Navigator

    print(Navigator(ip=domain).ip)


if __name__ == "__main__":
    app()
