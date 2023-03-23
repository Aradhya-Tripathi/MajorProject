import logging

import typer

logging.getLogger("scapy").setLevel(logging.ERROR)


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

    observer = Sniffer(
        sniff_count=sniff_count,
        bp_filters=bp_filters,
        extra_questions=extra_questions,
        send_request=send_request,
    )
    observer.observe()


######################## IP action commands ########################


@app.command()
def classify(request_to: str):
    from netscanner.ip.navigator import Navigator

    Navigator(ip=request_to).classify_request()


@app.command()
def traceroute(destination: str, verbose: bool = False):
    from netscanner.ip.navigator import Navigator

    Navigator(ip=destination).trace_packet_route(verbose=verbose)


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
