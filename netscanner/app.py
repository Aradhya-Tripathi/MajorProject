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
    from netscanner.ip.classify import classify_request

    classify_request(request_to=request_to)


@app.command()
def traceroute(destination: str, verbose: bool = False):
    from netscanner.ip.trace import trace_packet_route

    trace_packet_route(destination=destination, verbose=verbose)


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
