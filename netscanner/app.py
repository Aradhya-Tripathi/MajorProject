import logging

import typer

logging.getLogger("scapy").setLevel(logging.ERROR)

from netscanner.classify.classify import classify_request
from netscanner.sniff.sniff import Sniffer

app = typer.Typer()


@app.command(
    name="sniff",
    epilog="Runs a packet sniffer with the given details and shows packet details",
)
def sniff(
    bp_filters: str = None,
    sniff_count: int = 0,
    extra_questions: str = None,
):
    if extra_questions:
        extra_questions = extra_questions.strip().split(",")

    observer = Sniffer(
        sniff_count=sniff_count, bp_filters=bp_filters, extra_questions=extra_questions
    )
    observer.observe()


@app.command()
def classify(request_to: str):
    classify_request(request_to=request_to)


@app.command()
def traceroute(request_to: str):
    ...


if __name__ == "__main__":
    app()
