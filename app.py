import logging

import typer

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy import all

from classify.abuse import abuse
from observatory.observer import Observer

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

    observer = Observer(
        sniff_count=sniff_count, bp_filters=bp_filters, extra_questions=extra_questions
    )
    observer.observe()


@app.command()
def classify(url: str, protocal: str = "tcp", verbose: bool = False):
    observer = Observer(
        sniff_count=1, bp_filters=f"{protocal} and src {url}", verbose=verbose
    )
    packets = observer.observe()
    src = packets[0][all.IP].src

    status = abuse(src)
    print(status)


if __name__ == "__main__":
    app()
