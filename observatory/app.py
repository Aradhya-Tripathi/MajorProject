import logging

import typer

logging.getLogger("scapy").setLevel(logging.ERROR)

from rich import print as pprint
from rich.console import Group
from rich.panel import Panel
from scapy import all

from observatory.classify.abuse import abuse
from observatory.sniff.sniff import Sniffer

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
def classify(ip: str, protocal: str = "tcp", verbose: bool = False):
    observer = Sniffer(
        sniff_count=1, bp_filters=f"{protocal} and src {ip}", verbose=verbose
    )
    packets = observer.observe()
    src = packets[0][all.IP].src

    data = abuse(src).get("data", None)

    if not data:
        raise Exception(
            f"Details about this Ip address {ip} not found in the database!"
        )

    panels = Group(
        *[
            f"[cyan]Confidance Score: [bold red] {data['abuseConfidenceScore']} [bold red]UNSAFE"
            if data["abuseConfidenceScore"] > 50
            else f"[cyan]Confidance Score: [bold green] {data['abuseConfidenceScore']} [bold green]SAFE",
            f"[cyan]Is a Public IP: [green]{data['isPublic']}",
            f"[cyan]Internet Service Provider: [green]{data['isp']}",
            f"[cyan]Domain: [green]{data['domain']}",
            f"[cyan]Usage of this domain: [green]{data['usageType']}",
        ]
    )

    pprint(Panel(panels, title="IP address details"))


if __name__ == "__main__":
    app()
