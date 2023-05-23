import sys

import click
from trogon import tui

from cli.renderer import render_netscanner, render_table_with_details

VERBOSE = False


@tui()
@click.group()
def netscanner_commands():
    pass


def extra_kwargs(ctx, kwargs: dict[any, any]):
    for i in range(0, len(ctx.args), 2):
        key = ctx.args[i].replace("--", "").replace("-", "_")
        value = ctx.args[i + 1]
        kwargs[key] = value

    parse_kwargs(kwargs)


def parse_kwargs(kwargs: dict[str, str]) -> None:
    for k, v in kwargs.items():
        try:
            kwargs[k] = eval(v)
        except Exception:
            ...


@click.command(
    "sniff",
    help="Run a live sniffer which captures and displays packets.",
)
@click.option("--bp-filters", default=None, type=str)
@click.option("--sniff-count", default=0, type=int)
@click.option("--extra-questions", default=None, type=str)
@click.option("--send-request", default=False, is_flag=True)
@click.option("--only-inbound", default=False, is_flag=True)
@click.option("--verbose", "-v", default=VERBOSE, is_flag=True)
def sniff(
    bp_filters: str = None,
    sniff_count: int = 0,
    extra_questions: str = None,
    send_request: bool = False,
    only_inbound: bool = False,
    verbose: bool = VERBOSE,
) -> None:
    from src.ip.sniff import Sniffer

    if extra_questions:
        extra_questions = extra_questions.replace(" ", "").split(",")

    Sniffer(
        sniff_count=sniff_count,
        bp_filters=bp_filters,
        extra_questions=extra_questions,
        send_request=send_request,
        only_inbound=only_inbound,
        verbose=verbose,
        show_packets=True,
    )


@click.command("traceroute", help="Trace route of packets using SYN packet flooding")
@click.argument("destination", type=str)
@click.option("--verbose", "-v", default=False, is_flag=True)
def traceroute(destination: str, verbose: bool = False) -> None:
    from src.ip.analyzer import NetworkAnalyzer

    intermediate_node_details, _ = NetworkAnalyzer(
        ip=destination, verbose=verbose
    ).trace_packet_route()

    render_table_with_details(intermediate_node_details=intermediate_node_details)


from cli.classify import classify
from cli.realtime import realtime
from cli.utility import utility

netscanner_commands.add_command(sniff)
netscanner_commands.add_command(traceroute)
netscanner_commands.add_command(realtime)
netscanner_commands.add_command(utility)
netscanner_commands.add_command(classify)


def main() -> None:
    if len(sys.argv) == 1:
        render_netscanner()

    netscanner_commands()


if __name__ == "__main__":
    main()
