from functools import lru_cache

import click

from cli.main import netscanner_commands
from cli.renderer import (
    render_chat_gpt_response,
    render_classification_panel,
    render_table_with_details,
)
from src.utils import Timeout, parse_duration


@netscanner_commands.group()
def classify():
    ...


@lru_cache(maxsize=512)
@classify.command("ip-address")
@click.argument("host", type=str)
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--use-gpt", "-gpt", is_flag=True, default=False)
@click.option("--timeout", "-t", type=str, default=None)
def ip_address(
    host: str,
    verbose: bool = False,
    use_gpt: bool = False,
    timeout: str = None,
) -> None:
    from src.ip.analyzer import NetworkAnalyzer

    classification_results = NetworkAnalyzer(
        ip=host, verbose=verbose
    ).abuse_ip_address_classification()

    render_classification_panel(classification_result=classification_results)

    with Timeout(seconds=parse_duration(timeout)):
        if use_gpt:
            from gpt.api import single_ip_address

            assessment = single_ip_address(
                ip_address=classification_results["ipAddress"],
                usage=classification_results["usageType"],
                is_safe=f"unsafe"
                if classification_results["abuseConfidenceScore"] > 50
                else f"safe",
                verbose=verbose,
            )
            render_chat_gpt_response(response=assessment)


@classify.command("intermediate-node")
@click.argument("destination", type=str)
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--timeout", "-t", type=str)
def intermediate_node(
    destination: str,
    verbose: bool = False,
    use_gpt: bool = False,
    timeout: str = None,
) -> None:
    from src.ip.analyzer import NetworkAnalyzer

    with Timeout(seconds=parse_duration(timeout)):
        intermediate_node_details = NetworkAnalyzer(
            ip=destination, verbose=verbose
        ).abuse_ip_intermediate_node_classification()

        render_table_with_details(
            intermediate_node_details=intermediate_node_details,
        )

        if use_gpt:
            from gpt.api import intermediate_nodes

            render_chat_gpt_response(
                response=intermediate_nodes(
                    ip_addresses=intermediate_node_details.keys(), verbose=verbose
                )
            )
