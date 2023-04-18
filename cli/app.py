import sys
from functools import lru_cache

import typer

from cli.renderer import (
    render_chat_gpt_response,
    render_classification_panel,
    render_netscanner,
    render_network_classification,
    render_open_ports,
    render_table_with_details,
)
from src.utils import Timeout

app = typer.Typer(invoke_without_command=True)
realtime = typer.Typer()
utility = typer.Typer()
classify = typer.Typer()
app.add_typer(realtime, name="realtime")
app.add_typer(utility, name="utils")
app.add_typer(classify, name="classify")

VERBOSE = False


######################## Command Utils ########################


def extra_kwargs(ctx, kwargs: dict[any, any]):
    for i in range(0, len(ctx.args), 2):
        key = ctx.args[i].replace("--", "").replace("-", "_")
        value = ctx.args[i + 1]
        kwargs[key] = value


######################## Sniff Command ########################


@app.command()
def sniff(
    bp_filters: str = None,
    sniff_count: int = 0,
    extra_questions: str = None,
    send_request: bool = False,
    only_inbound: bool = False,
    verbose: bool = typer.Option(VERBOSE, "--verbose", "-v"),
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


@realtime.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True}
)
def dashboard(ctx: typer.Context, verbose: bool = VERBOSE) -> None:
    from src.ip.realtime import Realtime

    kwargs = {}
    extra_kwargs(ctx, kwargs)

    Realtime(verbose=verbose, **kwargs).dashboard()


@realtime.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True}
)
def monitor(
    ctx: typer.Context,
    duration: str = None,
    wait_for: int = 1,
    notify: bool = False,
    verbose: bool = typer.Option(VERBOSE, "--verbose", "-v"),
) -> None:
    from src.ip.realtime import Realtime

    kwargs = {}
    extra_kwargs(ctx, kwargs)
    Realtime(
        duration=duration,
        wait_for=wait_for,
        notify=notify,
        verbose=verbose,
        **kwargs,
    ).monitor()


@app.command()
def traceroute(
    destination: str, verbose: bool = typer.Option(VERBOSE, "--verbose", "-v")
) -> None:
    from src.ip.navigator import Navigator

    intermediate_node_details, _ = Navigator(
        ip=destination, verbose=verbose
    ).trace_packet_route()

    render_table_with_details(intermediate_node_details=intermediate_node_details)


######################## IP action commands ########################


@lru_cache(maxsize=512)
@classify.command()
def ip_address(
    request_to: str,
    verbose: bool = typer.Option(VERBOSE, "--verbose", "-v"),
    use_gpt: bool = typer.Option(False, "--use-gpt", "-gpt"),
    timeout: int = None,
) -> None:
    from src.ip.navigator import Navigator

    classification_results = Navigator(
        ip=request_to, verbose=verbose
    ).abuse_ip_address_classification()

    render_classification_panel(classification_result=classification_results)

    with Timeout(seconds=timeout):
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


@classify.command()
def intermediate_node(
    destination: str,
    verbose: bool = typer.Option(VERBOSE, "--verbose", "-v"),
    use_gpt: bool = typer.Option(False, "--use-gpt", "-gpt"),
    timeout: int = None,
) -> None:
    from src.ip.navigator import Navigator

    with Timeout(seconds=timeout):
        intermediate_node_details = Navigator(
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


@classify.command()
def network_traffic(
    sniff_count: int = 10,
    connection_type: str = "tcp",
    verbose: bool = typer.Option(VERBOSE, "--verbose", "-v"),
) -> None:
    from src.ip.navigator import Navigator

    classified_packets = Navigator(verbose=verbose).abuse_ip_sniff_and_classify(
        sniff_count=sniff_count, connection_type=connection_type
    )
    render_network_classification(intermediate_node_details=classified_packets)


@utility.command()
def private_ip() -> None:
    from src.ip.utils import private_ip

    private_ip()


@utility.command()
def public_ip() -> None:
    from src.ip.utils import public_ip

    public_ip()


@utility.command()
def get_ip_address(domain: str) -> None:
    from src.ip.navigator import Navigator

    print(Navigator(ip=domain).ip)


@utility.command()
def set_env_variables() -> None:
    from src.utils import set_env

    abuse_ip_api = typer.prompt(text="[cyan]Enter AbuseIP API key", hide_input=True)
    location_database = typer.prompt(
        text="[cyan]Enter location databse API key", hide_input=True
    )
    chatapi = typer.prompt(text="[cyan]Enter OpenAI API key", hide_input=True)
    set_env(vars=[abuse_ip_api, location_database, chatapi])


@utility.command()
def ports_in_use(
    host: str,
    start: int = 0,
    end: int = 1000,
    max_workers: int = 100,
    timeout: int = None,
    use_gpt: bool = typer.Option(False, "--use-gpt", "-gpt"),
    verbose: bool = typer.Option(VERBOSE, "--verbose", "-v"),
) -> None:
    from src.ip.utils import ports_in_use

    with Timeout(seconds=timeout):
        ports = ports_in_use(
            host=host,
            start=start,
            end=end,
            max_workers=max_workers,
            verbose=verbose,
        )
        render_open_ports(host, ports)

        if use_gpt:
            from gpt.api import port_usages

            usage = port_usages(ports=ports.keys(), verbose=verbose)
            render_chat_gpt_response(response=usage)


def main() -> None:
    if len(sys.argv) == 1:
        render_netscanner()

    app()


if __name__ == "__main__":
    main()
