import click

from cli.main import netscanner_commands
from cli.renderer import render_chat_gpt_response, render_open_ports
from src.utils import parse_duration


@netscanner_commands.group()
def utility():
    ...


@utility.command("private-ip", help="Show private IP address")
def private_ip() -> None:
    from src.ip.utils import private_ip

    private_ip()


@utility.command("public-ip", help="Show public IP address")
def public_ip() -> None:
    from src.ip.utils import public_ip

    public_ip()


@utility.command("get-ip-address", help="Get domains IP address")
def get_ip_address(domain: str) -> None:
    from src.ip.analyzer import NetworkAnalyzer

    print(NetworkAnalyzer(ip=domain).ip)


@utility.command("set-env-vars", help="Set environmnet variables")
def set_env_variables() -> None:
    from src.utils import set_env

    abuse_ip_api = click.prompt(text="Enter AbuseIP API key", hide_input=True)
    location_database = click.prompt(
        text="Enter location databse API key", hide_input=True
    )
    chatapi = click.prompt(text="Enter OpenAI API key", hide_input=True)
    set_env(vars=[abuse_ip_api, location_database, chatapi])


@utility.command("ports-in-use", help="Check ports in use for a host")
@click.argument("host", type=str)
@click.option("--start", "-s", type=int, default=0, help="Starting port number")
@click.option("--end", "-e", type=int, default=1000, help="End port number")
@click.option(
    "--max-workers",
    "-mw",
    type=int,
    default=10,
    help="Maximum number of workers to use for this operation",
)
@click.option("--timeout", "-t", type=str, default=None, help="Timeout for the scan")
@click.option(
    "--use-gpt",
    "-gpt",
    is_flag=True,
    default=False,
    help="Use GPT for verbose port information",
)
@click.pass_obj
def ports_in_use(
    verbose: bool,
    host: str,
    start: int = 0,
    end: int = 1000,
    max_workers: int = 10,
    timeout: str = None,
    use_gpt: bool = False,
) -> None:
    from src.ip.utils import ports_in_use
    from src.utils import Timeout

    with Timeout(seconds=parse_duration(duration=timeout)):
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
