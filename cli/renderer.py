# Handled of all final output render.
# cSpell:ignore RenderableType, ABUSEIP, renderable

import random
import time
import typing

from rich import box as rich_box
from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.status import Status
from rich.table import Table

if typing.TYPE_CHECKING:
    from rich.console import RenderableType
    from rich.style import StyleType


class AdaptiveStatus(Status):
    """Status needs a context wrapper thus initialized new class for it."""

    def __init__(
            self,
            status: "RenderableType",
            *,
            console: typing.Optional[Console] = None,
            spinner: str = "dots",
            spinner_style: "StyleType" = "status.spinner",
            speed: float = 1,
            refresh_per_second: float = 12.5,
            verbose: bool = True,
    ):
        self.verbose = verbose
        super().__init__(
            status,
            console=console,
            spinner=spinner,
            spinner_style=spinner_style,
            speed=speed,
            refresh_per_second=refresh_per_second,
        )

    def __enter__(self) -> "Status":
        if self.verbose:
            super().__enter__()
            return self

    def __exit__(self, *args, **kwargs) -> None:
        if self.verbose:
            super().__exit__(*args, **kwargs)


class AdaptiveConsole(Console):
    def status(
            self,
            status: "RenderableType",
            *,
            spinner: str = "dots",
            spinner_style: "StyleType" = "status.spinner",
            speed: float = 1,
            refresh_per_second: float = 12.5,
            verbose: bool = True,
    ) -> "Status":
        return AdaptiveStatus(
            status,
            verbose=verbose,
            spinner=spinner,
            spinner_style=spinner_style,
            speed=speed,
            refresh_per_second=refresh_per_second,
        )

    def print(self, *args, **kwargs) -> None:
        """As print requires no special approach simply using this."""
        if kwargs.pop("verbose", True):
            return super().print(*args, **kwargs)


console = AdaptiveConsole()


def render_packet_travel_map() -> None:
    # latitude, longitude = [], []
    # for detail in self.navigator.intermediate_node_details.values():
    #     latitude.append(detail["latitude"])
    #     longitude.append(detail["longitude"])

    # # Render on map
    # console.print(latitude, longitude)
    console.print("Not Implemented", style="bold red")


def render_table_with_details(
        intermediate_node_details: dict[str, dict[str, str]],
        box: rich_box.Box = rich_box.HEAVY_HEAD,
) -> None:
    colors = ["cyan", "blink cyan", "magenta", "green"]
    init_columns = False
    table = Table(
        title=f"[green]Network Topology",
        padding=1,
        expand=True,
        box=box,
        highlight=True,
    )

    for ip, detail in intermediate_node_details.items():
        keys = list(detail.keys())
        keys.insert(0, "IP Address")

        for key in keys:
            if init_columns:
                break

            table.add_column(
                key.replace("_", " ").title(),
                justify="center",
                style=random.choice(colors),
                no_wrap=True,
                overflow="ignore",
            )

        init_columns = True
        table.add_row(ip, *map(str, detail.values()))

    console.print(table)


def render_classification_panel(classification_result: dict[str, str]):
    panel_group = Group(
        *[
            f"[cyan]Confidence Score: [bold red]UNSAFE ([bold red]{classification_result['abuseConfidenceScore']})"
            if classification_result["abuseConfidenceScore"] > 50
            else f"[cyan]Confidence Score: [bold green]SAFE ([bold green]{classification_result['abuseConfidenceScore']})",
            f"[cyan]Is a Public IP: [green]{classification_result['isPublic']}",
            f"[cyan]Internet Service Provider: [green]{classification_result['isp']}",
            f"[cyan]Domain: [green]{classification_result['domain']}",
            f"[cyan]Usage of this domain: [green]{classification_result['usageType']}",
        ]
    )

    console.print(
        Panel(panel_group, title="[red]IP address details", safe_box=False, expand=True)
    )


def render_sniffed_packets(question_and_answers: dict[str, str], packet_count: int):
    panels = []

    for k, v in question_and_answers.items():
        panels.append(f"[cyan]{k}: [green]{v}")

    console.print(
        Panel(
            renderable=Group(*panels),
            title=f"[red]Packet Information Packet Count: {packet_count}",
            subtitle=f"[red]End Of Information Packet Count: {packet_count}",
            box=rich_box.DOUBLE_EDGE,
        )
    )


def render_network_classification(
        intermediate_node_details: dict[str, dict[str, str]]
) -> None:
    from src.ip.utils import ABUSEIP_UNWANTED

    for value in intermediate_node_details.values():
        for unwanted in ABUSEIP_UNWANTED:
            del value[unwanted]

    render_table_with_details(
        intermediate_node_details=intermediate_node_details,
    )


def render_chat_gpt_response(response: str) -> None:
    panel = Panel(
        title="[magenta]GPT",
        title_align="center",
        border_style="red",
        renderable="",
    )
    with Live(panel, auto_refresh=False, vertical_overflow="visible") as live:
        def _update(t):
            panel.renderable += "[bold white]" + t
            return panel

        for res in response:
            time.sleep(0.002)
            live.update(_update(res), refresh=True)


def render_open_ports(host: str, ports: dict[int:str]) -> None:
    all_ports = Columns(
        [port + " " + reason for port, reason in ports.items()],
        column_first=False,
        expand=True,
        equal=True,
    )
    console.print(Panel(all_ports, title=f"Open Ports on {host}"))
