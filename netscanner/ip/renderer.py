# Handled of all final output render.
import random
import typing

from rich.console import Group
from rich.panel import Panel
from rich.table import Table

from netscanner.ip import console

if typing.TYPE_CHECKING:
    from netscanner.ip.navigator import Navigator


class Renderer:
    """
    Takes in a navigator object and reders necessary information from the same.
    """

    def __init__(self, navigator: "Navigator"):
        self.navigator = navigator
        self.random_color_hack = ["cyan", "green", "magenta"]

        if self.navigator.trace_packet_route.has_been_called:
            self.render_trace_route()

        if self.navigator.abuse_ip_classification_on_single_address.has_been_called:
            self.render_classification_result()

    def render_trace_route(self) -> None:
        init_columns = False
        table = Table(
            title=f"[green]Path taken by packets to reach {self.navigator.ip}.",
            expand=True,
        )

        for ip, detail in self.navigator.intermediate_node_details.items():
            keys = list(detail.keys())
            keys.insert(0, "IP address")

            for key in keys:
                if init_columns:
                    break
                table.add_column(
                    key.replace("_", " ").capitalize(),
                    justify="center",
                    style=random.choice(self.random_color_hack),
                )

            init_columns = True
            table.add_row(ip, *map(str, detail.values()))

        console.print(table)

    def render_classification_result(self):
        panels = Group(
            *[
                f"[cyan]Confidance Score: [bold red] {self.navigator.classification_result['abuseConfidenceScore']} [bold red]UNSAFE"
                if self.navigator.classification_result["abuseConfidenceScore"] > 50
                else f"[cyan]Confidance Score: [bold green] {self.navigator.classification_result['abuseConfidenceScore']} [bold green]SAFE",
                f"[cyan]Is a Public IP: [green]{self.navigator.classification_result['isPublic']}",
                f"[cyan]Internet Service Provider: [green]{self.navigator.classification_result['isp']}",
                f"[cyan]Domain: [green]{self.navigator.classification_result['domain']}",
                f"[cyan]Usage of this domain: [green]{self.navigator.classification_result['usageType']}",
            ]
        )

        console.print(Panel(panels, title="[red]IP address details"))
