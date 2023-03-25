# Handled of all final output render.
import random

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table

console = Console()


def render_packet_travle_map() -> None:
    # latitude, longitude = [], []
    # for detail in self.navigator.intermediate_node_details.values():
    #     latitude.append(detail["latitude"])
    #     longitude.append(detail["longitude"])

    # # Render on map
    # console.print(latitude, longitude)
    console.print("Not Implemented", style="bold red")


def render_table_with_details(intermediate_node_details: dict[str, str]) -> None:
    colors = ["cyan", "blink cyan", "magenta", "green"]
    init_columns = False
    table = Table(
        title=f"[green]Network Topology",
        expand=True,
    )

    for idx, (ip, detail) in enumerate(intermediate_node_details.items(), start=1):
        keys = list(detail.keys())
        keys.insert(0, "Sno.")
        keys.insert(1, "IP Address")

        for key in keys:
            if init_columns:
                break

            table.add_column(
                key.replace("_", " ").title(),
                justify="center",
                style=random.choice(colors) if key != "Sno." else "bold white",
                no_wrap=True,
            )

        init_columns = True
        table.add_row(str(idx), ip, *map(str, detail.values()))

    console.print(table)


def render_classification_panel(classification_result: dict[str, str]):
    panel_group = Group(
        *[
            f"[cyan]Confidance Score: [bold red]UNSAFE ([bold red]{classification_result['abuseConfidenceScore']})"
            if classification_result["abuseConfidenceScore"] > 50
            else f"[cyan]Confidance Score: [bold green]SAFE ([bold green]{classification_result['abuseConfidenceScore']})",
            f"[cyan]Is a Public IP: [green]{classification_result['isPublic']}",
            f"[cyan]Internet Service Provider: [green]{classification_result['isp']}",
            f"[cyan]Domain: [green]{classification_result['domain']}",
            f"[cyan]Usage of this domain: [green]{classification_result['usageType']}",
        ]
    )

    console.print(Panel(panel_group, title="[red]IP address details", safe_box=False))


def render_sniffed_packets(question_and_answers: dict[str, str], packet_count: int):
    panels = []

    for k, v in question_and_answers.items():
        panels.append(f"[cyan]{k}: [green]{v}")

    console.print(
        Panel(
            renderable=Group(*panels),
            title=f"[red]Packet Information Packet Count: {packet_count}",
            subtitle=f"[red]End Of Information Packet Count: {packet_count}",
        )
    )
