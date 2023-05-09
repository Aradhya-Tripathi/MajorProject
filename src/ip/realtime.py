# This file is to handle background sniffing and or classifying and reporting the same.

import os
import random
import shlex
import signal
import subprocess
import sys
import time
from typing import TYPE_CHECKING, Any
from warnings import warn

import asciichartpy as asc

# isort: off

from rich import box
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.style import Style
from rich.text import Text
from cli.renderer import console

from scapy import all as modules

# isort: on

# from src.ip.classification import model
from src.ip.classification.abuseip import AbuseIPClassification
from src.ip.sniff import Sniffer
from src.ip.utils import PORT_MAPPINGS, hostname
from src.utils import parse_duration

if TYPE_CHECKING:
    from rich.console import RenderableType


class Dashboard:
    def __init__(
        self,
        capture_duration: str = "0.5 second",
        classification_rate: float = 0.5,
        **kwargs,
    ) -> None:
        self._precision = 3
        self._transient_factor = 5
        self.width, self.height = console.size.width, console.size.height
        self.middle_column_ratio = 2
        self.capture_duration = capture_duration
        self.classification_rate = classification_rate
        self.plot_configs = {
            "max": self.height // self.middle_column_ratio,  # Divided into 3 columns
            "min": 0,
            "format": "",
            "width": self.width,
        }
        self.capture_rates = []
        self.protocals = {}
        self.sports = {}
        self.dports = {}
        self.sources = {}
        self.capture_info = {
            "network_graph": Text(""),
            "top_protocals": Text(""),
            "details": Text(""),
            "threats": Text(""),
            "top_dports": Text(""),
            "top_sports": Text(""),
            "top_sources": Text(""),
        }
        self.color_map = {
            "protocals": "magenta",
            "sources": "magenta",
            "dports": "green",
            "sports": "cyan",
        }
        kwargs.pop("show_packets", None)
        self.sniffer = Sniffer(**kwargs)
        self.render()

    def initialize_panels(self) -> None:
        def _create_panel(renderable: "RenderableType", title: str) -> Panel:
            return Panel(
                renderable=renderable,
                title=title,
                box=box.HEAVY,
                style="bright_black",
            )

        self.network_traffic_panel = _create_panel(
            "", "[bold light_coral]Real-time Network Traffic"
        )
        self.packet_details_panel = _create_panel("", "[bold cyan]Packet Flow")
        self.threat_alert_panel = _create_panel("", "[bold red]Threat Alerts")
        self.top_protocals_panel = _create_panel("", "[bold cyan]Top Protocols")
        self.top_dports_panel = _create_panel("", "[bold cyan]Top Destination Ports")
        self.top_sports_panel = _create_panel("", "[bold cyan]Top Source Ports")
        self.top_sources_panel = _create_panel("", "[bold cyan]Top Sources")

    def initialize_layout(self) -> None:
        self.layout = Layout()

        self.layout.split_column(
            Layout(renderable=self.network_traffic_panel, name="top"),
            Layout(name="middle", ratio=self.middle_column_ratio),
            Layout(name="bottom"),
        )

        self.layout["middle"].split_row(
            Layout(
                renderable=self.packet_details_panel,
                name="left",
                ratio=self.middle_column_ratio,
            ),
            Layout(renderable=self.threat_alert_panel, name="right"),
        )

        self.layout["bottom"].split_row(
            Layout(name="bottom_left", renderable=self.top_protocals_panel),
            Layout(name="bottom_middle1", renderable=self.top_dports_panel),
            Layout(name="bottom_middle2", renderable=self.top_sports_panel),
            Layout(name="bottom_right", renderable=self.top_sources_panel),
        )

    def capture_statistics(self) -> float:
        # Reset all defaults.
        self.flush()
        time.sleep(parse_duration(self.capture_duration))
        self.set_capture_details()

    def flush(self) -> None:
        self.sniffer.packet_count = 0
        self.sniffer.packets.clear()

        if len(self.capture_rates) > (self.width - self._transient_factor):
            self.capture_rates = []

        self.clear_capture_info("threats", self.height // self.middle_column_ratio)
        self.clear_capture_info("details", self.height // self.middle_column_ratio)
        self.clear_top_info("top_dports", self.height // self.middle_column_ratio + 1)
        self.clear_top_info("top_sports", self.height // self.middle_column_ratio + 1)
        self.clear_top_info(
            "top_protocals", self.height // self.middle_column_ratio + 1
        )
        self.clear_top_info("top_sources", self.height // self.middle_column_ratio + 1)

    def clear_capture_info(self, info_name: str, max_lines: int) -> None:
        if str(self.capture_info[info_name]).count("\n") >= max_lines:
            self.capture_info[info_name] = Text("")

    def clear_top_info(self, info_name: str, max_lines: int) -> None:
        if str(self.capture_info[info_name]).count("\n") >= max_lines:
            self.capture_info[info_name] = {}

    def _format_dict_to_str(self, item: dict[str, Any | str]) -> str:
        dict_to_str = ""
        for protocal, freq in item.items():
            dict_to_str += f"{protocal} - {freq}\n"
        return dict_to_str

    def set_capture_details(self) -> None:
        srcs = set()
        packets_for_model = []
        for packet in self.sniffer.packets:
            if not packet.haslayer(modules.IP):
                continue

            packet = packet[modules.IP]
            srcs.add(packet.src)
            proto = self.sniffer.proto_lookup_table[packet.proto]
            src = hostname(packet.src)

            self.protocals[proto] = self.protocals.get(proto, 0) + 1
            self.sources[src] = self.sources.get(src, 0) + 1

            try:
                dport = PORT_MAPPINGS.get(packet.dport, packet.dport)
                sport = PORT_MAPPINGS.get(packet.sport, packet.sport)
                self.dports[dport] = self.dports.get(dport, 0) + 1
                self.sports[sport] = self.sports.get(sport, 0) + 1
            except AttributeError:
                ...

            self.capture_info["details"] += Text(
                f"""* Source {hostname(packet.src)} - Destination {hostname(packet.dst)}\
 - Port(s/d) {getattr(packet, 'sport', 'N/A')}\
 - {getattr(packet, 'dport', 'N/A')}\n""",
                style="cyan",
                justify="center",
            )
            packets_for_model.append(
                [
                    proto,
                    packet.flags,
                    len(packet.load) if hasattr(packet, "load") else 0,
                    len(packet.payload) if hasattr(packet, "payload") else 0,
                    packet[modules.TCP].urgptr if packet.haslayer(modules.TCP) else 0,
                ]
            )

        self.get_threats(srcs=srcs, packets=packets_for_model)

        self.capture_info["network_graph"] = self.get_network_traffic(
            round(
                self.sniffer.packet_count / parse_duration(self.capture_duration),
                self._precision,
            )
        )

        for info in ["protocals", "dports", "sports", "sources"]:
            self.capture_info["top_" + info] = Text(
                self._format_dict_to_str(getattr(self, info)),
                justify="center",
                style=self.color_map[info],
            )

    def get_network_traffic(self, capture_rate: float) -> str:
        self.capture_rates.append(capture_rate)
        graph = Text(
            asc.plot(self.capture_rates, self.plot_configs),
            style=Style(color="white", bold=True),
        )
        return graph

    def get_threats(self, srcs: set, packets: list[modules.Packet]) -> None:
        if random.random() > self.classification_rate:
            return

        packet_details = AbuseIPClassification(srcs).detect()
        # model.predict(packets=packets),

        if not isinstance(packet_details, dict):
            for detail in packet_details:
                host = hostname(detail["ipAddress"])
                self.capture_info["threats"] += Text.from_markup(
                    f"[blink bold red]* Unsafe packet source {host}[/blink bold red]\n"
                    if detail["abuseConfidenceScore"] > 50
                    else f"[cyan]* Safe packet source {host}[/cyan]\n",
                )
        else:
            host = hostname(packet_details["ipAddress"])
            self.capture_info["threats"] += Text.from_markup(
                f"[blink bold red]* Unsafe packet source {host}[/blink bold red]\n"
                if packet_details["abuseConfidenceScore"] > 50
                else f"[green]* Safe packet source {host}[/green]\n",
            )

    def update_dashboard(
        self,
        network_traffic_renderable: Text,
        packet_details_renderable: Text,
        threat_alert_renderable: Text,
        top_protocals_renderable: Text,
        top_dports_renderable: Text,
        top_sports_renderable: Text,
        top_sources_renderable: Text,
    ) -> None:
        self.network_traffic_panel.renderable = network_traffic_renderable
        self.packet_details_panel.renderable = packet_details_renderable
        self.threat_alert_panel.renderable = threat_alert_renderable
        self.top_protocals_panel.renderable = top_protocals_renderable
        self.top_dports_panel.renderable = top_dports_renderable
        self.top_sports_panel.renderable = top_sports_renderable
        self.top_sources_panel.renderable = top_sources_renderable

        self.layout["top"]._renderable = self.network_traffic_panel
        self.layout["middle"]["left"]._renderable = self.packet_details_panel
        self.layout["middle"]["right"]._renderable = self.threat_alert_panel

        self.layout["bottom"]["bottom_left"]._renderable = self.top_protocals_panel
        self.layout["bottom"]["bottom_middle1"]._renderable = self.top_dports_panel
        self.layout["bottom"]["bottom_middle2"]._renderable = self.top_sports_panel
        self.layout["bottom"]["bottom_right"]._renderable = self.top_sources_panel

    def render(self) -> None:
        self.initialize_panels()
        self.initialize_layout()

        with Live(auto_refresh=False, screen=False) as live:
            try:
                while True:
                    self.capture_statistics()
                    self.update_dashboard(
                        network_traffic_renderable=self.capture_info["network_graph"],
                        threat_alert_renderable=self.capture_info["threats"],
                        packet_details_renderable=self.capture_info["details"],
                        top_protocals_renderable=self.capture_info["top_protocals"],
                        top_dports_renderable=self.capture_info["top_dports"],
                        top_sports_renderable=self.capture_info["top_sports"],
                        top_sources_renderable=self.capture_info["top_sources"],
                    )
                    live.update(self.layout, refresh=True)
            except KeyboardInterrupt:
                console.print("Safely shutting down the sniffer...", style="info")
                self.sniffer.stop()


class Realtime:
    lock_name = f"/tmp/{__name__}.lock"

    def __init__(
        self,
        duration: str = None,
        wait_for: int = 1,
        notify: bool = False,
        verbose: bool = False,
        classification_rate: float = 0.5,
        **kwargs,
    ) -> None:
        self.duration = duration
        self.wait_for = wait_for
        self.verbose = verbose
        self.kwargs = kwargs
        self.classification_rate = classification_rate

        if sys.platform != "darwin" and notify:
            warn(
                """Only supports pop up notifcation for darwin systems however
terminal bell will still work if supported by the terminal""",
                category=UserWarning,
                stacklevel=3,
            )

        self.notify = notify

        self.kwargs["is_async"] = True
        self.sniffer = None
        self.classified_packets = {}

    def setup(self) -> None:
        if os.path.isfile(self.lock_name):
            raise OSError(
                "Program is already running kill all instances of the program before starting."
            )
        with open(self.lock_name, "w+") as lock_file:
            lock_file.write(str(os.getpid()))

        # If stopped via a signal which covers ctrl + C.
        for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGQUIT]:
            signal.signal(sig, self.signal_handler)

    def signal_handler(self, *arg):
        self.cleanup()

    def send_notification(self, packet_src: str) -> None:
        console.bell()
        message = f"Unsafe packet detected from {packet_src}"
        command = (
            f'display notification "{message}" with title "Unsafe packet detected"'
        )
        subprocess.run(shlex.split(f"osascript -e '{command}'"))
        self.classified_packets[packet_src]["notified"] = True

    def dashboard(self, capture_duration: str = "0.5 second") -> Dashboard:
        # Only for cli usage.
        return Dashboard(
            classification_rate=self.classification_rate,
            capture_duration=capture_duration,
            **self.kwargs,
        )

    def _classify(self, src: str) -> bool:
        if src not in self.classified_packets:
            self.classified_packets[src] = {
                "is_safe": (
                    AbuseIPClassification(src).detect()["abuseConfidenceScore"] < 50
                ),
                "notified": False,
            }
        return self.classified_packets[src]

    def monitor(self) -> None:
        """
        Background monitor extention of `netscanner sniff`
        saves information to redis cache and also notifies of abuse IP classifications.

        classification_rate: percentage of packets that are classified (defaults to 50%)
        """
        try:
            self.setup()
            console.print(
                f"\n[italic]Monitoring with a classification rate of {self.classification_rate * 100}%\n",
                style="info",
                verbose=self.verbose,
            )
            self.sniffer = Sniffer(**self.kwargs, verbose=self.verbose)

            for packet in self.sniffer.stream_packets(
                duration=self.duration, wait_for=self.wait_for
            ):
                packet = packet[modules.IP]
                if random.random() > self.classification_rate:
                    continue

                classification = self._classify(src=packet.src)
                if (
                    not classification["is_safe"]
                    and self.notify
                    and not classification["notified"]
                ):
                    self.send_notification(packet_src=packet.src)

            self.cleanup()

        except Exception:
            console.print_exception()
            self.cleanup()

    def cleanup(self) -> None:
        console.print("Cleaning up...", style="info", verbose=self.verbose)
        if self.sniffer:
            self.sniffer.stop()
        if os.path.isfile(self.lock_name):
            os.unlink(self.lock_name)
        exit()
