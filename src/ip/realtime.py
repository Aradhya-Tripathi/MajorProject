# This file is to handle background sniffing and or classifying and reporting the same.

import os
import random
import shlex
import signal
import subprocess
import sys
import time
from datetime import datetime

import asciichartpy as asc

# Rich imports specefically for dashboard class
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.style import Style
from rich.text import Text

from scapy import all as modules

from cli.renderer import console
from src.ip.classification.abuseip_classification import AbuseIPClassification
from src.ip.model.cache import get_cache
from src.ip.sniff import Sniffer
from src.ip.utils import hostname
from src.utils import parse_duration

from src.ip.history import History


class Dashboard:
    def __init__(self, duration: str = None, wait_for: int = 1, **kwargs) -> None:
        self.duration = duration
        self.wait_for = wait_for
        self._precision = 3
        self._transient_factor = 5
        self.width, self.height = console.size.width, console.size.height
        self.middle_column_ratio = 2
        self.bottom_column_ratio = 3
        self.plot_configs = {
            "max": self.height // 3,  # Divided into 3 columns
            "min": 0,
            "format": "",
            "width": self.width,
        }
        self.capture_rates = []
        # Implement this so that srcs present in this don't go for classification again
        self.classified = []
        self.protocals = (
            {}
        )  # This is here since packet count ins't just for the capture duration
        self.capture_info = {
            "top_protocals": Text(""),
            "history": Text(""),
            "threats": Text(""),
        }
        self.sniffer = Sniffer(**kwargs)
        self.render()

    def capture_statistics(self, capture_duration: str = "0.5 second") -> float:
        # Reset all defaults.
        self.flush()
        time.sleep(parse_duration(capture_duration))
        self.set_capture_details()
        return self.get_network_traffic(
            round(
                self.sniffer.packet_count / parse_duration(capture_duration),
                self._precision,
            )
        )

    def get_network_traffic(self, capture_rate: float) -> str:
        self.capture_rates.append(capture_rate)
        graph = Text(
            asc.plot(self.capture_rates, self.plot_configs),
            style=Style(color="green", bold=True),
        )
        return graph

    def get_threats(self, srcs: set) -> None:
        if random.choice([True, False]):
            return

        srcs = random.sample(list(srcs), len(srcs) // 2)
        packet_details = AbuseIPClassification(srcs).detect()
        if not isinstance(packet_details, dict):
            for detail in packet_details:
                host = hostname(detail["ipAddress"])
                self.classified.append(host)
                self.capture_info["threats"] += Text.from_markup(
                    f"[bold red]* Unsafe packet source {host}[/bold red]\n"
                    if detail["abuseConfidenceScore"] > 50
                    else f"[cyan]* Safe packet source {host}[/cyan]\n",
                )
        else:
            host = hostname(packet_details["ipAddress"])
            self.classified.append(host)
            self.capture_info["threats"] += Text.from_markup(
                f"[bold red]* Unsafe packet source {host}[/bold red]\n"
                if packet_details["abuseConfidenceScore"] > 50
                else f"[green]* Safe packet source {host}[/green]\n",
            )

    def flush(self) -> None:
        self.sniffer.packet_count = 0
        self.sniffer.packets = []

        if len(self.capture_rates) > (self.width - self._transient_factor):
            self.capture_rates = []

        if str(self.capture_info["threats"]).count("\n") >= (self.height // 3):
            self.capture_info["threats"] = Text("")

        if str(self.capture_info["history"]).count("\n") >= (self.height // 3):
            self.capture_info["history"] = Text("")

    def set_capture_details(self) -> None:
        srcs = set()
        for packet in self.sniffer.packets:
            if not packet.haslayer(modules.IP):
                continue

            packet = packet[modules.IP]
            srcs.add(packet.src)
            proto = self.sniffer.proto_lookup_table[packet.proto]
            self.protocals[proto] = self.protocals.get(proto, 0) + 1
            self.capture_info["history"] += Text(
                f"""* Source {hostname(packet.src)} - Destination {hostname(packet.dst)}\
 - Port(s/d) {getattr(packet, 'sport', 'N/A')}\
 - {getattr(packet, 'dport', 'N/A')}\n""",
                style="bold cyan",
                justify="center",
            )

        self.get_threats(srcs=srcs)

        top_protocals = {
            k: v
            for k, v in sorted(
                self.protocals.items(), key=lambda item: item[1], reverse=True
            )
        }
        dict_string = ""
        for protocal, freq in top_protocals.items():
            dict_string += f"* {protocal} - {freq}\n"

        self.capture_info["top_protocals"] = Text(
            dict_string, justify="left", style="bold red"
        )

    def render(self) -> None:
        with Live(auto_refresh=False, screen=True) as live:
            try:
                while True:
                    network_traffic = self.capture_statistics()
                    live.update(
                        self.get_dashboard(
                            network_traffic_renderable=network_traffic,
                            network_statistics_renderable="",
                            threat_alert_renderable=self.capture_info["threats"],
                            packet_history_renderable=self.capture_info["history"],
                            top_protocals_renderable=self.capture_info["top_protocals"],
                        ),
                        refresh=True,
                    )
            except KeyboardInterrupt:
                self.sniffer.stop()

    def get_dashboard(
        self,
        network_traffic_renderable: str | Text,
        network_statistics_renderable: str | Text,
        threat_alert_renderable: str | Text,
        packet_history_renderable: str | Text,
        top_protocals_renderable: str | Text,
    ) -> Layout:
        layout = Layout()

        # Panels
        network_traffic_panel = Panel(
            network_traffic_renderable,
            title="[bold light_coral]Real-time Network Traffic[/bold light_coral]",
        )

        network_statistics_panel = Panel(
            network_statistics_renderable,
            title="[bold cyan]Packet Detail[/bold cyan]",
        )

        threat_alert_panel = Panel(
            threat_alert_renderable,
            title="[bold red]Threat Alerts[/bold red]",
        )

        packet_history_panel = Panel(
            packet_history_renderable,
            title="[bold dark_sea_green]Packet History[/bold dark_sea_green]",
        )

        top_protocals_panel = Panel(
            top_protocals_renderable,
            title="[bold bright_green]Top Protocols[/bold bright_green]",
        )

        layout.split_column(
            Layout(renderable=network_traffic_panel, name="top"),
            Layout(name="middle"),
            Layout(name="bottom"),
        )

        layout["middle"].split_row(
            Layout(
                renderable=network_statistics_panel,
                name="left",
                ratio=self.middle_column_ratio,
            ),
            Layout(renderable=threat_alert_panel, name="right"),
        )

        layout["bottom"].split_row(
            Layout(
                renderable=packet_history_panel,
                name="left",
                ratio=self.bottom_column_ratio,
            ),
            Layout(renderable=top_protocals_panel, name="right"),
        )

        return layout


class Realtime:
    lock_name = f"/tmp/{__name__}.lock"

    def __init__(
        self,
        duration: str = None,
        wait_for: int = 1,
        notify: bool = False,
        verbose: bool = False,
        **kwargs,
    ) -> None:
        self.duration = duration
        self.wait_for = wait_for
        self.verbose = verbose
        self.kwargs = kwargs
        self.cache = get_cache()
        self.history = History()

        if sys.platform != "darwin" and notify:
            raise OSError("Only supports notifcation for darwin systems")

        self.notify = notify
        for request in ["show_packets", "send_request"]:
            self.kwargs.pop(request, None)

        self.kwargs["verbose"] = False
        self.kwargs["is_async"] = True
        self.sniffer = None

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
        message = f"Unsafe packet detected from {packet_src}"
        command = (
            f'display notification "{message}" with title "Unsafe packet detected"'
        )
        subprocess.run(shlex.split(f"osascript -e '{command}'"))
        self.notified = True

    def dashboard(self) -> None:
        # Only for cli usage.
        Dashboard(**self.kwargs)

    def monitor(self) -> None:
        """
        Background monitor extention of `netscanner sniff`
        saves information to redis cache and also notifies of abuse IP classifications.
        """
        self.setup()
        console.print(
            "\n[italic]Starting sniffer and streaming packets\n",
            style="info",
            verbose=self.verbose,
        )
        self.sniffer = Sniffer(**self.kwargs)

        for packet in self.sniffer.stream_packets(
            duration=self.duration, wait_for=self.wait_for
        ):
            packet = packet[modules.IP]
            # 50/50 process further or return also no duplicate src IPs stored.
            if self.history.exists(packet.src) or random.choice([True, False]):
                continue

            is_safe = (
                AbuseIPClassification(packet.src).detect()["abuseConfidenceScore"] < 50
            )
            if not is_safe and self.notify:
                self.send_notification(packet_src=packet.src)

            self.history.add(
                src=packet.src,
                dst=packet.dst,
                timestamp=str(datetime.now()),
                is_safe=is_safe,
            )
        # If stopped via timeout.
        self.cleanup()

    def cleanup(self) -> None:
        console.print("Cleaning up", style="info", verbose=self.verbose)
        self.sniffer.stop()
        if os.path.isfile(self.lock_name):
            os.unlink(self.lock_name)
