import logging
import os
import re
import socket
import time
from datetime import datetime

from rich import print as pprint
from rich.console import Group
from rich.panel import Panel

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy import all

SRC_PATTERN = re.compile(r"\bsrc\b\s+(\S+)")
QUESTIONS = [
    "dst",
    "src",
    "ttl",
    "proto",
    "chksum",
    "seq",
    "ack",
    "urgptr",
    "sport",
    "dport",
    "time",
    "payload",
]


def convert_unix_timestamp(timestamp: float) -> str:
    return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def get_src(bp_filters: str) -> str:
    if ip := SRC_PATTERN.findall(bp_filters):
        return ip[0]


class Sniffer:
    __slots__ = (
        "sniff_count",
        "bp_filters",
        "questions",
        "proto_lookup_table",
        "packets",
        "verbose",
        "packet_count",
        "send_request",
    )

    def __init__(
        self,
        sniff_count: int = 0,
        bp_filters: str | None = None,
        extra_questions: list | None = None,
        verbose: bool = True,
        send_request: bool = False,
    ):

        if os.getuid() != 0:
            raise PermissionError(
                "Not enough permissions to run this sniffer use as root"
            )

        pprint("[cyan]Initializing Parameters...")

        self.verbose = verbose
        self.send_request = send_request
        self.bp_filters = bp_filters if bp_filters else ""
        self.sniff_count = sniff_count
        extra_questions = extra_questions if extra_questions else []

        self.questions = self.questions_from_sniff(extra_questions=extra_questions)
        self.proto_lookup_table = self.proto_lookup()
        self.packets = []
        self.packet_count = 0

        pprint("[cyan]Parameters initialized.")

    def questions_from_sniff(self, extra_questions: list | None) -> list[str]:
        """Get questions and extra details for IP packet."""
        QUESTIONS.extend(extra_questions if extra_questions else [])
        return QUESTIONS

    def proto_lookup(self) -> dict[int, str]:
        """
        Returns the protocal associated with it's corresponding protocal number according to IANA.
        """
        lookup = {}
        prefix = "IPPROTO_"

        for proto, number in vars(socket).items():
            if proto.startswith(prefix):
                lookup[number] = proto[len(prefix) :]

        return lookup

    def prn(self, packet: all.Packet) -> None:
        question_and_answers = {}
        panels = []
        self.packets.append(packet)
        self.packet_count += 1

        for question in self.questions:
            try:
                if question == "proto":
                    question_and_answers[question] = self.proto_lookup_table[
                        getattr(packet[all.IP], question)
                    ]

                elif question == "time":
                    question_and_answers[question] = convert_unix_timestamp(
                        getattr(packet[all.IP], question)
                    )

                elif question == "route":
                    question_and_answers[question] = getattr(packet[all.IP], question)()

                else:
                    question_and_answers[question] = getattr(packet[all.IP], question)
            except (IndexError, AttributeError) as e:
                panels.append((f"[red]Error: {e}; {packet}"))

        if self.verbose:
            for k, v in question_and_answers.items():
                panels.append(f"[cyan]{k}: [green]{v}")

            panel_group = Group(*panels)

            pprint(
                Panel(
                    panel_group,
                    title=f"[red]Packet Information Packet Count: {self.packet_count}",
                    subtitle=f"[red]End Of Information Packet Count: {self.packet_count}",
                )
            )

    def send_network_request(self, src: str) -> None:
        """Sends http request to the specified sRC"""
        pprint(f"\n[cyan]Sending Request To [bold green]{src}", end="\n\n")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((src, 80))

    def observe(self) -> None:
        if not self.sniff_count or not self.send_request:
            pprint("[italic]Actively Sniffing Press Ctrl + C to exit", end="\n\n")

        # Using filters as Specified by BPF (https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)

        sniffer = all.AsyncSniffer(
            prn=self.prn,
            filter=self.bp_filters if self.bp_filters else None,
            count=self.sniff_count,
        )
        sniffer.start()

        if self.send_request:
            if src := get_src(self.bp_filters):
                while len(self.packets) < self.sniff_count:
                    self.send_network_request(src)

        if not self.sniff_count:
            try:
                while True:
                    time.sleep(1)

            except KeyboardInterrupt:
                sniffer.stop()

        sniffer.join()
        return self.packets


if __name__ == "__main__":
    Sniffer(extra_questions=["route"], bp_filters="ip").observe()
