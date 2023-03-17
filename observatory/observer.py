import logging
import os
import re
import socket
import time
from datetime import datetime

from rich.console import Console

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
pprint = Console()


def convert_unix_timestamp(timestamp: float) -> str:
    return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def get_src(bp_filters: str) -> str:
    if ip := SRC_PATTERN.findall(bp_filters):
        return ip[0]


class Observer:
    __slots__ = (
        "sniff_count",
        "bp_filters",
        "questions",
        "proto_lookup_table",
        "packets",
        "verbose",
    )

    def __init__(
        self,
        sniff_count: int = 0,
        bp_filters: str | None = None,
        extra_questions: list | None = None,
        verbose: bool = True,
    ):

        if os.getuid() != 0:
            raise PermissionError(
                "Not enough permissions to run this sniffer use as root"
            )

        self.verbose = verbose
        self.bp_filters = bp_filters if bp_filters else ""
        self.sniff_count = sniff_count
        extra_questions = extra_questions if extra_questions else []

        self.questions = self.questions_from_sniff(extra_questions=extra_questions)
        self.proto_lookup_table = self.proto_lookup()
        self.packets = []

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
        self.packets.append(packet)

        if self.verbose:
            print("-" * 20, "Packet Information", "-" * 20)

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
                print(f"Error: {e}; {packet}")

        if self.verbose:
            for k, v in question_and_answers.items():
                print(f"{k}: {v}")

            print("-" * 20, "End Of Information", "-" * 20, end="\n\n")

    def send_network_request(self, src: str) -> None:
        """Sends http request to the specified sRC"""

        print(f"Sending Request To {src}", end="\n\n")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((src, 80))

    def observe(self) -> None:
        if not self.sniff_count:
            print("Starting Sniffer Press Ctrl + C to exit", end="\n\n")

        # Using filters as Specified by BPF

        sniffer = all.AsyncSniffer(
            prn=self.prn,
            filter=self.bp_filters if self.bp_filters else None,
            count=self.sniff_count,
        )
        sniffer.start()

        if src := get_src(self.bp_filters):
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
    Observer(extra_questions=["route"], bp_filters="ip").observe()
