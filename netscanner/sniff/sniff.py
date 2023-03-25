import logging
import os
import socket

from netscanner.ip.utils import QUESTIONS, proto_lookup
from netscanner.utils import get_src, convert_unix_timestamp
from renderer import console, render_sniffed_packets

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy import all


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

        console.print("[cyan]Initializing Parameters...")

        self.verbose = verbose
        self.send_request = send_request
        self.bp_filters = bp_filters if bp_filters else ""
        self.sniff_count = sniff_count
        extra_questions = extra_questions if extra_questions else []

        self.questions = self.questions_from_sniff(extra_questions=extra_questions)
        self.proto_lookup_table = proto_lookup()
        self.packets = []
        self.packet_count = 0

        console.print("[cyan]Parameters initialized.")
        self.observe()

    def questions_from_sniff(self, extra_questions: list | None) -> list[str]:
        """Get questions and extra details for IP packet."""
        QUESTIONS.extend(extra_questions if extra_questions else [])
        return QUESTIONS

    def prn(self, packet: all.Packet) -> None:
        self.packets.append(packet)
        self.packet_count += 1

        if self.verbose:
            question_and_answers = {}

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
                        question_and_answers[question] = getattr(
                            packet[all.IP], question
                        )()

                    else:
                        question_and_answers[question] = getattr(
                            packet[all.IP], question
                        )
                except (IndexError, AttributeError) as e:
                    console.print("Invalid packet!", style="bold red")

            render_sniffed_packets(
                question_and_answers=question_and_answers,
                packet_count=self.packet_count,
            )

    def send_network_request(self, src: str) -> None:
        """Sends http request to the specified sRC"""
        console.print(f"\n[cyan]Sending Request To [bold green]{src}", end="\n\n")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((src, 80))

    def observe(self) -> None:
        if not self.sniff_count or not self.send_request:
            console.print(
                "[italic]Actively Sniffing Press Ctrl + C to exit", end="\n\n"
            )

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
                    ...

            except KeyboardInterrupt:
                sniffer.stop()

        sniffer.join()
        return self.packets


if __name__ == "__main__":
    Sniffer(extra_questions=["route"], bp_filters="ip")
