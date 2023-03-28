import logging
import os
import socket

from netscanner.ip.utils import QUESTIONS, private_ip, proto_lookup
from netscanner.utils import convert_unix_timestamp, get_src
from renderer import console, render_sniffed_packets

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy import all as modules


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
        "only_inbound",
    )

    def __init__(
        self,
        sniff_count: int = 0,
        bp_filters: str | None = None,
        extra_questions: list | None = None,
        verbose: bool = True,
        send_request: bool = False,
        only_inbound: bool = False,
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
        self.only_inbound = only_inbound
        extra_questions = extra_questions if extra_questions else []

        self.questions = self.questions_from_sniff(extra_questions=extra_questions)
        self.proto_lookup_table = proto_lookup()
        self.packets = []
        self.packet_count = 0

        console.print("[cyan]Parameters initialized.")
        self.observe()

    def get_packets(self) -> list[modules.Packet]:
        return self.packets

    def questions_from_sniff(self, extra_questions: list | None) -> list[str]:
        """Get questions and extra details for IP packet."""
        QUESTIONS.extend(extra_questions if extra_questions else [])
        return QUESTIONS

    def prn(self, packet: modules.Packet) -> None:
        self.packets.append(packet)
        self.packet_count += 1

        if self.verbose:
            question_and_answers = {}

            for question in self.questions:
                try:
                    if question == "proto":
                        question_and_answers[question] = self.proto_lookup_table[
                            getattr(packet[modules.IP], question)
                        ]

                    elif question == "time":
                        question_and_answers[question] = convert_unix_timestamp(
                            getattr(packet[modules.IP], question)
                        )

                    elif question == "route":
                        question_and_answers[question] = getattr(
                            packet[modules.IP], question
                        )()

                    else:
                        question_and_answers[question] = getattr(
                            packet[modules.IP], question
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
        if self.only_inbound:
            private_address = private_ip(verbose=self.verbose)
            inbound_filter = (
                f"dst host {private_address} and not src host {private_address}"
            )
            self.bp_filters = inbound_filter + " and " + self.bp_filters

        if not self.sniff_count or not self.send_request:
            console.print(
                "[italic]Actively Sniffing Press Ctrl + C to exit", end="\n\n"
            )

        # Using filters as Specified by BPF (https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)
        sniffer = modules.AsyncSniffer(
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
