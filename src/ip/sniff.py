import binascii
import logging
import os
import socket
import time
from typing import Generator

from cli.renderer import console, render_sniffed_packets
from src.ip.history import History
from src.ip.utils import QUESTIONS, private_ip, proto_lookup
from src.utils import Timeout, convert_unix_timestamp, get_src, parse_duration

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy import all as modules
from scapy import error

idx = -1


class Sniffer:
    def __init__(
        self,
        sniff_count: int = 0,
        bp_filters: str = None,
        extra_questions: list | None = None,
        verbose: bool = True,
        send_request: bool = False,
        only_inbound: bool = False,
        show_packets: bool = False,
        is_async: bool = False,
        record: bool = True,
    ):
        if os.getuid() != 0:
            raise PermissionError(
                "Not enough permissions to run this sniffer use as root"
            )
        self.verbose = verbose
        self.record = record
        self.show_packets = show_packets
        self.is_async = is_async
        self.send_request = send_request
        self.bp_filters = bp_filters if bp_filters else ""
        self.sniff_count = sniff_count
        self.only_inbound = only_inbound
        extra_questions = extra_questions if extra_questions else []

        self.questions = self.questions_from_sniff(extra_questions=extra_questions)
        self.proto_lookup_table = proto_lookup()
        self.packet_count = 0
        self._sniffer = None
        self.packets = []

        console.print(
            "\n",
            "-" * 20,
            "Sniffer",
            "-" * 20,
            "\n",
            verbose=self.verbose,
            style="info",
        )

        if self.record:
            self.history = History()
            console.print("Storing all network activity.", style="blink red")

        console.print("Parameters initialized.", verbose=self.verbose, style="info")
        self.sniff()

    def stream_packets(
        self, duration: str = "1 second", wait_for: int = 1
    ) -> Generator:
        """Yield packets as they are sniffed"""
        with Timeout(seconds=parse_duration(duration), kill_func=self.stop):
            idx = 0
            try:
                while True and self._sniffer.running:
                    if idx < len(self.packets):
                        yield self.packets[idx]
                        idx += 1
                    else:
                        # If no packets are added after timeout break out of the stream
                        time.sleep(wait_for)
            except KeyboardInterrupt:
                self.stop()

    def get_packets(self) -> list[modules.Packet]:
        return self.packets

    def questions_from_sniff(self, extra_questions: list | None) -> list[str]:
        """Get questions and extra details for IP packet."""
        QUESTIONS.extend(extra_questions if extra_questions else [])
        return QUESTIONS

    def prn(self, packet: modules.Packet) -> None:
        if not packet.haslayer(modules.IP):
            return

        question_and_answers = {}
        self.packets.append(packet)
        self.packet_count += 1
        ip_packet = packet[modules.IP]

        if self.record:
            self.history.add(
                src=ip_packet.src,
                dst=ip_packet.dst,
                is_safe=None,
                dport=getattr(ip_packet, "dport", None),
                sport=getattr(ip_packet, "sport", None),
                protocal=self.proto_lookup_table[ip_packet.proto],
            )

        if not self.show_packets:
            return

        for question in self.questions:
            try:
                if question == "proto":
                    question_and_answers[question] = self.proto_lookup_table[
                        getattr(ip_packet, question)
                    ]

                elif question == "time":
                    question_and_answers[question] = convert_unix_timestamp(
                        getattr(ip_packet, question)
                    )

                elif question == "route":
                    question_and_answers[question] = getattr(ip_packet, question)()

                elif question == "load":
                    question_and_answers[question] = str(
                        binascii.hexlify((getattr(ip_packet, question))).decode()
                    )

                elif question == "length":
                    question_and_answers[question] = len(ip_packet)

                else:
                    question_and_answers[question] = getattr(ip_packet, question, None)

            except (IndexError, AttributeError) as e:
                console.print(f"Invalid packet! {e}", style="bold red")

        render_sniffed_packets(
            question_and_answers=question_and_answers,
            packet_count=self.packet_count,
        )

    def send_network_request(self, src: str) -> None:
        """Sends http request to the specified SRC"""
        console.print(
            f"\nSending Request To [bold green]{src}",
            end="\n\n",
            verbose=self.verbose,
            style="info",
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((src, 80))

    def stop(self, **kwarg) -> None:
        if self._sniffer:
            try:
                self._sniffer.stop()
            except error.Scapy_Exception:
                self._sniffer.join()

    def start(self) -> None:
        if self._sniffer:
            self._sniffer.start()

    def request(self) -> None:
        if src := get_src(self.bp_filters):
            while len(self.packets) < self.sniff_count:
                self.send_network_request(src)

    def block_thread(self) -> None:
        try:
            while True:
                ...
        except KeyboardInterrupt:
            self.stop()

    def sniff(self) -> None:
        if self.only_inbound:
            private_address = private_ip(verbose=self.verbose)
            inbound_filter = (
                f"dst host {private_address} and not src host {private_address}"
            )
            if self.bp_filters:
                self.bp_filters = inbound_filter + " and " + self.bp_filters
            else:
                self.bp_filters = inbound_filter

        if not self.sniff_count or self.is_async:
            console.print(
                "[italic]Actively Sniffing",
                end="\n\n",
                verbose=self.verbose,
                style="info",
            )

        # Using filters as Specified by BPF (https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)
        self._sniffer = modules.AsyncSniffer(
            prn=self.prn,
            filter=self.bp_filters if self.bp_filters else None,
            count=self.sniff_count,
        )
        self.start()

        if self.send_request:
            self.request()

        # Truly async
        if self.is_async:
            return

        # Is not async and sniff_count isn't supplied it just keeps the thread waiting
        if not self.sniff_count:
            self.block_thread()

        self.stop()


if __name__ == "__main__":
    Sniffer(extra_questions=["route"], bp_filters="ip")
