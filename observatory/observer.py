import logging
import re
import socket
import time
from datetime import datetime

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy import all

word = "src"
pattern = r"\b" + word + r"\b\s+(\S+)"


SRC_PATTERN = re.compile(pattern)


def convert_unix_timestamp(timestamp: float) -> str:
    return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def get_src(bp_filters: str) -> str:
    if ip := SRC_PATTERN.findall(bp_filters):
        return ip[0]


class Observer:
    __slots__ = (
        "sniff_count",
        "bp_filters",
        "extra_details",
        "details_required",
        "verbose",
        "proto_lookup_table",
    )

    def __init__(
        self,
        sniff_count: int = 0,
        bp_filters: str | None = None,
        extra_details: list | None = None,
        verbose: bool = False,
    ):
        self.bp_filters = bp_filters if bp_filters else ""
        self.sniff_count = sniff_count
        self.verbose = verbose
        extra_details = extra_details if extra_details else []

        self.details_required = self.requirements_from_sniff(
            extra_details=extra_details
        )
        self.proto_lookup_table = self.proto_lookup()

    def requirements_from_sniff(self, extra_details: list | None) -> list[str]:
        details = [
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
        details.extend(extra_details if extra_details else [])
        return details

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

        print("-" * 20, "Packet Information", "-" * 20)

        for requirments in self.details_required:
            try:
                if requirments == "proto":
                    question_and_answers[requirments] = self.proto_lookup_table[
                        getattr(packet[all.IP], requirments)
                    ]

                elif requirments == "time":
                    question_and_answers[requirments] = convert_unix_timestamp(
                        getattr(packet[all.IP], requirments)
                    )

                elif requirments == "route":
                    question_and_answers[requirments] = getattr(
                        packet[all.IP], requirments
                    )()

                else:
                    question_and_answers[requirments] = getattr(
                        packet[all.IP], requirments
                    )
            except (IndexError, AttributeError) as e:
                print(f"Error: {e}; {packet}")

        for k, v in question_and_answers.items():
            print(f"{k}: {v}")

        print("-" * 20, "End Of Information", "-" * 20, end="\n\n")

    def send_network_request(self, src: str) -> None:
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


if __name__ == "__main__":
    Observer(extra_details=["route"], bp_filters="udp").observe()
